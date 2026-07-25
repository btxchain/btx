// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_coupled.h>

#include <consensus/params.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_bank_root_cache.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <span.h>

#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <future>
#include <limits>
#include <mutex>
#include <thread>
#include <vector>

namespace matmul::v4::rc {

const RCCoupDomainTagSet& RCCoupDomainTagsForVersion(uint32_t transcript_version)
{
    static const RCCoupDomainTagSet kV1{
        kRCCoupEpisodeTag,           kRCCoupBankTag,
        kRCCoupLobeTag,              kRCCoupBarrierTag,
        kRCCoupPermTag,              kRCCoupMixTag,
        kRCCoupExtractTag,           kRCCoupFullBankTag,
        kRCCoupMaterialExchangeTag,  kRCCoupMaterialExchangeRoundsTag,
    };
    static const RCCoupDomainTagSet kV2{
        kRCCoupEpisodeTagV2,          kRCCoupBankTagV2,
        kRCCoupLobeTagV2,             kRCCoupBarrierTagV2,
        kRCCoupPermTagV2,             kRCCoupMixTagV2,
        kRCCoupExtractTagV2,          kRCCoupFullBankTagV2,
        kRCCoupMaterialExchangeTagV2, kRCCoupMaterialExchangeRoundsTag,
    };
    static const RCCoupDomainTagSet kV3{
        kRCCoupEpisodeTagV3,          kRCCoupBankTagV3,
        kRCCoupLobeTagV3,             kRCCoupBarrierTagV3,
        kRCCoupPermTagV3,             kRCCoupMixTagV3,
        kRCCoupExtractTagV3,          kRCCoupFullBankTagV3,
        kRCCoupMaterialExchangeTagV3, kRCCoupMaterialExchangeRoundsTag,
    };
    static const RCCoupDomainTagSet kV4{
        kRCCoupEpisodeTagV4,          kRCCoupBankTagV4,
        kRCCoupLobeTagV4,             kRCCoupBarrierTagV4,
        kRCCoupPermTagV4,             kRCCoupMixTagV4,
        kRCCoupExtractTagV4,          kRCCoupFullBankTagV4,
        kRCCoupMaterialExchangeTagV4, kRCCoupMaterialExchangeRoundsTagV4,
    };
    if (transcript_version == ENC_RC_V4) return kV4;
    if (transcript_version == ENC_RC_V3) return kV3;
    if (transcript_version == ENC_RC_V2) return kV2;
    return kV1;
}

namespace {

namespace lt = matmul::v4::lt;

inline size_t TagLen(const char* tag) { return std::strlen(tag); }

template <typename Fn>
void ParallelForCoupled(size_t jobs, uint32_t threads, const Fn& fn)
{
    if (jobs == 0) return;
    threads = std::max<uint32_t>(
        1, std::min<uint32_t>({threads, 64U, static_cast<uint32_t>(jobs)}));
    if (threads <= 1) {
        for (size_t i = 0; i < jobs; ++i) fn(i);
        return;
    }
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (uint32_t t = 0; t < threads; ++t) {
        workers.emplace_back([&, t] {
            const size_t begin = (jobs * t) / threads;
            const size_t end = (jobs * (t + 1U)) / threads;
            for (size_t i = begin; i < end; ++i) fn(i);
        });
    }
    for (auto& worker : workers) worker.join();
}

uint256 Sha256Tagged(const char* tag, size_t taglen, const unsigned char* data, size_t len)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    if (len > 0) hasher.Write(data, len);
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint256 Sha256dBytes(const unsigned char* data, size_t len)
{
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data, len).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

uint256 Sha256TaggedU32(const char* tag, size_t taglen, const uint256& a, uint32_t le32)
{
    unsigned char buf[32 + 4];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, le32);
    return Sha256Tagged(tag, taglen, buf, sizeof(buf));
}

uint256 Sha256TaggedU32U32(const char* tag, size_t taglen, const uint256& a, uint32_t x,
                           uint32_t y)
{
    unsigned char buf[32 + 8];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, x);
    WriteLE32(buf + 36, y);
    return Sha256Tagged(tag, taglen, buf, sizeof(buf));
}

/** XOF words from a seed (SHA256 counter mode) for Fisher–Yates / mix masks. */
class ShaXof {
public:
    explicit ShaXof(const uint256& seed) : m_seed(seed) {}

    uint32_t NextU32()
    {
        if (m_pos + 4 > 32) {
            Refill();
        }
        const uint32_t v = ReadLE32(m_block + m_pos);
        m_pos += 4;
        return v;
    }

    uint64_t NextU64()
    {
        // Two LE u32 halves — avoids needing 8-byte alignment in the XOF window.
        const uint64_t lo = NextU32();
        const uint64_t hi = NextU32();
        return lo | (hi << 32);
    }

private:
    void Refill()
    {
        unsigned char buf[32 + 4];
        std::memcpy(buf, m_seed.data(), 32);
        WriteLE32(buf + 32, m_ctr++);
        uint8_t out[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(buf, sizeof(buf)).Finalize(out);
        std::memcpy(m_block, out, 32);
        m_pos = 0;
    }

    uint256 m_seed;
    uint32_t m_ctr{0};
    uint32_t m_pos{32};
    unsigned char m_block[32]{};
};

uint256 BarrierRoot(uint32_t barrier, const std::vector<int8_t>& state,
                    const RCCoupDomainTagSet& tags)
{
    const size_t tlen = TagLen(tags.barrier);
    std::vector<unsigned char> buf;
    buf.reserve(tlen + 4 + state.size());
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tags.barrier),
               reinterpret_cast<const unsigned char*>(tags.barrier) + tlen);
    unsigned char le[4];
    WriteLE32(le, barrier);
    buf.insert(buf.end(), le, le + 4);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(state.data()),
               reinterpret_cast<const unsigned char*>(state.data()) + state.size());
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 BankCommitment(const std::vector<std::vector<int8_t>>& pages, uint32_t bank_pages,
                       uint32_t lobe_width, const RCCoupDomainTagSet& tags)
{
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(tags.bank), TagLen(tags.bank));
    const size_t page_bytes = static_cast<size_t>(lobe_width) * lobe_width;
    for (uint32_t p = 0; p < bank_pages; ++p) {
        // Malformed page size → null commitment (caller treats as reject).
        if (pages[p].size() != page_bytes) return uint256{};
        outer.Write(reinterpret_cast<const unsigned char*>(pages[p].data()), pages[p].size());
    }
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    outer.Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

/** Stream pages into the hasher without retaining the full bank (Streamed). */
uint256 BankCommitmentStreaming(const CBlockHeader& header, int32_t height,
                                const RCCoupParams& params, uint32_t transcript_version,
                                uint32_t expansion_threads, bool pipeline_pages,
                                const lt::ExactGemmBackend& gemm,
                                const std::shared_ptr<RCCoupBankRootCache>& root_cache,
                                RCCoupTiming* timing)
{
    RCCoupBankRootCacheKey cache_key;
    if (root_cache != nullptr) {
        cache_key.template_hash = RCBankTemplateHash(header);
        cache_key.params_fingerprint = FingerprintRCCoupParams(params);
        cache_key.height = height;
        cache_key.transcript_version = transcript_version;
        cache_key.bank_pages = params.bank_pages;
        cache_key.width = params.lobe_width;
        uint256 cached;
        if (root_cache->Lookup(cache_key, cached)) {
            if (timing != nullptr) timing->bank_cache_hit = true;
            return cached;
        }
    }

    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(tags.bank), TagLen(tags.bank));
    const size_t page_bytes = static_cast<size_t>(params.lobe_width) * params.lobe_width;
    bool device_page_enabled = gemm.seeded_page_s8 != nullptr;
    const auto derive_page = [&](uint32_t p, uint32_t threads) {
        if (device_page_enabled) {
            std::vector<int8_t> device_page;
            bool ok = false;
            try {
                const uint256 seed = DeriveCoupledBankPageSeed(
                    header, height, p, params, transcript_version);
                ok = !seed.IsNull() &&
                     gemm.seeded_page_s8(seed, params.lobe_width, device_page) &&
                     device_page.size() == page_bytes;
            } catch (...) {
                ok = false;
            }
            if (ok) {
                if (timing != nullptr) ++timing->bank_device_pages;
                return device_page;
            }
            // Fail closed to the CPU oracle once. Repeated device retries would
            // amplify a provider/runtime failure across all 1,536 pages.
            device_page_enabled = false;
        }
        if (timing != nullptr) ++timing->bank_cpu_pages;
        return DeriveCoupledBankPage(header, height, p, params, transcript_version, threads);
    };
    if (pipeline_pages && expansion_threads > 1 && params.bank_pages > 1) {
        // Reserve one logical worker for ordered SHA256 while the next page is
        // expanded. At most two expanded pages (current + in-flight) exist.
        const uint32_t producer_threads = expansion_threads - 1;
        std::vector<int8_t> page = derive_page(0, producer_threads);
        for (uint32_t p = 0; p < params.bank_pages; ++p) {
            std::future<std::vector<int8_t>> next;
            if (p + 1 < params.bank_pages) {
                try {
                    next = std::async(std::launch::async, derive_page, p + 1,
                                      producer_threads);
                } catch (...) {
                    return uint256{};
                }
            }
            if (page.size() != page_bytes) return uint256{};
            outer.Write(reinterpret_cast<const unsigned char*>(page.data()), page.size());
            if (next.valid()) {
                try {
                    page = next.get();
                } catch (...) {
                    return uint256{};
                }
            }
        }
    } else {
        for (uint32_t p = 0; p < params.bank_pages; ++p) {
            const auto page = derive_page(p, expansion_threads);
            if (page.size() != page_bytes) return uint256{};
            outer.Write(reinterpret_cast<const unsigned char*>(page.data()), page.size());
        }
    }
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    outer.Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    const uint256 root{Span<const unsigned char>{d2, sizeof(d2)}};
    if (root_cache != nullptr) root_cache->Store(cache_key, root);
    return root;
}

/**
 * C6 pattern 0 — hypercube butterfly (ascending strides), sum/diff.
 * Indices are XOR-relabeled by `mask` so the cut is nonce-dependent.
 *
 * u64_wrap=false: signed int64 arithmetic (V2 / M=1 digest-stable path).
 * u64_wrap=true:  explicit uint64 two's-complement wrap (V3 M≥32) — defined
 * modular ring, identical bit pattern to wrapping signed add on two's-complement
 * hosts but without signed-overflow UB.
 */
void MixButterflyAscending(std::vector<int64_t>& s, uint32_t mask, uint32_t n, bool u64_wrap)
{
    for (uint32_t stage = 0; (uint32_t{1} << stage) < n; ++stage) {
        const uint32_t stride = uint32_t{1} << stage;
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = i ^ mask;
            const uint32_t pj = j ^ mask;
            if (u64_wrap) {
                const uint64_t a = static_cast<uint64_t>(s[pi]);
                const uint64_t b = static_cast<uint64_t>(s[pj]);
                s[pi] = static_cast<int64_t>(a + b);
                s[pj] = static_cast<int64_t>(a - b);
            } else {
                const int64_t a = s[pi];
                const int64_t b = s[pj];
                s[pi] = a + b;
                s[pj] = a - b;
            }
        }
    }
}

/**
 * C6 pattern 1 — reverse-stride reduce-scatter style fold (descending strides)
 * with a rotate-relabel so partitions that minimize pattern 0 do not minimize
 * this cut. Integer sums/diffs only (see MixButterflyAscending for wrap policy).
 */
void MixButterflyDescending(std::vector<int64_t>& s, uint32_t mask, uint32_t n, bool u64_wrap)
{
    // Entry guard: non-pow2 / tiny n is a reject path (ValidateRCCoupParams).
    if (n < 2 || (n & (n - 1)) != 0) return;
    uint32_t bits = 0;
    for (uint32_t t = n; t > 1; t >>= 1) ++bits;
    auto rotl = [bits, n](uint32_t x, uint32_t r) -> uint32_t {
        r %= bits;
        return ((x << r) | (x >> (bits - r))) & (n - 1);
    };
    for (int stage = static_cast<int>(bits) - 1; stage >= 0; --stage) {
        const uint32_t stride = uint32_t{1} << static_cast<uint32_t>(stage);
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = rotl(i ^ mask, 3);
            const uint32_t pj = rotl(j ^ mask, 3);
            if (u64_wrap) {
                const uint64_t a = static_cast<uint64_t>(s[pi]);
                const uint64_t b = static_cast<uint64_t>(s[pj]);
                s[pi] = static_cast<int64_t>(a + b);
                s[pj] = static_cast<int64_t>(b - a);
            } else {
                const int64_t a = s[pi];
                const int64_t b = s[pj];
                // Distinct linear form from pattern 0 (still exact integer).
                s[pi] = a + b;
                s[pj] = b - a;
            }
        }
    }
}

class CoupledStageBarrier
{
public:
    explicit CoupledStageBarrier(uint32_t workers)
        : m_workers(workers), m_remaining(workers)
    {
    }

    void Wait()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        const uint64_t generation = m_generation;
        if (--m_remaining == 0) {
            m_remaining = m_workers;
            ++m_generation;
            lock.unlock();
            m_cv.notify_all();
            return;
        }
        m_cv.wait(lock, [&] { return m_generation != generation; });
    }

private:
    const uint32_t m_workers;
    uint32_t m_remaining;
    uint64_t m_generation{0};
    std::mutex m_mutex;
    std::condition_variable m_cv;
};

void MixButterflyParallel(std::vector<int64_t>& s, uint32_t mask, uint32_t n,
                          bool u64_wrap, uint32_t pattern, uint32_t threads)
{
    if (n < 2 || (n & (n - 1)) != 0) return;
    const uint32_t pairs = n / 2U;
    threads = std::max<uint32_t>(
        1, std::min<uint32_t>({threads, 64U, pairs}));
    if (threads <= 1) {
        if (pattern == 0) {
            MixButterflyAscending(s, mask, n, u64_wrap);
        } else {
            MixButterflyDescending(s, mask, n, u64_wrap);
        }
        return;
    }

    uint32_t bits = 0;
    for (uint32_t t = n; t > 1; t >>= 1) ++bits;
    CoupledStageBarrier stage_barrier(threads);
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (uint32_t worker = 0; worker < threads; ++worker) {
        workers.emplace_back([&, worker] {
            const uint32_t begin = static_cast<uint32_t>(
                (static_cast<uint64_t>(pairs) * worker) / threads);
            const uint32_t end = static_cast<uint32_t>(
                (static_cast<uint64_t>(pairs) * (worker + 1U)) / threads);
            for (uint32_t logical_stage = 0; logical_stage < bits; ++logical_stage) {
                const uint32_t stage =
                    pattern == 0 ? logical_stage : bits - 1U - logical_stage;
                const uint32_t stride = uint32_t{1} << stage;
                for (uint32_t pair = begin; pair < end; ++pair) {
                    const uint32_t block = pair / stride;
                    const uint32_t offset = pair - block * stride;
                    const uint32_t i = block * (stride * 2U) + offset;
                    const uint32_t j = i + stride;
                    uint32_t pi = i ^ mask;
                    uint32_t pj = j ^ mask;
                    if (pattern != 0) {
                        constexpr uint32_t rotate = 3;
                        const uint32_t r = rotate % bits;
                        pi = ((pi << r) | (pi >> (bits - r))) & (n - 1U);
                        pj = ((pj << r) | (pj >> (bits - r))) & (n - 1U);
                    }
                    if (u64_wrap) {
                        const uint64_t a = static_cast<uint64_t>(s[pi]);
                        const uint64_t b = static_cast<uint64_t>(s[pj]);
                        s[pi] = static_cast<int64_t>(a + b);
                        s[pj] = static_cast<int64_t>(
                            pattern == 0 ? a - b : b - a);
                    } else {
                        const int64_t a = s[pi];
                        const int64_t b = s[pj];
                        s[pi] = a + b;
                        s[pj] = pattern == 0 ? a - b : b - a;
                    }
                }
                stage_barrier.Wait();
            }
        });
    }
    for (auto& worker : workers) worker.join();
}

void ApplyAllToAllMix(std::vector<int64_t>& s, const uint256& sigma, uint32_t barrier,
                      uint32_t n, bool material_exchange = false,
                      uint32_t exchange_rows = dc::kRCCoupExchangeRowsDefault,
                      bool u64_wrap = false, const RCCoupDomainTagSet* tags = nullptr,
                      uint32_t threads = 1)
{
    const RCCoupDomainTagSet& t =
        tags != nullptr ? *tags : RCCoupDomainTagsForVersion(ENC_RC_V1);
    // When material exchange is ON, absorb rows into the mix domain so fabric
    // pressure is digest-visible (NVLink-shaped thesis). Legacy path unchanged.
    uint256 mix_seed;
    if (material_exchange) {
        const uint32_t rows = exchange_rows == 0 ? dc::kRCCoupExchangeRowsDefault : exchange_rows;
        mix_seed = Sha256TaggedU32U32(t.exchange, TagLen(t.exchange), sigma, barrier, rows);
    } else {
        mix_seed = Sha256TaggedU32(t.mix, TagLen(t.mix), sigma, barrier);
    }
    ShaXof xof(mix_seed);
    const uint32_t mask = xof.NextU32() & (n - 1);
    const uint32_t pattern = barrier % kRCCoupMixPatterns;
    if (threads > 1) {
        MixButterflyParallel(s, mask, n, u64_wrap, pattern, threads);
    } else if (pattern == 0) {
        MixButterflyAscending(s, mask, n, u64_wrap);
    } else {
        MixButterflyDescending(s, mask, n, u64_wrap);
    }
}

/** Overflow-safe XOR-fold of int64 lanes (uint64 view). */
uint64_t AccXorFold(const std::vector<int64_t>& s)
{
    uint64_t fold = 0;
    for (int64_t v : s) {
        fold ^= static_cast<uint64_t>(v);
    }
    return fold;
}

/**
 * Round seed = SHA256d(tag ‖ sigma ‖ barrier ‖ round ‖ 8-byte fold).
 * Dependency-linked: fold binds prior accumulator state into the seed.
 */
uint256 ExchangeRoundSeed(const uint256& sigma, uint32_t barrier, uint32_t round,
                          uint64_t fold, const RCCoupDomainTagSet& tags)
{
    unsigned char buf[32 + 4 + 4 + 8];
    std::memcpy(buf, sigma.data(), 32);
    WriteLE32(buf + 32, barrier);
    WriteLE32(buf + 36, round);
    WriteLE64(buf + 40, fold);
    const size_t tlen = TagLen(tags.exchange_rounds);
    std::vector<unsigned char> pre;
    pre.reserve(tlen + sizeof(buf));
    pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(tags.exchange_rounds),
               reinterpret_cast<const unsigned char*>(tags.exchange_rounds) + tlen);
    pre.insert(pre.end(), buf, buf + sizeof(buf));
    return Sha256dBytes(pre.data(), pre.size());
}

/** Bijective XOR of all lanes with an XOF keystream (uint64 view — no signed UB). */
void ApplyXorKeystream(std::vector<int64_t>& s, ShaXof& xof)
{
    for (int64_t& lane : s) {
        const uint64_t k = xof.NextU64();
        lane = static_cast<int64_t>(static_cast<uint64_t>(lane) ^ k);
    }
}

/** Parallel counter blocks, identical to ShaXof(seed).NextU64() lane order. */
void ApplyXorKeystreamParallel(std::vector<int64_t>& s, const uint256& seed,
                               uint32_t threads)
{
    const size_t blocks = (s.size() + 3U) / 4U; // SHA block = four LE64 lanes
    ParallelForCoupled(blocks, threads, [&](size_t block_index) {
        unsigned char input[32 + 4];
        std::memcpy(input, seed.data(), 32);
        WriteLE32(input + 32, static_cast<uint32_t>(block_index));
        uint8_t hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(input, sizeof(input)).Finalize(hash);
        const size_t lane0 = block_index * 4U;
        for (size_t j = 0; j < 4 && lane0 + j < s.size(); ++j) {
            const uint64_t key = ReadLE64(hash + j * sizeof(uint64_t));
            s[lane0 + j] =
                static_cast<int64_t>(static_cast<uint64_t>(s[lane0 + j]) ^ key);
        }
    });
}

/** Fisher–Yates balanced permutation derived from an arbitrary seed. */
void ApplyBalancedPermutationFromSeed(std::vector<int64_t>& s, const uint256& seed)
{
    const uint32_t n = static_cast<uint32_t>(s.size());
    if (n == 0) return;
    ShaXof xof(seed);
    std::vector<uint32_t> pi(n);
    for (uint32_t i = 0; i < n; ++i) pi[i] = i;
    for (uint32_t i = n - 1; i > 0; --i) {
        const uint32_t j = xof.NextU32() % (i + 1);
        const uint32_t tmp = pi[i];
        pi[i] = pi[j];
        pi[j] = tmp;
    }
    std::vector<int64_t> tmp(n);
    for (uint32_t i = 0; i < n; ++i) {
        tmp[pi[i]] = s[i];
    }
    s = std::move(tmp);
}

/**
 * Parallelize only independent SHA counter blocks and the collision-free
 * scatter. Fisher–Yates swaps remain in canonical serial draw order.
 */
void ApplyBalancedPermutationFromSeedParallel(std::vector<int64_t>& s,
                                              const uint256& seed, uint32_t threads)
{
    const uint32_t n = static_cast<uint32_t>(s.size());
    if (n == 0) return;
    const size_t draws = n - 1U;
    std::vector<uint32_t> random(draws);
    const size_t blocks = (draws + 7U) / 8U; // SHA block = eight LE32 draws
    ParallelForCoupled(blocks, threads, [&](size_t block_index) {
        unsigned char input[32 + 4];
        std::memcpy(input, seed.data(), 32);
        WriteLE32(input + 32, static_cast<uint32_t>(block_index));
        uint8_t hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(input, sizeof(input)).Finalize(hash);
        const size_t draw0 = block_index * 8U;
        for (size_t j = 0; j < 8 && draw0 + j < draws; ++j) {
            random[draw0 + j] = ReadLE32(hash + j * sizeof(uint32_t));
        }
    });

    std::vector<uint32_t> pi(n);
    ParallelForCoupled(n, threads, [&](size_t i) {
        pi[i] = static_cast<uint32_t>(i);
    });
    size_t draw = 0;
    for (uint32_t i = n - 1; i > 0; --i) {
        const uint32_t j = random[draw++] % (i + 1);
        const uint32_t tmp = pi[i];
        pi[i] = pi[j];
        pi[j] = tmp;
    }
    std::vector<int64_t> tmp(n);
    ParallelForCoupled(n, threads, [&](size_t i) {
        tmp[pi[i]] = s[i];
    });
    s = std::move(tmp);
}

/**
 * After ApplyAllToAllMix: when material_exchange && exchange_rounds>0, run that
 * many dependency-linked XOR+permute rounds (V3). No-op when rounds==0.
 */
void ApplyMaterialExchangeRounds(std::vector<int64_t>& s, const uint256& sigma,
                                 uint32_t barrier, const RCCoupOptions& options)
{
    if (!options.material_exchange || options.exchange_rounds == 0) return;
    if (s.empty()) return;
    const auto& tags = RCCoupDomainTagsForVersion(options.transcript_version);
    for (uint32_t r = 0; r < options.exchange_rounds; ++r) {
        const uint64_t fold = AccXorFold(s);
        const uint256 seed = ExchangeRoundSeed(sigma, barrier, r, fold, tags);
        if (options.expansion_threads > 1) {
            ApplyXorKeystreamParallel(s, seed, options.expansion_threads);
            ApplyBalancedPermutationFromSeedParallel(
                s, seed, options.expansion_threads);
        } else {
            ShaXof xof(seed);
            ApplyXorKeystream(s, xof);
            // Fresh XOF from the same seed for the balanced permutation
            // (independent of keystream consumption above).
            ApplyBalancedPermutationFromSeed(s, seed);
        }
    }
}

void ApplyBalancedPermutation(std::vector<int64_t>& s, const std::vector<uint32_t>& pi)
{
    std::vector<int64_t> tmp(s.size());
    for (uint32_t i = 0; i < static_cast<uint32_t>(s.size()); ++i) {
        tmp[pi[i]] = s[i];
    }
    s = std::move(tmp);
}

void ApplyBalancedPermutationParallel(std::vector<int64_t>& s,
                                      const std::vector<uint32_t>& pi,
                                      uint32_t threads)
{
    std::vector<int64_t> tmp(s.size());
    ParallelForCoupled(s.size(), threads, [&](size_t i) {
        tmp[pi[i]] = s[i];
    });
    s = std::move(tmp);
}

/**
 * Non-affine Extract (C3.d / C5): ExtractMXTileInt64 per 32-wide tile.
 * Lookup-argument-shaped for Stage E (see header note).
 */
[[nodiscard]] bool ExtractActiveState(const uint256& prf_key, const std::vector<int64_t>& raw,
                                       std::vector<int8_t>& out)
{
    if (raw.size() != out.size() || raw.size() % kRCMxBlockLen != 0) return false;
    const uint32_t n_tiles = static_cast<uint32_t>(raw.size() / kRCMxBlockLen);
    for (uint32_t t = 0; t < n_tiles; ++t) {
        ExtractMXTileInt64(prf_key, /*i=*/0, /*bj=*/t, raw.data() + t * kRCMxBlockLen,
                           out.data() + t * kRCMxBlockLen);
    }
    return true;
}

[[nodiscard]] bool ExtractActiveStateParallel(const uint256& prf_key,
                                               const std::vector<int64_t>& raw,
                                               std::vector<int8_t>& out,
                                               uint32_t threads)
{
    if (threads <= 1) return ExtractActiveState(prf_key, raw, out);
    if (raw.size() != out.size() || raw.size() % kRCMxBlockLen != 0) return false;
    const size_t n_tiles = raw.size() / kRCMxBlockLen;
    ParallelForCoupled(n_tiles, threads, [&](size_t tile) {
        const size_t offset = tile * kRCMxBlockLen;
        ExtractMXTileInt64(prf_key, /*i=*/0, static_cast<uint32_t>(tile),
                           raw.data() + offset, out.data() + offset);
    });
    return true;
}

/**
 * Device-first ExactGemmS8S8 (mirrors RC ExactGemmS8S8Dispatched):
 * successful device output replaces CPU; empty/failing backend → CPU.
 * Wrong-but-successful backends are NOT silently rescued.
 */
std::vector<int32_t> ExactGemmS8S8Dispatched(const lt::ExactGemmBackend& gemm,
                                             const std::vector<int8_t>& L,
                                             const std::vector<int8_t>& R, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             uint32_t cpu_threads)
{
    const auto run_cpu = [&]() {
        if (cpu_threads > 1) {
            return lt::ExactGemmS8S8Parallel(L, R, rows, inner, cols, cpu_threads);
        }
        return lt::ExactGemmS8S8(L, R, rows, inner, cols);
    };
    if (gemm.gemm_s8s8 == nullptr) {
        return run_cpu();
    }

    std::vector<int32_t> device;
    bool device_ok = false;
    try {
        device_ok = gemm.gemm_s8s8(L, R, rows, inner, cols, device) &&
                    device.size() == static_cast<size_t>(rows) * cols;
    } catch (...) {
        device_ok = false;
    }
    if (!device_ok) {
        return run_cpu();
    }
    // Device-first: never gate digests on getenv (BTX_RC_EXACT_GEMM_COMPARE
    // and friends are miner/harness diagnostics only).
    return device;
}

/** Local lobe GEMM: M×W · W×W → M×W int32, widened to int64 (C3.a). */
void LobeLocalGemm(const int8_t* lobe_rows, const std::vector<int8_t>& page, uint32_t rows,
                   uint32_t lobe_width, int64_t* out_w, const lt::ExactGemmBackend& gemm,
                   uint32_t cpu_threads)
{
    const size_t nL = static_cast<size_t>(rows) * lobe_width;
    std::vector<int8_t> L(lobe_rows, lobe_rows + nL);
    const auto y =
        ExactGemmS8S8Dispatched(gemm, L, page, /*rows=*/rows, lobe_width, lobe_width,
                                cpu_threads);
    if (y.size() != nL) {
        for (size_t i = 0; i < nL; ++i) out_w[i] = 0;
        return;
    }
    for (size_t i = 0; i < nL; ++i) {
        out_w[i] = static_cast<int64_t>(y[i]);
    }
}

bool LobeLocalSeededPageGemm(const uint256& page_seed, const int8_t* lobe_rows,
                             uint32_t rows, uint32_t lobe_width, int64_t* out_w,
                             const lt::ExactGemmBackend& gemm)
{
    if (gemm.seeded_page_s8s8 == nullptr || page_seed.IsNull()) return false;
    const size_t nL = static_cast<size_t>(rows) * lobe_width;
    std::vector<int8_t> L(lobe_rows, lobe_rows + nL);
    std::vector<int32_t> y;
    bool ok = false;
    try {
        ok = gemm.seeded_page_s8s8(page_seed, L, rows, lobe_width, y) &&
             y.size() == nL;
    } catch (...) {
        ok = false;
    }
    if (!ok) return false;
    for (size_t i = 0; i < nL; ++i) {
        out_w[i] = static_cast<int64_t>(y[i]);
    }
    return true;
}

uint256 BankRootSeed(const CBlockHeader& header, int32_t height,
                     uint32_t transcript_version)
{
    // Template-scoped: same projection as ComputeTemplateHash (null seeds +
    // zero nonces). Leaving §H.4 seeds in would make the bank vary per nonce
    // and break Q>1 HeadersShareBankTemplate / TryMineRCCoupledBatch.
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const uint256 tmpl_hash = RCBankTemplateHash(header);
    return Sha256TaggedU32(tags.bank, TagLen(tags.bank), tmpl_hash,
                           static_cast<uint32_t>(height));
}

void MaybeZeroSkipPage(std::vector<int8_t>& page, uint32_t page_index,
                       const RCCoupOptions& options)
{
    if (options.skip_bank_page && options.skip_page_index == page_index) {
        std::fill(page.begin(), page.end(), int8_t{0});
    }
}

DistEpisodeResult RunCoupledBarrierDistributedImpl(const CBlockHeader& header, int32_t height,
                                                   const RCCoupParams& params, uint32_t barrier,
                                                   uint32_t n_devices, DistReduceOrder order,
                                                   const lt::ExactGemmBackend& gemm)
{
    // Malformed dims / barrier / device count → REJECT (null digest), never assert.
    if (!ValidateRCCoupParams(params) || barrier >= params.barriers || n_devices < 1) {
        DistEpisodeResult bad;
        bad.n_devices = n_devices;
        bad.order = order;
        return bad;
    }

    const uint32_t n = params.StateBytes();
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    // Distributed path stays on V1 domains (legacy single-page schedule).
    constexpr uint32_t kTv = ENC_RC_V1;
    const auto& tags = RCCoupDomainTagsForVersion(kTv);
    const auto lobe_seeds = DeriveCoupledLobeSeeds(sigma, params, kTv);

    std::vector<int8_t> state(n);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        const auto tile =
            ExpandMxDequantInt8(lobe_seeds[ell], params.lobe_width, params.lobe_width);
        std::memcpy(state.data() + ell * params.lobe_width, tile.data(), params.lobe_width);
    }

    std::vector<std::vector<int64_t>> segs(params.lobes);
    std::vector<std::vector<int64_t>> per_device(n_devices);
    for (uint32_t d = 0; d < n_devices; ++d) {
        per_device[d].assign(params.lobe_width, 0);
    }

    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        // Distributed path stays on legacy single-page schedule (digest-stable).
        const uint32_t page_id =
            SelectCoupledBankPageIds(barrier, ell, params, sigma, /*full=*/false, kTv).front();
        auto page = DeriveCoupledBankPage(header, height, page_id, params, kTv);
        std::vector<int64_t> row(params.lobe_width, 0);
        LobeLocalGemm(state.data() + ell * params.lobe_width, page, /*rows=*/1,
                      params.lobe_width, row.data(), gemm, /*cpu_threads=*/1);
        segs[ell] = row;
        const uint32_t owner = DeviceForSegment(ell, n_devices);
        for (uint32_t c = 0; c < params.lobe_width; ++c) {
            per_device[owner][c] += row[c];
        }
    }

    std::vector<int64_t> lobe_sum(params.lobe_width, 0);
    for (const auto& seg : segs) {
        for (uint32_t c = 0; c < params.lobe_width; ++c) lobe_sum[c] += seg[c];
    }
    const auto reduced = ReduceDevicePartials(per_device, order);
    if (reduced != lobe_sum) {
        DistEpisodeResult bad;
        bad.n_devices = n_devices;
        bad.order = order;
        return bad;
    }

    std::vector<int64_t> acc(n, 0);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        std::memcpy(acc.data() + ell * params.lobe_width, segs[ell].data(),
                    params.lobe_width * sizeof(int64_t));
    }
    const auto pi = DeriveCoupledBalancedPermutation(sigma, barrier, params, kTv);
    ApplyBalancedPermutation(acc, pi);
    ApplyAllToAllMix(acc, sigma, barrier, n, dc::RCCoupMaterialExchangeActive(),
                     dc::kRCCoupExchangeRowsDefault, RCCoupUseMixU64Wrap(params), &tags);

    const uint256 extract_seed =
        Sha256TaggedU32U32(tags.extract, TagLen(tags.extract), sigma, barrier,
                           /*unused=*/0);
    std::vector<int8_t> extracted(n);
    if (!ExtractActiveState(lt::DeriveMatExpandPrfKey(extract_seed), acc, extracted)) {
        DistEpisodeResult bad;
        bad.n_devices = n_devices;
        bad.order = order;
        return bad;
    }

    DistEpisodeResult out;
    out.pre_extract_sum = std::move(acc);
    out.extracted = std::move(extracted);
    out.n_segs = params.lobes;
    out.n_devices = n_devices;
    out.order = order;
    {
        std::vector<unsigned char> buf;
        buf.reserve(32 + out.pre_extract_sum.size() * 8 + out.extracted.size());
        const char tag[] = "BTX_RC_COUP_DIST_V1";
        buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tag),
                   reinterpret_cast<const unsigned char*>(tag) + sizeof(tag) - 1);
        for (int64_t v : out.pre_extract_sum) {
            unsigned char le[8];
            WriteLE64(le, static_cast<uint64_t>(v));
            buf.insert(buf.end(), le, le + 8);
        }
        buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(out.extracted.data()),
                   reinterpret_cast<const unsigned char*>(out.extracted.data()) +
                       out.extracted.size());
        out.digest = Sha256dBytes(buf.data(), buf.size());
    }
    return out;
}

} // namespace

CBlockHeader ProjectRCBankTemplateHeader(const CBlockHeader& header)
{
    CBlockHeader tmpl{header};
    tmpl.nNonce64 = 0;
    tmpl.nNonce = 0;
    tmpl.seed_a.SetNull();
    tmpl.seed_b.SetNull();
    tmpl.matmul_digest.SetNull();
    return tmpl;
}

uint256 RCBankTemplateHash(const CBlockHeader& header)
{
    // Equivalent to ComputeTemplateHash: null seeds + zero nonces into
    // ComputeMatMulHeaderHash (matmul_digest is not part of that preimage).
    return matmul::ComputeMatMulHeaderHash(ProjectRCBankTemplateHeader(header));
}

bool ValidateRCCoupParams(const RCCoupParams& p)
{
    if (p.barriers == 0 || p.lobes == 0 || p.lobe_width == 0 || p.bank_pages == 0) {
        return false;
    }
    if (p.rows_per_lobe == 0 || p.pages_per_barrier_lobe == 0) return false;
    // C5: production barrier count is 4–8 (toy=4, medium=8).
    if (p.barriers < 4 || p.barriers > 8) return false;
    if (p.lobe_width % 32 != 0) return false;
    const uint32_t n = p.StateBytes();
    if (n % 32 != 0) return false;
    if ((n & (n - 1)) != 0) return false; // power of two for butterfly
    return true;
}

RCCoupParams MakeToyRCCoupParams()
{
    RCCoupParams p;
    p.barriers = kRCCoupRounds;
    p.lobes = kRCCoupLobes;
    p.lobe_width = kRCCoupLobeWidth;
    p.bank_pages = kRCCoupBankPages;
    p.rows_per_lobe = 1;
    p.pages_per_barrier_lobe = dc::kRCCoupPagesPerBarrierLobe;
    return p;
}

RCCoupParams MakeMediumRCCoupParams()
{
    RCCoupParams p;
    p.barriers = 8;
    p.lobes = 8;
    p.lobe_width = 64;
    p.bank_pages = 32;
    p.rows_per_lobe = 1;
    p.pages_per_barrier_lobe = dc::kRCCoupPagesPerBarrierLobe;
    return p;
}

RCCoupParams MakeProductionRCCoupParams()
{
    // V2 production (heights INT32_MAX):
    //   int8 expanded = 768 × 8192² = 48 GiB
    //   packed (×17/32) ≈ 25.5 GiB — fits a 32 GiB consumer card
    //   M=1, pages/slot=12 → 8×8×12 covers 768 once
    RCCoupParams p;
    p.barriers = 8;
    p.lobes = 8;
    p.lobe_width = 8192;
    p.bank_pages = 768;
    p.rows_per_lobe = 1;
    p.pages_per_barrier_lobe = dc::kRCCoupPagesPerBarrierLobe;
    return p;
}

RCCoupParams MakeProductionV3RCCoupParams()
{
    // V3 hypothesis (heights INT32_MAX; TMTO audit may NO-GO):
    //   M=128, W=8192, pages=1536, pages/slot=24
    //   packed ≈ 51 GiB, int8 96 GiB, MACs = 12 TiMAC, coverage 1536
    // Pair with MakeV3RCCoupOptions() (exchange_rounds=4 → 4 GiB digest-affecting
    // material exchange). Params alone do not set exchange_rounds.
    RCCoupParams p;
    p.barriers = 8;
    p.lobes = 8;
    p.lobe_width = 8192;
    p.bank_pages = 1536;
    p.rows_per_lobe = 128;
    p.pages_per_barrier_lobe = dc::kRCCoupPagesPerBarrierLobeV3;
    return p;
}

RCCoupOptions MakeV3RCCoupOptions()
{
    RCCoupOptions o;
    o.transcript_version = ENC_RC_V3;
    o.material_exchange = true;
    o.exchange_rows = 128;
    o.exchange_rounds = 4;
    return o;
}

RCCoupOptions MakeV4RCCoupOptions()
{
    RCCoupOptions o = MakeV3RCCoupOptions();
    o.transcript_version = ENC_RC_V4;
    return o;
}

RCCoupOptions MakeMediumV3RCCoupOptions()
{
    RCCoupOptions o;
    o.transcript_version = ENC_RC_V3;
    // exchange_rounds=0: CI medium-V3 golden pins independent V3 domains +
    // uint64-wrap Mix without the 4-round exchange cost.
    return o;
}

RCCoupOptions MakeMediumV4RCCoupOptions()
{
    RCCoupOptions o = MakeMediumV3RCCoupOptions();
    o.transcript_version = ENC_RC_V4;
    return o;
}

RCCoupParams MakeMediumV3RCCoupParams()
{
    // Ratio-preserving CI toy for V3 (coverage + Mix u64-wrap path):
    //   4×4×4 = 64 pages; M=32 ≥ 32 → uint64 wrap Mix; W=64 MX-aligned.
    RCCoupParams p;
    p.barriers = 4;
    p.lobes = 4;
    p.lobe_width = 64;
    p.bank_pages = 64;
    p.rows_per_lobe = 32;
    p.pages_per_barrier_lobe = 4;
    return p;
}

RCCoupParams ResolveRCCoupParams(const Consensus::Params& p)
{
    // F8: profile × toydims matrix. Invalid profile → zero params → fail closed.
    switch (p.nMatMulRCCoupledProfile) {
    case 4:
        return p.fMatMulRCCoupledUseToyDims ? MakeMediumV3RCCoupParams()
                                            : MakeProductionV3RCCoupParams();
    case 2:
        return p.fMatMulRCCoupledUseToyDims ? MakeToyRCCoupParams()
                                            : MakeMediumRCCoupParams();
    case 3:
        return p.fMatMulRCCoupledUseToyDims ? MakeMediumV3RCCoupParams()
                                            : MakeProductionV3RCCoupParams();
    default: {
        // Explicit zeros — RCCoupParams{} would apply default member initializers
        // and look like a valid toy shape.
        RCCoupParams z;
        z.barriers = 0;
        z.lobes = 0;
        z.lobe_width = 0;
        z.bank_pages = 0;
        z.rows_per_lobe = 0;
        z.pages_per_barrier_lobe = 0;
        return z;
    }
    }
}

RCCoupOptions ResolveRCCoupOptions(const Consensus::Params& p)
{
    // F7/F8: profile=4 selects proof-friendly V4 domains; profile=3 selects
    // V3 transcript domains; profile=2 keeps V1 tags.
    switch (p.nMatMulRCCoupledProfile) {
    case 4:
        return p.fMatMulRCCoupledUseToyDims ? MakeMediumV4RCCoupOptions()
                                            : MakeV4RCCoupOptions();
    case 3:
        return p.fMatMulRCCoupledUseToyDims ? MakeMediumV3RCCoupOptions()
                                            : MakeV3RCCoupOptions();
    case 2:
    default:
        return RCCoupOptions{};
    }
}

RCCoupOptions MakeCpuRCCoupReplayOptions(const RCCoupParams& params,
                                         RCCoupOptions options)
{
    constexpr uint64_t kMaxResidentReplayBytes = 8ull << 30;
    if (EstimateRCCoupResidentPeakBytes(params) > kMaxResidentReplayBytes) {
        options.mode = RCCoupExecMode::Streamed;
    }
    const uint32_t threads =
        std::min<uint32_t>(
            64, std::max<uint32_t>(1, std::thread::hardware_concurrency()));
    if (threads >= 4) {
        // The bank is a separate deterministic input to the final episode hash:
        // reserve a bounded third of the host for its page producer + ordered
        // SHA stream while the remaining workers execute the stateful episode.
        options.bank_expansion_threads = std::max<uint32_t>(2, threads / 3U);
        options.expansion_threads = threads - options.bank_expansion_threads;
        options.cpu_gemm_threads = options.expansion_threads;
        options.pipeline_cpu_page_gemm = options.expansion_threads > 1;
        options.overlap_cpu_bank_episode = true;
    } else {
        options.bank_expansion_threads = threads;
        options.expansion_threads = threads;
        options.cpu_gemm_threads = threads;
        options.pipeline_cpu_page_gemm = threads > 1;
        options.overlap_cpu_bank_episode = false;
    }
    options.bank_root_cache.reset();
    return options;
}

uint64_t MaxRCCoupPageSumAbsBound(const RCCoupParams& p)
{
    // |acc| ≤ P · W · 127² after P page-sums (int8±127 ExactGemm lanes).
    if (p.pages_per_barrier_lobe == 0 || p.lobe_width == 0) return 0;
    const uint64_t pw = static_cast<uint64_t>(p.pages_per_barrier_lobe) * p.lobe_width;
    constexpr uint64_t kProd = static_cast<uint64_t>(kRCCoupInt8ProdAbsMax);
    if (pw > std::numeric_limits<uint64_t>::max() / kProd) {
        return std::numeric_limits<uint64_t>::max();
    }
    return pw * kProd;
}

uint64_t MaxRCCoupPostMixAbsBound(const RCCoupParams& p)
{
    // Conservative: unnormalized butterfly grows by at most StateBytes() = n.
    const uint64_t page_bound = MaxRCCoupPageSumAbsBound(p);
    const uint64_t n = p.StateBytes();
    if (page_bound == 0 || n == 0) return 0;
    if (page_bound > std::numeric_limits<uint64_t>::max() / n) {
        return std::numeric_limits<uint64_t>::max();
    }
    return page_bound * n;
}

bool RCCoupPostMixFitsInt64(const RCCoupParams& p)
{
    return MaxRCCoupPostMixAbsBound(p) <=
           static_cast<uint64_t>(std::numeric_limits<int64_t>::max());
}

bool RCCoupUseMixU64Wrap(const RCCoupParams& p, bool force_signed)
{
    if (force_signed) return false;
    // V3 shapes (M≥32): explicit uint64 wrap. V2 M=1 stays signed int64.
    return p.rows_per_lobe >= 32;
}

bool RCCoupBarrierLoopComplete(const RCCoupParams& p)
{
    // C1–C6 structural checklist (see header). Mix-pattern count is a compile-
    // time constant; ValidateRCCoupParams covers bank/lobe/perm/Extract shape.
    static_assert(kRCCoupMixPatterns >= 2, "C6: need ≥2 mix patterns");
    static_assert(kRCCoupRounds >= 4 && kRCCoupRounds <= 8, "C5: toy barriers in [4,8]");
    return ValidateRCCoupParams(p) && kRCCoupMixPatterns >= 2;
}

uint64_t TotalRCCoupMacs(const RCCoupParams& p)
{
    // M × pages/slot × barriers × lobes × W²  (saturating).
    if (p.barriers == 0 || p.lobes == 0 || p.lobe_width == 0 || p.rows_per_lobe == 0 ||
        p.pages_per_barrier_lobe == 0) {
        return 0;
    }
    const uint64_t w2 = static_cast<uint64_t>(p.lobe_width) * p.lobe_width;
    if (w2 == 0) return 0;
    auto mul_sat = [](uint64_t a, uint64_t b) -> uint64_t {
        if (a == 0 || b == 0) return 0;
        if (a > std::numeric_limits<uint64_t>::max() / b) {
            return std::numeric_limits<uint64_t>::max();
        }
        return a * b;
    };
    uint64_t acc = mul_sat(static_cast<uint64_t>(p.rows_per_lobe),
                           static_cast<uint64_t>(p.pages_per_barrier_lobe));
    acc = mul_sat(acc, static_cast<uint64_t>(p.barriers));
    acc = mul_sat(acc, static_cast<uint64_t>(p.lobes));
    return mul_sat(acc, w2);
}

uint64_t TotalRCCoupPackedBytes(const RCCoupParams& p)
{
    // pages × W² × 17/32 — integer form: pages × W² × 17 / 32
    if (p.bank_pages == 0 || p.lobe_width == 0) return 0;
    const uint64_t w2 = static_cast<uint64_t>(p.lobe_width) * p.lobe_width;
    if (p.bank_pages > std::numeric_limits<uint64_t>::max() / w2) {
        return std::numeric_limits<uint64_t>::max();
    }
    const uint64_t elems = static_cast<uint64_t>(p.bank_pages) * w2;
    // elems * 17 may overflow; check before multiply.
    if (elems > std::numeric_limits<uint64_t>::max() / 17ull) {
        return std::numeric_limits<uint64_t>::max();
    }
    return (elems * 17ull) / 32ull;
}

uint64_t TotalRCCoupExpandedBytes(const RCCoupParams& p)
{
    if (p.bank_pages == 0 || p.lobe_width == 0) return 0;
    const uint64_t w2 = static_cast<uint64_t>(p.lobe_width) * p.lobe_width;
    if (p.bank_pages > std::numeric_limits<uint64_t>::max() / w2) {
        return std::numeric_limits<uint64_t>::max();
    }
    return static_cast<uint64_t>(p.bank_pages) * w2;
}

uint64_t TotalRCCoupExchangeBytes(const RCCoupParams& p, const RCCoupOptions& options)
{
    // exchange_rounds × barriers × StateBytes() × sizeof(int64_t) × 2 (R+W)
    if (!options.material_exchange || options.exchange_rounds == 0) return 0;
    if (p.barriers == 0 || p.StateBytes() == 0) return 0;
    auto mul_sat = [](uint64_t a, uint64_t b) -> uint64_t {
        if (a == 0 || b == 0) return 0;
        if (a > std::numeric_limits<uint64_t>::max() / b) {
            return std::numeric_limits<uint64_t>::max();
        }
        return a * b;
    };
    uint64_t acc = mul_sat(static_cast<uint64_t>(options.exchange_rounds),
                           static_cast<uint64_t>(p.barriers));
    acc = mul_sat(acc, static_cast<uint64_t>(p.StateBytes()));
    acc = mul_sat(acc, static_cast<uint64_t>(sizeof(int64_t)));
    return mul_sat(acc, 2ull);
}

uint64_t EstimateRCCoupStreamedPeakBytes(const RCCoupParams& p)
{
    // Streamed retains one bank page + active int8 state + int64 accumulator.
    const uint64_t page = static_cast<uint64_t>(p.lobe_width) * p.lobe_width;
    const uint64_t state = static_cast<uint64_t>(p.StateBytes());
    const uint64_t acc = state * sizeof(int64_t);
    const uint64_t barrier_roots = static_cast<uint64_t>(p.barriers) * 32;
    return page + state + acc + barrier_roots;
}

uint64_t EstimateRCCoupResidentPeakBytes(const RCCoupParams& p)
{
    const uint64_t page = static_cast<uint64_t>(p.lobe_width) * p.lobe_width;
    const uint64_t bank = static_cast<uint64_t>(p.bank_pages) * page;
    const uint64_t state = static_cast<uint64_t>(p.StateBytes());
    const uint64_t acc = state * sizeof(int64_t);
    const uint64_t barrier_roots = static_cast<uint64_t>(p.barriers) * 32;
    return bank + state + acc + barrier_roots;
}

uint256 FingerprintRCCoupParams(const RCCoupParams& p)
{
    std::vector<unsigned char> buf;
    auto put_u32 = [&](uint32_t v) {
        buf.push_back(static_cast<unsigned char>(v));
        buf.push_back(static_cast<unsigned char>(v >> 8));
        buf.push_back(static_cast<unsigned char>(v >> 16));
        buf.push_back(static_cast<unsigned char>(v >> 24));
    };
    static constexpr char kTag[] = "BTX_RC_COUP_PROD_PARAMS_V1";
    buf.insert(buf.end(), kTag, kTag + sizeof(kTag) - 1);
    put_u32(p.barriers);
    put_u32(p.lobes);
    put_u32(p.lobe_width);
    put_u32(p.bank_pages);
    put_u32(p.rows_per_lobe);
    put_u32(p.pages_per_barrier_lobe);
    put_u32(p.StateBytes());
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 DeriveCoupledBankPageSeed(const CBlockHeader& header, int32_t height, uint32_t page,
                                  const RCCoupParams& params, uint32_t transcript_version)
{
    // Out-of-range page → empty (reject), never assert/crash.
    if (params.bank_pages == 0 || page >= params.bank_pages) return {};
    if (params.lobe_width == 0 || (params.lobe_width % 32) != 0) return {};
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const uint256 bank_root_seed = BankRootSeed(header, height, transcript_version);
    return Sha256TaggedU32(tags.bank, TagLen(tags.bank), bank_root_seed, page);
}

std::vector<int8_t> DeriveCoupledBankPage(const CBlockHeader& header, int32_t height,
                                          uint32_t page, const RCCoupParams& params,
                                          uint32_t transcript_version,
                                          uint32_t expansion_threads)
{
    const uint256 page_seed =
        DeriveCoupledBankPageSeed(header, height, page, params, transcript_version);
    if (page_seed.IsNull()) return {};
    if (expansion_threads > 1) {
        return ExpandMxDequantInt8Parallel(page_seed, params.lobe_width, params.lobe_width,
                                           expansion_threads);
    }
    return ExpandMxDequantInt8(page_seed, params.lobe_width, params.lobe_width);
}

std::vector<std::vector<int8_t>> DeriveCoupledBankPages(const CBlockHeader& header,
                                                        int32_t height,
                                                        const RCCoupParams& params,
                                                        uint32_t transcript_version,
                                                        uint32_t expansion_threads)
{
    std::vector<std::vector<int8_t>> pages(params.bank_pages);
    for (uint32_t p = 0; p < params.bank_pages; ++p) {
        pages[p] = DeriveCoupledBankPage(header, height, p, params, transcript_version,
                                         expansion_threads);
    }
    return pages;
}

std::vector<std::vector<int8_t>> DeriveCoupledBankPages(const CBlockHeader& header,
                                                        int32_t height)
{
    return DeriveCoupledBankPages(header, height, MakeToyRCCoupParams(), ENC_RC_V1);
}

std::vector<uint256> DeriveCoupledLobeSeeds(const uint256& sigma, const RCCoupParams& params,
                                            uint32_t transcript_version)
{
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    std::vector<uint256> out(params.lobes);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        out[ell] = Sha256TaggedU32(tags.lobe, TagLen(tags.lobe), sigma, ell);
    }
    return out;
}

std::array<uint256, kRCCoupLobes> DeriveCoupledLobeSeeds(const uint256& sigma)
{
    const auto v = DeriveCoupledLobeSeeds(sigma, MakeToyRCCoupParams(), ENC_RC_V1);
    std::array<uint256, kRCCoupLobes> out{};
    for (uint32_t i = 0; i < kRCCoupLobes; ++i) out[i] = v[i];
    return out;
}

bool RCCoupUsesProofFriendlyPermutation(uint32_t transcript_version)
{
    return transcript_version == ENC_RC_V4;
}

RCCoupProofFriendlyPermutationSpec DeriveCoupledProofFriendlyPermutationSpec(
    const uint256& sigma, uint32_t barrier, const RCCoupParams& params,
    uint32_t transcript_version)
{
    RCCoupProofFriendlyPermutationSpec spec;
    const uint32_t n = params.StateBytes();
    if (!RCCoupUsesProofFriendlyPermutation(transcript_version)) return spec;
    if (n < 2 || (n & (n - 1)) != 0) return spec;

    spec.n = n;
    for (uint32_t t = n; t > 1; t >>= 1) ++spec.bits;
    spec.out_to_in_bit.resize(spec.bits);
    spec.xor_mask_bit.resize(spec.bits);
    for (uint32_t i = 0; i < spec.bits; ++i) spec.out_to_in_bit[i] = i;

    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const uint256 perm_seed =
        Sha256TaggedU32(tags.perm, TagLen(tags.perm), sigma, barrier);
    ShaXof xof(perm_seed);
    for (uint32_t i = spec.bits - 1; i > 0; --i) {
        const uint32_t j = xof.NextU32() % (i + 1);
        const uint32_t tmp = spec.out_to_in_bit[i];
        spec.out_to_in_bit[i] = spec.out_to_in_bit[j];
        spec.out_to_in_bit[j] = tmp;
    }
    for (uint32_t i = 0; i < spec.bits; ++i) spec.xor_mask_bit[i] = xof.NextU32() & 1u;
    return spec;
}

uint32_t ApplyCoupledProofFriendlyPermutationIndex(
    uint32_t src, const RCCoupProofFriendlyPermutationSpec& spec)
{
    if (spec.n == 0 || src >= spec.n || spec.out_to_in_bit.size() != spec.bits ||
        spec.xor_mask_bit.size() != spec.bits) {
        return spec.n;
    }
    uint32_t dst = 0;
    for (uint32_t out_bit = 0; out_bit < spec.bits; ++out_bit) {
        const uint32_t in_bit = spec.out_to_in_bit[out_bit];
        const uint32_t bit = ((src >> in_bit) & 1u) ^ spec.xor_mask_bit[out_bit];
        dst |= bit << out_bit;
    }
    return dst;
}

uint32_t InvertCoupledProofFriendlyPermutationIndex(
    uint32_t dst, const RCCoupProofFriendlyPermutationSpec& spec)
{
    if (spec.n == 0 || dst >= spec.n || spec.out_to_in_bit.size() != spec.bits ||
        spec.xor_mask_bit.size() != spec.bits) {
        return spec.n;
    }
    uint32_t src = 0;
    for (uint32_t out_bit = 0; out_bit < spec.bits; ++out_bit) {
        const uint32_t in_bit = spec.out_to_in_bit[out_bit];
        const uint32_t bit = ((dst >> out_bit) & 1u) ^ spec.xor_mask_bit[out_bit];
        src |= bit << in_bit;
    }
    return src;
}

std::vector<uint32_t> DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier,
                                                       const RCCoupParams& params,
                                                       uint32_t transcript_version)
{
    const uint32_t n = params.StateBytes();
    if (RCCoupUsesProofFriendlyPermutation(transcript_version)) {
        const auto spec =
            DeriveCoupledProofFriendlyPermutationSpec(sigma, barrier, params, transcript_version);
        std::vector<uint32_t> pi(n);
        for (uint32_t i = 0; i < n; ++i) pi[i] = ApplyCoupledProofFriendlyPermutationIndex(i, spec);
        return pi;
    }
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const uint256 perm_seed =
        Sha256TaggedU32(tags.perm, TagLen(tags.perm), sigma, barrier);
    ShaXof xof(perm_seed);
    std::vector<uint32_t> pi(n);
    for (uint32_t i = 0; i < n; ++i) {
        pi[i] = i;
    }
    // Fisher–Yates: every index hit exactly once; fixed N iterations (C4).
    for (uint32_t i = n - 1; i > 0; --i) {
        const uint32_t j = xof.NextU32() % (i + 1);
        const uint32_t tmp = pi[i];
        pi[i] = pi[j];
        pi[j] = tmp;
    }
    return pi;
}

std::vector<uint32_t> DeriveCoupledBalancedPermutationParallel(
    const uint256& sigma, uint32_t barrier, const RCCoupParams& params,
    uint32_t transcript_version, uint32_t threads)
{
    const uint32_t n = params.StateBytes();
    if (threads <= 1 || n < 2) {
        return DeriveCoupledBalancedPermutation(sigma, barrier, params, transcript_version);
    }
    if (RCCoupUsesProofFriendlyPermutation(transcript_version)) {
        const auto spec = DeriveCoupledProofFriendlyPermutationSpec(
            sigma, barrier, params, transcript_version);
        std::vector<uint32_t> pi(n);
        ParallelForCoupled(n, threads, [&](size_t i) {
            pi[i] = ApplyCoupledProofFriendlyPermutationIndex(
                static_cast<uint32_t>(i), spec);
        });
        return pi;
    }

    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const uint256 perm_seed =
        Sha256TaggedU32(tags.perm, TagLen(tags.perm), sigma, barrier);
    const size_t draws = n - 1U;
    std::vector<uint32_t> random(draws);
    const size_t blocks = (draws + 7U) / 8U;
    ParallelForCoupled(blocks, threads, [&](size_t block_index) {
        unsigned char input[32 + 4];
        std::memcpy(input, perm_seed.data(), 32);
        WriteLE32(input + 32, static_cast<uint32_t>(block_index));
        uint8_t hash[CSHA256::OUTPUT_SIZE];
        CSHA256().Write(input, sizeof(input)).Finalize(hash);
        const size_t draw0 = block_index * 8U;
        for (size_t j = 0; j < 8 && draw0 + j < draws; ++j) {
            random[draw0 + j] = ReadLE32(hash + j * sizeof(uint32_t));
        }
    });

    std::vector<uint32_t> pi(n);
    ParallelForCoupled(n, threads, [&](size_t i) {
        pi[i] = static_cast<uint32_t>(i);
    });
    size_t draw = 0;
    for (uint32_t i = n - 1; i > 0; --i) {
        const uint32_t j = random[draw++] % (i + 1);
        const uint32_t tmp = pi[i];
        pi[i] = pi[j];
        pi[j] = tmp;
    }
    return pi;
}

std::array<uint32_t, kRCCoupStateBytes> DeriveCoupledBalancedPermutation(const uint256& sigma,
                                                                         uint32_t barrier)
{
    const auto v =
        DeriveCoupledBalancedPermutation(sigma, barrier, MakeToyRCCoupParams(), ENC_RC_V1);
    std::array<uint32_t, kRCCoupStateBytes> out{};
    for (uint32_t i = 0; i < kRCCoupStateBytes; ++i) out[i] = v[i];
    return out;
}

bool IsBalancedPermutation(const std::vector<uint32_t>& pi, uint32_t n)
{
    if (pi.size() != n) return false;
    std::vector<bool> seen(n, false);
    for (uint32_t i = 0; i < n; ++i) {
        if (pi[i] >= n) return false;
        if (seen[pi[i]]) return false;
        seen[pi[i]] = true;
    }
    return true;
}

bool IsBalancedPermutation(const std::array<uint32_t, kRCCoupStateBytes>& pi)
{
    return IsBalancedPermutation(
        std::vector<uint32_t>(pi.begin(), pi.end()), kRCCoupStateBytes);
}

std::vector<uint32_t> SelectCoupledBankPageIds(uint32_t barrier, uint32_t lobe,
                                               const RCCoupParams& params, const uint256& sigma,
                                               bool full_bank_schedule,
                                               uint32_t transcript_version)
{
    // Malformed entry → empty page list (caller rejects), never assert/crash.
    if (params.bank_pages == 0) return {};
    if (params.barriers != 0 && barrier >= params.barriers) return {};
    if (params.lobes != 0 && lobe >= params.lobes) return {};
    if (!full_bank_schedule) {
        return {static_cast<uint32_t>((barrier + lobe) % params.bank_pages)};
    }

    // Frozen episode-global balanced permutation of [0, bank_pages).
    // Slot (barrier, lobe, k) → perm[(barrier*lobes+lobe)*P + k] (mod bank_pages).
    // V2: 8×8×12 = 768; V3: 8×8×24 = 1536 when bank_pages matches.
    const uint32_t P = params.pages_per_barrier_lobe == 0 ? dc::kRCCoupPagesPerBarrierLobe
                                                          : params.pages_per_barrier_lobe;
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const uint256 perm_seed =
        Sha256TaggedU32(tags.full_bank, TagLen(tags.full_bank), sigma, params.bank_pages);
    ShaXof xof(perm_seed);
    std::vector<uint32_t> perm(params.bank_pages);
    for (uint32_t i = 0; i < params.bank_pages; ++i) {
        perm[i] = i;
    }
    for (uint32_t i = params.bank_pages - 1; i > 0; --i) {
        const uint32_t j = xof.NextU32() % (i + 1);
        const uint32_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
    const uint64_t base =
        (static_cast<uint64_t>(barrier) * params.lobes + lobe) * static_cast<uint64_t>(P);
    std::vector<uint32_t> out(P);
    for (uint32_t k = 0; k < P; ++k) {
        out[k] = perm[static_cast<size_t>((base + k) % params.bank_pages)];
    }
    return out;
}

uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header, int32_t height,
                                        const RCCoupOptions& options)
{
    return RecomputeCoupledPuzzleReference(header, height, MakeToyRCCoupParams(), options, {},
                                           nullptr, nullptr);
}

uint256 MineCoupledPuzzle(const CBlockHeader& header, int32_t height,
                          const RCCoupParams& params, const lt::ExactGemmBackend& gemm,
                          const RCCoupOptions& options, RCCoupTiming* out_timing)
{
    return RecomputeCoupledPuzzleReference(header, height, params, options, gemm, out_timing,
                                           nullptr);
}

uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header, int32_t height,
                                        const RCCoupParams& params,
                                        const RCCoupOptions& options,
                                        const lt::ExactGemmBackend& gemm,
                                        RCCoupTiming* out_timing,
                                        RCCoupEpisodeTranscript* out_tx)
{
    // Consensus-reachable: malformed dims → REJECT (null digest), never assert/crash.
    if (!ValidateRCCoupParams(params)) {
        if (out_tx) *out_tx = RCCoupEpisodeTranscript{};
        return uint256{};
    }
    if (out_timing) *out_timing = RCCoupTiming{};
    const auto t0 = std::chrono::steady_clock::now();
    const uint32_t n = params.StateBytes();
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint32_t tv = options.transcript_version;
    const auto& tags = RCCoupDomainTagsForVersion(tv);
    if (out_tx) {
        *out_tx = RCCoupEpisodeTranscript{};
    }

    const bool streamed = options.mode == RCCoupExecMode::Streamed;
    const bool checkpointed = options.mode == RCCoupExecMode::Checkpointed;
    // SequentialLobes and Resident both keep a full bank; Resident additionally
    // keeps active state across barriers without re-deriving (same as Sequential
    // for the toy CPU path — digests identical by construction).
    const bool retain_bank = options.mode == RCCoupExecMode::SequentialLobes ||
                             options.mode == RCCoupExecMode::Resident;

    // Bank commitment binds the honest epoch/template pages (before any
    // skip_page test mutation). Streamed hashes pages without retaining them.
    // Independent CPU replay may defer the join until after the barriers:
    // bank_root and the barrier roots are independent inputs to the final hash.
    struct BankResult {
        uint256 root;
        double elapsed_s{0};
    };
    uint256 bank_root;
    std::vector<std::vector<int8_t>> pages;
    std::future<BankResult> bank_future;
    const uint32_t bank_threads =
        options.bank_expansion_threads == 0
            ? options.expansion_threads
            : options.bank_expansion_threads;
    const auto compute_streamed_bank = [&] {
        const auto started = std::chrono::steady_clock::now();
        BankResult result;
        result.root = BankCommitmentStreaming(
            header, height, params, tv, bank_threads,
            options.pipeline_bank_commitment, gemm,
            options.bank_root_cache, out_timing);
        result.elapsed_s =
            std::chrono::duration<double>(
                std::chrono::steady_clock::now() - started)
                .count();
        return result;
    };
    const bool can_overlap_cpu_bank =
        streamed && out_tx == nullptr && !options.skip_bank_page &&
        options.overlap_cpu_bank_episode && bank_threads > 1 &&
        gemm.gemm_s8s8 == nullptr && gemm.gemm_s32s8 == nullptr &&
        gemm.seeded_page_s8s8 == nullptr && gemm.seeded_page_s8 == nullptr;
    if (can_overlap_cpu_bank) {
        try {
            bank_future =
                std::async(std::launch::async, compute_streamed_bank);
            if (out_timing) out_timing->bank_episode_overlap = true;
        } catch (...) {
            bank_future = {};
        }
    }
    if (!bank_future.valid()) {
        const auto t_bank0 = std::chrono::steady_clock::now();
        if (streamed) {
            const BankResult result = compute_streamed_bank();
            bank_root = result.root;
            if (out_timing) out_timing->bank_s = result.elapsed_s;
        } else {
            const auto pages_commit = DeriveCoupledBankPages(header, height, params, tv);
            bank_root = BankCommitment(pages_commit, params.bank_pages, params.lobe_width, tags);
            if (retain_bank) {
                pages = pages_commit;
                if (options.skip_bank_page && options.skip_page_index < params.bank_pages) {
                    std::fill(pages[options.skip_page_index].begin(),
                              pages[options.skip_page_index].end(), int8_t{0});
                }
            }
            if (out_timing) {
                out_timing->bank_s = std::chrono::duration<double>(
                                         std::chrono::steady_clock::now() - t_bank0)
                                         .count();
            }
        }
        if (bank_root.IsNull()) return uint256{};
        if (out_tx) out_tx->bank_root = bank_root;
    }

    std::vector<int8_t> state(n);
    {
        const auto t_activation0 = std::chrono::steady_clock::now();
        const auto lobe_seeds = DeriveCoupledLobeSeeds(sigma, params, tv);
        const uint32_t M0 = params.rows_per_lobe == 0 ? 1 : params.rows_per_lobe;
        const uint32_t W0 = params.lobe_width;
        const uint32_t lobe_stride0 = M0 * W0;
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            // Nonce-fresh lobe activation (C2): first M rows of a W×W MX tile
            // (M>=32 V3 profiles can expand that exact prefix directly because
            // both mantissa and row-block scale streams are prefix-stable).
            const bool direct_prefix = M0 >= kRCMxBlockLen &&
                                       (M0 % kRCMxBlockLen) == 0;
            const uint32_t expand_rows = direct_prefix ? M0 : W0;
            const auto activation =
                options.expansion_threads > 1
                    ? ExpandMxDequantInt8Parallel(lobe_seeds[ell], expand_rows, W0,
                                                  options.expansion_threads)
                    : ExpandMxDequantInt8(lobe_seeds[ell], expand_rows, W0);
            if (activation.size() < lobe_stride0) return uint256{};
            std::memcpy(state.data() + static_cast<size_t>(ell) * lobe_stride0,
                        activation.data(), lobe_stride0);
        }
        if (out_timing) {
            out_timing->activation_s =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t_activation0)
                    .count();
        }
    }

    std::vector<uint256> barrier_roots(params.barriers);
    // Checkpoint buffer: only Extracted active state survives barrier boundaries.
    std::vector<int8_t> checkpoint = state;

    const auto t_bar0 = std::chrono::steady_clock::now();
    for (uint32_t b = 0; b < params.barriers; ++b) {
        if (checkpointed) {
            // Restore from last barrier checkpoint and re-page the bank.
            state = checkpoint;
            pages = DeriveCoupledBankPages(header, height, params, tv);
            if (options.skip_bank_page && options.skip_page_index < params.bank_pages) {
                std::fill(pages[options.skip_page_index].begin(),
                          pages[options.skip_page_index].end(), int8_t{0});
            }
        }

        if (options.skip_barrier && options.skip_barrier_index == b) {
            // Identity pass — shortcut detection must change the digest.
            barrier_roots[b] = BarrierRoot(b, state, tags);
            checkpoint = state;
            if (checkpointed) {
                pages.clear();
                pages.shrink_to_fit();
            }
            continue;
        }

        std::vector<int64_t> acc(n, 0);

        // C3.a — local exact int8 GEMM per lobe vs epoch bank page(s).
        // Consensus lobe order is always 0..L-1 (scheduling-invariant digest).
        // Legacy: one page (barrier+lobe)%bank_pages. Full schedule defaults ON
        // via RCCoupOptions (dc::kRCCoupFullBankScheduleEnabled).
        const bool full_sched = options.full_bank_schedule;
        const uint32_t M = params.rows_per_lobe == 0 ? 1 : params.rows_per_lobe;
        const uint32_t W = params.lobe_width;
        const uint32_t lobe_stride = M * W;
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const auto page_ids =
                SelectCoupledBankPageIds(b, ell, params, sigma, full_sched, tv);
            if (page_ids.empty()) return uint256{};
            int64_t* dest = acc.data() + static_cast<size_t>(ell) * lobe_stride;
            const int8_t* lobe_rows =
                state.data() + static_cast<size_t>(ell) * lobe_stride;
            auto accumulate_partial = [&](const std::vector<int64_t>& partial) {
                const auto t_acc0 = std::chrono::steady_clock::now();
                for (uint32_t i = 0; i < lobe_stride; ++i) {
                    dest[i] += partial[i];
                }
                if (out_timing) {
                    out_timing->accumulate_s +=
                        std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - t_acc0)
                            .count();
                }
            };
            auto try_fused = [&](uint32_t page_id, std::vector<int64_t>& partial) {
                const uint256 page_seed =
                    DeriveCoupledBankPageSeed(header, height, page_id, params, tv);
                const auto t_fused0 = std::chrono::steady_clock::now();
                const bool fused = LobeLocalSeededPageGemm(
                    page_seed, lobe_rows, M, W, partial.data(), gemm);
                if (out_timing) {
                    if (fused) ++out_timing->seeded_page_gemms;
                    out_timing->gemm_s +=
                        std::chrono::duration<double>(
                            std::chrono::steady_clock::now() - t_fused0)
                            .count();
                }
                return fused;
            };

            // One host SHA-NI page producer complements the GPU SHA sampler.
            // Twelve-page groups preserve accumulation order: expand page 0 on
            // host while pages 1..11 use fused CUDA, then GEMM page 0 and add
            // partials in their original schedule order. The 1:11 split tracks
            // the measured producer-rate ratio after the parallel device scan.
            constexpr size_t kHostGpuGroup = 12;
            size_t page_cursor = 0;
            const bool can_overlap_host =
                streamed && out_tx == nullptr && !options.skip_bank_page &&
                options.expansion_threads > 1 && gemm.seeded_page_s8s8 != nullptr &&
                gemm.gemm_s8s8 != nullptr;
            if (can_overlap_host) {
                struct HostPage {
                    std::vector<int8_t> bytes;
                    double expand_s{0};
                };
                while (page_cursor + kHostGpuGroup <= page_ids.size()) {
                    const uint32_t host_page_id = page_ids[page_cursor];
                    const uint256 host_seed = DeriveCoupledBankPageSeed(
                        header, height, host_page_id, params, tv);
                    std::future<HostPage> host_future;
                    try {
                        host_future = std::async(
                            std::launch::async,
                            [host_seed, W, threads = options.expansion_threads] {
                                HostPage result;
                                const auto t0 = std::chrono::steady_clock::now();
                                try {
                                    result.bytes = ExpandMxDequantInt8Parallel(
                                        host_seed, W, W, threads);
                                } catch (...) {
                                    result.bytes.clear();
                                }
                                result.expand_s =
                                    std::chrono::duration<double>(
                                        std::chrono::steady_clock::now() - t0)
                                        .count();
                                return result;
                            });
                    } catch (...) {
                        break;
                    }

                    std::vector<std::vector<int64_t>> group(
                        kHostGpuGroup,
                        std::vector<int64_t>(static_cast<size_t>(lobe_stride), 0));
                    for (size_t j = 1; j < kHostGpuGroup; ++j) {
                        if (!try_fused(page_ids[page_cursor + j], group[j])) {
                            const auto t_page0 = std::chrono::steady_clock::now();
                            const auto page = DeriveCoupledBankPage(
                                header, height, page_ids[page_cursor + j], params, tv,
                                options.expansion_threads);
                            if (out_timing) {
                                out_timing->page_expand_s +=
                                    std::chrono::duration<double>(
                                        std::chrono::steady_clock::now() - t_page0)
                                        .count();
                            }
                            const auto t_gemm0 = std::chrono::steady_clock::now();
                            LobeLocalGemm(lobe_rows, page, M, W, group[j].data(), gemm,
                                          options.cpu_gemm_threads);
                            if (out_timing) {
                                out_timing->gemm_s +=
                                    std::chrono::duration<double>(
                                        std::chrono::steady_clock::now() - t_gemm0)
                                        .count();
                            }
                        }
                    }
                    HostPage host_page;
                    try {
                        host_page = host_future.get();
                    } catch (...) {
                        host_page = HostPage{};
                    }
                    if (host_page.bytes.size() != static_cast<size_t>(W) * W) {
                        const auto t_page0 = std::chrono::steady_clock::now();
                        host_page.bytes = DeriveCoupledBankPage(
                            header, height, host_page_id, params, tv,
                            options.expansion_threads);
                        if (out_timing) {
                            out_timing->page_expand_s +=
                                std::chrono::duration<double>(
                                    std::chrono::steady_clock::now() - t_page0)
                                    .count();
                        }
                    } else if (out_timing) {
                        ++out_timing->host_overlap_pages;
                        out_timing->host_overlap_expand_s += host_page.expand_s;
                    }
                    const auto t_gemm0 = std::chrono::steady_clock::now();
                    LobeLocalGemm(lobe_rows, host_page.bytes, M, W, group[0].data(), gemm,
                                  options.cpu_gemm_threads);
                    if (out_timing) {
                        out_timing->gemm_s +=
                            std::chrono::duration<double>(
                                std::chrono::steady_clock::now() - t_gemm0)
                                .count();
                    }
                    for (const auto& partial : group) accumulate_partial(partial);
                    page_cursor += kHostGpuGroup;
                }
            }

            // Independent CPU replay: while page p is consumed by exact GEMM,
            // expand page p+1 on a bounded second worker group. Page results are
            // still accumulated in schedule order and no device callback is used.
            const bool can_pipeline_cpu =
                streamed && out_tx == nullptr && !options.skip_bank_page &&
                options.pipeline_cpu_page_gemm && options.expansion_threads > 1 &&
                options.cpu_gemm_threads > 1 && gemm.gemm_s8s8 == nullptr &&
                gemm.seeded_page_s8s8 == nullptr;
            if (can_pipeline_cpu && page_cursor < page_ids.size()) {
                struct CpuPage {
                    std::vector<int8_t> bytes;
                    double expand_s{0};
                };
                const uint32_t producer_threads =
                    std::max<uint32_t>(1, options.expansion_threads / 2U);
                const uint32_t gemm_threads =
                    std::max<uint32_t>(
                        1, options.cpu_gemm_threads -
                               options.cpu_gemm_threads / 2U);
                const auto start_page = [&](uint32_t page_id) {
                    return std::async(
                        std::launch::async,
                        [&, page_id] {
                            CpuPage result;
                            const auto t_page0 = std::chrono::steady_clock::now();
                            try {
                                result.bytes = DeriveCoupledBankPage(
                                    header, height, page_id, params, tv,
                                    producer_threads);
                            } catch (...) {
                                result.bytes.clear();
                            }
                            result.expand_s =
                                std::chrono::duration<double>(
                                    std::chrono::steady_clock::now() - t_page0)
                                    .count();
                            return result;
                        });
                };

                std::future<CpuPage> current;
                try {
                    current = start_page(page_ids[page_cursor]);
                } catch (...) {
                    current = {};
                }
                while (current.valid() && page_cursor < page_ids.size()) {
                    const uint32_t current_page_id = page_ids[page_cursor];
                    CpuPage host_page;
                    try {
                        host_page = current.get();
                    } catch (...) {
                        host_page = {};
                    }
                    if (host_page.bytes.size() != static_cast<size_t>(W) * W) {
                        const auto t_page0 = std::chrono::steady_clock::now();
                        host_page.bytes = DeriveCoupledBankPage(
                            header, height, current_page_id, params, tv,
                            producer_threads);
                        host_page.expand_s =
                            std::chrono::duration<double>(
                                std::chrono::steady_clock::now() - t_page0)
                                .count();
                    }
                    if (out_timing) {
                        out_timing->page_expand_s += host_page.expand_s;
                    }

                    std::future<CpuPage> next;
                    if (page_cursor + 1 < page_ids.size()) {
                        try {
                            next = start_page(page_ids[page_cursor + 1]);
                        } catch (...) {
                            next = {};
                        }
                    }

                    std::vector<int64_t> partial(
                        static_cast<size_t>(lobe_stride), 0);
                    const auto t_gemm0 = std::chrono::steady_clock::now();
                    LobeLocalGemm(lobe_rows, host_page.bytes, M, W,
                                  partial.data(), gemm, gemm_threads);
                    if (out_timing) {
                        out_timing->gemm_s +=
                            std::chrono::duration<double>(
                                std::chrono::steady_clock::now() - t_gemm0)
                                .count();
                    }
                    accumulate_partial(partial);
                    if (out_timing) ++out_timing->cpu_overlap_pages;
                    ++page_cursor;
                    current = std::move(next);
                }
            }

            for (; page_cursor < page_ids.size(); ++page_cursor) {
                const uint32_t page_id = page_ids[page_cursor];
                std::vector<int64_t> partial(static_cast<size_t>(lobe_stride), 0);
                std::vector<int8_t> page_for_tx;
                if (streamed) {
                    // Mining-only fast path: generate the deterministic page and
                    // consume it in one device operation. Validation/GKR transcript
                    // capture/shortcut tests retain the explicit CPU page oracle.
                    bool fused = false;
                    if (out_tx == nullptr && !options.skip_bank_page &&
                        gemm.seeded_page_s8s8 != nullptr) {
                        fused = try_fused(page_id, partial);
                    }
                    if (!fused) {
                        const auto t_page0 = std::chrono::steady_clock::now();
                        auto page = DeriveCoupledBankPage(
                            header, height, page_id, params, tv,
                            options.expansion_threads);
                        if (out_timing) {
                            out_timing->page_expand_s +=
                                std::chrono::duration<double>(
                                    std::chrono::steady_clock::now() - t_page0)
                                    .count();
                        }
                        MaybeZeroSkipPage(page, page_id, options);
                        if (out_tx) page_for_tx = page;
                        const auto t_gemm0 = std::chrono::steady_clock::now();
                        LobeLocalGemm(lobe_rows, page, M, W, partial.data(), gemm,
                                      options.cpu_gemm_threads);
                        if (out_timing) {
                            out_timing->gemm_s +=
                                std::chrono::duration<double>(
                                    std::chrono::steady_clock::now() - t_gemm0)
                                    .count();
                        }
                    }
                } else {
                    if (out_tx) page_for_tx = pages[page_id];
                    const auto t_gemm0 = std::chrono::steady_clock::now();
                    LobeLocalGemm(lobe_rows, pages[page_id], M, W,
                                  partial.data(), gemm, options.cpu_gemm_threads);
                    if (out_timing) {
                        out_timing->gemm_s +=
                            std::chrono::duration<double>(
                                std::chrono::steady_clock::now() - t_gemm0)
                                .count();
                    }
                }
                if (out_tx) {
                    RCCoupGemmTranscript gt;
                    gt.barrier = b;
                    gt.lobe = ell;
                    gt.page_id = page_id;
                    gt.A.assign(lobe_rows, lobe_rows + lobe_stride);
                    gt.B = std::move(page_for_tx);
                    gt.Y = partial;
                    out_tx->gemms.push_back(std::move(gt));
                }
                accumulate_partial(partial);
            }
        }

        // C3.b — nonce-derived balanced permutation over full active state.
        {
            const auto t_perm0 = std::chrono::steady_clock::now();
            const auto pi =
                options.expansion_threads > 1
                    ? DeriveCoupledBalancedPermutationParallel(
                          sigma, b, params, tv, options.expansion_threads)
                    : DeriveCoupledBalancedPermutation(sigma, b, params, tv);
            if (!IsBalancedPermutation(pi, n)) return uint256{};
            if (options.expansion_threads > 1) {
                ApplyBalancedPermutationParallel(acc, pi, options.expansion_threads);
            } else {
                ApplyBalancedPermutation(acc, pi);
            }
            if (out_timing) {
                out_timing->permutation_s +=
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t_perm0)
                        .count();
            }
        }

        // C3.c — exact integer all-to-all mix (≥2 nonce-relabeled patterns).
        // Material exchange (default ON) absorbs exchange_rows into the mix domain.
        {
            const auto t_mix0 = std::chrono::steady_clock::now();
            ApplyAllToAllMix(acc, sigma, b, n, options.material_exchange, options.exchange_rows,
                             RCCoupUseMixU64Wrap(params, options.force_signed_mix), &tags,
                             options.expansion_threads);
            if (out_timing) {
                out_timing->mix_s +=
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t_mix0)
                        .count();
            }
        }
        // V3: digest-affecting XOR+permute rounds (no-op when exchange_rounds==0).
        {
            const auto t_exchange0 = std::chrono::steady_clock::now();
            ApplyMaterialExchangeRounds(acc, sigma, b, options);
            if (out_timing) {
                out_timing->exchange_s +=
                    std::chrono::duration<double>(
                        std::chrono::steady_clock::now() - t_exchange0)
                        .count();
            }
        }

        // C3.d — non-affine Extract (lookup-argument-shaped for Stage E).
        {
            const auto t_extract0 = std::chrono::steady_clock::now();
            const uint256 extract_seed =
                Sha256TaggedU32U32(tags.extract, TagLen(tags.extract), sigma, b,
                                   /*unused=*/0);
            const uint256 prf_key = lt::DeriveMatExpandPrfKey(extract_seed);
            if (!ExtractActiveStateParallel(
                    prf_key, acc, state, options.expansion_threads)) {
                return uint256{};
            }
            if (out_timing) {
                out_timing->extract_s +=
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t_extract0)
                        .count();
            }

            // C3.e — feed-forward: next barrier reads this Extracted state.
            const auto t_root0 = std::chrono::steady_clock::now();
            barrier_roots[b] = BarrierRoot(b, state, tags);
            if (out_timing) {
                out_timing->barrier_root_s +=
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t_root0)
                        .count();
            }
            if (out_tx) {
                RCCoupExtractTranscript et;
                et.barrier = b;
                et.extract_prf = prf_key;
                et.extract_in = acc;
                et.extract_out = state;
                et.barrier_root = barrier_roots[b];
                out_tx->extracts.push_back(std::move(et));
            }
        }
        checkpoint = state;

        if (checkpointed) {
            // Drop resident bank + int64 scratch; only checkpoint remains.
            pages.clear();
            pages.shrink_to_fit();
            acc.clear();
            acc.shrink_to_fit();
        }
    }
    if (out_timing) {
        out_timing->barriers_s = std::chrono::duration<double>(
                                     std::chrono::steady_clock::now() - t_bar0)
                                     .count();
    }

    if (bank_future.valid()) {
        const auto t_wait0 = std::chrono::steady_clock::now();
        BankResult result;
        try {
            result = bank_future.get();
        } catch (...) {
            return uint256{};
        }
        if (out_timing) {
            out_timing->bank_s = result.elapsed_s;
            out_timing->bank_overlap_wait_s =
                std::chrono::duration<double>(
                    std::chrono::steady_clock::now() - t_wait0)
                    .count();
        }
        bank_root = result.root;
        if (bank_root.IsNull()) return uint256{};
    }

    // episode_digest = SHA256d(episode_tag ‖ bank_root ‖ barrier_roots…)
    const size_t ep_len = TagLen(tags.episode);
    std::vector<unsigned char> buf;
    buf.reserve(ep_len + 32 + params.barriers * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tags.episode),
               reinterpret_cast<const unsigned char*>(tags.episode) + ep_len);
    buf.insert(buf.end(), bank_root.begin(), bank_root.end());
    for (const uint256& root : barrier_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    const uint256 digest = Sha256dBytes(buf.data(), buf.size());
    if (out_tx) {
        out_tx->barrier_roots = barrier_roots;
        out_tx->bank_root = bank_root;
    }
    if (out_timing) {
        out_timing->total_s =
            std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    }
    return digest;
}

DistEpisodeResult RunCoupledBarrierDistributed(const CBlockHeader& header, int32_t height,
                                               const RCCoupParams& params, uint32_t barrier,
                                               uint32_t n_devices, DistReduceOrder order,
                                               const lt::ExactGemmBackend& gemm)
{
    return RunCoupledBarrierDistributedImpl(header, height, params, barrier, n_devices, order,
                                            gemm);
}

bool ApplyCoupledBarrierTail(const uint256& sigma, uint32_t barrier, const RCCoupParams& params,
                             std::vector<int64_t>& acc, std::vector<int8_t>& state_out,
                             uint256* barrier_root_out, const RCCoupOptions& options)
{
    if (!ValidateRCCoupParams(params) || barrier >= params.barriers) return false;
    const uint32_t n = params.StateBytes();
    if (acc.size() != n || state_out.size() != n) return false;
    const uint32_t tv = options.transcript_version;
    const auto& tags = RCCoupDomainTagsForVersion(tv);
    const auto pi = DeriveCoupledBalancedPermutation(sigma, barrier, params, tv);
    if (!IsBalancedPermutation(pi, n)) return false;
    ApplyBalancedPermutation(acc, pi);
    ApplyAllToAllMix(acc, sigma, barrier, n, options.material_exchange, options.exchange_rows,
                     RCCoupUseMixU64Wrap(params, options.force_signed_mix), &tags,
                     options.expansion_threads);
    ApplyMaterialExchangeRounds(acc, sigma, barrier, options);
    const uint256 extract_seed =
        Sha256TaggedU32U32(tags.extract, TagLen(tags.extract), sigma, barrier,
                           /*unused=*/0);
    const uint256 prf_key = lt::DeriveMatExpandPrfKey(extract_seed);
    if (!ExtractActiveStateParallel(
            prf_key, acc, state_out, options.expansion_threads)) {
        return false;
    }
    if (barrier_root_out) *barrier_root_out = BarrierRoot(barrier, state_out, tags);
    return true;
}

uint256 AssembleCoupledEpisodeDigest(const uint256& bank_root,
                                     const std::vector<uint256>& barrier_roots,
                                     uint32_t transcript_version)
{
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    const size_t ep_len = TagLen(tags.episode);
    std::vector<unsigned char> buf;
    buf.reserve(ep_len + 32 + barrier_roots.size() * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tags.episode),
               reinterpret_cast<const unsigned char*>(tags.episode) + ep_len);
    buf.insert(buf.end(), bank_root.begin(), bank_root.end());
    for (const uint256& root : barrier_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 CommitCoupledBankPages(const std::vector<std::vector<int8_t>>& pages,
                               const RCCoupParams& params, uint32_t transcript_version)
{
    const auto& tags = RCCoupDomainTagsForVersion(transcript_version);
    return BankCommitment(pages, params.bank_pages, params.lobe_width, tags);
}

} // namespace matmul::v4::rc
