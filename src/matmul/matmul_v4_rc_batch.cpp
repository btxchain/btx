// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_batch.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <span.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <vector>

namespace matmul::v4::rc {
namespace {

namespace lt = matmul::v4::lt;

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
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(buf, sizeof(buf));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint256 Sha256TaggedU32U32(const char* tag, size_t taglen, const uint256& a, uint32_t x,
                           uint32_t y)
{
    unsigned char buf[32 + 8];
    std::memcpy(buf, a.data(), 32);
    WriteLE32(buf + 32, x);
    WriteLE32(buf + 36, y);
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(buf, sizeof(buf));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

class ShaXof {
public:
    explicit ShaXof(const uint256& seed) : m_seed(seed) {}
    uint32_t NextU32()
    {
        if (m_pos + 4 > 32) Refill();
        const uint32_t v = ReadLE32(m_block + m_pos);
        m_pos += 4;
        return v;
    }
    uint64_t NextU64()
    {
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

uint256 BarrierRoot(uint32_t barrier, const std::vector<int8_t>& state)
{
    std::vector<unsigned char> buf;
    buf.reserve((sizeof(kRCCoupBarrierTag) - 1) + 4 + state.size());
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupBarrierTag),
               reinterpret_cast<const unsigned char*>(kRCCoupBarrierTag) +
                   sizeof(kRCCoupBarrierTag) - 1);
    unsigned char le[4];
    WriteLE32(le, barrier);
    buf.insert(buf.end(), le, le + 4);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(state.data()),
               reinterpret_cast<const unsigned char*>(state.data()) + state.size());
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 BankCommitment(const std::vector<std::vector<int8_t>>& pages, uint32_t bank_pages,
                       uint32_t lobe_width)
{
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(kRCCoupBankTag),
                sizeof(kRCCoupBankTag) - 1);
    const size_t page_bytes = static_cast<size_t>(lobe_width) * lobe_width;
    for (uint32_t p = 0; p < bank_pages; ++p) {
        assert(pages[p].size() == page_bytes);
        outer.Write(reinterpret_cast<const unsigned char*>(pages[p].data()), pages[p].size());
    }
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    outer.Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

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

void MixButterflyDescending(std::vector<int64_t>& s, uint32_t mask, uint32_t n, bool u64_wrap)
{
    assert(n >= 2 && (n & (n - 1)) == 0);
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
                s[pi] = a + b;
                s[pj] = b - a;
            }
        }
    }
}

void ApplyAllToAllMix(std::vector<int64_t>& s, const uint256& sigma, uint32_t barrier,
                      uint32_t n, bool material_exchange = false,
                      uint32_t exchange_rows = dc::kRCCoupExchangeRowsDefault,
                      bool u64_wrap = false)
{
    uint256 mix_seed;
    if (material_exchange) {
        const uint32_t rows = exchange_rows == 0 ? dc::kRCCoupExchangeRowsDefault : exchange_rows;
        mix_seed = Sha256TaggedU32U32(kRCCoupMaterialExchangeTag,
                                      sizeof(kRCCoupMaterialExchangeTag) - 1, sigma, barrier,
                                      rows);
    } else {
        mix_seed = Sha256TaggedU32(kRCCoupMixTag, sizeof(kRCCoupMixTag) - 1, sigma, barrier);
    }
    ShaXof xof(mix_seed);
    const uint32_t mask = xof.NextU32() & (n - 1);
    const uint32_t pattern = barrier % kRCCoupMixPatterns;
    if (pattern == 0) {
        MixButterflyAscending(s, mask, n, u64_wrap);
    } else {
        MixButterflyDescending(s, mask, n, u64_wrap);
    }
}

uint64_t AccXorFold(const std::vector<int64_t>& s)
{
    uint64_t fold = 0;
    for (int64_t v : s) fold ^= static_cast<uint64_t>(v);
    return fold;
}

uint256 ExchangeRoundSeed(const uint256& sigma, uint32_t barrier, uint32_t round, uint64_t fold)
{
    unsigned char buf[32 + 4 + 4 + 8];
    std::memcpy(buf, sigma.data(), 32);
    WriteLE32(buf + 32, barrier);
    WriteLE32(buf + 36, round);
    WriteLE64(buf + 40, fold);
    std::vector<unsigned char> pre;
    pre.reserve((sizeof(kRCCoupMaterialExchangeRoundsTag) - 1) + sizeof(buf));
    pre.insert(pre.end(),
               reinterpret_cast<const unsigned char*>(kRCCoupMaterialExchangeRoundsTag),
               reinterpret_cast<const unsigned char*>(kRCCoupMaterialExchangeRoundsTag) +
                   sizeof(kRCCoupMaterialExchangeRoundsTag) - 1);
    pre.insert(pre.end(), buf, buf + sizeof(buf));
    return Sha256dBytes(pre.data(), pre.size());
}

void ApplyXorKeystream(std::vector<int64_t>& s, ShaXof& xof)
{
    for (int64_t& lane : s) {
        const uint64_t k = xof.NextU64();
        lane = static_cast<int64_t>(static_cast<uint64_t>(lane) ^ k);
    }
}

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
    for (uint32_t i = 0; i < n; ++i) tmp[pi[i]] = s[i];
    s = std::move(tmp);
}

void ApplyMaterialExchangeRounds(std::vector<int64_t>& s, const uint256& sigma, uint32_t barrier,
                                 const RCCoupOptions& options)
{
    if (!options.material_exchange || options.exchange_rounds == 0) return;
    if (s.empty()) return;
    for (uint32_t r = 0; r < options.exchange_rounds; ++r) {
        const uint64_t fold = AccXorFold(s);
        const uint256 seed = ExchangeRoundSeed(sigma, barrier, r, fold);
        {
            ShaXof xof(seed);
            ApplyXorKeystream(s, xof);
        }
        ApplyBalancedPermutationFromSeed(s, seed);
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

void ExtractActiveState(const uint256& prf_key, const std::vector<int64_t>& raw,
                        std::vector<int8_t>& out)
{
    assert(raw.size() == out.size());
    assert(raw.size() % kRCMxBlockLen == 0);
    const uint32_t n_tiles = static_cast<uint32_t>(raw.size() / kRCMxBlockLen);
    for (uint32_t t = 0; t < n_tiles; ++t) {
        ExtractMXTileInt64(prf_key, /*i=*/0, /*bj=*/t, raw.data() + t * kRCMxBlockLen,
                           out.data() + t * kRCMxBlockLen);
    }
}

std::vector<int32_t> ExactGemmS8S8Dispatched(const lt::ExactGemmBackend& gemm,
                                             const std::vector<int8_t>& L,
                                             const std::vector<int8_t>& R, uint32_t rows,
                                             uint32_t inner, uint32_t cols)
{
    const auto run_cpu = [&]() { return lt::ExactGemmS8S8(L, R, rows, inner, cols); };
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
    if (!device_ok) return run_cpu();
    // Device-first: digests must not depend on getenv (compare env is harness-only).
    return device;
}

bool HeadersShareBankTemplate(const std::vector<CBlockHeader>& headers)
{
    if (headers.empty()) return false;
    // Same projection as BankRootSeed / ComputeTemplateHash (null seeds).
    const uint256 th = RCBankTemplateHash(headers[0]);
    for (size_t i = 1; i < headers.size(); ++i) {
        if (RCBankTemplateHash(headers[i]) != th) return false;
    }
    return true;
}

/**
 * Core Q-batch: independent per-nonce state (sigma, lobes, barrier roots).
 * q_limit is the accepted headers.size() ceiling (miner max or harness max).
 */
bool MineRCCoupledBatchIndependent(const std::vector<CBlockHeader>& headers, int32_t height,
                                   const RCCoupParams& params, std::vector<uint256>& digests_out,
                                   uint32_t q_limit, bool use_resident_bank,
                                   const lt::ExactGemmBackend& gemm, const RCCoupOptions& options)
{
    digests_out.clear();
    if (headers.empty() || !ValidateRCCoupParams(params)) return false;
    if (q_limit == 0 || headers.size() > q_limit) return false;
    if (!HeadersShareBankTemplate(headers)) return false;

    // Full-bank / material-exchange follow RCCoupOptions defaults (dc levers ON).
    // Never getenv. Callers may set options.full_bank_schedule=false for legacy.
    RCCoupOptions opts = options;

    const uint32_t Q = static_cast<uint32_t>(headers.size());
    const uint32_t n = params.StateBytes();
    const uint32_t W = params.lobe_width;
    const uint32_t M = params.rows_per_lobe == 0 ? 1 : params.rows_per_lobe;
    const uint32_t lobe_stride = M * W;
    if (n != params.lobes * lobe_stride) return false;

    // Bank is template-scoped — derive once from the canonical projection.
    const auto pages =
        DeriveCoupledBankPages(ProjectRCBankTemplateHeader(headers[0]), height, params);
    const uint256 bank_root = BankCommitment(pages, params.bank_pages, params.lobe_width);
    (void)use_resident_bank; // CPU reference always retains pages for the batch.

    // Independent per-nonce state — never reuse / overwrite a shared slot 0.
    // Lobe fill matches RecomputeCoupledPuzzleReference: first M rows of W×W MX tile.
    std::vector<uint256> sigmas(Q);
    std::vector<std::vector<int8_t>> states(Q, std::vector<int8_t>(n));
    for (uint32_t q = 0; q < Q; ++q) {
        sigmas[q] = matmul::v4::DeriveSigma(headers[q]);
        const auto lobe_seeds = DeriveCoupledLobeSeeds(sigmas[q], params);
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const auto tile = ExpandMxDequantInt8(lobe_seeds[ell], W, W);
            if (tile.size() != static_cast<size_t>(W) * W || lobe_stride > tile.size()) {
                return false;
            }
            std::memcpy(states[q].data() + static_cast<size_t>(ell) * lobe_stride, tile.data(),
                        lobe_stride);
        }
    }

    std::vector<std::vector<uint256>> barrier_roots(Q, std::vector<uint256>(params.barriers));
    const bool mix_u64 = RCCoupUseMixU64Wrap(params, opts.force_signed_mix);

    for (uint32_t b = 0; b < params.barriers; ++b) {
        if (opts.skip_barrier && opts.skip_barrier_index == b) {
            for (uint32_t q = 0; q < Q; ++q) {
                barrier_roots[q][b] = BarrierRoot(b, states[q]);
            }
            continue;
        }

        std::vector<std::vector<int64_t>> accs(Q, std::vector<int64_t>(n, 0));
        const bool full_sched = opts.full_bank_schedule;

        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            // Full schedule: per-header page lists (sigma-dependent) + M-row GEMMs.
            if (full_sched) {
                for (uint32_t q = 0; q < Q; ++q) {
                    const auto page_ids =
                        SelectCoupledBankPageIds(b, ell, params, sigmas[q], true);
                    if (page_ids.empty()) return false;
                    int64_t* dest = accs[q].data() + static_cast<size_t>(ell) * lobe_stride;
                    for (uint32_t page_id : page_ids) {
                        std::vector<int8_t> L(
                            states[q].data() + static_cast<size_t>(ell) * lobe_stride,
                            states[q].data() + static_cast<size_t>(ell) * lobe_stride +
                                lobe_stride);
                        const auto y =
                            ExactGemmS8S8Dispatched(gemm, L, pages[page_id], M, W, W);
                        if (y.size() != lobe_stride) return false;
                        for (uint32_t i = 0; i < lobe_stride; ++i) {
                            dest[i] += static_cast<int64_t>(y[i]);
                        }
                    }
                }
                continue;
            }

            // Stacked / non-full: shared page_id; ExactGemm (Q*M)×W · W×W.
            const uint32_t page_id =
                SelectCoupledBankPageIds(b, ell, params, sigmas[0], false).front();
            std::vector<int8_t> Lstacked(static_cast<size_t>(Q) * lobe_stride);
            for (uint32_t q = 0; q < Q; ++q) {
                std::memcpy(Lstacked.data() + static_cast<size_t>(q) * lobe_stride,
                            states[q].data() + static_cast<size_t>(ell) * lobe_stride,
                            lobe_stride);
            }
            const auto Y = ExactGemmS8S8Dispatched(gemm, Lstacked, pages[page_id], Q * M, W, W);
            if (Y.size() != static_cast<size_t>(Q) * lobe_stride) return false;
            for (uint32_t q = 0; q < Q; ++q) {
                for (uint32_t i = 0; i < lobe_stride; ++i) {
                    accs[q][static_cast<size_t>(ell) * lobe_stride + i] =
                        static_cast<int64_t>(Y[static_cast<size_t>(q) * lobe_stride + i]);
                }
            }
        }

        for (uint32_t q = 0; q < Q; ++q) {
            auto& acc = accs[q];
            const auto pi = DeriveCoupledBalancedPermutation(sigmas[q], b, params);
            assert(IsBalancedPermutation(pi, n));
            ApplyBalancedPermutation(acc, pi);
            ApplyAllToAllMix(acc, sigmas[q], b, n, opts.material_exchange, opts.exchange_rows,
                             mix_u64);
            ApplyMaterialExchangeRounds(acc, sigmas[q], b, opts);
            const uint256 extract_seed = Sha256TaggedU32U32(
                kRCCoupExtractTag, sizeof(kRCCoupExtractTag) - 1, sigmas[q], b, 0);
            ExtractActiveState(lt::DeriveMatExpandPrfKey(extract_seed), acc, states[q]);
            barrier_roots[q][b] = BarrierRoot(b, states[q]);
        }
    }

    digests_out.resize(Q);
    for (uint32_t q = 0; q < Q; ++q) {
        std::vector<unsigned char> buf;
        buf.reserve(sizeof(kRCCoupEpisodeTag) - 1 + 32 + params.barriers * 32);
        buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag),
                   reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag) +
                       sizeof(kRCCoupEpisodeTag) - 1);
        buf.insert(buf.end(), bank_root.begin(), bank_root.end());
        for (const uint256& root : barrier_roots[q]) {
            buf.insert(buf.end(), root.begin(), root.end());
        }
        digests_out[q] = Sha256dBytes(buf.data(), buf.size());
    }
    return true;
}

} // namespace

bool TryMineRCCoupledBatch(const std::vector<CBlockHeader>& headers, int32_t height,
                           const RCCoupParams& params, std::vector<uint256>& digests_out,
                           const RCMinerBatchConfig& cfg, const lt::ExactGemmBackend& gemm,
                           const RCCoupOptions& options)
{
    if (cfg.Q == 0 || cfg.Q > dc::kRCMinerBatchQMax) return false;
    return MineRCCoupledBatchIndependent(headers, height, params, digests_out,
                                         dc::kRCMinerBatchQMax, cfg.use_resident_bank, gemm,
                                         options);
}

bool RunCoupledQSweep(const std::vector<CBlockHeader>& headers, int32_t height,
                      const RCCoupParams& params, std::vector<uint256>& digests_out,
                      uint32_t q_cap, const lt::ExactGemmBackend& gemm,
                      const RCCoupOptions& options)
{
    const uint32_t limit =
        q_cap == 0 ? kRCCoupledQSweepHarnessMax
                   : std::min(q_cap, kRCCoupledQSweepHarnessMax);
    return MineRCCoupledBatchIndependent(headers, height, params, digests_out, limit,
                                         /*use_resident_bank=*/true, gemm, options);
}

} // namespace matmul::v4::rc
