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
#include <matmul/matmul_v4_rc_extract.h>
#include <span.h>

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace matmul::v4::rc {
namespace {

namespace lt = matmul::v4::lt;

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

/** Stream pages into the hasher without retaining the full bank (Streamed). */
uint256 BankCommitmentStreaming(const CBlockHeader& header, int32_t height,
                                const RCCoupParams& params)
{
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(kRCCoupBankTag),
                sizeof(kRCCoupBankTag) - 1);
    for (uint32_t p = 0; p < params.bank_pages; ++p) {
        const auto page = DeriveCoupledBankPage(header, height, p, params);
        outer.Write(reinterpret_cast<const unsigned char*>(page.data()), page.size());
    }
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    outer.Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

/**
 * C6 pattern 0 — hypercube butterfly (ascending strides), int64 sum/diff.
 * Indices are XOR-relabeled by `mask` so the cut is nonce-dependent.
 */
void MixButterflyAscending(std::vector<int64_t>& s, uint32_t mask, uint32_t n)
{
    for (uint32_t stage = 0; (uint32_t{1} << stage) < n; ++stage) {
        const uint32_t stride = uint32_t{1} << stage;
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = i ^ mask;
            const uint32_t pj = j ^ mask;
            const int64_t a = s[pi];
            const int64_t b = s[pj];
            s[pi] = a + b;
            s[pj] = a - b;
        }
    }
}

/**
 * C6 pattern 1 — reverse-stride reduce-scatter style fold (descending strides)
 * with a rotate-relabel so partitions that minimize pattern 0 do not minimize
 * this cut. Integer sums/diffs only.
 */
void MixButterflyDescending(std::vector<int64_t>& s, uint32_t mask, uint32_t n)
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
            const int64_t a = s[pi];
            const int64_t b = s[pj];
            // Distinct linear form from pattern 0 (still exact integer).
            s[pi] = a + b;
            s[pj] = b - a;
        }
    }
}

void ApplyAllToAllMix(std::vector<int64_t>& s, const uint256& sigma, uint32_t barrier,
                      uint32_t n)
{
    const uint256 mix_seed = Sha256TaggedU32(kRCCoupMixTag, sizeof(kRCCoupMixTag) - 1, sigma, barrier);
    ShaXof xof(mix_seed);
    const uint32_t mask = xof.NextU32() & (n - 1);
    const uint32_t pattern = barrier % kRCCoupMixPatterns;
    if (pattern == 0) {
        MixButterflyAscending(s, mask, n);
    } else {
        MixButterflyDescending(s, mask, n);
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

/**
 * Non-affine Extract (C3.d / C5): ExtractMXTileInt64 per 32-wide tile.
 * Lookup-argument-shaped for Stage E (see header note).
 */
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

/**
 * Device-first ExactGemmS8S8 (mirrors RC ExactGemmS8S8Dispatched):
 * successful device output replaces CPU; empty/failing backend → CPU.
 * Wrong-but-successful backends are NOT silently rescued.
 */
std::vector<int32_t> ExactGemmS8S8Dispatched(const lt::ExactGemmBackend& gemm,
                                             const std::vector<int8_t>& L,
                                             const std::vector<int8_t>& R, uint32_t rows,
                                             uint32_t inner, uint32_t cols)
{
    const auto run_cpu = [&]() {
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

    static const bool compare =
        [] {
            const char* e = std::getenv("BTX_RC_EXACT_GEMM_COMPARE");
            return e != nullptr && e[0] == '1' && e[1] == '\0';
        }();
    if (compare) {
        const std::vector<int32_t> cpu = run_cpu();
        if (device != cpu) return cpu;
    }
    return device;
}

/** Local lobe GEMM: 1×W · W×W → 1×W int32, widened to int64 (C3.a). */
void LobeLocalGemm(const int8_t* lobe_row, const std::vector<int8_t>& page, uint32_t lobe_width,
                   int64_t* out_w, const lt::ExactGemmBackend& gemm)
{
    std::vector<int8_t> L(lobe_row, lobe_row + lobe_width);
    const auto y = ExactGemmS8S8Dispatched(gemm, L, page, /*rows=*/1, lobe_width, lobe_width);
    assert(y.size() == lobe_width);
    for (uint32_t c = 0; c < lobe_width; ++c) {
        out_w[c] = static_cast<int64_t>(y[c]);
    }
}

uint256 BankRootSeed(const CBlockHeader& header, int32_t height)
{
    CBlockHeader tmpl = header;
    tmpl.nNonce64 = 0;
    tmpl.nNonce = 0;
    const uint256 tmpl_hash = matmul::ComputeMatMulHeaderHash(tmpl);
    return Sha256TaggedU32(kRCCoupBankTag, sizeof(kRCCoupBankTag) - 1, tmpl_hash,
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
    assert(ValidateRCCoupParams(params));
    assert(barrier < params.barriers);
    assert(n_devices >= 1);

    const uint32_t n = params.StateBytes();
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const auto lobe_seeds = DeriveCoupledLobeSeeds(sigma, params);

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
        const uint32_t page_id = (barrier + ell) % params.bank_pages;
        auto page = DeriveCoupledBankPage(header, height, page_id, params);
        std::vector<int64_t> row(params.lobe_width, 0);
        LobeLocalGemm(state.data() + ell * params.lobe_width, page, params.lobe_width, row.data(),
                      gemm);
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
    assert(reduced == lobe_sum);

    std::vector<int64_t> acc(n, 0);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        std::memcpy(acc.data() + ell * params.lobe_width, segs[ell].data(),
                    params.lobe_width * sizeof(int64_t));
    }
    const auto pi = DeriveCoupledBalancedPermutation(sigma, barrier, params);
    ApplyBalancedPermutation(acc, pi);
    ApplyAllToAllMix(acc, sigma, barrier, n);

    const uint256 extract_seed =
        Sha256TaggedU32U32(kRCCoupExtractTag, sizeof(kRCCoupExtractTag) - 1, sigma, barrier,
                           /*unused=*/0);
    std::vector<int8_t> extracted(n);
    ExtractActiveState(lt::DeriveMatExpandPrfKey(extract_seed), acc, extracted);

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

bool ValidateRCCoupParams(const RCCoupParams& p)
{
    if (p.barriers == 0 || p.lobes == 0 || p.lobe_width == 0 || p.bank_pages == 0) {
        return false;
    }
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
    return p;
}

RCCoupParams MakeMediumRCCoupParams()
{
    RCCoupParams p;
    p.barriers = 8;
    p.lobes = 8;
    p.lobe_width = 64;
    p.bank_pages = 32;
    return p;
}

RCCoupParams ResolveRCCoupParams(const Consensus::Params& p)
{
    return p.fMatMulRCCoupledUseToyDims ? MakeToyRCCoupParams() : MakeMediumRCCoupParams();
}

bool RCCoupBarrierLoopComplete(const RCCoupParams& p)
{
    // C1–C6 structural checklist (see header). Mix-pattern count is a compile-
    // time constant; ValidateRCCoupParams covers bank/lobe/perm/Extract shape.
    static_assert(kRCCoupMixPatterns >= 2, "C6: need ≥2 mix patterns");
    static_assert(kRCCoupRounds >= 4 && kRCCoupRounds <= 8, "C5: toy barriers in [4,8]");
    return ValidateRCCoupParams(p) && kRCCoupMixPatterns >= 2;
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

std::vector<int8_t> DeriveCoupledBankPage(const CBlockHeader& header, int32_t height,
                                          uint32_t page, const RCCoupParams& params)
{
    assert(page < params.bank_pages);
    const uint256 bank_root_seed = BankRootSeed(header, height);
    const uint256 page_seed =
        Sha256TaggedU32(kRCCoupBankTag, sizeof(kRCCoupBankTag) - 1, bank_root_seed, page);
    return ExpandMxDequantInt8(page_seed, params.lobe_width, params.lobe_width);
}

std::vector<std::vector<int8_t>> DeriveCoupledBankPages(const CBlockHeader& header,
                                                        int32_t height,
                                                        const RCCoupParams& params)
{
    std::vector<std::vector<int8_t>> pages(params.bank_pages);
    for (uint32_t p = 0; p < params.bank_pages; ++p) {
        pages[p] = DeriveCoupledBankPage(header, height, p, params);
    }
    return pages;
}

std::vector<std::vector<int8_t>> DeriveCoupledBankPages(const CBlockHeader& header,
                                                        int32_t height)
{
    return DeriveCoupledBankPages(header, height, MakeToyRCCoupParams());
}

std::vector<uint256> DeriveCoupledLobeSeeds(const uint256& sigma, const RCCoupParams& params)
{
    std::vector<uint256> out(params.lobes);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        out[ell] = Sha256TaggedU32(kRCCoupLobeTag, sizeof(kRCCoupLobeTag) - 1, sigma, ell);
    }
    return out;
}

std::array<uint256, kRCCoupLobes> DeriveCoupledLobeSeeds(const uint256& sigma)
{
    const auto v = DeriveCoupledLobeSeeds(sigma, MakeToyRCCoupParams());
    std::array<uint256, kRCCoupLobes> out{};
    for (uint32_t i = 0; i < kRCCoupLobes; ++i) out[i] = v[i];
    return out;
}

std::vector<uint32_t> DeriveCoupledBalancedPermutation(const uint256& sigma, uint32_t barrier,
                                                       const RCCoupParams& params)
{
    const uint32_t n = params.StateBytes();
    const uint256 perm_seed =
        Sha256TaggedU32(kRCCoupPermTag, sizeof(kRCCoupPermTag) - 1, sigma, barrier);
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

std::array<uint32_t, kRCCoupStateBytes> DeriveCoupledBalancedPermutation(const uint256& sigma,
                                                                         uint32_t barrier)
{
    const auto v = DeriveCoupledBalancedPermutation(sigma, barrier, MakeToyRCCoupParams());
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

uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header, int32_t height,
                                        const RCCoupOptions& options)
{
    return RecomputeCoupledPuzzleReference(header, height, MakeToyRCCoupParams(), options, {},
                                           nullptr);
}

uint256 MineCoupledPuzzle(const CBlockHeader& header, int32_t height,
                          const RCCoupParams& params, const lt::ExactGemmBackend& gemm,
                          const RCCoupOptions& options)
{
    return RecomputeCoupledPuzzleReference(header, height, params, options, gemm, nullptr);
}

uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header, int32_t height,
                                        const RCCoupParams& params,
                                        const RCCoupOptions& options,
                                        const lt::ExactGemmBackend& gemm,
                                        RCCoupTiming* out_timing)
{
    assert(ValidateRCCoupParams(params));
    const auto t0 = std::chrono::steady_clock::now();
    const uint32_t n = params.StateBytes();
    const uint256 sigma = matmul::v4::DeriveSigma(header);

    const bool streamed = options.mode == RCCoupExecMode::Streamed;
    const bool checkpointed = options.mode == RCCoupExecMode::Checkpointed;
    // SequentialLobes and Resident both keep a full bank; Resident additionally
    // keeps active state across barriers without re-deriving (same as Sequential
    // for the toy CPU path — digests identical by construction).
    const bool retain_bank = options.mode == RCCoupExecMode::SequentialLobes ||
                             options.mode == RCCoupExecMode::Resident;

    // Bank commitment binds the honest epoch/template pages (before any
    // skip_page test mutation). Streamed hashes pages without retaining them.
    uint256 bank_root;
    std::vector<std::vector<int8_t>> pages;
    {
        const auto t_bank0 = std::chrono::steady_clock::now();
        if (streamed) {
            bank_root = BankCommitmentStreaming(header, height, params);
        } else {
            const auto pages_commit = DeriveCoupledBankPages(header, height, params);
            bank_root = BankCommitment(pages_commit, params.bank_pages, params.lobe_width);
            if (retain_bank) {
                pages = pages_commit;
                if (options.skip_bank_page && options.skip_page_index < params.bank_pages) {
                    std::fill(pages[options.skip_page_index].begin(),
                              pages[options.skip_page_index].end(), int8_t{0});
                }
            }
        }
        if (out_timing) {
            out_timing->bank_s = std::chrono::duration<double>(
                                     std::chrono::steady_clock::now() - t_bank0)
                                     .count();
        }
    }

    const auto lobe_seeds = DeriveCoupledLobeSeeds(sigma, params);
    std::vector<int8_t> state(n);
    for (uint32_t ell = 0; ell < params.lobes; ++ell) {
        // Nonce-fresh lobe activation (C2): first row of a W×W MX tile
        // (ExpandMxDequantInt8 requires rows % 32 == 0).
        const auto tile =
            ExpandMxDequantInt8(lobe_seeds[ell], params.lobe_width, params.lobe_width);
        assert(tile.size() == static_cast<size_t>(params.lobe_width) * params.lobe_width);
        std::memcpy(state.data() + ell * params.lobe_width, tile.data(), params.lobe_width);
    }

    std::vector<uint256> barrier_roots(params.barriers);
    // Checkpoint buffer: only Extracted active state survives barrier boundaries.
    std::vector<int8_t> checkpoint = state;

    const auto t_bar0 = std::chrono::steady_clock::now();
    for (uint32_t b = 0; b < params.barriers; ++b) {
        if (checkpointed) {
            // Restore from last barrier checkpoint and re-page the bank.
            state = checkpoint;
            pages = DeriveCoupledBankPages(header, height, params);
            if (options.skip_bank_page && options.skip_page_index < params.bank_pages) {
                std::fill(pages[options.skip_page_index].begin(),
                          pages[options.skip_page_index].end(), int8_t{0});
            }
        }

        if (options.skip_barrier && options.skip_barrier_index == b) {
            // Identity pass — shortcut detection must change the digest.
            barrier_roots[b] = BarrierRoot(b, state);
            checkpoint = state;
            if (checkpointed) {
                pages.clear();
                pages.shrink_to_fit();
            }
            continue;
        }

        std::vector<int64_t> acc(n, 0);

        // C3.a — local exact int8 GEMM per lobe vs epoch bank page (fixed work).
        // Consensus lobe order is always 0..L-1 (scheduling-invariant digest).
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const uint32_t page_id = (b + ell) % params.bank_pages;
            if (streamed) {
                auto page = DeriveCoupledBankPage(header, height, page_id, params);
                MaybeZeroSkipPage(page, page_id, options);
                LobeLocalGemm(state.data() + ell * params.lobe_width, page, params.lobe_width,
                              acc.data() + ell * params.lobe_width, gemm);
                // Drop page immediately (do not retain full bank).
            } else {
                LobeLocalGemm(state.data() + ell * params.lobe_width, pages[page_id],
                              params.lobe_width, acc.data() + ell * params.lobe_width, gemm);
            }
        }

        // C3.b — nonce-derived balanced permutation over full active state.
        const auto pi = DeriveCoupledBalancedPermutation(sigma, b, params);
        assert(IsBalancedPermutation(pi, n));
        ApplyBalancedPermutation(acc, pi);

        // C3.c — exact integer all-to-all mix (≥2 nonce-relabeled patterns).
        ApplyAllToAllMix(acc, sigma, b, n);

        // C3.d — non-affine Extract (lookup-argument-shaped for Stage E).
        const uint256 extract_seed =
            Sha256TaggedU32U32(kRCCoupExtractTag, sizeof(kRCCoupExtractTag) - 1, sigma, b,
                               /*unused=*/0);
        const uint256 prf_key = lt::DeriveMatExpandPrfKey(extract_seed);
        ExtractActiveState(prf_key, acc, state);

        // C3.e — feed-forward: next barrier reads this Extracted state.
        barrier_roots[b] = BarrierRoot(b, state);
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

    // episode_digest = SHA256d("BTX_RC_COUP_EPISODE_V1" ‖ bank_root ‖ barrier_roots…)
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCCoupEpisodeTag) - 1 + 32 + params.barriers * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag) +
                   sizeof(kRCCoupEpisodeTag) - 1);
    buf.insert(buf.end(), bank_root.begin(), bank_root.end());
    for (const uint256& root : barrier_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    const uint256 digest = Sha256dBytes(buf.data(), buf.size());
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

} // namespace matmul::v4::rc
