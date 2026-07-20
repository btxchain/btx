// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_coupled.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <span.h>

#include <cassert>
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

uint256 BarrierRoot(uint32_t barrier, const std::array<int8_t, kRCCoupStateBytes>& state)
{
    std::vector<unsigned char> buf;
    buf.reserve((sizeof(kRCCoupBarrierTag) - 1) + 4 + kRCCoupStateBytes);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupBarrierTag),
               reinterpret_cast<const unsigned char*>(kRCCoupBarrierTag) +
                   sizeof(kRCCoupBarrierTag) - 1);
    unsigned char le[4];
    WriteLE32(le, barrier);
    buf.insert(buf.end(), le, le + 4);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(state.data()),
               reinterpret_cast<const unsigned char*>(state.data()) + kRCCoupStateBytes);
    return Sha256dBytes(buf.data(), buf.size());
}

uint256 BankCommitment(const std::vector<std::vector<int8_t>>& pages)
{
    CSHA256 outer;
    outer.Write(reinterpret_cast<const unsigned char*>(kRCCoupBankTag),
                sizeof(kRCCoupBankTag) - 1);
    for (uint32_t p = 0; p < kRCCoupBankPages; ++p) {
        assert(pages[p].size() == static_cast<size_t>(kRCCoupLobeWidth) * kRCCoupLobeWidth);
        outer.Write(reinterpret_cast<const unsigned char*>(pages[p].data()), pages[p].size());
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
void MixButterflyAscending(std::array<int64_t, kRCCoupStateBytes>& s, uint32_t mask)
{
    for (uint32_t stage = 0; (uint32_t{1} << stage) < kRCCoupStateBytes; ++stage) {
        const uint32_t stride = uint32_t{1} << stage;
        for (uint32_t i = 0; i < kRCCoupStateBytes; ++i) {
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
void MixButterflyDescending(std::array<int64_t, kRCCoupStateBytes>& s, uint32_t mask)
{
    auto rotl7 = [](uint32_t x, uint32_t r) -> uint32_t {
        r %= 7; // log2(128)
        const uint32_t bits = 7;
        return ((x << r) | (x >> (bits - r))) & (kRCCoupStateBytes - 1);
    };
    for (int stage = 6; stage >= 0; --stage) {
        const uint32_t stride = uint32_t{1} << static_cast<uint32_t>(stage);
        for (uint32_t i = 0; i < kRCCoupStateBytes; ++i) {
            const uint32_t j = i ^ stride;
            if (i >= j) continue;
            const uint32_t pi = rotl7(i ^ mask, 3);
            const uint32_t pj = rotl7(j ^ mask, 3);
            const int64_t a = s[pi];
            const int64_t b = s[pj];
            // Distinct linear form from pattern 0 (still exact integer).
            s[pi] = a + b;
            s[pj] = b - a;
        }
    }
}

void ApplyAllToAllMix(std::array<int64_t, kRCCoupStateBytes>& s, const uint256& sigma,
                      uint32_t barrier)
{
    const uint256 mix_seed = Sha256TaggedU32(kRCCoupMixTag, sizeof(kRCCoupMixTag) - 1, sigma, barrier);
    ShaXof xof(mix_seed);
    const uint32_t mask = xof.NextU32() & (kRCCoupStateBytes - 1);
    const uint32_t pattern = barrier % kRCCoupMixPatterns;
    if (pattern == 0) {
        MixButterflyAscending(s, mask);
    } else {
        MixButterflyDescending(s, mask);
    }
}

void ApplyBalancedPermutation(std::array<int64_t, kRCCoupStateBytes>& s,
                              const std::array<uint32_t, kRCCoupStateBytes>& pi)
{
    std::array<int64_t, kRCCoupStateBytes> tmp{};
    for (uint32_t i = 0; i < kRCCoupStateBytes; ++i) {
        tmp[pi[i]] = s[i];
    }
    s = tmp;
}

/**
 * Non-affine Extract (C3.d / C5): ExtractMXTileInt64 per 32-wide tile.
 * Lookup-argument-shaped for Stage E (see header note).
 */
void ExtractActiveState(const uint256& prf_key, const std::array<int64_t, kRCCoupStateBytes>& raw,
                        std::array<int8_t, kRCCoupStateBytes>& out)
{
    const uint32_t n_tiles = kRCCoupStateBytes / kRCMxBlockLen;
    for (uint32_t t = 0; t < n_tiles; ++t) {
        ExtractMXTileInt64(prf_key, /*i=*/0, /*bj=*/t, raw.data() + t * kRCMxBlockLen,
                           out.data() + t * kRCMxBlockLen);
    }
}

/** Local lobe GEMM: 1×32 · 32×32 → 1×32 int32, widened to int64 (C3.a). */
void LobeLocalGemm(const int8_t* lobe_row, const std::vector<int8_t>& page,
                   int64_t* out32)
{
    std::vector<int8_t> L(lobe_row, lobe_row + kRCCoupLobeWidth);
    const auto y = lt::ExactGemmS8S8(L, page, /*rows=*/1, kRCCoupLobeWidth, kRCCoupLobeWidth);
    assert(y.size() == kRCCoupLobeWidth);
    for (uint32_t c = 0; c < kRCCoupLobeWidth; ++c) {
        out32[c] = static_cast<int64_t>(y[c]);
    }
}

} // namespace

std::vector<std::vector<int8_t>> DeriveCoupledBankPages(const CBlockHeader& header, int32_t height)
{
    // Template-scoped: header hash with nNonce64 cleared conceptually via the
    // existing template-hash path when available; toy binds template hash + height.
    CBlockHeader tmpl = header;
    tmpl.nNonce64 = 0;
    tmpl.nNonce = 0;
    const uint256 tmpl_hash = matmul::ComputeMatMulHeaderHash(tmpl);
    const uint256 bank_root_seed =
        Sha256TaggedU32(kRCCoupBankTag, sizeof(kRCCoupBankTag) - 1, tmpl_hash,
                        static_cast<uint32_t>(height));

    std::vector<std::vector<int8_t>> pages(kRCCoupBankPages);
    for (uint32_t p = 0; p < kRCCoupBankPages; ++p) {
        const uint256 page_seed = Sha256TaggedU32(kRCCoupBankTag, sizeof(kRCCoupBankTag) - 1,
                                                  bank_root_seed, p);
        pages[p] = ExpandMxDequantInt8(page_seed, kRCCoupLobeWidth, kRCCoupLobeWidth);
    }
    return pages;
}

std::array<uint256, kRCCoupLobes> DeriveCoupledLobeSeeds(const uint256& sigma)
{
    std::array<uint256, kRCCoupLobes> out{};
    for (uint32_t ell = 0; ell < kRCCoupLobes; ++ell) {
        out[ell] = Sha256TaggedU32(kRCCoupLobeTag, sizeof(kRCCoupLobeTag) - 1, sigma, ell);
    }
    return out;
}

std::array<uint32_t, kRCCoupStateBytes> DeriveCoupledBalancedPermutation(const uint256& sigma,
                                                                         uint32_t barrier)
{
    const uint256 perm_seed =
        Sha256TaggedU32(kRCCoupPermTag, sizeof(kRCCoupPermTag) - 1, sigma, barrier);
    ShaXof xof(perm_seed);
    std::array<uint32_t, kRCCoupStateBytes> pi{};
    for (uint32_t i = 0; i < kRCCoupStateBytes; ++i) {
        pi[i] = i;
    }
    // Fisher–Yates: every index hit exactly once; fixed N iterations (C4).
    for (uint32_t i = kRCCoupStateBytes - 1; i > 0; --i) {
        const uint32_t j = xof.NextU32() % (i + 1);
        const uint32_t tmp = pi[i];
        pi[i] = pi[j];
        pi[j] = tmp;
    }
    return pi;
}

bool IsBalancedPermutation(const std::array<uint32_t, kRCCoupStateBytes>& pi)
{
    std::array<bool, kRCCoupStateBytes> seen{};
    for (uint32_t i = 0; i < kRCCoupStateBytes; ++i) {
        if (pi[i] >= kRCCoupStateBytes) return false;
        if (seen[pi[i]]) return false;
        seen[pi[i]] = true;
    }
    return true;
}

uint256 RecomputeCoupledPuzzleReference(const CBlockHeader& header, int32_t height,
                                        const RCCoupOptions& options)
{
    const uint256 sigma = matmul::v4::DeriveSigma(header);

    // Bank commitment uses the pristine epoch/template pages (before any
    // skip_page test mutation) so the episode binds the honest bank.
    const auto pages_commit = DeriveCoupledBankPages(header, height);
    const uint256 bank_root = BankCommitment(pages_commit);

    // Resident path keeps pages; Checkpointed re-derives per barrier (paging).
    std::vector<std::vector<int8_t>> pages;
    const bool checkpointed = options.mode == RCCoupExecMode::Checkpointed;
    if (!checkpointed) {
        pages = pages_commit;
        if (options.skip_bank_page && options.skip_page_index < kRCCoupBankPages) {
            std::fill(pages[options.skip_page_index].begin(),
                      pages[options.skip_page_index].end(), int8_t{0});
        }
    }

    const auto lobe_seeds = DeriveCoupledLobeSeeds(sigma);
    std::array<int8_t, kRCCoupStateBytes> state{};
    for (uint32_t ell = 0; ell < kRCCoupLobes; ++ell) {
        // Nonce-fresh lobe activation (C2): first row of a 32×32 MX tile
        // (ExpandMxDequantInt8 requires rows % 32 == 0).
        const auto tile =
            ExpandMxDequantInt8(lobe_seeds[ell], kRCCoupLobeWidth, kRCCoupLobeWidth);
        assert(tile.size() == static_cast<size_t>(kRCCoupLobeWidth) * kRCCoupLobeWidth);
        std::memcpy(state.data() + ell * kRCCoupLobeWidth, tile.data(), kRCCoupLobeWidth);
    }

    std::array<uint256, kRCCoupRounds> barrier_roots{};
    // Checkpoint buffer: only Extracted active state survives barrier boundaries.
    std::array<int8_t, kRCCoupStateBytes> checkpoint = state;

    for (uint32_t b = 0; b < kRCCoupRounds; ++b) {
        if (checkpointed) {
            // Restore from last barrier checkpoint and re-page the bank.
            state = checkpoint;
            pages = DeriveCoupledBankPages(header, height);
            if (options.skip_bank_page && options.skip_page_index < kRCCoupBankPages) {
                std::fill(pages[options.skip_page_index].begin(),
                          pages[options.skip_page_index].end(), int8_t{0});
            }
        }

        if (options.skip_barrier && options.skip_barrier_index == b) {
            // Identity pass — shortcut detection must change the digest.
            barrier_roots[b] = BarrierRoot(b, state);
            checkpoint = state;
            continue;
        }

        std::array<int64_t, kRCCoupStateBytes> acc{};

        // C3.a — local exact int8 GEMM per lobe vs epoch bank page (fixed work).
        // Consensus lobe order is always 0..L-1 (scheduling-invariant digest).
        for (uint32_t ell = 0; ell < kRCCoupLobes; ++ell) {
            const uint32_t page_id = (b + ell) % kRCCoupBankPages;
            LobeLocalGemm(state.data() + ell * kRCCoupLobeWidth, pages[page_id],
                          acc.data() + ell * kRCCoupLobeWidth);
        }

        // C3.b — nonce-derived balanced permutation over full active state.
        const auto pi = DeriveCoupledBalancedPermutation(sigma, b);
        assert(IsBalancedPermutation(pi));
        ApplyBalancedPermutation(acc, pi);

        // C3.c — exact integer all-to-all mix (≥2 nonce-relabeled patterns).
        ApplyAllToAllMix(acc, sigma, b);

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
            // Drop resident bank + int64 scratch (already scoped); only checkpoint remains.
            pages.clear();
            pages.shrink_to_fit();
        }
    }

    // episode_digest = SHA256d("BTX_RC_COUP_EPISODE_V1" ‖ bank_root ‖ barrier_roots…)
    std::vector<unsigned char> buf;
    buf.reserve(sizeof(kRCCoupEpisodeTag) - 1 + 32 + kRCCoupRounds * 32);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag),
               reinterpret_cast<const unsigned char*>(kRCCoupEpisodeTag) +
                   sizeof(kRCCoupEpisodeTag) - 1);
    buf.insert(buf.end(), bank_root.begin(), bank_root.end());
    for (const uint256& root : barrier_roots) {
        buf.insert(buf.end(), root.begin(), root.end());
    }
    return Sha256dBytes(buf.data(), buf.size());
}

} // namespace matmul::v4::rc
