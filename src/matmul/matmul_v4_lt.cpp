// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_lt.h>

#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>

#include <arith_uint256.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>

namespace matmul::v4::lt {
namespace {

namespace bx = matmul::v4::bmx4;

// V4.4-LT domain-separation tags. Distinct from the V42 (ENC-BMX4C) and V42D
// tags so LT is a cryptographically independent encoding profile: a seed can
// never yield correlated C / D / LT operand streams.
constexpr char kMatExpandGTag[] = "BTX_MATEXPAND_G_V44LT";  // template-scoped G
constexpr char kMatExpandHTag[] = "BTX_MATEXPAND_H_V44LT";  // template-scoped H
constexpr char kMatExpandWTag[] = "BTX_MATEXPAND_W_V44LT";  // nonce-fresh panel (B)
constexpr char kMatExpandWATag[] = "BTX_MATEXPAND_WA_V44LT"; // template panel (A)
constexpr char kProjectorUTagV44LT[] = "BTX_MATMUL_V44LT_SKETCH_U";
constexpr char kProjectorVTagV44LT[] = "BTX_MATMUL_V44LT_SKETCH_V";
constexpr char kQStarCommitTag[] = "BTX_QSTAR_COMMIT_V44LT";

// SHA256(tag || hash [|| extra]) -> uint256. Matches the single-SHA256 tagged
// derivation style of matmul_v4_bmx4.cpp::DeriveTaggedSeed.
uint256 DeriveTaggedSeed(const char* tag, size_t taglen, const uint256& hash)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(hash.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

// SHA256d over two concatenated 32-byte hashes (Bitcoin-style Merkle node).
uint256 Sha256dPair(const uint256& a, const uint256& b)
{
    uint8_t buf[2 * uint256::size()];
    std::memcpy(buf, a.data(), uint256::size());
    std::memcpy(buf + uint256::size(), b.data(), uint256::size());
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(buf, sizeof(buf)).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    return uint256{Span<const unsigned char>{d2, sizeof(d2)}};
}

// MatExpand core: Bhat = Extract(Mix((G * W) * H)), n*n row-major, |.| <= 48.
//   G = ExpandProjectorBMX4C(seed_G, n, n)   template-scoped M11
//   H = ExpandProjectorBMX4C(seed_H, w, n)   template-scoped M11
//   W = ExpandProjectorBMX4C(seed_W, n, w)   panel (nonce/template per caller)
//   Y  = G * W          (n x n)*(n x w) = n x w  exact s8xs8->s32, |Y| <= 36*n
//   B32 = Y * H         (n x w)*(w x n) = n x n  exact s32xs8->s32
//   Bhat[i,j] = ExtractDequantMatExpand(B32[i,j], i, j, salt(seed_W))
//
// C-15 non-collapse: Extract is NOT an affine function of B32. A Freivalds
// verifier that only sees Bhat therefore cannot reassociate through G/W/H to
// skip the dense MatExpand GEMMs (the linear-fold shortcut class).
//
// `backend` may redirect the two dense GEMMs to a bit-exact device path;
// nullptr slots (or a false return) fall back to ExactGemm*.
std::vector<int8_t> MatExpandCore(const uint256& tmpl, const uint256& seed_w, uint32_t n,
                                  const ExactGemmBackend& backend)
{
    const uint32_t w = kMatExpandPanelW;
    const uint256 seed_g = DeriveTaggedSeed(kMatExpandGTag, sizeof(kMatExpandGTag) - 1, tmpl);
    const uint256 seed_h = DeriveTaggedSeed(kMatExpandHTag, sizeof(kMatExpandHTag) - 1, tmpl);

    const std::vector<int8_t> G = bx::ExpandProjectorBMX4C(seed_g, n, n); // n x n
    const std::vector<int8_t> H = bx::ExpandProjectorBMX4C(seed_h, w, n); // w x n
    const std::vector<int8_t> W = bx::ExpandProjectorBMX4C(seed_w, n, w); // n x w

    std::vector<int32_t> Y;
    if (backend.gemm_s8s8 == nullptr || !backend.gemm_s8s8(G, W, n, n, w, Y)) {
        Y = ExactGemmS8S8(G, W, n, n, w);
    }
    std::vector<int32_t> B32;
    if (backend.gemm_s32s8 == nullptr || !backend.gemm_s32s8(Y, H, n, w, n, B32)) {
        B32 = ExactGemmS32S8(Y, H, n, w, n);
    }

    // Position salt binds the panel seed so A vs B (and distinct nonces) never
    // share an Extract stream even when B32 collides.
    const uint64_t salt = ReadLE64(seed_w.data());

    std::vector<int8_t> out(static_cast<size_t>(n) * n);
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            const size_t idx = static_cast<size_t>(i) * n + j;
            out[idx] = ExtractDequantMatExpand(B32[idx], i, j, salt);
        }
    }
    return out;
}

} // namespace

int32_t FoldInt32ToEmax48(int32_t y)
{
    // Legacy linear fold retained for adversarial differential tests only.
    // Normative MatExpand uses ExtractDequantMatExpand (see MatExpandCore).
    int32_t a = y % 97;
    if (a < 0) a += 97;
    return a - 48; // [-48, 48]
}

uint64_t MixMatExpandEntry(int32_t raw, uint32_t i, uint32_t j, uint64_t salt)
{
    // SplitMix64-style avalanche over (raw, i, j, salt). Pure integer; identical
    // on every backend. Position salts kill translation-invariance shortcuts.
    uint64_t z = static_cast<uint64_t>(static_cast<uint32_t>(raw));
    z ^= static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL;
    z ^= static_cast<uint64_t>(j) * 0xBF58476D1CE4E5B9ULL;
    z ^= salt;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int8_t ExtractDequantMatExpand(int32_t raw, uint32_t i, uint32_t j, uint64_t salt)
{
    // M11 rejection sample from the Mix nibble stream, then E8M0-style scale
    // e ∈ {0,1,2,3} from an independent Mix lane. Output = mu << e ∈ [-48,48].
    // Nonlinearity: SampleMantissaNibble is a table over a 4-bit domain with
    // rejections, so Extract is not affine in `raw` and does not commute with
    // left/right multiplication by Freivalds probes.
    uint64_t mixed = MixMatExpandEntry(raw, i, j, salt);
    uint64_t remix = 0;
    for (;;) {
        for (int shift = 0; shift < 64; shift += 4) {
            bool accepted = false;
            const int8_t mu = bx::SampleMantissaNibble(
                static_cast<uint8_t>((mixed >> shift) & 0x0F), accepted);
            if (!accepted) continue;
            const uint64_t scale_stream = MixMatExpandEntry(
                raw, i, j, salt ^ 0xD1B54A32D192ED03ULL ^ (remix << 1));
            const uint8_t e = static_cast<uint8_t>(scale_stream & 0x3);
            const int32_t v = static_cast<int32_t>(mu) << e;
            return static_cast<int8_t>(v);
        }
        ++remix;
        mixed = MixMatExpandEntry(raw, i, j, salt + remix);
    }
}

std::vector<int32_t> ExactGemmS8S8(const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                                   uint32_t rows, uint32_t inner, uint32_t cols)
{
    // Exact s8xs8->s32: |L|,|R| <= 48, so every accumulator is exact in int32.
    std::vector<int32_t> out(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t i = 0; i < rows; ++i) {
        const int8_t* l_row = &L[static_cast<size_t>(i) * inner];
        int32_t* o_row = &out[static_cast<size_t>(i) * cols];
        for (uint32_t k = 0; k < inner; ++k) {
            const int32_t l_ik = l_row[k];
            if (l_ik == 0) continue; // deterministic skip of zero MACs
            const int8_t* r_row = &R[static_cast<size_t>(k) * cols];
            for (uint32_t c = 0; c < cols; ++c) {
                o_row[c] += l_ik * static_cast<int32_t>(r_row[c]);
            }
        }
    }
    return out;
}

std::vector<int32_t> ExactGemmS32S8(const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                                    uint32_t rows, uint32_t inner, uint32_t cols)
{
    // Exact s32xs8->s32 for the (G*W)*H stage; L = Y (int32), R = H (s8).
    std::vector<int32_t> out(static_cast<size_t>(rows) * cols, 0);
    for (uint32_t i = 0; i < rows; ++i) {
        const int32_t* l_row = &L[static_cast<size_t>(i) * inner];
        int32_t* o_row = &out[static_cast<size_t>(i) * cols];
        for (uint32_t k = 0; k < inner; ++k) {
            const int32_t l_ik = l_row[k];
            if (l_ik == 0) continue;
            const int8_t* r_row = &R[static_cast<size_t>(k) * cols];
            for (uint32_t c = 0; c < cols; ++c) {
                o_row[c] += l_ik * static_cast<int32_t>(r_row[c]);
            }
        }
    }
    return out;
}

std::vector<int8_t> ExpandOperandBMatExpand(const CBlockHeader& header, uint32_t n)
{
    return ExpandOperandBMatExpand(header, n, ExactGemmBackend{});
}

std::vector<int8_t> ExpandOperandBMatExpand(const CBlockHeader& header, uint32_t n,
                                            const ExactGemmBackend& backend)
{
    // B is nonce-fresh: the thin panel W binds the FULL header hash (which binds
    // nNonce64), mirroring DeriveOperandSeedBMX4C's B scoping. G/H are template-
    // scoped, so the marginal per-nonce MatExpand work (G*W, (G*W)*H) is priced.
    const uint256 tmpl = matmul::v4::ComputeTemplateHash(header);
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
    return MatExpandCore(tmpl, seed_w, n, backend);
}

std::vector<int8_t> ExpandOperandAMatExpand(const CBlockHeader& header, uint32_t n)
{
    return ExpandOperandAMatExpand(header, n, ExactGemmBackend{});
}

std::vector<int8_t> ExpandOperandAMatExpand(const CBlockHeader& header, uint32_t n,
                                            const ExactGemmBackend& backend)
{
    // A is template-scoped: the thin panel W binds the TEMPLATE hash only, so A
    // is constant across a miner's nonce sweep (invariant I1'). Distinct WA tag.
    const uint256 tmpl = matmul::v4::ComputeTemplateHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWATag, sizeof(kMatExpandWATag) - 1, tmpl);
    return MatExpandCore(tmpl, seed_w, n, backend);
}

std::pair<uint256, uint256> DeriveProjectorSeedsBMX4CLT(const CBlockHeader& header)
{
    const uint256 template_hash = matmul::v4::ComputeTemplateHash(header);
    return {DeriveTaggedSeed(kProjectorUTagV44LT, sizeof(kProjectorUTagV44LT) - 1, template_hash),
            DeriveTaggedSeed(kProjectorVTagV44LT, sizeof(kProjectorVTagV44LT) - 1, template_hash)};
}

bool ValidateDimsBMX4CLT(uint32_t n, uint32_t& m_out)
{
    // Deep tile b = kTileBLT = 2; identical structural gates to ENC-BMX4C.
    return bx::ValidateDimsBMX4(n, kTileBLT, m_out);
}

bool ComputeDigestBMX4CLT(const CBlockHeader& header, uint32_t n,
                          uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    return ComputeDigestBMX4CLT(header, n, ExactGemmBackend{}, digest_out, payload_out);
}

bool ComputeDigestBMX4CLT(const CBlockHeader& header, uint32_t n,
                          const ExactGemmBackend& backend,
                          uint256& digest_out, std::vector<unsigned char>& payload_out)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header); // UNCHANGED
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4CLT(header);

    const std::vector<int8_t> Ahat = ExpandOperandAMatExpand(header, n, backend);
    const std::vector<int8_t> Bhat = ExpandOperandBMatExpand(header, n, backend);
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

    // Optimal factoring Chat = (U*Ahat)(Bhat*V), never forming C. |Ahat|,|Bhat|
    // <= 48 and |U|,|V| <= 6, so the UNCHANGED v4 projection + direct mod-q
    // combine consume them exactly (byte-identical to U*(A*B)*V). Deep tile
    // m = n/2 raises the enforced combine work but touches no accumulator bound.
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, Ahat, n, m);
    const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(Bhat, V, n, m);
    const std::vector<Fq> Chat = matmul::v4::ComputeCombineModQ(P, Q, n, m);

    payload_out = matmul::v4::SerializeSketch(Chat);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload_out);
    return true;
}

bool VerifySketchBMX4CLT(const CBlockHeader& header, uint32_t n, uint32_t rounds,
                         const std::vector<unsigned char>& payload, uint256& digest_out)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) {
        return false;
    }
    // Fail-closed on rounds == 0 (F-L3): SketchFreivalds returns true on an
    // empty round set, so a misconfigured 0-round verify would degrade to a
    // no-op accept. Mirror VerifySketchBMX4C.
    if (rounds == 0) {
        return false;
    }

    std::vector<Fq> sketch;
    if (!matmul::v4::ParseSketch(payload, m, sketch)) {
        return false;
    }

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    digest_out = matmul::v4::ComputeSketchDigest(sigma, payload);
    if (digest_out != header.matmul_digest) {
        return false;
    }

    // Re-MatExpand the operands; the UNCHANGED SketchFreivalds verifier consumes
    // them as exact integers -- it is compute-path-agnostic (design §3).
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4CLT(header);
    const std::vector<int8_t> Ahat = ExpandOperandAMatExpand(header, n);
    const std::vector<int8_t> Bhat = ExpandOperandBMatExpand(header, n);
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

    return matmul::v4::SketchFreivalds(Ahat, Bhat, U, V, sketch, sigma, payload,
                                       n, m, rounds);
}

uint256 ComputeWindowMerkleRoot(Span<const uint256> digests)
{
    if (digests.empty()) return uint256{}; // zero root for an empty window

    std::vector<uint256> layer(digests.begin(), digests.end());
    while (layer.size() > 1) {
        if (layer.size() & 1u) {
            layer.push_back(layer.back()); // Bitcoin-style odd-node duplication
        }
        std::vector<uint256> next(layer.size() / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            next[i] = Sha256dPair(layer[2 * i], layer[2 * i + 1]);
        }
        layer = std::move(next);
    }
    return layer[0];
}

uint256 SealWindowCommit(const uint256& sigma_anchor, const uint256& merkle_root, uint32_t Qstar)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kQStarCommitTag), sizeof(kQStarCommitTag) - 1);
    hasher.Write(sigma_anchor.data(), uint256::size());
    hasher.Write(merkle_root.data(), uint256::size());
    uint8_t qstar_le[4];
    WriteLE32(qstar_le, Qstar);
    hasher.Write(qstar_le, sizeof(qstar_le));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

bool VerifyWindowSlotFreivalds(const CBlockHeader& tmpl, uint32_t n,
                               const std::vector<WindowSlot>& slots, uint32_t r)
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) return false;
    if (slots.empty()) return false;

    const size_t count = slots.size();
    // r == 0 or r >= count verifies ALL slots; otherwise a deterministic strided
    // subset of r slots (spread across the window) is checked.
    const bool verify_all = (r == 0 || r >= count);
    const size_t to_check = verify_all ? count : r;
    const size_t stride = verify_all ? 1 : (count / to_check);

    for (size_t t = 0; t < to_check; ++t) {
        const size_t i = verify_all ? t : ((t * stride) % count);
        CBlockHeader header = tmpl;
        header.nNonce64 = slots[i].nonce;
        header.nNonce = static_cast<uint32_t>(slots[i].nonce);
        uint256 digest;
        std::vector<unsigned char> payload;
        if (!ComputeDigestBMX4CLT(header, n, digest, payload)) return false;
        if (digest != slots[i].digest) return false;
    }
    return true;
}

WindowSketchMinerLT::WindowSketchMinerLT(const CBlockHeader& header, uint32_t n,
                                         ExactGemmBackend backend)
    : m_template{header}, m_n{n}, m_backend{backend}
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) return;
    m_m = m;
    m_template_hash = matmul::v4::ComputeTemplateHash(m_template);

    // Template-scoped derivations (invariant I1'): Ahat (MatExpand with the
    // template panel), U, V, and the left factor P = U*Ahat are paid ONCE per
    // template. The per-nonce marginal work is {MatExpand Bhat, Bhat*V, combine,
    // digest}. Device backends accelerate only the MatExpand GEMMs.
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4CLT(m_template);
    m_A = ExpandOperandAMatExpand(m_template, n, m_backend);
    m_U = bx::ExpandProjectorBMX4C(seed_u, m_m, n);
    m_V = bx::ExpandProjectorBMX4C(seed_v, n, m_m);
    m_P = matmul::v4::ComputeProjectedLeft(m_U, m_A, n, m_m);
    m_valid = true;
}

bool WindowSketchMinerLT::MineWindow(const std::vector<CBlockHeader>& headers,
                                     const uint256& target,
                                     std::vector<DigestOnlyResultLT>& out) const
{
    out.clear();
    if (!m_valid || headers.empty()) return false;

    const arith_uint256 bn_target = UintToArith256(target);
    out.reserve(headers.size());
    for (const CBlockHeader& header : headers) {
        if (matmul::v4::ComputeTemplateHash(header) != m_template_hash) {
            out.clear();
            return false;
        }
        const uint256 sigma = matmul::v4::DeriveSigma(header);
        const std::vector<int8_t> Bhat = ExpandOperandBMatExpand(header, m_n, m_backend);
        const std::vector<int32_t> Q = matmul::v4::ComputeProjectedRight(Bhat, m_V, m_n, m_m);
        const std::vector<Fq> Chat = matmul::v4::ComputeCombineModQ(m_P, Q, m_n, m_m);

        DigestOnlyResultLT res;
        res.nonce = header.nNonce64;
        res.digest = matmul::v4::ComputeSketchDigestFromFq(sigma, Chat);
        res.target_match = UintToArith256(res.digest) <= bn_target;
        res.backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
        out.push_back(std::move(res));
    }
    return true;
}

bool WindowSketchMinerLT::Mine(const std::vector<uint64_t>& nonces, const uint256& target,
                               std::vector<DigestOnlyResultLT>& out,
                               std::vector<std::vector<unsigned char>>* payloads_out) const
{
    out.clear();
    if (payloads_out != nullptr) payloads_out->clear();
    if (!m_valid || nonces.empty()) return false;

    std::vector<CBlockHeader> headers(nonces.size(), m_template);
    for (size_t i = 0; i < nonces.size(); ++i) {
        headers[i].nNonce64 = nonces[i];
        headers[i].nNonce = static_cast<uint32_t>(nonces[i]);
        // Intentionally leave seed_a/seed_b as on the template. Consensus
        // mining must call MineWindow with SetDeterministicMatMulSeeds applied.
    }
    if (!MineWindow(headers, target, out)) return false;

    if (payloads_out != nullptr) {
        payloads_out->resize(nonces.size());
        for (size_t i = 0; i < nonces.size(); ++i) {
            if (!out[i].target_match) {
                (*payloads_out)[i].clear();
                continue;
            }
            uint256 d;
            std::vector<unsigned char> payload;
            if (ComputeDigestBMX4CLT(headers[i], m_n, d, payload) && d == out[i].digest) {
                (*payloads_out)[i] = std::move(payload);
            } else {
                (*payloads_out)[i].clear();
            }
        }
    }
    return true;
}

matmul::v4::bmx4::ExactAccelPlan PlanLTAccel(std::string_view device_class)
{
    // MatExpand replaces the SHA operand XOF with dense exact-int GEMMs; the
    // projection/combine lane choice for the deep-m sketch is the same device
    // taxonomy as ENC-BMX4C (MXFP4 on Blackwell/MI350, FP8 on Rubin-class, INT8
    // elsewhere). Consensus never sees these lanes — only the integer Ĉ.
    return matmul::v4::bmx4::PlanExactAccelLanes(device_class);
}

} // namespace matmul::v4::lt
