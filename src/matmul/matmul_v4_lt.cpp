// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_lt.h>

#include <matmul/matmul_pow.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt_mx_exact.h>

#include <arith_uint256.h>
#include <crypto/chacha20.h>
#include <crypto/common.h>
#include <crypto/sha256.h>
#include <primitives/block.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cassert>
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
constexpr char kQStarSlotTag[] = "BTX_QSTAR_SLOT_V44LT";       // Phase B full slot id
constexpr char kQStarLeafTag[] = "BTX_QSTAR_LEAF_V44LT";       // Merkle leaf preimage
constexpr char kQStarSlotSeedATag[] = "BTX_QSTAR_SLOTSEED_A_V44LT";
constexpr char kQStarSlotSeedBTag[] = "BTX_QSTAR_SLOTSEED_B_V44LT";

// SHA256(tag ‖ a ‖ b) → uint256 (domain-separated two-hash fold).
uint256 DeriveTaggedPair(const char* tag, size_t taglen, const uint256& a, const uint256& b)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(tag), taglen);
    hasher.Write(a.data(), uint256::size());
    hasher.Write(b.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

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

struct MatExpandTemplateProjectors {
    std::vector<int8_t> G;
    std::vector<int8_t> H;
};

MatExpandTemplateProjectors PrepareMatExpandTemplateProjectors(const uint256& tmpl, uint32_t n)
{
    const uint256 seed_g = DeriveTaggedSeed(kMatExpandGTag, sizeof(kMatExpandGTag) - 1, tmpl);
    const uint256 seed_h = DeriveTaggedSeed(kMatExpandHTag, sizeof(kMatExpandHTag) - 1, tmpl);
    MatExpandTemplateProjectors out;
    out.G = bx::ExpandProjectorBMX4C(seed_g, n, n);
    out.H = bx::ExpandProjectorBMX4C(seed_h, kMatExpandPanelW, n);
    return out;
}

// MatExpand core: Bhat = Extract_MX((G * W) * H), n*n row-major, |.| <= 48.
//   G = ExpandProjectorBMX4C(seed_G, n, n)   template-scoped M11
//   H = ExpandProjectorBMX4C(seed_H, w, n)   template-scoped M11
//   W = ExpandProjectorBMX4C(seed_W, n, w)   panel (nonce/template per caller)
//   Y  = G * W          (n x n)*(n x w) = n x w  exact s8xs8->s32, |Y| <= 36*n
//   B32 = Y * H         (n x w)*(w x n) = n x n  exact s32xs8->s32
//   prf_key = DeriveMatExpandPrfKey(seed_W)
//   Bhat = MX-block Extract over B32 tiles (E8M0 scales + tile ChaCha M11)
//
// C-15 non-collapse: Extract is NOT an affine function of B32. A Freivalds
// verifier that only sees Bhat therefore cannot reassociate through G/W/H to
// skip the dense MatExpand GEMMs (the linear-fold shortcut class).
// Lever-B MX Extract replaces per-cell ChaCha (external C-15 review still open).
//
// `backend` may redirect the two dense GEMMs to a bit-exact device path;
// nullptr slots (or a false return) fall back to ExactGemm*.
std::vector<int8_t> MatExpandCorePrepared(const uint256& seed_w, uint32_t n,
                                          const std::vector<int8_t>& G,
                                          const std::vector<int8_t>& H,
                                          const ExactGemmBackend& backend,
                                          std::vector<int8_t>* mu_out = nullptr,
                                          std::vector<uint8_t>* scales_out = nullptr,
                                          bool materialize_dense = true)
{
    assert(n % kMatExpandMxBlockLen == 0);
    const uint32_t w = kMatExpandPanelW;
    assert(G.size() == static_cast<size_t>(n) * n);
    assert(H.size() == static_cast<size_t>(w) * n);
    const std::vector<int8_t> W = bx::ExpandProjectorBMX4C(seed_w, n, w); // n x w

    std::vector<int32_t> Y;
    bool y_ok = false;
    if (backend.gemm_s8s8 != nullptr) {
        try {
            y_ok = backend.gemm_s8s8(G, W, n, n, w, Y) &&
                   Y.size() == static_cast<size_t>(n) * w;
        } catch (...) {
            y_ok = false;
        }
    }
    if (!y_ok) {
        Y = ExactGemmS8S8(G, W, n, n, w);
    }
    std::vector<int32_t> B32;
    bool b32_ok = false;
    if (backend.gemm_s32s8 != nullptr) {
        try {
            b32_ok = backend.gemm_s32s8(Y, H, n, w, n, B32) &&
                     B32.size() == static_cast<size_t>(n) * n;
        } catch (...) {
            b32_ok = false;
        }
    }
    if (!b32_ok) {
        B32 = ExactGemmS32S8(Y, H, n, w, n);
    }

    const uint256 prf_key = DeriveMatExpandPrfKey(seed_w);
    const uint32_t nblk = n / kMatExpandMxBlockLen;
    std::vector<int8_t> out;
    if (materialize_dense) {
        out.resize(static_cast<size_t>(n) * n);
    }
    if (mu_out) {
        mu_out->assign(static_cast<size_t>(n) * n, 0);
    }
    if (scales_out) {
        scales_out->assign(static_cast<size_t>(n) * nblk, 0);
    }
    int8_t mu_tile[kMatExpandMxBlockLen];
    for (uint32_t i = 0; i < n; ++i) {
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const int32_t* raw32 = B32.data() + static_cast<size_t>(i) * n +
                                   static_cast<size_t>(bj) * kMatExpandMxBlockLen;
            ExtractMatExpandMxTileMantissas(prf_key, i, bj, raw32, mu_tile);
            const uint8_t e = DeriveMatExpandMxScale(prf_key, i, bj);
            if (scales_out) {
                (*scales_out)[static_cast<size_t>(i) * nblk + bj] = e;
            }
            const int32_t scale = int32_t{1} << e;
            for (uint32_t t = 0; t < kMatExpandMxBlockLen; ++t) {
                const size_t idx = static_cast<size_t>(i) * n +
                                   static_cast<size_t>(bj) * kMatExpandMxBlockLen + t;
                if (mu_out) {
                    (*mu_out)[idx] = mu_tile[t];
                }
                if (materialize_dense) {
                    out[idx] = static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) * scale);
                }
            }
        }
    }
    return out;
}

std::vector<int8_t> MatExpandCore(const uint256& tmpl, const uint256& seed_w, uint32_t n,
                                  const ExactGemmBackend& backend,
                                  std::vector<int8_t>* mu_out = nullptr,
                                  std::vector<uint8_t>* scales_out = nullptr,
                                  bool materialize_dense = true)
{
    const MatExpandTemplateProjectors projectors = PrepareMatExpandTemplateProjectors(tmpl, n);
    return MatExpandCorePrepared(seed_w, n, projectors.G, projectors.H, backend, mu_out, scales_out,
                                 materialize_dense);
}

} // namespace

namespace {

// Normative MX PRF key tag (Lever B). Legacy cell ChaCha uses kMatExpandPrfTagCell.
constexpr char kMatExpandPrfTag[] = "BTX_MATEXPAND_MXPRF_V44LT";
constexpr char kMatExpandPrfTagCell[] = "BTX_MATEXPAND_PRF_V44LT";
constexpr char kMatExpandMxScaleTag[] = "BTX_MATEXPAND_MXSCALE_V44LT";

// One ChaCha20 keystream (≤64 bytes) bound to (raw,i,j,counter,lane) — LEGACY
// per-cell path (ExtractDequantMatExpandChaChaCell / related-nonce tests).
void MatExpandPrfKeystream(const uint256& prf_key, int32_t raw, uint32_t i, uint32_t j,
                           uint32_t remix, uint32_t lane, Span<std::byte> out)
{
    static_assert(sizeof(i) == 4 && sizeof(j) == 4,
                  "MatExpand position salt (i,j) must be full-width uint32");
    std::array<std::byte, ChaCha20::KEYLEN> key_bytes{};
    std::memcpy(key_bytes.data(), prf_key.data(), ChaCha20::KEYLEN);
    ChaCha20 chacha{Span<const std::byte>{key_bytes}};
    const uint32_t nonce_first = static_cast<uint32_t>(raw) ^ lane;
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(j);
    assert(((nonce_second >> 32) & 0xffffffffull) == static_cast<uint64_t>(i));
    assert((nonce_second & 0xffffffffull) == static_cast<uint64_t>(j));
    chacha.Seek(ChaCha20::Nonce96{nonce_first, nonce_second}, remix);
    chacha.Keystream(out);
}

// MX-block tile ChaCha: nonce_first = bj ⊕ 'MXBL', nonce_second = (i<<32)|bj.
void MatExpandMxTileKeystream(const uint256& prf_key, uint32_t i, uint32_t bj, uint32_t remix,
                              Span<std::byte> out)
{
    static_assert(sizeof(i) == 4 && sizeof(bj) == 4,
                  "MatExpand MX tile salt (i,bj) must be full-width uint32");
    std::array<std::byte, ChaCha20::KEYLEN> key_bytes{};
    std::memcpy(key_bytes.data(), prf_key.data(), ChaCha20::KEYLEN);
    ChaCha20 chacha{Span<const std::byte>{key_bytes}};
    const uint32_t nonce_first = bj ^ kMatExpandPrfLaneMxBlock;
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(bj);
    chacha.Seek(ChaCha20::Nonce96{nonce_first, nonce_second}, remix);
    chacha.Keystream(out);
}

} // namespace

int32_t FoldInt32ToEmax48(int32_t y)
{
    // Legacy linear fold retained for adversarial differential tests only.
    // Normative MatExpand uses MX-block ExtractDequantMatExpand (see MatExpandCore).
    int32_t a = y % 97;
    if (a < 0) a += 97;
    return a - 48; // [-48, 48]
}

uint256 DeriveMatExpandPrfKey(const uint256& seed_w)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kMatExpandPrfTag),
                 sizeof(kMatExpandPrfTag) - 1);
    hasher.Write(seed_w.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint256 DeriveMatExpandPrfKeyChaChaCell(const uint256& seed_w)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kMatExpandPrfTagCell),
                 sizeof(kMatExpandPrfTagCell) - 1);
    hasher.Write(seed_w.data(), uint256::size());
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint8_t DeriveMatExpandMxScale(const uint256& prf_key, uint32_t i, uint32_t bj)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kMatExpandMxScaleTag),
                 sizeof(kMatExpandMxScaleTag) - 1);
    hasher.Write(prf_key.data(), uint256::size());
    uint8_t ile[4], bjle[4];
    WriteLE32(ile, i);
    WriteLE32(bjle, bj);
    hasher.Write(ile, sizeof(ile));
    hasher.Write(bjle, sizeof(bjle));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return static_cast<uint8_t>(out[0] & 0x3);
}

void ExtractMatExpandMxTileMantissas(const uint256& prf_key, uint32_t i, uint32_t bj,
                                     const int32_t raw32[kMatExpandMxBlockLen],
                                     int8_t mu_out[kMatExpandMxBlockLen])
{
    std::array<std::byte, 64> ks{};
    uint32_t remix = 0;
    uint32_t filled = 0;
    while (filled < kMatExpandMxBlockLen) {
        MatExpandMxTileKeystream(prf_key, i, bj, remix, Span<std::byte>{ks});
        for (size_t b = 0; b < ks.size() && filled < kMatExpandMxBlockLen; ++b) {
            const uint8_t byte = static_cast<uint8_t>(ks[b]);
            for (uint8_t shift : {0, 4}) {
                if (filled >= kMatExpandMxBlockLen) break;
                const uint8_t nibble = static_cast<uint8_t>((byte >> shift) & 0x0F);
                const uint32_t raw_u = static_cast<uint32_t>(raw32[filled]);
                // Bind cell to B32: mix raw into the nibble before M11 rejection.
                const uint8_t mixed = static_cast<uint8_t>(
                    (nibble ^ static_cast<uint8_t>((raw_u * 0x9E3779B9u) >> 28)) & 0x0F);
                bool accepted = false;
                const int8_t mu = matmul::v4::bmx4::SampleMantissaNibble(mixed, accepted);
                if (accepted) {
                    mu_out[filled++] = mu;
                }
            }
        }
        ++remix;
    }
}

uint64_t MixMatExpandEntry(int32_t raw, uint32_t i, uint32_t j, uint64_t salt)
{
    // LEGACY SplitMix64-style avalanche — differential tests only.
    uint64_t z = static_cast<uint64_t>(static_cast<uint32_t>(raw));
    z ^= static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL;
    z ^= static_cast<uint64_t>(j) * 0xBF58476D1CE4E5B9ULL;
    z ^= salt;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int8_t ExtractDequantMatExpandSplitMix(int32_t raw, uint32_t i, uint32_t j, uint64_t salt)
{
    // LEGACY SplitMix+M11 path — not consensus under ENC_BMX4C_LT.
    uint64_t mixed = MixMatExpandEntry(raw, i, j, salt);
    uint64_t remix = 0;
    for (;;) {
        for (int shift = 0; shift < 64; shift += 4) {
            bool accepted = false;
            const int8_t mu = matmul::v4::bmx4::SampleMantissaNibble(
                static_cast<uint8_t>((mixed >> shift) & 0x0F), accepted);
            if (!accepted) continue;
            const uint64_t scale_stream = MixMatExpandEntry(
                raw, i, j, salt ^ 0xD1B54A32D192ED03ULL ^ (remix << 1));
            const uint8_t e = static_cast<uint8_t>(scale_stream & 0x3);
            // Exact mul — never signed left-shift (negative mu << e is UB).
            return static_cast<int8_t>(static_cast<int32_t>(mu) * (int32_t{1} << e));
        }
        ++remix;
        mixed = MixMatExpandEntry(raw, i, j, salt + remix);
    }
}

int8_t ExtractDequantMatExpandChaChaCell(int32_t raw, uint32_t i, uint32_t j,
                                         const uint256& prf_key)
{
    // LEGACY per-cell ChaCha20 Extract — differential / related-nonce tests only.
    static_assert(sizeof(i) == 4 && sizeof(j) == 4,
                  "ChaChaCell position salt (i,j) must be full-width uint32");
    std::array<std::byte, 8> mant_bytes{};
    std::array<std::byte, 8> scale_bytes{};
    uint32_t remix = 0;
    for (;;) {
        MatExpandPrfKeystream(prf_key, raw, i, j, remix, kMatExpandPrfLaneMant,
                              Span<std::byte>{mant_bytes});
        const uint64_t mixed = ReadLE64(reinterpret_cast<const unsigned char*>(mant_bytes.data()));
        for (int shift = 0; shift < 64; shift += 4) {
            bool accepted = false;
            const int8_t mu = matmul::v4::bmx4::SampleMantissaNibble(
                static_cast<uint8_t>((mixed >> shift) & 0x0F), accepted);
            if (!accepted) continue;
            MatExpandPrfKeystream(prf_key, raw, i, j, remix, kMatExpandPrfLaneScale,
                                  Span<std::byte>{scale_bytes});
            const uint64_t scale_stream =
                ReadLE64(reinterpret_cast<const unsigned char*>(scale_bytes.data()));
            const uint8_t e = static_cast<uint8_t>(scale_stream & 0x3);
            return static_cast<int8_t>(static_cast<int32_t>(mu) * (int32_t{1} << e));
        }
        ++remix;
    }
}

int8_t ExtractDequantMatExpand(int32_t raw, uint32_t i, uint32_t j, const uint256& prf_key)
{
    // Normative Lever-B MX Extract (synthetic tile: all 32 raws = `raw`).
    static_assert(sizeof(i) == 4 && sizeof(j) == 4,
                  "ExtractDequantMatExpand position salt (i,j) must be full-width uint32");
    const uint32_t bj = j / kMatExpandMxBlockLen;
    const uint32_t t = j % kMatExpandMxBlockLen;
    int32_t raw32[kMatExpandMxBlockLen];
    for (uint32_t k = 0; k < kMatExpandMxBlockLen; ++k) {
        raw32[k] = raw;
    }
    int8_t mu_tile[kMatExpandMxBlockLen];
    ExtractMatExpandMxTileMantissas(prf_key, i, bj, raw32, mu_tile);
    const uint8_t e = DeriveMatExpandMxScale(prf_key, i, bj);
    return static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) * (int32_t{1} << e));
}

int8_t ExtractDequantMatExpandAt(const int32_t* B32, uint32_t n, uint32_t i, uint32_t j,
                                 const uint256& prf_key)
{
    assert(B32 != nullptr);
    assert(n % kMatExpandMxBlockLen == 0);
    assert(i < n && j < n);
    const uint32_t bj = j / kMatExpandMxBlockLen;
    const uint32_t t = j % kMatExpandMxBlockLen;
    const int32_t* raw32 = B32 + static_cast<size_t>(i) * n +
                           static_cast<size_t>(bj) * kMatExpandMxBlockLen;
    int8_t mu_tile[kMatExpandMxBlockLen];
    ExtractMatExpandMxTileMantissas(prf_key, i, bj, raw32, mu_tile);
    const uint8_t e = DeriveMatExpandMxScale(prf_key, i, bj);
    return static_cast<int8_t>(static_cast<int32_t>(mu_tile[t]) * (int32_t{1} << e));
}

namespace {

// Host twin of CUDA/HIP DeviceMatExpandPrfLE64 / DeviceExtractDequant. Kept in
// this TU so unit tests can pin accel kernels against CPU goldens without a GPU.
inline uint32_t AccelReplicaRotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

inline void AccelReplicaChaChaQuarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d = AccelReplicaRotl32(d ^ a, 16);
    c += d; b = AccelReplicaRotl32(b ^ c, 12);
    a += b; d = AccelReplicaRotl32(d ^ a, 8);
    c += d; b = AccelReplicaRotl32(b ^ c, 7);
}

// Host twin of CUDA/HIP DeviceMatExpandPrfLE64. Same full-width (i,j) packing:
// nonce_second = (i<<32)|j — MUST NOT truncate either half.
uint64_t AccelReplicaMatExpandPrfLE64(const uint32_t key[8], int32_t raw, uint32_t i, uint32_t j,
                                      uint32_t remix, uint32_t lane)
{
    static_assert(sizeof(i) == 4 && sizeof(j) == 4,
                  "AccelReplica position salt (i,j) must be full-width uint32");
    uint32_t x0 = 0x61707865u, x1 = 0x3320646eu, x2 = 0x79622d32u, x3 = 0x6b206574u;
    uint32_t x4 = key[0], x5 = key[1], x6 = key[2], x7 = key[3];
    uint32_t x8 = key[4], x9 = key[5], x10 = key[6], x11 = key[7];
    uint32_t x12 = remix;
    uint32_t x13 = static_cast<uint32_t>(raw) ^ lane;
    // Full 32-bit i → x15, full 32-bit j → x14 (RFC8439 nonce layout).
    const uint64_t nonce_second = (static_cast<uint64_t>(i) << 32) | static_cast<uint64_t>(j);
    uint32_t x14 = static_cast<uint32_t>(nonce_second);
    uint32_t x15 = static_cast<uint32_t>(nonce_second >> 32);
    assert(x15 == i && x14 == j);

    const uint32_t j4 = x4, j5 = x5, j6 = x6, j7 = x7;
    const uint32_t j8 = x8, j9 = x9, j10 = x10, j11 = x11;
    const uint32_t j12 = x12, j13 = x13, j14 = x14, j15 = x15;

    for (int r = 0; r < 10; ++r) {
        AccelReplicaChaChaQuarter(x0, x4, x8, x12);
        AccelReplicaChaChaQuarter(x1, x5, x9, x13);
        AccelReplicaChaChaQuarter(x2, x6, x10, x14);
        AccelReplicaChaChaQuarter(x3, x7, x11, x15);
        AccelReplicaChaChaQuarter(x0, x5, x10, x15);
        AccelReplicaChaChaQuarter(x1, x6, x11, x12);
        AccelReplicaChaChaQuarter(x2, x7, x8, x13);
        AccelReplicaChaChaQuarter(x3, x4, x9, x14);
    }

    x0 += 0x61707865u; x1 += 0x3320646eu; x2 += 0x79622d32u; x3 += 0x6b206574u;
    x4 += j4; x5 += j5; x6 += j6; x7 += j7;
    x8 += j8; x9 += j9; x10 += j10; x11 += j11;
    x12 += j12; x13 += j13; x14 += j14; x15 += j15;

    return static_cast<uint64_t>(x0) | (static_cast<uint64_t>(x1) << 32);
}

} // namespace

uint64_t MatExpandPrfLaneLE64(const uint256& prf_key, int32_t raw, uint32_t i, uint32_t j,
                              uint32_t remix, uint32_t lane)
{
    uint32_t key[8];
    for (int w = 0; w < 8; ++w) {
        key[w] = ReadLE32(prf_key.data() + static_cast<size_t>(w) * 4);
    }
    return AccelReplicaMatExpandPrfLE64(key, raw, i, j, remix, lane);
}

int8_t ExtractDequantMatExpandAccelReplica(int32_t raw, uint32_t i, uint32_t j,
                                           const uint256& prf_key)
{
    // Host twin of CUDA/HIP DeviceExtractDequantMatExpandMx (synthetic tile).
    // Must stay bit-identical to normative ExtractDequantMatExpand.
    return ExtractDequantMatExpand(raw, i, j, prf_key);
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

std::vector<int8_t> ExpandOperandBMatExpandMx(const CBlockHeader& header, uint32_t n,
                                              const ExactGemmBackend& backend,
                                              std::vector<int8_t>& mu_out,
                                              std::vector<uint8_t>& scales_out)
{
    const uint256 tmpl = matmul::v4::ComputeTemplateHash(header);
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
    return MatExpandCore(tmpl, seed_w, n, backend, &mu_out, &scales_out);
}

void ExpandOperandBMatExpandMxComponents(const CBlockHeader& header, uint32_t n,
                                         const ExactGemmBackend& backend,
                                         std::vector<int8_t>& mu_out,
                                         std::vector<uint8_t>& scales_out)
{
    const uint256 tmpl = matmul::v4::ComputeTemplateHash(header);
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
    (void)MatExpandCore(tmpl, seed_w, n, backend, &mu_out, &scales_out,
                        /*materialize_dense=*/false);
}

std::vector<int32_t> ComputeProjectedRightMxBlockScaleLT(const std::vector<int8_t>& mu,
                                                         const std::vector<uint8_t>& scales,
                                                         const std::vector<int8_t>& V, uint32_t n,
                                                         uint32_t m)
{
    assert(n % kMatExpandMxBlockLen == 0);
    const uint32_t nblk = n / kMatExpandMxBlockLen;
    assert(mu.size() == static_cast<size_t>(n) * n);
    assert(scales.size() == static_cast<size_t>(n) * nblk);
    assert(V.size() == static_cast<size_t>(n) * m);
    std::vector<int32_t> Q(static_cast<size_t>(n) * m, 0);
    for (uint32_t i = 0; i < n; ++i) {
        int32_t* q_row = Q.data() + static_cast<size_t>(i) * m;
        for (uint32_t bj = 0; bj < nblk; ++bj) {
            const uint8_t e = scales[static_cast<size_t>(i) * nblk + bj];
            const int32_t scale = int32_t{1} << e;
            const size_t mu_base = static_cast<size_t>(i) * n +
                                   static_cast<size_t>(bj) * kMatExpandMxBlockLen;
            for (uint32_t t = 0; t < kMatExpandMxBlockLen; ++t) {
                const int32_t coeff = static_cast<int32_t>(mu[mu_base + t]) * scale;
                if (coeff == 0) continue;
                const uint32_t j = bj * kMatExpandMxBlockLen + t;
                const int8_t* v_row = V.data() + static_cast<size_t>(j) * m;
                // Stream contiguous V/Q rows so compilers can vectorize this
                // exact s8-by-small-int update. All public bounds fit int32.
                for (uint32_t c = 0; c < m; ++c) {
                    q_row[c] += coeff * static_cast<int32_t>(v_row[c]);
                }
            }
        }
    }
    return Q;
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
    const uint256 tmpl = matmul::v4::ComputeTemplateHash(header);
    const MatExpandTemplateProjectors projectors = PrepareMatExpandTemplateProjectors(tmpl, n);
    const uint256 seed_wa = DeriveTaggedSeed(kMatExpandWATag, sizeof(kMatExpandWATag) - 1, tmpl);
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4CLT(header);

    const std::vector<int8_t> Ahat =
        MatExpandCorePrepared(seed_wa, n, projectors.G, projectors.H, backend);
    std::vector<int8_t> b_mu;
    std::vector<uint8_t> b_scales;
    (void)MatExpandCorePrepared(seed_w, n, projectors.G, projectors.H, backend,
                                &b_mu, &b_scales, /*materialize_dense=*/false);
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

    // Optimal factoring Chat = (U*Ahat)(Bhat*V), never forming C or a dense
    // dequantized Bhat. The MX component lane is exactly Bhat*V with
    // Bhat[i,j]=mu[i,j]*2^e[i,j/32]. Deep tile m=n/2 raises the enforced
    // combine work but touches no accumulator bound.
    const std::vector<int32_t> P = matmul::v4::ComputeProjectedLeft(U, Ahat, n, m);
    const std::vector<int32_t> Q =
        ComputeProjectedRightMxBlockScaleLT(b_mu, b_scales, V, n, m);
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
    const uint256 tmpl = matmul::v4::ComputeTemplateHash(header);
    const MatExpandTemplateProjectors projectors = PrepareMatExpandTemplateProjectors(tmpl, n);
    const uint256 seed_wa = DeriveTaggedSeed(kMatExpandWATag, sizeof(kMatExpandWATag) - 1, tmpl);
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1, header_hash);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4CLT(header);
    const std::vector<int8_t> Ahat =
        MatExpandCorePrepared(seed_wa, n, projectors.G, projectors.H, ExactGemmBackend{});
    const std::vector<int8_t> Bhat =
        MatExpandCorePrepared(seed_w, n, projectors.G, projectors.H, ExactGemmBackend{});
    const std::vector<int8_t> U = bx::ExpandProjectorBMX4C(seed_u, m, n);
    const std::vector<int8_t> V = bx::ExpandProjectorBMX4C(seed_v, n, m);

    return matmul::v4::SketchFreivalds(Ahat, Bhat, U, V, sketch, sigma, payload,
                                       n, m, rounds);
}

uint256 ComputeWindowMerkleRoot(Span<const uint256> digests)
{
    // Consensus seal paths always pass Q* ∈ {128,256,512}. Assert power-of-two for
    // any non-empty input so a shared-helper misuse cannot silently pad.
    assert(digests.empty() || (digests.size() & (digests.size() - 1)) == 0);
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

uint256 CommitWindowSlotLeaf(const uint256& slot_id, const uint256& digest)
{
    return DeriveTaggedPair(kQStarLeafTag, sizeof(kQStarLeafTag) - 1, slot_id, digest);
}

void BindWindowSlotIdIntoSeeds(CBlockHeader& header, const uint256& slot_id)
{
    header.seed_a = DeriveTaggedPair(kQStarSlotSeedATag, sizeof(kQStarSlotSeedATag) - 1,
                                     header.seed_a, slot_id);
    header.seed_b = DeriveTaggedPair(kQStarSlotSeedBTag, sizeof(kQStarSlotSeedBTag) - 1,
                                     header.seed_b, slot_id);
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
        // Diagnostic path: if the caller supplied a slot_id, bind it the same
        // way production seal construction does; otherwise fall back to nonce-
        // only (legacy harnesses that never set slot_id).
        if (!slots[i].slot_id.IsNull()) {
            BindWindowSlotIdIntoSeeds(header, slots[i].slot_id);
        }
        uint256 digest;
        std::vector<unsigned char> payload;
        if (!ComputeDigestBMX4CLT(header, n, digest, payload)) return false;
        if (digest != slots[i].digest) return false;
    }
    return true;
}

uint256 DeriveWindowSlotId(const uint256& sigma_anchor, uint32_t slot_index)
{
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kQStarSlotTag), sizeof(kQStarSlotTag) - 1);
    hasher.Write(sigma_anchor.data(), uint256::size());
    uint8_t idx_le[4];
    WriteLE32(idx_le, slot_index);
    hasher.Write(idx_le, sizeof(idx_le));
    uint8_t out[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(out);
    return uint256{Span<const unsigned char>{out, sizeof(out)}};
}

uint64_t DeriveWindowSlotNonce(const uint256& sigma_anchor, uint32_t slot_index)
{
    // Header grinding compatibility: nNonce64 := low 64 bits LE of the full
    // 256-bit slot identifier (same bytes as historical DeriveWindowSlotNonce).
    return ReadLE64(DeriveWindowSlotId(sigma_anchor, slot_index).data());
}

bool ComputeSealDigestBMX4CLT(const CBlockHeader& anchor, uint32_t n, uint32_t Qstar,
                              const SlotSeedFn& slot_seed_fn, uint256& seal_out,
                              std::vector<WindowSlot>* slots_out,
                              std::vector<std::vector<unsigned char>>* slot_payloads_out,
                              ExactGemmBackend backend, ExactMxProjectionBackend mx_proj)
{
    seal_out.SetNull();
    if (slots_out) slots_out->clear();
    if (slot_payloads_out) slot_payloads_out->clear();
    if (!IsValidConsensusQStar(Qstar) || !slot_seed_fn) return false;
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) return false;

    // Prepare template-invariant A/U/V/P once. Slots share the template hash
    // (seed_a/seed_b are nulled in ComputeTemplateHash); only B/Q/Chat vary.
    // Injectable ExactGemm + ExactMx backends accelerate MatExpand / B̂·V;
    // callers that omit them keep CPU ExactGemm* / MX oracle.
    WindowSketchMinerLT prepared{anchor, n, std::move(backend), std::move(mx_proj)};
    if (!prepared.Valid()) return false;

    const uint256 sigma_anchor = matmul::v4::DeriveSigma(anchor);
    std::vector<uint256> leaves;
    leaves.reserve(Qstar);
    if (slots_out) slots_out->reserve(Qstar);
    if (slot_payloads_out) slot_payloads_out->reserve(Qstar);

    // Reject duplicate full slot identifiers deterministically. Low-64 nNonce
    // collisions alone must NOT under-work the seal: seeds + leaf bind the
    // full 256-bit id.
    std::vector<uint256> seen_ids;
    seen_ids.reserve(Qstar);

    for (uint32_t j = 0; j < Qstar; ++j) {
        const uint256 slot_id = DeriveWindowSlotId(sigma_anchor, j);
        if (std::find(seen_ids.begin(), seen_ids.end(), slot_id) != seen_ids.end()) {
            return false;
        }
        seen_ids.push_back(slot_id);

        CBlockHeader slot = anchor;
        slot.nNonce64 = ReadLE64(slot_id.data());
        slot.nNonce = static_cast<uint32_t>(slot.nNonce64);
        if (!slot_seed_fn(slot)) return false;
        BindWindowSlotIdIntoSeeds(slot, slot_id);

        uint256 slot_digest;
        std::vector<unsigned char> payload;
        if (!prepared.MineSlot(slot, slot_digest, slot_payloads_out ? &payload : nullptr)) {
            return false;
        }
        leaves.push_back(CommitWindowSlotLeaf(slot_id, slot_digest));
        if (slots_out) {
            WindowSlot leaf;
            leaf.slot_id = slot_id;
            leaf.nonce = slot.nNonce64;
            leaf.digest = slot_digest;
            slots_out->push_back(std::move(leaf));
        }
        if (slot_payloads_out) slot_payloads_out->push_back(std::move(payload));
    }

    const uint256 merkle = ComputeWindowMerkleRoot(leaves);
    seal_out = SealWindowCommit(sigma_anchor, merkle, Qstar);
    return true;
}

bool VerifySealWindowFreivalds(const CBlockHeader& anchor, uint32_t n, uint32_t Qstar,
                               uint32_t rounds, const SlotSeedFn& slot_seed_fn,
                               const std::vector<std::vector<unsigned char>>& slot_payloads,
                               uint256& seal_out)
{
    seal_out.SetNull();
    if (!IsValidConsensusQStar(Qstar) || !slot_seed_fn) return false;
    if (slot_payloads.size() != Qstar) return false;
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) return false;

    const uint256 sigma_anchor = matmul::v4::DeriveSigma(anchor);
    std::vector<uint256> leaves;
    leaves.reserve(Qstar);
    std::vector<uint256> seen_ids;
    seen_ids.reserve(Qstar);

    for (uint32_t j = 0; j < Qstar; ++j) {
        const uint256 slot_id = DeriveWindowSlotId(sigma_anchor, j);
        if (std::find(seen_ids.begin(), seen_ids.end(), slot_id) != seen_ids.end()) {
            return false;
        }
        seen_ids.push_back(slot_id);

        CBlockHeader slot = anchor;
        slot.nNonce64 = ReadLE64(slot_id.data());
        slot.nNonce = static_cast<uint32_t>(slot.nNonce64);
        if (!slot_seed_fn(slot)) return false;
        BindWindowSlotIdIntoSeeds(slot, slot_id);

        // VerifySketchBMX4CLT requires header.matmul_digest == H(sigma‖payload).
        // Seal mode stores the lottery object on the ANCHOR only; pin the slot
        // commitment digest onto the ephemeral slot header before Freivalds.
        const uint256 sigma_slot = matmul::v4::DeriveSigma(slot);
        slot.matmul_digest = matmul::v4::ComputeSketchDigest(sigma_slot, slot_payloads[j]);

        uint256 slot_digest;
        if (!VerifySketchBMX4CLT(slot, n, rounds, slot_payloads[j], slot_digest)) return false;
        leaves.push_back(CommitWindowSlotLeaf(slot_id, slot_digest));
    }

    const uint256 merkle = ComputeWindowMerkleRoot(leaves);
    seal_out = SealWindowCommit(sigma_anchor, merkle, Qstar);
    return true;
}

bool SealWindowProofMatchesCommitment(const CBlockHeader& anchor, uint32_t n, uint32_t Qstar,
                                      const SlotSeedFn& slot_seed_fn,
                                      const std::vector<std::vector<unsigned char>>& slot_payloads)
{
    if (!IsValidConsensusQStar(Qstar) || !slot_seed_fn) return false;
    if (slot_payloads.size() != Qstar) return false;
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) return false;

    const uint256 sigma_anchor = matmul::v4::DeriveSigma(anchor);
    std::vector<uint256> leaves;
    leaves.reserve(Qstar);
    std::vector<uint256> seen_ids;
    seen_ids.reserve(Qstar);

    for (uint32_t j = 0; j < Qstar; ++j) {
        const uint256 slot_id = DeriveWindowSlotId(sigma_anchor, j);
        if (std::find(seen_ids.begin(), seen_ids.end(), slot_id) != seen_ids.end()) {
            return false;
        }
        seen_ids.push_back(slot_id);

        CBlockHeader slot = anchor;
        slot.nNonce64 = ReadLE64(slot_id.data());
        slot.nNonce = static_cast<uint32_t>(slot.nNonce64);
        if (!slot_seed_fn(slot)) return false;
        BindWindowSlotIdIntoSeeds(slot, slot_id);

        // Auth-only: digest = H(sigma_slot ‖ payload bytes); no Freivalds.
        std::vector<Fq> sketch;
        if (!matmul::v4::ParseSketch(slot_payloads[j], m, sketch)) return false;
        leaves.push_back(CommitWindowSlotLeaf(
            slot_id, matmul::v4::ComputeSketchDigest(matmul::v4::DeriveSigma(slot),
                                                     slot_payloads[j])));
    }

    const uint256 merkle = ComputeWindowMerkleRoot(leaves);
    const uint256 seal = SealWindowCommit(sigma_anchor, merkle, Qstar);
    return seal == anchor.matmul_digest;
}

WindowSketchMinerLT::WindowSketchMinerLT(const CBlockHeader& header, uint32_t n,
                                         ExactGemmBackend backend,
                                         ExactMxProjectionBackend mx_proj)
    : m_template{header}, m_n{n}, m_backend{backend}, m_mx_proj{mx_proj}
{
    uint32_t m = 0;
    if (!ValidateDimsBMX4CLT(n, m)) return;
    m_m = m;
    m_template_hash = matmul::v4::ComputeTemplateHash(m_template);

    // Template-scoped derivations (invariant I1'): G, H, Ahat (MatExpand with
    // the template panel), U, V, and the left factor P = U*Ahat are paid ONCE
    // per template. In particular, retaining G/H prevents the CPU and
    // per-call-device-GEMM fallback from regenerating n*n + w*n deterministic
    // projector bytes for every nonce. The per-nonce marginal work is now
    // exactly {expand W, G*W, (G*W)*H, MX Extract, Bhat*V, combine, digest}.
    // CUDA/HIP accel TUs prefer a fuller device-resident loop and use this
    // miner only as the fail-closed ExactGemm fallback.
    const uint256 seed_wa = DeriveTaggedSeed(kMatExpandWATag, sizeof(kMatExpandWATag) - 1,
                                             m_template_hash);
    const auto [seed_u, seed_v] = DeriveProjectorSeedsBMX4CLT(m_template);
    MatExpandTemplateProjectors projectors = PrepareMatExpandTemplateProjectors(m_template_hash, n);
    m_G = std::move(projectors.G);
    m_H = std::move(projectors.H);
    m_A = MatExpandCorePrepared(seed_wa, n, m_G, m_H, m_backend);
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
        DigestOnlyResultLT res;
        // Phase A needs only the digest. Avoid serializing and then discarding
        // the m*m field payload for every losing nonce; Mine() materializes it
        // only for target matches below.
        if (!MineSlot(header, res.digest, nullptr)) {
            out.clear();
            return false;
        }
        res.nonce = header.nNonce64;
        res.target_match = UintToArith256(res.digest) <= bn_target;
        res.backend_status = matmul::v4::bmx4::DigestOnlyBackendStatus::Ok;
        out.push_back(std::move(res));
    }
    return true;
}

bool WindowSketchMinerLT::MineSlot(const CBlockHeader& header, uint256& digest_out,
                                   std::vector<unsigned char>* payload_out) const
{
    digest_out.SetNull();
    if (payload_out) payload_out->clear();
    if (!m_valid) return false;
    if (matmul::v4::ComputeTemplateHash(header) != m_template_hash) return false;

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    const uint256 header_hash = matmul::ComputeMatMulHeaderHash(header);
    const uint256 seed_w = DeriveTaggedSeed(kMatExpandWTag, sizeof(kMatExpandWTag) - 1,
                                            header_hash);
    std::vector<int8_t> mu;
    std::vector<uint8_t> scales;
    (void)MatExpandCorePrepared(seed_w, m_n, m_G, m_H, m_backend, &mu, &scales,
                                /*materialize_dense=*/false);
    // Device ExactMxProjectionBackend when set; mismatched results fail closed
    // to ComputeProjectedRightMxBlockScaleLT (byte-identical digests).
    const std::vector<int32_t> Q = ComputeProjectedRightMxDispatched(
        mu, scales, m_V, m_n, m_m, m_mx_proj, /*provenance=*/nullptr);
    const std::vector<Fq> Chat = matmul::v4::ComputeCombineModQ(m_P, Q, m_n, m_m);
    digest_out = matmul::v4::ComputeSketchDigestFromFq(sigma, Chat);
    if (payload_out) {
        *payload_out = matmul::v4::SerializeSketch(Chat);
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
            // Reuse the prepared A/G/H/U/V/P state for the rare winner rather
            // than invoking the full one-shot digest path again.
            if (MineSlot(headers[i], d, &payload) && d == out[i].digest) {
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
    // Static lane-intent taxonomy only (same as ENC-BMX4C PlanExactAccelLanes).
    // Never claim runtime native MXFP4/FP8 from this planner: no silicon probe,
    // no self-qual, no kernel wiring. Logical ScalePartitionedMxfp4 means the
    // miner SHOULD match ComputeProjectedRightMxBlockScaleLT (exact-integer MX);
    // native_*_qualified stays false until a backend reports proven bits.
    // Consensus sees only Ĉ. C-15 OPEN; public heights INT32_MAX.
    return matmul::v4::bmx4::PlanExactAccelLanes(device_class);
}

} // namespace matmul::v4::lt
