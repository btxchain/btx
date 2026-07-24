// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_freivalds_sampled.h>

#include <crypto/common.h>                 // ReadLE64 / WriteLE32 / WriteLE64
#include <matmul/matmul_v4.h>              // matmul::v4::DeriveSigma
#include <matmul/matmul_v4_rc.h>           // BuildTileTreeLeaves / Open/VerifyMerkleProof
#include <matmul/matmul_v4_rc_freivalds.h> // FreivaldsCheckGemm (frozen Fable primitive)
#include <matmul/matmul_v4_rc_fri_ext3.h>  // Sha256dBytes
#include <matmul/matmul_v4_rc_gkr_air.h>   // gkr_air Extract tile re-exec

#include <algorithm>
#include <array>
#include <cassert>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <list>
#include <map>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>

#if defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif
#endif

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#include <compat/cpuid.h>
#include <immintrin.h>
#endif

namespace matmul::v4::rc {

namespace {

#if defined(__GNUC__) || defined(__clang__)
#define BTX_RC_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define BTX_RC_ALWAYS_INLINE inline
#endif

double Secs(std::chrono::steady_clock::time_point s)
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - s).count();
}

uint32_t CarrierPrewarmInnerThreads(uint32_t total_threads)
{
    if (total_threads <= 1) return 1;
    if (const char* env = std::getenv("BTX_RC_CARRIER_PREWARM_INNER_THREADS")) {
        const unsigned long requested = std::strtoul(env, nullptr, 10);
        if (requested > 0) {
            return static_cast<uint32_t>(
                std::clamp<unsigned long>(requested, 1, total_threads));
        }
    }
    // Wave scheduling: split work across distinct operands, but let large
    // operands use enough inner workers that X0/K/V/W do not become serial
    // prewarm stragglers. 8 is the best default on Apple M-class 14/16-thread
    // validation hosts; callers can override for measurement.
    return std::min<uint32_t>(8, total_threads);
}

// A layer's extract_out is committed to the round tile-tree stream iff it is one
// of SV / Fwd(down). QKt's S and the fused-FFN UP wire's H are NOT streamed (both
// are recomputed by the verifier from anchored inputs — see header).
bool LayerInStream(RCGkrLayerKind k)
{
    return k == RCGkrLayerKind::GemmPhase1SV || k == RCGkrLayerKind::GemmPhase2Fwd;
}

bool LayerInAccStream(RCGkrLayerKind k)
{
    return k == RCGkrLayerKind::GemmPhase1QKt || k == RCGkrLayerKind::GemmPhase1SV ||
           k == RCGkrLayerKind::GemmPhase2FfnUp || k == RCGkrLayerKind::GemmPhase2Fwd;
}

// Byte offset of a layer's extract_out within its round stream. MUST match the
// RCGkrReconstructRoundStream layout: Z ‖ for l: (Down_l). Fused FFN commits ONE
// output per layer (the DOWN projection X[l+1] = b_seq×d_model); the UP wire's H
// is internal and never streamed.
uint64_t LayerStreamOffset(const RCEpisodeParams& p, RCGkrLayerKind kind, uint32_t layer)
{
    const uint64_t z = static_cast<uint64_t>(p.n_q) * p.d_head;
    const uint64_t per_l = static_cast<uint64_t>(p.b_seq) * p.d_model; // one DOWN output / layer
    switch (kind) {
    case RCGkrLayerKind::GemmPhase1SV:
        return 0;
    case RCGkrLayerKind::GemmPhase2Fwd:
        return z + static_cast<uint64_t>(layer) * per_l;
    default:
        return 0; // QKt / FfnUp: not in stream (never sampled as a stream unit)
    }
}

// Canonical round tile-tree geometry (R-01 T-BIND), derived SOLELY from the
// consensus-pinned episode params — never from an attacker-supplied proof/root.
// The round stream produced by RCGkrReconstructRoundStream is, for EVERY round,
//     Z (SV extract_out, n_q·d_head bytes) ‖ for l∈[0,L): DOWN_l (b_seq·d_model)
// so its logical length is CONSTANT across rounds and equals the sum below (this
// is exactly LayerStreamOffset's z + L·per_l). There is ONE tile-tree per round
// covering the whole concatenation, so BOTH the SV/Z + FFN-DOWN output-tile
// openings AND the chained-input-row (A-row) opening — which anchors X[l], itself
// a DOWN output living in the SAME round stream — share this single geometry.
// real_leaves matches RoundMerkleStream::FinalizeLeaves (one zero leaf even for an
// empty stream, final partial leaf zero-padded, then next_pow2 padding); depth is
// the exact sibling count OpenMerkleProof emits (log2 of the padded leaf count).
struct RoundTreeGeom {
    uint64_t logical_bytes{0};
    uint32_t real_leaves{0};  // ceil(logical_bytes / T_leaf), min 1 (non-padding leaves)
    uint32_t depth{0};        // log2(next_pow2(real_leaves)) == canonical path length
};
RoundTreeGeom TreeGeometryForLogicalBytes(uint64_t logical_bytes, uint32_t t_leaf_in)
{
    RoundTreeGeom g;
    g.logical_bytes = logical_bytes;
    const uint32_t t_leaf = t_leaf_in ? t_leaf_in : 1;
    uint64_t real = (g.logical_bytes + t_leaf - 1) / t_leaf;
    if (real == 0) real = 1;  // empty stream still emits one zero leaf
    uint64_t padded = 1;
    uint32_t depth = 0;
    while (padded < real) { padded <<= 1; ++depth; }
    g.real_leaves = static_cast<uint32_t>(real);
    g.depth = depth;
    return g;
}

RoundTreeGeom RoundStreamTreeGeometry(const RCEpisodeParams& p)
{
    return TreeGeometryForLogicalBytes(
        static_cast<uint64_t>(p.n_q) * p.d_head +
            static_cast<uint64_t>(p.L_lyr) * p.b_seq * p.d_model,
        p.T_leaf);
}

RoundTreeGeom AccStreamTreeGeometry(const RCEpisodeParams& p)
{
    const uint64_t elem = sizeof(int64_t);
    const uint64_t phase1_bytes =
        static_cast<uint64_t>(p.n_q) *
        (static_cast<uint64_t>(p.n_ctx) + static_cast<uint64_t>(p.d_head)) * elem;
    const uint64_t ffn_layer_bytes =
        static_cast<uint64_t>(p.b_seq) *
        (static_cast<uint64_t>(p.d_ff) + static_cast<uint64_t>(p.d_model)) * elem;
    return TreeGeometryForLogicalBytes(phase1_bytes + static_cast<uint64_t>(p.L_lyr) *
                                                         ffn_layer_bytes,
                                       p.T_leaf);
}

bool AccTileStreamOffset(const RCEpisodeParams& p, const RCGkrSampledLayerProv& lp,
                         uint32_t row, uint32_t bcol, uint64_t& out)
{
    if (!LayerInAccStream(lp.kind) || row >= lp.m || lp.n == 0 ||
        bcol >= lp.n / kRCMxBlockLen) {
        return false;
    }

    // RunEpisode streams Phase 1 row-interleaved: QK^T row i, then SV row i.
    // Phase 2 is layer-contiguous: UP_l, then FWD_l. These offsets are consensus
    // layout for V2 accumulator-root sampling.
    const uint64_t elem = sizeof(int64_t);
    const uint64_t T = kRCMxBlockLen;
    const uint64_t phase1_row =
        (static_cast<uint64_t>(p.n_ctx) + static_cast<uint64_t>(p.d_head)) * elem;
    const uint64_t phase1_bytes = static_cast<uint64_t>(p.n_q) * phase1_row;
    const uint64_t ffn_up_bytes = static_cast<uint64_t>(p.b_seq) * p.d_ff * elem;
    const uint64_t ffn_fwd_bytes = static_cast<uint64_t>(p.b_seq) * p.d_model * elem;
    const uint64_t ffn_layer_bytes = ffn_up_bytes + ffn_fwd_bytes;
    switch (lp.kind) {
    case RCGkrLayerKind::GemmPhase1QKt:
        out = static_cast<uint64_t>(row) * phase1_row +
              static_cast<uint64_t>(bcol) * T * elem;
        return true;
    case RCGkrLayerKind::GemmPhase1SV:
        out = static_cast<uint64_t>(row) * phase1_row +
              static_cast<uint64_t>(p.n_ctx) * elem +
              static_cast<uint64_t>(bcol) * T * elem;
        return true;
    case RCGkrLayerKind::GemmPhase2FfnUp:
        out = phase1_bytes + static_cast<uint64_t>(lp.layer) * ffn_layer_bytes +
              (static_cast<uint64_t>(row) * p.d_ff + static_cast<uint64_t>(bcol) * T) *
                  elem;
        return true;
    case RCGkrLayerKind::GemmPhase2Fwd:
        out = phase1_bytes + static_cast<uint64_t>(lp.layer) * ffn_layer_bytes +
              ffn_up_bytes +
              (static_cast<uint64_t>(row) * p.d_model + static_cast<uint64_t>(bcol) * T) *
                  elem;
        return true;
    default:
        return false;
    }
}

// SHA256d(kRCLeafTag ‖ bytes) — byte-identical to RoundMerkleStream::EmitLeaf.
uint256 LeafHashFromBytes(const std::vector<uint8_t>& leaf_bytes)
{
    std::vector<unsigned char> pre;
    pre.reserve(1 + leaf_bytes.size());
    pre.push_back(kRCLeafTag);
    pre.insert(pre.end(), leaf_bytes.begin(), leaf_bytes.end());
    return Sha256dBytes(pre.data(), pre.size());
}

uint256 AccumulatorTileTag(RCGkrLayerKind kind, uint32_t layer_index, uint32_t round,
                           uint32_t row, uint32_t bcol, const int64_t* acc_block)
{
    static constexpr char kTag[] = "BTX_RC_FRVS_ACC_TILE_V1";
    std::vector<unsigned char> pre;
    pre.reserve(sizeof(kTag) - 1 + 5 * 4 + kRCMxBlockLen * 8);
    pre.insert(pre.end(), reinterpret_cast<const unsigned char*>(kTag),
               reinterpret_cast<const unsigned char*>(kTag) + sizeof(kTag) - 1);
    auto put32 = [&](uint32_t v) {
        unsigned char tmp[4];
        WriteLE32(tmp, v);
        pre.insert(pre.end(), tmp, tmp + 4);
    };
    auto put64 = [&](uint64_t v) {
        unsigned char tmp[8];
        WriteLE64(tmp, v);
        pre.insert(pre.end(), tmp, tmp + 8);
    };
    put32(static_cast<uint32_t>(kind));
    put32(layer_index);
    put32(round);
    put32(row);
    put32(bcol);
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        put64(static_cast<uint64_t>(acc_block[t]));
    }
    return Sha256dBytes(pre.data(), pre.size());
}

std::vector<int8_t> AccumulatorTileBytes(const int64_t* acc_block)
{
    std::vector<int8_t> out(kRCMxBlockLen * sizeof(int64_t));
    unsigned char tmp[8];
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        WriteLE64(tmp, static_cast<uint64_t>(acc_block[t]));
        std::memcpy(out.data() + static_cast<size_t>(t) * sizeof(int64_t), tmp, sizeof(tmp));
    }
    return out;
}

std::vector<int8_t> TransposeI8Local(const std::vector<int8_t>& src, uint32_t rows, uint32_t cols)
{
    std::vector<int8_t> out(static_cast<size_t>(rows) * cols);
    for (uint32_t i = 0; i < rows; ++i)
        for (uint32_t j = 0; j < cols; ++j)
            out[static_cast<size_t>(j) * rows + i] = src[static_cast<size_t>(i) * cols + j];
    return out;
}

bool DenseRowBlockFitsS32(uint32_t k)
{
    // Worst signed-int8 product magnitude is (-128)*(-128)=16384. The FFN
    // verifier contractions (4096 and 16384) are safely int32-accumulable;
    // very-wide attention/SV contractions are left on the int64 scalar path.
    return static_cast<uint64_t>(k) * 128u * 128u <=
           static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
}

BTX_RC_ALWAYS_INLINE int64_t DenseDotScalarI64(const int8_t* a, const int8_t* b, uint32_t k)
{
    int64_t acc = 0;
    for (uint32_t i = 0; i < k; ++i) {
        acc += static_cast<int64_t>(a[i]) * static_cast<int64_t>(b[i]);
    }
    return acc;
}

void DenseRowBlockScalar(const int8_t* lhs, const int8_t* rhs, uint32_t k,
                         uint32_t rhs_cols, uint32_t rhs_col0,
                         int64_t out[kRCMxBlockLen])
{
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = 0;
    for (uint32_t t = 0; t < k; ++t) {
        const int64_t a = static_cast<int64_t>(lhs[t]);
        const int8_t* row = rhs + static_cast<size_t>(t) * rhs_cols + rhs_col0;
        for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
            out[c] += a * static_cast<int64_t>(row[c]);
        }
    }
}

#if defined(__aarch64__) && defined(__ARM_NEON)
#if defined(__clang__) || defined(__GNUC__)
#define BTX_RC_TARGET_I8MM __attribute__((target("i8mm")))
#else
#define BTX_RC_TARGET_I8MM
#endif

bool HaveArmI8MM()
{
#if defined(__ARM_FEATURE_MATMUL_INT8) || defined(__ARM_FEATURE_I8MM)
    return true;
#elif defined(__APPLE__)
    int val = 0;
    size_t len = sizeof(val);
    return sysctlbyname("hw.optional.arm.FEAT_I8MM", &val, &len, nullptr, 0) == 0 && val != 0;
#elif defined(__linux__) && defined(HWCAP2_I8MM)
    return (getauxval(AT_HWCAP2) & HWCAP2_I8MM) != 0;
#else
    return false;
#endif
}

#if defined(__ARM_FEATURE_DOTPROD)
BTX_RC_ALWAYS_INLINE int32_t DenseDotNeonS32(const int8_t* a, const int8_t* b, uint32_t k)
{
    assert(DenseRowBlockFitsS32(k));
    uint32_t i = 0;
    int32x4_t acc = vdupq_n_s32(0);
    for (; i + 16 <= k; i += 16) {
        acc = vdotq_s32(acc, vld1q_s8(a + i), vld1q_s8(b + i));
    }
    alignas(16) int32_t lanes[4];
    vst1q_s32(lanes, acc);
    int32_t sum = lanes[0] + lanes[1] + lanes[2] + lanes[3];
    for (; i < k; ++i) {
        sum += static_cast<int32_t>(a[i]) * static_cast<int32_t>(b[i]);
    }
    return sum;
}
#endif

BTX_RC_TARGET_I8MM void DenseRowBlockTransposedI8mmS32(const int8_t* lhs,
                                                       const int8_t* rhs_t,
                                                       uint32_t k,
                                                       uint32_t rhs_cols,
                                                       uint32_t rhs_col0,
                                                       int64_t out[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32(k));
    assert((k % 8) == 0);
    assert((kRCMxBlockLen % 2) == 0);
    (void)rhs_cols;

    int32x4_t acc[kRCMxBlockLen / 2];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) acc[p] = vdupq_n_s32(0);
    const int8x8_t zero = vdup_n_s8(0);

    for (uint32_t i = 0; i < k; i += 8) {
        const int8x16_t a = vcombine_s8(vld1_s8(lhs + i), zero);
        for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
            const uint32_t c0 = rhs_col0 + 2 * p;
            const int8x8_t b0 = vld1_s8(rhs_t + static_cast<size_t>(c0) * k + i);
            const int8x8_t b1 = vld1_s8(rhs_t + static_cast<size_t>(c0 + 1) * k + i);
            const int8x16_t b = vcombine_s8(b0, b1);
            acc[p] = vmmlaq_s32(acc[p], a, b);
        }
    }

    alignas(16) int32_t lanes[4];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
        vst1q_s32(lanes, acc[p]);
        out[2 * p] = static_cast<int64_t>(lanes[0]);
        out[2 * p + 1] = static_cast<int64_t>(lanes[1]);
    }
}

BTX_RC_TARGET_I8MM void DenseTwoRowsBlockTransposedI8mmS32(const int8_t* lhs0,
                                                           const int8_t* lhs1,
                                                           const int8_t* rhs_t,
                                                           uint32_t k,
                                                           uint32_t rhs_cols,
                                                           uint32_t rhs_col0,
                                                           int64_t out0[kRCMxBlockLen],
                                                           int64_t out1[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32(k));
    assert((k % 8) == 0);
    assert((kRCMxBlockLen % 2) == 0);
    (void)rhs_cols;

    int32x4_t acc[kRCMxBlockLen / 2];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) acc[p] = vdupq_n_s32(0);

    for (uint32_t i = 0; i < k; i += 8) {
        const int8x16_t a = vcombine_s8(vld1_s8(lhs0 + i), vld1_s8(lhs1 + i));
        for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
            const uint32_t c0 = rhs_col0 + 2 * p;
            const int8x8_t b0 = vld1_s8(rhs_t + static_cast<size_t>(c0) * k + i);
            const int8x8_t b1 = vld1_s8(rhs_t + static_cast<size_t>(c0 + 1) * k + i);
            const int8x16_t b = vcombine_s8(b0, b1);
            acc[p] = vmmlaq_s32(acc[p], a, b);
        }
    }

    alignas(16) int32_t lanes[4];
    for (uint32_t p = 0; p < kRCMxBlockLen / 2; ++p) {
        vst1q_s32(lanes, acc[p]);
        out0[2 * p] = static_cast<int64_t>(lanes[0]);
        out0[2 * p + 1] = static_cast<int64_t>(lanes[1]);
        out1[2 * p] = static_cast<int64_t>(lanes[2]);
        out1[2 * p + 1] = static_cast<int64_t>(lanes[3]);
    }
}

void DenseRowBlockNeonS32(const int8_t* lhs, const int8_t* rhs, uint32_t k,
                          uint32_t rhs_cols, uint32_t rhs_col0,
                          int64_t out[kRCMxBlockLen])
{
    assert(DenseRowBlockFitsS32(k));

    int32x4_t acc0 = vdupq_n_s32(0);
    int32x4_t acc1 = vdupq_n_s32(0);
    int32x4_t acc2 = vdupq_n_s32(0);
    int32x4_t acc3 = vdupq_n_s32(0);
    int32x4_t acc4 = vdupq_n_s32(0);
    int32x4_t acc5 = vdupq_n_s32(0);
    int32x4_t acc6 = vdupq_n_s32(0);
    int32x4_t acc7 = vdupq_n_s32(0);

    for (uint32_t t = 0; t < k; ++t) {
        const int8x8_t a = vdup_n_s8(lhs[t]);
        const int8_t* row = rhs + static_cast<size_t>(t) * rhs_cols + rhs_col0;

        const int16x8_t p0 = vmull_s8(a, vld1_s8(row + 0));
        const int16x8_t p1 = vmull_s8(a, vld1_s8(row + 8));
        const int16x8_t p2 = vmull_s8(a, vld1_s8(row + 16));
        const int16x8_t p3 = vmull_s8(a, vld1_s8(row + 24));

        acc0 = vaddw_s16(acc0, vget_low_s16(p0));
        acc1 = vaddw_s16(acc1, vget_high_s16(p0));
        acc2 = vaddw_s16(acc2, vget_low_s16(p1));
        acc3 = vaddw_s16(acc3, vget_high_s16(p1));
        acc4 = vaddw_s16(acc4, vget_low_s16(p2));
        acc5 = vaddw_s16(acc5, vget_high_s16(p2));
        acc6 = vaddw_s16(acc6, vget_low_s16(p3));
        acc7 = vaddw_s16(acc7, vget_high_s16(p3));
    }

    alignas(16) int32_t tmp[kRCMxBlockLen];
    vst1q_s32(tmp + 0, acc0);
    vst1q_s32(tmp + 4, acc1);
    vst1q_s32(tmp + 8, acc2);
    vst1q_s32(tmp + 12, acc3);
    vst1q_s32(tmp + 16, acc4);
    vst1q_s32(tmp + 20, acc5);
    vst1q_s32(tmp + 24, acc6);
    vst1q_s32(tmp + 28, acc7);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        out[c] = static_cast<int64_t>(tmp[c]);
    }
}

bool DenseRowBlockNeonSelfTest()
{
    constexpr uint32_t kRows = 257;
    constexpr uint32_t kCols = 96;
    constexpr uint32_t kCol0 = 32;
    std::vector<int8_t> lhs(kRows);
    std::vector<int8_t> rhs(static_cast<size_t>(kRows) * kCols);
    for (uint32_t i = 0; i < kRows; ++i) {
        lhs[i] = static_cast<int8_t>((static_cast<int32_t>((i * 37u + 11u) & 0xffu)) - 128);
        for (uint32_t j = 0; j < kCols; ++j) {
            rhs[static_cast<size_t>(i) * kCols + j] =
                static_cast<int8_t>((static_cast<int32_t>(((i + 3u) * 131u + j * 17u) & 0xffu)) - 128);
        }
    }
    int64_t scalar[kRCMxBlockLen];
    int64_t neon[kRCMxBlockLen];
    DenseRowBlockScalar(lhs.data(), rhs.data(), kRows, kCols, kCol0, scalar);
    DenseRowBlockNeonS32(lhs.data(), rhs.data(), kRows, kCols, kCol0, neon);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        if (scalar[c] != neon[c]) return false;
    }
    return true;
}

#if defined(__ARM_FEATURE_DOTPROD)
bool DenseDotNeonSelfTest()
{
    constexpr uint32_t kLen = 4097; // crosses vector and tail boundaries
    std::vector<int8_t> a(kLen);
    std::vector<int8_t> b(kLen);
    for (uint32_t i = 0; i < kLen; ++i) {
        a[i] = static_cast<int8_t>((static_cast<int32_t>((i * 29u + 7u) & 0xffu)) - 128);
        b[i] = static_cast<int8_t>((static_cast<int32_t>((i * 53u + 19u) & 0xffu)) - 128);
    }
    return DenseDotScalarI64(a.data(), b.data(), kLen) ==
           static_cast<int64_t>(DenseDotNeonS32(a.data(), b.data(), kLen));
}
#endif

bool DenseRowBlockI8mmSelfTest()
{
    if (!HaveArmI8MM()) return false;
    constexpr uint32_t kRows = 264; // multiple of 8 plus crosses cache-line boundaries
    constexpr uint32_t kCols = 96;
    constexpr uint32_t kCol0 = 32;
    std::vector<int8_t> lhs(kRows);
    std::vector<int8_t> rhs(static_cast<size_t>(kRows) * kCols);
    for (uint32_t i = 0; i < kRows; ++i) {
        lhs[i] = static_cast<int8_t>((static_cast<int32_t>((i * 41u + 5u) & 0xffu)) - 128);
        for (uint32_t j = 0; j < kCols; ++j) {
            rhs[static_cast<size_t>(i) * kCols + j] =
                static_cast<int8_t>((static_cast<int32_t>(((i + 7u) * 109u + j * 23u) & 0xffu)) - 128);
        }
    }
    const std::vector<int8_t> rhs_t = TransposeI8Local(rhs, kRows, kCols);
    int64_t scalar[kRCMxBlockLen];
    int64_t i8mm[kRCMxBlockLen];
    DenseRowBlockScalar(lhs.data(), rhs.data(), kRows, kCols, kCol0, scalar);
    DenseRowBlockTransposedI8mmS32(lhs.data(), rhs_t.data(), kRows, kCols, kCol0, i8mm);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        if (scalar[c] != i8mm[c]) return false;
    }
    std::vector<int8_t> lhs1(kRows);
    for (uint32_t i = 0; i < kRows; ++i) {
        lhs1[i] = static_cast<int8_t>((static_cast<int32_t>((i * 67u + 13u) & 0xffu)) - 128);
    }
    int64_t scalar1[kRCMxBlockLen];
    int64_t pair0[kRCMxBlockLen];
    int64_t pair1[kRCMxBlockLen];
    DenseRowBlockScalar(lhs1.data(), rhs.data(), kRows, kCols, kCol0, scalar1);
    DenseTwoRowsBlockTransposedI8mmS32(lhs.data(), lhs1.data(), rhs_t.data(), kRows, kCols,
                                       kCol0, pair0, pair1);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        if (scalar[c] != pair0[c] || scalar1[c] != pair1[c]) return false;
    }
    return true;
}

bool DenseRowBlockI8mmAvailable()
{
    static const bool ok = DenseRowBlockI8mmSelfTest();
    return ok;
}
#endif // __aarch64__ && __ARM_NEON

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
#if defined(__clang__) || defined(__GNUC__)
#define BTX_RC_TARGET_AVX2 __attribute__((target("avx2")))
#else
#define BTX_RC_TARGET_AVX2
#endif

// OS-enabled AVX state (XMM|YMM saved by the OS) + CPUID.7 EBX bit 5 (AVX2).
// Mirrors the detection in matmul_v4_rc_freivalds_i8mm.cpp.
bool DenseAvxStateEnabled()
{
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    if (((ecx >> 27) & 1u) == 0) return false; // OSXSAVE
    uint32_t a = 0, d = 0;
    __asm__("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    return (a & 0x6u) == 0x6u; // XMM (bit1) | YMM (bit2) enabled by the OS.
}

bool DenseHaveAvx2()
{
    if (!DenseAvxStateEnabled()) return false;
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
    GetCPUID(7, 0, eax, ebx, ecx, edx);
    return ((ebx >> 5) & 1u) != 0;
}

// Number of rows folded before the int32 partials are flushed to int64. Chosen so
// a full chunk cannot overflow int32: within a chunk every int32 lane accumulates
// at most kDenseAvx2Chunk products, each |a*b| <= 128*128 = 16384, so
// |lane| <= 65536 * 16384 = 2^16 * 2^14 = 2^30 < 2^31. (kDenseAvx2Chunk*128*128
// < 2^31 is the invariant.)
constexpr uint32_t kDenseAvx2Chunk = 65536;

// AVX2 broadcast-MAC recompute of one 32-col output block. BYTE-IDENTICAL to
// DenseRowBlockScalar for ALL k and all int8 inputs, so it needs neither the
// DenseRowBlockFitsS32 gate nor any k alignment: k is processed in chunks of
// kDenseAvx2Chunk with int32 lane accumulation (exact within a chunk, see above),
// and each chunk's 32 int32 partials fold into int64 acc[] (exact for the whole
// k sum: |acc[c]| <= k*16384, e.g. 786432*16384 ~ 1.3e10 << 2^63).
//
// Lane -> column mapping (must match DenseRowBlockScalar, which writes
// out[c] += a*row[c] with row[c] = rhs[t*rhs_cols + rhs_col0 + c]):
//   - _mm256_loadu_si256 puts row[i] in byte lane i (i=0..31).
//   - _mm256_cvtepi8_epi16 widens the low/high 128-bit halves PRESERVING lane
//     order: w0[j]=row[j] (j=0..15), w1[j]=row[16+j].
//   - _mm256_mullo_epi16 is per-lane, so p0[j]=a*row[j], p1[j]=a*row[16+j]
//     (exact: |a*row| <= 16384 < 2^15, no wrap).
//   - _mm256_cvtepi16_epi32 again preserves lane order across the two 128-bit
//     halves, giving int32 groups of 8: cols 0..7, 8..15, 16..23, 24..31.
//   - acc0..acc3 store to tmp[0..7],[8..15],[16..23],[24..31], i.e. tmp[c] is
//     the partial for column c. No cross-lane permute is ever used, so column c
//     lands in exactly the accumulator lane the scalar loop writes.
BTX_RC_TARGET_AVX2 void DenseRowBlockAvx2S32(const int8_t* lhs, const int8_t* rhs, uint32_t k,
                                             uint32_t rhs_cols, uint32_t rhs_col0,
                                             int64_t out[kRCMxBlockLen])
{
    int64_t acc[kRCMxBlockLen];
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) acc[c] = 0;

    uint32_t t = 0;
    while (t < k) {
        const uint32_t end = std::min(k, t + kDenseAvx2Chunk);
        __m256i acc0 = _mm256_setzero_si256(); // cols 0..7
        __m256i acc1 = _mm256_setzero_si256(); // cols 8..15
        __m256i acc2 = _mm256_setzero_si256(); // cols 16..23
        __m256i acc3 = _mm256_setzero_si256(); // cols 24..31
        for (; t < end; ++t) {
            const int8_t* row = rhs + static_cast<size_t>(t) * rhs_cols + rhs_col0;
            const __m256i b = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(row));
            const __m256i w0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(b));       // row[0..15]
            const __m256i w1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(b, 1));  // row[16..31]
            const __m256i av = _mm256_set1_epi16(static_cast<int16_t>(lhs[t]));
            const __m256i p0 = _mm256_mullo_epi16(av, w0); // a*row[0..15]
            const __m256i p1 = _mm256_mullo_epi16(av, w1); // a*row[16..31]
            acc0 = _mm256_add_epi32(acc0, _mm256_cvtepi16_epi32(_mm256_castsi256_si128(p0)));
            acc1 = _mm256_add_epi32(acc1, _mm256_cvtepi16_epi32(_mm256_extracti128_si256(p0, 1)));
            acc2 = _mm256_add_epi32(acc2, _mm256_cvtepi16_epi32(_mm256_castsi256_si128(p1)));
            acc3 = _mm256_add_epi32(acc3, _mm256_cvtepi16_epi32(_mm256_extracti128_si256(p1, 1)));
        }
        alignas(32) int32_t tmp[kRCMxBlockLen];
        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp + 0), acc0);
        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp + 8), acc1);
        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp + 16), acc2);
        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp + 24), acc3);
        for (uint32_t c = 0; c < kRCMxBlockLen; ++c) acc[c] += static_cast<int64_t>(tmp[c]);
    }
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) out[c] = acc[c];
}

// One byte-equality case vs DenseRowBlockScalar. `extreme` fills lhs/rhs with
// ±128/127 so products sit at the |16384| worst case (exercises int32-per-chunk
// headroom and, for large k, an overall sum that overflows int32 but not int64).
bool DenseRowBlockAvx2Case(uint32_t k, uint32_t rhs_cols, uint32_t rhs_col0, bool extreme)
{
    std::vector<int8_t> lhs(k);
    std::vector<int8_t> rhs(static_cast<size_t>(k) * rhs_cols);
    for (uint32_t t = 0; t < k; ++t) {
        lhs[t] = extreme
                     ? ((t & 1u) ? static_cast<int8_t>(-128) : static_cast<int8_t>(127))
                     : static_cast<int8_t>((static_cast<int32_t>((t * 37u + 11u) & 0xffu)) - 128);
        for (uint32_t j = 0; j < rhs_cols; ++j) {
            const int32_t v =
                extreme ? (((t + j) & 1u) ? -128 : 127)
                        : static_cast<int32_t>(((t + 3u) * 131u + j * 17u) & 0xffu) - 128;
            rhs[static_cast<size_t>(t) * rhs_cols + j] = static_cast<int8_t>(v);
        }
    }
    int64_t scalar[kRCMxBlockLen];
    int64_t avx2[kRCMxBlockLen];
    DenseRowBlockScalar(lhs.data(), rhs.data(), k, rhs_cols, rhs_col0, scalar);
    DenseRowBlockAvx2S32(lhs.data(), rhs.data(), k, rhs_cols, rhs_col0, avx2);
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        if (scalar[c] != avx2[c]) return false;
    }
    return true;
}

bool DenseRowBlockAvx2SelfTest()
{
    if (!DenseHaveAvx2()) return false;
    // Small k with various rhs_col0 (block need not be aligned; rhs_col0+32<=cols).
    if (!DenseRowBlockAvx2Case(1, 32, 0, false)) return false;    // k=1 edge
    if (!DenseRowBlockAvx2Case(257, 96, 32, false)) return false; // offset block
    if (!DenseRowBlockAvx2Case(64, 40, 8, false)) return false;   // unaligned col0
    // Chunk-boundary crossings.
    if (!DenseRowBlockAvx2Case(kDenseAvx2Chunk - 1, 33, 1, false)) return false; // just under
    if (!DenseRowBlockAvx2Case(kDenseAvx2Chunk, 32, 0, false)) return false;     // exactly one chunk
    if (!DenseRowBlockAvx2Case(kDenseAvx2Chunk + 1, 48, 16, false)) return false; // just over
    // Large k, ±128 extremes: spans 4 chunks and its overall sum exceeds int32,
    // proving the int32->int64 fold (200000*16384 ~ 3.3e9 > 2^31).
    if (!DenseRowBlockAvx2Case(200000, 32, 0, true)) return false;
    return true;
}

bool DenseRowBlockAvx2Available()
{
    // Process-wide operator kill switch BTX_RC_DENSE_AVX2=0 forces the int64 scalar
    // recompute everywhere (consensus-safe: the AVX2 and scalar paths are
    // byte-identical, enforced by DenseRowBlockAvx2SelfTest above). Read once and
    // cached so there is no per-block getenv/CPUID and no mid-process flip.
    static const bool ok = [] {
        if (const char* env = std::getenv("BTX_RC_DENSE_AVX2")) {
            if (env[0] == '0' && env[1] == '\0') return false;
        }
        return DenseRowBlockAvx2SelfTest();
    }();
    return ok;
}
#endif // __x86_64__

// The sampleable-unit list: Λ layer indices whose extract_out is streamed.
// Identical on prover and verifier — derived from the public wiring only.
std::vector<uint32_t> SampleableUnits(const std::vector<RCGkrSampledLayerProv>& prov,
                                      bool include_internal_raw)
{
    std::vector<uint32_t> units;
    for (uint32_t i = 0; i < prov.size(); ++i) {
        if (include_internal_raw ? LayerInAccStream(prov[i].kind) : LayerInStream(prov[i].kind)) {
            units.push_back(i);
        }
    }
    return units;
}

// Common trivial/target/digest/round-seed gates + base_seed derivation. Mirrors
// VerifyWinnerProofV7Compact's cheap gate block (reasons prefixed "v7fs:").
bool CheckGatesAndSeed(uint32_t version, const RCEpisodeParams& episode, int32_t proof_height,
                       const uint256& claimed_digest, const uint256& pow_bind,
                       const uint256& episode_sigma, const std::vector<uint256>& round_roots,
                       const std::vector<uint256>& acc_roots,
                       const std::vector<uint256>& round_seeds, const CBlockHeader& header,
                       int32_t height, const arith_uint256& target, uint256& base_seed,
                       std::string& why)
{
    if (version != kRCGkrProofVersionV7) { why = "v7fs:version"; return false; }
    if (!ValidateRCEpisodeParams(episode)) { why = "v7fs:params_invalid"; return false; }
    if (proof_height != height) { why = "v7fs:height"; return false; }
    if (pow_bind != RCGkrDerivePowBind(claimed_digest)) { why = "v7fs:pow_bind"; return false; }
    if (claimed_digest != header.matmul_digest) { why = "v7fs:digest_not_header_bound"; return false; }
    if (episode_sigma != matmul::v4::DeriveSigma(header)) { why = "v7fs:sigma"; return false; }
    if (round_roots.size() != episode.rounds) { why = "v7fs:round_roots_size"; return false; }
    static const std::vector<uint256> empty_acc_roots;
    const std::vector<uint256>& fs_acc_roots =
        UseRCEpisodeDigestV2(episode) ? acc_roots : empty_acc_roots;
    if (UseRCEpisodeDigestV2(episode) && acc_roots.size() != episode.rounds) {
        why = "v7fs:acc_roots_size";
        return false;
    }
    const uint256 digest = RCGkrEpisodeDigestForParams(episode, round_roots, fs_acc_roots);
    if (digest != claimed_digest) { why = "v7fs:digest_from_roots"; return false; }
    if (UintToArith256(digest) > target) { why = "v7fs:target"; return false; }
    for (uint32_t r = 0; r < episode.rounds; ++r) {
        const uint256 expect =
            RCRoundSeedForParams(episode, episode_sigma, round_roots, fs_acc_roots, r);
        if (r >= round_seeds.size() || expect != round_seeds[r]) { why = "v7fs:round_seeds"; return false; }
    }
    base_seed = RCGkrFsSeedV7WithAccRoots(header, height, episode, target, claimed_digest,
                                          episode_sigma, round_roots, fs_acc_roots);
    return true;
}

// Per-sampled-layer core: (b) Freivalds A·B=Y, (c) extract_in==Y(+A) and the
// native Extract sampler re-exec extract_in→extract_out. Shared by both modes.
bool CheckLayerFreivaldsExtract(RCGkrLayerKind kind, uint32_t m, uint32_t k, uint32_t n,
                                const std::vector<int8_t>& A, const std::vector<int8_t>& B,
                                const std::vector<int64_t>& Y,
                                const std::vector<int64_t>& extract_in,
                                const std::vector<int8_t>& extract_out,
                                const uint256& extract_prf,
                                const std::vector<int8_t>& residual,
                                const uint256& base_seed, uint32_t layer_index,
                                uint64_t& n_extract_tiles, std::string& why)
{
    (void)kind;
    const size_t mk = static_cast<size_t>(m) * k;
    const size_t kn = static_cast<size_t>(k) * n;
    const size_t mn = static_cast<size_t>(m) * n;
    if (A.size() != mk || B.size() != kn || Y.size() != mn || extract_in.size() != mn ||
        extract_out.size() != mn) {
        why = "v7fs:wire_shape";
        return false;
    }
    // (b) GEMM correctness by Freivalds random projection (O(mk+kn+mn)).
    const uint256 seed = FreivaldsLayerChallengeSeed(base_seed, layer_index);
    std::string fw;
    if (!FreivaldsCheckGemm(A, B, Y, m, k, n, seed, kRCFreivaldsReps, &fw)) {
        why = "v7fs:freivalds:" + fw;
        return false;
    }
    // (c) accumulator/residual relation: extract_in == Y (+ residual). For the
    // fused DOWN layer the residual is X[l] (the layer input, shaped m×n), NOT the
    // A=H operand; empty for the non-residual kinds.
    if (!residual.empty() && residual.size() != mn) { why = "v7fs:residual_shape"; return false; }
    for (size_t idx = 0; idx < mn; ++idx) {
        int64_t expect = Y[idx];
        if (!residual.empty()) expect += static_cast<int64_t>(residual[idx]);
        if (extract_in[idx] != expect) { why = "v7fs:extract_in:binding"; return false; }
    }
    // (c) Extract sampler glue, re-executed natively for THIS layer's tiles.
    if (n % kRCMxBlockLen != 0) { why = "v7fs:extract:n_block"; return false; }
    gkr_air::TableTM tm;
    gkr_air::TableTX tx;
    const uint32_t n_blocks = n / kRCMxBlockLen;
    for (uint32_t i = 0; i < m; ++i) {
        for (uint32_t bj = 0; bj < n_blocks; ++bj) {
            gkr_air::TilePublic pub;
            pub.prf_key = extract_prf;
            pub.i = i;
            pub.bj = bj;
            std::array<int64_t, kRCMxBlockLen> in{};
            const size_t off = static_cast<size_t>(i) * n + static_cast<size_t>(bj) * kRCMxBlockLen;
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = extract_in[off + t];
            const gkr_air::TileWitness tw = gkr_air::TraceTile(pub, in);
            const gkr_air::TileCheckResult cr = gkr_air::CheckTileConstraints(tw, tm, tx);
            if (!cr.ok) { why = "v7fs:extract_air:" + cr.failure; return false; }
            for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
                if (tw.out[t] != extract_out[off + t]) { why = "v7fs:extract_air:out_binding"; return false; }
            }
            ++n_extract_tiles;
        }
    }
    return true;
}

// Covering leaf window [leaf*T_leaf, +T_leaf) of `stream`, zero-padded at tail.
std::vector<uint8_t> LeafWindow(const std::vector<int8_t>& stream, uint32_t t_leaf, uint32_t leaf)
{
    std::vector<uint8_t> w(t_leaf, 0);
    const size_t start = static_cast<size_t>(leaf) * t_leaf;
    for (uint32_t b = 0; b < t_leaf; ++b) {
        const size_t s = start + b;
        if (s < stream.size()) w[b] = static_cast<uint8_t>(stream[s]);
    }
    return w;
}

// Verify a single covering leaf: its bytes hash + Merkle path reproduce
// round_root, AND its overlap with extract_out[stream_offset .. +len) matches.
//
// R-01 T-BIND: `geom` is the canonical round-tree geometry derived from the
// consensus-pinned episode (RoundStreamTreeGeometry). Before trusting the fold we
// enforce that the supplied path has EXACTLY the canonical depth and that the leaf
// index is a REAL (non-padding, in-range) leaf. Together with VerifyMerkleProof's
// high-bit-consumption check this rejects: a shallow/truncated tree presented for
// the full production vector, an over-long path, a high-bit index alias
// (i vs i+2^d), an out-of-range index, and openings to pow2 padding leaves — none
// of which the bare `cur == root` fold caught. The honest builder is unchanged:
// OpenMerkleProof already emits exactly geom.depth siblings for in-range leaves.
bool CheckCoveringLeaf(const std::vector<uint8_t>& leaf_bytes, uint32_t leaf_index,
                       const RCMerkleProof& mproof, const uint256& round_root, uint32_t t_leaf,
                       uint64_t stream_offset, const std::vector<int8_t>& extract_out,
                       const RoundTreeGeom& geom, std::string& why)
{
    if (leaf_bytes.size() != t_leaf) { why = "v7fs:tiletree:leaf_size"; return false; }
    // Granular reasons for the two geometry binds, then the geometry-checked fold
    // (which re-asserts depth/range and consumes all high index bits).
    if (mproof.siblings.size() != geom.depth) { why = "v7fs:tiletree:depth"; return false; }
    if (leaf_index >= geom.real_leaves) { why = "v7fs:tiletree:leaf_range"; return false; }
    const uint256 leaf_hash = LeafHashFromBytes(leaf_bytes);
    if (!VerifyMerkleProof(leaf_hash, leaf_index, mproof, round_root, geom.depth,
                           geom.real_leaves)) {
        why = "v7fs:tiletree:open";
        return false;
    }
    // Overlap of this leaf's byte range with the extract_out byte range.
    const uint64_t leaf_start = static_cast<uint64_t>(leaf_index) * t_leaf;
    const uint64_t leaf_end = leaf_start + t_leaf;
    const uint64_t eo_start = stream_offset;
    const uint64_t eo_end = stream_offset + extract_out.size();
    const uint64_t lo = std::max(leaf_start, eo_start);
    const uint64_t hi = std::min(leaf_end, eo_end);
    for (uint64_t s = lo; s < hi; ++s) {
        const uint8_t from_leaf = leaf_bytes[s - leaf_start];
        const uint8_t from_eo = static_cast<uint8_t>(extract_out[s - eo_start]);
        if (from_leaf != from_eo) { why = "v7fs:tiletree:bytes"; return false; }
    }
    return true;
}

// ===========================================================================
// ANCHORED per-tile carrier (v3, scratchpad/sound-carrier-design.md §4): a
// sampled layer opens s_tile FS-derived output tiles (each a single (row i,
// 32-col block bj)); per tile the verifier ANCHORS the layer-input row (open
// X[l] row from round_roots, or PRF-regenerate at l=0 / SV) and RECOMPUTES the
// full contraction (H-row + Y-row for DOWN, or S-row + Y for SV) to check the
// committed extract_out. No relayed Y / contraction segments; no tautology.
// The carrier also carries an exact pre-Extract accumulator tag for each opened
// tile. This is carrier-local integrity evidence for opened samples; a complete
// quantization-cost proof needs those accumulator commitments bound before the
// sample challenge.
// ===========================================================================

// One output tile's FS-derived plan: which (row, bcol). Contraction is always
// full (recomputed from anchored operands), so there is no segment plan.
struct TilePlan {
    uint32_t row{0};
    uint32_t bcol{0};
};

bool BoundedSampleCandidate(uint64_t candidate, uint64_t bound, uint64_t& out)
{
    assert(bound != 0);
    const uint64_t reject_below = (uint64_t{0} - bound) % bound;
    if (candidate < reject_below) return false;
    out = candidate % bound;
    return true;
}

class Sha256dCounterXof
{
public:
    explicit Sha256dCounterXof(std::vector<unsigned char> prefix) :
        m_msg(std::move(prefix)), m_prefix_len(m_msg.size())
    {
        m_msg.resize(m_prefix_len + 8);
    }

    uint64_t NextU64()
    {
        if (m_offset == m_block.size()) Refill();
        const uint64_t v = ReadLE64(m_block.data() + m_offset);
        m_offset += 8;
        return v;
    }

private:
    void Refill()
    {
        WriteLE64(m_msg.data() + m_prefix_len, m_counter++);
        const uint256 h = Sha256dBytes(m_msg.data(), m_msg.size());
        std::memcpy(m_block.data(), h.data(), m_block.size());
        m_offset = 0;
    }

    std::vector<unsigned char> m_msg;
    size_t m_prefix_len{0};
    uint64_t m_counter{0};
    std::array<unsigned char, 32> m_block{};
    size_t m_offset{32};
};

uint64_t DrawBounded(Sha256dCounterXof& xof, uint64_t bound)
{
    assert(bound != 0);
    for (;;) {
        uint64_t out = 0;
        if (BoundedSampleCandidate(xof.NextU64(), bound, out)) return out;
    }
}

std::vector<unsigned char> SampleXofPrefix(const uint256& base_seed)
{
    constexpr size_t kTagLen = sizeof(kRCFreivaldsSampleTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32);
    std::memcpy(buf.data(), kRCFreivaldsSampleTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    return buf;
}

std::vector<unsigned char> SegPosXofPrefix(const uint256& base_seed, uint32_t layer_index)
{
    constexpr size_t kTagLen = sizeof(kRCFreivaldsSegPosTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32 + 4);
    std::memcpy(buf.data(), kRCFreivaldsSegPosTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    WriteLE32(buf.data() + kTagLen + 32, layer_index);
    return buf;
}

// Deterministic, verifier-recomputable output-tile plan for a sampled layer of
// shape (m, n). Identical on prover and verifier (the miner cannot choose which
// output entries are opened). FS derivation is a SHA256d counter-XOF over the
// segment-position domain; each bounded draw is exact rejection sampling, so no
// modulo-reduction bias enters the tile schedule.
std::vector<TilePlan> TilePositions(const uint256& base_seed, uint32_t layer_index, uint32_t m,
                                    uint32_t n)
{
    std::vector<TilePlan> plans;
    if (m == 0 || n < kRCMxBlockLen) return plans;
    const uint32_t n_blocks = n / kRCMxBlockLen;
    const uint64_t tile_space = static_cast<uint64_t>(m) * n_blocks;
    const uint32_t want_tiles =
        static_cast<uint32_t>(std::min<uint64_t>(kRCFreivaldsSegOutTiles, tile_space));
    Sha256dCounterXof xof(SegPosXofPrefix(base_seed, layer_index));
    std::unordered_map<uint64_t, uint64_t> remap;
    remap.reserve(want_tiles * 2);
    auto mapped = [&](uint64_t pos) {
        const auto it = remap.find(pos);
        return it == remap.end() ? pos : it->second;
    };
    for (uint64_t i = 0; i < want_tiles; ++i) {
        const uint64_t j = i + DrawBounded(xof, tile_space - i);
        const uint64_t t = mapped(j);
        remap[j] = mapped(i);
        const uint32_t row = static_cast<uint32_t>(t / n_blocks);
        const uint32_t bcol = static_cast<uint32_t>(t - static_cast<uint64_t>(row) * n_blocks);
        plans.push_back(TilePlan{row, bcol});
    }
    return plans;
}

// PRF operand-expansion cache keyed by seed (weights + leaf activations expand
// once per verify; each Λ seed is domain-separated so it maps to one shape).
using RegenCache = std::map<uint256, std::vector<int8_t>>;
using TransposeCache = std::map<uint256, std::vector<int8_t>>;

uint32_t CarrierVerifyThreadCount(size_t jobs)
{
    if (jobs <= 1) return 1;
    uint32_t hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 1;
    uint32_t requested = hw;
    if (const char* env = std::getenv("BTX_RC_CARRIER_VERIFY_THREADS")) {
        char* end = nullptr;
        const unsigned long v = std::strtoul(env, &end, 10);
        if (end != env && v > 0) requested = static_cast<uint32_t>(std::min<unsigned long>(v, 64));
    }
    return std::max<uint32_t>(1, std::min<uint32_t>(requested, static_cast<uint32_t>(std::min<size_t>(jobs, 64))));
}

template <typename Fn>
void ParallelFor(size_t jobs, uint32_t threads, const Fn& fn)
{
    if (jobs == 0) return;
    if (threads <= 1 || jobs <= 1) {
        for (size_t i = 0; i < jobs; ++i) fn(i);
        return;
    }
    std::atomic<size_t> next{0};
    std::exception_ptr eptr;
    std::mutex eptr_mutex;
    std::vector<std::thread> workers;
    workers.reserve(threads);
    for (uint32_t t = 0; t < threads; ++t) {
        workers.emplace_back([&]() {
            try {
                for (;;) {
                    const size_t i = next.fetch_add(1, std::memory_order_relaxed);
                    if (i >= jobs) break;
                    fn(i);
                }
            } catch (...) {
                std::lock_guard<std::mutex> lock(eptr_mutex);
                if (!eptr) eptr = std::current_exception();
                next.store(jobs, std::memory_order_relaxed);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    if (eptr) std::rethrow_exception(eptr);
}

// Extract one 32-col output block (row i, block bj) from an int64 accumulator row,
// using the position-indexed Extract sampler. Returns the T int8 outputs.
std::array<int8_t, kRCMxBlockLen> ExtractBlock(const uint256& prf, uint32_t i, uint32_t bj,
                                               const int64_t* acc_block)
{
    std::array<int8_t, kRCMxBlockLen> out{};
    ExtractMXTileInt64(prf, i, bj, acc_block, out.data());
    return out;
}

} // namespace

namespace test {
bool FreivaldsSampleCandidateAcceptedForTesting(uint64_t candidate, uint64_t bound, uint64_t& out)
{
    if (bound == 0) return false;
    return BoundedSampleCandidate(candidate, bound, out);
}
} // namespace test

bool RCDenseRowBlockVectorizedAvailable()
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    static const bool self_test_ok = DenseRowBlockNeonSelfTest()
#if defined(__ARM_FEATURE_DOTPROD)
        && DenseDotNeonSelfTest()
#endif
        ;
    return self_test_ok;
#else
    return false;
#endif
}

void RCDenseRowBlockExactI8(const int8_t* lhs, const int8_t* rhs, uint32_t k,
                            uint32_t rhs_cols, uint32_t rhs_col0,
                            int64_t out[kRCMxBlockLen])
{
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (RCDenseRowBlockVectorizedAvailable() && DenseRowBlockFitsS32(k)) {
        DenseRowBlockNeonS32(lhs, rhs, k, rhs_cols, rhs_col0, out);
        return;
    }
#endif
#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    // Chunked int32->int64 AVX2 kernel: byte-exact for ANY k (no DenseRowBlockFitsS32
    // gate), so it also covers wide SV (k=n_ctx) that the int32-only NEON path skips.
    if (DenseRowBlockAvx2Available()) {
        DenseRowBlockAvx2S32(lhs, rhs, k, rhs_cols, rhs_col0, out);
        return;
    }
#endif
    DenseRowBlockScalar(lhs, rhs, k, rhs_cols, rhs_col0, out);
}

void RCDenseRowBlockTransposedExactI8(const int8_t* lhs, const int8_t* rhs_t, uint32_t k,
                                      uint32_t rhs_cols, uint32_t rhs_col0,
                                      int64_t out[kRCMxBlockLen])
{
    assert(rhs_col0 + kRCMxBlockLen <= rhs_cols);
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (RCDenseRowBlockVectorizedAvailable() && DenseRowBlockFitsS32(k) && (k % 8) == 0 &&
        DenseRowBlockI8mmAvailable()) {
        DenseRowBlockTransposedI8mmS32(lhs, rhs_t, k, rhs_cols, rhs_col0, out);
        return;
    }
#endif
#if defined(__aarch64__) && defined(__ARM_FEATURE_DOTPROD)
    if (RCDenseRowBlockVectorizedAvailable() && DenseRowBlockFitsS32(k)) {
        for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
            out[c] = static_cast<int64_t>(
                DenseDotNeonS32(lhs, rhs_t + static_cast<size_t>(rhs_col0 + c) * k, k));
        }
        return;
    }
#endif
    for (uint32_t c = 0; c < kRCMxBlockLen; ++c) {
        out[c] = DenseDotScalarI64(lhs, rhs_t + static_cast<size_t>(rhs_col0 + c) * k, k);
    }
}

void RCDenseTwoRowsBlockTransposedExactI8(const int8_t* lhs0, const int8_t* lhs1,
                                          const int8_t* rhs_t, uint32_t k,
                                          uint32_t rhs_cols, uint32_t rhs_col0,
                                          int64_t out0[kRCMxBlockLen],
                                          int64_t out1[kRCMxBlockLen])
{
    assert(rhs_col0 + kRCMxBlockLen <= rhs_cols);
#if defined(__aarch64__) && defined(__ARM_NEON)
    if (RCDenseRowBlockVectorizedAvailable() && DenseRowBlockFitsS32(k) && (k % 8) == 0 &&
        DenseRowBlockI8mmAvailable()) {
        DenseTwoRowsBlockTransposedI8mmS32(lhs0, lhs1, rhs_t, k, rhs_cols, rhs_col0, out0, out1);
        return;
    }
#endif
    RCDenseRowBlockTransposedExactI8(lhs0, rhs_t, k, rhs_cols, rhs_col0, out0);
    RCDenseRowBlockTransposedExactI8(lhs1, rhs_t, k, rhs_cols, rhs_col0, out1);
}

// ---------------------------------------------------------------------------
// FS sample derivation.
// ---------------------------------------------------------------------------
uint256 FreivaldsLayerChallengeSeed(const uint256& base_seed, uint32_t layer_index)
{
    constexpr size_t kTagLen = sizeof(kRCFreivaldsGemmSeedTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32 + 4);
    std::memcpy(buf.data(), kRCFreivaldsGemmSeedTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    WriteLE32(buf.data() + kTagLen + 32, layer_index);
    return Sha256dBytes(buf.data(), buf.size());
}

std::vector<uint32_t> FreivaldsSampleLayers(const uint256& base_seed, uint32_t n_units,
                                            uint32_t lambda)
{
    std::vector<uint32_t> out;
    if (n_units == 0 || lambda == 0) return out;
    const uint32_t want = std::min(lambda, n_units);
    out.reserve(want);
    std::vector<uint32_t> units(n_units);
    for (uint32_t i = 0; i < n_units; ++i) units[i] = i;
    Sha256dCounterXof xof(SampleXofPrefix(base_seed));
    for (uint32_t i = 0; i < want; ++i) {
        const uint32_t j = i + static_cast<uint32_t>(DrawBounded(xof, n_units - i));
        std::swap(units[i], units[j]);
        out.push_back(units[i]);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Full-wires sublinear verifier.
// ---------------------------------------------------------------------------
bool VerifyEpisodeFreivaldsSampled(const RCGkrProofV7& proof, const CBlockHeader& header,
                                   int32_t height, const arith_uint256& target, std::string* why,
                                   RCFreivaldsSampledTiming* out_timing, uint32_t lambda)
{
    const auto t0 = std::chrono::steady_clock::now();
    RCFreivaldsSampledTiming tm;
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        if (out_timing) { tm.ok = false; tm.total_s = Secs(t0); tm.note = m; *out_timing = tm; }
        return false;
    };

    std::string gwhy;
    uint256 base_seed;
    if (!CheckGatesAndSeed(proof.version, proof.episode, proof.height, proof.claimed_digest,
                           proof.pow_bind, proof.episode_sigma, proof.round_roots,
                           proof.acc_roots, proof.round_seeds, header, height, target, base_seed,
                           gwhy)) {
        return fail(gwhy);
    }
    // Layout parity: wires must equal the canonical Λ enumeration (kind/dims).
    const RCGkrLayout layout_l = RCGkrTraceLayout(proof.episode);
    if (proof.wires.size() != layout_l.layers.size()) return fail("v7fs:layout_count");
    for (size_t li = 0; li < layout_l.layers.size(); ++li) {
        const auto& ls = layout_l.layers[li];
        const auto& w = proof.wires[li];
        if (!(ls.kind == w.kind && ls.round == w.round && ls.layer == w.layer && ls.m == w.m &&
              ls.n == w.n && ls.k == w.k)) {
            return fail("v7fs:layout_layer_mismatch");
        }
    }
    const std::vector<RCGkrSampledLayerProv> prov =
        RCGkrEpisodeLayerProvenance(header, proof.episode, proof.round_roots, proof.acc_roots);
    if (prov.size() != proof.wires.size()) return fail("v7fs:wiring_count");
    tm.gates_s = Secs(t0);

    // FS sample derivation over the sampleable units.
    const auto t_s = std::chrono::steady_clock::now();
    const std::vector<uint32_t> sampleable = SampleableUnits(prov, UseRCEpisodeDigestV2(proof.episode));
    tm.n_units_total = static_cast<uint32_t>(sampleable.size());
    const std::vector<uint32_t> units = FreivaldsSampleLayers(base_seed, tm.n_units_total, lambda);
    tm.n_sampled = static_cast<uint32_t>(units.size());
    tm.sample_s = Secs(t_s);

    // The λ sampled-layer checks. Round streams/leaves are built at most once per
    // round that actually holds a sampled layer.
    const auto t_p = std::chrono::steady_clock::now();
    std::unordered_map<uint32_t, std::vector<uint256>> leaves_cache;
    std::unordered_map<uint32_t, std::vector<int8_t>> stream_cache;
    const uint32_t t_leaf = proof.episode.T_leaf;
    // R-01: canonical tile-tree geometry pinned by the episode (same for every
    // round and every opening type — the whole round stream is one tree).
    const RoundTreeGeom geom = RoundStreamTreeGeometry(proof.episode);
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const RCGkrV7WireWitness& w = proof.wires[li];
        const RCGkrSampledLayerProv& lp = prov[li];
        // (b)+(c). The fused DOWN residual is X[l] (the layer input) = the UP wire's
        // A operand (down.A chains to the UP wire's H), NOT w.A (=H).
        std::vector<int8_t> resid;
        if (lp.fwd_residual) {
            if (lp.a.is_leaf || lp.a.src_idx >= proof.wires.size()) return fail("v7fs:residual_src");
            resid = proof.wires[lp.a.src_idx].A;
        }
        std::string cwhy;
        if (!CheckLayerFreivaldsExtract(lp.kind, w.m, w.k, w.n, w.A, w.B, w.Y, w.extract_in,
                                        w.extract_out, lp.extract_prf, resid, base_seed,
                                        li, tm.n_extract_tiles, cwhy)) {
            return fail(cwhy);
        }
        ++tm.n_freivalds_calls;
        // (d) chained-operand byte-equality against the referenced prior wires.
        auto chain_ok = [&](const RCGkrSampledOperandProv& ref, const std::vector<int8_t>& committed,
                            const char* label) -> bool {
            if (ref.is_leaf) return true;
            if (ref.src_idx >= proof.wires.size()) { fail(std::string("v7fs:chain_src:") + label); return false; }
            const std::vector<int8_t>& src = proof.wires[ref.src_idx].extract_out;
            if (src.size() != static_cast<size_t>(ref.erows) * ref.ecols) { fail(std::string("v7fs:chain_dims:") + label); return false; }
            const std::vector<int8_t> expected =
                ref.transpose ? TransposeI8Local(src, ref.erows, ref.ecols) : src;
            if (expected != committed) { fail(std::string("v7fs:chain:") + label); return false; }
            return true;
        };
        if (!chain_ok(lp.a, w.A, "A")) return false;
        if (!chain_ok(lp.b, w.B, "B")) return false;
        // (a) tile-tree opening of extract_out against round_roots[round].
        const uint32_t r = w.round;
        if (r >= proof.round_roots.size()) return fail("v7fs:round_index");
        auto sit = stream_cache.find(r);
        if (sit == stream_cache.end()) {
            sit = stream_cache.emplace(r, RCGkrReconstructRoundStream(proof.wires, r, proof.episode))
                      .first;
            leaves_cache.emplace(r, BuildTileTreeLeaves(sit->second, t_leaf));
        }
        const std::vector<int8_t>& stream_r = sit->second;
        const std::vector<uint256>& leaves = leaves_cache.at(r);
        const uint64_t off = LayerStreamOffset(proof.episode, lp.kind, lp.layer);
        const uint64_t len = w.extract_out.size();
        const uint32_t first_leaf = static_cast<uint32_t>(off / t_leaf);
        const uint32_t last_leaf = static_cast<uint32_t>((off + len - 1) / t_leaf);
        for (uint32_t lf = first_leaf; lf <= last_leaf; ++lf) {
            if (lf >= leaves.size()) return fail("v7fs:tiletree:leaf_index");
            const RCMerkleProof mp = OpenMerkleProof(leaves, lf);
            const std::vector<uint8_t> lb = LeafWindow(stream_r, t_leaf, lf);
            std::string owhy;
            if (!CheckCoveringLeaf(lb, lf, mp, proof.round_roots[r], t_leaf, off, w.extract_out,
                                   geom, owhy)) {
                return fail(owhy);
            }
            tm.n_merkle_hashes += mp.siblings.size();
            ++tm.n_merkle_openings;
        }
        ++tm.n_layers_checked;
    }
    tm.perlayer_s = Secs(t_p);
    tm.ok = true;
    tm.total_s = Secs(t0);
    tm.note = "v7fs full-wires: " + std::to_string(tm.n_layers_checked) + "/" +
              std::to_string(tm.n_units_total) + " layers Freivalds-checked (flat in N)";
    if (out_timing) *out_timing = tm;
    if (why) *why = tm.note;
    return true;
}

// Per-sampled-unit relay byte bound: a function of T_leaf and the tree depth
// only, NOT of m,n,k (width unpin). Per tile is dominated by opened leaves and
// Merkle paths. Tree depth for any reachable N is < 32 (a round stream is < 2^40
// bytes and T_leaf >= 64 => < 2^34 leaves); the bound uses depth 32.
size_t RCFreivaldsSegLayerByteBound(const RCEpisodeParams& params)
{
    const uint32_t T = kRCMxBlockLen;              // 32
    constexpr uint32_t kDepth = 32;                // safe tree-depth upper bound
    const uint64_t one_leaf_open = 3 + params.T_leaf          // covering leaf (full bytes)
                                   + 3 + static_cast<uint64_t>(kDepth) * 32; // Merkle proof
    const uint64_t per_tile =
        8 + 5                       // row + bcol
        + 3 + T                     // extract_out
        + 32                        // exact accumulator tile tag
        + 9 + 5 + one_leaf_open     // accumulator stream_offset + leaf + proof
        + 1                         // a_prf_regen flag
        + 9 + 5                     // a_row_stream_offset + a_row_leaf_index
        + 3 + one_leaf_open         // anchored A-row leaf + proof
        + 9 + 5                     // extract_out stream_offset + first_leaf
        + 3 + one_leaf_open;        // extract_out covering leaf + proof
    return static_cast<size_t>(kRCFreivaldsSegOutTiles) * static_cast<size_t>(per_tile) + 64;
}

// ---------------------------------------------------------------------------
// Carrier builder (miner side) — v3 ANCHORED per-tile carrier. For each FS-sampled
// layer, open s_tile random output tiles (a single (row, 32-col block) each) and,
// per tile, open the anchored layer-input A-row (against round_roots, or leave it
// PRF-regenerable) plus the committed extract_out. No relayed Y and no contraction
// segments (superseded the v2 segment carrier). Relay is bounded by the per-tile
// anchored footprint, independent of the full operand size (design §2c resolution).
// O(N) to reconstruct the round leaves once (intrinsic to the miner's digest).
// ---------------------------------------------------------------------------
bool BuildFreivaldsSampledCarrier(const RCGkrProofV7& proof, const CBlockHeader& header,
                                  int32_t height, const arith_uint256& target,
                                  RCFreivaldsSampledCarrier& out, std::string* why, uint32_t lambda)
{
    auto fail = [&](const std::string& m) { if (why) *why = m; return false; };
    std::string gwhy;
    uint256 base_seed;
    if (!CheckGatesAndSeed(proof.version, proof.episode, proof.height, proof.claimed_digest,
                           proof.pow_bind, proof.episode_sigma, proof.round_roots,
                           proof.acc_roots, proof.round_seeds, header, height, target, base_seed,
                           gwhy)) {
        return fail(gwhy);
    }
    const std::vector<RCGkrSampledLayerProv> prov =
        RCGkrEpisodeLayerProvenance(header, proof.episode, proof.round_roots, proof.acc_roots);
    if (prov.size() != proof.wires.size()) return fail("v7fs:wiring_count");
    const std::vector<uint32_t> sampleable = SampleableUnits(prov, UseRCEpisodeDigestV2(proof.episode));
    const std::vector<uint32_t> units =
        FreivaldsSampleLayers(base_seed, static_cast<uint32_t>(sampleable.size()), lambda);

    out = RCFreivaldsSampledCarrier{};
    out.version = kRCFreivaldsSampledCarrierVersion;
    out.episode = proof.episode;
    out.height = proof.height;
    out.claimed_digest = proof.claimed_digest;
    out.pow_bind = proof.pow_bind;
    out.episode_sigma = proof.episode_sigma;
    out.round_seeds = proof.round_seeds;
    out.round_roots = proof.round_roots;
    out.acc_roots = proof.acc_roots;
    out.lambda = lambda;

    const uint32_t t_leaf = proof.episode.T_leaf;
    const uint32_t T = kRCMxBlockLen;
    std::unordered_map<uint32_t, std::vector<uint256>> leaves_cache;
    std::unordered_map<uint32_t, std::vector<int8_t>> stream_cache;
    std::unordered_map<uint32_t, std::vector<uint256>> acc_leaves_cache;
    std::unordered_map<uint32_t, std::vector<int8_t>> acc_stream_cache;
    auto ensure_stream = [&](uint32_t r)
        -> std::pair<const std::vector<int8_t>*, const std::vector<uint256>*> {
        auto sit = stream_cache.find(r);
        if (sit == stream_cache.end()) {
            sit = stream_cache.emplace(r, RCGkrReconstructRoundStream(proof.wires, r, proof.episode))
                      .first;
            leaves_cache.emplace(r, BuildTileTreeLeaves(sit->second, t_leaf));
        }
        return {&sit->second, &leaves_cache.at(r)};
    };
    auto ensure_acc_stream = [&](uint32_t r)
        -> std::pair<const std::vector<int8_t>*, const std::vector<uint256>*> {
        auto sit = acc_stream_cache.find(r);
        if (sit == acc_stream_cache.end()) {
            sit = acc_stream_cache
                      .emplace(r, RCGkrReconstructRoundAccStream(proof.wires, r, proof.episode))
                      .first;
            acc_leaves_cache.emplace(r, BuildTileTreeLeaves(sit->second, t_leaf));
        }
        return {&sit->second, &acc_leaves_cache.at(r)};
    };
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const RCGkrV7WireWitness& w = proof.wires[li];
        const RCGkrSampledLayerProv& lp = prov[li];
        RCFreivaldsSampledLayer e;
        e.layer_index = li;
        e.round = w.round;
        e.kind = w.kind;
        e.m = w.m; e.n = w.n; e.k = w.k;

        const uint32_t r = w.round;
        const uint64_t layer_off = LayerStreamOffset(proof.episode, lp.kind, lp.layer);

        const std::vector<TilePlan> plans = TilePositions(base_seed, li, w.m, w.n);
        for (const TilePlan& pl : plans) {
            RCFreivaldsSampledTile tile;
            tile.row = pl.row;
            tile.bcol = pl.bcol;
            const size_t ybase = static_cast<size_t>(pl.row) * w.n + static_cast<size_t>(pl.bcol) * T;
            if (LayerInStream(lp.kind)) {
                tile.extract_out.assign(w.extract_out.begin() + ybase,
                                        w.extract_out.begin() + ybase + T);
            }
            tile.acc_tag = AccumulatorTileTag(lp.kind, li, w.round, pl.row, pl.bcol,
                                              w.extract_in.data() + ybase);
            if (!proof.acc_roots.empty()) {
                const auto [acc_stream, acc_leaves] = ensure_acc_stream(r);
                if (!AccTileStreamOffset(proof.episode, lp, pl.row, pl.bcol,
                                         tile.acc_stream_offset)) {
                    return fail("v7fs:build:acc_off");
                }
                tile.acc_first_leaf = static_cast<uint32_t>(tile.acc_stream_offset / t_leaf);
                const uint32_t acc_last_leaf = static_cast<uint32_t>(
                    (tile.acc_stream_offset + T * sizeof(int64_t) - 1) / t_leaf);
                for (uint32_t lf = tile.acc_first_leaf; lf <= acc_last_leaf; ++lf) {
                    if (lf >= acc_leaves->size()) return fail("v7fs:build:acc_leaf_index");
                    tile.acc_leaf_bytes.push_back(LeafWindow(*acc_stream, t_leaf, lf));
                    tile.acc_leaf_proofs.push_back(OpenMerkleProof(*acc_leaves, lf));
                }
            }

            // Anchor the layer-input A-row (X[l] row for DOWN, S row for SV).
            if (lp.kind == RCGkrLayerKind::GemmPhase1SV) {
                tile.a_prf_regen = true; // S regenerated from Q,K (QKt + Extract)
            } else if (lp.kind == RCGkrLayerKind::GemmPhase2FfnUp ||
                       lp.kind == RCGkrLayerKind::GemmPhase2Fwd) {
                // FfnUp anchors X[l] directly. Fwd anchors the UP wire's A operand,
                // which is the same X[l] row feeding H=Extract(X[l]*W_up).
                const RCGkrSampledOperandProv& xprov =
                    (lp.kind == RCGkrLayerKind::GemmPhase2FfnUp)
                        ? lp.a
                        : prov[lp.a.src_idx].a;
                if (xprov.is_leaf) {
                    tile.a_prf_regen = true; // X0 regenerated at l==0
                } else {
                    // Open X[l] committed row from round_roots (same round r).
                    const auto [stream, leaves] = ensure_stream(r);
                    const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                    const uint64_t off_A = LayerStreamOffset(proof.episode, src.kind, src.layer) +
                                           static_cast<uint64_t>(pl.row) * proof.episode.d_model;
                    tile.a_row_stream_offset = off_A;
                    tile.a_row_leaf_index = static_cast<uint32_t>(off_A / t_leaf);
                    if (tile.a_row_leaf_index >= leaves->size()) return fail("v7fs:build:a_leaf_index");
                    tile.a_row_leaf = LeafWindow(*stream, t_leaf, tile.a_row_leaf_index);
                    tile.a_row_proof = OpenMerkleProof(*leaves, tile.a_row_leaf_index);
                }
            } else {
                tile.a_prf_regen = true; // QKt operands are PRF-regenerated by the verifier.
            }

            if (LayerInStream(lp.kind)) {
                const auto [stream, leaves] = ensure_stream(r);
                // Tile-tree opening of this 32-byte extract_out block.
                const uint64_t off = layer_off + static_cast<uint64_t>(pl.row) * w.n +
                                     static_cast<uint64_t>(pl.bcol) * T;
                tile.stream_offset = off;
                tile.first_leaf = static_cast<uint32_t>(off / t_leaf);
                const uint32_t last_leaf = static_cast<uint32_t>((off + T - 1) / t_leaf);
                for (uint32_t lf = tile.first_leaf; lf <= last_leaf; ++lf) {
                    if (lf >= leaves->size()) return fail("v7fs:build:leaf_index");
                    tile.leaf_bytes.push_back(LeafWindow(*stream, t_leaf, lf));
                    tile.leaf_proofs.push_back(OpenMerkleProof(*leaves, lf));
                }
            }
            e.tiles.push_back(std::move(tile));
        }
        out.sampled.push_back(std::move(e));
    }
    return true;
}

// ---------------------------------------------------------------------------
// Carrier verifier (relay-optimized; operates on the v3 ANCHORED carrier ALONE).
// Per sampled layer, recompute the FS output-tile positions and, for each carried
// tile: (b) EXACT-RECOMPUTE the full contraction from anchored operands — H-row +
// Y-row for a fused-FFN DOWN tile (X·W_up then H·W_down + residual), or the S-row
// + S·V for an SV tile — with PRF-regenerated weights, and compare byte-for-byte
// against the committed extract_out. This carrier does NOT run Freivalds and does
// NOT relay Y or contraction segments (the v2 segment-Freivalds path is gone —
// header §v3): every opened tile's GEMM is checked exactly. (c) extract glue is
// covered because the recompute reproduces extract_out through Extract; (a) the
// committed extract_out (and the anchored A-row) open against round_roots.
// O(λ·s_tile·(k + log N)) — the contraction k dominates the per-tile recompute.
// ---------------------------------------------------------------------------
bool VerifyEpisodeFreivaldsSampledCarrier(const RCFreivaldsSampledCarrier& carrier,
                                          const CBlockHeader& header, int32_t height,
                                          const arith_uint256& target, std::string* why,
                                          RCFreivaldsSampledTiming* out_timing)
{
    const auto t0 = std::chrono::steady_clock::now();
    RCFreivaldsSampledTiming tm;
    auto fail = [&](const std::string& m) {
        if (why) *why = m;
        if (out_timing) { tm.ok = false; tm.total_s = Secs(t0); tm.note = m; *out_timing = tm; }
        return false;
    };
    if (carrier.version != kRCFreivaldsSampledCarrierVersion) return fail("v7fs:carrier_version");

    std::string gwhy;
    uint256 base_seed;
    if (!CheckGatesAndSeed(kRCGkrProofVersionV7, carrier.episode, carrier.height,
                           carrier.claimed_digest, carrier.pow_bind, carrier.episode_sigma,
                           carrier.round_roots, carrier.acc_roots, carrier.round_seeds, header,
                           height, target, base_seed, gwhy)) {
        return fail(gwhy);
    }
    if (UseRCEpisodeDigestV2(carrier.episode)) {
        const auto t_terminal = std::chrono::steady_clock::now();
        if (carrier.episode.rounds == 0 ||
            carrier.round_roots.size() != carrier.episode.rounds ||
            carrier.acc_roots.size() != carrier.episode.rounds) {
            return fail("v7fs:terminal_shape");
        }
        const uint32_t terminal_round = carrier.episode.rounds - 1;
        RCRoundTranscript terminal;
        if (!RecomputeRCEpisodeRoundRoots(header, carrier.episode, height, terminal_round,
                                          carrier.round_roots, carrier.acc_roots,
                                          terminal)) {
            return fail("v7fs:terminal_recompute");
        }
        tm.terminal_s = Secs(t_terminal);
        if (terminal.round_root != carrier.round_roots[terminal_round]) {
            return fail("v7fs:terminal_round_root");
        }
        if (terminal.acc_root != carrier.acc_roots[terminal_round]) {
            return fail("v7fs:terminal_acc_root");
        }
    }
    const std::vector<RCGkrSampledLayerProv> prov =
        RCGkrEpisodeLayerProvenance(header, carrier.episode, carrier.round_roots,
                                    carrier.acc_roots);
    const std::vector<uint32_t> sampleable =
        SampleableUnits(prov, UseRCEpisodeDigestV2(carrier.episode));
    tm.n_units_total = static_cast<uint32_t>(sampleable.size());
    const std::vector<uint32_t> units =
        FreivaldsSampleLayers(base_seed, tm.n_units_total, carrier.lambda);
    tm.n_sampled = static_cast<uint32_t>(units.size());
    tm.recompute_vectorized = RCDenseRowBlockVectorizedAvailable() || RCDensePackedI8mmAvailable();
    if (carrier.sampled.size() != units.size()) return fail("v7fs:carrier_count");
    tm.gates_s = Secs(t0);

    {
        const auto t_plan = std::chrono::steady_clock::now();
        const uint32_t t_leaf = carrier.episode.T_leaf;
        const uint32_t T = kRCMxBlockLen;
        // R-01 T-BIND: canonical round tile-tree geometry from the consensus-pinned
        // episode. The carrier's leaf_proofs / a_row_proof are UNTRUSTED (P2P), so
        // every opening below is bound to this depth + real-leaf count. Both the
        // extract_out output-tile opening and the anchored A-row opening target the
        // SAME per-round tree, hence share this one geometry.
        const RoundTreeGeom geom = RoundStreamTreeGeometry(carrier.episode);
        const RoundTreeGeom acc_geom = AccStreamTreeGeometry(carrier.episode);
        struct UnitPlan {
            size_t carrier_index{0};
            uint32_t li{0};
            std::vector<TilePlan> tiles;
        };
        struct SeedPlan {
            uint32_t rows{0};
            uint32_t cols{0};
            uint32_t uses{0};
            bool transpose_for_unitcheck{false};
        };
        std::vector<UnitPlan> unit_plans;
        unit_plans.reserve(units.size());
        std::map<uint256, SeedPlan> seed_plan;
        uint64_t seed_uses = 0;
        auto note_seed = [&](const uint256& seed, uint32_t rows, uint32_t cols,
                             bool transpose_for_unitcheck = false) -> bool {
            auto it = seed_plan.find(seed);
            if (it == seed_plan.end()) {
                seed_plan.emplace(seed, SeedPlan{rows, cols, 1, transpose_for_unitcheck});
            } else {
                if (it->second.rows != rows || it->second.cols != cols) return false;
                ++it->second.uses;
                it->second.transpose_for_unitcheck =
                    it->second.transpose_for_unitcheck || transpose_for_unitcheck;
            }
            ++seed_uses;
            return true;
        };
        auto note_x0_row = [&](const RCGkrSampledOperandProv& xprov, uint32_t row,
                               uint32_t d_model) -> bool {
            if (!xprov.x0_row_blocks) {
                return note_seed(xprov.seed, carrier.episode.b_seq, d_model);
            }
            if (xprov.erows != carrier.episode.b_seq || xprov.ecols != d_model ||
                row >= carrier.episode.b_seq) {
                return false;
            }
            const uint32_t block = row / kRCX0RowBlockRows;
            return note_seed(DeriveX0RowBlockSeed(xprov.seed, block), kRCX0RowBlockRows,
                             d_model);
        };

        for (size_t j = 0; j < units.size(); ++j) {
            const uint32_t li = sampleable[units[j]];
            const RCFreivaldsSampledLayer& e = carrier.sampled[j];
            if (e.layer_index != li) return fail("v7fs:carrier_order");
            if (li >= prov.size()) return fail("v7fs:carrier_layer_index");
            const RCGkrSampledLayerProv& lp = prov[li];
            if (!(e.kind == lp.kind && e.m == lp.m && e.n == lp.n && e.k == lp.k)) {
                return fail("v7fs:carrier_layer_mismatch");
            }
            if (e.n % T != 0) return fail("v7fs:carrier_n_block");
            if (e.round >= carrier.round_roots.size()) return fail("v7fs:round_index");
            const std::vector<TilePlan> plans = TilePositions(base_seed, li, e.m, e.n);
            if (e.tiles.size() != plans.size()) return fail("v7fs:carrier_tile_count");
            for (size_t ti = 0; ti < plans.size(); ++ti) {
                const TilePlan& pl = plans[ti];
                const RCFreivaldsSampledTile& tile = e.tiles[ti];
                if (tile.row != pl.row || tile.bcol != pl.bcol) return fail("v7fs:carrier_tile_pos");
                if (LayerInStream(lp.kind)) {
                    if (tile.extract_out.size() != T) return fail("v7fs:tile_shape");
                } else if (!tile.extract_out.empty()) {
                    return fail("v7fs:internal_extract_out");
                }
                if (tile.row >= e.m || tile.bcol >= e.n / T) return fail("v7fs:tile_range");
                if (!carrier.acc_roots.empty()) {
                    uint64_t acc_off = 0;
                    if (!AccTileStreamOffset(carrier.episode, lp, tile.row, tile.bcol, acc_off)) {
                        return fail("v7fs:acc_off");
                    }
                    if (tile.acc_stream_offset != acc_off) return fail("v7fs:acc_off");
                    if (tile.acc_first_leaf != static_cast<uint32_t>(acc_off / t_leaf)) {
                        return fail("v7fs:acc_leaf_index");
                    }
                    const uint32_t acc_last = static_cast<uint32_t>(
                        (acc_off + T * sizeof(int64_t) - 1) / t_leaf);
                    if (tile.acc_leaf_bytes.size() !=
                            static_cast<size_t>(acc_last - tile.acc_first_leaf + 1) ||
                        tile.acc_leaf_proofs.size() != tile.acc_leaf_bytes.size()) {
                        return fail("v7fs:acc_leaf_count");
                    }
                }
            }
            if (lp.kind == RCGkrLayerKind::GemmPhase1QKt) {
                for (const auto& tile : e.tiles) {
                    if (!tile.a_prf_regen || !tile.a_row_leaf.empty()) return fail("v7fs:qkt_anchor");
                    if (!note_seed(lp.a.seed, e.m, e.k)) return fail("v7fs:seed_shape");
                    if (!note_seed(lp.b.seed, e.n, e.k)) return fail("v7fs:seed_shape");
                }
            } else if (lp.kind == RCGkrLayerKind::GemmPhase1SV) {
                if (lp.a.is_leaf || lp.a.src_idx >= prov.size()) return fail("v7fs:sv_qkt_src");
                const RCGkrSampledLayerProv& qkt = prov[lp.a.src_idx];
                if (qkt.kind != RCGkrLayerKind::GemmPhase1QKt) return fail("v7fs:sv_qkt_kind");
                const uint32_t d_head = carrier.episode.d_head;
                const uint32_t n_ctx = e.k;
                if (n_ctx % T != 0) return fail("v7fs:sv_ctx_block");
                for (const auto& tile : e.tiles) {
                    if (!tile.a_prf_regen || !tile.a_row_leaf.empty()) return fail("v7fs:sv_anchor");
                    if (!note_seed(qkt.a.seed, carrier.episode.n_q, d_head)) return fail("v7fs:seed_shape");
                    if (!note_seed(qkt.b.seed, n_ctx, d_head)) return fail("v7fs:seed_shape");
                    if (!note_seed(lp.b.seed, n_ctx, d_head)) return fail("v7fs:seed_shape");
                }
            } else if (lp.kind == RCGkrLayerKind::GemmPhase2FfnUp) {
                const uint32_t d_model = e.k;
                const uint32_t d_ff = e.n;
                if (d_model > t_leaf) return fail("v7fs:up_a_row_multileaf");
                const RCGkrSampledOperandProv& xprov = lp.a;
                for (const auto& tile : e.tiles) {
                    if (xprov.is_leaf) {
                        if (!tile.a_prf_regen || !tile.a_row_leaf.empty())
                            return fail("v7fs:up_l0_anchor");
                        if (!note_x0_row(xprov, tile.row, d_model))
                            return fail("v7fs:seed_shape");
                    } else {
                        if (tile.a_prf_regen) return fail("v7fs:up_anchor_flag");
                        if (xprov.src_idx >= prov.size()) return fail("v7fs:up_x_src");
                        const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                        const uint64_t off_A = LayerStreamOffset(carrier.episode, src.kind, src.layer) +
                                               static_cast<uint64_t>(tile.row) * d_model;
                        if (tile.a_row_stream_offset != off_A) return fail("v7fs:up_a_off");
                        const uint32_t a_leaf = static_cast<uint32_t>(off_A / t_leaf);
                        if (tile.a_row_leaf_index != a_leaf) return fail("v7fs:up_a_leaf_index");
                        if (tile.a_row_leaf.size() != t_leaf) return fail("v7fs:up_a_leaf_size");
                        const uint64_t rel = off_A - static_cast<uint64_t>(a_leaf) * t_leaf;
                        if (rel + d_model > t_leaf) return fail("v7fs:up_a_row_span");
                    }
                    if (!note_seed(lp.b.seed, d_model, d_ff, /*transpose_w_up=*/true))
                        return fail("v7fs:seed_shape");
                }
            } else if (lp.kind == RCGkrLayerKind::GemmPhase2Fwd) {
                if (lp.a.is_leaf || lp.a.src_idx >= prov.size()) return fail("v7fs:down_a_src");
                const RCGkrSampledLayerProv& up = prov[lp.a.src_idx];
                if (up.kind != RCGkrLayerKind::GemmPhase2FfnUp) return fail("v7fs:down_up_kind");
                const uint32_t d_model = e.n;
                const uint32_t d_ff = e.k;
                if (d_ff % T != 0) return fail("v7fs:down_ff_block");
                if (d_model > t_leaf) return fail("v7fs:a_row_multileaf");
                const RCGkrSampledOperandProv& xprov = up.a;
                for (const auto& tile : e.tiles) {
                    if (xprov.is_leaf) {
                        if (!tile.a_prf_regen || !tile.a_row_leaf.empty())
                            return fail("v7fs:down_l0_anchor");
                        if (!note_x0_row(xprov, tile.row, d_model))
                            return fail("v7fs:seed_shape");
                    } else {
                        if (tile.a_prf_regen) return fail("v7fs:down_anchor_flag");
                        if (xprov.src_idx >= prov.size()) return fail("v7fs:down_x_src");
                        const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                        const uint64_t off_A = LayerStreamOffset(carrier.episode, src.kind, src.layer) +
                                               static_cast<uint64_t>(tile.row) * d_model;
                        if (tile.a_row_stream_offset != off_A) return fail("v7fs:a_off");
                        const uint32_t a_leaf = static_cast<uint32_t>(off_A / t_leaf);
                        if (tile.a_row_leaf_index != a_leaf) return fail("v7fs:a_leaf_index");
                        if (tile.a_row_leaf.size() != t_leaf) return fail("v7fs:a_leaf_size");
                        const uint64_t rel = off_A - static_cast<uint64_t>(a_leaf) * t_leaf;
                        if (rel + d_model > t_leaf) return fail("v7fs:a_row_span");
                    }
                    if (!note_seed(up.b.seed, d_model, d_ff, /*transpose_w_up=*/true))
                        return fail("v7fs:seed_shape");
                    if (!note_seed(lp.b.seed, d_ff, d_model, /*transpose_for_unitcheck=*/true))
                        return fail("v7fs:seed_shape");
                }
            } else {
                return fail("v7fs:unsupported_kind");
            }
            unit_plans.push_back(UnitPlan{j, li, plans});
        }
        tm.plan_s = Secs(t_plan);
        tm.verify_threads = CarrierVerifyThreadCount(std::max(unit_plans.size(), seed_plan.size()));
        tm.regen_misses = static_cast<uint32_t>(seed_plan.size());
        tm.regen_hits = seed_uses > seed_plan.size()
                            ? static_cast<uint32_t>(seed_uses - seed_plan.size())
                            : 0;
        for (const auto& [seed, sp] : seed_plan) {
            (void)seed;
            tm.regen_bytes += static_cast<uint64_t>(sp.rows) * sp.cols;
        }

        struct SeedJob {
            uint256 seed;
            uint32_t rows{0};
            uint32_t cols{0};
            bool transpose_for_unitcheck{false};
            std::vector<int8_t> bytes;
        };
        std::vector<SeedJob> seed_jobs;
        seed_jobs.reserve(seed_plan.size());
        for (const auto& [seed, sp] : seed_plan) {
            seed_jobs.push_back(SeedJob{seed, sp.rows, sp.cols, sp.transpose_for_unitcheck, {}});
        }
        const bool use_packed_i8mm = RCDensePackedI8mmAvailable();
        RegenCache regen;
        TransposeCache unitcheck_w_cache;
        const auto t_prewarm = std::chrono::steady_clock::now();
        try {
            std::sort(seed_jobs.begin(), seed_jobs.end(), [](const SeedJob& a, const SeedJob& b) {
                const uint64_t abytes = static_cast<uint64_t>(a.rows) * a.cols;
                const uint64_t bbytes = static_cast<uint64_t>(b.rows) * b.cols;
                if (abytes != bbytes) return abytes > bbytes;
                return a.seed < b.seed;
            });
            const auto t_regen = std::chrono::steady_clock::now();
            const uint32_t inner_threads = CarrierPrewarmInnerThreads(tm.verify_threads);
            const uint32_t outer_threads = std::max<uint32_t>(1, tm.verify_threads / inner_threads);
            ParallelFor(seed_jobs.size(), outer_threads, [&](size_t i) {
                seed_jobs[i].bytes =
                    ExpandMxDequantInt8Parallel(seed_jobs[i].seed, seed_jobs[i].rows,
                                                seed_jobs[i].cols, inner_threads);
            });
            tm.regen_s = Secs(t_regen);
            for (auto& job : seed_jobs) regen.emplace(job.seed, std::move(job.bytes));

            std::vector<size_t> transpose_jobs;
            for (size_t i = 0; i < seed_jobs.size(); ++i) {
                if (seed_jobs[i].transpose_for_unitcheck) transpose_jobs.push_back(i);
            }
            std::vector<std::vector<int8_t>> transposed_bytes(transpose_jobs.size());
            ParallelFor(transpose_jobs.size(), tm.verify_threads, [&](size_t i) {
                const SeedJob& job = seed_jobs[transpose_jobs[i]];
                const auto it = regen.find(job.seed);
                if (it == regen.end()) throw std::runtime_error("missing prewarmed W_up");
                transposed_bytes[i] = use_packed_i8mm
                    ? RCPackDenseI8mmOutputBlocks(it->second, job.rows, job.cols)
                    : TransposeI8Local(it->second, job.rows, job.cols);
            });
            for (size_t i = 0; i < transpose_jobs.size(); ++i) {
                unitcheck_w_cache.emplace(seed_jobs[transpose_jobs[i]].seed, std::move(transposed_bytes[i]));
            }
        } catch (...) {
            return fail("v7fs:worker_exception");
        }
        tm.prewarm_s = Secs(t_prewarm);

        struct UnitResult {
            bool ok{true};
            std::string why;
            uint32_t n_layers_checked{0};
            uint32_t n_freivalds_calls{0};
            uint64_t n_extract_tiles{0};
            uint32_t n_merkle_openings{0};
            uint64_t n_merkle_hashes{0};
            double recompute_s{0.0};
            double merkle_s{0.0};
        };
        std::vector<UnitResult> results(unit_plans.size());
        const RegenCache& regen_ro = regen;
        const TransposeCache& unitcheck_w_ro = unitcheck_w_cache;
        auto get_seed = [&](const uint256& seed) -> const std::vector<int8_t>& {
            const auto it = regen_ro.find(seed);
            if (it == regen_ro.end()) throw std::runtime_error("missing prewarmed seed");
            return it->second;
        };
        auto get_transposed = [&](const uint256& seed) -> const std::vector<int8_t>& {
            const auto it = unitcheck_w_ro.find(seed);
            if (it == unitcheck_w_ro.end()) throw std::runtime_error("missing unitcheck W cache");
            return it->second;
        };

        const auto t_unit = std::chrono::steady_clock::now();
        try {
            ParallelFor(unit_plans.size(), tm.verify_threads, [&](size_t pi) {
                UnitResult r;
                auto reject = [&](const std::string& m) {
                    r.ok = false;
                    r.why = m;
                };
                const UnitPlan& plan = unit_plans[pi];
                const RCFreivaldsSampledLayer& e = carrier.sampled[plan.carrier_index];
                const RCGkrSampledLayerProv& lp = prov[plan.li];
                const uint64_t layer_off = LayerStreamOffset(carrier.episode, lp.kind, lp.layer);
                auto finish_tile = [&](const RCFreivaldsSampledTile& tile,
                                       const int64_t* acc_block,
                                       const std::array<int8_t, kRCMxBlockLen>& eo) -> bool {
                    const uint256 expect_acc =
                        AccumulatorTileTag(lp.kind, plan.li, e.round, tile.row, tile.bcol, acc_block);
                    if (tile.acc_tag != expect_acc) {
                        reject("v7fs:acc_tag");
                        return false;
                    }
                    if (!carrier.acc_roots.empty()) {
                        if (e.round >= carrier.acc_roots.size()) {
                            reject("v7fs:acc_round");
                            return false;
                        }
                        const std::vector<int8_t> acc_bytes = AccumulatorTileBytes(acc_block);
                        const uint32_t first_leaf =
                            static_cast<uint32_t>(tile.acc_stream_offset / t_leaf);
                        const uint32_t last_leaf = static_cast<uint32_t>(
                            (tile.acc_stream_offset + acc_bytes.size() - 1) / t_leaf);
                        if (tile.acc_first_leaf != first_leaf) {
                            reject("v7fs:acc_first_leaf");
                            return false;
                        }
                        const uint32_t n_leaves = last_leaf - first_leaf + 1;
                        if (tile.acc_leaf_bytes.size() != n_leaves ||
                            tile.acc_leaf_proofs.size() != n_leaves) {
                            reject("v7fs:acc_leaf_count");
                            return false;
                        }
                        for (uint32_t x = 0; x < n_leaves; ++x) {
                            const uint32_t lf = first_leaf + x;
                            std::string awhy;
                            const auto t_mk_acc = std::chrono::steady_clock::now();
                            const bool acc_ok =
                                CheckCoveringLeaf(tile.acc_leaf_bytes[x], lf,
                                                  tile.acc_leaf_proofs[x],
                                                  carrier.acc_roots[e.round], t_leaf,
                                                  tile.acc_stream_offset, acc_bytes, acc_geom,
                                                  awhy);
                            r.merkle_s += Secs(t_mk_acc);
                            if (!acc_ok) {
                                reject("v7fs:acc_" + awhy);
                                return false;
                            }
                            r.n_merkle_hashes += tile.acc_leaf_proofs[x].siblings.size();
                            ++r.n_merkle_openings;
                        }
                    }
                    if (!LayerInStream(lp.kind)) {
                        if (!tile.leaf_bytes.empty() || !tile.leaf_proofs.empty() ||
                            !tile.extract_out.empty()) {
                            reject("v7fs:internal_output_opening");
                            return false;
                        }
                        ++r.n_freivalds_calls;
                        return true;
                    }
                    for (uint32_t c = 0; c < T; ++c) {
                        if (eo[c] != tile.extract_out[c]) {
                            reject("v7fs:recompute_mismatch");
                            return false;
                        }
                    }
                    ++r.n_extract_tiles;
                    // NOTE: the carrier path does NOT Freivalds. This counter
                    // tallies EXACT per-tile recompute checks (one per opened
                    // tile); the "freivalds" name is retained only for cross-path
                    // instrumentation continuity with the full-wires verifier (which
                    // does run FreivaldsCheckGemm). See the struct-field comment.
                    ++r.n_freivalds_calls;
                    const uint64_t off_expect = layer_off + static_cast<uint64_t>(tile.row) * e.n +
                                                static_cast<uint64_t>(tile.bcol) * T;
                    if (tile.stream_offset != off_expect) { reject("v7fs:carrier_offset"); return false; }
                    const uint32_t first_leaf = static_cast<uint32_t>(off_expect / t_leaf);
                    const uint32_t last_leaf = static_cast<uint32_t>((off_expect + T - 1) / t_leaf);
                    if (tile.first_leaf != first_leaf) { reject("v7fs:carrier_first_leaf"); return false; }
                    const uint32_t n_leaves = last_leaf - first_leaf + 1;
                    if (tile.leaf_bytes.size() != n_leaves || tile.leaf_proofs.size() != n_leaves) {
                        reject("v7fs:carrier_leaf_count");
                        return false;
                    }
                    for (uint32_t x = 0; x < n_leaves; ++x) {
                        const uint32_t lf = first_leaf + x;
                        std::string owhy;
                        const auto t_mk2 = std::chrono::steady_clock::now();
                        const bool eo_ok = CheckCoveringLeaf(tile.leaf_bytes[x], lf, tile.leaf_proofs[x],
                                           carrier.round_roots[e.round], t_leaf, off_expect,
                                           tile.extract_out, geom, owhy);
                        r.merkle_s += Secs(t_mk2);
                        if (!eo_ok) {
                            reject(owhy);
                            return false;
                        }
                        r.n_merkle_hashes += tile.leaf_proofs[x].siblings.size();
                        ++r.n_merkle_openings;
                    }
                    return true;
                };
                if (lp.kind == RCGkrLayerKind::GemmPhase1QKt) {
                    const std::vector<int8_t>& Q = get_seed(lp.a.seed);
                    const std::vector<int8_t>& K = get_seed(lp.b.seed);
                    for (size_t ti = 0; ti < plan.tiles.size(); ++ti) {
                        const RCFreivaldsSampledTile& tile = e.tiles[ti];
                        const auto t_rc_qkt = std::chrono::steady_clock::now();
                        std::array<int64_t, kRCMxBlockLen> qblk{};
                        const uint32_t out_col0 = tile.bcol * T;
                        for (uint32_t c = 0; c < T; ++c) {
                            const uint32_t ctx = out_col0 + c;
                            int64_t acc = 0;
                            for (uint32_t d = 0; d < e.k; ++d) {
                                acc += static_cast<int64_t>(Q[static_cast<size_t>(tile.row) * e.k + d]) *
                                       static_cast<int64_t>(K[static_cast<size_t>(ctx) * e.k + d]);
                            }
                            qblk[c] = acc;
                        }
                        r.recompute_s += Secs(t_rc_qkt);
                        std::array<int8_t, kRCMxBlockLen> unused_eo{};
                        if (!finish_tile(tile, qblk.data(), unused_eo)) break;
                    }
                } else if (lp.kind == RCGkrLayerKind::GemmPhase1SV) {
                    for (size_t ti = 0; ti < plan.tiles.size(); ++ti) {
                        const RCFreivaldsSampledTile& tile = e.tiles[ti];
                        const RCGkrSampledLayerProv& qkt = prov[lp.a.src_idx];
                        const uint32_t d_head = carrier.episode.d_head;
                        const uint32_t n_ctx = e.k;
                        const std::vector<int8_t>& Q = get_seed(qkt.a.seed);
                        const std::vector<int8_t>& K = get_seed(qkt.b.seed);
                        const std::vector<int8_t>& V = get_seed(lp.b.seed);
                        const auto t_rc_sv = std::chrono::steady_clock::now();
                        std::vector<int8_t> S_row(n_ctx);
                        std::array<int64_t, kRCMxBlockLen> blk{};
                        for (uint32_t bt = 0; bt < n_ctx / T; ++bt) {
                            for (uint32_t c = 0; c < T; ++c) {
                                const uint32_t t = bt * T + c;
                                int64_t acc = 0;
                                for (uint32_t d = 0; d < d_head; ++d)
                                    acc += static_cast<int64_t>(Q[static_cast<size_t>(tile.row) * d_head + d]) *
                                           static_cast<int64_t>(K[static_cast<size_t>(t) * d_head + d]);
                                blk[c] = acc;
                            }
                            const auto so = ExtractBlock(qkt.extract_prf, tile.row, bt, blk.data());
                            for (uint32_t c = 0; c < T; ++c) S_row[bt * T + c] = so[c];
                        }
                        std::array<int64_t, kRCMxBlockLen> yblk{};
                        const uint32_t out_col0 = tile.bcol * T;
                        RCDenseRowBlockExactI8(S_row.data(), V.data(), n_ctx, d_head, out_col0,
                                               yblk.data());
                        const std::array<int8_t, kRCMxBlockLen> eo =
                            ExtractBlock(lp.extract_prf, tile.row, tile.bcol, yblk.data());
                        r.recompute_s += Secs(t_rc_sv);
                        if (!finish_tile(tile, yblk.data(), eo)) break;
                    }
                } else if (lp.kind == RCGkrLayerKind::GemmPhase2FfnUp) {
                    const uint32_t d_model = e.k;
                    const uint32_t d_ff = e.n;
                    const RCGkrSampledOperandProv& xprov = lp.a;
                    const std::vector<int8_t>& W_up_t = get_transposed(lp.b.seed);
                    auto load_x_row = [&](const RCFreivaldsSampledTile& tile,
                                          std::vector<int8_t>& X_row) -> bool {
                        X_row.assign(d_model, 0);
                        if (xprov.is_leaf) {
                            if (xprov.x0_row_blocks) {
                                const uint32_t block = tile.row / kRCX0RowBlockRows;
                                const uint32_t rel = tile.row % kRCX0RowBlockRows;
                                const std::vector<int8_t>& X0 =
                                    get_seed(DeriveX0RowBlockSeed(xprov.seed, block));
                                for (uint32_t d = 0; d < d_model; ++d)
                                    X_row[d] = X0[static_cast<size_t>(rel) * d_model + d];
                            } else {
                                const std::vector<int8_t>& X0 = get_seed(xprov.seed);
                                for (uint32_t d = 0; d < d_model; ++d)
                                    X_row[d] = X0[static_cast<size_t>(tile.row) * d_model + d];
                            }
                        } else {
                            std::string awhy;
                            const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                            const uint64_t off_A = LayerStreamOffset(carrier.episode, src.kind, src.layer) +
                                                   static_cast<uint64_t>(tile.row) * d_model;
                            const uint32_t a_leaf = static_cast<uint32_t>(off_A / t_leaf);
                            const uint64_t rel = off_A - static_cast<uint64_t>(a_leaf) * t_leaf;
                            for (uint32_t d = 0; d < d_model; ++d)
                                X_row[d] = static_cast<int8_t>(tile.a_row_leaf[rel + d]);
                            const auto t_mk = std::chrono::steady_clock::now();
                            const bool a_ok = CheckCoveringLeaf(tile.a_row_leaf, a_leaf, tile.a_row_proof,
                                                   carrier.round_roots[e.round], t_leaf, off_A, X_row,
                                                   geom, awhy);
                            r.merkle_s += Secs(t_mk);
                            if (!a_ok) { reject(awhy); return false; }
                            r.n_merkle_hashes += tile.a_row_proof.siblings.size();
                            ++r.n_merkle_openings;
                        }
                        return true;
                    };
                    for (size_t ti = 0; ti < plan.tiles.size(); ++ti) {
                        const RCFreivaldsSampledTile& tile = e.tiles[ti];
                        std::vector<int8_t> X_row;
                        if (!load_x_row(tile, X_row)) break;
                        const auto t_rc_up = std::chrono::steady_clock::now();
                        std::array<int64_t, kRCMxBlockLen> hblk{};
                        const uint32_t out_col0 = tile.bcol * T;
                        if (use_packed_i8mm) {
                            RCDenseRowBlockPackedI8mmExactI8(X_row.data(), W_up_t.data(), d_model,
                                                             d_ff, out_col0, hblk.data());
                        } else {
                            RCDenseRowBlockTransposedExactI8(X_row.data(), W_up_t.data(), d_model,
                                                             d_ff, out_col0, hblk.data());
                        }
                        r.recompute_s += Secs(t_rc_up);
                        std::array<int8_t, kRCMxBlockLen> unused_eo{};
                        if (!finish_tile(tile, hblk.data(), unused_eo)) break;
                    }
                } else {
                    const RCGkrSampledLayerProv& up = prov[lp.a.src_idx];
                    const uint32_t d_model = e.n;
                    const uint32_t d_ff = e.k;
                    const RCGkrSampledOperandProv& xprov = up.a;
                    const std::vector<int8_t>& W_up_t = get_transposed(up.b.seed);
                    const std::vector<int8_t>& W_down_t = get_transposed(lp.b.seed);
                    auto load_x_row = [&](const RCFreivaldsSampledTile& tile,
                                          std::vector<int8_t>& X_row) -> bool {
                        X_row.assign(d_model, 0);
                        if (xprov.is_leaf) {
                            if (xprov.x0_row_blocks) {
                                const uint32_t block = tile.row / kRCX0RowBlockRows;
                                const uint32_t rel = tile.row % kRCX0RowBlockRows;
                                const std::vector<int8_t>& X0 =
                                    get_seed(DeriveX0RowBlockSeed(xprov.seed, block));
                                for (uint32_t d = 0; d < d_model; ++d)
                                    X_row[d] = X0[static_cast<size_t>(rel) * d_model + d];
                            } else {
                                const std::vector<int8_t>& X0 = get_seed(xprov.seed);
                                for (uint32_t d = 0; d < d_model; ++d)
                                    X_row[d] = X0[static_cast<size_t>(tile.row) * d_model + d];
                            }
                        } else {
                            std::string awhy;
                            const RCGkrSampledLayerProv& src = prov[xprov.src_idx];
                            const uint64_t off_A = LayerStreamOffset(carrier.episode, src.kind, src.layer) +
                                                   static_cast<uint64_t>(tile.row) * d_model;
                            const uint32_t a_leaf = static_cast<uint32_t>(off_A / t_leaf);
                            const uint64_t rel = off_A - static_cast<uint64_t>(a_leaf) * t_leaf;
                            for (uint32_t d = 0; d < d_model; ++d)
                                X_row[d] = static_cast<int8_t>(tile.a_row_leaf[rel + d]);
                            const auto t_mk = std::chrono::steady_clock::now();
                            const bool a_ok = CheckCoveringLeaf(tile.a_row_leaf, a_leaf, tile.a_row_proof,
                                                   carrier.round_roots[e.round], t_leaf, off_A, X_row,
                                                   geom, awhy);
                            r.merkle_s += Secs(t_mk);
                            if (!a_ok) { reject(awhy); return false; }
                            r.n_merkle_hashes += tile.a_row_proof.siblings.size();
                            ++r.n_merkle_openings;
                        }
                        return true;
                    };

                    for (size_t ti = 0; ti < plan.tiles.size();) {
                        const bool paired = ti + 1 < plan.tiles.size();
                        const RCFreivaldsSampledTile& tile0 = e.tiles[ti];
                        std::vector<int8_t> X0;
                        if (!load_x_row(tile0, X0)) break;
                        std::vector<int8_t> X1;
                        const RCFreivaldsSampledTile* tile1 = nullptr;
                        if (paired) {
                            tile1 = &e.tiles[ti + 1];
                            if (!load_x_row(*tile1, X1)) break;
                        }
                        const auto t_rc_dn = std::chrono::steady_clock::now();
                        std::vector<int8_t> H0(d_ff);
                        std::vector<int8_t> H1(paired ? d_ff : 0);
                        std::array<int64_t, kRCMxBlockLen> blk{};
                        std::array<int64_t, kRCMxBlockLen> blk1{};
                        for (uint32_t bj = 0; bj < d_ff / T; ++bj) {
                            const uint32_t col0 = bj * T;
                            if (paired) {
                                if (use_packed_i8mm) {
                                    RCDenseTwoRowsBlockPackedI8mmExactI8(X0.data(), X1.data(), W_up_t.data(),
                                                                        d_model, d_ff, col0,
                                                                        blk.data(), blk1.data());
                                } else {
                                    RCDenseTwoRowsBlockTransposedExactI8(X0.data(), X1.data(), W_up_t.data(),
                                                                         d_model, d_ff, col0,
                                                                         blk.data(), blk1.data());
                                }
                            } else {
                                if (use_packed_i8mm) {
                                    RCDenseRowBlockPackedI8mmExactI8(X0.data(), W_up_t.data(), d_model,
                                                                     d_ff, col0, blk.data());
                                } else {
                                    RCDenseRowBlockTransposedExactI8(X0.data(), W_up_t.data(), d_model,
                                                                     d_ff, col0, blk.data());
                                }
                            }
                            const auto h0 = ExtractBlock(up.extract_prf, tile0.row, bj, blk.data());
                            for (uint32_t c = 0; c < T; ++c) H0[bj * T + c] = h0[c];
                            if (paired) {
                                const auto h1 = ExtractBlock(up.extract_prf, tile1->row, bj, blk1.data());
                                for (uint32_t c = 0; c < T; ++c) H1[bj * T + c] = h1[c];
                            }
                        }
                        struct TileRecompute {
                            std::array<int64_t, kRCMxBlockLen> acc{};
                            std::array<int8_t, kRCMxBlockLen> eo{};
                        };
                        auto down_tile = [&](const RCFreivaldsSampledTile& tile,
                                             const std::vector<int8_t>& X_row,
                                             const std::vector<int8_t>& H_row) {
                            TileRecompute out;
                            const uint32_t out_col0 = tile.bcol * T;
                            if (use_packed_i8mm) {
                                RCDenseRowBlockPackedI8mmExactI8(H_row.data(), W_down_t.data(), d_ff,
                                                                 d_model, out_col0, out.acc.data());
                            } else {
                                RCDenseRowBlockTransposedExactI8(H_row.data(), W_down_t.data(), d_ff,
                                                                 d_model, out_col0, out.acc.data());
                            }
                            for (uint32_t c = 0; c < T; ++c)
                                out.acc[c] += static_cast<int64_t>(X_row[out_col0 + c]);
                            out.eo = ExtractBlock(lp.extract_prf, tile.row, tile.bcol, out.acc.data());
                            return out;
                        };
                        const TileRecompute rc0 = down_tile(tile0, X0, H0);
                        TileRecompute rc1;
                        if (paired) rc1 = down_tile(*tile1, X1, H1);
                        r.recompute_s += Secs(t_rc_dn);
                        if (!finish_tile(tile0, rc0.acc.data(), rc0.eo)) break;
                        if (paired && !finish_tile(*tile1, rc1.acc.data(), rc1.eo)) break;
                        ti += paired ? 2 : 1;
                    }
                }
                if (r.ok) ++r.n_layers_checked;
                results[pi] = std::move(r);
            });
        } catch (...) {
            return fail("v7fs:worker_exception");
        }
        tm.unitcheck_s = Secs(t_unit);

        const auto t_reduce = std::chrono::steady_clock::now();
        for (const UnitResult& r : results) {
            tm.recompute_s += r.recompute_s;
            tm.merkle_s += r.merkle_s;
            tm.n_extract_tiles += r.n_extract_tiles;
            tm.n_freivalds_calls += r.n_freivalds_calls;
            tm.n_merkle_openings += r.n_merkle_openings;
            tm.n_merkle_hashes += r.n_merkle_hashes;
            tm.n_layers_checked += r.n_layers_checked;
            if (!r.ok) {
                tm.reduce_s = Secs(t_reduce);
                return fail(r.why.empty() ? "v7fs:unit_reject" : r.why);
            }
        }
        tm.reduce_s = Secs(t_reduce);
        tm.perlayer_s = tm.prewarm_s + tm.unitcheck_s + tm.reduce_s;
        tm.ok = true;
        tm.total_s = Secs(t0);
        tm.note = "v7fs anchored carrier: " + std::to_string(tm.n_layers_checked) + "/" +
                  std::to_string(tm.n_units_total) + " layers recomputed from anchored operands";
        if (out_timing) *out_timing = tm;
        if (why) *why = tm.note;
        return true;
    }
}

// ===========================================================================
// RELAY: carrier serialization (byte-exact) + bounded deserialization.
// Hand-rolled little-endian codec so every untrusted read is explicitly
// budget- and count-checked. The carrier is a RELAY-ONLY object — this byte
// layout is NOT consensus-serialized (it never enters a block/digest/FS seed);
// the consensus binding is the SEMANTIC check in the carrier verifier.
// ===========================================================================
namespace {

void PutU32(std::vector<unsigned char>& b, uint32_t v)
{
    b.push_back(static_cast<unsigned char>(v & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 8) & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 16) & 0xff));
    b.push_back(static_cast<unsigned char>((v >> 24) & 0xff));
}
void PutU64(std::vector<unsigned char>& b, uint64_t v)
{
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<unsigned char>((v >> (8 * i)) & 0xff));
}
// Bitcoin CompactSize (canonical).
void PutCompact(std::vector<unsigned char>& b, uint64_t n)
{
    if (n < 253) {
        b.push_back(static_cast<unsigned char>(n));
    } else if (n <= 0xffff) {
        b.push_back(253);
        b.push_back(static_cast<unsigned char>(n & 0xff));
        b.push_back(static_cast<unsigned char>((n >> 8) & 0xff));
    } else if (n <= 0xffffffffULL) {
        b.push_back(254);
        PutU32(b, static_cast<uint32_t>(n));
    } else {
        b.push_back(255);
        PutU64(b, n);
    }
}
void PutBytes(std::vector<unsigned char>& b, const unsigned char* p, size_t n)
{
    b.insert(b.end(), p, p + n);
}
void PutHash(std::vector<unsigned char>& b, const uint256& h) { PutBytes(b, h.data(), 32); }
void PutEpisode(std::vector<unsigned char>& b, const RCEpisodeParams& e)
{
    // Consensus transcript version plus the 9 shape fields, in the canonical order
    // used by the FS seed (RCGkrFsSeedV7). phase1_tile_delta is an
    // RCEpisodeOptions execution knob (0 under consensus, never digest-bearing)
    // and is intentionally absent.
    PutU32(b, e.transcript_version);
    PutU32(b, e.rounds);
    PutU32(b, e.d_head);
    PutU32(b, e.n_q);
    PutU32(b, e.n_ctx);
    PutU32(b, e.L_lyr);
    PutU32(b, e.d_model);
    PutU32(b, e.d_ff);
    PutU32(b, e.b_seq);
    PutU32(b, e.T_leaf);
}

/** Budget-checked, non-throwing reader over an untrusted span. */
struct BoundedReader {
    const unsigned char* p;
    size_t remaining;
    bool ok{true};
    std::string err;

    explicit BoundedReader(Span<const unsigned char> in)
        : p(in.data()), remaining(in.size()) {}

    bool fail(const std::string& m) { ok = false; if (err.empty()) err = m; return false; }
    bool need(size_t n) { return remaining >= n ? true : fail("carrier:underrun"); }

    bool U32(uint32_t& v)
    {
        if (!need(4)) return false;
        v = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
            (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
        p += 4; remaining -= 4; return true;
    }
    bool U64(uint64_t& v)
    {
        if (!need(8)) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(p[i]) << (8 * i);
        p += 8; remaining -= 8; return true;
    }
    bool U8(uint8_t& v)
    {
        if (!need(1)) return false;
        v = *p++; --remaining; return true;
    }
    bool Hash(uint256& h)
    {
        if (!need(32)) return false;
        std::memcpy(h.data(), p, 32);
        p += 32; remaining -= 32; return true;
    }
    // Canonical CompactSize with a caller-supplied hard cap.
    bool Compact(uint64_t& n, uint64_t cap)
    {
        if (!need(1)) return false;
        const uint8_t ch = *p++; --remaining;
        if (ch < 253) {
            n = ch;
        } else if (ch == 253) {
            if (!need(2)) return false;
            n = static_cast<uint64_t>(p[0]) | (static_cast<uint64_t>(p[1]) << 8);
            p += 2; remaining -= 2;
            if (n < 253) return fail("carrier:noncanonical_compact");
        } else if (ch == 254) {
            uint32_t v; if (!U32(v)) return false;
            n = v;
            if (n <= 0xffff) return fail("carrier:noncanonical_compact");
        } else {
            if (!U64(n)) return false;
            if (n <= 0xffffffffULL) return fail("carrier:noncanonical_compact");
        }
        if (n > cap) return fail("carrier:count_over_cap");
        return true;
    }
    bool Episode(RCEpisodeParams& e)
    {
        return U32(e.transcript_version) &&
               U32(e.rounds) && U32(e.d_head) && U32(e.n_q) && U32(e.n_ctx) &&
               U32(e.L_lyr) && U32(e.d_model) && U32(e.d_ff) && U32(e.b_seq) && U32(e.T_leaf);
    }
    // Read a length-prefixed int8 vector; count bounded by remaining bytes and
    // the whole-carrier element ceiling, so allocation can never exceed input.
    bool VecI8(std::vector<int8_t>& v)
    {
        uint64_t cnt;
        if (!Compact(cnt, kRCCarrierMaxVecElems)) return false;
        if (!need(cnt)) return false;   // 1 byte/elem
        v.resize(cnt);
        for (uint64_t i = 0; i < cnt; ++i) v[i] = static_cast<int8_t>(p[i]);
        p += cnt; remaining -= cnt; return true;
    }
    bool VecI64(std::vector<int64_t>& v)
    {
        uint64_t cnt;
        if (!Compact(cnt, kRCCarrierMaxVecElems / 8 + 1)) return false;
        if (!need(cnt * 8)) return false;
        v.resize(cnt);
        for (uint64_t i = 0; i < cnt; ++i) {
            uint64_t u = 0;
            for (int j = 0; j < 8; ++j) u |= static_cast<uint64_t>(p[8 * i + j]) << (8 * j);
            v[i] = static_cast<int64_t>(u);
        }
        p += cnt * 8; remaining -= cnt * 8; return true;
    }
    bool VecHash(std::vector<uint256>& v, uint64_t cap)
    {
        uint64_t cnt;
        if (!Compact(cnt, cap)) return false;
        if (!need(cnt * 32)) return false;
        v.resize(cnt);
        for (uint64_t i = 0; i < cnt; ++i) { std::memcpy(v[i].data(), p + 32 * i, 32); }
        p += cnt * 32; remaining -= cnt * 32; return true;
    }
    bool RawBytes(std::vector<uint8_t>& v)
    {
        uint64_t cnt;
        if (!Compact(cnt, kRCCarrierMaxVecElems)) return false;
        if (!need(cnt)) return false;
        v.resize(cnt);
        std::memcpy(v.data(), p, cnt);
        p += cnt; remaining -= cnt; return true;
    }
};

} // namespace

void SerializeRCFreivaldsCarrier(const RCFreivaldsSampledCarrier& c,
                                 std::vector<unsigned char>& out)
{
    out.clear();
    PutU32(out, c.version);
    PutEpisode(out, c.episode);
    PutU32(out, static_cast<uint32_t>(c.height));
    PutHash(out, c.claimed_digest);
    PutHash(out, c.pow_bind);
    PutHash(out, c.episode_sigma);
    PutCompact(out, c.round_seeds.size());
    for (const auto& h : c.round_seeds) PutHash(out, h);
    PutCompact(out, c.round_roots.size());
    for (const auto& h : c.round_roots) PutHash(out, h);
    PutCompact(out, c.acc_roots.size());
    for (const auto& h : c.acc_roots) PutHash(out, h);
    PutU32(out, c.lambda);
    PutCompact(out, c.sampled.size());
    for (const auto& e : c.sampled) {
        PutU32(out, e.layer_index);
        PutU32(out, e.round);
        PutU32(out, static_cast<uint32_t>(e.kind));
        PutU32(out, e.m);
        PutU32(out, e.n);
        PutU32(out, e.k);
        PutCompact(out, e.tiles.size());
        for (const auto& tile : e.tiles) {
            PutU32(out, tile.row);
            PutU32(out, tile.bcol);
            PutCompact(out, tile.extract_out.size());
            for (int8_t x : tile.extract_out) out.push_back(static_cast<unsigned char>(x));
            PutHash(out, tile.acc_tag);
            PutU64(out, tile.acc_stream_offset);
            PutU32(out, tile.acc_first_leaf);
            PutCompact(out, tile.acc_leaf_bytes.size());
            for (const auto& lb : tile.acc_leaf_bytes) {
                PutCompact(out, lb.size());
                PutBytes(out, lb.data(), lb.size());
            }
            PutCompact(out, tile.acc_leaf_proofs.size());
            for (const auto& pf : tile.acc_leaf_proofs) {
                PutCompact(out, pf.siblings.size());
                for (const auto& s : pf.siblings) PutHash(out, s);
            }
            // Anchored A-row (empty + flag when PRF-regenerable).
            out.push_back(tile.a_prf_regen ? 1 : 0);
            PutU64(out, tile.a_row_stream_offset);
            PutU32(out, tile.a_row_leaf_index);
            PutCompact(out, tile.a_row_leaf.size());
            PutBytes(out, tile.a_row_leaf.data(), tile.a_row_leaf.size());
            PutCompact(out, tile.a_row_proof.siblings.size());
            for (const auto& s : tile.a_row_proof.siblings) PutHash(out, s);
            // extract_out tile-tree opening.
            PutU64(out, tile.stream_offset);
            PutU32(out, tile.first_leaf);
            PutCompact(out, tile.leaf_bytes.size());
            for (const auto& lb : tile.leaf_bytes) {
                PutCompact(out, lb.size());
                PutBytes(out, lb.data(), lb.size());
            }
            PutCompact(out, tile.leaf_proofs.size());
            for (const auto& pf : tile.leaf_proofs) {
                PutCompact(out, pf.siblings.size());
                for (const auto& s : pf.siblings) PutHash(out, s);
            }
        }
    }
}

bool DeserializeRCFreivaldsCarrierBounded(Span<const unsigned char> in,
                                          RCFreivaldsSampledCarrier& out, std::string* why)
{
    auto bad = [&](const std::string& m) { if (why) *why = m; return false; };
    // Hard byte ceiling BEFORE touching the bytes: an oversize frame is rejected
    // for the cost of a size compare, never a copy or allocation.
    if (in.size() > kRCFreivaldsCarrierMaxSerializedBytes) return bad("carrier:oversize");

    BoundedReader r(in);
    RCFreivaldsSampledCarrier c;
    if (!r.U32(c.version)) return bad(r.err);
    if (c.version != kRCFreivaldsSampledCarrierVersion) return bad("carrier:version");
    if (!r.Episode(c.episode)) return bad(r.err);
    uint32_t h_raw; if (!r.U32(h_raw)) return bad(r.err);
    c.height = static_cast<int32_t>(h_raw);
    if (!r.Hash(c.claimed_digest)) return bad(r.err);
    if (!r.Hash(c.pow_bind)) return bad(r.err);
    if (!r.Hash(c.episode_sigma)) return bad(r.err);
    if (!r.VecHash(c.round_seeds, kRCCarrierMaxRounds)) return bad(r.err);
    if (!r.VecHash(c.round_roots, kRCCarrierMaxRounds)) return bad(r.err);
    if (!r.VecHash(c.acc_roots, kRCCarrierMaxRounds)) return bad(r.err);
    if (!r.U32(c.lambda)) return bad(r.err);

    uint64_t n_sampled;
    if (!r.Compact(n_sampled, kRCCarrierMaxSampledLayers)) return bad(r.err);
    c.sampled.resize(n_sampled);
    for (uint64_t i = 0; i < n_sampled; ++i) {
        RCFreivaldsSampledLayer& e = c.sampled[i];
        uint32_t kind_raw;
        if (!r.U32(e.layer_index) || !r.U32(e.round) || !r.U32(kind_raw) ||
            !r.U32(e.m) || !r.U32(e.n) || !r.U32(e.k)) {
            return bad(r.err);
        }
        e.kind = static_cast<RCGkrLayerKind>(kind_raw);
        uint64_t n_tiles;
        if (!r.Compact(n_tiles, kRCCarrierMaxTilesPerLayer)) return bad(r.err);
        e.tiles.resize(n_tiles);
        for (uint64_t ti = 0; ti < n_tiles; ++ti) {
            RCFreivaldsSampledTile& tile = e.tiles[ti];
            if (!r.U32(tile.row) || !r.U32(tile.bcol)) return bad(r.err);
            if (!r.VecI8(tile.extract_out)) return bad(r.err);
            if (!r.Hash(tile.acc_tag)) return bad(r.err);
            if (!r.U64(tile.acc_stream_offset) || !r.U32(tile.acc_first_leaf)) return bad(r.err);
            uint64_t n_acc_leaves;
            if (!r.Compact(n_acc_leaves, kRCCarrierMaxLeavesPerTile)) return bad(r.err);
            tile.acc_leaf_bytes.resize(n_acc_leaves);
            for (uint64_t x = 0; x < n_acc_leaves; ++x) {
                if (!r.RawBytes(tile.acc_leaf_bytes[x])) return bad(r.err);
            }
            uint64_t n_acc_proofs;
            if (!r.Compact(n_acc_proofs, kRCCarrierMaxLeavesPerTile)) return bad(r.err);
            tile.acc_leaf_proofs.resize(n_acc_proofs);
            for (uint64_t x = 0; x < n_acc_proofs; ++x) {
                if (!r.VecHash(tile.acc_leaf_proofs[x].siblings, kRCCarrierMaxMerkleSiblings)) {
                    return bad(r.err);
                }
            }
            // Anchored A-row.
            uint8_t regen;
            if (!r.U8(regen)) return bad(r.err);
            tile.a_prf_regen = (regen != 0);
            if (!r.U64(tile.a_row_stream_offset) || !r.U32(tile.a_row_leaf_index)) return bad(r.err);
            if (!r.RawBytes(tile.a_row_leaf)) return bad(r.err);
            if (!r.VecHash(tile.a_row_proof.siblings, kRCCarrierMaxMerkleSiblings)) return bad(r.err);
            // extract_out tile-tree opening.
            if (!r.U64(tile.stream_offset) || !r.U32(tile.first_leaf)) return bad(r.err);
            uint64_t n_leaves;
            if (!r.Compact(n_leaves, kRCCarrierMaxLeavesPerTile)) return bad(r.err);
            tile.leaf_bytes.resize(n_leaves);
            for (uint64_t x = 0; x < n_leaves; ++x) {
                if (!r.RawBytes(tile.leaf_bytes[x])) return bad(r.err);
            }
            uint64_t n_proofs;
            if (!r.Compact(n_proofs, kRCCarrierMaxLeavesPerTile)) return bad(r.err);
            tile.leaf_proofs.resize(n_proofs);
            for (uint64_t x = 0; x < n_proofs; ++x) {
                if (!r.VecHash(tile.leaf_proofs[x].siblings, kRCCarrierMaxMerkleSiblings)) {
                    return bad(r.err);
                }
            }
        }
    }
    if (r.remaining != 0) return bad("carrier:trailing_data");
    out = std::move(c);
    return true;
}

// ===========================================================================
// RELAY: process-local carrier store (LRU+TTL). Same policy and limits as the
// V7 proof store (kRCGkrProofCacheMaxEntries / kRCGkrProofCacheTtlSeconds);
// independent mutex so carrier traffic never contends the GKR cache lock.
// ===========================================================================
namespace {
std::mutex g_rc_carrier_mu;
struct RCCarrierStoreEntry {
    RCFreivaldsSampledCarrier carrier;
    std::chrono::steady_clock::time_point expires_at;
    std::list<uint256>::iterator lru_it;
};
std::list<uint256> g_rc_carrier_lru;
std::map<uint256, RCCarrierStoreEntry> g_rc_carrier_store;

void CarrierEvictExpiredLocked(std::chrono::steady_clock::time_point now)
{
    for (auto it = g_rc_carrier_store.begin(); it != g_rc_carrier_store.end();) {
        if (it->second.expires_at <= now) {
            g_rc_carrier_lru.erase(it->second.lru_it);
            it = g_rc_carrier_store.erase(it);
        } else {
            ++it;
        }
    }
}
void CarrierEvictLruLocked()
{
    while (g_rc_carrier_store.size() > kRCGkrProofCacheMaxEntries) {
        const uint256 oldest = g_rc_carrier_lru.back();
        g_rc_carrier_lru.pop_back();
        g_rc_carrier_store.erase(oldest);
    }
}
} // namespace

void RCFreivaldsCarrierStorePut(const uint256& block_hash, RCFreivaldsSampledCarrier carrier)
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    const auto now = std::chrono::steady_clock::now();
    CarrierEvictExpiredLocked(now);
    const auto expires = now + std::chrono::seconds(kRCGkrProofCacheTtlSeconds);
    auto it = g_rc_carrier_store.find(block_hash);
    if (it != g_rc_carrier_store.end()) {
        g_rc_carrier_lru.erase(it->second.lru_it);
        g_rc_carrier_lru.push_front(block_hash);
        it->second.carrier = std::move(carrier);
        it->second.expires_at = expires;
        it->second.lru_it = g_rc_carrier_lru.begin();
    } else {
        g_rc_carrier_lru.push_front(block_hash);
        RCCarrierStoreEntry entry;
        entry.carrier = std::move(carrier);
        entry.expires_at = expires;
        entry.lru_it = g_rc_carrier_lru.begin();
        g_rc_carrier_store.emplace(block_hash, std::move(entry));
    }
    CarrierEvictLruLocked();
}

bool RCFreivaldsCarrierStoreGet(const uint256& block_hash, RCFreivaldsSampledCarrier& out)
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    const auto now = std::chrono::steady_clock::now();
    auto it = g_rc_carrier_store.find(block_hash);
    if (it == g_rc_carrier_store.end()) return false;
    if (it->second.expires_at <= now) {
        g_rc_carrier_lru.erase(it->second.lru_it);
        g_rc_carrier_store.erase(it);
        return false;
    }
    g_rc_carrier_lru.erase(it->second.lru_it);
    g_rc_carrier_lru.push_front(block_hash);
    it->second.lru_it = g_rc_carrier_lru.begin();
    out = it->second.carrier;
    return true;
}

bool RCFreivaldsCarrierStoreHave(const uint256& block_hash)
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    CarrierEvictExpiredLocked(std::chrono::steady_clock::now());
    return g_rc_carrier_store.count(block_hash) != 0;
}

void RCFreivaldsCarrierStoreClear()
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    g_rc_carrier_store.clear();
    g_rc_carrier_lru.clear();
}

size_t RCFreivaldsCarrierStoreSizeForTest()
{
    std::lock_guard<std::mutex> lock(g_rc_carrier_mu);
    CarrierEvictExpiredLocked(std::chrono::steady_clock::now());
    return g_rc_carrier_store.size();
}

} // namespace matmul::v4::rc
