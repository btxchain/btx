// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_mx_layout.h>

#include <cuda/matmul_v4_lt_accel.h>
#include <hip/matmul_v4_lt_accel.h>
#include <matmul/exact_gemm_resolve.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_lt.h>
#include <metal/matmul_v4_lt_accel.h>

#include <cassert>
#include <cstring>

namespace matmul::v4::rc {
namespace {

namespace bx = matmul::v4::bmx4;
namespace lt = matmul::v4::lt;

inline int8_t DequantMu(int8_t mu, uint8_t e)
{
    return static_cast<int8_t>(static_cast<int32_t>(mu) * (int32_t{1} << e));
}

} // namespace

RCMxPacked ExpandMxPacked(const uint256& seed, uint32_t rows, uint32_t cols, RCMxScaleAxis axis)
{
    assert(rows > 0 && cols > 0);
    assert((rows % kRCMxBlockLen) == 0);
    assert((cols % kRCMxBlockLen) == 0);

    RCMxPacked out;
    out.rows = rows;
    out.cols = cols;
    out.axis = axis;
    const size_t count = static_cast<size_t>(rows) * cols;
    out.mu.resize(count);
    bx::ExpandMantissaStream(seed, count, out.mu.data());
    out.scales.resize(RCMxScaleCount(rows, cols, axis));
    bx::ExpandScaleStream(seed, out.scales.size(), out.scales.data());
    return out;
}

std::vector<int8_t> DequantMxPacked(const RCMxPacked& packed)
{
    assert(packed.mu.size() == static_cast<size_t>(packed.rows) * packed.cols);
    assert(packed.scales.size() == RCMxScaleCount(packed.rows, packed.cols, packed.axis));
    std::vector<int8_t> out(packed.mu.size());
    for (uint32_t i = 0; i < packed.rows; ++i) {
        for (uint32_t j = 0; j < packed.cols; ++j) {
            const size_t idx = static_cast<size_t>(i) * packed.cols + j;
            out[idx] = DequantMu(packed.mu[idx], RCMxScaleAt(packed, i, j));
        }
    }
    return out;
}

RCMxScaleAxis RequiredMxScaleAxis(RCMxGemmStage stage, bool left_operand)
{
    switch (stage) {
    case RCMxGemmStage::Phase1ScoreQKt:
        return RCMxScaleAxis::RowBlock; // K = d_head along cols for Q and K
    case RCMxGemmStage::Phase1ValueSV:
        // S (left): row-block on n_ctx; V (right): col-block on n_ctx rows
        return left_operand ? RCMxScaleAxis::RowBlock : RCMxScaleAxis::ColBlock;
    case RCMxGemmStage::Phase2Forward:
        // X row-block; Wt is col-block along K (W stored row-block, then transposed)
        return left_operand ? RCMxScaleAxis::RowBlock : RCMxScaleAxis::ColBlock;
    case RCMxGemmStage::Phase2Backward:
        return left_operand ? RCMxScaleAxis::RowBlock : RCMxScaleAxis::ColBlock;
    case RCMxGemmStage::Phase2Wgrad:
        // Both G and X need col-block on batch when formed as Gᵀ / X panels
        return RCMxScaleAxis::ColBlock;
    }
    return RCMxScaleAxis::RowBlock;
}

RCMxPacked PrepareMxPackedForScoreQ(const uint256& seed_Q, uint32_t n_q, uint32_t d_head)
{
    return ExpandMxPacked(seed_Q, n_q, d_head, RequiredMxScaleAxis(RCMxGemmStage::Phase1ScoreQKt, true));
}

RCMxPacked PrepareMxPackedForScoreK(const uint256& seed_K, uint32_t n_ctx, uint32_t d_head)
{
    return ExpandMxPacked(seed_K, n_ctx, d_head, RequiredMxScaleAxis(RCMxGemmStage::Phase1ScoreQKt, false));
}

RCMxPacked PrepareMxPackedForValueV(const uint256& seed_V, uint32_t n_ctx, uint32_t d_head)
{
    return ExpandMxPacked(seed_V, n_ctx, d_head, RequiredMxScaleAxis(RCMxGemmStage::Phase1ValueSV, false));
}

RCMxPacked PrepareMxPackedForFwdX(const uint256& seed_X, uint32_t b_seq, uint32_t d_model)
{
    return ExpandMxPacked(seed_X, b_seq, d_model, RequiredMxScaleAxis(RCMxGemmStage::Phase2Forward, true));
}

RCMxPacked PrepareMxPackedForBwdW(const uint256& seed_W, uint32_t d_model)
{
    return ExpandMxPacked(seed_W, d_model, d_model, RequiredMxScaleAxis(RCMxGemmStage::Phase2Backward, false));
}

RCMxPacked PrepareMxPackedForWgradG(const uint256& seed_G, uint32_t b_seq, uint32_t d_model)
{
    return ExpandMxPacked(seed_G, b_seq, d_model, RequiredMxScaleAxis(RCMxGemmStage::Phase2Wgrad, true));
}

RCMxPacked PrepareMxPackedForWgradX(const uint256& seed_X, uint32_t b_seq, uint32_t d_model)
{
    return ExpandMxPacked(seed_X, b_seq, d_model, RequiredMxScaleAxis(RCMxGemmStage::Phase2Wgrad, false));
}

bool TryDeviceMxGemmPackedStub(const RCMxPacked& /*left*/, const RCMxPacked& /*right*/,
                               uint32_t /*rows*/, uint32_t /*inner*/, uint32_t /*cols*/,
                               std::vector<int32_t>& out)
{
    // Fail-closed stub: no native block-scaled MX episode kernel. Cleared
    // output + false ⇒ callers must not treat this as tensor-device success.
    out.clear();
    return false;
}

RCPhase2ExactGemmDeviceProbe ProbeRCPhase2ExactGemmDevice()
{
    RCPhase2ExactGemmDeviceProbe st;
    // Resolve RC-gated ExactGemm (CUDA/HIP LaunchGemmS8S8 when available).
    const lt::ExactGemmBackend backend = matmul_v4::accel::MakeResolvedExactGemmBackendForRC();
    if (backend.gemm_s8s8 == nullptr) {
        st.provider = "cpu";
        st.detail = "no_device_backend_after_rc_selfqual";
        return st;
    }
    st.backend_resolved = true;
    st.provider = "device";

    // Toy Phase-2 forward shape: ExactGemmS8S8(X, Wt) with d_model=b_seq=32.
    constexpr uint32_t k = 32;
    std::vector<int8_t> X(static_cast<size_t>(k) * k);
    std::vector<int8_t> Wt(static_cast<size_t>(k) * k);
    for (uint32_t i = 0; i < k * k; ++i) {
        X[i] = static_cast<int8_t>((static_cast<int32_t>(i) % 97) - 48);
        Wt[i] = static_cast<int8_t>((static_cast<int32_t>(i * 5) % 95) - 47);
    }
    const std::vector<int32_t> cpu = lt::ExactGemmS8S8(X, Wt, k, k, k);
    std::vector<int32_t> device;
    bool ok = false;
    try {
        ok = backend.gemm_s8s8(X, Wt, k, k, k, device);
    } catch (...) {
        ok = false;
    }
    st.device_gemm_returned = ok;
    if (!ok) {
        st.detail = "device_gemm_declined";
        return st;
    }
    st.matched_cpu_exactgemm = (device == cpu);
    if (!st.matched_cpu_exactgemm) {
        st.detail = "device_gemm_mismatch_vs_cpu";
        return st;
    }
#if defined(BTX_ENABLE_CUDA_EXPERIMENTAL)
    st.used_tensor_imma_or_mfma = matmul_v4::cuda::LtLastS8S8UsedImma();
    // Honesty: only claim cuda_imma when IMMA actually ran; else alu/stub.
    st.provider = st.used_tensor_imma_or_mfma ? "cuda_imma" : "cuda_alu";
#elif defined(BTX_ENABLE_HIP)
    st.used_tensor_imma_or_mfma = matmul_v4::hip::LtLastS8S8UsedMfma();
    st.provider = st.used_tensor_imma_or_mfma ? "hip_mfma" : "hip_alu";
#elif defined(BTX_ENABLE_METAL)
    st.used_tensor_imma_or_mfma = matmul_v4::metal::LtLastS8S8UsedTensorOps();
    st.provider = st.used_tensor_imma_or_mfma ? "metal_tensor_ops" : "metal_alu";
#else
    st.used_tensor_imma_or_mfma = false;
    st.provider = "alu_or_stub";
#endif
    st.detail = "ok";
    return st;
}

} // namespace matmul::v4::rc
