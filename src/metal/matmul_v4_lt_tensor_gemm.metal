// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// MatMul v4.4-LT ExactGemm TensorOps kernel. Authoritative source for both
// the precompiled metallib (CMake -std=metal4.0) and the generated inline
// fallback in matmul_v4_lt_tensor_gemm_source.h.
//
// Precompiling this at build time is what lets a launchd/daemon btxd admit
// Metal without talking to MTLCompilerService at runtime (issue 51).

#include <metal_stdlib>
#if defined(__METAL_VERSION__) && (__METAL_VERSION__ >= 400) && \
    __has_include(<MetalPerformancePrimitives/MetalPerformancePrimitives.h>)
#include <MetalPerformancePrimitives/MetalPerformancePrimitives.h>
#define BTX_LT_HAVE_TENSOR_OPS 1
#endif

using namespace metal;

#define BTX_LT_TENSOR_TILE_M 32
#define BTX_LT_TENSOR_TILE_N 32

struct GemmParams {
    uint m_rows;
    uint k;
    uint n_cols;
};

#if defined(BTX_LT_HAVE_TENSOR_OPS)
kernel void matmul_v4_lt_s8_gemm_s32_tensor(
    constant GemmParams& p [[buffer(0)]],
    device int8_t* x [[buffer(1)]],
    device int8_t* y [[buffer(2)]],
    device int32_t* d [[buffer(3)]],
    uint2 tgid [[threadgroup_position_in_grid]])
{
    using namespace mpp;
    using namespace mpp::tensor_ops;

    constexpr auto desc = matmul2d_descriptor(BTX_LT_TENSOR_TILE_M, BTX_LT_TENSOR_TILE_N);
    matmul2d<desc, execution_simdgroup> op;

    auto mX = tensor(x, dextents<int, 2>{(int)p.k, (int)p.m_rows}, array<int, 2>{1, (int)p.k});
    auto mY = tensor(y, dextents<int, 2>{(int)p.n_cols, (int)p.k}, array<int, 2>{1, (int)p.n_cols});
    auto mD = tensor(d, dextents<int, 2>{(int)p.n_cols, (int)p.m_rows}, array<int, 2>{1, (int)p.n_cols});

    const int row0 = (int)(tgid.y * BTX_LT_TENSOR_TILE_M);
    const int col0 = (int)(tgid.x * BTX_LT_TENSOR_TILE_N);

    auto tX = mX.slice(0, row0);
    auto tY = mY.slice(col0, 0);
    auto tD = mD.slice(col0, row0);

    op.run(tX, tY, tD);
}
#endif
