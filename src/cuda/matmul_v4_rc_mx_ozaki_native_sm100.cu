// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

// SM100a (B200 / GB200 datacenter Blackwell, compute capability 10.0) link-time
// capability marker for the RC Ozaki native block-scaled MXFP4 path that issues
// 5th-generation tensor-core MMAs via tcgen05.mma.kind::mxf8f6f4.block_scale.
//
// This mirrors matmul_v4_rc_mx_ozaki_native_sm120a.cu (Agent A/B pattern):
//
//   * Agent B (CMake / arch wiring, cmake/BTXCudaSm100.cmake):
//       - Add this TU to btx_matmul_backend ONLY when building with feature-
//         qualified sm_100a (BTX_CUDA_SM100_NATIVE=ON).
//       - Compile this file with -gencode=arch=compute_100a,code=sm_100a.
//         Bare -arch=sm_100 is NOT enough — ptxas can still target plain sm_100
//         which lacks the tcgen05 block-scaled MMA; the architecture-accelerated
//         'a' target is mandatory (same rule as sm_120a for the SM120 warp MMA).
//       - Attach an sm_100a fatbin slice to matmul_v4_rc_mx_ozaki_native.cu so the
//         tcgen05 inline PTX (gated by __CUDA_ARCH_SPECIFIC__==1000) compiles IN.
//         Plain sm_100 leaves the tcgen05 MMA body as a zero-producing stub, so
//         the runtime exact self-qual (bit-exact vs the int64 oracle) fails and
//         the backend stays fail-closed on SM100_CUBLASLT / INT8.
//
//   * Agent C (runtime honesty):
//       - RcOzakiMxfp4Sm100NativeLinked() is true ONLY when this strong
//         definition is linked. The weak stub in matmul_v4_rc_mx_ozaki_native.cu
//         and the host stub in matmul_v4_rc_mx_ozaki_native_link.cpp return false
//         otherwise. Never advertise SM100_MMA (hand tcgen05) as build-capable
//         when this returns false.
//       - This marker alone NEVER flips SelectedBackend. SM100_MMA additionally
//         requires: (1) a real sm_100 (major==10) device, (2) this marker true,
//         (3) the complete bit-exact self-qual suite passing with a positive
//         native tensor-core launch count on that silicon.
//
// SM100 (this file) and SM120 (matmul_v4_rc_mx_ozaki_native_sm120a.cu) are
// SEPARATE latches on SEPARATE ISAs — never cross-infer. sm_100 uses the async
// tcgen05.mma (TMEM-resident) family; sm_120 uses warp-synchronous mma.sync.
// The two block-scaled MMA encodings are NOT interchangeable.
//
// This TU intentionally carries no device kernels — relocatable device code is
// not required. The tcgen05 MMA body stays in matmul_v4_rc_mx_ozaki_native.cu
// under the __CUDA_ARCH_SPECIFIC__==1000 guard so plain multi-arch fatbins keep
// compiling with that body left OUT.

namespace matmul_v4::cuda {

bool RcOzakiMxfp4Sm100NativeLinked()
{
    return true;
}

} // namespace matmul_v4::cuda
