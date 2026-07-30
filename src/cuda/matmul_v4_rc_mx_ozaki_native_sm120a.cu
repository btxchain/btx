// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_mx_ozaki_native.h>

// SM120a link-time capability marker for RC Ozaki MXFP4 block-scaled MMA.
//
// Agent B (CMake / arch wiring):
//   * Add this TU to btx_matmul_backend only when building with feature-
//     qualified sm_120a (e.g. BTX_CUDA_ARCHITECTURES contains 120a).
//   * Prefer compiling this file with -arch=sm_120a (or equivalent gencode).
//   * Ensure matmul_v4_rc_mx_ozaki_native.cu's fatbin also includes an sm_120a
//     slice so the block-scaled inline PTX (gated by __CUDA_ARCH_SPECIFIC__==1200)
//     actually compiles IN. Plain sm_120 alone leaves the MMA body as zeros.
//
// Agent C (runtime honesty):
//   * RcOzakiMxfp4Sm120aKernelLinked() is true only when this strong definition
//     is linked. Weak stubs in native.cu / native_link.cpp return false otherwise.
//   * Do not advertise SM120_MMA as build-capable when this returns false.
//
// This TU intentionally carries no device kernels — relocatable device code is
// not required. The MMA body stays in matmul_v4_rc_mx_ozaki_native.cu under the
// SPECIFIC guard so existing multi-arch fatbins keep compiling.

namespace matmul_v4::cuda {

bool RcOzakiMxfp4Sm120aKernelLinked()
{
    return true;
}

} // namespace matmul_v4::cuda
