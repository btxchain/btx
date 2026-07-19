// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_bmx4_cutlass_mxfp4.h>

// Default / no-CUTLASS build: the grouped MXFP4 TENSOR kernel is not linked.
// Portable exact GroupedMxfp4Project{Left,Right} in the header remains the
// always-available datapath (IsGroupedMxfp4Available() == true).

namespace matmul_v4::cuda::cutlass_mxfp4 {

bool IsGroupedMxfp4TensorKernelCompiled()
{
    return false;
}

bool IsGroupedMxfp4TensorKernelLinked()
{
    return false;
}

} // namespace matmul_v4::cuda::cutlass_mxfp4
