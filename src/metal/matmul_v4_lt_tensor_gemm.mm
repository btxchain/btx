// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_lt_tensor_gemm.h>

// Metal LT TensorOps preference. The BMX4C backend already ships a self-tested
// Metal 4 mpp::tensor_ops::matmul2d INT8 path (metal/matmul_v4_bmx4_accel.mm).
// Wiring that recipe into LT ExactGemm requires an M5-class device + metal4.0
// compile; until the shared pipeline state is factored out, this TU declines
// (IsLtTensorOpsGemmAvailable == false) so WindowSketchMinerLT keeps the
// scalar/ALU ExactGemm tiles. Never claim TensorOps when the ALU path ran.

namespace matmul_v4::metal {

bool IsLtTensorOpsGemmAvailable()
{
    return false;
}

bool TryLaunchLtTensorOpsGemmS8S8(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                  uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

bool TryLaunchLtTensorOpsGemmS32S8(const std::vector<int32_t>&, const std::vector<int8_t>&,
                                   uint32_t, uint32_t, uint32_t, std::vector<int32_t>&)
{
    return false;
}

} // namespace matmul_v4::metal
