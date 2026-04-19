// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/oracle_accel.h>

namespace btx::cuda {

MatMulGeneratedInputsDevice::~MatMulGeneratedInputsDevice() = default;

MatMulInputGenerationProfile ProbeMatMulInputGenerationProfile()
{
    MatMulInputGenerationProfile profile;
    profile.available = false;
    profile.pool_initialized = false;
    profile.library_source = "unavailable";
    profile.reason = "CUDA oracle acceleration is unavailable on this build";
    return profile;
}

MatMulInputGenerationResult GenerateMatMulInputsGPU(const MatMulInputGenerationRequest&)
{
    MatMulInputGenerationResult result;
    result.available = false;
    result.success = false;
    result.error = "CUDA oracle acceleration is unavailable on this build";
    return result;
}

MatMulInputGenerationDeviceResult GenerateMatMulInputsGPUDevice(const MatMulInputGenerationRequest&)
{
    MatMulInputGenerationDeviceResult result;
    result.available = false;
    result.success = false;
    result.error = "CUDA oracle acceleration is unavailable on this build";
    return result;
}

} // namespace btx::cuda
