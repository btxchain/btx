// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/cuda_context.h>
#include <cuda/matmul_accel.h>

namespace btx::cuda {

CudaRuntimeProbe ProbeCudaRuntime()
{
    CudaRuntimeProbe probe;
    probe.reason = "disabled_by_build";
    return probe;
}

MatMulAccelerationProbe ProbeMatMulDigestAcceleration()
{
    MatMulAccelerationProbe probe;
    probe.reason = "disabled_by_build";
    return probe;
}

MatMulBufferPoolStats ProbeMatMulBufferPool()
{
    MatMulBufferPoolStats stats;
    stats.reason = "disabled_by_build";
    return stats;
}

MatMulDispatchConfig ProbeMatMulDispatchConfig()
{
    MatMulDispatchConfig config;
    config.reason = "disabled_by_build";
    return config;
}

MatMulKernelProfile ProbeMatMulKernelProfile()
{
    MatMulKernelProfile profile;
    profile.reason = "disabled_by_build";
    return profile;
}

MatMulProfilingStats ProbeMatMulProfilingStats()
{
    MatMulProfilingStats stats;
    stats.reason = "disabled_by_build";
    return stats;
}

MatMulCompressedWordsResult ComputeCompressedWords(const MatMulCompressedWordsRequest&,
                                                  MatMulCompressedWordsMode)
{
    MatMulCompressedWordsResult result;
    result.error = "disabled_by_build";
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsBatch(const MatMulCompressedWordsBatchRequest&,
                                                            MatMulCompressedWordsMode)
{
    MatMulCompressedWordsBatchResult result;
    result.error = "disabled_by_build";
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankBatch(const MatMulLowRankCompressedWordsBatchRequest&,
                                                                    MatMulCompressedWordsMode)
{
    MatMulCompressedWordsBatchResult result;
    result.error = "disabled_by_build";
    return result;
}

MatMulCompressedWordsBatchResult ComputeCompressedWordsLowRankDeviceBatch(
    const MatMulLowRankCompressedWordsDeviceBatchRequest&,
    MatMulCompressedWordsMode)
{
    MatMulCompressedWordsBatchResult result;
    result.error = "disabled_by_build";
    return result;
}

} // namespace btx::cuda
