// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_accel.h>

namespace btx::metal {

MatMulAccelerationProbe ProbeMatMulDigestAcceleration()
{
    return MatMulAccelerationProbe{
        .available = false,
        .reason = "disabled_by_build",
    };
}

MatMulBaseMatricesResult UploadBaseMatrices(const MatMulBaseMatricesRequest&)
{
    MatMulBaseMatricesResult result;
    result.available = false;
    result.success = false;
    result.error = "Metal MatMul acceleration is unavailable on this build";
    return result;
}

MatMulBufferPoolStats ProbeMatMulBufferPool()
{
    MatMulBufferPoolStats stats;
    stats.available = false;
    stats.initialized = false;
    stats.reason = "Metal MatMul acceleration is unavailable on this build";
    return stats;
}

MatMulDispatchConfig ProbeMatMulDispatchConfig()
{
    MatMulDispatchConfig config;
    config.available = false;
    config.reason = "Metal MatMul acceleration is unavailable on this build";
    return config;
}

MatMulKernelProfile ProbeMatMulKernelProfile()
{
    MatMulKernelProfile profile;
    profile.available = false;
    profile.reason = "Metal MatMul acceleration is unavailable on this build";
    return profile;
}

MatMulProfilingStats ProbeMatMulProfilingStats()
{
    MatMulProfilingStats stats;
    stats.available = false;
    stats.reason = "Metal MatMul acceleration is unavailable on this build";
    return stats;
}

bool ShouldUseFunctionConstantSpecializationPolicy(uint32_t, bool)
{
    return false;
}

MatMulDigestSubmission SubmitCanonicalTranscriptDigest(const MatMulDigestRequest&)
{
    MatMulDigestSubmission submission;
    submission.available = false;
    submission.submitted = false;
    submission.error = "Metal MatMul acceleration is unavailable on this build";
    return submission;
}

bool IsCanonicalTranscriptDigestSubmissionReady(const MatMulDigestSubmission&)
{
    return false;
}

MatMulDigestResult WaitForCanonicalTranscriptDigestSubmission(MatMulDigestSubmission&& submission)
{
    MatMulDigestResult result;
    result.available = submission.available;
    result.success = false;
    result.error = submission.error.empty()
        ? "Metal MatMul acceleration is unavailable on this build"
        : submission.error;
    return result;
}

MatMulDigestResult ComputeCanonicalTranscriptDigest(const MatMulDigestRequest&)
{
    MatMulDigestResult result;
    result.available = false;
    result.success = false;
    result.error = "Metal MatMul acceleration is unavailable on this build";
    return result;
}

MatMulDigestBatchSubmission SubmitCanonicalTranscriptDigestBatch(const MatMulDigestBatchRequest&)
{
    MatMulDigestBatchSubmission submission;
    submission.available = false;
    submission.submitted = false;
    submission.error = "Metal MatMul acceleration is unavailable on this build";
    return submission;
}

bool IsCanonicalTranscriptDigestBatchSubmissionReady(const MatMulDigestBatchSubmission&)
{
    return false;
}

MatMulDigestBatchResult WaitForCanonicalTranscriptDigestBatchSubmission(MatMulDigestBatchSubmission&& submission)
{
    MatMulDigestBatchResult result;
    result.available = submission.available;
    result.success = false;
    result.error = submission.error.empty()
        ? "Metal MatMul acceleration is unavailable on this build"
        : submission.error;
    return result;
}

MatMulDigestBatchResult ComputeCanonicalTranscriptDigestBatch(const MatMulDigestBatchRequest&)
{
    MatMulDigestBatchResult result;
    result.available = false;
    result.success = false;
    result.error = "Metal MatMul acceleration is unavailable on this build";
    return result;
}

} // namespace btx::metal
