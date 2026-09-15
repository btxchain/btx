// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_QUALIFICATION_H
#define BITCOIN_MODELNET_QUALIFICATION_H

#include <modelnet/types.h>
#include <span.h>

#include <optional>
#include <string>
#include <vector>

namespace modelnet {

enum class QualResult : uint8_t {
    STRUCTURE_VERIFIED = 0,
    PROFILE_VERIFIED = 1,
    RUNTIME_OBSERVED = 2,
    INVALID_MODEL = 3,
    NOT_RUN_RESOURCE_LIMIT = 4,
    REJECTED_UNSAFE_FORMAT = 5,
    ENCRYPTED_UNQUALIFIED = 6,
    /** CUDA was skipped so the validator/mining GPU is never shared. */
    NOT_RUN_CUDA_ISOLATION = 7,
};

const char* QualResultName(QualResult r);

struct QualReport {
    QualResult result{QualResult::INVALID_MODEL};
    std::string detail;
    AdmissionLevel level{AdmissionLevel::FAILED};
    uint64_t header_bytes{0};
    uint64_t tensor_count{0};
};

/**
 * Optional CUDA runtime observation. Defaults match `-modelruntimecheck=0` and
 * `-modelgpu` unset: no libcuda, no cudaSetDevice in btxd, no kernel, no sharing
 * of the validator/mining GPU. When runtime_check is set and
 * BTX_CUDA_QUAL_WORKER (or PATH cuda_qual_worker) exists, QualifyRuntime
 * posix_spawns that isolated worker with --gpu=N and optional
 * --allow-shared-gpu from BTX_ALLOW_SHARED_GPU. Catalog cuda_qualification=false
 * stays honest because QualifyFile never calls this and default opts never run CUDA.
 */
struct QualRuntimeOpts {
    /** `-modelgpu`. Unset means none; never inherit the validator GPU. */
    std::optional<int> gpu_index{};
    /** Production default. True only if the operator explicitly allows it. */
    bool allow_validator_gpu{false};
    /** `-modelruntimecheck`. Default 0: return NOT_RUN without touching CUDA. */
    bool runtime_check{false};
};

/** Default ExactReplay / mining device. Qualification never auto-selects this. */
constexpr int DEFAULT_MINING_GPU_INDEX = 0;

/** Static SafeTensors / GGUF checks. Never executes Pickle, .pt, Python, or CUDA kernels. */
QualResult QualifyBytes(const std::string& filename_hint, Span<const unsigned char> bytes, QualReport& report);
/** Header-only file qualification. Does not load a multi-gigabyte artifact into RAM. Never CUDA. */
QualResult QualifyFile(const std::string& path, QualReport& report);
/**
 * Structure check, then optional runtime. Default opts return NOT_RUN_CUDA_ISOLATION
 * without loading libcuda. Pickle / .pt / Python are rejected and never executed.
 * CUDA kernels run only in an isolated worker process, never via cudaSetDevice in btxd.
 */
QualResult QualifyRuntime(const std::string& path, const QualRuntimeOpts& opts, QualReport& report);

bool LooksLikePickle(Span<const unsigned char> bytes);
bool LooksLikeExecutable(const std::string& filename_hint, Span<const unsigned char> bytes);

/** BTX_VALIDATOR_GPU if set to a non-negative int, else DEFAULT_MINING_GPU_INDEX. */
int ValidatorGpuIndex();
/** True if index is device 0 (default mining) or the validator GPU from env. */
bool IsValidatorOrMiningGpu(int gpu_index);
/** True only when BTX_MODEL_CUDA_QUALIFY_COMPILE is defined. Production/tests: false. */
bool ModelCudaQualifyKernelCompiled();

/** ISO-02: model import/retrieve/qualify never takes cs_main. */
bool ModelWorkTakesConsensusLock();
/** ISO-02: model work must yield to ExactReplay / monetary validation. */
bool ModelWorkMayStarveExactReplay();

} // namespace modelnet

#endif // BITCOIN_MODELNET_QUALIFICATION_H
