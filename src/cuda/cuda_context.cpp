// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/cuda_context.h>

#include <cuda_runtime_api.h>

#include <algorithm>
#include <string>

namespace btx::cuda {
namespace {

constexpr int MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR{8};

std::string ComputeCapabilityString(int major, int minor)
{
    return "sm_" + std::to_string(major) + std::to_string(minor);
}

} // namespace

CudaRuntimeProbe ProbeCudaRuntime()
{
    CudaRuntimeProbe probe;
    probe.compiled = true;

    int runtime_version{0};
    const cudaError_t runtime_version_error = cudaRuntimeGetVersion(&runtime_version);
    if (runtime_version_error != cudaSuccess) {
        probe.reason = "cuda_runtime_unavailable:" + std::string(cudaGetErrorString(runtime_version_error));
        return probe;
    }
    probe.runtime_version = static_cast<uint32_t>(runtime_version);

    int driver_api_version{0};
    const cudaError_t driver_version_error = cudaDriverGetVersion(&driver_api_version);
    if (driver_version_error == cudaSuccess) {
        probe.driver_api_version = static_cast<uint32_t>(driver_api_version);
    }

    int device_count{0};
    const cudaError_t count_error = cudaGetDeviceCount(&device_count);
    if (count_error != cudaSuccess) {
        probe.reason = count_error == cudaErrorNoDevice
            ? "no_supported_device"
            : "cuda_runtime_unavailable:" + std::string(cudaGetErrorString(count_error));
        return probe;
    }
    if (device_count <= 0) {
        probe.reason = "no_supported_device";
        return probe;
    }

    bool saw_too_old_device{false};
    int best_major{0};
    int best_minor{0};
    for (int device_index = 0; device_index < device_count; ++device_index) {
        cudaDeviceProp properties{};
        const cudaError_t properties_error = cudaGetDeviceProperties(&properties, device_index);
        if (properties_error != cudaSuccess) {
            probe.reason = "cuda_runtime_unavailable:" + std::string(cudaGetErrorString(properties_error));
            continue;
        }

        best_major = std::max(best_major, properties.major);
        if (best_major == properties.major) {
            best_minor = std::max(best_minor, properties.minor);
        }

        if (properties.major < MIN_SUPPORTED_COMPUTE_CAPABILITY_MAJOR) {
            saw_too_old_device = true;
            continue;
        }

        probe.available = true;
        probe.reason = "ready";
        probe.device_index = device_index;
        probe.device_name = properties.name;
        probe.compute_capability_major = static_cast<uint32_t>(properties.major);
        probe.compute_capability_minor = static_cast<uint32_t>(properties.minor);
        probe.global_memory_bytes = static_cast<uint64_t>(properties.totalGlobalMem);
        probe.multiprocessor_count = static_cast<uint32_t>(properties.multiProcessorCount);
        return probe;
    }

    if (saw_too_old_device) {
        probe.reason = "device_compute_capability_too_old:" + ComputeCapabilityString(best_major, best_minor);
    } else if (probe.reason.empty()) {
        probe.reason = "no_supported_device";
    }
    return probe;
}

} // namespace btx::cuda
