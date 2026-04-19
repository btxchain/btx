// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_CUDA_CONTEXT_H
#define BITCOIN_CUDA_CUDA_CONTEXT_H

#include <cstdint>
#include <string>

namespace btx::cuda {

struct CudaRuntimeProbe {
    bool compiled{false};
    bool available{false};
    std::string reason;
    int device_index{-1};
    std::string device_name;
    uint32_t compute_capability_major{0};
    uint32_t compute_capability_minor{0};
    uint64_t global_memory_bytes{0};
    uint32_t multiprocessor_count{0};
    uint32_t driver_api_version{0};
    uint32_t runtime_version{0};
};

CudaRuntimeProbe ProbeCudaRuntime();

} // namespace btx::cuda

#endif // BITCOIN_CUDA_CUDA_CONTEXT_H
