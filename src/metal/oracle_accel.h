// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_ORACLE_ACCEL_H
#define BITCOIN_METAL_ORACLE_ACCEL_H

#include <matmul/field.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

namespace btx::metal {

struct MatMulInputGenerationRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint256 sigma;
};

struct MatMulInputGenerationResult {
    bool available{false};
    bool success{false};
    std::vector<matmul::field::Element> noise_e_l;
    std::vector<matmul::field::Element> noise_e_r;
    std::vector<matmul::field::Element> noise_f_l;
    std::vector<matmul::field::Element> noise_f_r;
    std::vector<matmul::field::Element> compress_vec;
    std::string error;
};

struct MatMulInputGenerationProfile {
    bool available{false};
    bool pool_initialized{false};
    uint64_t samples{0};
    uint64_t allocation_events{0};
    uint64_t reuse_events{0};
    double last_encode_noise_us{0.0};
    double last_encode_compress_us{0.0};
    double last_submit_wait_us{0.0};
    double last_gpu_generation_ms{0.0};
    std::string library_source;
    std::string reason;
};

MatMulInputGenerationProfile ProbeMatMulInputGenerationProfile();
MatMulInputGenerationResult GenerateMatMulInputsGPU(const MatMulInputGenerationRequest& request);

} // namespace btx::metal

#endif // BITCOIN_METAL_ORACLE_ACCEL_H
