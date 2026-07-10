// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_ORACLE_ACCEL_H
#define BITCOIN_CUDA_ORACLE_ACCEL_H

#include <matmul/field.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace btx::cuda {

struct MatMulGeneratedInputsDevice {
    int device_index{-1};
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint32_t noise_words{0};
    uint32_t compress_words{0};
    matmul::field::Element* storage{nullptr};
    void* ready_event{nullptr};
    matmul::field::Element* noise_e_l{nullptr};
    matmul::field::Element* noise_e_r{nullptr};
    matmul::field::Element* noise_f_l{nullptr};
    matmul::field::Element* noise_f_r{nullptr};
    matmul::field::Element* compress_vec{nullptr};

    MatMulGeneratedInputsDevice() = default;
    MatMulGeneratedInputsDevice(const MatMulGeneratedInputsDevice&) = delete;
    MatMulGeneratedInputsDevice& operator=(const MatMulGeneratedInputsDevice&) = delete;
    MatMulGeneratedInputsDevice(MatMulGeneratedInputsDevice&&) = delete;
    MatMulGeneratedInputsDevice& operator=(MatMulGeneratedInputsDevice&&) = delete;
    ~MatMulGeneratedInputsDevice();
};

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

struct MatMulInputGenerationDeviceResult {
    bool available{false};
    bool success{false};
    std::shared_ptr<const MatMulGeneratedInputsDevice> inputs;
    std::string error;
};

struct MatMulInputGenerationDeviceBatchRequest {
    uint32_t n{0};
    uint32_t b{0};
    uint32_t r{0};
    uint32_t batch_size{0};
    const uint256* sigmas{nullptr};
};

struct MatMulInputGenerationDeviceBatchResult {
    bool available{false};
    bool success{false};
    std::vector<std::shared_ptr<const MatMulGeneratedInputsDevice>> inputs;
    std::string error;
};

struct MatMulNonceSeedPreHashScanRequest {
    int32_t version{0};
    uint256 previous_block_hash;
    uint256 merkle_root;
    uint32_t time{0};
    uint32_t bits{0};
    uint64_t start_nonce{0};
    uint16_t matmul_dim{0};
    uint32_t block_height{0};
    uint32_t scan_count{0};
    uint256 pre_hash_target;
    uint32_t seed_version{2};
    int64_t parent_median_time_past{0};
    bool compact_pass_offsets{false};
    bool compact_pass_records{false};
};

struct MatMulNonceSeedPreHashPassRecord {
    uint32_t offset{0};
    uint256 seed_a;
    uint256 seed_b;
    uint256 sigma;
};

struct MatMulNonceSeedPreHashScanResult {
    bool available{false};
    bool success{false};
    uint32_t scanned_count{0};
    std::vector<uint8_t> pass_flags;
    std::vector<uint32_t> pass_offsets;
    std::vector<MatMulNonceSeedPreHashPassRecord> pass_records;
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
MatMulInputGenerationDeviceResult GenerateMatMulInputsGPUDevice(const MatMulInputGenerationRequest& request);
MatMulInputGenerationDeviceBatchResult GenerateMatMulInputsGPUDeviceBatch(
    const MatMulInputGenerationDeviceBatchRequest& request);
MatMulNonceSeedPreHashScanResult ScanMatMulNonceSeedPreHashGPU(
    const MatMulNonceSeedPreHashScanRequest& request);

} // namespace btx::cuda

#endif // BITCOIN_CUDA_ORACLE_ACCEL_H
