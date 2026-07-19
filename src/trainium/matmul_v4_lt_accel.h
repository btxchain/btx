// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TRAINIUM_MATMUL_V4_LT_ACCEL_H
#define BITCOIN_TRAINIUM_MATMUL_V4_LT_ACCEL_H

#include <cstddef>
#include <cstdint>
#include <vector>

// AWS Neuron/NKI does not expose native S8 x S8 -> S32 nc_matmul, but its
// documented BF16 Tensor Engine inputs and FP32 accumulation preserve the LT
// integer transcript exactly when every possible partial sum is within 2^24.
// The host adapter proves that bound before calling a separately compiled NKI
// NEFF/NRT bridge, then self-qualifies the bridge against CPU ExactGemm.

namespace matmul_v4::trainium {

inline constexpr uint32_t kTrainiumNeuronExactGemmProviderAbiV1 = 1;

struct TrainiumNeuronExactGemmProviderV1 {
    uint32_t abi_version{kTrainiumNeuronExactGemmProviderAbiV1};
    size_t struct_size{sizeof(TrainiumNeuronExactGemmProviderV1)};
    const char* provider_name{nullptr};
    void* context{nullptr};

    // Provider converts S8 -> BF16 exactly, runs BF16 Tensor Engine matmul with
    // FP32 accumulation, checks every FP32 output is finite/integral/in-range,
    // and converts it exactly to S32. It must not throw and must support
    // concurrent calls. `used_bf16_tensor_engine` may be true only when that
    // native path—not an NRT host/CPU fallback—executed.
    bool (*gemm_s8s8_bf16)(void* context, const int8_t* left, size_t left_elems,
                           const int8_t* right, size_t right_elems,
                           uint32_t rows, uint32_t inner, uint32_t cols,
                           int32_t* out, size_t out_elems,
                           bool* used_bf16_tensor_engine){nullptr};
};

/** First process-lifetime provider wins. Disabled without BTX_HAVE_NEURON_NRT. */
[[nodiscard]] bool RegisterTrainiumNeuronExactGemmProvider(
    const TrainiumNeuronExactGemmProviderV1& provider);

void ResetTrainiumNeuronExactGemmProviderForTesting();

/** True only after bounded BF16/FP32 probes match CPU and attest Tensor Engine. */
[[nodiscard]] bool IsTrainiumExactGemmAvailable();

[[nodiscard]] bool TryLaunchLtTrainiumGemmS8S8(const std::vector<int8_t>& left,
                                               const std::vector<int8_t>& right,
                                               uint32_t rows, uint32_t inner, uint32_t cols,
                                               std::vector<int32_t>& out);

/** No exact S32 x S8 Tensor Engine construction is documented; always declines. */
[[nodiscard]] bool TryLaunchLtTrainiumGemmS32S8(const std::vector<int32_t>& left,
                                                const std::vector<int8_t>& right,
                                                uint32_t rows, uint32_t inner, uint32_t cols,
                                                std::vector<int32_t>& out);

} // namespace matmul_v4::trainium

#endif // BITCOIN_TRAINIUM_MATMUL_V4_LT_ACCEL_H
