// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TRAINIUM_MATMUL_V4_RC_ACCEL_H
#define BTX_TRAINIUM_MATMUL_V4_RC_ACCEL_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC episode provider for AWS Trainium / Neuron NKI.
// HARD BLOCKER deficit: "requires Neuron+Trainium"
// Qualifying test: rc_trainium_episode_device_qualify
// Host unit-exact: rc_trainium_episode_host_byte_exact

namespace matmul_v4::trainium {

inline constexpr uint32_t kTrainiumNeuronRcEpisodeProviderAbiV1 = 1;

struct RCTrainiumEpisodeShape {
    uint32_t barriers{0};
    uint32_t lobes{0};
    uint32_t lobe_width{0};
    uint32_t bank_pages{0};
    uint32_t batch_q{1};
};

struct TrainiumNeuronRcEpisodeProviderV1 {
    uint32_t abi_version{kTrainiumNeuronRcEpisodeProviderAbiV1};
    size_t struct_size{sizeof(TrainiumNeuronRcEpisodeProviderV1)};
    const char* provider_name{nullptr};
    void* context{nullptr};

    bool (*run_barrier_batch)(void* context, const int8_t* bank_pages, size_t bank_bytes,
                              uint32_t barriers, uint32_t lobes, uint32_t lobe_width,
                              uint32_t bank_pages_count, uint32_t batch_q,
                              const int8_t* state_in, int32_t* state_out,
                              bool* used_bf16_tensor_engine){nullptr};
};

[[nodiscard]] bool RegisterTrainiumNeuronRcEpisodeProvider(
    const TrainiumNeuronRcEpisodeProviderV1& provider);
void ResetTrainiumNeuronRcEpisodeProviderForTesting();

[[nodiscard]] bool IsRcTrainiumCompiled();
[[nodiscard]] std::string RcTrainiumDeficit(); // "requires Neuron+Trainium"

[[nodiscard]] bool HostReferenceRcTrainiumCoupledEpisode(
    const CBlockHeader& header, int32_t height, const matmul::v4::rc::RCCoupParams& params,
    uint256& out_digest, matmul::v4::rc::RCEpisodeTiming* timing = nullptr);

class RCTrainiumEpisodeContext
{
public:
    RCTrainiumEpisodeContext() = default;
    ~RCTrainiumEpisodeContext() { Destroy(); }
    RCTrainiumEpisodeContext(const RCTrainiumEpisodeContext&) = delete;
    RCTrainiumEpisodeContext& operator=(const RCTrainiumEpisodeContext&) = delete;

    [[nodiscard]] bool Init(const RCTrainiumEpisodeShape& shape, std::string* error = nullptr);
    [[nodiscard]] bool Init(const matmul::v4::rc::RCCoupParams& params, uint32_t batch_q = 1,
                            std::string* error = nullptr);
    [[nodiscard]] bool LoadBank(const std::vector<std::vector<int8_t>>& pages,
                                std::string* error = nullptr);
    [[nodiscard]] bool RunBarriers(std::string* error = nullptr);
    [[nodiscard]] bool ExtractHost(const uint256& prf_key, std::vector<int8_t>& out,
                                   std::string* error = nullptr);
    [[nodiscard]] matmul::v4::rc::RCEpisodeTiming LastTiming() const { return m_timing; }
    void Destroy();
    [[nodiscard]] bool Ready() const { return m_ready; }

private:
    RCTrainiumEpisodeShape m_shape{};
    bool m_ready{false};
    bool m_bank_loaded{false};
    std::vector<std::vector<int8_t>> m_bank;
    std::vector<int8_t> m_state;
    matmul::v4::rc::RCEpisodeTiming m_timing{};
};

[[nodiscard]] bool IsTrainiumNeuronRcEpisodeAvailable();

} // namespace matmul_v4::trainium

#endif // BTX_TRAINIUM_MATMUL_V4_RC_ACCEL_H
