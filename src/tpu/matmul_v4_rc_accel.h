// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TPU_MATMUL_V4_RC_ACCEL_H
#define BTX_TPU_MATMUL_V4_RC_ACCEL_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC episode provider for Google Cloud TPU / PJRT.
//
// Mirrors LT ExactGemm PJRT registration, but for RC coupled episodes:
// persistent bank, Q-batch, barrier loop, Extract, device timing.
//
// Without BTX_HAVE_TPU_PJRT: host reference is unit-byte-exact; device register
// fail-closed. HARD BLOCKER deficit: "requires PJRT+TPU"
// Qualifying test: rc_tpu_episode_device_qualify
// Host unit-exact: rc_tpu_episode_host_byte_exact

namespace matmul_v4::tpu {

inline constexpr uint32_t kTpuPjrtRcEpisodeProviderAbiV1 = 1;

struct RCTpuEpisodeShape {
    uint32_t barriers{0};
    uint32_t lobes{0};
    uint32_t lobe_width{0};
    uint32_t bank_pages{0};
    uint32_t batch_q{1};
};

struct TpuPjrtRcEpisodeProviderV1 {
    uint32_t abi_version{kTpuPjrtRcEpisodeProviderAbiV1};
    size_t struct_size{sizeof(TpuPjrtRcEpisodeProviderV1)};
    const char* provider_name{nullptr};
    void* context{nullptr};

    // Run one barrier of Q×W · W×W ExactGemm lobes on TPU MXU. Must attest
    // used_exact_mxu=true (never host fallback). Returns false on any PJRT error.
    bool (*run_barrier_batch)(void* context, const int8_t* bank_pages, size_t bank_bytes,
                              uint32_t barriers, uint32_t lobes, uint32_t lobe_width,
                              uint32_t bank_pages_count, uint32_t batch_q,
                              const int8_t* state_in, int32_t* state_out,
                              bool* used_exact_mxu){nullptr};
};

[[nodiscard]] bool RegisterTpuPjrtRcEpisodeProvider(const TpuPjrtRcEpisodeProviderV1& provider);
void ResetTpuPjrtRcEpisodeProviderForTesting();

[[nodiscard]] bool IsRcTpuCompiled();
/** True after a registered provider's self-qual surface was invoked. */
[[nodiscard]] bool IsRcTpuAttempted();
[[nodiscard]] std::string RcTpuDeficit(); // "requires PJRT+TPU" when unqualified

/** Host reference: MineRCCoupledEpisode digests — always unit-byte-exact. */
[[nodiscard]] bool HostReferenceRcTpuCoupledEpisode(
    const CBlockHeader& header, int32_t height, const matmul::v4::rc::RCCoupParams& params,
    uint256& out_digest, matmul::v4::rc::RCEpisodeTiming* timing = nullptr);

class RCTpuEpisodeContext
{
public:
    RCTpuEpisodeContext() = default;
    ~RCTpuEpisodeContext() { Destroy(); }
    RCTpuEpisodeContext(const RCTpuEpisodeContext&) = delete;
    RCTpuEpisodeContext& operator=(const RCTpuEpisodeContext&) = delete;

    [[nodiscard]] bool Init(const RCTpuEpisodeShape& shape, std::string* error = nullptr);
    [[nodiscard]] bool Init(const matmul::v4::rc::RCCoupParams& params, uint32_t batch_q = 1,
                            std::string* error = nullptr);
    [[nodiscard]] bool LoadBank(const std::vector<std::vector<int8_t>>& pages,
                                std::string* error = nullptr);
    /** Device barrier DAG. Fail-closed without registered+qualified PJRT provider. */
    [[nodiscard]] bool RunBarriers(std::string* error = nullptr);
    /** Extract active state via host ExtractMX (byte-exact). */
    [[nodiscard]] bool ExtractHost(const uint256& prf_key, std::vector<int8_t>& out,
                                   std::string* error = nullptr);
    [[nodiscard]] matmul::v4::rc::RCEpisodeTiming LastTiming() const { return m_timing; }
    void Destroy();
    [[nodiscard]] bool Ready() const { return m_ready; }

private:
    RCTpuEpisodeShape m_shape{};
    bool m_ready{false};
    bool m_bank_loaded{false};
    std::vector<std::vector<int8_t>> m_bank;
    std::vector<int8_t> m_state;
    matmul::v4::rc::RCEpisodeTiming m_timing{};
};

[[nodiscard]] bool IsTpuPjrtRcEpisodeAvailable();

} // namespace matmul_v4::tpu

#endif // BTX_TPU_MATMUL_V4_RC_ACCEL_H
