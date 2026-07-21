// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_ASCEND_MATMUL_V4_RC_ACCEL_H
#define BTX_ASCEND_MATMUL_V4_RC_ACCEL_H

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

// ENC_RC episode provider for Huawei Ascend / CANN Cube.
// HARD BLOCKER deficit: "requires CANN+Ascend"
// Qualifying test: rc_ascend_episode_device_qualify
// Host unit-exact: rc_ascend_episode_host_byte_exact
// Never label Cube INT8 ExactGemm as native MX float.

namespace matmul_v4::ascend {

struct RCAscendEpisodeShape {
    uint32_t barriers{0};
    uint32_t lobes{0};
    uint32_t lobe_width{0};
    uint32_t bank_pages{0};
    uint32_t batch_q{1};
};

[[nodiscard]] bool IsRcAscendCompiled();
[[nodiscard]] std::string RcAscendDeficit(); // "requires CANN+Ascend"

[[nodiscard]] bool HostReferenceRcAscendCoupledEpisode(
    const CBlockHeader& header, int32_t height, const matmul::v4::rc::RCCoupParams& params,
    uint256& out_digest, matmul::v4::rc::RCEpisodeTiming* timing = nullptr);

/** Cube ExactGemm s8×s8 for one RC lobe panel — fail-closed without CANN. */
[[nodiscard]] bool TryLaunchRcAscendGemmS8S8(const std::vector<int8_t>& left,
                                             const std::vector<int8_t>& right, uint32_t rows,
                                             uint32_t inner, uint32_t cols,
                                             std::vector<int32_t>& out,
                                             bool* used_cube_path = nullptr);

class RCAscendEpisodeContext
{
public:
    RCAscendEpisodeContext() = default;
    ~RCAscendEpisodeContext() { Destroy(); }
    RCAscendEpisodeContext(const RCAscendEpisodeContext&) = delete;
    RCAscendEpisodeContext& operator=(const RCAscendEpisodeContext&) = delete;

    [[nodiscard]] bool Init(const RCAscendEpisodeShape& shape, std::string* error = nullptr);
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
    RCAscendEpisodeShape m_shape{};
    bool m_ready{false};
    bool m_bank_loaded{false};
    std::vector<std::vector<int8_t>> m_bank;
    std::vector<int8_t> m_state;
    matmul::v4::rc::RCEpisodeTiming m_timing{};
};

[[nodiscard]] bool IsAscendRcEpisodeAvailable();

} // namespace matmul_v4::ascend

#endif // BTX_ASCEND_MATMUL_V4_RC_ACCEL_H
