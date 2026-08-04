// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_exact_replay_cuda.h>

// Host/stub when CUDA ExactReplay TU is not linked.
namespace matmul_v4::cuda {

bool IsRcExactReplayCudaAvailable() { return false; }

void ResetRcExactReplayCudaStats() {}

RcExactReplayCudaStats GetRcExactReplayCudaStats() { return {}; }

RcExactReplaySlotReuseOrderingTestResult
RunRcExactReplaySlotReuseOrderingTest()
{
    RcExactReplaySlotReuseOrderingTestResult result;
    result.interlock_supported = false;
    result.detail = "CUDA ExactReplay unavailable";
    return result;
}

bool TryCudaRcPhase1AssociativeRecall(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                      const std::vector<int8_t>&, const uint256&, const uint256&,
                                      uint32_t, uint32_t, uint32_t, std::vector<int8_t>&,
                                      const uint256*, const uint256*, const uint256*)
{
    return false;
}

bool TryCudaRcFusedExactGemmInt64(const std::vector<int8_t>&, uint32_t, uint32_t,
                                  const std::vector<int8_t>&, uint32_t, std::vector<int64_t>&)
{
    return false;
}

bool TryCudaRcExtractMXMatrixInt64(const uint256&, const std::vector<int64_t>&, uint32_t,
                                   uint32_t, std::vector<int8_t>&)
{
    return false;
}

bool TryCudaRcFusedFfnLayer(const std::vector<int8_t>&, const std::vector<int8_t>&,
                            const std::vector<int8_t>&, const uint256&, const uint256&, uint32_t,
                            uint32_t, uint32_t, std::vector<int8_t>&)
{
    return false;
}

bool TryCudaRcFusedFfnChain(const std::vector<int8_t>&, bool, const std::vector<int8_t>&,
                            const std::vector<int8_t>&, const std::vector<std::vector<int8_t>>&,
                            const std::vector<std::vector<int8_t>>&, const std::vector<uint256>&,
                            const std::vector<uint256>&, uint32_t, uint32_t, uint32_t, uint32_t,
                            std::vector<std::vector<int8_t>>&,
                            const std::vector<uint256>*, const std::vector<uint256>*)
{
    return false;
}

bool LaunchRcExactReplayFusedFfn(const std::vector<int8_t>&, const std::vector<int8_t>&,
                                 const std::vector<int8_t>&, const uint256&, const uint256&,
                                 uint32_t, uint32_t, uint32_t, uint32_t, std::vector<int8_t>&)
{
    return false;
}

bool LaunchRcExactReplayFusedFfnChain(const std::vector<int8_t>&,
                                      const std::vector<std::vector<int8_t>>&,
                                      const std::vector<std::vector<int8_t>>&,
                                      const std::vector<uint256>&, const std::vector<uint256>&,
                                      uint32_t, uint32_t, uint32_t,
                                      std::vector<std::vector<int8_t>>&)
{
    return false;
}

bool LaunchRcExactReplayPhase1(const std::vector<int8_t>&, const std::vector<int8_t>&,
                               const std::vector<int8_t>&, const uint256&, const uint256&,
                               uint32_t, uint32_t, uint32_t, std::vector<int8_t>&)
{
    return false;
}

bool LaunchRcExactReplayFusedFfnChainSeeded(
    const std::vector<int8_t>&, const std::vector<uint256>&,
    const std::vector<uint256>&, const std::vector<uint256>&,
    const std::vector<uint256>&, uint32_t, uint32_t, uint32_t,
    std::vector<std::vector<int8_t>>&)
{
    return false;
}

bool LaunchRcExactReplayPhase1Seeded(
    const uint256&, const uint256&, const uint256&, const uint256&,
    const uint256&, uint32_t, uint32_t, uint32_t, std::vector<int8_t>&)
{
    return false;
}

bool LaunchRcExactReplayExpandMx(
    const uint256&, uint32_t, uint32_t, std::vector<int8_t>&)
{
    return false;
}

bool LaunchRcExactReplayExpandMxForTest(
    const uint256&, uint32_t, uint32_t, uint32_t,
    std::vector<int8_t>&)
{
    return false;
}

} // namespace matmul_v4::cuda
