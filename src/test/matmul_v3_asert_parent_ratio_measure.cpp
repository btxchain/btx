// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// One-shot measurement aid for Epoch-A ASERT work-ratio calibration:
// local MatMul v3 SolveMatMul attempt throughput (production mainnet-like
// dims) on this host. Not a consensus test; prints a JSON line to stdout.
// Does not touch GPU ExactReplay paths.

#include <boost/test/unit_test.hpp>

#include <arith_uint256.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>

BOOST_FIXTURE_TEST_SUITE(matmul_v3_asert_parent_ratio_measure, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(measure_v3_parent_attempts_per_s_mainnet_like)
{
    auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();
    // Force live mainnet-like v3 work unit (pre-RC). Keep all v4/RC heights disabled.
    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulMinDimension = 64;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulPreHashEpsilonBits = 18;
    consensus.nMatMulPreHashEpsilonBitsUpgrade = 18;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 0;
    consensus.nMatMulNonceSeedHeight = 0;
    consensus.nMatMulParentMtpSeedHeight = 0;
    consensus.nMatMulProductDigestHeight = 0;
    consensus.nMatMulV4Height = std::numeric_limits<int32_t>::max();
    consensus.nMatMulBMX4CHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000a1"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000a2"};
    header.nTime = 1780000000U;
    // Hard target so SolveMatMul burns attempts without finishing early.
    header.nBits = arith_uint256{1}.GetCompact();
    header.nNonce64 = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    constexpr int32_t kHeight = 200000;
    constexpr int64_t kParentMtp = 1779999910;
    constexpr uint64_t kTries = 2'000'000; // ~ε=18 ⇒ expect ~few matmul hits
    uint64_t max_tries = kTries;
    ResetMatMulSolveRuntimeStats();
    const auto t0 = std::chrono::steady_clock::now();
    const bool solved = SolveMatMul(header, consensus, max_tries, kHeight,
                                    /*abort_flag=*/nullptr,
                                    /*freivalds_payload_out=*/nullptr,
                                    /*share_target_override=*/nullptr,
                                    std::optional<int64_t>{kParentMtp});
    const auto t1 = std::chrono::steady_clock::now();
    const double wall_s =
        std::chrono::duration_cast<std::chrono::duration<double>>(t1 - t0).count();
    const MatMulSolveRuntimeStats st = ProbeMatMulSolveRuntimeStats();

    const uint64_t attempts_done = kTries - max_tries;
    const double attempts_per_s =
        wall_s > 0.0 ? static_cast<double>(attempts_done) / wall_s : 0.0;

    std::cout << "ASERT_V3_PARENT_JSON:"
              << "{"
              << "\"workload\":\"matmul_v3_mainnet_like\","
              << "\"n\":" << consensus.nMatMulDimension << ","
              << "\"b\":" << consensus.nMatMulTranscriptBlockSize << ","
              << "\"r\":" << consensus.nMatMulNoiseRank << ","
              << "\"prehash_epsilon_bits\":" << consensus.nMatMulPreHashEpsilonBits << ","
              << "\"requested_tries\":" << kTries << ","
              << "\"attempts_done\":" << attempts_done << ","
              << "\"solved\":" << (solved ? "true" : "false") << ","
              << "\"wall_s\":" << wall_s << ","
              << "\"attempts_per_s\":" << attempts_per_s << ","
              << "\"runtime_stats_attempts\":" << st.attempts << ","
              << "\"runtime_stats_total_elapsed_us\":" << st.total_elapsed_us
              << "}" << std::endl;

    BOOST_CHECK_GT(attempts_done, 0u);
    BOOST_CHECK_GT(wall_s, 0.0);
    BOOST_CHECK_GT(attempts_per_s, 0.0);
}

BOOST_AUTO_TEST_SUITE_END()
