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
#include <matmul/accelerated_solver.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/chaintype.h>

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace {

std::string JsonEscape(std::string_view input)
{
    std::string out;
    out.reserve(input.size());
    for (const char ch : input) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += ch; break;
        }
    }
    return out;
}

std::string PublicSourceRevision()
{
    const char* value{std::getenv("BTX_SOURCE_REVISION")};
    if (value == nullptr) return "unknown";
    const std::string revision{value};
    if (revision.size() != 40) return "unknown";
    for (const unsigned char ch : revision) {
        if (!std::isxdigit(ch)) return "unknown";
    }
    return revision;
}

} // namespace

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
    //
    // WARNING -- READ BEFORE USING THIS NUMBER FOR ANYTHING. target == 1 makes
    // the pre-hash target 1 << 18, so P(sigma passes) = 2^-238 and the matmul
    // digest stage is NEVER reached. What this harness measures is therefore
    // the v3 SHA header-grind rate R_sigma, with ZERO matmuls executed -- not a
    // v3 matmul rate and not, under any composition, an ASERT work ratio.
    // Dividing it by an RC episode rate yields a hash-rate-over-episode-rate
    // quantity with no operational meaning; that is how the discarded
    // 16893794/1 Epoch-A rescale was produced. The assertion at the bottom of
    // this test pins digest_requests == 0 so the limitation cannot be
    // rediscovered the hard way.
    header.nBits = arith_uint256{1}.GetCompact();
    header.nNonce64 = 0;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    constexpr int32_t kHeight = 200000;
    constexpr int64_t kParentMtp = 1779999910;
    // NOT "a few matmul hits": at target == 1 the expected count is 2e6 * 2^-238.
    constexpr uint64_t kTries = 2'000'000;
    uint64_t max_tries = kTries;
    const auto backend_selection =
        matmul::accelerated::ResolveMiningBackendFromEnvironment();
    const auto backend_requirement =
        matmul::accelerated::ResolveBackendRequirementFromEnvironment();
    BOOST_REQUIRE(backend_requirement.valid);
    if (backend_requirement.enabled) {
        BOOST_REQUIRE(matmul::accelerated::IsBackendRequirementSatisfied(
            backend_requirement, backend_selection));
    }
    matmul::accelerated::ResetMatMulBackendRuntimeStats();
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
    const auto backend_stats =
        matmul::accelerated::ProbeMatMulBackendRuntimeStats();

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
              << "\"requested_backend\":\""
              << matmul::backend::ToString(backend_selection.requested) << "\","
              << "\"active_backend\":\""
              << matmul::backend::ToString(backend_selection.active) << "\","
              << "\"backend_selection_reason\":\""
              << JsonEscape(backend_selection.reason) << "\","
              << "\"source_revision\":\"" << PublicSourceRevision() << "\","
              << "\"required_backend_enabled\":"
              << (backend_requirement.enabled ? "true" : "false") << ","
              << "\"required_backend_satisfied\":"
              << (matmul::accelerated::IsBackendRequirementSatisfied(
                      backend_requirement, backend_selection)
                      ? "true"
                      : "false")
              << ","
              << "\"measures\":\"v3_sha_prehash_grind_rate_only\","
              << "\"usable_as_asert_work_ratio\":false,"
              << "\"usable_as_asert_work_ratio_reason\":"
                 "\"target==1 gates out the matmul stage; digest_requests is 0, "
                 "so attempts_per_s is a SHA grind rate, not a v3 block rate\","
              << "\"requested_tries\":" << kTries << ","
              << "\"attempts_done\":" << attempts_done << ","
              << "\"solved\":" << (solved ? "true" : "false") << ","
              << "\"wall_s\":" << wall_s << ","
              << "\"attempts_per_s\":" << attempts_per_s << ","
              << "\"runtime_stats_attempts\":" << st.attempts << ","
              << "\"runtime_stats_total_elapsed_us\":" << st.total_elapsed_us
              << ",\"backend_digest_requests\":" << backend_stats.digest_requests
              << ",\"backend_requested_cpu\":" << backend_stats.requested_cpu
              << ",\"backend_requested_metal\":" << backend_stats.requested_metal
              << ",\"backend_requested_cuda\":" << backend_stats.requested_cuda
              << ",\"backend_metal_successes\":" << backend_stats.metal_successes
              << ",\"backend_cuda_successes\":" << backend_stats.cuda_successes
              << ",\"backend_metal_fallbacks_to_cpu\":"
              << backend_stats.metal_fallbacks_to_cpu
              << ",\"backend_cuda_fallbacks_to_cpu\":"
              << backend_stats.cuda_fallbacks_to_cpu
              << "}" << std::endl;

    BOOST_CHECK_GT(attempts_done, 0u);
    BOOST_CHECK_GT(wall_s, 0.0);
    BOOST_CHECK_GT(attempts_per_s, 0.0);
    // Pin the regime. If a future edit lowers the difficulty so the matmul
    // stage actually runs, this fires and forces the author to also fix the
    // "measures"/"usable_as_asert_work_ratio" fields above, rather than
    // silently emitting a number that looks like, but is not, a work ratio.
    BOOST_CHECK_EQUAL(backend_stats.digest_requests, 0u);
}

BOOST_AUTO_TEST_SUITE_END()
