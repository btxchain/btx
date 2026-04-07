// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_UTIL_SMILE2_PROOF_REDESIGN_HARNESS_H
#define BTX_TEST_UTIL_SMILE2_PROOF_REDESIGN_HARNESS_H

#include <consensus/amount.h>
#include <shielded/smile2/ct_proof.h>
#include <test/shielded_ingress_proof_runtime_report.h>
#include <test/shielded_v2_send_runtime_report.h>
#include <univalue.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace btx::test::smile2redesign {

struct MetricBudget
{
    std::optional<uint64_t> max_proof_bytes;
    std::optional<uint64_t> max_tx_bytes;
    std::optional<int64_t> max_build_median_ns;
    std::optional<int64_t> max_verify_median_ns;
};

struct CtScenarioConfig
{
    std::string name;
    size_t anon_set{32};
    size_t input_count{1};
    size_t output_count{1};
    std::vector<int64_t> input_amounts;
    std::vector<int64_t> output_amounts;
    uint8_t seed{0x42};
    MetricBudget budget;
};

struct DirectSendScenarioConfig
{
    shieldedv2send::RuntimeScenarioConfig scenario;
    MetricBudget budget;
};

struct IngressScenarioConfig
{
    ingress::ProofRuntimeBackendKind backend_kind{ingress::ProofRuntimeBackendKind::SMILE};
    size_t reserve_output_count{1};
    size_t leaf_count{8};
    MetricBudget budget;
};

struct ProofRedesignFrameworkConfig
{
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    CAmount fee_sat{1000};
    std::vector<CtScenarioConfig> ct_scenarios;
    std::vector<DirectSendScenarioConfig> direct_send_scenarios;
    std::vector<IngressScenarioConfig> ingress_scenarios;
};

struct CTDeterministicSetup
{
    std::vector<smile2::SmileKeyPair> keys;
    smile2::CTPublicData pub;
    std::vector<smile2::CTInput> inputs;
    std::vector<smile2::CTOutput> outputs;

    static CTDeterministicSetup Create(size_t anon_set,
                                       size_t input_count,
                                       size_t output_count,
                                       const std::vector<int64_t>& input_amounts,
                                       const std::vector<int64_t>& output_amounts,
                                       uint8_t seed);
};

ProofRedesignFrameworkConfig MakeFastProofRedesignFrameworkConfig();
ProofRedesignFrameworkConfig MakeLaunchBaselineProofRedesignFrameworkConfig();
UniValue BuildProofRedesignFrameworkReport(const ProofRedesignFrameworkConfig& config);

} // namespace btx::test::smile2redesign

#endif // BTX_TEST_UTIL_SMILE2_PROOF_REDESIGN_HARNESS_H
