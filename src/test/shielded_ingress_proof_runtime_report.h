// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_INGRESS_PROOF_RUNTIME_REPORT_H
#define BTX_TEST_SHIELDED_INGRESS_PROOF_RUNTIME_REPORT_H

#include <univalue.h>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace btx::test::ingress {

enum class ProofRuntimeBackendKind : uint8_t {
    SMILE = 1,
    MATRICT_PLUS = 2,
    RECEIPT_BACKED = 3,
};

struct ProofRuntimeReportConfig
{
    ProofRuntimeBackendKind backend_kind{ProofRuntimeBackendKind::SMILE};
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    size_t reserve_output_count{1};
    size_t leaf_count{100};
};

UniValue BuildProofRuntimeReport(const ProofRuntimeReportConfig& config);

struct ProofCapacitySweepConfig
{
    ProofRuntimeBackendKind backend_kind{ProofRuntimeBackendKind::SMILE};
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    size_t reserve_output_count{1};
    std::vector<size_t> leaf_counts;
};

UniValue BuildProofCapacitySweepReport(const ProofCapacitySweepConfig& config);

struct ProofBackendDecisionReportConfig
{
    ProofRuntimeBackendKind backend_kind{ProofRuntimeBackendKind::SMILE};
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    size_t reserve_output_count{1};
    std::vector<size_t> measured_leaf_counts;
    std::vector<size_t> target_leaf_counts;
};

UniValue BuildProofBackendDecisionReport(const ProofBackendDecisionReportConfig& config);

} // namespace btx::test::ingress

#endif // BTX_TEST_SHIELDED_INGRESS_PROOF_RUNTIME_REPORT_H
