// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PARENT_EXTERNAL_PRODUCER_EQUALITY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PARENT_EXTERNAL_PRODUCER_EQUALITY_H

#include <matmul/matmul_v4_rc_stage3_streaming_episode_closure.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::normalized_parent_external_producer_equality {

namespace streaming = streaming_episode_closure;

inline constexpr uint16_t kVersionV1 = 1;

/**
 * Six dual-Fp3 producer terminals the normalized parent must equality-
 * constrain: A/B/Y against the upstream builder / previous-Extract exports.
 *
 * Streaming layer closures already prove leaf↔producer multiset equality.
 * This assessment tracks the still-open same-parent role-export alias that
 * must attach those expected alg roots to the fourteen-role parent AIR.
 */
enum class TerminalKindV1 : uint8_t {
    OperandA = 0,
    OperandB = 1,
    OutputY = 2,
};

struct TerminalStatusV1 {
    TerminalKindV1 kind{TerminalKindV1::OperandA};
    uint32_t layer_ordinal{0};
    uint256 expected_vector_root_alg{};
    bool streaming_child_verified{false};
    bool role_export_equality_constrained{false};
    std::string residual;
};

struct AssessmentV1 {
    uint16_t version{kVersionV1};
    bool streaming_receipt_present{false};
    bool streaming_receipt_verified{false};
    uint32_t layer_count{0};
    uint32_t terminals_required{0};
    uint32_t terminals_streaming_verified{0};
    uint32_t terminals_role_export_joined{0};
    std::vector<TerminalStatusV1> terminals;
    std::vector<std::string> residuals;
    bool all_streaming_children_verified{false};
    bool all_role_export_equality_constrained{false};
    /**
     * True only when every required terminal is streaming-verified and
     * role-export equality is constrained inside the normalized parent.
     * Remains false until that same-parent attachment is executable.
     */
    bool external_producer_terminal_equality_complete{false};
    std::string note;
};

[[nodiscard]] const char* TerminalKindNameV1(TerminalKindV1 kind);

/**
 * Assess the winner's streaming episode receipt against the open parent
 * role-export residual.  Never flips Ready / authority flags.
 */
[[nodiscard]] AssessmentV1 AssessStreamingRoleExportEqualityV1(
    const streaming::StreamingEpisodeClosureReceiptV1* receipt,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_parent_external_producer_equality

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PARENT_EXTERNAL_PRODUCER_EQUALITY_H
