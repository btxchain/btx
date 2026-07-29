// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>

namespace matmul::v4::rc::normalized_parent_external_producer_equality {
namespace {

void Note(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_parent_external_producer_equality:" +
            detail;
    }
}

TerminalStatusV1 MakeTerminal(
    TerminalKindV1 kind,
    uint32_t layer_ordinal,
    const uint256& expected_root,
    bool streaming_verified,
    bool role_export_joined)
{
    TerminalStatusV1 out;
    out.kind = kind;
    out.layer_ordinal = layer_ordinal;
    out.expected_vector_root_alg = expected_root;
    out.streaming_child_verified = streaming_verified;
    out.role_export_equality_constrained = role_export_joined;
    if (!streaming_verified) {
        out.residual =
            std::string{TerminalKindNameV1(kind)} +
            ":layer_" + std::to_string(layer_ordinal) +
            ":streaming_child_unverified";
    } else if (!role_export_joined) {
        out.residual =
            std::string{TerminalKindNameV1(kind)} +
            ":layer_" + std::to_string(layer_ordinal) +
            ":normalized_role_export_alias_open";
    }
    return out;
}

} // namespace

const char* TerminalKindNameV1(TerminalKindV1 kind)
{
    switch (kind) {
    case TerminalKindV1::OperandA: return "operand_a";
    case TerminalKindV1::OperandB: return "operand_b";
    case TerminalKindV1::OutputY: return "output_y";
    }
    return "unknown";
}

AssessmentV1 AssessStreamingRoleExportEqualityV1(
    const streaming::StreamingEpisodeClosureReceiptV1* receipt,
    std::string* why)
{
    AssessmentV1 out;
    if (receipt == nullptr) {
        out.residuals.push_back(
            "streaming_episode_closure_receipt_missing");
        out.note =
            "stage3:normalized_parent_external_producer_equality:"
            "streaming_receipt_missing;"
            "external_producer_terminal_equality_pending";
        Note(why, "streaming_receipt_missing");
        return out;
    }
    out.streaming_receipt_present = true;
    out.layer_count =
        static_cast<uint32_t>(receipt->layers.size());

    std::string verify_why;
    if (!streaming::VerifyStreamingEpisodeClosureReceiptV1(
            *receipt, &verify_why) ||
        receipt->production_authority ||
        !receipt->every_gemm_child_verified) {
        out.residuals.push_back(
            "streaming_episode_closure_receipt_invalid:" +
            verify_why);
        out.note =
            "stage3:normalized_parent_external_producer_equality:"
            "streaming_receipt_invalid;"
            "external_producer_terminal_equality_pending";
        Note(why, "streaming_receipt_invalid:" + verify_why);
        return out;
    }
    out.streaming_receipt_verified = true;

    out.terminals.reserve(out.layer_count * 3U);
    for (const auto& layer : receipt->layers) {
        const auto& closure = layer.closure;
        const bool streaming_ok =
            layer.retained_commitment ==
                streaming::
                    ComputeStreamedLayerClosureCommitmentV1(
                        layer) &&
            closure.proof_owned_terminal_cancellation &&
            closure.all_children_proof_verified &&
            !closure.production_authority;
        // Role-export equality inside the normalized parent is still the
        // open attachment.  Streaming closures deliberately keep
        // role_export_equality_constrained false until that same-parent
        // alias executes.
        const bool role_export =
            closure.role_export_equality_constrained;

        out.terminals.push_back(MakeTerminal(
            TerminalKindV1::OperandA,
            layer.layer_ordinal,
            closure.operand_a_vector_root_alg,
            streaming_ok &&
                !closure.operand_a_vector_root_alg.IsNull(),
            role_export));
        out.terminals.push_back(MakeTerminal(
            TerminalKindV1::OperandB,
            layer.layer_ordinal,
            closure.operand_b_vector_root_alg,
            streaming_ok &&
                !closure.operand_b_vector_root_alg.IsNull(),
            role_export));
        out.terminals.push_back(MakeTerminal(
            TerminalKindV1::OutputY,
            layer.layer_ordinal,
            closure.output_y_vector_root_alg,
            streaming_ok &&
                !closure.output_y_vector_root_alg.IsNull(),
            role_export));
    }

    out.terminals_required =
        static_cast<uint32_t>(out.terminals.size());
    for (const auto& terminal : out.terminals) {
        if (terminal.streaming_child_verified) {
            ++out.terminals_streaming_verified;
        }
        if (terminal.role_export_equality_constrained) {
            ++out.terminals_role_export_joined;
        }
        if (!terminal.residual.empty()) {
            out.residuals.push_back(terminal.residual);
        }
    }
    out.all_streaming_children_verified =
        out.terminals_required > 0 &&
        out.terminals_streaming_verified ==
            out.terminals_required;
    out.all_role_export_equality_constrained =
        out.terminals_required > 0 &&
        out.terminals_role_export_joined ==
            out.terminals_required;
    out.external_producer_terminal_equality_complete =
        out.all_streaming_children_verified &&
        out.all_role_export_equality_constrained;

    if (out.external_producer_terminal_equality_complete) {
        out.note =
            "stage3:normalized_parent_external_producer_equality:"
            "all_terminals_joined";
        Note(why, "all_terminals_joined");
    } else {
        const std::string pending_detail =
            "streaming_verified=" +
            std::to_string(out.terminals_streaming_verified) +
            "/" +
            std::to_string(out.terminals_required) +
            ";role_export_joined=" +
            std::to_string(out.terminals_role_export_joined) +
            "/" +
            std::to_string(out.terminals_required) +
            ";external_producer_terminal_equality_pending";
        out.note =
            "stage3:normalized_parent_external_producer_equality:" +
            pending_detail;
        Note(why, pending_detail);
    }
    return out;
}

} // namespace matmul::v4::rc::normalized_parent_external_producer_equality
