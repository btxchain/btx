// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>

#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <hash.h>

#include <algorithm>
#include <utility>

namespace matmul::v4::rc::normalized_parent_external_producer_equality {
namespace {

namespace gf = gkr_field;

using AirCS = air_quotient::AirConstraintSystem<gf::Fp3>;

void Note(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_parent_external_producer_equality:" +
            detail;
    }
}

bool Fail(std::string* why, const std::string& detail)
{
    Note(why, detail);
    return false;
}

std::array<uint32_t, 8> Root8(const uint256& root)
{
    std::array<uint32_t, 8> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(root.begin()[offset]) |
            (static_cast<uint32_t>(root.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(root.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(root.begin()[offset + 3]) << 24);
    }
    return out;
}

void AddRootWordPin(
    AirCS& cs,
    uint32_t column,
    uint32_t expected,
    const char* name)
{
    cs.constraints.push_back(
        {
            name,
            air_quotient::AirKind::kEverywhere,
            1,
            [column, expected](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[column],
                    gf::Fp3::FromFp(
                        gf::FromU64(expected)));
            },
        });
}

void AddSameParentFirstRowAlias(
    AirCS& cs,
    uint32_t left,
    uint32_t right,
    const char* name)
{
    cs.constraints.push_back(
        {
            name,
            air_quotient::AirKind::kFirstRow,
            1,
            [left, right](
                const std::vector<gf::Fp3>& current,
                const std::vector<gf::Fp3>&) {
                return gf::Sub(
                    current[left],
                    current[right]);
            },
        });
}

uint32_t AllocatePinnedRootWordColumn(
    AirCS& cs,
    std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t word_value,
    const char* pin_name)
{
    const uint32_t column = cs.n_columns++;
    columns.push_back(
        std::vector<gf::Fp3>(
            cs.n_rows,
            gf::Fp3::FromFp(gf::FromU64(word_value))));
    AddRootWordPin(cs, column, word_value, pin_name);
    return column;
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

const ParentExportPinV1* FindExportPin(
    const std::vector<ParentExportPinV1>& pins,
    TerminalKindV1 kind,
    uint32_t layer_ordinal)
{
    for (const auto& pin : pins) {
        if (pin.kind == kind &&
            pin.layer_ordinal == layer_ordinal) {
            return &pin;
        }
    }
    return nullptr;
}

bool JoinConstrained(const ParentTerminalJoinV1& join)
{
    return join.roots_equal &&
        join.expected_pinned &&
        join.export_pinned_or_reused &&
        join.root_words_same_parent_aliased &&
        !join.expected_vector_root_alg.IsNull() &&
        !join.export_vector_root_alg.IsNull();
}

bool StreamingLayerTerminalOk(
    const streaming::StreamedLayerClosureV1& layer,
    const uint256& expected_root)
{
    return layer.retained_commitment ==
               streaming::
                   ComputeStreamedLayerClosureCommitmentV1(
                       layer) &&
        layer.closure.proof_owned_terminal_cancellation &&
        layer.closure.all_children_proof_verified &&
        !layer.closure.production_authority &&
        !layer.closure.role_export_equality_constrained &&
        !expected_root.IsNull();
}

/**
 * Structural premises Assess/VerifyCertificate need to bind parent role-export
 * joins to a streaming receipt.  Full FRI replay stays on Attach /
 * VerifyStreamingEpisodeClosureReceiptV1 at ingress; Assess must remain fast
 * and fixture-capable without a multi-hour mine.
 */
bool StreamingReceiptRoleExportPremisesV1(
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    std::string* why)
{
    if (receipt.version != streaming::kReceiptVersionV1 ||
        receipt.production_authority ||
        !receipt.every_gemm_child_verified ||
        receipt.extract_role_children_consumed ||
        receipt.normalized_parent_consumed ||
        receipt.layers.empty() ||
        receipt.receipt_commitment.IsNull() ||
        receipt.receipt_commitment !=
            streaming::
                ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                    receipt)) {
        return Fail(why, "receipt_role_export_premises");
    }
    for (const auto& layer : receipt.layers) {
        const std::array<uint256, 3> roots = {
            layer.closure.operand_a_vector_root_alg,
            layer.closure.operand_b_vector_root_alg,
            layer.closure.output_y_vector_root_alg,
        };
        for (const auto& root : roots) {
            if (!StreamingLayerTerminalOk(layer, root)) {
                return Fail(
                    why,
                    "receipt_role_export_layer_terminal");
            }
        }
    }
    return true;
}

bool AppendTerminalJoin(
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    TerminalKindV1 kind,
    uint32_t layer_ordinal,
    const uint256& expected_root,
    const ParentExportPinV1& export_pin,
    ParentTerminalJoinV1& join,
    std::string* why)
{
    join = {};
    join.kind = kind;
    join.layer_ordinal = layer_ordinal;
    join.expected_vector_root_alg = expected_root;
    join.export_vector_root_alg =
        export_pin.export_vector_root_alg;
    if (expected_root.IsNull() ||
        export_pin.export_vector_root_alg.IsNull()) {
        return Fail(why, "attach_null_root");
    }
    join.roots_equal =
        expected_root == export_pin.export_vector_root_alg;
    if (!join.roots_equal) {
        return Fail(
            why,
            std::string{TerminalKindNameV1(kind)} +
                ":layer_" + std::to_string(layer_ordinal) +
                ":export_root_mismatch");
    }
    if (parent_cs.n_rows < 2 ||
        parent_columns.size() != parent_cs.n_columns) {
        return Fail(why, "attach_parent_shape");
    }

    const auto expected_words = Root8(expected_root);
    const auto export_words =
        Root8(export_pin.export_vector_root_alg);
    for (uint32_t word = 0; word < 8; ++word) {
        join.expected_root_word_columns[word] =
            AllocatePinnedRootWordColumn(
                parent_cs, parent_columns,
                expected_words[word],
                "stage3.parent_role_export.expected_root_word");
        if (export_pin.has_existing_root_word_columns) {
            const uint32_t existing =
                export_pin.existing_root_word_columns[word];
            if (existing >= parent_cs.n_columns) {
                return Fail(why, "attach_existing_column");
            }
            join.export_root_word_columns[word] = existing;
        } else {
            join.export_root_word_columns[word] =
                AllocatePinnedRootWordColumn(
                    parent_cs, parent_columns,
                    export_words[word],
                    "stage3.parent_role_export.export_root_word");
        }
        AddSameParentFirstRowAlias(
            parent_cs,
            join.expected_root_word_columns[word],
            join.export_root_word_columns[word],
            "stage3.parent_role_export.root_same_parent_alias");
    }
    join.expected_pinned = true;
    join.export_pinned_or_reused = true;
    join.root_words_same_parent_aliased = true;
    return true;
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

RCStage3RelationEndpoint TerminalExportEndpointV1(
    TerminalKindV1 kind)
{
    switch (kind) {
    case TerminalKindV1::OperandA:
        return RCStage3RelationEndpoint::EpisodeGemmOperandA;
    case TerminalKindV1::OperandB:
        return RCStage3RelationEndpoint::EpisodeGemmOperandB;
    case TerminalKindV1::OutputY:
        return RCStage3RelationEndpoint::EpisodeGemmOutputY;
    }
    return RCStage3RelationEndpoint::EpisodeGemmOperandA;
}

uint256 ComputeParentRoleExportEqualityCertificateCommitmentV1(
    const ParentRoleExportEqualityCertificateV1& certificate)
{
    if (certificate.version != kCertificateVersionV1 ||
        certificate.streaming_receipt_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << std::string{
                "BTX_RC_STAGE3_PARENT_ROLE_EXPORT_EQUALITY_V1"}
         << certificate.version
         << certificate.streaming_receipt_commitment
         << certificate.terminals_required
         << certificate.terminals_constrained
         << certificate.all_terminals_constrained
         << static_cast<uint32_t>(certificate.joins.size());
    for (const auto& join : certificate.joins) {
        hash << static_cast<uint8_t>(join.kind)
             << join.layer_ordinal
             << join.expected_vector_root_alg
             << join.export_vector_root_alg
             << join.expected_pinned
             << join.export_pinned_or_reused
             << join.roots_equal
             << join.root_words_same_parent_aliased;
        for (uint32_t column :
             join.expected_root_word_columns) {
            hash << column;
        }
        for (uint32_t column :
             join.export_root_word_columns) {
            hash << column;
        }
    }
    return hash.GetSHA256();
}

bool BuildHostedExportPinsFromStreamingReceiptV1(
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    std::vector<ParentExportPinV1>& out_pins,
    std::string* why)
{
    out_pins.clear();
    std::string verify_why;
    if (!streaming::VerifyStreamingEpisodeClosureReceiptV1(
            receipt, &verify_why) ||
        receipt.production_authority ||
        !receipt.every_gemm_child_verified) {
        return Fail(
            why,
            "hosted_pins_receipt_invalid:" + verify_why);
    }
    out_pins.reserve(receipt.layers.size() * 3U);
    for (const auto& layer : receipt.layers) {
        const auto& closure = layer.closure;
        const std::array<
            std::pair<TerminalKindV1, uint256>, 3>
            terminals = {{
                {TerminalKindV1::OperandA,
                 closure.operand_a_vector_root_alg},
                {TerminalKindV1::OperandB,
                 closure.operand_b_vector_root_alg},
                {TerminalKindV1::OutputY,
                 closure.output_y_vector_root_alg},
            }};
        for (const auto& [kind, root] : terminals) {
            if (root.IsNull() ||
                !StreamingLayerTerminalOk(layer, root)) {
                return Fail(
                    why,
                    std::string{TerminalKindNameV1(kind)} +
                        ":layer_" +
                        std::to_string(layer.layer_ordinal) +
                        ":hosted_pin_unavailable");
            }
            ParentExportPinV1 pin;
            pin.kind = kind;
            pin.layer_ordinal = layer.layer_ordinal;
            pin.export_vector_root_alg = root;
            out_pins.push_back(pin);
        }
    }
    if (out_pins.empty()) {
        return Fail(why, "hosted_pins_empty");
    }
    return true;
}

bool AttachParentRoleExportEqualityTerminalsV1(
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const uint256& streaming_receipt_commitment,
    const std::vector<ParentExportPinV1>& expected_terminals,
    const std::vector<ParentExportPinV1>& export_pins,
    ParentRoleExportEqualityCertificateV1& out,
    std::string* why)
{
    out = {};
    out.version = kCertificateVersionV1;
    if (streaming_receipt_commitment.IsNull()) {
        return Fail(why, "attach_receipt_commitment_null");
    }
    if (parent_cs.n_rows < 2 ||
        parent_columns.size() != parent_cs.n_columns) {
        return Fail(why, "attach_parent_shape");
    }
    if (expected_terminals.empty()) {
        return Fail(why, "attach_terminals_empty");
    }
    out.streaming_receipt_commitment =
        streaming_receipt_commitment;
    out.terminals_required =
        static_cast<uint32_t>(expected_terminals.size());
    out.joins.reserve(out.terminals_required);

    for (const auto& expected : expected_terminals) {
        if (expected.export_vector_root_alg.IsNull()) {
            return Fail(
                why,
                std::string{TerminalKindNameV1(expected.kind)} +
                    ":layer_" +
                    std::to_string(expected.layer_ordinal) +
                    ":expected_root_null");
        }
        const ParentExportPinV1* pin = FindExportPin(
            export_pins, expected.kind,
            expected.layer_ordinal);
        if (pin == nullptr) {
            return Fail(
                why,
                std::string{TerminalKindNameV1(expected.kind)} +
                    ":layer_" +
                    std::to_string(expected.layer_ordinal) +
                    ":export_pin_missing");
        }
        ParentTerminalJoinV1 join;
        if (!AppendTerminalJoin(
                parent_cs, parent_columns, expected.kind,
                expected.layer_ordinal,
                expected.export_vector_root_alg, *pin, join,
                why)) {
            return false;
        }
        if (JoinConstrained(join)) {
            ++out.terminals_constrained;
        }
        out.joins.push_back(std::move(join));
    }

    out.all_terminals_constrained =
        out.terminals_required > 0 &&
        out.terminals_constrained == out.terminals_required &&
        out.joins.size() == out.terminals_required;
    out.certificate_commitment =
        ComputeParentRoleExportEqualityCertificateCommitmentV1(
            out);
    if (!out.all_terminals_constrained ||
        out.certificate_commitment.IsNull()) {
        return Fail(why, "attach_incomplete");
    }
    out.note =
        "stage3:normalized_parent_external_producer_equality:"
        "parent_role_export_equality_attached";
    if (why != nullptr) {
        *why = out.note;
    }
    return true;
}

bool AttachParentRoleExportEqualityV1(
    AirCS& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    const std::vector<ParentExportPinV1>& export_pins,
    ParentRoleExportEqualityCertificateV1& out,
    std::string* why)
{
    out = {};
    std::string verify_why;
    if (!streaming::VerifyStreamingEpisodeClosureReceiptV1(
            receipt, &verify_why) ||
        receipt.production_authority ||
        !receipt.every_gemm_child_verified ||
        receipt.receipt_commitment.IsNull()) {
        return Fail(
            why, "attach_receipt_invalid:" + verify_why);
    }
    std::vector<ParentExportPinV1> expected;
    expected.reserve(receipt.layers.size() * 3U);
    for (const auto& layer : receipt.layers) {
        const auto& closure = layer.closure;
        const std::array<
            std::pair<TerminalKindV1, uint256>, 3>
            terminals = {{
                {TerminalKindV1::OperandA,
                 closure.operand_a_vector_root_alg},
                {TerminalKindV1::OperandB,
                 closure.operand_b_vector_root_alg},
                {TerminalKindV1::OutputY,
                 closure.output_y_vector_root_alg},
            }};
        for (const auto& [kind, root] : terminals) {
            if (!StreamingLayerTerminalOk(layer, root)) {
                return Fail(
                    why,
                    std::string{TerminalKindNameV1(kind)} +
                        ":layer_" +
                        std::to_string(layer.layer_ordinal) +
                        ":streaming_terminal_unready");
            }
            ParentExportPinV1 pin;
            pin.kind = kind;
            pin.layer_ordinal = layer.layer_ordinal;
            pin.export_vector_root_alg = root;
            expected.push_back(pin);
        }
    }
    return AttachParentRoleExportEqualityTerminalsV1(
        parent_cs, parent_columns,
        receipt.receipt_commitment, expected, export_pins,
        out, why);
}

bool VerifyParentRoleExportEqualityCertificateV1(
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    const ParentRoleExportEqualityCertificateV1& certificate,
    std::string* why)
{
    std::string verify_why;
    if (!StreamingReceiptRoleExportPremisesV1(
            receipt, &verify_why)) {
        return Fail(
            why,
            "verify_certificate_receipt_invalid:" +
                verify_why);
    }
    if (certificate.version != kCertificateVersionV1 ||
        certificate.streaming_receipt_commitment !=
            receipt.receipt_commitment ||
        certificate.certificate_commitment !=
            ComputeParentRoleExportEqualityCertificateCommitmentV1(
                certificate) ||
        certificate.certificate_commitment.IsNull() ||
        !certificate.all_terminals_constrained ||
        certificate.terminals_required == 0 ||
        certificate.terminals_constrained !=
            certificate.terminals_required ||
        certificate.joins.size() !=
            certificate.terminals_required ||
        certificate.terminals_required !=
            receipt.layers.size() * 3U) {
        return Fail(why, "verify_certificate_statement");
    }

    size_t join_index = 0;
    for (const auto& layer : receipt.layers) {
        const auto& closure = layer.closure;
        const std::array<
            std::pair<TerminalKindV1, uint256>, 3>
            terminals = {{
                {TerminalKindV1::OperandA,
                 closure.operand_a_vector_root_alg},
                {TerminalKindV1::OperandB,
                 closure.operand_b_vector_root_alg},
                {TerminalKindV1::OutputY,
                 closure.output_y_vector_root_alg},
            }};
        for (const auto& [kind, root] : terminals) {
            if (join_index >= certificate.joins.size()) {
                return Fail(why, "verify_certificate_join_count");
            }
            const auto& join = certificate.joins[join_index++];
            if (join.kind != kind ||
                join.layer_ordinal != layer.layer_ordinal ||
                join.expected_vector_root_alg != root ||
                join.export_vector_root_alg != root ||
                !StreamingLayerTerminalOk(layer, root) ||
                !JoinConstrained(join)) {
                return Fail(
                    why,
                    std::string{TerminalKindNameV1(kind)} +
                        ":layer_" +
                        std::to_string(layer.layer_ordinal) +
                        ":verify_join");
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:normalized_parent_external_producer_equality:"
            "parent_certificate_verified";
    }
    return true;
}

AssessmentV1 AssessStreamingRoleExportEqualityV1(
    const streaming::StreamingEpisodeClosureReceiptV1* receipt,
    const ParentRoleExportEqualityCertificateV1* parent_certificate,
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
    // Assess binds certificate joins to receipt commitments + terminal flags.
    // Full FRI replay remains on Attach/VerifyStreamingEpisodeClosureReceiptV1.
    if (!StreamingReceiptRoleExportPremisesV1(
            *receipt, &verify_why)) {
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

    const bool certificate_ok =
        parent_certificate != nullptr &&
        VerifyParentRoleExportEqualityCertificateV1(
            *receipt, *parent_certificate, &verify_why);
    out.parent_certificate_present =
        parent_certificate != nullptr;
    out.parent_certificate_verified = certificate_ok;

    out.terminals.reserve(out.layer_count * 3U);
    for (const auto& layer : receipt->layers) {
        const auto& closure = layer.closure;
        const bool streaming_ok_base =
            layer.retained_commitment ==
                streaming::
                    ComputeStreamedLayerClosureCommitmentV1(
                        layer) &&
            closure.proof_owned_terminal_cancellation &&
            closure.all_children_proof_verified &&
            !closure.production_authority &&
            // Streaming local closure must remain fail-closed on
            // parent attachment claims.
            !closure.role_export_equality_constrained;

        const auto role_export_for =
            [&](TerminalKindV1 kind,
                uint32_t layer_ordinal) {
                if (!certificate_ok ||
                    parent_certificate == nullptr) {
                    return false;
                }
                for (const auto& join :
                     parent_certificate->joins) {
                    if (join.kind == kind &&
                        join.layer_ordinal ==
                            layer_ordinal &&
                        JoinConstrained(join)) {
                        return true;
                    }
                }
                return false;
            };

        out.terminals.push_back(MakeTerminal(
            TerminalKindV1::OperandA,
            layer.layer_ordinal,
            closure.operand_a_vector_root_alg,
            streaming_ok_base &&
                !closure.operand_a_vector_root_alg.IsNull(),
            role_export_for(
                TerminalKindV1::OperandA,
                layer.layer_ordinal)));
        out.terminals.push_back(MakeTerminal(
            TerminalKindV1::OperandB,
            layer.layer_ordinal,
            closure.operand_b_vector_root_alg,
            streaming_ok_base &&
                !closure.operand_b_vector_root_alg.IsNull(),
            role_export_for(
                TerminalKindV1::OperandB,
                layer.layer_ordinal)));
        out.terminals.push_back(MakeTerminal(
            TerminalKindV1::OutputY,
            layer.layer_ordinal,
            closure.output_y_vector_root_alg,
            streaming_ok_base &&
                !closure.output_y_vector_root_alg.IsNull(),
            role_export_for(
                TerminalKindV1::OutputY,
                layer.layer_ordinal)));
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
    if (parent_certificate == nullptr) {
        out.residuals.push_back(
            "parent_role_export_equality_certificate_missing");
    } else if (!certificate_ok) {
        out.residuals.push_back(
            "parent_role_export_equality_certificate_invalid:" +
            verify_why);
    }

    out.all_streaming_children_verified =
        out.terminals_required > 0 &&
        out.terminals_streaming_verified ==
            out.terminals_required;
    out.all_role_export_equality_constrained =
        out.terminals_required > 0 &&
        out.terminals_role_export_joined ==
            out.terminals_required &&
        certificate_ok;
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
