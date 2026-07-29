// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PARENT_EXTERNAL_PRODUCER_EQUALITY_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PARENT_EXTERNAL_PRODUCER_EQUALITY_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_streaming_episode_closure.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::normalized_parent_external_producer_equality {

namespace streaming = streaming_episode_closure;

inline constexpr uint16_t kVersionV1 = 1;
inline constexpr uint16_t kCertificateVersionV1 = 1;

/**
 * Per-layer A/B/Y producer terminals the normalized parent must equality-
 * constrain against upstream builder / previous-Extract role exports (or
 * parent-hosted export pins that absorb those alg roots into the parent AIR).
 *
 * Streaming layer closures already prove leaf↔producer multiset equality and
 * deliberately keep `LayerClosureV1::role_export_equality_constrained` false
 * so local ingress verification stays fail-closed.  Same-parent attachment is
 * owned by `ParentRoleExportEqualityCertificateV1` below.
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
    bool parent_certificate_present{false};
    bool parent_certificate_verified{false};
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
     * role-export equality is constrained inside the normalized parent
     * certificate.  Remains false while the certificate is missing/invalid.
     */
    bool external_producer_terminal_equality_complete{false};
    std::string note;
};

/**
 * One independently claimed parent-side export root for a streaming terminal.
 *
 * When `has_existing_root_word_columns` is true, Attach reuses those ordinary
 * parent columns (already pinned by the endpoint bank).  Otherwise Attach
 * allocates fresh root-word columns pinned to `export_vector_root_alg`.
 */
struct ParentExportPinV1 {
    TerminalKindV1 kind{TerminalKindV1::OperandA};
    uint32_t layer_ordinal{0};
    uint256 export_vector_root_alg{};
    bool has_existing_root_word_columns{false};
    std::array<uint32_t, 8> existing_root_word_columns{};
};

/**
 * One executed same-parent join between a streaming expected VectorRootAlg and
 * a parent export pin.  `root_words_same_parent_aliased` is true only after
 * first-row equality constraints are appended for all eight root words.
 */
struct ParentTerminalJoinV1 {
    TerminalKindV1 kind{TerminalKindV1::OperandA};
    uint32_t layer_ordinal{0};
    uint256 expected_vector_root_alg{};
    uint256 export_vector_root_alg{};
    std::array<uint32_t, 8> expected_root_word_columns{};
    std::array<uint32_t, 8> export_root_word_columns{};
    bool expected_pinned{false};
    bool export_pinned_or_reused{false};
    bool roots_equal{false};
    bool root_words_same_parent_aliased{false};
};

/**
 * Parent-owned certificate that streaming A/B/Y terminal roots are hosted and
 * equality-constrained inside the normalized parent AIR.  Streaming
 * VerifyLayerClosureV1 continues to reject any claim that local layer closure
 * already performed this attachment.
 */
struct ParentRoleExportEqualityCertificateV1 {
    uint16_t version{kCertificateVersionV1};
    uint256 streaming_receipt_commitment{};
    std::vector<ParentTerminalJoinV1> joins;
    uint32_t terminals_required{0};
    uint32_t terminals_constrained{0};
    bool all_terminals_constrained{false};
    uint256 certificate_commitment{};
    std::string note;
};

[[nodiscard]] const char* TerminalKindNameV1(TerminalKindV1 kind);

[[nodiscard]] RCStage3RelationEndpoint TerminalExportEndpointV1(
    TerminalKindV1 kind);

[[nodiscard]] uint256
ComputeParentRoleExportEqualityCertificateCommitmentV1(
    const ParentRoleExportEqualityCertificateV1& certificate);

/**
 * Build parent export pins that host each streaming terminal root inside the
 * parent AIR.  Premises: receipt verifies and every A/B/Y alg root is present.
 * This is the honest "attach expected roots to the parent" surface when the
 * fourteen-role bank does not yet expose per-layer builder/Extract exports.
 */
[[nodiscard]] bool BuildHostedExportPinsFromStreamingReceiptV1(
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    std::vector<ParentExportPinV1>& out_pins,
    std::string* why = nullptr);

/**
 * Fixture/canary attach: equality-constrain an explicit terminal list (already
 * measured elsewhere) to matching export pins inside `parent_cs`.  Binds the
 * resulting certificate to `streaming_receipt_commitment` so a later Assess
 * against the real receipt can verify the same commitment.
 */
[[nodiscard]] bool AttachParentRoleExportEqualityTerminalsV1(
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& parent_cs,
    std::vector<std::vector<gkr_field::Fp3>>& parent_columns,
    const uint256& streaming_receipt_commitment,
    const std::vector<ParentExportPinV1>& expected_terminals,
    const std::vector<ParentExportPinV1>& export_pins,
    ParentRoleExportEqualityCertificateV1& out,
    std::string* why = nullptr);

/**
 * Append root-word pins and same-parent first-row aliases so each streaming
 * expected VectorRootAlg is equality-constrained to the matching export pin.
 * Fails closed when the receipt is invalid, a pin is missing, or roots differ.
 */
[[nodiscard]] bool AttachParentRoleExportEqualityV1(
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& parent_cs,
    std::vector<std::vector<gkr_field::Fp3>>& parent_columns,
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    const std::vector<ParentExportPinV1>& export_pins,
    ParentRoleExportEqualityCertificateV1& out,
    std::string* why = nullptr);

/**
 * Recompute the certificate commitment and require every required terminal to
 * be roots-equal + same-parent aliased against the supplied receipt.  Uses
 * structural streaming role-export premises (commitment + terminal flags);
 * full FRI replay remains on Attach / VerifyStreamingEpisodeClosureReceiptV1.
 */
[[nodiscard]] bool VerifyParentRoleExportEqualityCertificateV1(
    const streaming::StreamingEpisodeClosureReceiptV1& receipt,
    const ParentRoleExportEqualityCertificateV1& certificate,
    std::string* why = nullptr);

/**
 * Assess streaming role-export premises plus the optional parent-owned
 * certificate.  Structural receipt premises (commitment + A/B/Y terminal
 * flags) gate streaming_verified; without a verified certificate, role-export
 * stays open.  Never flips Ready / authority flags.  Full FRI replay is not
 * re-run here so CI fixtures can close equality_complete without mining.
 */
[[nodiscard]] AssessmentV1 AssessStreamingRoleExportEqualityV1(
    const streaming::StreamingEpisodeClosureReceiptV1* receipt,
    const ParentRoleExportEqualityCertificateV1* parent_certificate =
        nullptr,
    std::string* why = nullptr);

} // namespace matmul::v4::rc::normalized_parent_external_producer_equality

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_NORMALIZED_PARENT_EXTERNAL_PRODUCER_EQUALITY_H
