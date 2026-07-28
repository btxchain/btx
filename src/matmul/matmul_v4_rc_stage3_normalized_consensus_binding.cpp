// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_consensus_binding.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_normalized_block_transport.h>
#include <matmul/matmul_v4_rc_stage3_role_sections.h>
#include <primitives/block.h>

namespace matmul::v4::rc::normalized_consensus_binding {
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_consensus_binding_v3:" +
            detail;
    }
    return false;
}

nav3::ComposedPublicStatementV3 ToNormalized(
    const RCStage3PublicInputs& inputs)
{
    return {
        .height = inputs.height,
        .n_bits = inputs.n_bits,
        .episode_profile = inputs.episode_profile,
        .coupled_profile = inputs.coupled_profile,
        .transcript_version = inputs.transcript_version,
        .program_consensus_pin =
            inputs.program_consensus_pin,
        .header_commitment = inputs.header_commitment,
        .params_commitment = inputs.params_commitment,
        .target = inputs.target,
        .sigma = inputs.sigma,
        .episode_digest = inputs.episode_digest,
        .coupled_digest = inputs.coupled_digest,
        .final_digest = inputs.final_digest,
    };
}

} // namespace

bool RebuildComposedPublicStatementV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    const uint256& episode_digest,
    const uint256& coupled_digest,
    nav3::ComposedPublicStatementV3& out,
    std::string* why)
{
    out = {};
    const auto required =
        RequiredRCStage3Statement(params, height);
    if (!required.has_value() ||
        *required != RCStage3StatementKind::Composed) {
        return Fail(why, "composed_statement_required");
    }
    ProductionProgramConsensusPinV1 pin;
    pin.recursive_alg_hash_root =
        params.hashMatMulRCStage3ProgramRegistryAlgRoot;
    pin.external_sha256d_audit_root =
        params.hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    pin.registry_binding =
        params.hashMatMulRCStage3ProgramRegistryBinding;

    RCStage3SuccinctProof statement;
    std::string statement_why;
    if (!BuildRCStage3StatementForHeader(
            block, params, height,
            RCStage3StatementKind::Composed,
            pin, episode_digest, coupled_digest,
            statement, &statement_why)) {
        return Fail(
            why, "statement:" + statement_why);
    }
    if (statement.public_inputs.target != target) {
        return Fail(why, "target");
    }
    if (statement.public_inputs.final_digest !=
        block.matmul_digest) {
        return Fail(why, "final_digest");
    }
    if (UintToArith256(block.matmul_digest) >
        UintToArith256(target)) {
        return Fail(why, "digest_above_target");
    }
    out = ToNormalized(statement.public_inputs);
    if (why != nullptr) {
        *why =
            "stage3:normalized_consensus_binding_v3:"
            "public_statement_rebuilt";
    }
    return true;
}

bool ValidateDirectReceiptConsensusBindingV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    const nav3::NormalizedAuthorityReceiptV3& receipt,
    DirectReceiptConsensusStatementV3& statement_out,
    std::string* why)
{
    statement_out = {};
    std::string receipt_why;
    if (!nav3::ValidateNormalizedAuthorityReceiptV3(
            receipt, &receipt_why)) {
        return Fail(
            why, "receipt:" + receipt_why);
    }
    if (receipt.outer_binding_kind !=
        nav3::OuterBindingKindV3::
            DirectBlockReceipt) {
        return Fail(why, "not_direct_receipt");
    }

    nav3::ComposedPublicStatementV3 expected;
    if (!RebuildComposedPublicStatementV3(
            block, params, height, target,
            receipt.public_statement.episode_digest,
            receipt.public_statement.coupled_digest,
            expected, why)) {
        return false;
    }
    if (receipt.public_statement != expected) {
        return Fail(why, "public_statement_substitution");
    }
    if (receipt.program_registry_root !=
        expected.program_consensus_pin
            .recursive_alg_hash_root) {
        return Fail(why, "program_registry_root");
    }
    if (receipt.outer_statement_root !=
        nav3::ComputeDirectOuterStatementRootV3(
            expected, receipt.roles)) {
        return Fail(why, "outer_statement_root");
    }

    statement_out.outer_binding_kind =
        nav3::OuterBindingKindV3::DirectBlockReceipt;
    statement_out.public_statement = expected;
    statement_out.expected_program_registry_root =
        expected.program_consensus_pin
            .recursive_alg_hash_root;
    if (why != nullptr) {
        *why =
            "stage3:normalized_consensus_binding_v3:"
            "direct_statement_bound_parent_rebuild_required";
    }
    return true;
}

bool DecodeAndBindAttachedDirectReceiptV3(
    const CBlock& block,
    const Consensus::Params& params,
    int32_t height,
    const uint256& target,
    nav3::NormalizedAuthorityReceiptV3& receipt_out,
    DirectReceiptConsensusStatementV3& statement_out,
    std::string* why)
{
    receipt_out = {};
    statement_out = {};
    std::string unpack_why;
    const auto bytes =
        normalized_block_transport::
            UnpackReceiptWordsV3(
                block.matrix_c_data, &unpack_why);
    if (!bytes.has_value()) {
        return Fail(
            why, "unpack:" + unpack_why);
    }
    std::string decode_why;
    const auto receipt =
        nav3::DeserializeNormalizedAuthorityReceiptV3(
            *bytes, &decode_why);
    if (!receipt.has_value()) {
        return Fail(
            why, "decode:" + decode_why);
    }
    if (!ValidateDirectReceiptConsensusBindingV3(
            block, params, height, target,
            *receipt, statement_out, why)) {
        return false;
    }
    receipt_out = *receipt;
    if (why != nullptr) {
        *why =
            "stage3:normalized_consensus_binding_v3:"
            "attached_direct_receipt_bound_parent_rebuild_required";
    }
    return true;
}

} // namespace matmul::v4::rc::normalized_consensus_binding
