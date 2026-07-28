// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_authority_composition.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>

namespace matmul::v4::rc::normalized_authority {
namespace {

constexpr char kOuterStatementDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_OUTER_STATEMENT_V3";
constexpr char kOuterRoleSectionDomainV3[] =
    "BTX_RC_STAGE3_NORMALIZED_AUTHORITY_OUTER_ROLE_SECTION_V3";

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_authority_composition_v3:" +
            detail;
    }
    return false;
}

uint256 OuterRoleSectionDigestV3(
    const RCStage3ProofSection& section)
{
    HashWriter hash;
    hash << kOuterRoleSectionDomainV3;
    hash << kReceiptVersionV3;
    hash << static_cast<uint16_t>(section.role);
    hash << static_cast<uint64_t>(section.proof.size());
    hash << section.proof;
    return hash.GetHash();
}

bool CanonicalOuterPrefix(
    const RCStage3SuccinctProof& proof)
{
    if (proof.magic != kRCStage3ProofMagic ||
        proof.version != kRCStage3ProofVersion ||
        proof.authority != RCProofAuthority::SuccinctV1 ||
        proof.statement != RCStage3StatementKind::Composed) {
        return false;
    }
    const auto required =
        RequiredRCStage3RelationRoles(
            RCStage3StatementKind::Composed);
    if (required.size() !=
            static_cast<size_t>(kRoleCountV3) + 1 ||
        proof.commitments.size() != required.size() ||
        proof.sections.size() != required.size() ||
        required.back() !=
            RCStage3RelationRole::CompositionLink) {
        return false;
    }
    for (size_t index = 0; index < required.size(); ++index) {
        if (proof.commitments[index].role !=
                required[index] ||
            proof.sections[index].role !=
                required[index]) {
            return false;
        }
        if (index < kRoleCountV3 &&
            (proof.commitments[index].root.IsNull() ||
             proof.sections[index].proof.empty())) {
            return false;
        }
    }
    return true;
}

} // namespace

uint256 ComputeOuterStatementRootV3(
    const RCStage3SuccinctProof& proof)
{
    if (!CanonicalOuterPrefix(proof)) return {};

    HashWriter hash;
    hash << kOuterStatementDomainV3;
    hash << kReceiptVersionV3;
    hash << proof.magic;
    hash << proof.version;
    hash << static_cast<uint8_t>(proof.authority);
    hash << static_cast<uint8_t>(proof.statement);

    const auto& public_inputs = proof.public_inputs;
    hash << public_inputs.height;
    hash << public_inputs.n_bits;
    hash << public_inputs.episode_profile;
    hash << public_inputs.coupled_profile;
    hash << public_inputs.transcript_version;
    hash << public_inputs.program_consensus_pin.version;
    hash << public_inputs.program_consensus_pin
                .recursive_alg_hash_root;
    hash << public_inputs.program_consensus_pin
                .external_sha256d_audit_root;
    hash << public_inputs.program_consensus_pin
                .registry_binding;
    hash << public_inputs.header_commitment;
    hash << public_inputs.params_commitment;
    hash << public_inputs.target;
    hash << public_inputs.sigma;
    hash << public_inputs.episode_digest;
    hash << public_inputs.coupled_digest;
    hash << public_inputs.final_digest;

    hash << kRoleCountV3;
    for (size_t index = 0;
         index < kRoleCountV3;
         ++index) {
        hash << static_cast<uint16_t>(
            proof.commitments[index].role);
        hash << proof.commitments[index].root;
        hash << OuterRoleSectionDigestV3(
            proof.sections[index]);
    }
    return hash.GetHash();
}

bool DecodeAndBindCompositionLinkV3(
    const RCStage3SuccinctProof& proof,
    BoundCompositionLinkV3& out,
    std::string* why)
{
    out = {};
    std::string composition_why;
    if (!VerifyRCStage3CompositionLink(
            proof, &composition_why)) {
        return Fail(
            why, "outer_composition:" +
                     composition_why);
    }
    if (!CanonicalOuterPrefix(proof)) {
        return Fail(why, "outer_role_order");
    }
    const size_t link_index = kRoleCountV3;
    if (proof.commitments[link_index].role !=
            RCStage3RelationRole::CompositionLink ||
        proof.sections[link_index].role !=
            RCStage3RelationRole::CompositionLink) {
        return Fail(why, "composition_link_role");
    }

    std::string decode_why;
    const auto receipt =
        DeserializeNormalizedAuthorityReceiptV3(
            proof.sections[link_index].proof,
            &decode_why);
    if (!receipt.has_value()) {
        return Fail(
            why, "receipt:" + decode_why);
    }
    if (proof.commitments[link_index].root !=
            receipt->receipt_root) {
        return Fail(why, "receipt_commitment");
    }
    if (receipt->program_registry_root !=
        proof.public_inputs.program_consensus_pin
            .recursive_alg_hash_root) {
        return Fail(why, "program_registry_root");
    }
    const uint256 outer_root =
        ComputeOuterStatementRootV3(proof);
    if (outer_root.IsNull() ||
        receipt->outer_statement_root != outer_root) {
        return Fail(why, "outer_statement_root");
    }
    if (receipt->roles.size() != kRoleCountV3) {
        return Fail(why, "receipt_role_count");
    }
    for (size_t index = 0;
         index < receipt->roles.size();
         ++index) {
        if (receipt->roles[index].role !=
                proof.commitments[index].role ||
            receipt->roles[index]
                    .relation_statement_root !=
                proof.commitments[index].root) {
            return Fail(why, "outer_role_commitment");
        }
    }

    out.receipt = *receipt;
    out.outer_statement_root = outer_root;
    if (why != nullptr) {
        *why =
            "stage3:normalized_authority_composition_v3:"
            "outer_bound_parent_cs_verify_required";
    }
    return true;
}

} // namespace matmul::v4::rc::normalized_authority
