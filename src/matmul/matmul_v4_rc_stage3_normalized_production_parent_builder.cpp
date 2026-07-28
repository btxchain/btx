// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_normalized_production_parent_builder.h>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <primitives/block.h>

namespace matmul::v4::rc::normalized_production_parent_builder {
namespace {

void Note(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:normalized_production_parent_builder:" +
            detail;
    }
}

} // namespace

const char* ProductionParentBuildStatusNameV1(
    ProductionParentBuildStatusV1 status)
{
    switch (status) {
    case ProductionParentBuildStatusV1::NotRequired:
        return "not_required";
    case ProductionParentBuildStatusV1::InvalidRequest:
        return "invalid_request";
    case ProductionParentBuildStatusV1::UnsupportedStatement:
        return "unsupported_statement";
    case ProductionParentBuildStatusV1::ProgramRegistryUnavailable:
        return "program_registry_unavailable";
    case ProductionParentBuildStatusV1::CompleteRelationParentUnavailable:
        return "complete_relation_parent_unavailable";
    case ProductionParentBuildStatusV1::Built:
        return "built";
    }
    return "unknown";
}

ProductionParentBuildStatusV1 BuildForSolvedBlockV1(
    const ProductionParentBuildInputV1& input,
    consumer::CanonicalRelationParentProductV1& out,
    std::string* why)
{
    out = {};
    if (input.version != kProductionParentBuildInputVersionV1 ||
        input.solved_block == nullptr ||
        input.params == nullptr ||
        input.height < 0 ||
        input.target.IsNull()) {
        Note(why, "request");
        return ProductionParentBuildStatusV1::InvalidRequest;
    }
    const auto statement =
        RequiredRCStage3Statement(*input.params, input.height);
    if (!statement.has_value()) {
        Note(why, "not_required");
        return ProductionParentBuildStatusV1::NotRequired;
    }
    if (*statement != RCStage3StatementKind::Composed) {
        Note(
            why,
            "complete_normalized_parent_requires_composed_"
            "episode_and_coupled_statement");
        return ProductionParentBuildStatusV1::UnsupportedStatement;
    }
    ProductionProgramConsensusPinV1 registry_pin;
    registry_pin.recursive_alg_hash_root =
        input.params->hashMatMulRCStage3ProgramRegistryAlgRoot;
    registry_pin.external_sha256d_audit_root =
        input.params->hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    registry_pin.registry_binding =
        input.params->hashMatMulRCStage3ProgramRegistryBinding;
    std::string pin_why;
    if (!ValidateProductionProgramConsensusPinV1(
            registry_pin, &pin_why)) {
        Note(why, "program_registry:" + pin_why);
        return ProductionParentBuildStatusV1::
            ProgramRegistryUnavailable;
    }

    // Deliberately no structural stub.  The typed output can only be
    // materialized when the block witness assembler supplies the complete
    // fourteen-role parent CS/columns, its retained R0 session, and verifier-
    // rebuilt NAV3 public inventory.  Returning an empty "valid" product here
    // would turn a provider integration milestone into an authority bypass.
    (void)input.episode_rounds;
    Note(
        why,
        "complete_episode_coupled_relation_parent_assembler_open");
    return ProductionParentBuildStatusV1::
        CompleteRelationParentUnavailable;
}

} // namespace matmul::v4::rc::normalized_production_parent_builder
