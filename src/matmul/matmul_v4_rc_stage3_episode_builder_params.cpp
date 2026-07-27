// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_builder_params.h>

namespace matmul::v4::rc {
namespace {

using gkr_field::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:episode_builder_params:" + detail;
    }
    return false;
}

} // namespace

std::vector<Fp3> CanonicalRCStage3EpisodeBuilderParamValues(
    const RCEpisodeParams& params)
{
    return {
        Fp3::FromFp(params.rounds),
        Fp3::FromFp(params.d_head),
        Fp3::FromFp(params.n_q),
        Fp3::FromFp(params.n_ctx),
        Fp3::FromFp(params.L_lyr),
        Fp3::FromFp(params.d_model),
        Fp3::FromFp(params.d_ff),
        Fp3::FromFp(params.b_seq),
        Fp3::FromFp(params.T_leaf),
    };
}

bool ProveRCStage3EpisodeBuilderParamsProduct(
    const uint256& statement_commitment,
    const RCEpisodeParams& params,
    RCStage3EpisodeBuilderParamsProduct& out,
    std::string* why)
{
    out = {};
    if (statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(params)) {
        return Fail(why, "public_inputs");
    }
    const auto values =
        CanonicalRCStage3EpisodeBuilderParamValues(params);
    const auto root = ComputeRCStage3EpisodeSemanticValueRoot(
        values, kRCStage3EpisodeBuilderParamsCells, 16, why);
    if (!root.has_value()) return false;
    const auto manifest =
        BuildRCStage3EpisodeSemanticMemoryManifest(
            RCStage3RelationEndpoint::EpisodeBuilderParams,
            statement_commitment, kRCStage3EpisodeBuilderParamsCells,
            kRCStage3EpisodeBuilderParamsCells,
            0, 1, *root, why);
    if (!manifest.has_value()) return false;
    out.version = kRCStage3EpisodeBuilderParamsVersion;
    out.memory_manifest = *manifest;
    return ProveRCStage3EpisodeSemanticMemory(
        out.memory_manifest, values, out.memory_proof, why);
}

bool VerifyRCStage3EpisodeBuilderParamsProduct(
    const uint256& expected_statement_commitment,
    const RCEpisodeParams& expected_params,
    const RCStage3EpisodeBuilderParamsProduct& product,
    std::string* why)
{
    if (product.version !=
            kRCStage3EpisodeBuilderParamsVersion ||
        expected_statement_commitment.IsNull() ||
        !ValidateRCEpisodeParams(expected_params)) {
        return Fail(why, "public_inputs_or_version");
    }
    const auto values =
        CanonicalRCStage3EpisodeBuilderParamValues(expected_params);
    const auto expected_root =
        ComputeRCStage3EpisodeSemanticValueRoot(
            values, kRCStage3EpisodeBuilderParamsCells, 16, why);
    if (!expected_root.has_value()) return false;
    const auto& manifest = product.memory_manifest;
    if (manifest.endpoint !=
            RCStage3RelationEndpoint::EpisodeBuilderParams ||
        manifest.role !=
            RCStage3RelationRole::EpisodeDeterministicBuilder ||
        manifest.statement_commitment !=
            expected_statement_commitment ||
        manifest.instance_count !=
            kRCStage3EpisodeBuilderParamsCells ||
        manifest.logical_rows !=
            kRCStage3EpisodeBuilderParamsCells ||
        manifest.n_rows != 16 ||
        manifest.address_begin != 0 ||
        manifest.address_stride != 1 ||
        manifest.canonical_value_root != *expected_root) {
        return Fail(why, "canonical_manifest_or_value_root");
    }
    if (!VerifyRCStage3EpisodeSemanticMemory(
            expected_statement_commitment, manifest,
            product.memory_proof, why)) {
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_builder_params:consensus_params_"
            "equal_proof_owned_value_column";
    }
    return true;
}

RCStage3EpisodeBuilderParamsAudit
CurrentRCStage3EpisodeBuilderParamsAudit()
{
    RCStage3EpisodeBuilderParamsAudit out;
    out.consensus_values_regenerated = true;
    out.exact_ordered_vector_root = true;
    out.proof_owned_value_column = true;
    out.statement_bound = true;
    out.local_relation_complete = true;
    // The expected vector is a verifier-owned public input resolved directly
    // from consensus. It has no unproved computation ancestor.
    out.producer_provenance_complete = true;
    out.semantic_complete =
        out.local_relation_complete &&
        out.producer_provenance_complete;
    out.recursively_consumed =
        kRCStage3EpisodeBuilderParamsRecursivelyConsumed;
    out.remaining =
        "normalized recursive child consumption remains";
    return out;
}

static_assert(
    kRCStage3EpisodeBuilderParamsSemanticProductExecutable);
static_assert(
    !kRCStage3EpisodeBuilderParamsRecursivelyConsumed);

} // namespace matmul::v4::rc
