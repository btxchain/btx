// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_semantic_endpoint_program_bridge.h>

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::semantic_endpoint_program_bridge {
namespace {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;
namespace topo = universal_topology;

constexpr char kBridgeDomain[] =
    "BTX_RC_STAGE3_SEMANTIC_ENDPOINT_PROGRAM_BRIDGE_V1";
constexpr char kBridgeAirSeedDomain[] =
    "BTX_RC_STAGE3_SEMANTIC_ENDPOINT_PROGRAM_BRIDGE_AIR_SEED_V1";

bool Fail(std::string* why, const std::string& reason)
{
    if (why != nullptr) {
        *why =
            "stage3:semantic_endpoint_program_bridge:" + reason;
    }
    return false;
}

template <size_t N>
void HashWords(HashWriter& hash, const std::array<uint32_t, N>& words)
{
    for (uint32_t word : words) hash << word;
}

std::array<uint32_t, kSemanticEndpointProgramBridgeDigestWordsV1>
Uint256Words(const uint256& value)
{
    std::array<
        uint32_t,
        kSemanticEndpointProgramBridgeDigestWordsV1> out{};
    for (uint32_t word = 0; word < out.size(); ++word) {
        const uint32_t offset = 4U * word;
        out[word] =
            static_cast<uint32_t>(value.begin()[offset]) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 1]) << 8) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 2]) << 16) |
            (static_cast<uint32_t>(
                 value.begin()[offset + 3]) << 24);
    }
    return out;
}

std::array<uint32_t, kSemanticEndpointProgramBridgeDigestWordsV1>
AlgDigestWords(const alg_hash::Digest& value)
{
    std::array<
        uint32_t,
        kSemanticEndpointProgramBridgeDigestWordsV1> out{};
    for (uint32_t lane = 0; lane < value.size(); ++lane) {
        const uint64_t canonical =
            static_cast<uint64_t>(gf::Canonical(value[lane]));
        out[2U * lane] =
            static_cast<uint32_t>(canonical);
        out[2U * lane + 1U] =
            static_cast<uint32_t>(canonical >> 32);
    }
    return out;
}

const topo::ProductionFamilyProgramSourceV1* FindFamily(
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    sites::ProductionProofSiteKind kind,
    RCStage3RelationRole role,
    bool& duplicate)
{
    duplicate = false;
    const topo::ProductionFamilyProgramSourceV1* found = nullptr;
    for (const auto& source : sources) {
        if (source.kind != kind || source.role != role) {
            continue;
        }
        if (found != nullptr) {
            duplicate = true;
            return nullptr;
        }
        found = &source;
    }
    return found;
}

const RCStage3RelationEndpointCellAudit* FindCell(
    const std::vector<RCStage3RelationEndpointCellAudit>& cells,
    RCStage3RelationEndpoint endpoint)
{
    const auto found = std::find_if(
        cells.begin(), cells.end(),
        [endpoint](
            const RCStage3RelationEndpointCellAudit& cell) {
            return cell.endpoint == endpoint;
        });
    return found == cells.end() ? nullptr : &*found;
}

struct OutputRecipe {
    RCStage3RelationEndpoint endpoint;
    uint32_t column;
    const char* source;
};

struct FamilyRecipe {
    sites::ProductionProofSiteKind kind;
    RCStage3RelationRole role;
    std::vector<OutputRecipe> outputs;
    cb::ProgramTable canonical;
    bool canonical_built{false};
};

FamilyRecipe MakeRecipe(
    sites::ProductionProofSiteKind kind,
    RCStage3RelationRole role,
    std::vector<OutputRecipe> outputs)
{
    FamilyRecipe out{kind, role, std::move(outputs), {}, false};
    std::string why;
    out.canonical_built =
        topo::BuildCanonicalProductionFamilyProgramTableV1(
            kind, role, out.canonical, &why);
    out.canonical_built =
        out.canonical_built &&
        out.canonical.role == role &&
        cb::ValidateProgramTable(out.canonical, &why);
    return out;
}

std::vector<FamilyRecipe> CanonicalOutputRecipes()
{
    using namespace coupled_air_col;
    return {
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeBuilderCounterXof,
            RCStage3RelationRole::EpisodeDeterministicBuilder,
            {
                {RCStage3RelationEndpoint::EpisodeBuilderParams,
                 topo::production_family_col_v1::
                     EpisodeBuilderParams,
                 "episode_builder_params:VECTOR_EXPORT"},
                {RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
                 topo::production_family_col_v1::
                     EpisodeBuilderSeedChain,
                 "episode_builder_seed_chain:VECTOR_EXPORT"},
                {RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
                 topo::production_family_col_v1::
                     EpisodeBuilderOperandXof,
                 "episode_builder_operand_xof:VECTOR_EXPORT"},
                {RCStage3RelationEndpoint::EpisodeBuilderTrace,
                 topo::production_family_col_v1::
                     EpisodeBuilderTrace,
                 "episode_builder:DEQUANT_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeGemmSumcheck,
            RCStage3RelationRole::EpisodeGemm,
            {
                {RCStage3RelationEndpoint::EpisodeGemmOperandA,
                 1, "episode_gemm:GEMM_A"},
                {RCStage3RelationEndpoint::EpisodeGemmOperandB,
                 2, "episode_gemm:GEMM_B"},
                {RCStage3RelationEndpoint::EpisodeGemmOutputY,
                 0, "episode_gemm:GEMM_GF"},
                {RCStage3RelationEndpoint::EpisodeGemmSumcheck,
                 0, "episode_gemm:SUMCHECK_TERMINAL_GF"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeSignedRange,
            RCStage3RelationRole::EpisodeGemm,
            {
                {RCStage3RelationEndpoint::EpisodeGemmSignedRange,
                 kRCStage3RangeValue,
                 "episode_gemm_signed_range:VALUE"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeExtractCore,
            RCStage3RelationRole::EpisodeExtract,
            {
                {RCStage3RelationEndpoint::EpisodeExtractInput,
                 air_quotient::kColUMix,
                 "episode_extract:U_MIX"},
                {RCStage3RelationEndpoint::EpisodeExtractSampler,
                 air_quotient::kColMixed,
                 "episode_extract:MIXED"},
                {RCStage3RelationEndpoint::EpisodeExtractScale,
                 air_quotient::kColE0,
                 "episode_extract:E0"},
                {RCStage3RelationEndpoint::EpisodeExtractOutput,
                 air_quotient::kColOut,
                 "episode_extract:OUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeExtractChaCha,
            RCStage3RelationRole::EpisodeExtract,
            {
                {RCStage3RelationEndpoint::EpisodeExtractChaCha,
                 kRCStage3HashKernelOutputColumnV1,
                 "episode_extract_chacha:FIXED_PROGRAM_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeWiring,
            RCStage3RelationRole::EpisodeWiring,
            {
                {RCStage3RelationEndpoint::EpisodeWiringCopy,
                 topo::production_family_col_v1::
                     EpisodeWiringCopy,
                 "episode_wiring:U"},
                {RCStage3RelationEndpoint::EpisodeWiringTranspose,
                 topo::production_family_col_v1::
                     EpisodeWiringTranspose,
                 "episode_wiring_transpose:DESTINATION_VALUE"},
                {RCStage3RelationEndpoint::EpisodeWiringResidual,
                 topo::production_family_col_v1::
                     EpisodeWiringResidual,
                 "episode_wiring_residual:EXTRACT_INPUT"},
                {RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
                 topo::production_family_col_v1::
                     EpisodeWiringRoundOrder,
                 "episode_wiring_round_order:CONSUMER"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeTileTreeSha256d,
            RCStage3RelationRole::EpisodeTileTree,
            {
                {RCStage3RelationEndpoint::EpisodeTileTreeStream,
                 topo::production_family_col_v1::
                     EpisodeTileTreeStream,
                 "episode_tile_tree:BYTE_BRIDGE_EXPORT"},
                {RCStage3RelationEndpoint::EpisodeTileTreeLeafHash,
                 topo::production_family_col_v1::
                     EpisodeTileTreeHash,
                 "episode_tile_tree_leaf:FIXED_PROGRAM_OUTPUT"},
                {RCStage3RelationEndpoint::EpisodeTileTreeInternalHash,
                 topo::production_family_col_v1::
                     EpisodeTileTreeHash,
                 "episode_tile_tree_internal:FIXED_PROGRAM_OUTPUT"},
                {RCStage3RelationEndpoint::EpisodeTileTreeRoot,
                 topo::production_family_col_v1::
                     EpisodeTileTreeHash,
                 "episode_tile_tree_root:FIXED_PROGRAM_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::EpisodeDigestSha256d,
            RCStage3RelationRole::EpisodeDigest,
            {
                {RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
                 topo::production_family_col_v1::
                     EpisodeDigestRoundRoots,
                 "episode_digest_round_roots:ROOT_EXPORT"},
                {RCStage3RelationEndpoint::EpisodeDigestValue,
                 topo::production_family_col_v1::
                     EpisodeDigestValue,
                 "episode_digest_value:FIXED_PROGRAM_OUTPUT"},
                {RCStage3RelationEndpoint::EpisodeDigestHeaderTarget,
                 topo::production_family_col_v1::
                     EpisodeDigestHeaderTarget,
                 "episode_digest_target:TARGET_BYTE"},
                {RCStage3RelationEndpoint::EpisodeDigestPow,
                 topo::production_family_col_v1::
                     EpisodeDigestPow,
                 "episode_digest_pow:DIGEST_BYTE"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledBank,
            RCStage3RelationRole::CoupledBank,
            {
                {RCStage3RelationEndpoint::CoupledBankPages,
                 BANK_NIB, "coupled_bank:NIB"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledBankCounterXof,
            RCStage3RelationRole::CoupledBank,
            {
                {RCStage3RelationEndpoint::CoupledBankSeedXof,
                 kRCStage3HashKernelOutputColumnV1,
                 "coupled_bank_seed_xof:FIXED_PROGRAM_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledBankCommitmentSha256d,
            RCStage3RelationRole::CoupledBank,
            {
                {RCStage3RelationEndpoint::CoupledBankRoot,
                 kRCStage3HashKernelOutputColumnV1,
                 "coupled_bank_root:FIXED_PROGRAM_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledGemm,
            RCStage3RelationRole::CoupledGemm,
            {
                {RCStage3RelationEndpoint::CoupledGemmOperandA,
                 GEMM_A, "coupled_gemm:A"},
                {RCStage3RelationEndpoint::CoupledGemmOperandB,
                 GEMM_B, "coupled_gemm:B"},
                {RCStage3RelationEndpoint::CoupledGemmOutputY,
                 GEMM_OUT, "coupled_gemm:OUT"},
                {RCStage3RelationEndpoint::CoupledGemmSignedRange,
                 topo::production_family_col_v1::
                     CoupledGemmSignedRange,
                 "coupled_gemm_signed_range:VALUE"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledExchange,
            RCStage3RelationRole::CoupledExchange,
            {
                {RCStage3RelationEndpoint::CoupledExchangeInput,
                 COPY_INPUT, "coupled_exchange:INPUT"},
                {RCStage3RelationEndpoint::CoupledExchangeOutput,
                 COPY_OUTPUT, "coupled_exchange:OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledExchangeXof,
            RCStage3RelationRole::CoupledExchange,
            {
                {RCStage3RelationEndpoint::CoupledExchangeHashXof,
                 kRCStage3HashKernelOutputColumnV1,
                 "coupled_exchange_xof:FIXED_PROGRAM_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledPermutation,
            RCStage3RelationRole::CoupledPermutation,
            {
                {RCStage3RelationEndpoint::CoupledPermutationInput,
                 COPY_INPUT, "coupled_permutation:INPUT"},
                {RCStage3RelationEndpoint::CoupledPermutationOutput,
                 COPY_OUTPUT, "coupled_permutation:OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledMix,
            RCStage3RelationRole::CoupledMix,
            {
                {RCStage3RelationEndpoint::CoupledMixInput,
                 MIX_A_LIMB, "coupled_mix:A_LIMB0"},
                {RCStage3RelationEndpoint::CoupledMixArithmetic,
                 MIX_SUM_LIMB, "coupled_mix:SUM_LIMB0"},
                {RCStage3RelationEndpoint::CoupledMixOutput,
                 MIX_DIFF_LIMB, "coupled_mix:DIFF_LIMB0"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledExtractCore,
            RCStage3RelationRole::CoupledExtract,
            {
                {RCStage3RelationEndpoint::CoupledExtractInput,
                 air_quotient::kColUMix,
                 "coupled_extract:U_MIX"},
                {RCStage3RelationEndpoint::CoupledExtractSampler,
                 air_quotient::kColMixed,
                 "coupled_extract:MIXED"},
                {RCStage3RelationEndpoint::CoupledExtractScale,
                 air_quotient::kColE0,
                 "coupled_extract:E0"},
                {RCStage3RelationEndpoint::CoupledExtractOutput,
                 air_quotient::kColOut,
                 "coupled_extract:OUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledExtractChaCha,
            RCStage3RelationRole::CoupledExtract,
            {
                {RCStage3RelationEndpoint::CoupledExtractChaCha,
                 topo::fixed_program_abi_v1::OutputValue,
                 "coupled_extract_chacha:"
                 "FIXED_PROGRAM_PROVENANCE_OUTPUT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledBarrierSha256d,
            RCStage3RelationRole::CoupledBarrier,
            {
                {RCStage3RelationEndpoint::CoupledBarrierInput,
                 topo::production_family_col_v1::
                     CoupledRootInput,
                 "coupled_barrier:ROOT_VALUE"},
                {RCStage3RelationEndpoint::CoupledBarrierHash,
                 topo::production_family_col_v1::
                     CoupledHashOutput,
                 "coupled_barrier:FIXED_PROGRAM_OUTPUT"},
                {RCStage3RelationEndpoint::CoupledBarrierOutput,
                 topo::production_family_col_v1::
                     CoupledRootOutput,
                 "coupled_barrier:ROOT_EXPORT"},
            }),
        MakeRecipe(
            sites::ProductionProofSiteKind::CoupledDigestSha256d,
            RCStage3RelationRole::CoupledDigest,
            {
                {RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
                 topo::production_family_col_v1::
                     CoupledRootInput,
                 "coupled_digest:ROOT_VALUE"},
                {RCStage3RelationEndpoint::CoupledDigestHash,
                 topo::production_family_col_v1::
                     CoupledHashOutput,
                 "coupled_digest:FIXED_PROGRAM_OUTPUT"},
                {RCStage3RelationEndpoint::CoupledDigestValue,
                 topo::production_family_col_v1::
                     CoupledRootOutput,
                 "coupled_digest:ROOT_EXPORT"},
            }),
    };
}

const FamilyRecipe* FindRecipe(
    const std::vector<FamilyRecipe>& recipes,
    RCStage3RelationEndpoint endpoint,
    const OutputRecipe*& output,
    bool& duplicate)
{
    duplicate = false;
    const FamilyRecipe* found = nullptr;
    output = nullptr;
    for (const auto& recipe : recipes) {
        for (const auto& candidate : recipe.outputs) {
            if (candidate.endpoint != endpoint) continue;
            if (found != nullptr) {
                duplicate = true;
                return nullptr;
            }
            found = &recipe;
            output = &candidate;
        }
    }
    return found;
}

const topo::ProductionFamilyProgramSourceV1* FindSemanticClaim(
    const std::vector<topo::ProductionFamilyProgramSourceV1>& sources,
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role,
    bool& duplicate)
{
    duplicate = false;
    const uint16_t id = static_cast<uint16_t>(endpoint);
    const topo::ProductionFamilyProgramSourceV1* found = nullptr;
    for (const auto& source : sources) {
        if (!source.semantic_relation_complete ||
            source.role != role ||
            std::find(
                source.semantic_endpoints.begin(),
                source.semantic_endpoints.end(),
                id) == source.semantic_endpoints.end()) {
            continue;
        }
        if (found != nullptr) {
            duplicate = true;
            return nullptr;
        }
        found = &source;
    }
    return found;
}

std::string ResidualFor(
    const SemanticEndpointProgramBindingV1& endpoint)
{
    if (!endpoint.selected_program_key) {
        return
            "no selected production family ProgramTable exports this "
            "endpoint";
    }
    if (!endpoint.canonical_output_metadata) {
        return
            "selected canonical ProgramTable is endpoint-keyed but exports "
            "no scalar relation-cell metadata for this endpoint";
    }
    if (!endpoint.executed_relation_cell) {
        return
            "canonical ProgramTable output exists but the live relation "
            "proof exports no immutable endpoint cell";
    }
    if (!endpoint.relation_column_exact) {
        return
            "canonical ProgramTable output column disagrees with the live "
            "relation-cell audit";
    }
    if (!endpoint.same_trace_ctl_alias) {
        return
            "exact relation cell is not equality-constrained to CTL::VALUE "
            "in the same proof";
    }
    return
        "direct ProgramTable-to-relation-cell alias is exact; normalized "
        "recursive child acceptance remains absent";
}

bool RoleOwns(
    RCStage3RelationRole role,
    RCStage3RelationEndpoint endpoint)
{
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    return std::find(
        required.begin(), required.end(), endpoint) != required.end();
}

uint32_t NextPowerOfTwo(uint32_t value)
{
    uint32_t out = 2;
    while (out < value) {
        if (out >
            std::numeric_limits<uint32_t>::max() / 2U) {
            return 0;
        }
        out *= 2U;
    }
    return out;
}

uint32_t StatusBits(
    const SemanticEndpointProgramBindingV1& endpoint)
{
    return
        (static_cast<uint32_t>(
             endpoint.selected_program_key) << 0) |
        (static_cast<uint32_t>(
             endpoint.exact_program_table_match) << 1) |
        (static_cast<uint32_t>(
             endpoint.registry_semantic_claim) << 2) |
        (static_cast<uint32_t>(
             endpoint.canonical_output_metadata) << 3) |
        (static_cast<uint32_t>(
             endpoint.executed_relation_cell) << 4) |
        (static_cast<uint32_t>(
             endpoint.relation_column_exact) << 5) |
        (static_cast<uint32_t>(
             endpoint.same_trace_ctl_alias) << 6) |
        (static_cast<uint32_t>(
             endpoint.direct_alias_ready) << 7) |
        (static_cast<uint32_t>(
             endpoint.recursive_child_accepted) << 8);
}

SemanticEndpointProgramBridgeAirLayoutV1 MakeAirLayout()
{
    SemanticEndpointProgramBridgeAirLayoutV1 out;
    uint32_t column = 0;
    out.claimed_endpoint = column++;
    out.claimed_role = column++;
    out.claimed_ordinal = column++;
    out.claimed_family = column++;
    out.claimed_site_kind = column++;
    out.claimed_relation_column = column++;
    out.claimed_status_bits = column++;
    out.claimed_missing_sources = column++;
    out.claimed_external_base = column;
    column += kSemanticEndpointProgramBridgeDigestWordsV1;
    out.claimed_recursive_base = column;
    column += kSemanticEndpointProgramBridgeDigestWordsV1;

    out.expected_active = column++;
    out.expected_endpoint = column++;
    out.expected_role = column++;
    out.expected_ordinal = column++;
    out.expected_family = column++;
    out.expected_site_kind = column++;
    out.expected_relation_column = column++;
    out.expected_status_bits = column++;
    out.expected_missing_sources = column++;
    out.expected_external_base = column;
    column += kSemanticEndpointProgramBridgeDigestWordsV1;
    out.expected_recursive_base = column;
    column += kSemanticEndpointProgramBridgeDigestWordsV1;
    out.total_columns = column;
    return out;
}

void AddExactColumnConstraint(
    air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    uint32_t claimed,
    uint32_t expected,
    const char* name)
{
    cs.constraints.push_back({
        name,
        air_quotient::AirKind::kEverywhere,
        1,
        [claimed, expected](
            const std::vector<gf::Fp3>& current,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                current[claimed], current[expected]);
        }});
}

} // namespace

SemanticEndpointProgramBridgeManifestV1
BuildSemanticEndpointProgramBridgeManifestV1()
{
    SemanticEndpointProgramBridgeManifestV1 out;
    const sites::ProductionProofSiteManifest site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto sources =
        topo::BuildProductionFamilyProgramSourcesV1(site_manifest);
    const auto cells =
        CurrentRCStage3RelationEndpointCellAudit();
    const auto recipes = CanonicalOutputRecipes();
    std::string why;

    out.production_site_manifest_commitment =
        site_manifest.commitment;
    out.production_sources_canonical =
        sites::ValidateProductionProofSiteManifest(
            site_manifest, &why) &&
        topo::ValidateProductionFamilyProgramSourcesV1(
            site_manifest, sources, &why);
    out.no_duplicate_endpoint_bindings = true;
    out.no_cross_role_bindings = true;
    out.exact_family_order =
        sources.size() ==
        topo::kProductionProgramFamilyCountV1;
    out.families.reserve(sources.size());
    for (uint32_t i = 0; i < sources.size(); ++i) {
        const auto& source = sources[i];
        SemanticProgramFamilyCoverageV1 family;
        family.family_index = source.family_index;
        family.proof_site_kind = source.kind;
        family.role = source.role;
        family.registry_claimed_endpoints =
            static_cast<uint32_t>(
                source.semantic_endpoints.size());
        family.exact_selected_program =
            out.production_sources_canonical &&
            source.family_index == i;
        out.exact_family_order =
            out.exact_family_order &&
            source.family_index == i;
        out.families.push_back(family);
    }

    std::set<uint16_t> seen;
    const auto& roles = RCStage3UnifiedRoleOrder();
    uint32_t ordinal = 0;
    for (const RCStage3RelationRole role : roles) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            SemanticEndpointProgramBindingV1 row;
            row.endpoint = endpoint;
            row.role = role;
            row.endpoint_ordinal = ordinal++;
            const bool inserted =
                seen.insert(static_cast<uint16_t>(endpoint)).second;
            out.no_duplicate_endpoint_bindings =
                out.no_duplicate_endpoint_bindings &&
                inserted;
            out.no_cross_role_bindings =
                out.no_cross_role_bindings &&
                RoleOwns(role, endpoint);

            bool claim_duplicate{false};
            const auto* claimed = FindSemanticClaim(
                sources, endpoint, role, claim_duplicate);
            const OutputRecipe* output = nullptr;
            bool recipe_duplicate{false};
            const FamilyRecipe* recipe = FindRecipe(
                recipes, endpoint, output, recipe_duplicate);

            bool family_duplicate{false};
            const topo::ProductionFamilyProgramSourceV1*
                recipe_source = nullptr;
            if (recipe != nullptr && !recipe_duplicate) {
                recipe_source = FindFamily(
                    sources, recipe->kind, recipe->role,
                    family_duplicate);
            }
            const bool exact_recipe =
                recipe != nullptr &&
                output != nullptr &&
                !recipe_duplicate &&
                !family_duplicate &&
                recipe->canonical_built &&
                recipe_source != nullptr &&
                recipe_source->program == recipe->canonical &&
                recipe_source->role == role &&
                output->column <
                    recipe_source->program.current_width;

            const topo::ProductionFamilyProgramSourceV1* selected =
                exact_recipe ? recipe_source : claimed;
            if (selected != nullptr &&
                !claim_duplicate &&
                selected->role == role) {
                const auto keys =
                    cb::CommitProgramTableForExternalAndRecursiveUse(
                        selected->program);
                row.family_index = selected->family_index;
                row.proof_site_kind = selected->kind;
                row.program_external_sha256d_words =
                    Uint256Words(keys.external_sha256d);
                row.program_recursive_alg_hash_words =
                    AlgDigestWords(keys.recursive_alg_hash);
                row.selected_program_key =
                    keys.same_canonical_serialization;
                row.exact_program_table_match =
                    row.selected_program_key &&
                    (exact_recipe ||
                     (claimed == selected &&
                      selected->semantic_relation_complete));
            }
            row.registry_semantic_claim =
                claimed != nullptr && !claim_duplicate &&
                claimed == selected;

            if (exact_recipe && selected == recipe_source) {
                row.canonical_output_metadata = true;
                row.relation_column = output->column;
                row.source = output->source;
            }

            const auto* cell = FindCell(cells, endpoint);
            row.executed_relation_cell =
                cell != nullptr && cell->relation_air_cell;
            row.same_trace_ctl_alias =
                cell != nullptr && cell->same_trace_ctl_alias;
            row.relation_column_exact =
                row.canonical_output_metadata &&
                row.executed_relation_cell &&
                cell->relation_column == row.relation_column;
            row.direct_alias_ready =
                row.selected_program_key &&
                row.exact_program_table_match &&
                row.canonical_output_metadata &&
                row.executed_relation_cell &&
                row.relation_column_exact &&
                row.same_trace_ctl_alias;
            row.recursive_child_accepted = false;

            if (!row.selected_program_key) {
                row.missing_sources |= MissingSelectedProgramKeyV1;
            }
            if (!row.canonical_output_metadata) {
                row.missing_sources |=
                    MissingCanonicalOutputMetadataV1;
            }
            if (!row.executed_relation_cell) {
                row.missing_sources |=
                    MissingExecutedRelationCellV1;
            }
            if (!row.same_trace_ctl_alias) {
                row.missing_sources |=
                    MissingSameTraceCtlAliasV1;
            }
            row.missing_sources |=
                MissingRecursiveChildAcceptanceV1;
            row.residual = ResidualFor(row);

            out.selected_program_key_endpoints +=
                row.selected_program_key;
            out.registry_semantic_claim_endpoints +=
                row.registry_semantic_claim;
            out.canonical_output_metadata_endpoints +=
                row.canonical_output_metadata;
            out.executed_relation_cell_endpoints +=
                row.executed_relation_cell;
            out.exact_relation_column_endpoints +=
                row.relation_column_exact;
            out.direct_alias_endpoints +=
                row.direct_alias_ready;
            out.recursive_child_accepted_endpoints +=
                row.recursive_child_accepted;
            if (row.selected_program_key) {
                auto& family = out.families[row.family_index];
                family.exact_output_endpoints +=
                    row.canonical_output_metadata;
                family.direct_alias_endpoints +=
                    row.direct_alias_ready;
            }
            out.endpoints.push_back(std::move(row));
        }
    }

    out.exact_endpoint_order =
        out.endpoints.size() ==
            kRCStage3RelationClosureEndpointCount &&
        ordinal == kRCStage3RelationClosureEndpointCount;
    for (const RCStage3RelationRole role : roles) {
        const bool complete = std::all_of(
            out.endpoints.begin(), out.endpoints.end(),
            [role](
                const SemanticEndpointProgramBindingV1& endpoint) {
                return endpoint.role != role ||
                    (endpoint.direct_alias_ready &&
                     endpoint.recursive_child_accepted);
            });
        out.complete_roles += complete;
    }
    out.canonical_u32_commitment = true;
    out.recursive_semantic_closure_complete =
        out.recursive_child_accepted_endpoints ==
            kRCStage3RelationClosureEndpointCount &&
        out.direct_alias_endpoints ==
            kRCStage3RelationClosureEndpointCount;
    out.production_authority =
        out.recursive_semantic_closure_complete &&
        kSemanticEndpointProgramBridgeAuthorityV1;
    out.bridge_commitment =
        ComputeSemanticEndpointProgramBridgeCommitmentV1(out);
    return out;
}

uint256 ComputeSemanticEndpointProgramBridgeCommitmentV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest)
{
    HashWriter hash;
    hash << std::string(kBridgeDomain);
    hash << manifest.version;
    hash << manifest.production_site_manifest_commitment;
    hash << static_cast<uint32_t>(manifest.endpoints.size());
    for (const auto& endpoint : manifest.endpoints) {
        hash << static_cast<uint16_t>(endpoint.endpoint);
        hash << static_cast<uint16_t>(endpoint.role);
        hash << endpoint.endpoint_ordinal;
        hash << endpoint.family_index;
        hash << static_cast<uint8_t>(
            endpoint.proof_site_kind);
        HashWords(
            hash, endpoint.program_external_sha256d_words);
        HashWords(
            hash, endpoint.program_recursive_alg_hash_words);
        hash << endpoint.relation_column;
        hash << static_cast<uint8_t>(
            endpoint.selected_program_key);
        hash << static_cast<uint8_t>(
            endpoint.exact_program_table_match);
        hash << static_cast<uint8_t>(
            endpoint.registry_semantic_claim);
        hash << static_cast<uint8_t>(
            endpoint.canonical_output_metadata);
        hash << static_cast<uint8_t>(
            endpoint.executed_relation_cell);
        hash << static_cast<uint8_t>(
            endpoint.relation_column_exact);
        hash << static_cast<uint8_t>(
            endpoint.same_trace_ctl_alias);
        hash << static_cast<uint8_t>(
            endpoint.direct_alias_ready);
        hash << static_cast<uint8_t>(
            endpoint.recursive_child_accepted);
        hash << endpoint.missing_sources;
        hash << endpoint.source;
        hash << endpoint.residual;
    }
    hash << static_cast<uint32_t>(manifest.families.size());
    for (const auto& family : manifest.families) {
        hash << family.family_index;
        hash << static_cast<uint8_t>(
            family.proof_site_kind);
        hash << static_cast<uint16_t>(family.role);
        hash << family.registry_claimed_endpoints;
        hash << family.exact_output_endpoints;
        hash << family.direct_alias_endpoints;
        hash << static_cast<uint8_t>(
            family.exact_selected_program);
    }
    hash << manifest.selected_program_key_endpoints;
    hash << manifest.registry_semantic_claim_endpoints;
    hash << manifest.canonical_output_metadata_endpoints;
    hash << manifest.executed_relation_cell_endpoints;
    hash << manifest.exact_relation_column_endpoints;
    hash << manifest.direct_alias_endpoints;
    hash << manifest.recursive_child_accepted_endpoints;
    hash << manifest.complete_roles;
    hash << static_cast<uint8_t>(
        manifest.exact_endpoint_order);
    hash << static_cast<uint8_t>(
        manifest.exact_family_order);
    hash << static_cast<uint8_t>(
        manifest.production_sources_canonical);
    hash << static_cast<uint8_t>(
        manifest.no_duplicate_endpoint_bindings);
    hash << static_cast<uint8_t>(
        manifest.no_cross_role_bindings);
    hash << static_cast<uint8_t>(
        manifest.canonical_u32_commitment);
    hash << static_cast<uint8_t>(
        manifest.recursive_semantic_closure_complete);
    hash << static_cast<uint8_t>(
        manifest.production_authority);
    return hash.GetHash();
}

bool ValidateSemanticEndpointProgramBridgeManifestV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest,
    std::string* why)
{
    if (manifest.version !=
            kSemanticEndpointProgramBridgeVersionV1 ||
        manifest.endpoints.size() !=
            kRCStage3RelationClosureEndpointCount ||
        manifest.families.size() !=
            topo::kProductionProgramFamilyCountV1 ||
        manifest.production_site_manifest_commitment.IsNull() ||
        manifest.bridge_commitment.IsNull()) {
        return Fail(why, "shape");
    }
    if (manifest.bridge_commitment !=
        ComputeSemanticEndpointProgramBridgeCommitmentV1(
            manifest)) {
        return Fail(why, "commitment");
    }

    const auto expected =
        BuildSemanticEndpointProgramBridgeManifestV1();
    if (manifest != expected) {
        if (manifest.endpoints != expected.endpoints) {
            return Fail(why, "endpoint_order_or_binding");
        }
        if (manifest.families != expected.families) {
            return Fail(why, "family_order_or_coverage");
        }
        return Fail(why, "derived_status");
    }
    if (!manifest.exact_endpoint_order ||
        !manifest.exact_family_order ||
        !manifest.production_sources_canonical ||
        !manifest.no_duplicate_endpoint_bindings ||
        !manifest.no_cross_role_bindings ||
        !manifest.canonical_u32_commitment ||
        manifest.recursive_semantic_closure_complete ||
        manifest.production_authority) {
        return Fail(why, "fail_closed_status");
    }
    if (why != nullptr) {
        *why =
            "stage3:semantic_endpoint_program_bridge:"
            "canonical_28_direct_aliases_recursive_child_acceptance_open";
    }
    return true;
}

bool DecodeSemanticEndpointProgramCanonicalU32V1(
    const gf::Fp3& cell,
    uint32_t& out,
    std::string* why)
{
    if (cell.c0 >= gf::kP ||
        cell.c1 >= gf::kP ||
        cell.c2 >= gf::kP) {
        return Fail(why, "noncanonical_field_representative");
    }
    if (cell.c1 != 0 || cell.c2 != 0) {
        return Fail(why, "nonzero_extension_coordinate");
    }
    if (cell.c0 > UINT32_MAX) {
        return Fail(why, "u32_overflow");
    }
    out = static_cast<uint32_t>(cell.c0);
    if (why != nullptr) {
        *why =
            "stage3:semantic_endpoint_program_bridge:"
            "canonical_u32";
    }
    return true;
}

uint256 ComputeSemanticEndpointProgramBridgeAirSeedV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest)
{
    HashWriter hash;
    hash << std::string(kBridgeAirSeedDomain);
    hash << manifest.version;
    hash << manifest.production_site_manifest_commitment;
    hash << manifest.bridge_commitment;
    return hash.GetHash();
}

SemanticEndpointProgramBridgeAirV1
BuildSemanticEndpointProgramBridgeAirV1(
    const SemanticEndpointProgramBridgeManifestV1& manifest)
{
    SemanticEndpointProgramBridgeAirV1 out;
    std::string why;
    if (!ValidateSemanticEndpointProgramBridgeManifestV1(
            manifest, &why)) {
        out.note = why;
        return out;
    }
    out.bridge_commitment = manifest.bridge_commitment;
    out.proof_seed =
        ComputeSemanticEndpointProgramBridgeAirSeedV1(
            manifest);
    out.layout = MakeAirLayout();
    out.active_rows =
        static_cast<uint32_t>(manifest.endpoints.size());
    out.cs.n_rows = NextPowerOfTwo(out.active_rows);
    out.cs.n_columns = out.layout.total_columns;
    out.cs.preprocessed_pin_ood = true;
    if (out.cs.n_rows == 0 || out.proof_seed.IsNull()) {
        out.note =
            "stage3:semantic_endpoint_program_bridge:"
            "air_shape_or_seed";
        return out;
    }
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows, gf::Fp3::Zero()));
    const auto put =
        [&out](
            uint32_t column, uint32_t row,
            uint32_t value) {
            out.columns[column][row] =
                gf::Fp3::FromFp(gf::FromU64(value));
        };
    for (uint32_t row = 0;
         row < manifest.endpoints.size(); ++row) {
        const auto& endpoint = manifest.endpoints[row];
        const uint32_t status = StatusBits(endpoint);
        put(
            out.layout.claimed_endpoint, row,
            static_cast<uint16_t>(endpoint.endpoint));
        put(
            out.layout.claimed_role, row,
            static_cast<uint16_t>(endpoint.role));
        put(
            out.layout.claimed_ordinal, row,
            endpoint.endpoint_ordinal);
        put(
            out.layout.claimed_family, row,
            endpoint.family_index);
        put(
            out.layout.claimed_site_kind, row,
            static_cast<uint8_t>(endpoint.proof_site_kind));
        put(
            out.layout.claimed_relation_column, row,
            endpoint.relation_column);
        put(
            out.layout.claimed_status_bits, row, status);
        put(
            out.layout.claimed_missing_sources, row,
            endpoint.missing_sources);

        put(out.layout.expected_active, row, 1);
        put(
            out.layout.expected_endpoint, row,
            static_cast<uint16_t>(endpoint.endpoint));
        put(
            out.layout.expected_role, row,
            static_cast<uint16_t>(endpoint.role));
        put(
            out.layout.expected_ordinal, row,
            endpoint.endpoint_ordinal);
        put(
            out.layout.expected_family, row,
            endpoint.family_index);
        put(
            out.layout.expected_site_kind, row,
            static_cast<uint8_t>(endpoint.proof_site_kind));
        put(
            out.layout.expected_relation_column, row,
            endpoint.relation_column);
        put(
            out.layout.expected_status_bits, row, status);
        put(
            out.layout.expected_missing_sources, row,
            endpoint.missing_sources);
        for (uint32_t word = 0;
             word <
                 kSemanticEndpointProgramBridgeDigestWordsV1;
             ++word) {
            put(
                out.layout.claimed_external_base + word,
                row,
                endpoint
                    .program_external_sha256d_words[word]);
            put(
                out.layout.claimed_recursive_base + word,
                row,
                endpoint
                    .program_recursive_alg_hash_words[word]);
            put(
                out.layout.expected_external_base + word,
                row,
                endpoint
                    .program_external_sha256d_words[word]);
            put(
                out.layout.expected_recursive_base + word,
                row,
                endpoint
                    .program_recursive_alg_hash_words[word]);
        }
    }

    for (uint32_t column =
             out.layout.expected_active;
         column < out.layout.total_columns; ++column) {
        out.cs.preprocessed.push_back(
            {column, out.columns[column]});
    }
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_endpoint,
        out.layout.expected_endpoint,
        "stage3.endpoint_program.endpoint");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_role,
        out.layout.expected_role,
        "stage3.endpoint_program.role");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_ordinal,
        out.layout.expected_ordinal,
        "stage3.endpoint_program.ordinal");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_family,
        out.layout.expected_family,
        "stage3.endpoint_program.family");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_site_kind,
        out.layout.expected_site_kind,
        "stage3.endpoint_program.site_kind");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_relation_column,
        out.layout.expected_relation_column,
        "stage3.endpoint_program.relation_column");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_status_bits,
        out.layout.expected_status_bits,
        "stage3.endpoint_program.status_bits");
    AddExactColumnConstraint(
        out.cs, out.layout.claimed_missing_sources,
        out.layout.expected_missing_sources,
        "stage3.endpoint_program.missing_sources");
    for (uint32_t word = 0;
         word < kSemanticEndpointProgramBridgeDigestWordsV1;
         ++word) {
        AddExactColumnConstraint(
            out.cs,
            out.layout.claimed_external_base + word,
            out.layout.expected_external_base + word,
            "stage3.endpoint_program.external_key");
        AddExactColumnConstraint(
            out.cs,
            out.layout.claimed_recursive_base + word,
            out.layout.expected_recursive_base + word,
            "stage3.endpoint_program.recursive_key");
    }
    out.violations =
        CountSemanticEndpointProgramBridgeAirViolationsV1(
            out.cs, out.columns);
    out.mapping_commitment_bound =
        out.violations == 0 &&
        out.proof_seed ==
            ComputeSemanticEndpointProgramBridgeAirSeedV1(
                manifest);
    out.only_expected_schedule_preprocessed = true;
    out.recursive_child_consumption =
        manifest.recursive_semantic_closure_complete;
    out.production_authority =
        manifest.production_authority;
    out.valid =
        out.mapping_commitment_bound &&
        out.only_expected_schedule_preprocessed &&
        !out.recursive_child_consumption &&
        !out.production_authority;
    out.note =
        out.valid
        ? "stage3:semantic_endpoint_program_bridge:"
          "exact_mapping_air_valid_not_child_authority"
        : "stage3:semantic_endpoint_program_bridge:"
          "mapping_air_invalid";
    return out;
}

uint32_t CountSemanticEndpointProgramBridgeAirViolationsV1(
    const air_quotient::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (cs.n_rows < 2 || columns.size() != cs.n_columns) {
        return UINT32_MAX;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return UINT32_MAX;
    }
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        std::vector<gf::Fp3> current(cs.n_columns);
        std::vector<gf::Fp3> next(cs.n_columns);
        const uint32_t next_row =
            (row + 1U) % cs.n_rows;
        for (uint32_t column = 0;
             column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            bool active = false;
            switch (constraint.kind) {
            case air_quotient::AirKind::kEverywhere:
                active = true;
                break;
            case air_quotient::AirKind::kTransition:
                active = row + 1U < cs.n_rows;
                break;
            case air_quotient::AirKind::kFirstRow:
                active = row == 0;
                break;
            case air_quotient::AirKind::kLastRow:
                active = row + 1U == cs.n_rows;
                break;
            }
            if (active &&
                !gf::IsZero(
                    constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations >
               std::numeric_limits<uint32_t>::max()
        ? UINT32_MAX
        : static_cast<uint32_t>(violations);
}

} // namespace matmul::v4::rc::semantic_endpoint_program_bridge
