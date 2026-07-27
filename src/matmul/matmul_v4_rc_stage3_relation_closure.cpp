// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_stream_endpoint.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <limits>

namespace matmul::v4::rc {
namespace {

constexpr char ROLE_DOMAIN[] = "BTX_RC_STAGE3_RELATION_ROLE_CLOSURE_V1";
constexpr char CLOSURE_DOMAIN[] = "BTX_RC_STAGE3_RELATION_CLOSURE_V1";
constexpr char DIRECT_ALIAS_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_RELATION_CTL_DIRECT_ALIAS_V1";
constexpr char COUPLED_ENDPOINT_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_ENDPOINT_AIR_V1";

const std::vector<RCStage3RelationEndpoint> EPISODE_BUILDER{
    RCStage3RelationEndpoint::EpisodeBuilderParams,
    RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
    RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
    RCStage3RelationEndpoint::EpisodeBuilderTrace,
};
const std::vector<RCStage3RelationEndpoint> EPISODE_GEMM{
    RCStage3RelationEndpoint::EpisodeGemmOperandA,
    RCStage3RelationEndpoint::EpisodeGemmOperandB,
    RCStage3RelationEndpoint::EpisodeGemmOutputY,
    RCStage3RelationEndpoint::EpisodeGemmSumcheck,
    RCStage3RelationEndpoint::EpisodeGemmSignedRange,
};
const std::vector<RCStage3RelationEndpoint> EPISODE_EXTRACT{
    RCStage3RelationEndpoint::EpisodeExtractInput,
    RCStage3RelationEndpoint::EpisodeExtractSampler,
    RCStage3RelationEndpoint::EpisodeExtractChaCha,
    RCStage3RelationEndpoint::EpisodeExtractScale,
    RCStage3RelationEndpoint::EpisodeExtractOutput,
};
const std::vector<RCStage3RelationEndpoint> EPISODE_WIRING{
    RCStage3RelationEndpoint::EpisodeWiringCopy,
    RCStage3RelationEndpoint::EpisodeWiringTranspose,
    RCStage3RelationEndpoint::EpisodeWiringResidual,
    RCStage3RelationEndpoint::EpisodeWiringRoundOrder,
};
const std::vector<RCStage3RelationEndpoint> EPISODE_TILE_TREE{
    RCStage3RelationEndpoint::EpisodeTileTreeStream,
    RCStage3RelationEndpoint::EpisodeTileTreeLeafHash,
    RCStage3RelationEndpoint::EpisodeTileTreeInternalHash,
    RCStage3RelationEndpoint::EpisodeTileTreeRoot,
};
const std::vector<RCStage3RelationEndpoint> EPISODE_DIGEST{
    RCStage3RelationEndpoint::EpisodeDigestRoundRoots,
    RCStage3RelationEndpoint::EpisodeDigestValue,
    RCStage3RelationEndpoint::EpisodeDigestHeaderTarget,
    RCStage3RelationEndpoint::EpisodeDigestPow,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_BANK{
    RCStage3RelationEndpoint::CoupledBankSeedXof,
    RCStage3RelationEndpoint::CoupledBankPages,
    RCStage3RelationEndpoint::CoupledBankRoot,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_GEMM{
    RCStage3RelationEndpoint::CoupledGemmOperandA,
    RCStage3RelationEndpoint::CoupledGemmOperandB,
    RCStage3RelationEndpoint::CoupledGemmOutputY,
    RCStage3RelationEndpoint::CoupledGemmSignedRange,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_EXCHANGE{
    RCStage3RelationEndpoint::CoupledExchangeInput,
    RCStage3RelationEndpoint::CoupledExchangeHashXof,
    RCStage3RelationEndpoint::CoupledExchangeOutput,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_PERMUTATION{
    RCStage3RelationEndpoint::CoupledPermutationInput,
    RCStage3RelationEndpoint::CoupledPermutationOutput,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_MIX{
    RCStage3RelationEndpoint::CoupledMixInput,
    RCStage3RelationEndpoint::CoupledMixArithmetic,
    RCStage3RelationEndpoint::CoupledMixOutput,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_EXTRACT{
    RCStage3RelationEndpoint::CoupledExtractInput,
    RCStage3RelationEndpoint::CoupledExtractSampler,
    RCStage3RelationEndpoint::CoupledExtractChaCha,
    RCStage3RelationEndpoint::CoupledExtractScale,
    RCStage3RelationEndpoint::CoupledExtractOutput,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_BARRIER{
    RCStage3RelationEndpoint::CoupledBarrierInput,
    RCStage3RelationEndpoint::CoupledBarrierHash,
    RCStage3RelationEndpoint::CoupledBarrierOutput,
};
const std::vector<RCStage3RelationEndpoint> COUPLED_DIGEST{
    RCStage3RelationEndpoint::CoupledDigestBankAndBarriers,
    RCStage3RelationEndpoint::CoupledDigestHash,
    RCStage3RelationEndpoint::CoupledDigestValue,
};
const std::vector<RCStage3RelationEndpoint> EMPTY_ENDPOINTS;

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:relation_closure:" + message;
    return false;
}

const RCStage3RelationEndpointPin* FindEndpoint(
    const RCStage3RelationRoleClosure& role,
    RCStage3RelationEndpoint endpoint)
{
    const auto it = std::find_if(
        role.endpoints.begin(), role.endpoints.end(),
        [endpoint](const RCStage3RelationEndpointPin& pin) {
            return pin.endpoint == endpoint;
        });
    return it == role.endpoints.end() ? nullptr : &*it;
}

void WriteEndpoint(HashWriter& hash, const RCStage3RelationEndpointPin& pin)
{
    hash << static_cast<uint16_t>(pin.endpoint);
    hash << pin.instance_count;
    hash << pin.manifest_root;
    hash << pin.proof_root;
    hash << pin.semantic_root;
    hash << pin.proof_column_root;
    hash << pin.recursive_child_commitment;
}

using Fp3 = gkr_field::Fp3;
using AirCS = air_quotient::AirConstraintSystem<Fp3>;
using AirConstraint = air_quotient::AirConstraint<Fp3>;

bool Canonical(const Fp3& value)
{
    return value.c0 < gkr_field::kP &&
           value.c1 < gkr_field::kP &&
           value.c2 < gkr_field::kP;
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << gkr_field::Canonical(value.c0);
    hash << gkr_field::Canonical(value.c1);
    hash << gkr_field::Canonical(value.c2);
}

std::vector<Fp3> SliceRow(const std::vector<Fp3>& row,
                          uint32_t begin,
                          uint32_t count)
{
    if (begin > row.size() || count > row.size() - begin) return {};
    return std::vector<Fp3>(
        row.begin() + begin, row.begin() + begin + count);
}

void CopyConstraintFamily(const AirCS& source,
                          uint32_t column_offset,
                          AirCS& destination)
{
    for (const auto& constraint : source.constraints) {
        AirConstraint shifted;
        shifted.name = constraint.name;
        shifted.kind = constraint.kind;
        shifted.alg_degree = constraint.alg_degree;
        shifted.eval =
            [eval = constraint.eval,
             column_offset,
             columns = source.n_columns](
                const std::vector<Fp3>& current,
                const std::vector<Fp3>& next) {
                return eval(
                    SliceRow(current, column_offset, columns),
                    SliceRow(next, column_offset, columns));
            };
        destination.constraints.push_back(std::move(shifted));
    }
    for (const auto& [column, values] : source.preprocessed) {
        destination.preprocessed.emplace_back(
            column_offset + column, values);
    }
    for (const auto& [column, root] : source.preprocessed_roots) {
        destination.preprocessed_roots.emplace_back(
            column_offset + column, root);
    }
    // Propagate the OOD-pin flag so the composed C_rho verifies on the row-wise
    // AlgB3 backend (which supports preprocessed_pin_ood, not per-column roots).
    destination.preprocessed_pin_ood =
        destination.preprocessed_pin_ood || source.preprocessed_pin_ood;
}

std::optional<uint32_t> EpisodeEndpointColumn(
    RCStage3RelationEndpoint endpoint,
    RCStage3EpisodeAirFamily family,
    RCStage3RelationRole role)
{
    using Family = RCStage3EpisodeAirFamily;
    using Endpoint = RCStage3RelationEndpoint;
    if (role == RCStage3RelationRole::EpisodeGemm &&
        family == Family::GemmEndpointFp3V1) {
        switch (endpoint) {
        case Endpoint::EpisodeGemmOperandA: return 1;
        case Endpoint::EpisodeGemmOperandB: return 2;
        case Endpoint::EpisodeGemmOutputY: return 0;
        default: return std::nullopt;
        }
    }
    if (role == RCStage3RelationRole::EpisodeExtract &&
        family == Family::ExtractSamplerCoreFp3V1) {
        switch (endpoint) {
        case Endpoint::EpisodeExtractSampler:
            return air_quotient::kColMixed;
        case Endpoint::EpisodeExtractOutput:
            return air_quotient::kColOut;
        default: return std::nullopt;
        }
    }
    if (role == RCStage3RelationRole::EpisodeWiring &&
        family == Family::WiringEqualityFp3V1 &&
        endpoint == Endpoint::EpisodeWiringCopy) {
        return 0;
    }
    return std::nullopt;
}

std::optional<uint32_t> CoupledEndpointColumn(
    RCStage3RelationEndpoint endpoint,
    RCStage3RelationRole role)
{
    using Endpoint = RCStage3RelationEndpoint;
    using namespace coupled_air_col;
    switch (role) {
    case RCStage3RelationRole::CoupledBank:
        if (endpoint == Endpoint::CoupledBankPages) return BANK_NIB;
        break;
    case RCStage3RelationRole::CoupledGemm:
        switch (endpoint) {
        case Endpoint::CoupledGemmOperandA: return GEMM_A;
        case Endpoint::CoupledGemmOperandB: return GEMM_B;
        case Endpoint::CoupledGemmOutputY: return GEMM_OUT;
        default: break;
        }
        break;
    case RCStage3RelationRole::CoupledExchange:
    case RCStage3RelationRole::CoupledPermutation:
        if (endpoint == Endpoint::CoupledExchangeInput ||
            endpoint == Endpoint::CoupledPermutationInput) {
            return COPY_INPUT;
        }
        if (endpoint == Endpoint::CoupledExchangeOutput ||
            endpoint == Endpoint::CoupledPermutationOutput) {
            return COPY_OUTPUT;
        }
        break;
    case RCStage3RelationRole::CoupledMix:
        switch (endpoint) {
        case Endpoint::CoupledMixInput: return MIX_A_LIMB;
        case Endpoint::CoupledMixArithmetic: return MIX_SUM_LIMB;
        case Endpoint::CoupledMixOutput: return MIX_DIFF_LIMB;
        default: break;
        }
        break;
    case RCStage3RelationRole::CoupledExtract:
        switch (endpoint) {
        case Endpoint::CoupledExtractInput:
            return air_quotient::kColUMix;
        case Endpoint::CoupledExtractSampler:
            return air_quotient::kColMixed;
        case Endpoint::CoupledExtractScale:
            return air_quotient::kColE0;
        case Endpoint::CoupledExtractOutput:
            return air_quotient::kColOut;
        default: break;
        }
        break;
    default:
        break;
    }
    return std::nullopt;
}

// The scalar relation-cell endpoints that previously had a proved,
// CTL-aliasable cell but NO opening to their committed manifest root.  Each now
// carries an executable in-AIR commitment opening (OpenRCStage3EndpointCommitment)
// with a passing honest opening and a firing tamper test, so its cell is proved
// to be the committed manifest value up to recursive-child consumption.
bool IsOpenedRelationEndpoint(RCStage3RelationEndpoint endpoint)
{
    switch (endpoint) {
    case RCStage3RelationEndpoint::EpisodeGemmOperandA:
    case RCStage3RelationEndpoint::EpisodeGemmOperandB:
    case RCStage3RelationEndpoint::EpisodeGemmOutputY:
    case RCStage3RelationEndpoint::EpisodeExtractSampler:
    case RCStage3RelationEndpoint::EpisodeExtractOutput:
    case RCStage3RelationEndpoint::EpisodeWiringCopy:
    case RCStage3RelationEndpoint::CoupledBankPages:
    case RCStage3RelationEndpoint::CoupledGemmOperandA:
    case RCStage3RelationEndpoint::CoupledGemmOperandB:
    case RCStage3RelationEndpoint::CoupledGemmOutputY:
    case RCStage3RelationEndpoint::CoupledExchangeInput:
    case RCStage3RelationEndpoint::CoupledExchangeOutput:
    case RCStage3RelationEndpoint::CoupledPermutationInput:
    case RCStage3RelationEndpoint::CoupledPermutationOutput:
    case RCStage3RelationEndpoint::CoupledMixInput:
    case RCStage3RelationEndpoint::CoupledMixArithmetic:
    case RCStage3RelationEndpoint::CoupledMixOutput:
    case RCStage3RelationEndpoint::CoupledExtractInput:
    case RCStage3RelationEndpoint::CoupledExtractSampler:
    case RCStage3RelationEndpoint::CoupledExtractScale:
    case RCStage3RelationEndpoint::CoupledExtractOutput:
        return true;
    default:
        return false;
    }
}

// No-cell endpoints whose committed VALUE column is a verifier-recomputed
// vector, opened cell-wise against the re-anchored VectorRootAlg root.
// (EpisodeBuilderParams: the 9 consensus-params cells the verifier regenerates
// and refuses from the manifest — CanonicalRCStage3EpisodeBuilderParamValues.)
bool IsVectorOpenedEndpoint(RCStage3RelationEndpoint endpoint)
{
    switch (endpoint) {
    case RCStage3RelationEndpoint::EpisodeBuilderParams:
    // Extract sampler value columns (kColUMix / kColE0), opened cell-wise
    // against a VectorRootAlg root over the REAL sampler columns.
    case RCStage3RelationEndpoint::EpisodeExtractInput:
    case RCStage3RelationEndpoint::EpisodeExtractScale:
        return true;
    default:
        return false;
    }
}

// Endpoints closed by a sibling lane's self-contained, verified alg binding,
// whose semantic pin is WIRED into this registry (copied, not re-run):
//   EpisodeBuilderTrace  -> RCStage3BuilderTraceWireSemanticPin (endpoint 4)
//   EpisodeGemmSumcheck  -> RCStage3GemmSumcheckWireSemanticPin (endpoint 8)
bool IsWiredBindingEndpoint(RCStage3RelationEndpoint endpoint)
{
    switch (endpoint) {
    case RCStage3RelationEndpoint::EpisodeBuilderTrace:    // #4  BuilderTrace
    case RCStage3RelationEndpoint::EpisodeGemmSumcheck:    // #8  GemmSumcheck
    case RCStage3RelationEndpoint::EpisodeBuilderSeedChain: // #2  SeedChain
    case RCStage3RelationEndpoint::EpisodeWiringTranspose: // #16 WiringTranspose
    case RCStage3RelationEndpoint::EpisodeWiringResidual:  // #17 WiringResidual
    case RCStage3RelationEndpoint::EpisodeWiringRoundOrder: // #18 WiringRoundOrder
    case RCStage3RelationEndpoint::CoupledBankRoot:        // #29 CoupledBankRoot
    case RCStage3RelationEndpoint::CoupledGemmSignedRange: // #33 CoupledGemmSignedRange
        return true;
    default:
        return false;
    }
}

RCStage3RelationEndpointCellAudit CellAudit(
    RCStage3RelationRole role,
    RCStage3RelationEndpoint endpoint)
{
    RCStage3RelationEndpointCellAudit out;
    out.endpoint = endpoint;
    out.role = role;
    out.remaining =
        "no immutable relation AIR cell is exported for this semantic endpoint";

    auto episode = [&](uint32_t column, const char* source,
                       const char* remaining) {
        out.relation_air_cell = true;
        out.same_trace_ctl_alias = true;
        out.relation_column = column;
        out.source = source;
        out.remaining = remaining;
    };

    switch (endpoint) {
    case RCStage3RelationEndpoint::EpisodeGemmOperandA:
        episode(1, "episode_air:gemm_endpoint:A",
                "the cell is proved and CTL-aliasable, but its opening to the "
                "manifest operand-A root is absent");
        break;
    case RCStage3RelationEndpoint::EpisodeGemmOperandB:
        episode(2, "episode_air:gemm_endpoint:B",
                "the cell is proved and CTL-aliasable, but its opening to the "
                "manifest operand-B root is absent");
        break;
    case RCStage3RelationEndpoint::EpisodeGemmOutputY:
        episode(0, "episode_air:gemm_endpoint:GF",
                "the local product cell is proved and CTL-aliasable, but "
                "all-layer sumcheck and the Y-root opening are absent");
        break;
    case RCStage3RelationEndpoint::EpisodeGemmSignedRange:
        out.relation_air_cell = true;
        out.semantic_relation_complete = true;
        out.source = "gemm_extract:signed_range:VALUE";
        out.remaining =
            "native relation-to-two-CTL root equality executes, but its "
            "recursive verifier child is not consumed";
        break;
    case RCStage3RelationEndpoint::EpisodeExtractSampler:
        episode(air_quotient::kColMixed,
                "episode_air:extract_sampler:MIXED",
                "the sampler core cell is proved and CTL-aliasable, but "
                "ChaCha input provenance and every-tile closure are absent");
        break;
    case RCStage3RelationEndpoint::EpisodeExtractOutput:
        episode(air_quotient::kColOut,
                "episode_air:extract_sampler:OUT",
                "the dequant output cell is proved and CTL-aliasable, but "
                "the output-root opening and every-tile closure are absent");
        break;
    case RCStage3RelationEndpoint::EpisodeWiringCopy:
        episode(0, "episode_air:wiring_equality:U",
                "the equality cell is proved and CTL-aliasable, but the "
                "complete immutable copy-edge manifest is absent");
        break;
    case RCStage3RelationEndpoint::CoupledBankPages:
        episode(coupled_air_col::BANK_NIB,
                "coupled_air:bank:NIB",
                "the local page-derived nibble cell is CTL-aliasable, but "
                "bank seed-XOF and page-root inclusion are absent");
        break;
    case RCStage3RelationEndpoint::CoupledGemmOperandA:
        episode(coupled_air_col::GEMM_A,
                "coupled_air:gemm:A",
                "the local operand cell is CTL-aliasable, but its committed "
                "operand-root opening and complete instance schedule are absent");
        break;
    case RCStage3RelationEndpoint::CoupledGemmOperandB:
        episode(coupled_air_col::GEMM_B,
                "coupled_air:gemm:B",
                "the local operand cell is CTL-aliasable, but its committed "
                "operand-root opening and complete instance schedule are absent");
        break;
    case RCStage3RelationEndpoint::CoupledGemmOutputY:
        episode(coupled_air_col::GEMM_OUT,
                "coupled_air:gemm:OUT",
                "the local accumulated output is CTL-aliasable, but its "
                "output-root opening and all-instance aggregation are absent");
        break;
    case RCStage3RelationEndpoint::CoupledExchangeInput:
        episode(coupled_air_col::COPY_INPUT,
                "coupled_air:exchange:INPUT",
                "the copy input is CTL-aliasable, but the fixed exchange "
                "schedule and material hash-XOF provenance are absent");
        break;
    case RCStage3RelationEndpoint::CoupledExchangeOutput:
        episode(coupled_air_col::COPY_OUTPUT,
                "coupled_air:exchange:OUTPUT",
                "the copy output is CTL-aliasable, but the committed output "
                "opening and material exchange schedule are absent");
        break;
    case RCStage3RelationEndpoint::CoupledPermutationInput:
        episode(coupled_air_col::COPY_INPUT,
                "coupled_air:permutation:INPUT",
                "the input cell is CTL-aliasable, but the bit-affine index "
                "schedule and committed input opening are absent");
        break;
    case RCStage3RelationEndpoint::CoupledPermutationOutput:
        episode(coupled_air_col::COPY_OUTPUT,
                "coupled_air:permutation:OUTPUT",
                "the output cell is CTL-aliasable, but the bit-affine index "
                "schedule and committed output opening are absent");
        break;
    case RCStage3RelationEndpoint::CoupledMixInput:
        episode(coupled_air_col::MIX_A_LIMB,
                "coupled_air:mix:A_LIMB0",
                "one ranged input limb is CTL-aliasable; the complete A/B "
                "limb vector, stage pairing and input-root opening remain");
        break;
    case RCStage3RelationEndpoint::CoupledMixArithmetic:
        episode(coupled_air_col::MIX_SUM_LIMB,
                "coupled_air:mix:SUM_LIMB0",
                "one proved add limb is CTL-aliasable; all limbs, subtraction "
                "and the immutable mix schedule remain");
        break;
    case RCStage3RelationEndpoint::CoupledMixOutput:
        episode(coupled_air_col::MIX_DIFF_LIMB,
                "coupled_air:mix:DIFF_LIMB0",
                "one proved output limb is CTL-aliasable; the complete output "
                "vector and output-root opening remain");
        break;
    case RCStage3RelationEndpoint::CoupledExtractInput:
        episode(air_quotient::kColUMix,
                "coupled_air:extract:U_MIX",
                "the sampler input cell is CTL-aliasable, but its state-root "
                "opening and int64 embedding are absent");
        break;
    case RCStage3RelationEndpoint::CoupledExtractSampler:
        episode(air_quotient::kColMixed,
                "coupled_air:extract:MIXED",
                "the sampler core cell is CTL-aliasable, but ChaCha "
                "provenance and all-instance closure are absent");
        break;
    case RCStage3RelationEndpoint::CoupledExtractScale:
        episode(air_quotient::kColE0,
                "coupled_air:extract:E0",
                "one public scale bit is CTL-aliasable; the complete scale "
                "schedule and SHA-derived scale proof remain");
        break;
    case RCStage3RelationEndpoint::CoupledExtractOutput:
        episode(air_quotient::kColOut,
                "coupled_air:extract:OUT",
                "the dequant output cell is CTL-aliasable, but range, "
                "output-root opening and all-instance closure remain");
        break;
    default:
        break;
    }

    // Blocker A: endpoints whose scalar relation cell now carries an executable
    // in-AIR commitment opening are semantically complete up to recursive-child
    // consumption.  The opening proves the CTL-aliased cell IS the value the
    // committed manifest root commits (OpenRCStage3EndpointCommitment).
    if (out.relation_air_cell && IsOpenedRelationEndpoint(endpoint)) {
        out.semantic_relation_complete = true;
        out.remaining =
            "in-AIR commitment opening binds the CTL VALUE cell to the "
            "committed manifest root (LeafHash + AlgHash Merkle path); only "
            "recursive-child consumption remains";
    }

    // Blocker A (stream/digest facet): endpoints that export a committed hash/
    // stream column (no scalar cell) close by the §4 SHA256d manifest recursive
    // binding + stream-root pin (OpenRCStage3StreamEndpointCommitment).
    if (RCStage3StreamEndpointManifestFamily(endpoint) !=
        RCStage3StreamManifestFamily::None) {
        out.semantic_relation_complete = true;
        out.remaining =
            "committed stream column is pinned to the §4 manifest binding's "
            "SHA256d stream_column_root (index-bound, reorder/substitution "
            "fail closed); CopyAndCtlWiring bus closure and recursive-child "
            "consumption remain";
    }

    // Blocker A (value-vector facet): no-cell endpoints whose verifier-recomputed
    // VALUE column is opened cell-wise against the re-anchored VectorRootAlg root.
    if (IsVectorOpenedEndpoint(endpoint)) {
        out.semantic_relation_complete = true;
        out.remaining =
            "a cell of the verifier-recomputed VALUE column opens the "
            "re-anchored VectorRootAlg root (Poseidon authority; SHA256d kept "
            "transport-only); recursive-child consumption remains";
    }

    // Blocker A (wired sibling bindings): the semantic pin of a sibling lane's
    // self-contained, verified alg binding is copied into this registry slot.
    if (IsWiredBindingEndpoint(endpoint)) {
        out.semantic_relation_complete = true;
        out.remaining =
            "semantic pin wired from the sibling lane's verified alg binding "
            "(two-layer VectorRootAlg fold / Thaler sumcheck, honest-accept + "
            "tamper-reject); recursive-child consumption remains";
    }

    return out;
}

} // namespace

bool BuildRCStage3RelationCtlDirectAliasConstraintSystem(
    const AirCS& relation_cs,
    const RCStage3CtlAirSpec& ctl_spec,
    uint32_t source_column,
    AirCS& out,
    RCStage3RelationCtlDirectAliasLayout* layout,
    std::string* why)
{
    out = {};
    RCStage3RelationCtlDirectAliasLayout local;
    if (relation_cs.n_rows < 2 ||
        (relation_cs.n_rows & (relation_cs.n_rows - 1)) != 0 ||
        relation_cs.n_columns == 0 ||
        source_column >= relation_cs.n_columns ||
        relation_cs.constraints.empty() ||
        !ValidateRCStage3CtlSchedule(ctl_spec.schedule, why)) {
        return Fail(why, "direct_alias:relation_shape");
    }
    const AirCS ctl_cs = BuildRCStage3CtlConstraintSystem(ctl_spec);
    if (ctl_cs.n_rows != relation_cs.n_rows ||
        ctl_cs.n_columns != stage3_ctl_col::NUM_COLUMNS ||
        ctl_cs.constraints.empty() ||
        relation_cs.n_columns >
            std::numeric_limits<uint32_t>::max() - ctl_cs.n_columns) {
        return Fail(why, "direct_alias:row_or_width_mismatch");
    }

    out.n_rows = relation_cs.n_rows;
    out.n_columns = relation_cs.n_columns + ctl_cs.n_columns;
    // Root pins remain exact in the product. OOD pinning is safe only when
    // every preprocessed family uses it; root equality remains stronger.
    out.preprocessed_pin_ood =
        relation_cs.preprocessed_pin_ood || ctl_cs.preprocessed_pin_ood;
    CopyConstraintFamily(relation_cs, 0, out);
    CopyConstraintFamily(ctl_cs, relation_cs.n_columns, out);

    const uint32_t ctl_value =
        relation_cs.n_columns + stage3_ctl_col::VALUE;
    AirConstraint alias;
    alias.name = "stage3.relation_ctl.direct_same_trace_value";
    alias.kind = air_quotient::AirKind::kEverywhere;
    alias.alg_degree = 1;
    alias.eval = [source_column, ctl_value](
                     const std::vector<Fp3>& current,
                     const std::vector<Fp3>&) {
        return gkr_field::Sub(
            current[source_column], current[ctl_value]);
    };
    out.constraints.push_back(std::move(alias));

    local.relation_columns = relation_cs.n_columns;
    local.ctl_column_base = relation_cs.n_columns;
    local.total_columns = out.n_columns;
    local.source_column = source_column;
    local.ctl_value_column = ctl_value;
    local.same_trace = true;
    local.direct_alias = true;
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why = "stage3:relation_closure:direct_alias_constraint_system_ok";
    }
    return true;
}

bool BuildRCStage3RelationCtlDirectAliasWitness(
    const RCStage3RelationCtlDirectAliasLayout& layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const RCStage3CtlWitness& ctl_witness,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.same_trace || !layout.direct_alias ||
        layout.relation_columns == 0 ||
        layout.ctl_column_base != layout.relation_columns ||
        layout.total_columns !=
            layout.relation_columns + stage3_ctl_col::NUM_COLUMNS ||
        layout.source_column >= layout.relation_columns ||
        layout.ctl_value_column !=
            layout.ctl_column_base + stage3_ctl_col::VALUE ||
        relation_columns.size() != layout.relation_columns ||
        !ctl_witness.ok ||
        ctl_witness.columns.size() != stage3_ctl_col::NUM_COLUMNS) {
        return Fail(why, "direct_alias:witness_shape");
    }
    const size_t rows = relation_columns.front().size();
    if (rows < 2) return Fail(why, "direct_alias:witness_rows");
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            return Fail(why, "direct_alias:relation_column_rows");
        }
    }
    for (const auto& column : ctl_witness.columns) {
        if (column.size() != rows) {
            return Fail(why, "direct_alias:ctl_column_rows");
        }
    }
    for (size_t row = 0; row < rows; ++row) {
        if (!gkr_field::Eq(
                relation_columns[layout.source_column][row],
                ctl_witness.columns[stage3_ctl_col::VALUE][row])) {
            return Fail(why, "direct_alias:value_mismatch");
        }
    }
    out = relation_columns;
    out.insert(
        out.end(), ctl_witness.columns.begin(), ctl_witness.columns.end());
    if (why != nullptr) {
        *why = "stage3:relation_closure:direct_alias_witness_ok";
    }
    return true;
}

bool BuildRCStage3RelationCtlDegree2DirectAliasConstraintSystem(
    const AirCS& relation_cs,
    const RCStage3CtlDegree2AirSpec& ctl_spec,
    uint32_t source_column,
    AirCS& out,
    RCStage3RelationCtlDegree2DirectAliasLayout* layout,
    std::string* why)
{
    out = {};
    RCStage3RelationCtlDegree2DirectAliasLayout local;
    if (relation_cs.n_rows < 2 ||
        (relation_cs.n_rows & (relation_cs.n_rows - 1)) != 0 ||
        relation_cs.n_columns == 0 ||
        source_column >= relation_cs.n_columns ||
        relation_cs.constraints.empty() ||
        !ValidateRCStage3CtlSchedule(ctl_spec.schedule, why)) {
        return Fail(why, "degree2_direct_alias:relation_shape");
    }
    const AirCS ctl_cs =
        BuildRCStage3CtlDegree2ConstraintSystem(ctl_spec);
    if (ctl_cs.n_rows != relation_cs.n_rows ||
        ctl_cs.n_columns != stage3_ctl_degree2_col::NUM_COLUMNS ||
        ctl_cs.constraints.empty() ||
        ctl_cs.QuotientLen() > ctl_cs.n_rows ||
        relation_cs.n_columns >
            std::numeric_limits<uint32_t>::max() - ctl_cs.n_columns) {
        return Fail(
            why, "degree2_direct_alias:row_or_width_mismatch");
    }

    out.n_rows = relation_cs.n_rows;
    out.n_columns = relation_cs.n_columns + ctl_cs.n_columns;
    out.preprocessed_pin_ood =
        relation_cs.preprocessed_pin_ood || ctl_cs.preprocessed_pin_ood;
    CopyConstraintFamily(relation_cs, 0, out);
    CopyConstraintFamily(ctl_cs, relation_cs.n_columns, out);

    const uint32_t ctl_value =
        relation_cs.n_columns + stage3_ctl_degree2_col::VALUE;
    AirConstraint alias;
    alias.name =
        "stage3.relation_ctl.degree2_direct_same_trace_value";
    alias.kind = air_quotient::AirKind::kEverywhere;
    alias.alg_degree = 1;
    alias.eval = [source_column, ctl_value](
                     const std::vector<Fp3>& current,
                     const std::vector<Fp3>&) {
        return gkr_field::Sub(
            current[source_column], current[ctl_value]);
    };
    out.constraints.push_back(std::move(alias));
    if (out.QuotientLen() > out.n_rows) {
        out = {};
        return Fail(
            why, "degree2_direct_alias:coefficient_count_expanded");
    }

    local.relation_columns = relation_cs.n_columns;
    local.ctl_column_base = relation_cs.n_columns;
    local.total_columns = out.n_columns;
    local.source_column = source_column;
    local.ctl_value_column = ctl_value;
    local.same_trace = true;
    local.direct_alias = true;
    local.exact_row_degree_two = true;
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "degree2_direct_alias_constraint_system_ok";
    }
    return true;
}

bool BuildRCStage3RelationCtlDegree2DirectAliasWitness(
    const RCStage3RelationCtlDegree2DirectAliasLayout& layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const RCStage3CtlDegree2Witness& ctl_witness,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.same_trace || !layout.direct_alias ||
        !layout.exact_row_degree_two ||
        layout.relation_columns == 0 ||
        layout.ctl_column_base != layout.relation_columns ||
        layout.total_columns !=
            layout.relation_columns +
                stage3_ctl_degree2_col::NUM_COLUMNS ||
        layout.source_column >= layout.relation_columns ||
        layout.ctl_value_column !=
            layout.ctl_column_base +
                stage3_ctl_degree2_col::VALUE ||
        relation_columns.size() != layout.relation_columns ||
        !ctl_witness.ok ||
        ctl_witness.version != kRCStage3CtlDegree2Version ||
        ctl_witness.columns.size() !=
            stage3_ctl_degree2_col::NUM_COLUMNS) {
        return Fail(why, "degree2_direct_alias:witness_shape");
    }
    const size_t rows = relation_columns.front().size();
    if (rows < 2 || (rows & (rows - 1)) != 0) {
        return Fail(why, "degree2_direct_alias:witness_rows");
    }
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            return Fail(
                why, "degree2_direct_alias:relation_column_rows");
        }
    }
    for (const auto& column : ctl_witness.columns) {
        if (column.size() != rows) {
            return Fail(
                why, "degree2_direct_alias:ctl_column_rows");
        }
    }
    for (size_t row = 0; row < rows; ++row) {
        if (!gkr_field::Eq(
                relation_columns[layout.source_column][row],
                ctl_witness.columns[
                    stage3_ctl_degree2_col::VALUE][row])) {
            return Fail(
                why, "degree2_direct_alias:value_mismatch");
        }
    }
    out = relation_columns;
    out.insert(
        out.end(),
        ctl_witness.columns.begin(),
        ctl_witness.columns.end());
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "degree2_direct_alias_witness_ok";
    }
    return true;
}

bool BuildRCStage3RelationCtlMaskedAliasConstraintSystem(
    const AirCS& relation_cs,
    const RCStage3CtlAirSpec& ctl_spec,
    const std::vector<RCStage3RelationCtlMaskedSource>& sources,
    AirCS& out,
    RCStage3RelationCtlMaskedAliasLayout* layout,
    std::string* why)
{
    out = {};
    RCStage3RelationCtlMaskedAliasLayout local;
    if (relation_cs.n_rows < 2 ||
        (relation_cs.n_rows & (relation_cs.n_rows - 1)) != 0 ||
        relation_cs.n_columns == 0 ||
        relation_cs.constraints.empty() ||
        sources.empty() || sources.size() > 64 ||
        !ValidateRCStage3CtlSchedule(ctl_spec.schedule, why)) {
        return Fail(why, "masked_alias:relation_shape");
    }
    const AirCS ctl_cs = BuildRCStage3CtlConstraintSystem(ctl_spec);
    if (ctl_cs.n_rows != relation_cs.n_rows ||
        ctl_cs.n_columns != stage3_ctl_col::NUM_COLUMNS ||
        ctl_cs.constraints.empty() ||
        relation_cs.n_columns >
            std::numeric_limits<uint32_t>::max() - ctl_cs.n_columns) {
        return Fail(why, "masked_alias:row_or_width_mismatch");
    }

    std::vector<const std::vector<Fp3>*> masks;
    masks.reserve(sources.size());
    for (size_t i = 0; i < sources.size(); ++i) {
        const auto& source = sources[i];
        if (source.source_column >= relation_cs.n_columns ||
            source.mask_column >= relation_cs.n_columns) {
            return Fail(why, "masked_alias:source_range");
        }
        for (size_t j = 0; j < i; ++j) {
            if (sources[j].mask_column == source.mask_column) {
                return Fail(why, "masked_alias:duplicate_mask");
            }
        }
        const auto mask = std::find_if(
            relation_cs.preprocessed.begin(),
            relation_cs.preprocessed.end(),
            [&](const auto& entry) {
                return entry.first == source.mask_column;
            });
        if (mask == relation_cs.preprocessed.end() ||
            mask->second.size() != relation_cs.n_rows) {
            return Fail(why, "masked_alias:mask_not_preprocessed");
        }
        masks.push_back(&mask->second);
    }
    for (uint32_t row = 0; row < relation_cs.n_rows; ++row) {
        uint32_t active = 0;
        for (const auto* mask : masks) {
            const Fp3& value = (*mask)[row];
            if (!gkr_field::Eq(value, Fp3::Zero()) &&
                !gkr_field::Eq(value, Fp3::One())) {
                return Fail(why, "masked_alias:mask_not_boolean");
            }
            active += gkr_field::Eq(value, Fp3::One()) ? 1U : 0U;
        }
        if (active > 1) {
            return Fail(why, "masked_alias:masks_overlap");
        }
    }

    out.n_rows = relation_cs.n_rows;
    out.n_columns = relation_cs.n_columns + ctl_cs.n_columns;
    out.preprocessed_pin_ood =
        relation_cs.preprocessed_pin_ood || ctl_cs.preprocessed_pin_ood;
    CopyConstraintFamily(relation_cs, 0, out);
    CopyConstraintFamily(ctl_cs, relation_cs.n_columns, out);
    const uint32_t ctl_value =
        relation_cs.n_columns + stage3_ctl_col::VALUE;
    AirConstraint alias;
    alias.name = "stage3.relation_ctl.fixed_masked_value";
    alias.kind = air_quotient::AirKind::kEverywhere;
    alias.alg_degree = 2;
    alias.eval = [sources, ctl_value](
                     const std::vector<Fp3>& current,
                     const std::vector<Fp3>&) {
        Fp3 selected = Fp3::Zero();
        for (const auto& source : sources) {
            selected = gkr_field::Add(
                selected,
                gkr_field::Mul(
                    current[source.mask_column],
                    current[source.source_column]));
        }
        return gkr_field::Sub(current[ctl_value], selected);
    };
    out.constraints.push_back(std::move(alias));

    local.relation_columns = relation_cs.n_columns;
    local.ctl_column_base = relation_cs.n_columns;
    local.total_columns = out.n_columns;
    local.ctl_value_column = ctl_value;
    local.sources = sources;
    local.preprocessed_masks = true;
    local.masks_boolean_and_disjoint = true;
    local.same_trace = true;
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:fixed_masked_alias_constraint_system_ok";
    }
    return true;
}

bool BuildRCStage3RelationCtlMaskedAliasWitness(
    const RCStage3RelationCtlMaskedAliasLayout& layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const RCStage3CtlWitness& ctl_witness,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.preprocessed_masks ||
        !layout.masks_boolean_and_disjoint ||
        !layout.same_trace ||
        layout.sources.empty() ||
        layout.relation_columns == 0 ||
        layout.ctl_column_base != layout.relation_columns ||
        layout.total_columns !=
            layout.relation_columns + stage3_ctl_col::NUM_COLUMNS ||
        layout.ctl_value_column !=
            layout.ctl_column_base + stage3_ctl_col::VALUE ||
        relation_columns.size() != layout.relation_columns ||
        !ctl_witness.ok ||
        ctl_witness.columns.size() != stage3_ctl_col::NUM_COLUMNS) {
        return Fail(why, "masked_alias:witness_shape");
    }
    const size_t rows = relation_columns.front().size();
    if (rows < 2) return Fail(why, "masked_alias:witness_rows");
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            return Fail(why, "masked_alias:relation_column_rows");
        }
    }
    for (const auto& column : ctl_witness.columns) {
        if (column.size() != rows) {
            return Fail(why, "masked_alias:ctl_column_rows");
        }
    }
    for (size_t row = 0; row < rows; ++row) {
        Fp3 selected = Fp3::Zero();
        uint32_t active = 0;
        for (const auto& source : layout.sources) {
            if (source.source_column >= relation_columns.size() ||
                source.mask_column >= relation_columns.size()) {
                return Fail(why, "masked_alias:source_range");
            }
            const Fp3& mask =
                relation_columns[source.mask_column][row];
            if (!gkr_field::Eq(mask, Fp3::Zero()) &&
                !gkr_field::Eq(mask, Fp3::One())) {
                return Fail(why, "masked_alias:mask_not_boolean");
            }
            active += gkr_field::Eq(mask, Fp3::One()) ? 1U : 0U;
            selected = gkr_field::Add(
                selected,
                gkr_field::Mul(
                    mask,
                    relation_columns[source.source_column][row]));
        }
        if (active > 1) {
            return Fail(why, "masked_alias:masks_overlap");
        }
        if (!gkr_field::Eq(
                selected,
                ctl_witness.columns[stage3_ctl_col::VALUE][row])) {
            return Fail(why, "masked_alias:value_mismatch");
        }
    }
    out = relation_columns;
    out.insert(
        out.end(), ctl_witness.columns.begin(), ctl_witness.columns.end());
    if (why != nullptr) {
        *why = "stage3:relation_closure:fixed_masked_alias_witness_ok";
    }
    return true;
}

uint256 ComputeRCStage3RelationCtlDirectAliasSeed(
    RCStage3RelationEndpoint endpoint,
    const uint256& relation_seed,
    const RCStage3CtlSchedule& schedule,
    const RCStage3CtlChallenges& challenges,
    const RCStage3CtlTerminal& terminal,
    uint32_t source_column)
{
    const uint16_t endpoint_id = static_cast<uint16_t>(endpoint);
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    if (relation_seed.IsNull() ||
        endpoint_id == 0 ||
        endpoint_id > kRCStage3RelationClosureEndpointCount ||
        CommitRCStage3CtlSchedule(schedule).IsNull() ||
        challenge_commitment.IsNull() ||
        !Canonical(challenges.gamma1) ||
        !Canonical(challenges.gamma2) ||
        !Canonical(challenges.alpha1) ||
        !Canonical(challenges.alpha2) ||
        !Canonical(terminal.alpha1_sum) ||
        !Canonical(terminal.alpha2_sum)) {
        return {};
    }
    HashWriter hash;
    hash << DIRECT_ALIAS_SEED_DOMAIN;
    hash << kRCStage3RelationClosureVersion;
    hash << endpoint_id;
    hash << relation_seed;
    hash << CommitRCStage3CtlSchedule(schedule);
    hash << challenge_commitment;
    hash << source_column;
    HashFp3(hash, challenges.gamma1);
    HashFp3(hash, challenges.gamma2);
    HashFp3(hash, challenges.alpha1);
    HashFp3(hash, challenges.alpha2);
    HashFp3(hash, terminal.alpha1_sum);
    HashFp3(hash, terminal.alpha2_sum);
    return hash.GetHash();
}

bool VerifyRCStage3EpisodeEndpointCtlDirectAliasProof(
    const RCStage3SuccinctProof& statement,
    RCStage3RelationEndpoint endpoint,
    const RCStage3EpisodeAirPublicPin& episode_pin,
    const RCStage3CtlManifest& ctl_manifest,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    size_t ctl_participant_index,
    const RCStage3CtlSchedule& schedule,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const auto source_column = EpisodeEndpointColumn(
        endpoint, episode_pin.family, episode_pin.role);
    if (!source_column.has_value()) {
        return Fail(why, "direct_alias:unregistered_episode_endpoint");
    }
    if (ctl_participant_index >= ctl_pins.size() ||
        ctl_pins.size() != ctl_manifest.participants.size()) {
        return Fail(why, "direct_alias:ctl_participant_shape");
    }
    const auto& participant =
        ctl_manifest.participants[ctl_participant_index];
    const auto& ctl_pin = ctl_pins[ctl_participant_index];
    if (participant.role != episode_pin.role ||
        ctl_pin.role != episode_pin.role ||
        ctl_pin.bus_id != ctl_manifest.bus_id ||
        ctl_pin.schedule_commitment !=
            CommitRCStage3CtlSchedule(schedule) ||
        participant.schedule_commitment !=
            ctl_pin.schedule_commitment ||
        participant.event_count != ctl_pin.event_count ||
        participant.send_count != ctl_pin.send_count ||
        participant.receive_count != ctl_pin.receive_count) {
        return Fail(why, "direct_alias:ctl_participant_binding");
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            ctl_manifest, ctl_pins, challenges, why)) {
        return Fail(why, "direct_alias:ctl_challenges");
    }
    if (ctl_pin.challenge_commitment !=
        CommitRCStage3CtlChallenges(challenges)) {
        return Fail(why, "direct_alias:ctl_challenge_commitment");
    }

    AirCS relation_cs;
    if (!ResolveRCStage3EpisodeAirConstraintSystem(
            statement, episode_pin, relation_cs, why)) {
        return Fail(why, "direct_alias:episode_constraint_system");
    }
    const RCStage3CtlAirSpec ctl_spec{
        schedule, challenges, ctl_pin.terminal};
    AirCS combined;
    RCStage3RelationCtlDirectAliasLayout layout;
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            relation_cs, ctl_spec, *source_column,
            combined, &layout, why)) {
        return false;
    }
    if (proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1 ||
        proof.batch.column_len.size() != proof.batch.columns.size() ||
        episode_pin.column_roots.size() != relation_cs.n_columns) {
        return Fail(why, "direct_alias:proof_shape");
    }
    for (uint32_t column = 0; column < relation_cs.n_columns; ++column) {
        if (proof.batch.columns[column].root !=
            episode_pin.column_roots[column].root) {
            return Fail(why, "direct_alias:relation_column_root");
        }
    }
    if (proof.batch.columns[layout.source_column].root !=
        proof.batch.columns[layout.ctl_value_column].root) {
        return Fail(why, "direct_alias:source_value_root");
    }

    std::array<uint256, 5> ctl_roots{};
    for (uint32_t column = stage3_ctl_col::NAMESPACE;
         column <= stage3_ctl_col::MULTIPLICITY; ++column) {
        ctl_roots[column] =
            proof.batch.columns[layout.ctl_column_base + column].root;
    }
    const uint32_t ctl_rows =
        proof.batch.column_len[layout.ctl_column_base];
    if (ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
            schedule, ctl_rows, proof.batch.n_coeffs, ctl_roots) !=
        ctl_pin.trace_commitment) {
        return Fail(why, "direct_alias:ctl_trace_commitment");
    }

    const uint256 relation_seed =
        ComputeRCStage3EpisodeAirSeed(statement, episode_pin);
    const uint256 seed = ComputeRCStage3RelationCtlDirectAliasSeed(
        endpoint, relation_seed, schedule, challenges,
        ctl_pin.terminal, *source_column);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(why, "direct_alias:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:episode_relation_cell_equals_"
            "same_trace_ctl_value_recursive_consumption_pending";
    }
    return true;
}

uint256 ComputeRCStage3CoupledEndpointAirSeed(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledEndpointAirPublicPin& pin)
{
    const auto source_column =
        CoupledEndpointColumn(pin.endpoint, pin.request.role);
    const uint256 expected_statement =
        CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 expected_shape =
        CommitRCStage3CoupledShape(pin.request.shape);
    RCStage3CoupledAirEntry entry;
    if (!source_column.has_value() ||
        expected_statement.IsNull() ||
        expected_shape.IsNull() ||
        pin.statement_commitment != expected_statement ||
        pin.shape_commitment != expected_shape ||
        !ResolveRCStage3CoupledAir(pin.request, entry) ||
        !entry.constraint_system_available ||
        pin.relation_column_roots.size() !=
            entry.constraints.n_columns) {
        return {};
    }
    for (const auto& root : pin.relation_column_roots) {
        if (root.IsNull()) return {};
    }
    HashWriter hash;
    hash << COUPLED_ENDPOINT_SEED_DOMAIN;
    hash << kRCStage3RelationClosureVersion;
    hash << pin.statement_commitment;
    hash << pin.shape_commitment;
    hash << static_cast<uint16_t>(pin.request.role);
    hash << static_cast<uint16_t>(pin.endpoint);
    hash << pin.request.extract_scale_e;
    HashFp3(hash, pin.request.gamma);
    HashFp3(hash, pin.request.alpha);
    hash << static_cast<uint32_t>(pin.relation_column_roots.size());
    for (const auto& root : pin.relation_column_roots) hash << root;
    return hash.GetHash();
}

bool VerifyRCStage3CoupledEndpointCtlDirectAliasProof(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledEndpointAirPublicPin& pin,
    const RCStage3CtlManifest& ctl_manifest,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    size_t ctl_participant_index,
    const RCStage3CtlSchedule& schedule,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    const auto source_column =
        CoupledEndpointColumn(pin.endpoint, pin.request.role);
    if (!source_column.has_value()) {
        return Fail(why, "coupled_alias:unregistered_endpoint");
    }
    const uint256 relation_seed =
        ComputeRCStage3CoupledEndpointAirSeed(statement, pin);
    if (relation_seed.IsNull()) {
        return Fail(why, "coupled_alias:public_pin");
    }
    if (ctl_participant_index >= ctl_pins.size() ||
        ctl_pins.size() != ctl_manifest.participants.size()) {
        return Fail(why, "coupled_alias:ctl_participant_shape");
    }
    const auto& participant =
        ctl_manifest.participants[ctl_participant_index];
    const auto& ctl_pin = ctl_pins[ctl_participant_index];
    if (participant.role != pin.request.role ||
        ctl_pin.role != pin.request.role ||
        ctl_pin.bus_id != ctl_manifest.bus_id ||
        ctl_pin.schedule_commitment !=
            CommitRCStage3CtlSchedule(schedule) ||
        participant.schedule_commitment !=
            ctl_pin.schedule_commitment ||
        participant.event_count != ctl_pin.event_count ||
        participant.send_count != ctl_pin.send_count ||
        participant.receive_count != ctl_pin.receive_count) {
        return Fail(why, "coupled_alias:ctl_participant_binding");
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            ctl_manifest, ctl_pins, challenges, why)) {
        return Fail(why, "coupled_alias:ctl_challenges");
    }
    if (ctl_pin.challenge_commitment !=
        CommitRCStage3CtlChallenges(challenges)) {
        return Fail(why, "coupled_alias:ctl_challenge_commitment");
    }

    RCStage3CoupledAirEntry entry;
    if (!ResolveRCStage3CoupledAir(
            pin.request, entry, why) ||
        !entry.constraint_system_available ||
        pin.relation_column_roots.size() !=
            entry.constraints.n_columns) {
        return Fail(why, "coupled_alias:constraint_system");
    }
    for (uint32_t column = 0;
         column < pin.relation_column_roots.size(); ++column) {
        entry.constraints.preprocessed_roots.emplace_back(
            column, pin.relation_column_roots[column]);
    }

    const RCStage3CtlAirSpec ctl_spec{
        schedule, challenges, ctl_pin.terminal};
    AirCS combined;
    RCStage3RelationCtlDirectAliasLayout layout;
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            entry.constraints, ctl_spec, *source_column,
            combined, &layout, why)) {
        return false;
    }
    if (proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1 ||
        proof.batch.column_len.size() != proof.batch.columns.size()) {
        return Fail(why, "coupled_alias:proof_shape");
    }
    for (uint32_t column = 0;
         column < entry.constraints.n_columns; ++column) {
        if (proof.batch.columns[column].root !=
            pin.relation_column_roots[column]) {
            return Fail(why, "coupled_alias:relation_column_root");
        }
    }
    if (proof.batch.columns[layout.source_column].root !=
        proof.batch.columns[layout.ctl_value_column].root) {
        return Fail(why, "coupled_alias:source_value_root");
    }
    std::array<uint256, 5> ctl_roots{};
    for (uint32_t column = stage3_ctl_col::NAMESPACE;
         column <= stage3_ctl_col::MULTIPLICITY; ++column) {
        ctl_roots[column] =
            proof.batch.columns[layout.ctl_column_base + column].root;
    }
    const uint32_t ctl_rows =
        proof.batch.column_len[layout.ctl_column_base];
    if (ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
            schedule, ctl_rows, proof.batch.n_coeffs, ctl_roots) !=
        ctl_pin.trace_commitment) {
        return Fail(why, "coupled_alias:ctl_trace_commitment");
    }

    const uint256 seed = ComputeRCStage3RelationCtlDirectAliasSeed(
        pin.endpoint, relation_seed, schedule, challenges,
        ctl_pin.terminal, *source_column);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(why, "coupled_alias:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:coupled_local_kernel_cell_equals_"
            "same_trace_ctl_value_commitment_opening_and_recursive_"
            "consumption_pending";
    }
    return true;
}

const char* RCStage3RelationEndpointName(RCStage3RelationEndpoint endpoint)
{
    switch (endpoint) {
    case RCStage3RelationEndpoint::EpisodeBuilderParams: return "episode:builder:params";
    case RCStage3RelationEndpoint::EpisodeBuilderSeedChain: return "episode:builder:seed_chain";
    case RCStage3RelationEndpoint::EpisodeBuilderOperandXof: return "episode:builder:operand_xof";
    case RCStage3RelationEndpoint::EpisodeBuilderTrace: return "episode:builder:trace";
    case RCStage3RelationEndpoint::EpisodeGemmOperandA: return "episode:gemm:a";
    case RCStage3RelationEndpoint::EpisodeGemmOperandB: return "episode:gemm:b";
    case RCStage3RelationEndpoint::EpisodeGemmOutputY: return "episode:gemm:y";
    case RCStage3RelationEndpoint::EpisodeGemmSumcheck: return "episode:gemm:sumcheck";
    case RCStage3RelationEndpoint::EpisodeGemmSignedRange: return "episode:gemm:signed_range";
    case RCStage3RelationEndpoint::EpisodeExtractInput: return "episode:extract:input";
    case RCStage3RelationEndpoint::EpisodeExtractSampler: return "episode:extract:sampler";
    case RCStage3RelationEndpoint::EpisodeExtractChaCha: return "episode:extract:chacha";
    case RCStage3RelationEndpoint::EpisodeExtractScale: return "episode:extract:scale";
    case RCStage3RelationEndpoint::EpisodeExtractOutput: return "episode:extract:output";
    case RCStage3RelationEndpoint::EpisodeWiringCopy: return "episode:wiring:copy";
    case RCStage3RelationEndpoint::EpisodeWiringTranspose: return "episode:wiring:transpose";
    case RCStage3RelationEndpoint::EpisodeWiringResidual: return "episode:wiring:residual";
    case RCStage3RelationEndpoint::EpisodeWiringRoundOrder: return "episode:wiring:round_order";
    case RCStage3RelationEndpoint::EpisodeTileTreeStream: return "episode:tiletree:stream";
    case RCStage3RelationEndpoint::EpisodeTileTreeLeafHash: return "episode:tiletree:leaf_hash";
    case RCStage3RelationEndpoint::EpisodeTileTreeInternalHash: return "episode:tiletree:internal_hash";
    case RCStage3RelationEndpoint::EpisodeTileTreeRoot: return "episode:tiletree:root";
    case RCStage3RelationEndpoint::EpisodeDigestRoundRoots: return "episode:digest:round_roots";
    case RCStage3RelationEndpoint::EpisodeDigestValue: return "episode:digest:value";
    case RCStage3RelationEndpoint::EpisodeDigestHeaderTarget: return "episode:digest:header_target";
    case RCStage3RelationEndpoint::EpisodeDigestPow: return "episode:digest:pow";
    case RCStage3RelationEndpoint::CoupledBankSeedXof: return "coupled:bank:seed_xof";
    case RCStage3RelationEndpoint::CoupledBankPages: return "coupled:bank:pages";
    case RCStage3RelationEndpoint::CoupledBankRoot: return "coupled:bank:root";
    case RCStage3RelationEndpoint::CoupledGemmOperandA: return "coupled:gemm:a";
    case RCStage3RelationEndpoint::CoupledGemmOperandB: return "coupled:gemm:b";
    case RCStage3RelationEndpoint::CoupledGemmOutputY: return "coupled:gemm:y";
    case RCStage3RelationEndpoint::CoupledGemmSignedRange: return "coupled:gemm:signed_range";
    case RCStage3RelationEndpoint::CoupledExchangeInput: return "coupled:exchange:input";
    case RCStage3RelationEndpoint::CoupledExchangeHashXof: return "coupled:exchange:hash_xof";
    case RCStage3RelationEndpoint::CoupledExchangeOutput: return "coupled:exchange:output";
    case RCStage3RelationEndpoint::CoupledPermutationInput: return "coupled:permutation:input";
    case RCStage3RelationEndpoint::CoupledPermutationOutput: return "coupled:permutation:output";
    case RCStage3RelationEndpoint::CoupledMixInput: return "coupled:mix:input";
    case RCStage3RelationEndpoint::CoupledMixArithmetic: return "coupled:mix:arithmetic";
    case RCStage3RelationEndpoint::CoupledMixOutput: return "coupled:mix:output";
    case RCStage3RelationEndpoint::CoupledExtractInput: return "coupled:extract:input";
    case RCStage3RelationEndpoint::CoupledExtractSampler: return "coupled:extract:sampler";
    case RCStage3RelationEndpoint::CoupledExtractChaCha: return "coupled:extract:chacha";
    case RCStage3RelationEndpoint::CoupledExtractScale: return "coupled:extract:scale";
    case RCStage3RelationEndpoint::CoupledExtractOutput: return "coupled:extract:output";
    case RCStage3RelationEndpoint::CoupledBarrierInput: return "coupled:barrier:input";
    case RCStage3RelationEndpoint::CoupledBarrierHash: return "coupled:barrier:hash";
    case RCStage3RelationEndpoint::CoupledBarrierOutput: return "coupled:barrier:output";
    case RCStage3RelationEndpoint::CoupledDigestBankAndBarriers: return "coupled:digest:bank_barriers";
    case RCStage3RelationEndpoint::CoupledDigestHash: return "coupled:digest:hash";
    case RCStage3RelationEndpoint::CoupledDigestValue: return "coupled:digest:value";
    }
    return "unknown";
}

const std::vector<RCStage3RelationEndpoint>&
RequiredRCStage3RelationEndpoints(RCStage3RelationRole role)
{
    switch (role) {
    case RCStage3RelationRole::EpisodeDeterministicBuilder: return EPISODE_BUILDER;
    case RCStage3RelationRole::EpisodeGemm: return EPISODE_GEMM;
    case RCStage3RelationRole::EpisodeExtract: return EPISODE_EXTRACT;
    case RCStage3RelationRole::EpisodeWiring: return EPISODE_WIRING;
    case RCStage3RelationRole::EpisodeTileTree: return EPISODE_TILE_TREE;
    case RCStage3RelationRole::EpisodeDigest: return EPISODE_DIGEST;
    case RCStage3RelationRole::CoupledBank: return COUPLED_BANK;
    case RCStage3RelationRole::CoupledGemm: return COUPLED_GEMM;
    case RCStage3RelationRole::CoupledExchange: return COUPLED_EXCHANGE;
    case RCStage3RelationRole::CoupledPermutation: return COUPLED_PERMUTATION;
    case RCStage3RelationRole::CoupledMix: return COUPLED_MIX;
    case RCStage3RelationRole::CoupledExtract: return COUPLED_EXTRACT;
    case RCStage3RelationRole::CoupledBarrier: return COUPLED_BARRIER;
    case RCStage3RelationRole::CoupledDigest: return COUPLED_DIGEST;
    case RCStage3RelationRole::CompositionLink: return EMPTY_ENDPOINTS;
    }
    return EMPTY_ENDPOINTS;
}

RCStage3RelationEndpoint
RCStage3RelationCtlExportEndpoint(RCStage3RelationRole role)
{
    switch (role) {
    case RCStage3RelationRole::EpisodeDeterministicBuilder:
        return RCStage3RelationEndpoint::EpisodeBuilderTrace;
    case RCStage3RelationRole::EpisodeGemm:
        return RCStage3RelationEndpoint::EpisodeGemmSignedRange;
    case RCStage3RelationRole::EpisodeExtract:
        return RCStage3RelationEndpoint::EpisodeExtractOutput;
    case RCStage3RelationRole::EpisodeWiring:
        return RCStage3RelationEndpoint::EpisodeWiringRoundOrder;
    case RCStage3RelationRole::EpisodeTileTree:
        return RCStage3RelationEndpoint::EpisodeTileTreeRoot;
    case RCStage3RelationRole::EpisodeDigest:
        return RCStage3RelationEndpoint::EpisodeDigestValue;
    case RCStage3RelationRole::CoupledBank:
        return RCStage3RelationEndpoint::CoupledBankRoot;
    case RCStage3RelationRole::CoupledGemm:
        return RCStage3RelationEndpoint::CoupledGemmSignedRange;
    case RCStage3RelationRole::CoupledExchange:
        return RCStage3RelationEndpoint::CoupledExchangeOutput;
    case RCStage3RelationRole::CoupledPermutation:
        return RCStage3RelationEndpoint::CoupledPermutationOutput;
    case RCStage3RelationRole::CoupledMix:
        return RCStage3RelationEndpoint::CoupledMixOutput;
    case RCStage3RelationRole::CoupledExtract:
        return RCStage3RelationEndpoint::CoupledExtractOutput;
    case RCStage3RelationRole::CoupledBarrier:
        return RCStage3RelationEndpoint::CoupledBarrierOutput;
    case RCStage3RelationRole::CoupledDigest:
        return RCStage3RelationEndpoint::CoupledDigestValue;
    case RCStage3RelationRole::CompositionLink:
        return {};
    }
    return {};
}

uint256 ComputeRCStage3RelationRoleMultiproofRoot(
    const RCStage3RelationRoleClosure& role)
{
    HashWriter hash;
    hash << ROLE_DOMAIN;
    hash << kRCStage3RelationClosureVersion;
    hash << static_cast<uint16_t>(role.role);
    hash << role.relation_commitment;
    hash << role.relation_statement_root;
    hash << static_cast<uint16_t>(role.endpoints.size());
    for (const auto& endpoint : role.endpoints) WriteEndpoint(hash, endpoint);
    return hash.GetHash();
}

uint256 ComputeRCStage3RelationClosureCommitment(
    const RCStage3RelationClosureV1& closure)
{
    HashWriter hash;
    hash << CLOSURE_DOMAIN;
    hash << closure.magic;
    hash << closure.version;
    hash << static_cast<uint8_t>(closure.strategy);
    hash << closure.unified_root_seed;
    hash << closure.statement_commitment;
    hash << closure.ctl_proof_bundle_commitment;
    hash << static_cast<uint16_t>(closure.roles.size());
    for (const auto& role : closure.roles) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.relation_commitment;
        hash << role.relation_statement_root;
        hash << role.endpoint_multiproof_root;
    }
    hash << closure.composition_link_commitment;
    hash << closure.final_digest_manifest_root;
    hash << closure.final_digest_proof_root;
    hash << closure.final_digest_semantic_root;
    hash << closure.final_digest_recursive_child_commitment;
    return hash.GetHash();
}

std::vector<RCStage3RelationClosureStrategyAssessment>
AssessRCStage3RelationClosureStrategies()
{
    return {
        {RCStage3RelationClosureStrategy::OneProofPerRole, 14, 52, true,
         true, false,
         "maximum isolation; compatible but duplicates hash/FRI verifier "
         "work and leaves fourteen heterogeneous recursive programs"},
        {RCStage3RelationClosureStrategy::FusedCompatibleAir, 14, 52, false,
         true, false,
         "local arithmetic/hash families can fuse, but current role AIRs "
         "have incompatible width, degree, domain and padding profiles"},
        {RCStage3RelationClosureStrategy::HashBoundMultiproof, 14, 52, true,
         true, false,
         "selected V1: exact endpoint ledger and executed CTL VALUE-root "
         "binding; normalized recursive execution remains open"},
    };
}

std::vector<RCStage3RelationClosureRoleAudit>
CurrentRCStage3RelationClosureRoleAudit()
{
    // Twenty-two endpoint families now expose concrete proof cells. Six
    // immutable episode columns and fifteen coupled local-kernel columns can
    // be put in the same proof as CTL::VALUE; the signed-range VALUE root
    // already verifies against both executed CTL sides.
    // This is still not semantic role closure: commitment openings, complete
    // manifests, missing hash relations and recursive execution remain open.
    return {
        {RCStage3RelationRole::EpisodeDeterministicBuilder, 4, 0, false, false,
         "header/params, seed chain and operand XOF are not connected to a "
         "complete builder child"},
        {RCStage3RelationRole::EpisodeGemm, 5, 4, false, false,
         "A/B/Y cells have executable same-trace CTL aliases and signed-range "
         "VALUE equality executes; operand/Y openings and sumcheck are not "
         "recursively joined"},
        {RCStage3RelationRole::EpisodeExtract, 5, 2, false, false,
         "sampler MIXED and dequant OUT have executable same-trace CTL "
         "aliases; input opening, all-tile closure, scale and ChaCha remain"},
        {RCStage3RelationRole::EpisodeWiring, 4, 1, false, false,
         "copy equality has an executable same-trace CTL alias; transpose, "
         "residual and round-order proof-root closure remain"},
        {RCStage3RelationRole::EpisodeTileTree, 4, 0, false, false,
         "hash manifests and boundary AIR execute, but stream/SSA CTL and "
         "recursive root consumption remain open"},
        {RCStage3RelationRole::EpisodeDigest, 4, 0, false, false,
         "typed SHA256d boundary exists without recursive round-root wiring"},
        {RCStage3RelationRole::CoupledBank, 3, 1, false, false,
         "the page-derived nibble cell is CTL-aliasable; seed-XOF, page "
         "inclusion and bank-root closure remain"},
        {RCStage3RelationRole::CoupledGemm, 4, 3, false, false,
         "A/B/OUT local-kernel cells are CTL-aliasable; operand/output "
         "openings, signed range and all-instance aggregation remain"},
        {RCStage3RelationRole::CoupledExchange, 3, 2, false, false,
         "input/output copy cells are CTL-aliasable; material hash-XOF and "
         "the public schedule remain"},
        {RCStage3RelationRole::CoupledPermutation, 2, 2, false, false,
         "input/output copy cells are CTL-aliasable; bit-affine index "
         "evaluation and committed root openings remain"},
        {RCStage3RelationRole::CoupledMix, 3, 3, false, false,
         "representative ranged input/arithmetic/output limbs are "
         "CTL-aliasable; full limb vectors and the mix schedule remain"},
        {RCStage3RelationRole::CoupledExtract, 5, 4, false, false,
         "input/sampler/scale/output cells are CTL-aliasable; ChaCha, int64 "
         "range, complete scale and output-root closure remain"},
        {RCStage3RelationRole::CoupledBarrier, 3, 0, false, false,
         "typed SHA256d manifest is not joined to state and output buses"},
        {RCStage3RelationRole::CoupledDigest, 3, 0, false, false,
         "typed final coupled hash lacks recursive bank/barrier inputs"},
    };
}

std::vector<RCStage3RelationEndpointCellAudit>
CurrentRCStage3RelationEndpointCellAudit()
{
    std::vector<RCStage3RelationEndpointCellAudit> out;
    out.reserve(kRCStage3RelationClosureEndpointCount);
    for (const RCStage3RelationRole role : RCStage3UnifiedRoleOrder()) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            out.push_back(CellAudit(role, endpoint));
        }
    }
    return out;
}

// ===========================================================================
// Commitment-opening AIR (blocker A).
//
// ONE AirConstraintSystem<Fp3>, proved by the standard batched-FRI backend.
// Two permutation strips share one trace:
//   * leaf strip  (perm block at base 0): Permute(v.c0,v.c1,v.c2,index,Le,0..)
//     — the alg_hash leaf hash of the relation cell.
//   * path strip  (Merkle-glue block at base kGluePermBase): one Compress level
//     per row, folding the accumulator up the authentication path.
// They are joined IN-CIRCUIT (not by host code):
//   * splice   (kFirstRow, 4 deg-1): path acc(row0) == leaf perm output(row0).
//   * position (kEverywhere, 1 deg-1 vs a public preprocessed column): the
//     direction bit each row equals the corresponding PUBLIC index bit, so the
//     statement is "cell is element `index`", not merely membership.
//   * root pin (kLastRow, 4 deg-1): terminal accumulator == committed root.
//   * value bind (kEverywhere, 1 deg-1): v == in0 + t*in1 + t^2*in2 binds the
//     value column (== CTL VALUE) to the three hashed leaf lanes.
// Honest witnesses divide exactly and verify; any tamper (cell, CTL value,
// sibling, direction, root) makes the quotient inexact and verification fail.
// ===========================================================================
namespace {

namespace ar = air_recurse;
namespace ah = alg_hash;
namespace aq = air_quotient;
namespace gf = gkr_field;

// Column layout of the unified opening trace.
constexpr uint32_t kLeafPermBase = 0;
constexpr uint32_t kValueCol = ar::kPermCellsPerPerm;               // 130
constexpr uint32_t kGluePermBase = kValueCol + 1;                   // 131
constexpr uint32_t kGlueDirCol = kGluePermBase + ar::kPermCellsPerPerm; // 261
constexpr uint32_t kGlueAccBase = kGlueDirCol + 1;                  // 262
constexpr uint32_t kGlueSibBase = kGlueAccBase + ah::kAlgHashDigestLen; // 266
constexpr uint32_t kExpectedDirCol =
    kGlueSibBase + ah::kAlgHashDigestLen;                          // 270
constexpr uint32_t kOpeningWidth = kExpectedDirCol + 1;            // 271

ar::PermLayout LeafPerm() { return ar::PermLayout{kLeafPermBase}; }
ar::MerkleGlueLayout GlueLayout()
{
    ar::MerkleGlueLayout g;
    g.perm = ar::PermLayout{kGluePermBase};
    g.dir_col = kGlueDirCol;
    g.acc_base = kGlueAccBase;
    g.sib_base = kGlueSibBase;
    return g;
}

// ---------------------------------------------------------------------------
// Poseidon (alg_hash) vector commitment — the re-anchored production root.
//
// Following ProductionProgramConsensusPinV1 (recursive_alg_hash_root is the
// sole authority; the SHA256d root is transport/audit-only), endpoint vector
// commitments are re-anchored to this Poseidon tree.  leaf_i = LeafHash(v_i, i)
// (index-bound), folded pairwise with the fixed 2->1 Compress — the EXACT tree
// OpenRCStage3EndpointCommitment authenticates in-AIR.  The alg_hash cap-256
// binding gives the same 2^128 floor as SHA256d, so this is an authority swap,
// not a soundness change.
// ---------------------------------------------------------------------------
ah::Digest VectorRootAlg(const std::vector<gf::Fp3>& values)
{
    uint32_t n = 1;
    while (n < values.size()) n <<= 1;
    std::vector<ah::Digest> level(n);
    for (uint32_t i = 0; i < n; ++i) {
        const gf::Fp3 v = i < values.size() ? values[i] : gf::Fp3::Zero();
        level[i] = ah::LeafHash(v, i);
    }
    while (level.size() > 1) {
        std::vector<ah::Digest> next(level.size() / 2);
        for (uint32_t k = 0; k < next.size(); ++k) {
            next[k] = ah::Compress(level[2 * k], level[2 * k + 1]);
        }
        level = std::move(next);
    }
    return level[0];
}

// Real authentication path of leaf `index` in the VectorRootAlg tree over
// `values` (|values| must be a power of two).  Siblings are genuine subtree
// roots (not synthetic); directions are the leaf-index bits.
struct VectorAlgPath {
    ah::Digest committed_leaf{};
    std::vector<ah::Digest> siblings;
    std::vector<bool> directions;
    ah::Digest root{};
};
VectorAlgPath BuildVectorAlgPath(const std::vector<gf::Fp3>& values, uint32_t index)
{
    VectorAlgPath out;
    const uint32_t n = static_cast<uint32_t>(values.size());
    std::vector<ah::Digest> level(n);
    for (uint32_t i = 0; i < n; ++i) level[i] = ah::LeafHash(values[i], i);
    out.committed_leaf = level[index];
    uint32_t idx = index;
    while (level.size() > 1) {
        const uint32_t sib = idx ^ 1U;
        out.siblings.push_back(level[sib]);
        out.directions.push_back((idx & 1U) != 0U);
        std::vector<ah::Digest> next(level.size() / 2);
        for (uint32_t k = 0; k < next.size(); ++k) {
            next[k] = ah::Compress(level[2 * k], level[2 * k + 1]);
        }
        level = std::move(next);
        idx >>= 1;
    }
    out.root = level[0];
    return out;
}

// LeafHash(cell, index) input state: [c0, c1, c2, index, leaf_domain, 0..].
ah::State LeafInputState(const gf::Fp3& cell, uint32_t index)
{
    ah::State s{};
    s[0] = gf::Canonical(cell.c0);
    s[1] = gf::Canonical(cell.c1);
    s[2] = gf::Canonical(cell.c2);
    s[3] = gf::FromU64(index);
    s[4] = ah::GetAlgHashConstants().leaf_domain;
    return s;
}

// Build the single proved opening AIR for a fixed public index/depth and
// committed root.  n_rows = path_len + 1 (must be a power of two); only the
// index bits (preprocessed) and the root (constants) are public.
aq::AirConstraintSystem<gf::Fp3> BuildOpeningConstraintSystem(
    uint32_t index, const ah::Digest& committed_root, uint32_t path_len)
{
    const ar::PermLayout leaf = LeafPerm();
    const ar::MerkleGlueLayout glue = GlueLayout();

    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = path_len + 1;
    cs.n_columns = kOpeningWidth;

    // Leaf permutation honesty (118 real S-box identities).
    for (auto& c : ar::BuildPermRoundConstraints(leaf)) cs.constraints.push_back(std::move(c));
    // Fixed leaf input pins (index lane, leaf-domain capacity, zero tail).
    const gf::Fp3 idx = gf::Fp3::FromFp(gf::FromU64(index));
    const gf::Fp3 dom = gf::Fp3::FromFp(ah::GetAlgHashConstants().leaf_domain);
    for (uint32_t lane = 3; lane < ar::kPermInputCells; ++lane) {
        gf::Fp3 want = gf::Fp3::Zero();
        if (lane == 3) want = idx;
        else if (lane == 4) want = dom;
        const uint32_t col = leaf.InputCol(lane);
        cs.constraints.push_back({"opening:leaf_input_pin", aq::AirKind::kEverywhere, 1,
                                  [col, want](const std::vector<gf::Fp3>& cur,
                                              const std::vector<gf::Fp3>&) {
                                      return gf::Sub(cur[col], want);
                                  }});
    }
    // CTL-value binding: v == in0 + t*in1 + t^2*in2 (deg 1).
    {
        const gf::Fp3 t{0, 1, 0};
        const gf::Fp3 t2{0, 0, 1};
        const uint32_t in0 = leaf.InputCol(0);
        const uint32_t in1 = leaf.InputCol(1);
        const uint32_t in2 = leaf.InputCol(2);
        cs.constraints.push_back({"opening:ctl_value_bind", aq::AirKind::kEverywhere, 1,
                                  [in0, in1, in2, t, t2](const std::vector<gf::Fp3>& cur,
                                                         const std::vector<gf::Fp3>&) {
                                      const gf::Fp3 recomposed = gf::Add(
                                          cur[in0],
                                          gf::Add(gf::Mul(t, cur[in1]), gf::Mul(t2, cur[in2])));
                                      return gf::Sub(cur[kValueCol], recomposed);
                                  }});
    }

    // Path permutation honesty + Merkle-glue wiring.
    for (auto& c : ar::BuildPermRoundConstraints(glue.perm)) cs.constraints.push_back(std::move(c));
    for (auto& c : ar::BuildMerkleGlueConstraints(glue)) cs.constraints.push_back(std::move(c));

    // Splice (kFirstRow): path accumulator row 0 == leaf permutation output.
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) {
        const uint32_t acc = glue.acc_base + j;
        cs.constraints.push_back({"opening:leaf_path_splice", aq::AirKind::kFirstRow, 1,
                                  [leaf, acc, j](const std::vector<gf::Fp3>& cur,
                                                 const std::vector<gf::Fp3>&) {
                                      return gf::Sub(cur[acc], ar::PermOutputLane(leaf, cur, j));
                                  }});
    }

    // Position pin (deg 1): direction bit each row equals the PUBLIC index bit.
    cs.constraints.push_back({"opening:position_index_bit", aq::AirKind::kEverywhere, 1,
                              [](const std::vector<gf::Fp3>& cur,
                                 const std::vector<gf::Fp3>&) {
                                  return gf::Sub(cur[kGlueDirCol], cur[kExpectedDirCol]);
                              }});

    // Terminal accumulator pinned to the committed manifest root (kLastRow).
    for (auto& c : ar::BuildMerkleRootBoundaryConstraints(glue.acc_base, committed_root)) {
        cs.constraints.push_back(std::move(c));
    }

    // The public index-bit column is verifier-owned preprocessing making the
    // direction pins a public-position statement.  It is OOD-pinned (canonical
    // values pinned through the batch dual-OOD DEEP evals) rather than bound by a
    // per-column Merkle root, because the row-wise AlgB3 recursion backend has no
    // per-column roots (preprocessed_roots is unsupported there).
    std::vector<gf::Fp3> expected(cs.n_rows, gf::Fp3::Zero());
    for (uint32_t l = 0; l < path_len; ++l) {
        expected[l] = ((index >> l) & 1U) ? gf::Fp3::One() : gf::Fp3::Zero();
    }
    cs.preprocessed.push_back({kExpectedDirCol, std::move(expected)});
    cs.preprocessed_pin_ood = true;
    return cs;
}

// Honest witness columns for (cell, ctl_value) against a manifest.
std::vector<std::vector<gf::Fp3>> BuildOpeningWitness(
    const gf::Fp3& cell, const gf::Fp3& ctl_value,
    const RCStage3CommitmentManifest& manifest)
{
    const ar::PermLayout leaf = LeafPerm();
    const ar::MerkleGlueLayout glue = GlueLayout();
    const uint32_t path_len = static_cast<uint32_t>(manifest.siblings.size());
    const uint32_t rows = path_len + 1;
    const ar::PermWitness leaf_w =
        ar::BuildPermWitness(LeafInputState(cell, manifest.leaf_index));

    std::vector<std::vector<gf::Fp3>> row_major(rows,
                                                std::vector<gf::Fp3>(kOpeningWidth, gf::Fp3::Zero()));
    ah::Digest acc{};
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) acc[j] = leaf_w.output[j];
    for (uint32_t r = 0; r < rows; ++r) {
        std::vector<gf::Fp3>& row = row_major[r];
        ar::WritePermWitness(leaf, leaf_w, row);
        row[kValueCol] = ctl_value;
        if (r < path_len) {
            ah::Digest parent{};
            ar::FillMerkleGlueRow(glue, acc, manifest.siblings[r],
                                  manifest.directions[r], row, &parent);
            acc = parent;
            row[kExpectedDirCol] = manifest.directions[r] ? gf::Fp3::One() : gf::Fp3::Zero();
        } else {
            // Terminal row: honest dummy glue block carrying the folded root.
            ar::FillMerkleGlueRow(glue, acc, ah::Digest{0, 0, 0, 0}, false, row, nullptr);
            row[kExpectedDirCol] = gf::Fp3::Zero();
        }
    }
    // AirQuotientProve consumes column-major witness (one vector per column).
    std::vector<std::vector<gf::Fp3>> cols(kOpeningWidth,
                                           std::vector<gf::Fp3>(rows, gf::Fp3::Zero()));
    for (uint32_t r = 0; r < rows; ++r) {
        for (uint32_t c = 0; c < kOpeningWidth; ++c) cols[c][r] = row_major[r][c];
    }
    return cols;
}

uint256 OpeningSeed(RCStage3RelationEndpoint endpoint, const ah::Digest& root)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_COMMITMENT_OPENING_V1";
    hash << kRCStage3RelationClosureVersion;
    hash << static_cast<uint16_t>(endpoint);
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) {
        hash << static_cast<uint64_t>(gf::Canonical(root[j]));
    }
    return hash.GetHash();
}

bool IsPow2(uint32_t x) { return x != 0 && (x & (x - 1)) == 0; }

} // namespace

bool RCStage3EndpointHasCommitmentOpening(RCStage3RelationEndpoint endpoint)
{
    return IsOpenedRelationEndpoint(endpoint);
}

uint32_t RCStage3CommitmentOpeningEndpointCount()
{
    uint32_t n = 0;
    for (const RCStage3RelationRole role : RCStage3UnifiedRoleOrder()) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            if (IsOpenedRelationEndpoint(endpoint)) ++n;
        }
    }
    return n;
}

RCStage3CommitmentManifest BuildRCStage3CanonicalManifest(
    RCStage3RelationEndpoint endpoint,
    const gf::Fp3& cell,
    uint32_t leaf_index,
    uint32_t path_len)
{
    // A REAL VectorRootAlg tree over 2^path_len committed values (the cell at
    // `leaf_index`, deterministic filler elsewhere): siblings are genuine
    // subtree roots and committed_root == VectorRootAlg(values).  This retires
    // the former synthetic per-level sibling formula.
    RCStage3CommitmentManifest m;
    const uint32_t n = 1U << path_len;
    const uint32_t index = leaf_index % n;
    std::vector<gf::Fp3> values(n);
    const uint64_t e = static_cast<uint64_t>(endpoint);
    for (uint32_t i = 0; i < n; ++i) {
        values[i] = (i == index)
                        ? cell
                        : gf::Fp3::FromFp(gf::FromU64(e * 1000003ULL + i * 131ULL + 7ULL));
    }
    const VectorAlgPath path = BuildVectorAlgPath(values, index);
    m.leaf_index = index;
    m.committed_leaf = path.committed_leaf;
    m.siblings = path.siblings;
    m.directions = path.directions;
    m.committed_root = path.root;
    return m;
}

RCStage3CommitmentManifest BuildRCStage3VectorManifest(
    RCStage3RelationEndpoint endpoint,
    const std::vector<gf::Fp3>& values,
    uint32_t index)
{
    (void)endpoint;
    // Smallest fixed T-BIND depth in {1,3,7,15} (so rows = depth+1 is a power of
    // two) that covers the value column and the opened index.
    const uint32_t need = std::max<uint32_t>(
        static_cast<uint32_t>(values.size()), index + 1U);
    uint32_t depth = 15;
    for (const uint32_t cand : {1U, 3U, 7U, 15U}) {
        if ((1U << cand) >= need) { depth = cand; break; }
    }
    const uint32_t n = 1U << depth;
    std::vector<gf::Fp3> padded(n, gf::Fp3::Zero());
    for (uint32_t i = 0; i < values.size() && i < n; ++i) padded[i] = values[i];

    const VectorAlgPath path = BuildVectorAlgPath(padded, index);
    RCStage3CommitmentManifest m;
    m.leaf_index = index;
    m.committed_leaf = path.committed_leaf;
    m.siblings = path.siblings;
    m.directions = path.directions;
    m.committed_root = path.root;
    return m;
}

alg_hash::Digest RCStage3ComputeVectorRootAlg(const std::vector<gf::Fp3>& values)
{
    return VectorRootAlg(values);
}

uint256 RCStage3VectorRootAlgCommitment(const std::vector<gf::Fp3>& values)
{
    const alg_hash::Digest d = VectorRootAlg(values);
    std::array<unsigned char, 32> bytes{};
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashDigestLen; ++lane) {
        const uint64_t v = static_cast<uint64_t>(gf::Canonical(d[lane]));
        for (uint32_t k = 0; k < 8; ++k) {
            bytes[lane * 8 + k] = static_cast<unsigned char>((v >> (8 * k)) & 0xFF);
        }
    }
    return uint256{Span<const unsigned char>{bytes.data(), bytes.size()}};
}

bool RCStage3EndpointHasVectorOpening(RCStage3RelationEndpoint endpoint)
{
    return IsVectorOpenedEndpoint(endpoint);
}

uint32_t RCStage3VectorOpeningEndpointCount()
{
    uint32_t n = 0;
    for (const RCStage3RelationRole role : RCStage3UnifiedRoleOrder()) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            if (IsVectorOpenedEndpoint(endpoint)) ++n;
        }
    }
    return n;
}

bool RCStage3EndpointIsWiredBinding(RCStage3RelationEndpoint endpoint)
{
    return IsWiredBindingEndpoint(endpoint);
}

uint32_t RCStage3WiredBindingEndpointCount()
{
    uint32_t n = 0;
    for (const RCStage3RelationRole role : RCStage3UnifiedRoleOrder()) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            if (IsWiredBindingEndpoint(endpoint)) ++n;
        }
    }
    return n;
}

RCStage3CommitmentOpening OpenRCStage3EndpointCommitment(
    RCStage3RelationEndpoint endpoint,
    const gf::Fp3& cell,
    const gf::Fp3& ctl_value,
    const RCStage3CommitmentManifest& manifest,
    std::string* why)
{
    RCStage3CommitmentOpening out;
    out.endpoint = endpoint;
    out.path_len = static_cast<uint32_t>(manifest.siblings.size());

    if (manifest.siblings.size() != manifest.directions.size() ||
        manifest.siblings.empty() || !IsPow2(out.path_len + 1)) {
        out.note = "path_shape";
        if (why != nullptr) *why = "stage3:commitment_opening:path_shape";
        return out;
    }

    const auto cs = BuildOpeningConstraintSystem(manifest.leaf_index,
                                                 manifest.committed_root, out.path_len);
    const auto columns = BuildOpeningWitness(cell, ctl_value, manifest);
    const uint256 seed = OpeningSeed(endpoint, manifest.committed_root);

    const auto proved = aq::AirQuotientProve<gf::Fp3>(cs, columns, seed);
    out.prover_ok = proved.ok;
    out.division_exact = proved.ok && proved.division_exact;

    std::string vwhy;
    out.verified = out.division_exact &&
                   aq::AirQuotientVerify<gf::Fp3>(cs, proved.proof, seed, &vwhy);

    out.leaf_consistent = out.division_exact;
    out.ctl_value_bound = out.division_exact;

    // Independent recompute of the folded root for the report field only.
    ah::Digest acc = ah::LeafHash(cell, manifest.leaf_index);
    for (uint32_t l = 0; l < out.path_len; ++l) {
        acc = manifest.directions[l] ? ah::Compress(manifest.siblings[l], acc)
                                     : ah::Compress(acc, manifest.siblings[l]);
    }
    bool root_eq = true;
    for (uint32_t k = 0; k < ah::kAlgHashDigestLen; ++k) {
        if (gf::Canonical(acc[k]) != gf::Canonical(manifest.committed_root[k])) root_eq = false;
    }
    out.root_matches_manifest = root_eq;

    out.opens = out.verified && out.ctl_value_bound && out.leaf_consistent &&
                out.root_matches_manifest;
    out.note = out.opens ? "opens" : (out.prover_ok ? "violation" : "prover_failed");
    if (why != nullptr) {
        *why = out.opens ? "stage3:commitment_opening:opens"
                         : ("stage3:commitment_opening:" + out.note +
                            (vwhy.empty() ? "" : ":" + vwhy));
    }
    return out;
}

// ===========================================================================
// Composable opening block + role-AIR direct product (C_rho assembly core).
// ===========================================================================

aq::AirConstraintSystem<gf::Fp3> BuildRCStage3OpeningConstraintSystem(
    uint32_t leaf_index, const ah::Digest& committed_root, uint32_t path_len)
{
    return BuildOpeningConstraintSystem(leaf_index, committed_root, path_len);
}

std::vector<std::vector<gf::Fp3>> BuildRCStage3OpeningWitness(
    const gf::Fp3& cell, const gf::Fp3& ctl_value,
    const RCStage3CommitmentManifest& manifest)
{
    return BuildOpeningWitness(cell, ctl_value, manifest);
}

bool RCStage3RoleIsInCsScalarOpenable(RCStage3RelationRole role)
{
    // Only the composable-kernel coupled roles whose EVERY required endpoint is
    // a same-trace scalar opening with a resolvable kernel column.
    switch (role) {
    case RCStage3RelationRole::CoupledPermutation:
    case RCStage3RelationRole::CoupledMix:
        break;
    default:
        return false;
    }
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (required.empty()) return false;
    for (const RCStage3RelationEndpoint e : required) {
        if (!IsOpenedRelationEndpoint(e)) return false;
        if (!CoupledEndpointColumn(e, role).has_value()) return false;
    }
    return true;
}

bool RCStage3RoleIsInCsClosable(RCStage3RelationRole role)
{
    if (RCStage3RoleIsInCsScalarOpenable(role)) return true;
    // Mixed scalar + wired ledger-fold roles.
    //   CoupledGemm  : A/B/Y scalar + SignedRange wired.
    //   EpisodeGemm  : A/B/Y scalar + Sumcheck wired + SignedRange wired.
    //   EpisodeWiring: Copy scalar + Transpose/Residual/RoundOrder wired.
    if (role == RCStage3RelationRole::CoupledGemm ||
        role == RCStage3RelationRole::EpisodeGemm ||
        role == RCStage3RelationRole::EpisodeWiring ||
        role == RCStage3RelationRole::CoupledExchange ||
        role == RCStage3RelationRole::CoupledBank ||
        role == RCStage3RelationRole::EpisodeDeterministicBuilder ||
        role == RCStage3RelationRole::CoupledExtract ||
        role == RCStage3RelationRole::EpisodeExtract) {
        return true;
    }
    // CompositionLink (role 32) — the fifteenth relation. It carries NO entry in
    // RequiredRCStage3RelationEndpoints (that registry is the semantic CTL/site
    // manifest and is deliberately left alone), so it can never become closable
    // via RCStage3RoleIsPureStream; its closer is named explicitly here and its
    // in-CS closer count comes from kRCStage3CompositionLinkInCsClosers below.
    // See BuildRCStage3CompositionLinkRoleAirCS for exactly what it does and
    // does not prove.
    if (role == RCStage3RelationRole::CompositionLink) return true;
    // Pure §4 stream roles (light binding fragment per endpoint; SHA fold is the
    // deferred aggregation child): CoupledBarrier/Digest, EpisodeTileTree/Digest.
    return RCStage3RoleIsPureStream(role);
}

uint32_t RCStage3RequiredInCsOpeningBlocks(RCStage3RelationRole role)
{
    if (!RCStage3RoleIsInCsClosable(role)) return 0;
    // CompositionLink's endpoints are not in the semantic endpoint registry
    // (RequiredRCStage3RelationEndpoints returns EMPTY_ENDPOINTS for it), so
    // deriving the count from that registry would return 0 and the completeness
    // gate in RebuildRCStage3RoleAirConstraintSystem would accept a
    // ZERO-CLOSER CompositionLink AIR. The count is stated here instead so the
    // gate genuinely bites: two §4 leg bindings + one sponge ledger fold.
    if (role == RCStage3RelationRole::CompositionLink) {
        return kRCStage3CompositionLinkInCsClosers;
    }
    return static_cast<uint32_t>(
        RequiredRCStage3RelationEndpoints(role).size());
}

uint32_t RCStage3CountInCsOpeningBlocks(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    // One alg_hash opening block per "opening:ctl_value_bind" — covers both
    // kernel-aliased scalar openings and standalone vector openings.
    uint32_t n = 0;
    for (const auto& c : cs.constraints) {
        if (c.name != nullptr &&
            std::string(c.name) == "opening:ctl_value_bind") {
            ++n;
        }
    }
    return n;
}

uint32_t RCStage3CountInCsClosers(const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    // alg_hash opening blocks (scalar/vector) + wired ledger-fold closers (each
    // contributes kAlgHashDigestLen sponge digest_pin families) + §4 stream
    // binding fragments (one stream_endpoint:value_alias each).
    uint32_t openings = RCStage3CountInCsOpeningBlocks(cs);
    uint32_t digest_pins = 0;
    uint32_t stream = 0;
    for (const auto& c : cs.constraints) {
        if (c.name == nullptr) continue;
        const std::string name(c.name);
        if (name == "sponge:digest_pin") ++digest_pins;
        else if (name == "stream_endpoint:value_alias") ++stream;
    }
    return openings + digest_pins / ah::kAlgHashDigestLen + stream;
}

namespace {

// Shared spine: compose the role's fragment kernel + one opening block per
// required endpoint (pinned to committed_roots[i]) + the deg-1 boundary alias
// tying each opening value column to the endpoint's kernel column.  Fills the
// product CS and the per-endpoint value-column list.  Witness is built by the
// caller (resolver: none; assembly test: from the manifests).
bool AssembleScalarRoleAirCS(
    RCStage3RelationRole role,
    const std::vector<ah::Digest>& committed_roots,
    uint32_t path_len,
    uint32_t leaf_index,
    aq::AirConstraintSystem<gf::Fp3>& product,
    uint32_t& fragment_columns,
    std::vector<RCStage3RelationEndpoint>& endpoints_out,
    std::vector<uint32_t>& value_columns_out,
    std::string* why)
{
    product = {};
    endpoints_out.clear();
    value_columns_out.clear();
    fragment_columns = 0;

    if (path_len == 0 || !IsPow2(path_len + 1)) {
        if (why != nullptr) *why = "stage3:role_air:path_shape";
        return false;
    }
    if (!RCStage3RoleIsInCsScalarOpenable(role)) {
        if (why != nullptr) *why = "stage3:role_air:role_not_scalar_openable";
        return false;
    }
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (committed_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:role_air:root_count";
        return false;
    }
    const uint32_t rows = path_len + 1;

    constraint_bytecode::ProgramTable kernel_table;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(role, kernel_table, why)) {
        return false;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kernel_table, rows, kernel_cs, why)) {
        return false;
    }
    const uint32_t kernel_w = kernel_cs.n_columns;

    product.n_rows = rows;
    CopyConstraintFamily(kernel_cs, 0, product);

    uint32_t next_col = kernel_w;
    for (uint32_t e = 0; e < required.size(); ++e) {
        const std::optional<uint32_t> k_col =
            CoupledEndpointColumn(required[e], role);
        if (!k_col.has_value() || *k_col >= kernel_w) {
            if (why != nullptr) *why = "stage3:role_air:endpoint_column";
            return false;
        }
        const aq::AirConstraintSystem<gf::Fp3> open_cs =
            BuildOpeningConstraintSystem(leaf_index, committed_roots[e],
                                         path_len);
        if (open_cs.n_columns != kRCStage3OpeningWidth) {
            if (why != nullptr) *why = "stage3:role_air:opening_width";
            return false;
        }
        const uint32_t base = next_col;
        CopyConstraintFamily(open_cs, base, product);
        const uint32_t v_col = base + kRCStage3OpeningValueColumn;
        const uint32_t kc = *k_col;
        product.constraints.push_back(
            {"role_air:endpoint_value_alias", aq::AirKind::kEverywhere, 1,
             [kc, v_col](const std::vector<gf::Fp3>& cur,
                         const std::vector<gf::Fp3>&) {
                 return gf::Sub(cur[kc], cur[v_col]);
             }});
        endpoints_out.push_back(required[e]);
        value_columns_out.push_back(v_col);
        next_col += kRCStage3OpeningWidth;
    }
    product.n_columns = next_col;
    fragment_columns = kernel_w;
    return true;
}

// Build a SATISFYING kernel witness (column-major, kernel_w x rows) for a
// fully-scalar coupled role. Every kernel column is filled and constant across
// rows (all kernel constraints are kEverywhere), so the deg-1 endpoint value
// aliases to the constant opening value hold on every row.
// `real_mix` (optional): when set, the CoupledMix adder consumes these REAL
// 64-bit operands (a,b), each as four little-endian 16-bit limbs, instead of the
// synthetic constants — so the proved sum=a+b / diff=b-a relation is over real
// block-derived values.  Null => synthetic (unchanged shipped behavior).
bool BuildScalarRoleKernelWitness(
    RCStage3RelationRole role, uint32_t kernel_w, uint32_t rows,
    std::vector<std::vector<gf::Fp3>>& cols, std::string* why,
    const std::array<uint32_t, 4>* real_mix_a = nullptr,
    const std::array<uint32_t, 4>* real_mix_b = nullptr)
{
    using namespace coupled_air_col;
    cols.assign(kernel_w, std::vector<gf::Fp3>(rows, gf::Fp3::Zero()));
    auto set = [&](uint32_t c, uint64_t v) {
        if (c >= kernel_w) return;
        const gf::Fp3 f = gf::Fp3::FromFp(gf::FromU64(v));
        for (uint32_t r = 0; r < rows; ++r) cols[c][r] = f;
    };
    if (role == RCStage3RelationRole::CoupledPermutation) {
        const uint64_t cell = 0x1234567ULL;
        set(COPY_INPUT, cell);
        set(COPY_OUTPUT, cell); // copy relation: output == input
        return true;
    }
    if (role == RCStage3RelationRole::CoupledMix) {
        const std::array<uint32_t, 4> a =
            real_mix_a != nullptr ? *real_mix_a
                                  : std::array<uint32_t, 4>{0x1234u, 0x5678u,
                                                            0x9abcu, 0xdef0u};
        const std::array<uint32_t, 4> b =
            real_mix_b != nullptr ? *real_mix_b
                                  : std::array<uint32_t, 4>{0x1111u, 0x2222u,
                                                            0x3333u, 0x4444u};
        std::array<uint32_t, 4> sum{}, carry{}, diff{}, borrow{};
        uint32_t cin = 0, bin = 0;
        for (uint32_t l = 0; l < 4; ++l) {
            const uint32_t s = a[l] + b[l] + cin;
            sum[l] = s & 0xFFFFu;
            carry[l] = s >> 16;
            cin = carry[l];
            int32_t d = static_cast<int32_t>(b[l]) - static_cast<int32_t>(a[l]) -
                        static_cast<int32_t>(bin);
            if (d < 0) { d += 0x10000; borrow[l] = 1; } else { borrow[l] = 0; }
            diff[l] = static_cast<uint32_t>(d);
            bin = borrow[l];
        }
        const std::array<uint32_t, 16> arith = {
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3],
            sum[0], sum[1], sum[2], sum[3], diff[0], diff[1], diff[2], diff[3]};
        for (uint32_t limb = 0; limb < 16; ++limb) {
            set(limb, arith[limb]); // MIX_A/B/SUM/DIFF limbs, cols 0..15
            for (uint32_t bit = 0; bit < 16; ++bit) {
                set(MIX_BITS + limb * 16u + bit, (arith[limb] >> bit) & 1u);
            }
        }
        for (uint32_t l = 0; l < 4; ++l) {
            set(MIX_CARRY + l, carry[l]);
            set(MIX_BORROW + l, borrow[l]);
        }
        return true;
    }
    if (why != nullptr) *why = "stage3:role_air:kernel_witness_unsupported";
    return false;
}

} // namespace

bool BuildRCStage3CoupledScalarRoleAirCS(
    RCStage3RelationRole role,
    const std::vector<ah::Digest>& endpoint_roots,
    uint32_t path_len,
    aq::AirConstraintSystem<gf::Fp3>& out,
    std::string* why)
{
    uint32_t fragment_columns = 0;
    std::vector<RCStage3RelationEndpoint> endpoints;
    std::vector<uint32_t> value_columns;
    return AssembleScalarRoleAirCS(role, endpoint_roots, path_len,
                                   /*leaf_index=*/0, out, fragment_columns,
                                   endpoints, value_columns, why);
}

RCStage3RoleAirProduct BuildRCStage3CoupledScalarRoleAir(
    RCStage3RelationRole role, uint32_t leaf_index, uint32_t path_len,
    std::string* why, const std::array<uint32_t, 4>* real_mix_a,
    const std::array<uint32_t, 4>* real_mix_b)
{
    RCStage3RoleAirProduct out;
    out.role = role;
    if (path_len == 0 || !IsPow2(path_len + 1)) {
        out.note = "path_shape";
        if (why != nullptr) *why = "stage3:role_air:path_shape";
        return out;
    }
    if (!RCStage3RoleIsInCsScalarOpenable(role)) {
        out.note = "role";
        if (why != nullptr) *why = "stage3:role_air:role_not_scalar_openable";
        return out;
    }
    const uint32_t rows = path_len + 1;
    const auto& required = RequiredRCStage3RelationEndpoints(role);

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(role, kt, why)) {
        out.note = "kernel_bytecode";
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> kcs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kcs, why)) {
        out.note = "kernel_air";
        return out;
    }
    const uint32_t kernel_w = kcs.n_columns;

    std::vector<std::vector<gf::Fp3>> kernel_cols;
    if (!BuildScalarRoleKernelWitness(role, kernel_w, rows, kernel_cols, why,
                                      real_mix_a, real_mix_b)) {
        out.note = "kernel_witness";
        return out;
    }

    // Read each endpoint cell from its kernel column and build its manifest.
    std::vector<ah::Digest> roots;
    std::vector<RCStage3CommitmentManifest> manifests;
    std::vector<gf::Fp3> cells;
    for (const RCStage3RelationEndpoint e : required) {
        const std::optional<uint32_t> k = CoupledEndpointColumn(e, role);
        if (!k.has_value() || *k >= kernel_w) {
            out.note = "endpoint_column";
            return out;
        }
        const gf::Fp3 cell = kernel_cols[*k][0];
        const RCStage3CommitmentManifest m =
            BuildRCStage3CanonicalManifest(e, cell, leaf_index, path_len);
        roots.push_back(m.committed_root);
        manifests.push_back(m);
        cells.push_back(cell);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    uint32_t fragment_columns = 0;
    std::vector<RCStage3RelationEndpoint> endpoints;
    std::vector<uint32_t> value_columns;
    if (!AssembleScalarRoleAirCS(role, roots, path_len, leaf_index, product,
                                 fragment_columns, endpoints, value_columns,
                                 why)) {
        out.note = "assemble";
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness = std::move(kernel_cols);
    for (uint32_t e = 0; e < manifests.size(); ++e) {
        std::vector<std::vector<gf::Fp3>> ow =
            BuildOpeningWitness(cells[e], cells[e], manifests[e]);
        if (ow.size() != kRCStage3OpeningWidth) {
            out.note = "opening_witness";
            return out;
        }
        for (auto& col : ow) witness.push_back(std::move(col));
    }

    out.endpoints = std::move(endpoints);
    out.endpoint_value_columns = std::move(value_columns);
    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = fragment_columns;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

RCStage3RoleAirProduct BuildRCStage3CoupledPermutationRoleAir(
    const gf::Fp3& cell, uint32_t leaf_index, uint32_t path_len,
    std::string* why)
{
    RCStage3RoleAirProduct out;
    out.role = RCStage3RelationRole::CoupledPermutation;

    if (path_len == 0 || !IsPow2(path_len + 1)) {
        out.note = "path_shape";
        if (why != nullptr) *why = "stage3:role_air:coupled_permutation:path_shape";
        return out;
    }
    const auto& required = RequiredRCStage3RelationEndpoints(
        RCStage3RelationRole::CoupledPermutation);

    // Canonical manifests give the real committed roots + siblings + the leaf
    // cell used for the honest witness.  The honest copy sets every endpoint
    // cell == `cell`.
    std::vector<ah::Digest> roots;
    std::vector<RCStage3CommitmentManifest> manifests;
    roots.reserve(required.size());
    manifests.reserve(required.size());
    for (const RCStage3RelationEndpoint e : required) {
        const RCStage3CommitmentManifest m =
            BuildRCStage3CanonicalManifest(e, cell, leaf_index, path_len);
        roots.push_back(m.committed_root);
        manifests.push_back(m);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    uint32_t fragment_columns = 0;
    std::vector<RCStage3RelationEndpoint> endpoints;
    std::vector<uint32_t> value_columns;
    if (!AssembleScalarRoleAirCS(RCStage3RelationRole::CoupledPermutation, roots,
                                 path_len, leaf_index, product, fragment_columns,
                                 endpoints, value_columns, why)) {
        out.note = "assemble";
        return out;
    }
    const uint32_t rows = path_len + 1;

    // Joint witness: kernel copy (output == input == cell) then each opening
    // block's honest witness, laid side by side on the shared rows.
    std::vector<std::vector<gf::Fp3>> witness;
    witness.reserve(product.n_columns);
    for (uint32_t c = 0; c < fragment_columns; ++c)
        witness.emplace_back(rows, cell);
    for (uint32_t e = 0; e < manifests.size(); ++e) {
        const std::vector<std::vector<gf::Fp3>> ow =
            BuildOpeningWitness(cell, cell, manifests[e]);
        if (ow.size() != kRCStage3OpeningWidth) {
            out.note = "opening_witness";
            if (why != nullptr)
                *why = "stage3:role_air:coupled_permutation:opening_witness";
            return out;
        }
        for (const auto& col : ow) witness.push_back(col);
    }

    out.endpoints = std::move(endpoints);
    out.endpoint_value_columns = std::move(value_columns);
    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = fragment_columns;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

bool BuildRCStage3CoupledGemmRoleAirCS(
    const std::vector<ah::Digest>& endpoint_roots, uint32_t path_len,
    aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    using namespace coupled_air_col;
    out = {};
    const auto& required =
        RequiredRCStage3RelationEndpoints(RCStage3RelationRole::CoupledGemm);
    if (endpoint_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:gemm_cs:root_count";
        return false;
    }
    const uint32_t rows = path_len + 1;

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(
            RCStage3RelationRole::CoupledGemm, kt, why)) {
        return false;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        return false;
    }
    if (kernel_cs.n_columns != GEMM_NUM_COLS) {
        if (why != nullptr) *why = "stage3:gemm_cs:kernel_width";
        return false;
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = rows;
    CopyConstraintFamily(kernel_cs, 0, product);
    uint32_t next_col = GEMM_NUM_COLS;

    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (IsWiredBindingEndpoint(e)) {
            aq::AirConstraintSystem<gf::Fp3> wired_cs;
            if (!BuildRCStage3SignedRangeWiredCloserCS(endpoint_roots[i],
                                                       wired_cs, why)) {
                return false;
            }
            if (wired_cs.n_rows != rows) {
                if (why != nullptr) *why = "stage3:gemm_cs:wired_rows";
                return false;
            }
            CopyConstraintFamily(wired_cs, next_col, product);
            next_col += wired_cs.n_columns;
        } else {
            const std::optional<uint32_t> kc =
                CoupledEndpointColumn(e, RCStage3RelationRole::CoupledGemm);
            if (!kc.has_value() || *kc >= GEMM_NUM_COLS) {
                if (why != nullptr) *why = "stage3:gemm_cs:endpoint_column";
                return false;
            }
            const aq::AirConstraintSystem<gf::Fp3> open_cs =
                BuildOpeningConstraintSystem(0, endpoint_roots[i], path_len);
            if (open_cs.n_columns != kRCStage3OpeningWidth) {
                if (why != nullptr) *why = "stage3:gemm_cs:opening_width";
                return false;
            }
            const uint32_t base = next_col;
            CopyConstraintFamily(open_cs, base, product);
            const uint32_t v_col = base + kRCStage3OpeningValueColumn;
            const uint32_t k = *kc;
            product.constraints.push_back(
                {"role_air:endpoint_value_alias", aq::AirKind::kEverywhere, 1,
                 [k, v_col](const std::vector<gf::Fp3>& cur,
                            const std::vector<gf::Fp3>&) {
                     return gf::Sub(cur[k], cur[v_col]);
                 }});
            next_col += kRCStage3OpeningWidth;
        }
    }
    product.n_columns = next_col;
    out = std::move(product);
    return true;
}

namespace {

// Leaf-lane count of each wired ledger-fold endpoint's LeafHashRow row.
uint32_t WiredEndpointLeafLanes(RCStage3RelationEndpoint e)
{
    switch (e) {
    case RCStage3RelationEndpoint::CoupledGemmSignedRange:
    case RCStage3RelationEndpoint::EpisodeGemmSignedRange: return 13;
    case RCStage3RelationEndpoint::EpisodeGemmSumcheck: return 6;
    case RCStage3RelationEndpoint::EpisodeWiringTranspose: return 21;
    case RCStage3RelationEndpoint::EpisodeWiringResidual: return 18;
    case RCStage3RelationEndpoint::EpisodeWiringRoundOrder: return 16;
    // BuilderTrace closes on builder_trace_root = fold of TraceColumnLeaf
    // (9 scalars + wiring_vector_root(4) = 13 lanes).
    case RCStage3RelationEndpoint::EpisodeBuilderTrace: return 13;
    default: return 0;
    }
}

bool WiredEndpointIsSignedRange(RCStage3RelationEndpoint e)
{
    return e == RCStage3RelationEndpoint::CoupledGemmSignedRange ||
           e == RCStage3RelationEndpoint::EpisodeGemmSignedRange;
}

// Resolver-side wired-closer CS for any wired endpoint, at `target_rows`.
bool BuildWiredEndpointCS(RCStage3RelationEndpoint e, const ah::Digest& root,
                          uint32_t target_rows,
                          aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    if (WiredEndpointIsSignedRange(e)) {
        if (target_rows != 8) { // 13-lane leaf fixes SignedRange at 8 rows
            if (why != nullptr) *why = "stage3:wired:signedrange_rows";
            return false;
        }
        return BuildRCStage3SignedRangeWiredCloserCS(root, out, why);
    }
    const uint32_t lanes = WiredEndpointLeafLanes(e);
    if (lanes == 0) {
        if (why != nullptr) *why = "stage3:wired:endpoint";
        return false;
    }
    return BuildRCStage3WiredLeafCloserCS(root, lanes, target_rows, out, why);
}

} // namespace

// ===========================================================================
// Faithful WIRED ledger-fold closer — Poseidon multi-permutation sponge CS.
// ===========================================================================
namespace {

constexpr uint32_t kSpongeMsgBase = ar::kPermCellsPerPerm;             // 130
constexpr uint32_t kSpongeRate = ah::kAlgHashRate;                     // 8
constexpr uint32_t kSpongeCap = ah::kAlgHashCapacity;                  // 4
constexpr uint32_t kSpongeSelCol = kSpongeMsgBase + kSpongeRate;       // 138

// Flatten an Fp3 row + index into the base-field sponge message with 10*
// padding to a rate multiple, exactly as alg_hash::LeafHashRow/SpongeHashFp.
std::vector<gf::Fp> SpongePaddedMessage(const std::vector<gf::Fp3>& row,
                                        uint32_t index)
{
    std::vector<gf::Fp> xs;
    xs.reserve(3 * row.size() + 1 + kSpongeRate);
    for (const gf::Fp3& v : row) {
        xs.push_back(gf::Canonical(v.c0));
        xs.push_back(gf::Canonical(v.c1));
        xs.push_back(gf::Canonical(v.c2));
    }
    xs.push_back(gf::FromU64(index));
    xs.push_back(1);
    while (xs.size() % kSpongeRate != 0) xs.push_back(0);
    return xs;
}

// Sponge block count + power-of-two row count for a row of `n_row_lanes` Fp3
// lanes hashed by LeafHashRow (message = 3*lanes + 1 index, then 10* padding).
void SpongeShape(uint32_t n_row_lanes, uint32_t& blocks, uint32_t& n_rows)
{
    uint32_t padded = 3 * n_row_lanes + 1 + 1; // content + index + pad '1'
    while (padded % kSpongeRate != 0) ++padded;
    blocks = padded / kSpongeRate;
    n_rows = 1;
    while (n_rows < blocks) n_rows <<= 1;
    if (n_rows < 2) n_rows = 2;
}

// Append the sponge constraint families (perm honesty, row-0 absorb, add-absorb
// chain, terminal squeeze pinned to `committed_digest` via the verifier-owned
// selector) to `cs`. Shared by the sponge witness product and the resolver-side
// wired-closer CS so both build the byte-identical constraint system.
void AppendSpongeCS(aq::AirConstraintSystem<gf::Fp3>& cs, uint32_t blocks,
                    const ah::Digest& committed_digest)
{
    const ar::PermLayout perm{0};
    const uint32_t n_rows = cs.n_rows;
    for (auto& c : ar::BuildPermRoundConstraints(perm)) cs.constraints.push_back(std::move(c));
    for (uint32_t j = 0; j < kSpongeRate; ++j) {
        const uint32_t in = perm.InputCol(j);
        const uint32_t m = kSpongeMsgBase + j;
        cs.constraints.push_back(
            {"sponge:row0_absorb", aq::AirKind::kFirstRow, 1,
             [in, m](const std::vector<gf::Fp3>& cur, const std::vector<gf::Fp3>&) {
                 return gf::Sub(cur[in], cur[m]);
             }});
    }
    for (uint32_t k = 0; k < kSpongeCap; ++k) {
        const uint32_t in = perm.InputCol(kSpongeRate + k);
        cs.constraints.push_back(
            {"sponge:row0_capacity", aq::AirKind::kFirstRow, 1,
             [in](const std::vector<gf::Fp3>& cur, const std::vector<gf::Fp3>&) {
                 return cur[in];
             }});
    }
    for (uint32_t j = 0; j < kSpongeRate; ++j) {
        const uint32_t in = perm.InputCol(j);
        const uint32_t m = kSpongeMsgBase + j;
        cs.constraints.push_back(
            {"sponge:absorb", aq::AirKind::kTransition, 1,
             [perm, in, m, j](const std::vector<gf::Fp3>& cur,
                              const std::vector<gf::Fp3>& next) {
                 const gf::Fp3 out_j = ar::PermOutputLane(perm, cur, j);
                 return gf::Sub(next[in], gf::Add(out_j, next[m]));
             }});
    }
    for (uint32_t k = 0; k < kSpongeCap; ++k) {
        const uint32_t lane = kSpongeRate + k;
        const uint32_t in = perm.InputCol(lane);
        cs.constraints.push_back(
            {"sponge:carry", aq::AirKind::kTransition, 1,
             [perm, in, lane](const std::vector<gf::Fp3>& cur,
                              const std::vector<gf::Fp3>& next) {
                 return gf::Sub(next[in], ar::PermOutputLane(perm, cur, lane));
             }});
    }
    const uint32_t last = blocks - 1;
    for (uint32_t j = 0; j < ah::kAlgHashDigestLen; ++j) {
        const gf::Fp want = gf::Canonical(committed_digest[j]);
        cs.constraints.push_back(
            {"sponge:digest_pin", aq::AirKind::kEverywhere, 2,
             [perm, j, want](const std::vector<gf::Fp3>& cur,
                             const std::vector<gf::Fp3>&) {
                 return gf::Mul(cur[kSpongeSelCol],
                                gf::Sub(ar::PermOutputLane(perm, cur, j),
                                        gf::Fp3::FromFp(want)));
             }});
    }
    std::vector<gf::Fp3> sel(n_rows, gf::Fp3::Zero());
    sel[last] = gf::Fp3::One();
    // OOD-pinned (row-wise AlgB3 backend has no per-column preprocessed roots).
    cs.preprocessed.push_back({kSpongeSelCol, std::move(sel)});
    cs.preprocessed_pin_ood = true;
}

} // namespace

RCStage3SpongeProduct BuildRCStage3LeafHashRowSpongeProduct(
    const std::vector<gf::Fp3>& row, uint32_t index, uint32_t target_n_rows,
    std::string* why)
{
    RCStage3SpongeProduct out;
    const std::vector<gf::Fp> msg = SpongePaddedMessage(row, index);
    const uint32_t blocks = static_cast<uint32_t>(msg.size()) / kSpongeRate;
    if (blocks == 0) {
        out.note = "empty";
        if (why != nullptr) *why = "stage3:sponge:empty";
        return out;
    }
    uint32_t n_rows = 1;
    while (n_rows < blocks) n_rows <<= 1;
    if (n_rows < 2) n_rows = 2;
    // Pad up to a shared row count (must be a power of two >= natural rows).
    if (target_n_rows != 0) {
        if (target_n_rows < n_rows || (target_n_rows & (target_n_rows - 1)) != 0) {
            out.note = "target_rows";
            if (why != nullptr) *why = "stage3:sponge:target_rows";
            return out;
        }
        n_rows = target_n_rows;
    }

    const ar::PermLayout perm{0};
    const ah::Digest digest = ah::LeafHashRow(row, index);
    const uint32_t last = blocks - 1;
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = n_rows;
    cs.n_columns = kRCStage3SpongeRowWidth;
    AppendSpongeCS(cs, blocks, digest);

    // --- Honest witness: run the real sponge, record each permutation block. ---
    std::vector<std::vector<gf::Fp3>> rows_major(
        n_rows, std::vector<gf::Fp3>(kRCStage3SpongeRowWidth, gf::Fp3::Zero()));
    ah::State s{}; // all zero
    for (uint32_t b = 0; b < blocks; ++b) {
        for (uint32_t j = 0; j < kSpongeRate; ++j) {
            s[j] = gf::Add(s[j], msg[b * kSpongeRate + j]); // add-absorb
        }
        const ar::PermWitness w = ar::BuildPermWitness(s);
        ar::WritePermWitness(perm, w, rows_major[b]);
        for (uint32_t j = 0; j < kSpongeRate; ++j) {
            rows_major[b][kSpongeMsgBase + j] =
                gf::Fp3::FromFp(msg[b * kSpongeRate + j]);
        }
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) s[i] = w.output[i];
    }
    // Pad rows (>= blocks) carry an honest zero-absorb block so every row is a
    // valid permutation and the transition/everywhere families hold.
    for (uint32_t b = blocks; b < n_rows; ++b) {
        const ar::PermWitness w = ar::BuildPermWitness(s);
        ar::WritePermWitness(perm, w, rows_major[b]);
        for (uint32_t i = 0; i < ah::kAlgHashT; ++i) s[i] = w.output[i];
    }
    rows_major[last][kSpongeSelCol] = gf::Fp3::One(); // terminal-squeeze gate

    std::vector<std::vector<gf::Fp3>> cols(
        kRCStage3SpongeRowWidth, std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
    for (uint32_t r = 0; r < n_rows; ++r) {
        for (uint32_t c = 0; c < kRCStage3SpongeRowWidth; ++c) {
            cols[c][r] = rows_major[r][c];
        }
    }

    out.cs = std::move(cs);
    out.witness = std::move(cols);
    out.digest = digest;
    out.blocks = blocks;
    out.ok = true;
    out.note = "sponge";
    return out;
}

namespace {

// The four Goldilocks-reduced limb lanes of a 256-bit root, exactly as
// coupled_signed_range_binding.cpp::PushRootLanes.
void PushRootLanesFp3(std::vector<gf::Fp3>& row, const uint256& root)
{
    const unsigned char* p = root.begin();
    for (uint32_t i = 0; i < 4; ++i) {
        uint64_t limb = 0;
        for (uint32_t b = 0; b < 8; ++b) {
            limb |= static_cast<uint64_t>(p[i * 8 + b]) << (8 * b);
        }
        row.push_back(gf::FromU64_3(limb));
    }
}

// Append the 4 SignedRange RANGE_VALUE==Y broadcast-bus gadgets (constraints +
// selector preprocessing) to `cs`, growing n_columns by 12. Deterministic /
// witness-independent, so the resolver CS and the witness product share it.
bool AppendSignedRangeGadgetConstraints(aq::AirConstraintSystem<gf::Fp3>& cs)
{
    const uint32_t n_rows = cs.n_rows;
    uint32_t next_col = cs.n_columns;
    for (uint32_t k = 0; k < ah::kAlgHashDigestLen; ++k) {
        const uint32_t p1 = 15 + 3 * k;
        const uint32_t p2 = 27 + 3 * k;
        const uint32_t r1 = p1 / kSpongeRate;
        const uint32_t c1 = kSpongeMsgBase + p1 % kSpongeRate;
        const uint32_t r2 = p2 / kSpongeRate;
        const uint32_t c2 = kSpongeMsgBase + p2 % kSpongeRate;
        if (r1 >= n_rows || r2 >= n_rows) return false;
        const uint32_t aA = next_col;
        const uint32_t aS1 = next_col + 1;
        const uint32_t aS2 = next_col + 2;
        next_col += 3;
        cs.constraints.push_back(
            {"wired:rooteq_pin", aq::AirKind::kEverywhere, 2,
             [aA, aS1, c1](const std::vector<gf::Fp3>& cur, const std::vector<gf::Fp3>&) {
                 return gf::Mul(cur[aS1], gf::Sub(cur[aA], cur[c1]));
             }});
        cs.constraints.push_back(
            {"wired:rooteq_broadcast", aq::AirKind::kTransition, 1,
             [aA](const std::vector<gf::Fp3>& cur, const std::vector<gf::Fp3>& next) {
                 return gf::Sub(next[aA], cur[aA]);
             }});
        cs.constraints.push_back(
            {"wired:rooteq_check", aq::AirKind::kEverywhere, 2,
             [aA, aS2, c2](const std::vector<gf::Fp3>& cur, const std::vector<gf::Fp3>&) {
                 return gf::Mul(cur[aS2], gf::Sub(cur[aA], cur[c2]));
             }});
        std::vector<gf::Fp3> s1v(n_rows, gf::Fp3::Zero());
        std::vector<gf::Fp3> s2v(n_rows, gf::Fp3::Zero());
        s1v[r1] = gf::Fp3::One();
        s2v[r2] = gf::Fp3::One();
        // OOD-pinned selectors (row-wise AlgB3 backend has no per-column roots).
        cs.preprocessed.push_back({aS1, std::move(s1v)});
        cs.preprocessed.push_back({aS2, std::move(s2v)});
        cs.preprocessed_pin_ood = true;
    }
    cs.n_columns = next_col;
    return true;
}

} // namespace

bool BuildRCStage3WiredLeafCloserCS(const ah::Digest& committed_root,
                                    uint32_t n_row_lanes, uint32_t target_n_rows,
                                    aq::AirConstraintSystem<gf::Fp3>& out,
                                    std::string* why)
{
    uint32_t blocks = 0, n_rows = 0;
    SpongeShape(n_row_lanes, blocks, n_rows);
    if (target_n_rows != 0) {
        if (target_n_rows < n_rows ||
            (target_n_rows & (target_n_rows - 1)) != 0) {
            if (why != nullptr) *why = "stage3:wired_leaf:target_rows";
            return false;
        }
        n_rows = target_n_rows;
    }
    out = {};
    out.n_rows = n_rows;
    out.n_columns = kRCStage3SpongeRowWidth;
    AppendSpongeCS(out, blocks, committed_root);
    return true;
}

// Resolver-side wired-closer CS (no witness): pins the sponge squeeze to the
// committed authority root the child pin carries, plus the RANGE_VALUE==Y bus.
bool BuildRCStage3SignedRangeWiredCloserCS(const ah::Digest& committed_root,
                                           aq::AirConstraintSystem<gf::Fp3>& out,
                                           std::string* why)
{
    uint32_t blocks = 0, n_rows = 0;
    SpongeShape(/*n_row_lanes=*/13, blocks, n_rows);
    out = {};
    out.n_rows = n_rows;
    out.n_columns = kRCStage3SpongeRowWidth;
    AppendSpongeCS(out, blocks, committed_root);
    if (!AppendSignedRangeGadgetConstraints(out)) {
        if (why != nullptr) *why = "stage3:wired:gadget_row_range";
        return false;
    }
    return true;
}

RCStage3WiredCloserProduct BuildRCStage3SignedRangeWiredCloserProduct(
    uint32_t shard_index, uint64_t cell_begin, uint32_t logical_rows,
    uint32_t n_rows_meta, uint64_t max_abs, const uint256& range_value_root,
    const uint256& y_interval_root, std::string* why)
{
    RCStage3WiredCloserProduct out;

    // Exact ShardLeaf row: [s, cell_begin, logical_rows, n_rows, max_abs,
    // RANGE_VALUE-root(4), Y-root(4)] = 13 Fp3 lanes.
    std::vector<gf::Fp3> row;
    row.push_back(gf::FromU64_3(shard_index));
    row.push_back(gf::FromU64_3(cell_begin));
    row.push_back(gf::FromU64_3(logical_rows));
    row.push_back(gf::FromU64_3(n_rows_meta));
    row.push_back(gf::FromU64_3(max_abs));
    PushRootLanesFp3(row, range_value_root);
    PushRootLanesFp3(row, y_interval_root);

    RCStage3SpongeProduct sp =
        BuildRCStage3LeafHashRowSpongeProduct(row, shard_index, 0, why);
    if (!sp.ok) {
        out.note = "sponge:" + sp.note;
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> cs = std::move(sp.cs);
    std::vector<std::vector<gf::Fp3>> witness = std::move(sp.witness);
    const uint32_t n_rows = cs.n_rows;

    // Per-lane BROADCAST copy bus (constraints via the shared helper so the
    // resolver CS is byte-identical): RANGE_VALUE lane k c0 (msg position 15+3k)
    // == Y lane k c0 (msg position 27+3k), across non-adjacent sponge rows.
    if (!AppendSignedRangeGadgetConstraints(cs)) {
        out.note = "gadget_row_range";
        if (why != nullptr) *why = "stage3:wired:gadget_row_range";
        return out;
    }
    for (uint32_t k = 0; k < ah::kAlgHashDigestLen; ++k) {
        const uint32_t p1 = 15 + 3 * k;
        const uint32_t p2 = 27 + 3 * k;
        const uint32_t r1 = p1 / kSpongeRate;
        const uint32_t c1 = kSpongeMsgBase + p1 % kSpongeRate;
        const uint32_t r2 = p2 / kSpongeRate;
        // Witness for gadget k: A constant == the RANGE_VALUE cell at (c1,r1);
        // selectors gate r1 / r2. (Columns appended in helper order.)
        std::vector<gf::Fp3> col_a(n_rows, witness[c1][r1]);
        std::vector<gf::Fp3> col_s1(n_rows, gf::Fp3::Zero());
        std::vector<gf::Fp3> col_s2(n_rows, gf::Fp3::Zero());
        col_s1[r1] = gf::Fp3::One();
        col_s2[r2] = gf::Fp3::One();
        witness.push_back(std::move(col_a));
        witness.push_back(std::move(col_s1));
        witness.push_back(std::move(col_s2));
        ++out.root_equality_gadgets;
    }

    out.cs = std::move(cs);
    out.witness = std::move(witness);
    out.committed_digest = sp.digest;
    out.ok = true;
    out.note = "wired_closer";
    return out;
}

RCStage3RoleAirProduct BuildRCStage3CoupledGemmRoleAir(
    std::string* why, const int64_t* real_a, const int64_t* real_b,
    const uint256* real_sr_root)
{
    using namespace coupled_air_col;
    RCStage3RoleAirProduct out;
    out.role = RCStage3RelationRole::CoupledGemm;

    // The SignedRange wired closer fixes the shared row count (13-lane leaf ->
    // 6 sponge blocks -> 8 rows). All fragments share it.  When a REAL range
    // root is supplied it is pinned as RANGE_VALUE == Y (the honest equality).
    uint256 sr_root;
    if (real_sr_root != nullptr) {
        sr_root = *real_sr_root;
    } else {
        std::fill(sr_root.begin(), sr_root.end(), 0x11);
    }
    RCStage3WiredCloserProduct wired =
        BuildRCStage3SignedRangeWiredCloserProduct(0, 100, 7, 8, 255, sr_root,
                                                   sr_root, why);
    if (!wired.ok) {
        out.note = "wired:" + wired.note;
        return out;
    }
    const uint32_t rows = wired.cs.n_rows; // 8
    const uint32_t path_len = rows - 1;    // 7 -> opening blocks are 8 rows
    if (!IsPow2(rows) || path_len == 0) {
        out.note = "rows";
        return out;
    }

    // --- GEMM a·b accumulator kernel with CONSTANT operands (so A/B/OUT are
    // row-constant and can be boundary-aliased to their opening blocks). When
    // REAL operands are supplied, (a,b) are the block's GEMM operands and OUT =
    // rows·a·b is the kernel's faithful accumulation of the real product. ---
    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(
            RCStage3RelationRole::CoupledGemm, kt, why)) {
        out.note = "kernel_bytecode";
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        out.note = "kernel_air";
        return out;
    }
    if (kernel_cs.n_columns != GEMM_NUM_COLS) {
        out.note = "kernel_width";
        return out;
    }
    const bool use_real = (real_a != nullptr && real_b != nullptr);
    const int64_t ai = use_real ? *real_a : 3;
    const int64_t bi = use_real ? *real_b : 5;
    const int64_t prodi = ai * bi;
    const int64_t out_i = prodi * static_cast<int64_t>(rows);
    auto cellv = [&](int64_t v) {
        return use_real ? gf::FromSigned3(v)
                        : gf::Fp3::FromFp(gf::FromU64(static_cast<uint64_t>(v)));
    };
    std::vector<std::vector<gf::Fp3>> kernel_cols(
        GEMM_NUM_COLS, std::vector<gf::Fp3>(rows, gf::Fp3::Zero()));
    for (uint32_t r = 0; r < rows; ++r) {
        kernel_cols[GEMM_A][r] = cellv(ai);
        kernel_cols[GEMM_B][r] = cellv(bi);
        kernel_cols[GEMM_ACTIVE][r] = gf::Fp3::One();
        kernel_cols[GEMM_ACC][r] =
            cellv(prodi * static_cast<int64_t>(r + 1)); // running sum a·b
        kernel_cols[GEMM_OUT][r] = cellv(out_i);        // final accumulator
    }

    // --- Compose: kernel ⊕ A/B/Y scalar openings ⊕ SignedRange wired closer. ---
    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = rows;
    CopyConstraintFamily(kernel_cs, 0, product);

    std::vector<std::vector<gf::Fp3>> witness = kernel_cols;
    uint32_t next_col = GEMM_NUM_COLS;

    struct ScalarEndpoint {
        RCStage3RelationEndpoint endpoint;
        uint32_t kernel_col;
        gf::Fp3 cell;
    };
    const std::array<ScalarEndpoint, 3> scalars = {
        ScalarEndpoint{RCStage3RelationEndpoint::CoupledGemmOperandA, GEMM_A,
                       cellv(ai)},
        ScalarEndpoint{RCStage3RelationEndpoint::CoupledGemmOperandB, GEMM_B,
                       cellv(bi)},
        ScalarEndpoint{RCStage3RelationEndpoint::CoupledGemmOutputY, GEMM_OUT,
                       cellv(out_i)}};

    for (const ScalarEndpoint& se : scalars) {
        const RCStage3CommitmentManifest m =
            BuildRCStage3CanonicalManifest(se.endpoint, se.cell, 0, path_len);
        const aq::AirConstraintSystem<gf::Fp3> open_cs =
            BuildOpeningConstraintSystem(0, m.committed_root, path_len);
        if (open_cs.n_columns != kRCStage3OpeningWidth) {
            out.note = "opening_width";
            return out;
        }
        const uint32_t base = next_col;
        CopyConstraintFamily(open_cs, base, product);
        const uint32_t v_col = base + kRCStage3OpeningValueColumn;
        const uint32_t kc = se.kernel_col;
        product.constraints.push_back(
            {"role_air:endpoint_value_alias", aq::AirKind::kEverywhere, 1,
             [kc, v_col](const std::vector<gf::Fp3>& cur,
                         const std::vector<gf::Fp3>&) {
                 return gf::Sub(cur[kc], cur[v_col]);
             }});
        const std::vector<std::vector<gf::Fp3>> ow =
            BuildOpeningWitness(se.cell, se.cell, m);
        for (const auto& col : ow) witness.push_back(col);
        out.endpoints.push_back(se.endpoint);
        out.endpoint_value_columns.push_back(v_col);
        out.endpoint_committed_roots.push_back(m.committed_root);
        next_col += kRCStage3OpeningWidth;
    }

    // SignedRange wired closer (standalone fragment: no kernel alias).
    const uint32_t wired_base = next_col;
    CopyConstraintFamily(wired.cs, wired_base, product);
    for (const auto& col : wired.witness) witness.push_back(col);
    out.endpoints.push_back(RCStage3RelationEndpoint::CoupledGemmSignedRange);
    out.endpoint_value_columns.push_back(wired_base); // fragment base
    out.endpoint_committed_roots.push_back(wired.committed_digest);
    next_col += wired.cs.n_columns;

    product.n_columns = next_col;
    out.fragment_columns = GEMM_NUM_COLS;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

bool BuildRCStage3EpisodeGemmRoleAirCS(
    const std::vector<ah::Digest>& endpoint_roots, uint32_t path_len,
    aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    out = {};
    const auto& required =
        RequiredRCStage3RelationEndpoints(RCStage3RelationRole::EpisodeGemm);
    if (endpoint_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:egemm_cs:root_count";
        return false;
    }
    const uint32_t rows = path_len + 1;

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::GemmEndpointFp3V1, kt, why)) {
        return false;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        return false;
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = rows;
    CopyConstraintFamily(kernel_cs, 0, product);
    uint32_t next_col = kernel_cs.n_columns;

    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (WiredEndpointLeafLanes(e) != 0) {
            aq::AirConstraintSystem<gf::Fp3> wired_cs;
            if (!BuildWiredEndpointCS(e, endpoint_roots[i], rows, wired_cs,
                                      why)) {
                return false;
            }
            if (wired_cs.n_rows != rows) {
                if (why != nullptr) *why = "stage3:egemm_cs:wired_rows";
                return false;
            }
            CopyConstraintFamily(wired_cs, next_col, product);
            next_col += wired_cs.n_columns;
        } else {
            const std::optional<uint32_t> kc = EpisodeEndpointColumn(
                e, RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
                RCStage3RelationRole::EpisodeGemm);
            if (!kc.has_value() || *kc >= kernel_cs.n_columns) {
                if (why != nullptr) *why = "stage3:egemm_cs:endpoint_column";
                return false;
            }
            const aq::AirConstraintSystem<gf::Fp3> open_cs =
                BuildOpeningConstraintSystem(0, endpoint_roots[i], path_len);
            if (open_cs.n_columns != kRCStage3OpeningWidth) {
                if (why != nullptr) *why = "stage3:egemm_cs:opening_width";
                return false;
            }
            const uint32_t base = next_col;
            CopyConstraintFamily(open_cs, base, product);
            const uint32_t v_col = base + kRCStage3OpeningValueColumn;
            const uint32_t k = *kc;
            product.constraints.push_back(
                {"role_air:endpoint_value_alias", aq::AirKind::kEverywhere, 1,
                 [k, v_col](const std::vector<gf::Fp3>& cur,
                            const std::vector<gf::Fp3>&) {
                     return gf::Sub(cur[k], cur[v_col]);
                 }});
            next_col += kRCStage3OpeningWidth;
        }
    }
    product.n_columns = next_col;
    out = std::move(product);
    return true;
}

RCStage3RoleAirProduct BuildRCStage3EpisodeGemmRoleAir(
    std::string* why, const int64_t* real_a, const int64_t* real_b,
    const uint256* real_sr_root)
{
    RCStage3RoleAirProduct out;
    out.role = RCStage3RelationRole::EpisodeGemm;
    const uint32_t rows = 8; // SignedRange (13-lane) fixes the shared rows
    const uint32_t path_len = rows - 1;
    const auto& required =
        RequiredRCStage3RelationEndpoints(RCStage3RelationRole::EpisodeGemm);

    // Episode GEMM kernel (GF = A·B), constant operands so endpoint cells alias.
    // With REAL operands, (a,b) is a block GEMM MAC term and Y = a·b exactly.
    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::GemmEndpointFp3V1, kt, why)) {
        out.note = "kernel_bytecode";
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        out.note = "kernel_air";
        return out;
    }
    const uint32_t kernel_w = kernel_cs.n_columns;
    const bool use_real = (real_a != nullptr && real_b != nullptr);
    const int64_t ai = use_real ? *real_a : 3;
    const int64_t bi = use_real ? *real_b : 5;
    const int64_t gfi = ai * bi;
    auto cellv = [&](int64_t v) {
        return use_real ? gf::FromSigned3(v)
                        : gf::Fp3::FromFp(gf::FromU64(static_cast<uint64_t>(v)));
    };
    std::vector<std::vector<gf::Fp3>> kernel_cols(
        kernel_w, std::vector<gf::Fp3>(rows, gf::Fp3::Zero()));
    for (uint32_t r = 0; r < rows; ++r) {
        kernel_cols[0][r] = cellv(gfi); // GF / Y
        kernel_cols[1][r] = cellv(ai);  // A
        kernel_cols[2][r] = cellv(bi);  // B
    }

    // Per-endpoint cell values (scalar) and committed roots (all endpoints).
    auto endpoint_cell = [&](RCStage3RelationEndpoint e) -> gf::Fp3 {
        if (e == RCStage3RelationEndpoint::EpisodeGemmOutputY) return cellv(gfi);
        if (e == RCStage3RelationEndpoint::EpisodeGemmOperandA) return cellv(ai);
        return cellv(bi);
    };

    // Build the wired-closer witness products up front (to learn their roots).
    // Sumcheck round leaf: [layer, k, g0, g1, g2, r].
    std::vector<gf::Fp3> sc_row = {gf::FromU64_3(2), gf::FromU64_3(1),
                                   gf::FromU64_3(7), gf::FromU64_3(11),
                                   gf::FromU64_3(13), gf::FromU64_3(17)};
    const RCStage3SpongeProduct sumcheck =
        BuildRCStage3LeafHashRowSpongeProduct(sc_row, 1, rows, why);
    if (!sumcheck.ok) {
        out.note = "sumcheck:" + sumcheck.note;
        return out;
    }
    uint256 sr_root;
    if (real_sr_root != nullptr) {
        sr_root = *real_sr_root;
    } else {
        std::fill(sr_root.begin(), sr_root.end(), 0x11);
    }
    const RCStage3WiredCloserProduct signed_range =
        BuildRCStage3SignedRangeWiredCloserProduct(0, 100, 7, 8, 255, sr_root,
                                                   sr_root, why);
    if (!signed_range.ok) {
        out.note = "signedrange:" + signed_range.note;
        return out;
    }

    // Collect the committed roots in required order [A,B,Y,Sumcheck,SignedRange].
    std::vector<ah::Digest> roots;
    std::vector<RCStage3CommitmentManifest> scalar_manifests;
    std::vector<gf::Fp3> scalar_cells;
    for (const RCStage3RelationEndpoint e : required) {
        if (e == RCStage3RelationEndpoint::EpisodeGemmSumcheck) {
            roots.push_back(sumcheck.digest);
        } else if (e == RCStage3RelationEndpoint::EpisodeGemmSignedRange) {
            roots.push_back(signed_range.committed_digest);
        } else {
            const gf::Fp3 cell = endpoint_cell(e);
            const RCStage3CommitmentManifest m =
                BuildRCStage3CanonicalManifest(e, cell, 0, path_len);
            roots.push_back(m.committed_root);
            scalar_manifests.push_back(m);
            scalar_cells.push_back(cell);
        }
    }

    // Build the CS via the resolver builder so the witness is guaranteed to fit.
    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3EpisodeGemmRoleAirCS(roots, path_len, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    // Assemble the witness in the same fragment order the CS composes.
    std::vector<std::vector<gf::Fp3>> witness = std::move(kernel_cols);
    uint32_t scalar_i = 0;
    for (const RCStage3RelationEndpoint e : required) {
        if (e == RCStage3RelationEndpoint::EpisodeGemmSumcheck) {
            for (const auto& col : sumcheck.witness) witness.push_back(col);
        } else if (e == RCStage3RelationEndpoint::EpisodeGemmSignedRange) {
            for (const auto& col : signed_range.witness) witness.push_back(col);
        } else {
            const std::vector<std::vector<gf::Fp3>> ow = BuildOpeningWitness(
                scalar_cells[scalar_i], scalar_cells[scalar_i],
                scalar_manifests[scalar_i]);
            for (const auto& col : ow) witness.push_back(col);
            ++scalar_i;
        }
        out.endpoints.push_back(e);
    }
    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = kernel_w;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

bool BuildRCStage3EpisodeWiringRoleAirCS(
    const std::vector<ah::Digest>& endpoint_roots, uint32_t path_len,
    aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    out = {};
    const auto& required =
        RequiredRCStage3RelationEndpoints(RCStage3RelationRole::EpisodeWiring);
    if (endpoint_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:ewiring_cs:root_count";
        return false;
    }
    const uint32_t rows = path_len + 1;

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::WiringEqualityFp3V1, kt, why)) {
        return false;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        return false;
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = rows;
    CopyConstraintFamily(kernel_cs, 0, product);
    uint32_t next_col = kernel_cs.n_columns;

    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (WiredEndpointLeafLanes(e) != 0) {
            aq::AirConstraintSystem<gf::Fp3> wired_cs;
            if (!BuildWiredEndpointCS(e, endpoint_roots[i], rows, wired_cs,
                                      why)) {
                return false;
            }
            if (wired_cs.n_rows != rows) {
                if (why != nullptr) *why = "stage3:ewiring_cs:wired_rows";
                return false;
            }
            CopyConstraintFamily(wired_cs, next_col, product);
            next_col += wired_cs.n_columns;
        } else {
            const std::optional<uint32_t> kc = EpisodeEndpointColumn(
                e, RCStage3EpisodeAirFamily::WiringEqualityFp3V1,
                RCStage3RelationRole::EpisodeWiring);
            if (!kc.has_value() || *kc >= kernel_cs.n_columns) {
                if (why != nullptr) *why = "stage3:ewiring_cs:endpoint_column";
                return false;
            }
            const aq::AirConstraintSystem<gf::Fp3> open_cs =
                BuildOpeningConstraintSystem(0, endpoint_roots[i], path_len);
            const uint32_t base = next_col;
            CopyConstraintFamily(open_cs, base, product);
            const uint32_t v_col = base + kRCStage3OpeningValueColumn;
            const uint32_t k = *kc;
            product.constraints.push_back(
                {"role_air:endpoint_value_alias", aq::AirKind::kEverywhere, 1,
                 [k, v_col](const std::vector<gf::Fp3>& cur,
                            const std::vector<gf::Fp3>&) {
                     return gf::Sub(cur[k], cur[v_col]);
                 }});
            next_col += kRCStage3OpeningWidth;
        }
    }
    product.n_columns = next_col;
    out = std::move(product);
    return true;
}

RCStage3RoleAirProduct BuildRCStage3EpisodeWiringRoleAir(
    std::string* why, const gf::Fp3* real_copy_cell)
{
    RCStage3RoleAirProduct out;
    out.role = RCStage3RelationRole::EpisodeWiring;
    const uint32_t rows = 16; // Transpose (21-lane) fixes the shared rows
    const uint32_t path_len = rows - 1;
    const auto& required =
        RequiredRCStage3RelationEndpoints(RCStage3RelationRole::EpisodeWiring);

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::WiringEqualityFp3V1, kt, why)) {
        out.note = "kernel_bytecode";
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        out.note = "kernel_air";
        return out;
    }
    const uint32_t kernel_w = kernel_cs.n_columns; // 2 (U, V)
    const gf::Fp3 copy_cell = real_copy_cell != nullptr
                                  ? *real_copy_cell
                                  : gf::Fp3::FromFp(gf::FromU64(0x99));
    std::vector<std::vector<gf::Fp3>> kernel_cols(
        kernel_w, std::vector<gf::Fp3>(rows, copy_cell)); // U == V == cell

    // Build the three wired-closer leaf rows exactly per the binding leaves.
    auto root_of = [](unsigned char v) {
        uint256 r;
        std::fill(r.begin(), r.end(), v);
        return r;
    };
    std::vector<gf::Fp3> transpose_row = {
        gf::FromU64_3(0), gf::FromU64_3(5), gf::FromU64_3(2), gf::FromU64_3(1),
        gf::FromU64_3(0), gf::FromU64_3(4), gf::FromU64_3(8), gf::FromU64_3(8),
        gf::FromU64_3(64)};
    PushRootLanesFp3(transpose_row, root_of(0x21));
    PushRootLanesFp3(transpose_row, root_of(0x22));
    PushRootLanesFp3(transpose_row, root_of(0x23));
    std::vector<gf::Fp3> residual_row = {
        gf::FromU64_3(0), gf::FromU64_3(5), gf::FromU64_3(2), gf::FromU64_3(0),
        gf::FromU64_3(4), gf::FromU64_3(64)};
    PushRootLanesFp3(residual_row, root_of(0x31));
    PushRootLanesFp3(residual_row, root_of(0x32));
    PushRootLanesFp3(residual_row, root_of(0x33));
    std::vector<gf::Fp3> round_order_row = {
        gf::FromU64_3(0), gf::FromU64_3(5), gf::FromU64_3(1), gf::FromU64_3(2),
        gf::FromU64_3(3), gf::FromU64_3(0), gf::FromU64_3(4), gf::FromU64_3(64)};
    PushRootLanesFp3(round_order_row, root_of(0x41));
    PushRootLanesFp3(round_order_row, root_of(0x42));

    const RCStage3SpongeProduct transpose =
        BuildRCStage3LeafHashRowSpongeProduct(transpose_row, 0, rows, why);
    const RCStage3SpongeProduct residual =
        BuildRCStage3LeafHashRowSpongeProduct(residual_row, 0, rows, why);
    const RCStage3SpongeProduct round_order =
        BuildRCStage3LeafHashRowSpongeProduct(round_order_row, 0, rows, why);
    if (!transpose.ok || !residual.ok || !round_order.ok) {
        out.note = "wired_leaf";
        return out;
    }

    // Copy scalar opening.
    const gf::Fp3 copy = copy_cell;
    const RCStage3CommitmentManifest copy_manifest = BuildRCStage3CanonicalManifest(
        RCStage3RelationEndpoint::EpisodeWiringCopy, copy, 0, path_len);

    std::vector<ah::Digest> roots;
    for (const RCStage3RelationEndpoint e : required) {
        switch (e) {
        case RCStage3RelationEndpoint::EpisodeWiringCopy:
            roots.push_back(copy_manifest.committed_root);
            break;
        case RCStage3RelationEndpoint::EpisodeWiringTranspose:
            roots.push_back(transpose.digest);
            break;
        case RCStage3RelationEndpoint::EpisodeWiringResidual:
            roots.push_back(residual.digest);
            break;
        case RCStage3RelationEndpoint::EpisodeWiringRoundOrder:
            roots.push_back(round_order.digest);
            break;
        default:
            out.note = "endpoint";
            return out;
        }
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3EpisodeWiringRoleAirCS(roots, path_len, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness = std::move(kernel_cols);
    for (const RCStage3RelationEndpoint e : required) {
        const RCStage3SpongeProduct* sp = nullptr;
        switch (e) {
        case RCStage3RelationEndpoint::EpisodeWiringCopy: {
            const std::vector<std::vector<gf::Fp3>> ow =
                BuildOpeningWitness(copy, copy, copy_manifest);
            for (const auto& col : ow) witness.push_back(col);
            break;
        }
        case RCStage3RelationEndpoint::EpisodeWiringTranspose: sp = &transpose; break;
        case RCStage3RelationEndpoint::EpisodeWiringResidual: sp = &residual; break;
        case RCStage3RelationEndpoint::EpisodeWiringRoundOrder: sp = &round_order; break;
        default: break;
        }
        if (sp != nullptr) {
            for (const auto& col : sp->witness) witness.push_back(col);
        }
        out.endpoints.push_back(e);
    }
    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = kernel_w;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

namespace {

// CoupledBankRoot (#29) and SeedChain (#2) are §4 SHA256d manifest bindings
// (BuildHashManifestRecursiveBinding / stream_column_root) — NOT Poseidon
// LeafHashRow folds — so they close with the DirectSha256d stream fragment even
// though IsWiredBindingEndpoint lists them.
bool IsInCsStreamEndpoint(RCStage3RelationEndpoint e)
{
    if (RCStage3StreamEndpointManifestFamily(e) !=
        RCStage3StreamManifestFamily::None) {
        return true;
    }
    return e == RCStage3RelationEndpoint::CoupledBankRoot ||
           e == RCStage3RelationEndpoint::EpisodeBuilderSeedChain;
}

// Map the closure's stream family to the stream-endpoint closer's family.
// Thin wrapper over the exported 1:1 mapper (keeps call sites short).
RCStage3StreamFamily StreamFamilyForEndpoint(RCStage3RelationEndpoint e)
{
    return RCStage3StreamFamilyForEndpoint(e);
}

// SHA256d root (8 uint32) <-> Digest (4 uint64), lossless 2-uint32-per-lane pack.
ah::Digest PackStreamRoot(const std::array<uint32_t, 8>& r)
{
    ah::Digest d{};
    for (uint32_t i = 0; i < 4; ++i) {
        d[i] = static_cast<uint64_t>(r[2 * i]) |
               (static_cast<uint64_t>(r[2 * i + 1]) << 32);
    }
    return d;
}
std::array<uint32_t, 8> UnpackStreamRoot(const ah::Digest& d)
{
    std::array<uint32_t, 8> r{};
    for (uint32_t i = 0; i < 4; ++i) {
        r[2 * i] = static_cast<uint32_t>(d[i] & 0xFFFFFFFFu);
        r[2 * i + 1] = static_cast<uint32_t>(d[i] >> 32);
    }
    return r;
}

constexpr uint32_t kPureStreamPathLen = 3; // SHA Merkle depth of the manifest

} // namespace

bool RCStage3RoleIsPureStream(RCStage3RelationRole role)
{
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (required.empty()) return false;
    for (const RCStage3RelationEndpoint e : required) {
        if (RCStage3StreamEndpointManifestFamily(e) ==
            RCStage3StreamManifestFamily::None) {
            return false;
        }
    }
    return true;
}

bool BuildRCStage3PureStreamRoleAirCS(
    RCStage3RelationRole role, const std::vector<ah::Digest>& endpoint_roots,
    aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    out = {};
    if (!RCStage3RoleIsPureStream(role)) {
        if (why != nullptr) *why = "stage3:stream_cs:not_pure_stream";
        return false;
    }
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (endpoint_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:stream_cs:root_count";
        return false;
    }
    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = 2;
    uint32_t next_col = 0;
    for (uint32_t i = 0; i < required.size(); ++i) {
        const std::array<uint32_t, 8> root8 = UnpackStreamRoot(endpoint_roots[i]);
        const aq::AirConstraintSystem<gf::Fp3> frag =
            BuildRCStage3StreamEndpointConstraintSystem(
                StreamFamilyForEndpoint(required[i]), /*leaf_index=*/0, root8,
                kPureStreamPathLen);
        if (frag.n_columns != kRCStage3StreamEndpointBindWidth ||
            frag.n_rows != 2) {
            if (why != nullptr) *why = "stage3:stream_cs:fragment_shape";
            return false;
        }
        CopyConstraintFamily(frag, next_col, product);
        next_col += frag.n_columns;
    }
    product.n_columns = next_col;
    out = std::move(product);
    return true;
}

RCStage3RoleAirProduct BuildRCStage3PureStreamRoleAir(RCStage3RelationRole role,
                                                      std::string* why)
{
    RCStage3RoleAirProduct out;
    out.role = role;
    if (!RCStage3RoleIsPureStream(role)) {
        out.note = "not_pure_stream";
        return out;
    }
    const auto& required = RequiredRCStage3RelationEndpoints(role);

    std::vector<ah::Digest> roots;
    std::vector<std::vector<std::vector<gf::Fp3>>> frag_witnesses;
    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        const RCStage3StreamFamily family = StreamFamilyForEndpoint(e);
        std::array<uint32_t, 8> stream_value{};
        for (uint32_t j = 0; j < 8; ++j) {
            stream_value[j] = static_cast<uint32_t>(e) * 131u + i * 17u + j;
        }
        const RCStage3StreamEndpointManifest manifest =
            BuildRCStage3StreamEndpointCanonicalManifest(family, stream_value, 0,
                                                         kPureStreamPathLen);
        std::array<uint32_t, 8> root8{};
        std::string rwhy;
        if (!RCStage3StreamEndpointCommittedRoot(family, manifest, root8,
                                                 &rwhy)) {
            out.note = "committed_root:" + rwhy;
            return out;
        }
        const gf::Fp3 ctl_value =
            gf::Fp3::FromFp(gf::FromU64(0x5100u + i));
        frag_witnesses.push_back(
            BuildRCStage3StreamEndpointWitness(root8, ctl_value));
        roots.push_back(PackStreamRoot(root8));
        out.endpoints.push_back(e);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3PureStreamRoleAirCS(role, roots, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness;
    for (const auto& fw : frag_witnesses) {
        for (const auto& col : fw) witness.push_back(col);
    }

    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = 0;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

RCStage3RoleAirProduct BuildRCStage3PureStreamRoleAirFromRoots(
    RCStage3RelationRole role,
    const std::vector<std::array<uint32_t, 8>>& endpoint_root8s,
    std::string* why)
{
    RCStage3RoleAirProduct out;
    out.role = role;
    if (!RCStage3RoleIsPureStream(role)) {
        out.note = "not_pure_stream";
        if (why != nullptr) *why = "stage3:stream_real:not_pure_stream";
        return out;
    }
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (endpoint_root8s.size() != required.size()) {
        out.note = "root_count";
        if (why != nullptr) *why = "stage3:stream_real:root_count";
        return out;
    }

    // Each endpoint pins a REAL committed SHA256d root (block data). The light
    // binding witness carries that exact root8; the CS pins it as public
    // constants (BuildRCStage3PureStreamRoleAirCS -> UnpackStreamRoot).
    std::vector<ah::Digest> roots;
    std::vector<std::vector<std::vector<gf::Fp3>>> frag_witnesses;
    for (uint32_t i = 0; i < required.size(); ++i) {
        const std::array<uint32_t, 8>& root8 = endpoint_root8s[i];
        const gf::Fp3 ctl_value = gf::Fp3::FromFp(gf::FromU64(0x5100u + i));
        frag_witnesses.push_back(
            BuildRCStage3StreamEndpointWitness(root8, ctl_value));
        roots.push_back(PackStreamRoot(root8));
        out.endpoints.push_back(required[i]);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3PureStreamRoleAirCS(role, roots, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness;
    for (const auto& fw : frag_witnesses)
        for (const auto& col : fw) witness.push_back(col);

    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = 0;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled_real";
    return out;
}

// ===========================================================================
// CompositionLink (role 32) — the fifteenth relation's in-CS closer.
//
// CompositionLink was the ONE required role of a Composed statement with no
// role AIR at all: RCStage3RoleIsInCsClosable(CompositionLink) was false, so
// RebuildRCStage3RoleAirConstraintSystem failed "no_role_air:composition:link"
// and a Composed statement could NEVER be fully section-verified, while the
// recursive resolver returned "complete_air_unavailable".
//
// The native relation (matmul_v4_rc_stage3_composition.cpp:112) is:
//     final_digest == SHA256d(ctx ‖ episode_digest ‖ coupled_digest)
// i.e. the two proved LEGS folded into one value. The in-CS closer mirrors
// exactly that structure on the algebraic side:
//
//   [0,10)    §4 stream binding fragment, EPISODE leg  — pins authority root 0
//   [10,20)   §4 stream binding fragment, COUPLED leg  — pins authority root 1
//   [20,159)  Poseidon sponge ledger fold over the row [episode, coupled],
//             terminal squeeze pinned to authority root 2 (the link digest)
//   + composition_link:{episode,coupled}_leg_recompose — degree-1 aliases
//     forcing the sponge's absorbed message to BE the two bound leg values
//   + composition_link:{index,pad}_pin — pins the sponge's index and 10*
//     padding lanes so the absorbed message cannot be retargeted
//
// WHAT THIS PROVES: a satisfying assignment exhibits two leg values that open
// against the two committed leg authority roots AND fold, under the tree's
// algebraic hash, to the committed link digest. Substituting either leg value,
// either leg root, or the link digest has no satisfying assignment.
//
// WHAT IT DOES NOT PROVE — read before quoting this as closure:
//  (a) The fold is the ALGEBRAIC hash (alg_hash / Poseidon sponge), not the
//      consensus SHA256d of ComputeRCStage3FinalDigest. Bridging the two is the
//      A-EXACT / external_sha256d_audit_root obligation. This is the SAME
//      deferral the four existing pure-stream roles already carry ("the SHA
//      fold is the DEFERRED recursive child"), not a new one — but it is a
//      deferral, and CompositionLink inherits it.
//      The executable SHA256d route exists (stage3_hash_air::
//      BuildComposedFinalDigestManifest -> BuildDirectSha256dManifestBoundary-
//      Instances -> BuildFixedProgramBoundaryConstraintSystem, 4 compressions
//      for the 179-byte composed preimage) and is NOT wired here.
//  (b) The three authority roots are section-carried PUBLIC PINS. Anchoring
//      them to the statement's episode_digest / coupled_digest / final_digest
//      is kRCStage3RoleSectionEndpointProvenanceReady, which is FALSE.
//
// No readiness constant is flipped by anything below.
// ===========================================================================

/** Columns of the CompositionLink C_rho: two §4 leg fragments + one sponge. */
const uint32_t kCompositionLinkEpisodeBase = 0;
const uint32_t kCompositionLinkCoupledBase =
    kRCStage3StreamEndpointBindWidth;
const uint32_t kCompositionLinkSpongeBase =
    2 * kRCStage3StreamEndpointBindWidth;
const uint32_t kCompositionLinkColumns =
    kCompositionLinkSpongeBase + kRCStage3SpongeRowWidth;

bool BuildRCStage3CompositionLinkRoleAirCS(
    const std::vector<ah::Digest>& endpoint_roots,
    aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    out = {};
    if (endpoint_roots.size() != kRCStage3CompositionLinkInCsClosers) {
        if (why != nullptr) *why = "stage3:composition_link_cs:root_count";
        return false;
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = 2;

    // --- (1) the two §4 leg binding fragments, each pinning its authority root.
    const std::array<RCStage3RelationEndpoint, 2> legs{
        RCStage3RelationEndpoint::EpisodeDigestValue,
        RCStage3RelationEndpoint::CoupledDigestValue,
    };
    for (uint32_t i = 0; i < 2; ++i) {
        const std::array<uint32_t, 8> root8 =
            UnpackStreamRoot(endpoint_roots[i]);
        const aq::AirConstraintSystem<gf::Fp3> frag =
            BuildRCStage3StreamEndpointConstraintSystem(
                StreamFamilyForEndpoint(legs[i]), /*leaf_index=*/0, root8,
                kPureStreamPathLen);
        if (frag.n_columns != kRCStage3StreamEndpointBindWidth ||
            frag.n_rows != 2) {
            if (why != nullptr) {
                *why = "stage3:composition_link_cs:leg_fragment_shape";
            }
            return false;
        }
        CopyConstraintFamily(frag, i * kRCStage3StreamEndpointBindWidth,
                             product);
    }

    // --- (2) the sponge ledger fold over the row [episode_leg, coupled_leg],
    //         terminal squeeze pinned to the committed link digest.
    aq::AirConstraintSystem<gf::Fp3> sponge_cs;
    if (!BuildRCStage3WiredLeafCloserCS(endpoint_roots[2], /*n_row_lanes=*/2,
                                        /*target_n_rows=*/2, sponge_cs, why)) {
        return false;
    }
    if (sponge_cs.n_columns != kRCStage3SpongeRowWidth ||
        sponge_cs.n_rows != 2) {
        if (why != nullptr) *why = "stage3:composition_link_cs:sponge_shape";
        return false;
    }
    CopyConstraintFamily(sponge_cs, kCompositionLinkSpongeBase, product);

    // --- (3) the RELATION: the folded message IS the two bound leg values.
    // SpongePaddedMessage lays a row of Fp3 lanes out as base coordinates
    // [c0,c1,c2] per lane, then the index, then the 10* padding — so lane L
    // occupies message positions 3L, 3L+1, 3L+2, all inside the single rate
    // block (3*2 + 1 + 1 = 8 == kAlgHashRate), i.e. all on row 0.
    const uint32_t msg_base =
        kCompositionLinkSpongeBase + air_recurse::kPermCellsPerPerm;
    const gf::Fp3 t{0, 1, 0};
    const gf::Fp3 t2{0, 0, 1};
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const uint32_t value_col =
            lane * kRCStage3StreamEndpointBindWidth +
            kRCStage3StreamEndpointBindValueColumn;
        const uint32_t m0 = msg_base + 3 * lane;
        const uint32_t m1 = m0 + 1;
        const uint32_t m2 = m0 + 2;
        product.constraints.push_back(
            {lane == 0 ? "composition_link:episode_leg_recompose"
                       : "composition_link:coupled_leg_recompose",
             aq::AirKind::kFirstRow, 1,
             [value_col, m0, m1, m2, t, t2](const std::vector<gf::Fp3>& cur,
                                            const std::vector<gf::Fp3>&) {
                 const gf::Fp3 recomposed = gf::Add(
                     cur[m0], gf::Add(gf::Mul(t, cur[m1]), gf::Mul(t2, cur[m2])));
                 return gf::Sub(cur[value_col], recomposed);
             }});
    }
    // Pin the index lane (6) and the 10* pad lane (7). Without these the prover
    // chooses the tail of the absorbed message freely and the fold no longer
    // determines the link digest from the legs alone.
    const uint32_t index_col = msg_base + 6;
    const uint32_t pad_col = msg_base + 7;
    product.constraints.push_back(
        {"composition_link:index_pin", aq::AirKind::kFirstRow, 1,
         [index_col](const std::vector<gf::Fp3>& cur,
                     const std::vector<gf::Fp3>&) { return cur[index_col]; }});
    product.constraints.push_back(
        {"composition_link:pad_pin", aq::AirKind::kFirstRow, 1,
         [pad_col](const std::vector<gf::Fp3>& cur,
                   const std::vector<gf::Fp3>&) {
             return gf::Sub(cur[pad_col], gf::Fp3::One());
         }});

    product.n_columns = kCompositionLinkColumns;
    out = std::move(product);
    return true;
}

RCStage3RoleAirProduct BuildRCStage3CompositionLinkRoleAir(
    const gf::Fp3& episode_leg, const gf::Fp3& coupled_leg,
    const std::array<uint32_t, 8>& episode_root8,
    const std::array<uint32_t, 8>& coupled_root8, std::string* why)
{
    RCStage3RoleAirProduct out;
    out.role = RCStage3RelationRole::CompositionLink;

    // The honest fold: LeafHashRow([episode_leg, coupled_leg], 0). Its digest IS
    // the committed link authority root the CS pins, so the pin is derived from
    // the legs, never chosen independently of them.
    const std::vector<gf::Fp3> row{episode_leg, coupled_leg};
    RCStage3SpongeProduct sponge =
        BuildRCStage3LeafHashRowSpongeProduct(row, /*index=*/0,
                                              /*target_n_rows=*/2, why);
    if (!sponge.ok) {
        out.note = "sponge:" + sponge.note;
        return out;
    }

    std::vector<ah::Digest> roots{
        PackStreamRoot(episode_root8),
        PackStreamRoot(coupled_root8),
        sponge.digest,
    };

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string awhy;
    if (!BuildRCStage3CompositionLinkRoleAirCS(roots, cs, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    // Witness: the two leg fragments then the sponge, in CS column order.
    std::vector<std::vector<gf::Fp3>> witness;
    for (const auto& col :
         BuildRCStage3StreamEndpointWitness(episode_root8, episode_leg)) {
        witness.push_back(col);
    }
    for (const auto& col :
         BuildRCStage3StreamEndpointWitness(coupled_root8, coupled_leg)) {
        witness.push_back(col);
    }
    for (auto& col : sponge.witness) witness.push_back(std::move(col));
    if (witness.size() != cs.n_columns) {
        out.note = "witness_width";
        if (why != nullptr) *why = "stage3:composition_link:witness_width";
        return out;
    }

    out.endpoints = {
        RCStage3RelationEndpoint::EpisodeDigestValue,
        RCStage3RelationEndpoint::CoupledDigestValue,
    };
    out.endpoint_value_columns = {
        kCompositionLinkEpisodeBase + kRCStage3StreamEndpointBindValueColumn,
        kCompositionLinkCoupledBase + kRCStage3StreamEndpointBindValueColumn,
    };
    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = 0;
    out.opening_blocks = kRCStage3CompositionLinkInCsClosers;
    out.cs = std::move(cs);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled_composition_link";
    return out;
}

namespace {

// Satisfying kernel witness for a coupled scalar+stream mixed role, constant
// across rows so its endpoint cells alias to the constant opening value.
// `real_copy_cell` (CoupledExchange) / `real_nibble` (CoupledBank, 0..15):
// when set, the kernel is driven by the REAL block-derived value instead of the
// synthetic constant.  The CoupledBank T_M nibble relation is faithful for any
// real nibble (ACC/MU from the consensus table, OUT = MU with E0=E1=0).
bool BuildCoupledMixedKernelWitness(RCStage3RelationRole role, uint32_t kernel_w,
                                    uint32_t rows,
                                    std::vector<std::vector<gf::Fp3>>& cols,
                                    const gf::Fp3* real_copy_cell = nullptr,
                                    const uint8_t* real_nibble = nullptr)
{
    using namespace coupled_air_col;
    cols.assign(kernel_w, std::vector<gf::Fp3>(rows, gf::Fp3::Zero()));
    auto set = [&](uint32_t c, const gf::Fp3& v) {
        if (c < kernel_w)
            for (uint32_t r = 0; r < rows; ++r) cols[c][r] = v;
    };
    if (role == RCStage3RelationRole::CoupledExchange) {
        const gf::Fp3 cell = real_copy_cell != nullptr
                                 ? *real_copy_cell
                                 : gf::Fp3::FromFp(gf::FromU64(0x77));
        set(COPY_INPUT, cell);
        set(COPY_OUTPUT, cell); // copy relation
        return true;
    }
    if (role == RCStage3RelationRole::CoupledBank) {
        // Real nibble n (0..15): bits n0..n3; ACC/MU from the consensus T_M
        // table; OUT = MU. E0=E1=0 so OUT = MU*(1+E0)(1+3E1) = MU.
        const uint8_t n = real_nibble != nullptr ? (*real_nibble & 0x0Fu) : 0u;
        const gkr_air::TableTM tm;
        const gf::Fp3 acc_n = gf::FromSigned3(tm.acc[n]);
        const gf::Fp3 mu_n = gf::FromSigned3(tm.mu[n]);
        set(BANK_NIB, gf::Fp3::FromFp(gf::FromU64(n)));
        for (uint32_t bit = 0; bit < 4; ++bit)
            set(BANK_NB0 + bit, gf::Fp3::FromFp(gf::FromU64((n >> bit) & 1u)));
        set(BANK_ACC, acc_n);
        set(BANK_MU, mu_n);
        set(BANK_E0, gf::Fp3::Zero());
        set(BANK_E1, gf::Fp3::Zero());
        set(BANK_OUT, mu_n); // OUT = MU*(1+E0)(1+3E1) = MU
        return true;
    }
    return false;
}

} // namespace

bool BuildRCStage3CoupledMixedRoleAirCS(
    RCStage3RelationRole role, const std::vector<ah::Digest>& endpoint_roots,
    uint32_t path_len, aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    out = {};
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (endpoint_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:mixed_cs:root_count";
        return false;
    }
    const uint32_t rows = path_len + 1;

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(role, kt, why)) return false;
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        return false;
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = rows;
    CopyConstraintFamily(kernel_cs, 0, product);
    uint32_t next_col = kernel_cs.n_columns;

    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (IsInCsStreamEndpoint(e)) {
            const std::array<uint32_t, 8> root8 =
                UnpackStreamRoot(endpoint_roots[i]);
            const aq::AirConstraintSystem<gf::Fp3> frag =
                BuildRCStage3StreamEndpointConstraintSystem(
                    StreamFamilyForEndpoint(e), 0, root8, kPureStreamPathLen);
            CopyConstraintFamily(frag, next_col, product);
            next_col += frag.n_columns;
        } else {
            const std::optional<uint32_t> kc = CoupledEndpointColumn(e, role);
            if (!kc.has_value() || *kc >= kernel_cs.n_columns) {
                if (why != nullptr) *why = "stage3:mixed_cs:endpoint_column";
                return false;
            }
            const aq::AirConstraintSystem<gf::Fp3> open_cs =
                BuildOpeningConstraintSystem(0, endpoint_roots[i], path_len);
            const uint32_t base = next_col;
            CopyConstraintFamily(open_cs, base, product);
            const uint32_t v_col = base + kRCStage3OpeningValueColumn;
            const uint32_t k = *kc;
            product.constraints.push_back(
                {"role_air:endpoint_value_alias", aq::AirKind::kEverywhere, 1,
                 [k, v_col](const std::vector<gf::Fp3>& cur,
                            const std::vector<gf::Fp3>&) {
                     return gf::Sub(cur[k], cur[v_col]);
                 }});
            next_col += kRCStage3OpeningWidth;
        }
    }
    product.n_columns = next_col;
    out = std::move(product);
    return true;
}

RCStage3RoleAirProduct BuildRCStage3CoupledMixedRoleAir(
    RCStage3RelationRole role, std::string* why, const gf::Fp3* real_copy_cell,
    const uint8_t* real_nibble,
    const std::vector<std::array<uint32_t, 8>>* real_stream_roots)
{
    RCStage3RoleAirProduct out;
    out.role = role;
    const uint32_t rows = 8;
    const uint32_t path_len = rows - 1;
    const auto& required = RequiredRCStage3RelationEndpoints(role);

    constraint_bytecode::ProgramTable kt;
    if (!BuildRCStage3CoupledLocalKernelProgramTable(role, kt, why)) {
        out.note = "kernel_bytecode";
        return out;
    }
    aq::AirConstraintSystem<gf::Fp3> kernel_cs;
    if (!constraint_bytecode::BuildAirConstraintSystemFromProgramTable(
            kt, rows, kernel_cs, why)) {
        out.note = "kernel_air";
        return out;
    }
    const uint32_t kernel_w = kernel_cs.n_columns;
    std::vector<std::vector<gf::Fp3>> kernel_cols;
    if (!BuildCoupledMixedKernelWitness(role, kernel_w, rows, kernel_cols,
                                        real_copy_cell, real_nibble)) {
        out.note = "kernel_witness";
        return out;
    }

    std::vector<ah::Digest> roots;
    std::vector<std::vector<std::vector<gf::Fp3>>> pieces;
    uint32_t stream_ix = 0; // index into real_stream_roots (stream endpoints)
    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (IsInCsStreamEndpoint(e)) {
            const RCStage3StreamFamily family = StreamFamilyForEndpoint(e);
            std::array<uint32_t, 8> root8{};
            if (real_stream_roots != nullptr &&
                stream_ix < real_stream_roots->size()) {
                // REAL committed SHA256d root pinned into the light binding.
                root8 = (*real_stream_roots)[stream_ix];
            } else {
                std::array<uint32_t, 8> stream_value{};
                for (uint32_t j = 0; j < 8; ++j)
                    stream_value[j] = static_cast<uint32_t>(e) * 131u + j;
                const RCStage3StreamEndpointManifest manifest =
                    BuildRCStage3StreamEndpointCanonicalManifest(
                        family, stream_value, 0, kPureStreamPathLen);
                std::string rwhy;
                if (!RCStage3StreamEndpointCommittedRoot(family, manifest, root8,
                                                         &rwhy)) {
                    out.note = "committed_root:" + rwhy;
                    return out;
                }
            }
            ++stream_ix;
            const std::vector<std::vector<gf::Fp3>> fw =
                BuildRCStage3StreamEndpointWitness(root8,
                                                   gf::Fp3::FromFp(gf::FromU64(9)));
            std::vector<std::vector<gf::Fp3>> padded;
            for (const auto& col : fw)
                padded.emplace_back(rows, col.empty() ? gf::Fp3::Zero() : col[0]);
            pieces.push_back(std::move(padded));
            roots.push_back(PackStreamRoot(root8));
        } else {
            const std::optional<uint32_t> kc = CoupledEndpointColumn(e, role);
            if (!kc.has_value() || *kc >= kernel_w) {
                out.note = "endpoint_column";
                return out;
            }
            const gf::Fp3 cell = kernel_cols[*kc][0]; // constant endpoint cell
            const RCStage3CommitmentManifest m =
                BuildRCStage3CanonicalManifest(e, cell, 0, path_len);
            pieces.push_back(BuildOpeningWitness(cell, cell, m));
            roots.push_back(m.committed_root);
        }
        out.endpoints.push_back(e);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3CoupledMixedRoleAirCS(role, roots, path_len, product,
                                            &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness = std::move(kernel_cols);
    for (const auto& piece : pieces)
        for (const auto& col : piece) witness.push_back(col);

    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = kernel_w;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

bool BuildRCStage3NoKernelRoleAirCS(
    RCStage3RelationRole role, const std::vector<ah::Digest>& endpoint_roots,
    uint32_t path_len, aq::AirConstraintSystem<gf::Fp3>& out, std::string* why)
{
    out = {};
    const auto& required = RequiredRCStage3RelationEndpoints(role);
    if (endpoint_roots.size() != required.size()) {
        if (why != nullptr) *why = "stage3:nokernel_cs:root_count";
        return false;
    }
    const uint32_t rows = path_len + 1;
    aq::AirConstraintSystem<gf::Fp3> product;
    product.n_rows = rows;
    uint32_t next_col = 0;
    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (IsInCsStreamEndpoint(e)) {
            const std::array<uint32_t, 8> root8 =
                UnpackStreamRoot(endpoint_roots[i]);
            const aq::AirConstraintSystem<gf::Fp3> frag =
                BuildRCStage3StreamEndpointConstraintSystem(
                    StreamFamilyForEndpoint(e), 0, root8, kPureStreamPathLen);
            CopyConstraintFamily(frag, next_col, product);
            next_col += frag.n_columns;
        } else if (WiredEndpointLeafLanes(e) != 0) {
            aq::AirConstraintSystem<gf::Fp3> wired_cs;
            if (!BuildWiredEndpointCS(e, endpoint_roots[i], rows, wired_cs, why)) {
                return false;
            }
            CopyConstraintFamily(wired_cs, next_col, product);
            next_col += wired_cs.n_columns;
        } else {
            // Standalone alg_hash opening (e.g. Params vector opening) — proves
            // the committed value opens to the endpoint authority root; no kernel
            // alias (this role has no arithmetic kernel).
            const aq::AirConstraintSystem<gf::Fp3> open_cs =
                BuildOpeningConstraintSystem(0, endpoint_roots[i], path_len);
            CopyConstraintFamily(open_cs, next_col, product);
            next_col += open_cs.n_columns;
        }
    }
    product.n_columns = next_col;
    out = std::move(product);
    return true;
}

RCStage3RoleAirProduct BuildRCStage3NoKernelRoleAir(
    RCStage3RelationRole role, std::string* why,
    const std::vector<gf::Fp3>* real_open_cells,
    const std::vector<std::array<uint32_t, 8>>* real_stream_roots)
{
    RCStage3RoleAirProduct out;
    out.role = role;
    const uint32_t rows = 8;
    const uint32_t path_len = rows - 1;
    const auto& required = RequiredRCStage3RelationEndpoints(role);

    std::vector<ah::Digest> roots;
    std::vector<std::vector<std::vector<gf::Fp3>>> pieces;
    uint32_t stream_ix = 0; // index into real_stream_roots (stream endpoints)
    uint32_t open_ix = 0;   // index into real_open_cells (opening endpoints)
    for (uint32_t i = 0; i < required.size(); ++i) {
        const RCStage3RelationEndpoint e = required[i];
        if (IsInCsStreamEndpoint(e)) {
            const RCStage3StreamFamily family = StreamFamilyForEndpoint(e);
            std::array<uint32_t, 8> root8{};
            if (real_stream_roots != nullptr &&
                stream_ix < real_stream_roots->size()) {
                root8 = (*real_stream_roots)[stream_ix]; // REAL committed root
            } else {
                std::array<uint32_t, 8> stream_value{};
                for (uint32_t j = 0; j < 8; ++j)
                    stream_value[j] = static_cast<uint32_t>(e) * 131u + j;
                const RCStage3StreamEndpointManifest manifest =
                    BuildRCStage3StreamEndpointCanonicalManifest(
                        family, stream_value, 0, kPureStreamPathLen);
                std::string rwhy;
                if (!RCStage3StreamEndpointCommittedRoot(family, manifest, root8,
                                                         &rwhy)) {
                    out.note = "committed_root:" + rwhy;
                    return out;
                }
            }
            ++stream_ix;
            const std::vector<std::vector<gf::Fp3>> fw =
                BuildRCStage3StreamEndpointWitness(root8,
                                                   gf::Fp3::FromFp(gf::FromU64(9)));
            std::vector<std::vector<gf::Fp3>> padded;
            for (const auto& col : fw)
                padded.emplace_back(rows, col.empty() ? gf::Fp3::Zero() : col[0]);
            pieces.push_back(std::move(padded));
            roots.push_back(PackStreamRoot(root8));
        } else if (WiredEndpointLeafLanes(e) != 0) {
            // BuilderTrace: fold the 13-lane TraceColumnLeaf row to builder_trace_root.
            std::vector<gf::Fp3> row = {
                gf::FromU64_3(0), gf::FromU64_3(1), gf::FromU64_3(2),
                gf::FromU64_3(3), gf::FromU64_3(8), gf::FromU64_3(8),
                gf::FromU64_3(0), gf::FromU64_3(4), gf::FromU64_3(0)};
            {
                uint256 r;
                std::fill(r.begin(), r.end(), 0x5b);
                PushRootLanesFp3(row, r); // wiring_vector_root(4)
            }
            const RCStage3SpongeProduct sp =
                BuildRCStage3LeafHashRowSpongeProduct(row, 0, rows, why);
            if (!sp.ok) {
                out.note = "builder_trace:" + sp.note;
                return out;
            }
            pieces.push_back(sp.witness);
            roots.push_back(sp.digest);
        } else {
            // Standalone vector opening (e.g. Params, extract in/out): a REAL
            // block-derived cell when provided, else synthetic.
            const gf::Fp3 cell =
                (real_open_cells != nullptr && open_ix < real_open_cells->size())
                    ? (*real_open_cells)[open_ix]
                    : gf::Fp3::FromFp(gf::FromU64(0xB1u + i));
            ++open_ix;
            const RCStage3CommitmentManifest m =
                BuildRCStage3CanonicalManifest(e, cell, 0, path_len);
            pieces.push_back(BuildOpeningWitness(cell, cell, m));
            roots.push_back(m.committed_root);
        }
        out.endpoints.push_back(e);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3NoKernelRoleAirCS(role, roots, path_len, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness;
    for (const auto& piece : pieces)
        for (const auto& col : piece) witness.push_back(col);

    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = 0;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled";
    return out;
}

// ===========================================================================
// Stream/digest endpoints: §4 SHA256d manifest-binding root-equality pin.
// ===========================================================================

RCStage3StreamManifestFamily RCStage3StreamEndpointManifestFamily(
    RCStage3RelationEndpoint endpoint)
{
    switch (endpoint) {
    // XOF counter streams.
    case RCStage3RelationEndpoint::EpisodeBuilderOperandXof:
    case RCStage3RelationEndpoint::CoupledBankSeedXof:
    case RCStage3RelationEndpoint::CoupledExchangeHashXof:
        return RCStage3StreamManifestFamily::XofCounter;
    // ChaCha init+block streams.
    case RCStage3RelationEndpoint::EpisodeExtractChaCha:
    case RCStage3RelationEndpoint::CoupledExtractChaCha:
        return RCStage3StreamManifestFamily::ChaChaInitAndBlock;
    // Complete leaf/node (tile-tree) stream.
    case RCStage3RelationEndpoint::EpisodeTileTreeStream:
    case RCStage3RelationEndpoint::EpisodeTileTreeLeafHash:
    case RCStage3RelationEndpoint::EpisodeTileTreeInternalHash:
    case RCStage3RelationEndpoint::EpisodeTileTreeRoot:
        return RCStage3StreamManifestFamily::CompleteStreamTileTree;
    // Direct SHA256d digest streams (relation families).
    case RCStage3RelationEndpoint::EpisodeDigestRoundRoots:
    case RCStage3RelationEndpoint::EpisodeDigestValue:
    case RCStage3RelationEndpoint::EpisodeDigestHeaderTarget:
    case RCStage3RelationEndpoint::EpisodeDigestPow:
        return RCStage3StreamManifestFamily::DirectSha256dEpisodeDigest;
    case RCStage3RelationEndpoint::CoupledBarrierInput:
    case RCStage3RelationEndpoint::CoupledBarrierHash:
    case RCStage3RelationEndpoint::CoupledBarrierOutput:
        return RCStage3StreamManifestFamily::DirectSha256dCoupledBarrier;
    case RCStage3RelationEndpoint::CoupledDigestBankAndBarriers:
    case RCStage3RelationEndpoint::CoupledDigestHash:
    case RCStage3RelationEndpoint::CoupledDigestValue:
        return RCStage3StreamManifestFamily::DirectSha256dCoupledDigest;
    default:
        return RCStage3StreamManifestFamily::None;
    }
}

RCStage3StreamFamily
RCStage3StreamFamilyForEndpoint(RCStage3RelationEndpoint endpoint)
{
    switch (RCStage3StreamEndpointManifestFamily(endpoint)) {
    case RCStage3StreamManifestFamily::XofCounter:
        return RCStage3StreamFamily::XofCounter;
    case RCStage3StreamManifestFamily::ChaChaInitAndBlock:
        return RCStage3StreamFamily::ChaChaInitAndBlock;
    case RCStage3StreamManifestFamily::CompleteStreamTileTree:
        return RCStage3StreamFamily::CompleteStream;
    case RCStage3StreamManifestFamily::DirectSha256dEpisodeDigest:
        return RCStage3StreamFamily::DirectSha256dEpisodeDigest;
    case RCStage3StreamManifestFamily::DirectSha256dCoupledBarrier:
        return RCStage3StreamFamily::DirectSha256dCoupledBarrier;
    case RCStage3StreamManifestFamily::DirectSha256dCoupledDigest:
        return RCStage3StreamFamily::DirectSha256dCoupledDigest;
    case RCStage3StreamManifestFamily::None:
        // CoupledBankRoot / EpisodeBuilderSeedChain close through the generic
        // DirectSha256d closer (no residual-family domain of their own).
        return RCStage3StreamFamily::DirectSha256d;
    }
    return RCStage3StreamFamily::DirectSha256d;
}

bool RCStage3EndpointHasStreamOpening(RCStage3RelationEndpoint endpoint)
{
    return RCStage3StreamEndpointManifestFamily(endpoint) !=
           RCStage3StreamManifestFamily::None;
}

uint32_t RCStage3StreamOpeningEndpointCount()
{
    uint32_t n = 0;
    for (const RCStage3RelationRole role : RCStage3UnifiedRoleOrder()) {
        for (const RCStage3RelationEndpoint endpoint :
             RequiredRCStage3RelationEndpoints(role)) {
            if (RCStage3EndpointHasStreamOpening(endpoint)) ++n;
        }
    }
    return n;
}

namespace {

// Build the canonical §4 manifest recursive binding for one family and verify it
// (against the honest or a corrupted binding).  Reuses the exact proven-good
// manifest fixtures from the hash-air binding tests.
bool BuildAndVerifyFamilyBinding(
    RCStage3StreamManifestFamily family, bool tamper_stream,
    stage3_hash_air::HashManifestRecursiveBinding& out_binding,
    bool& out_verified, std::string* why)
{
    using namespace stage3_hash_air;
    out_verified = false;
    const auto corrupt = [&](HashManifestRecursiveBinding b) {
        b.stream_column_root.begin()[0] ^= 0x01;
        return b;
    };

    switch (family) {
    case RCStage3StreamManifestFamily::XofCounter: {
        uint256 seed;
        for (uint32_t i = 0; i < 32; ++i) seed.begin()[i] = 9 * i + 3;
        CounterXofManifest m;
        if (!BuildCounterXofManifest(seed, 0x65, CounterXofMode::Scale2Bit, 257,
                                     m, why))
            return false;
        if (!BuildXofCounterManifestRecursiveBinding(m, out_binding, why))
            return false;
        out_verified = VerifyXofCounterManifestRecursiveBinding(
            m, tamper_stream ? corrupt(out_binding) : out_binding, why);
        return true;
    }
    case RCStage3StreamManifestFamily::ChaChaInitAndBlock: {
        std::array<uint8_t, 32> key{};
        for (uint32_t i = 0; i < 32; ++i) key[i] = 5 * i + 1;
        ChaChaConsumptionManifest m;
        if (!BuildChaChaConsumptionManifest(key, 0xa1b2c3d4U,
                                            0x1020304050607080ULL, 13, 141, m,
                                            why))
            return false;
        if (!BuildChaChaInitAndBlockManifestRecursiveBinding(m, out_binding, why))
            return false;
        out_verified = VerifyChaChaInitAndBlockManifestRecursiveBinding(
            m, tamper_stream ? corrupt(out_binding) : out_binding, why);
        return true;
    }
    case RCStage3StreamManifestFamily::CompleteStreamTileTree: {
        std::vector<uint8_t> stream(197);
        for (uint32_t i = 0; i < stream.size(); ++i) stream[i] = 17 * i + 4;
        TileTreeManifest m;
        if (!BuildTileTreeManifest(stream, 48, m, why)) return false;
        if (!BuildCompleteStreamManifestRecursiveBinding(m, out_binding, why))
            return false;
        out_verified = VerifyCompleteStreamManifestRecursiveBinding(
            m, tamper_stream ? corrupt(out_binding) : out_binding, why);
        return true;
    }
    case RCStage3StreamManifestFamily::DirectSha256dEpisodeDigest:
    case RCStage3StreamManifestFamily::DirectSha256dCoupledBarrier:
    case RCStage3StreamManifestFamily::DirectSha256dCoupledDigest: {
        std::vector<uint8_t> preimage(197);
        for (uint32_t i = 0; i < preimage.size(); ++i) preimage[i] = 17 * i + 4;
        const DirectHashRelation relation =
            family == RCStage3StreamManifestFamily::DirectSha256dEpisodeDigest
                ? DirectHashRelation::EpisodeDigest
            : family == RCStage3StreamManifestFamily::DirectSha256dCoupledBarrier
                ? DirectHashRelation::CoupledBarrier
                : DirectHashRelation::CoupledDigest;
        DirectSha256dManifest m;
        if (!BuildDirectSha256dManifest(relation, preimage, m, why)) return false;
        if (!BuildCompleteStreamManifestRecursiveBinding(m, out_binding, why))
            return false;
        out_verified = VerifyCompleteStreamManifestRecursiveBinding(
            m, tamper_stream ? corrupt(out_binding) : out_binding, why);
        return true;
    }
    default:
        return false;
    }
}

} // namespace

RCStage3StreamEndpointOpening OpenRCStage3StreamEndpointCommitment(
    RCStage3RelationEndpoint endpoint, bool tamper_stream, bool substitute_root,
    std::string* why)
{
    RCStage3StreamEndpointOpening out;
    out.endpoint = endpoint;
    out.family = RCStage3StreamEndpointManifestFamily(endpoint);
    if (out.family == RCStage3StreamManifestFamily::None) {
        out.note = "no_manifest_binding_family";
        if (why != nullptr) *why = "stage3:stream_opening:no_manifest_binding_family";
        return out;
    }

    stage3_hash_air::HashManifestRecursiveBinding binding;
    bool verified = false;
    if (!BuildAndVerifyFamilyBinding(out.family, tamper_stream, binding, verified,
                                     why)) {
        out.note = "binding_build_failed";
        return out;
    }
    out.binding_built = true;
    out.binding_verified = verified;
    out.manifest_commitment = binding.manifest_commitment;
    out.stream_column_root = binding.stream_column_root;

    // Pin the endpoint's committed stream root to the §4 stream_column_root.
    uint256 endpoint_committed_root = binding.stream_column_root;
    if (substitute_root) endpoint_committed_root.begin()[0] ^= 0x01;
    out.root_pinned = (endpoint_committed_root == binding.stream_column_root);

    out.opens = out.binding_verified && out.root_pinned;
    out.note = out.opens ? "opens" : "violation";
    if (why != nullptr && out.opens) *why = "stage3:stream_opening:opens";
    return out;
}

bool VerifyRCStage3RelationClosureV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3UnifiedRootPublicPin& root,
    const RCStage3UnifiedCtlProofBundle& ctl_bundle,
    const RCStage3RelationClosureV1& closure,
    std::string* why)
{
    if (closure.magic != kRCStage3RelationClosureMagic) {
        return Fail(why, "bad_magic");
    }
    if (closure.version != kRCStage3RelationClosureVersion) {
        return Fail(why, "bad_version");
    }
    if (closure.strategy !=
        RCStage3RelationClosureStrategy::HashBoundMultiproof) {
        return Fail(why, "noncanonical_strategy");
    }
    if (!ValidateRCStage3UnifiedRootPublicBinding(statement, root, why)) {
        return Fail(why, "unified_root_public_binding");
    }
    if (!VerifyRCStage3UnifiedCtlProofBundle(root, ctl_bundle, why)) {
        return Fail(why, "ctl_bundle");
    }
    if (closure.unified_root_seed !=
            ComputeRCStage3UnifiedRootSeed(root) ||
        closure.statement_commitment != root.statement_commitment ||
        closure.ctl_proof_bundle_commitment !=
            CommitRCStage3UnifiedCtlProofBundle(ctl_bundle)) {
        return Fail(why, "root_binding");
    }
    if (closure.roles.size() != kRCStage3RelationClosureRoleCount ||
        root.roles.size() != kRCStage3RelationClosureRoleCount ||
        ctl_bundle.children.size() != kRCStage3RelationClosureRoleCount) {
        return Fail(why, "role_count");
    }

    const auto& order = RCStage3UnifiedRoleOrder();
    uint32_t endpoint_total = 0;
    for (size_t i = 0; i < order.size(); ++i) {
        const auto& role = closure.roles[i];
        const auto& root_role = root.roles[i];
        const auto& ctl_child = ctl_bundle.children[i];
        if (role.role != order[i] || root_role.role != order[i] ||
            ctl_child.role != order[i]) {
            return Fail(why, "role_order");
        }
        if (role.relation_commitment != root_role.relation_commitment ||
            role.relation_commitment !=
                ctl_child.relation_export.relation_commitment) {
            return Fail(why, "relation_commitment");
        }
        if (role.relation_statement_root.IsNull()) {
            return Fail(why, "null_relation_statement");
        }
        const auto& required = RequiredRCStage3RelationEndpoints(role.role);
        if (role.endpoints.size() != required.size()) {
            return Fail(why, "endpoint_count");
        }
        endpoint_total += static_cast<uint32_t>(required.size());
        for (size_t j = 0; j < required.size(); ++j) {
            const auto& endpoint = role.endpoints[j];
            if (endpoint.endpoint != required[j]) {
                return Fail(why, "endpoint_order");
            }
            if (endpoint.instance_count == 0 ||
                endpoint.manifest_root.IsNull() ||
                endpoint.proof_root.IsNull() ||
                endpoint.semantic_root.IsNull() ||
                endpoint.proof_column_root.IsNull() ||
                endpoint.recursive_child_commitment.IsNull()) {
                return Fail(why, "incomplete_endpoint");
            }
        }
        if (role.endpoint_multiproof_root !=
            ComputeRCStage3RelationRoleMultiproofRoot(role)) {
            return Fail(why, "endpoint_multiproof_root");
        }
        const auto* exported = FindEndpoint(
            role, RCStage3RelationCtlExportEndpoint(role.role));
        if (exported == nullptr ||
            exported->proof_column_root !=
                ctl_child.relation_export
                    .prechallenge_column_roots[stage3_ctl_col::VALUE]) {
            return Fail(why, "proof_to_ctl_value_root");
        }

        if (role.role == RCStage3RelationRole::EpisodeDigest &&
            exported->semantic_root !=
                statement.public_inputs.episode_digest) {
            return Fail(why, "episode_digest");
        }
        if (role.role == RCStage3RelationRole::CoupledDigest &&
            exported->semantic_root !=
                statement.public_inputs.coupled_digest) {
            return Fail(why, "coupled_digest");
        }
    }
    if (endpoint_total != kRCStage3RelationClosureEndpointCount) {
        return Fail(why, "registry_endpoint_total");
    }
    if (closure.composition_link_commitment !=
            root.composition_link_commitment ||
        closure.final_digest_manifest_root.IsNull() ||
        closure.final_digest_proof_root.IsNull() ||
        closure.final_digest_recursive_child_commitment.IsNull() ||
        closure.final_digest_semantic_root !=
            statement.public_inputs.final_digest) {
        return Fail(why, "final_digest");
    }
    if (closure.closure_commitment !=
        ComputeRCStage3RelationClosureCommitment(closure)) {
        return Fail(why, "closure_commitment");
    }
    if (why != nullptr) {
        *why = "stage3:relation_closure:v1_binding_ok_recursive_children_open";
    }
    return true;
}

} // namespace matmul::v4::rc
