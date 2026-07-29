// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
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
constexpr char DIRECT_ALIAS_AUX_DOMAIN[] =
    "BTX_RC_STAGE3_RELATION_CTL_DIRECT_ALIAS_AUX_V1";
constexpr char SIGNED_RANGE_DUAL_CTL_AUX_DOMAIN[] =
    "BTX_RC_STAGE3_SIGNED_RANGE_DUAL_CTL_AUX_V1";
constexpr char BUILDER_PROGRAM_ALIAS_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_BUILDER_PROGRAM_CTL_ALIAS_V1";
constexpr char EPISODE_GEMM_PROGRAM_BATCH_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_PROGRAM_CTL_BATCH_V1";
constexpr char EPISODE_GEMM_PROGRAM_CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_GEMM_PROGRAM_CTL_TRANSCRIPT_V1";
constexpr char EPISODE_EXTRACT_PROGRAM_BATCH_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_PROGRAM_CTL_BATCH_V1";
constexpr char EPISODE_EXTRACT_PROGRAM_CTL_TRANSCRIPT_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_PROGRAM_CTL_TRANSCRIPT_V1";
constexpr char EPISODE_EXTRACT_OUTPUT_RECEIVER_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_EPISODE_EXTRACT_OUTPUT_RECEIVER_V1";
constexpr char COUPLED_ENDPOINT_SEED_DOMAIN[] =
    "BTX_RC_STAGE3_COUPLED_ENDPOINT_AIR_V1";

// Parent-verified recursive-child evidence bits (one per relation endpoint).
// Default false. Set only by RegisterRCStage3ParentVerifiedRecursiveChild-
// EvidenceV1 after ordinary V3 tape / consumer leaves are verified inside
// the narrow parent and mapped onto an endpoint. Never derived from
// kRCStage3RelationClosureRecursiveChildrenExecutable alone.
std::array<bool, kRCStage3RelationClosureEndpointCount>
    g_parent_verified_recursive_child_evidence{};

[[nodiscard]] uint16_t EndpointEvidenceIndex(
    RCStage3RelationEndpoint endpoint)
{
    return static_cast<uint16_t>(endpoint);
}

constexpr std::array<RCStage3RelationEndpoint,
                     kRCStage3BuilderProgramAliasLaneCountV1>
    BUILDER_ALIAS_ENDPOINTS{
        RCStage3RelationEndpoint::EpisodeBuilderParams,
        RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
        RCStage3RelationEndpoint::EpisodeBuilderOperandXof,
        RCStage3RelationEndpoint::EpisodeBuilderTrace,
    };
constexpr std::array<uint32_t,
                     kRCStage3BuilderProgramAliasLaneCountV1>
    BUILDER_ALIAS_COLUMNS{
        universal_topology::production_family_col_v1::
            EpisodeBuilderParams,
        universal_topology::production_family_col_v1::
            EpisodeBuilderSeedChain,
        universal_topology::production_family_col_v1::
            EpisodeBuilderOperandXof,
        universal_topology::production_family_col_v1::
            EpisodeBuilderTrace,
    };

constexpr std::array<RCStage3RelationEndpoint,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>
    EPISODE_GEMM_BATCH_ENDPOINTS{
        RCStage3RelationEndpoint::EpisodeGemmOperandA,
        RCStage3RelationEndpoint::EpisodeGemmOperandB,
        RCStage3RelationEndpoint::EpisodeGemmOutputY,
        RCStage3RelationEndpoint::EpisodeGemmSignedRange,
    };
constexpr uint32_t EPISODE_GEMM_PROGRAM_COLUMNS = 3;
constexpr uint32_t EPISODE_GEMM_RANGE_PROGRAM_COLUMNS =
    kRCStage3SignedRangeColumns + 2 +
    kRCStage3SignedRangeBits;
constexpr std::array<uint32_t,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>
    EPISODE_GEMM_BATCH_SOURCE_COLUMNS{
        1,
        2,
        0,
        EPISODE_GEMM_PROGRAM_COLUMNS +
            kRCStage3RangeValue,
    };
constexpr std::array<RCStage3RelationEndpoint,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>
    EPISODE_EXTRACT_BATCH_ENDPOINTS{
        RCStage3RelationEndpoint::EpisodeExtractInput,
        RCStage3RelationEndpoint::EpisodeExtractSampler,
        RCStage3RelationEndpoint::EpisodeExtractScale,
        RCStage3RelationEndpoint::EpisodeExtractOutput,
    };
constexpr std::array<uint32_t,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>
    EPISODE_EXTRACT_BATCH_SOURCE_COLUMNS{
        air_quotient::kColUMix,
        air_quotient::kColMixed,
        air_quotient::kColE0,
        air_quotient::kColOut,
    };

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
        case Endpoint::EpisodeExtractInput:
            return air_quotient::kColUMix;
        case Endpoint::EpisodeExtractSampler:
            return air_quotient::kColMixed;
        case Endpoint::EpisodeExtractScale:
            return air_quotient::kColE0;
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
    case RCStage3RelationEndpoint::EpisodeBuilderParams:
        episode(
            universal_topology::production_family_col_v1::
                EpisodeBuilderParams,
            "episode_air:builder_program:PARAMS",
            "the canonical builder bytecode cell and its independently "
            "challenged CTL VALUE lane execute in one shared quotient proof; "
            "recursive-child consumption remains");
        break;
    case RCStage3RelationEndpoint::EpisodeBuilderSeedChain:
        episode(
            universal_topology::production_family_col_v1::
                EpisodeBuilderSeedChain,
            "episode_air:builder_program:SEED_CHAIN",
            "the canonical builder bytecode cell and its independently "
            "challenged CTL VALUE lane execute in one shared quotient proof; "
            "recursive-child consumption remains");
        break;
    case RCStage3RelationEndpoint::EpisodeBuilderOperandXof:
        episode(
            universal_topology::production_family_col_v1::
                EpisodeBuilderOperandXof,
            "episode_air:builder_program:OPERAND_XOF",
            "the canonical builder bytecode cell and its independently "
            "challenged CTL VALUE lane execute in one shared quotient proof; "
            "recursive-child consumption remains");
        break;
    case RCStage3RelationEndpoint::EpisodeBuilderTrace:
        episode(
            universal_topology::production_family_col_v1::
                EpisodeBuilderTrace,
            "episode_air:builder_program:TRACE",
            "the canonical builder bytecode cell and its independently "
            "challenged CTL VALUE lane execute in one shared quotient proof; "
            "recursive-child consumption remains");
        break;
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
        out.same_trace_ctl_alias = true;
        out.semantic_relation_complete = true;
        out.relation_column = kRCStage3RangeValue;
        out.source = "gemm_extract:signed_range:VALUE";
        out.remaining =
            "the signed-range VALUE cell and both producer/Extract CTL VALUE "
            "cells execute in one dual-alias quotient proof; its recursive "
            "verifier child is not consumed";
        break;
    case RCStage3RelationEndpoint::EpisodeExtractInput:
        episode(air_quotient::kColUMix,
                "episode_air:extract_program:U_MIX",
                "the canonical scale-bound ExtractCore input cell and its "
                "producer CTL VALUE execute in one quotient proof; ChaCha "
                "input provenance and recursive consumption remain");
        break;
    case RCStage3RelationEndpoint::EpisodeExtractSampler:
        episode(air_quotient::kColMixed,
                "episode_air:extract_program:MIXED",
                "the canonical scale-bound ExtractCore sampler cell and its "
                "producer CTL VALUE execute in one quotient proof; ChaCha "
                "input provenance and recursive consumption remain");
        break;
    case RCStage3RelationEndpoint::EpisodeExtractScale:
        episode(air_quotient::kColE0,
                "episode_air:extract_program:E0",
                "the verifier-scale-bound ExtractCore E0 cell and its "
                "producer CTL VALUE execute in one quotient proof; SHA/XOF "
                "scale provenance and recursive consumption remain");
        break;
    case RCStage3RelationEndpoint::EpisodeExtractOutput:
        episode(air_quotient::kColOut,
                "episode_air:extract_program:OUT",
                "the canonical scale-bound ExtractCore output cell and its "
                "producer CTL VALUE execute in one quotient proof; complete "
                "output provenance and recursive consumption remain");
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

    // Stream / vector / wired openings expose an aliasable VALUE cell through
    // the stream-endpoint bind fragment or the sibling wired pin.  With the
    // complete fixed-point parent hosting those children, they count as
    // same-trace CTL aliases for the HashBoundMultiproof ledger.
    if (out.semantic_relation_complete &&
        kRCStage3RelationClosureRecursiveChildrenExecutable &&
        !out.same_trace_ctl_alias) {
        out.same_trace_ctl_alias = true;
        if (!out.relation_air_cell) {
            out.relation_air_cell = true;
        }
    }

    // The cell audit has no caller-supplied proof bundle from which it could
    // infer transitive producer closure.  Only the two verifier-regenerated
    // public anchors terminate without another semantic endpoint.  Keeping
    // these facts separate prevents the 52/52 local-opening inventory from
    // being misreported as 52/52 episode/coupled computation closure.
    out.producer_provenance_complete =
        out.semantic_relation_complete &&
        (endpoint ==
             RCStage3RelationEndpoint::EpisodeBuilderParams ||
         endpoint ==
             RCStage3RelationEndpoint::EpisodeDigestHeaderTarget);
    out.strict_transitive_complete =
        out.semantic_relation_complete &&
        out.producer_provenance_complete;
    // Honest consumption: parent-verified child evidence is required.
    // RecursiveChildrenExecutable alone must not invent this bit.
    const bool parent_verified_child =
        RCStage3EndpointParentVerifiedRecursiveChildEvidenceV1(endpoint);
    out.recursive_child_consumed =
        out.semantic_relation_complete &&
        out.same_trace_ctl_alias &&
        parent_verified_child;
    if (out.recursive_child_consumed) {
        out.remaining =
            "normalized recursive child executes the opened/CTL-aliased "
            "endpoint; consensus authority remains fail-closed";
    } else if (parent_verified_child) {
        out.remaining =
            "parent-verified recursive child evidence present, but "
            "semantic/CTL alias still open";
    }

    return out;
}

bool ResolveBuilderProgramAirV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    constraint_bytecode::ProgramTable& table,
    AirCS& out,
    std::string* why)
{
    table = {};
    out = {};
    if (pin.version != kRCStage3BuilderProgramAliasVersionV1 ||
        pin.statement_commitment.IsNull() ||
        pin.n_rows < 2 ||
        (pin.n_rows & (pin.n_rows - 1U)) != 0) {
        return Fail(why, "builder_alias:public_pin_shape");
    }
    if (!universal_topology::
            BuildCanonicalProductionFamilyProgramTableV1(
                soundness_scenarios::ProductionProofSiteKind::
                    EpisodeBuilderCounterXof,
                RCStage3RelationRole::EpisodeDeterministicBuilder,
                table, why)) {
        return Fail(why, "builder_alias:canonical_program");
    }
    const auto keys =
        constraint_bytecode::
            CommitProgramTableForExternalAndRecursiveUse(table);
    if (!keys.same_canonical_serialization ||
        keys.external_sha256d != pin.program_external_sha256d ||
        keys.recursive_alg_hash !=
            pin.program_recursive_alg_hash ||
        pin.relation_column_roots.size() != table.current_width) {
        table = {};
        return Fail(why, "builder_alias:program_or_root_pin");
    }
    for (const auto& root : pin.relation_column_roots) {
        if (root.IsNull()) {
            table = {};
            return Fail(why, "builder_alias:null_relation_root");
        }
    }
    if (!constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, pin.n_rows, out, why) ||
        out.n_columns != table.current_width ||
        table.challenge_width != 0) {
        table = {};
        out = {};
        return Fail(why, "builder_alias:program_air");
    }
    out.preprocessed_roots.reserve(
        pin.relation_column_roots.size());
    for (uint32_t column = 0;
         column < pin.relation_column_roots.size();
         ++column) {
        out.preprocessed_roots.emplace_back(
            column, pin.relation_column_roots[column]);
    }
    return true;
}

uint256 ConstantProgramColumnRootV1(
    const Fp3& value,
    uint32_t n_rows,
    uint32_t n_coeffs)
{
    if (n_rows == 0 || n_coeffs < n_rows) return {};
    return air_quotient::AirCommittedValuesRoot<Fp3>(
        std::vector<Fp3>(n_rows, value), n_coeffs);
}

std::vector<uint256> ExpectedSignedRangeProgramRootsV1(
    const RCStage3SignedRangePin& pin,
    uint32_t n_coeffs)
{
    constexpr uint32_t MAX_ABS =
        kRCStage3SignedRangeColumns;
    constexpr uint32_t MAX_ABS_BITS = MAX_ABS + 1;
    constexpr uint32_t LOGICAL_ROWS =
        MAX_ABS_BITS + kRCStage3SignedRangeBits;
    static_assert(
        LOGICAL_ROWS + 1 ==
        EPISODE_GEMM_RANGE_PROGRAM_COLUMNS);
    if (pin.column_roots.size() !=
            kRCStage3SignedRangeColumns ||
        n_coeffs < pin.n_rows) {
        return {};
    }
    std::vector<uint256> roots(
        EPISODE_GEMM_RANGE_PROGRAM_COLUMNS);
    for (uint32_t column = 0;
         column < kRCStage3SignedRangeColumns;
         ++column) {
        if (pin.column_roots[column].column != column ||
            pin.column_roots[column].root.IsNull()) {
            return {};
        }
        roots[column] = pin.column_roots[column].root;
    }
    roots[MAX_ABS] = ConstantProgramColumnRootV1(
        gkr_field::FromU64_3(pin.max_abs),
        pin.n_rows, n_coeffs);
    for (uint32_t bit = 0;
         bit < kRCStage3SignedRangeBits;
         ++bit) {
        roots[MAX_ABS_BITS + bit] =
            ConstantProgramColumnRootV1(
                gkr_field::FromU64_3(
                    (pin.max_abs >> bit) & 1U),
                pin.n_rows, n_coeffs);
    }
    roots[LOGICAL_ROWS] = ConstantProgramColumnRootV1(
        gkr_field::FromU64_3(pin.logical_rows),
        pin.n_rows, n_coeffs);
    if (std::any_of(
            roots.begin(), roots.end(),
            [](const uint256& root) {
                return root.IsNull();
            })) {
        return {};
    }
    return roots;
}

bool ResolveEpisodeGemmProgramBatchAirV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    AirCS& out,
    std::vector<uint256>& relation_roots,
    std::string* why)
{
    out = {};
    relation_roots.clear();
    if (pin.version !=
            kRCStage3EpisodeGemmProgramBatchVersionV1 ||
        pin.statement_commitment.IsNull() ||
        pin.statement_commitment != manifest.statement_commitment ||
        pin.statement_commitment != range_pin.statement_commitment ||
        pin.n_rows != range_pin.n_rows ||
        pin.layer_ordinal != range_pin.layer_ordinal ||
        pin.layer_ordinal >= manifest.layers.size() ||
        range_pin.manifest_commitment !=
            ComputeRCStage3GemmExtractManifestCommitment(manifest) ||
        !ValidateRCStage3GemmExtractManifest(manifest, why)) {
        return Fail(why, "gemm_batch:public_pin_shape");
    }
    for (const auto& root : pin.gemm_column_roots) {
        if (root.IsNull()) {
            return Fail(why, "gemm_batch:null_gemm_root");
        }
    }

    // Validate the fully populated range pin against the exact manifest before
    // replacing the native callbacks by their canonical bytecode equivalent.
    AirCS native_range;
    if (!ResolveRCStage3SignedRangeCtlAlignedConstraintSystem(
            manifest, range_pin, native_range, why)) {
        return Fail(why, "gemm_batch:range_pin");
    }

    constraint_bytecode::ProgramTable gemm_table;
    constraint_bytecode::ProgramTable range_table;
    if (!universal_topology::
            BuildCanonicalProductionFamilyProgramTableV1(
                soundness_scenarios::ProductionProofSiteKind::
                    EpisodeGemmSumcheck,
                RCStage3RelationRole::EpisodeGemm,
                gemm_table, why) ||
        !universal_topology::
            BuildCanonicalProductionFamilyProgramTableV1(
                soundness_scenarios::ProductionProofSiteKind::
                    EpisodeSignedRange,
                RCStage3RelationRole::EpisodeGemm,
                range_table, why)) {
        return Fail(why, "gemm_batch:canonical_program");
    }
    const auto gemm_keys =
        constraint_bytecode::
            CommitProgramTableForExternalAndRecursiveUse(gemm_table);
    const auto range_keys =
        constraint_bytecode::
            CommitProgramTableForExternalAndRecursiveUse(range_table);
    if (!gemm_keys.same_canonical_serialization ||
        !range_keys.same_canonical_serialization ||
        gemm_keys.external_sha256d !=
            pin.gemm_program_external_sha256d ||
        gemm_keys.recursive_alg_hash !=
            pin.gemm_program_recursive_alg_hash ||
        range_keys.external_sha256d !=
            pin.range_program_external_sha256d ||
        range_keys.recursive_alg_hash !=
            pin.range_program_recursive_alg_hash ||
        gemm_table.current_width !=
            EPISODE_GEMM_PROGRAM_COLUMNS ||
        range_table.current_width !=
            EPISODE_GEMM_RANGE_PROGRAM_COLUMNS ||
        gemm_table.challenge_width != 0 ||
        range_table.challenge_width != 0) {
        return Fail(why, "gemm_batch:program_key_or_shape");
    }

    AirCS gemm_cs;
    AirCS range_cs;
    if (!constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                gemm_table, pin.n_rows, gemm_cs, why) ||
        !constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                range_table, pin.n_rows, range_cs, why)) {
        return Fail(why, "gemm_batch:program_air");
    }

    const uint64_t quotient =
        3 * static_cast<uint64_t>(pin.n_rows) - 3;
    if (quotient >
        std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "gemm_batch:coefficient_overflow");
    }
    const uint32_t n_coeffs =
        FriNextPow2(static_cast<uint32_t>(quotient));
    const auto range_roots =
        ExpectedSignedRangeProgramRootsV1(
            range_pin, n_coeffs);
    if (range_roots.size() !=
        EPISODE_GEMM_RANGE_PROGRAM_COLUMNS) {
        return Fail(why, "gemm_batch:range_parameter_roots");
    }
    for (uint32_t column = 0;
         column < pin.gemm_column_roots.size();
         ++column) {
        gemm_cs.preprocessed_roots.emplace_back(
            column, pin.gemm_column_roots[column]);
    }
    for (uint32_t column = 0;
         column < range_roots.size();
         ++column) {
        range_cs.preprocessed_roots.emplace_back(
            column, range_roots[column]);
    }

    out.n_rows = pin.n_rows;
    out.n_columns =
        gemm_cs.n_columns + range_cs.n_columns;
    CopyConstraintFamily(gemm_cs, 0, out);
    CopyConstraintFamily(
        range_cs, gemm_cs.n_columns, out);

    // Match the production range/CTL coefficient domain without changing the
    // accepted relation: ACTIVE is already boolean in the canonical table.
    AirConstraint alignment;
    alignment.name =
        "stage3.gemm_batch.range.active_boolean_square";
    alignment.kind = air_quotient::AirKind::kEverywhere;
    alignment.alg_degree = 4;
    alignment.eval = [](
                         const std::vector<Fp3>& row,
                         const std::vector<Fp3>&) {
        const Fp3 active =
            row[EPISODE_GEMM_PROGRAM_COLUMNS +
                kRCStage3RangeActive];
        const Fp3 boolean_identity =
            gkr_field::Mul(
                active,
                gkr_field::Sub(active, Fp3::One()));
        return gkr_field::Mul(
            boolean_identity, boolean_identity);
    };
    out.constraints.push_back(std::move(alignment));
    if (out.QuotientLen() != quotient) {
        out = {};
        return Fail(why, "gemm_batch:degree_alignment");
    }

    relation_roots.assign(
        pin.gemm_column_roots.begin(),
        pin.gemm_column_roots.end());
    relation_roots.insert(
        relation_roots.end(),
        range_roots.begin(), range_roots.end());
    return true;
}

Fp3 EpisodeExtractProgramChallengeV1(
    const uint256& seed,
    const char* label,
    const std::vector<uint256>& base_roots,
    uint32_t n_rows,
    uint32_t n_coeffs)
{
    const uint256 digest =
        air_quotient::AirChallengeDigest(
            seed, label, base_roots,
            {n_rows, n_coeffs});
    return gkr_field::FromChallengeBytes3(
        digest.data());
}

bool ResolveEpisodeExtractProgramBatchAirV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    constraint_bytecode::ProgramTable& table,
    AirCS& out,
    std::vector<uint256>& relation_roots,
    std::string* why)
{
    table = {};
    out = {};
    relation_roots.clear();
    const auto& episode = pin.episode_air;
    if (pin.version !=
            kRCStage3EpisodeExtractProgramBatchVersionV1 ||
        episode.role != RCStage3RelationRole::EpisodeExtract ||
        episode.family !=
            RCStage3EpisodeAirFamily::ExtractSamplerCoreFp3V1 ||
        episode.column_roots.size() !=
            air_quotient::kRcSamplerNumCols ||
        episode.n_rows == 0 ||
        episode.n_coeffs == 0) {
        return Fail(why, "extract_batch:public_pin_shape");
    }

    // Resolve the legacy/native adapter only as an independent public-pin and
    // transcript validator.  The returned relation below is built from the
    // canonical ProgramTable, not from the native callbacks.
    AirCS native;
    if (!ResolveRCStage3EpisodeAirConstraintSystem(
            statement, episode, native, why)) {
        return Fail(why, "extract_batch:episode_pin");
    }
    if (!BuildRCStage3EpisodeExtractLocalKernelProgramTable(
            episode.extract_scale_e, table, why)) {
        return Fail(why, "extract_batch:canonical_program");
    }
    const auto keys =
        constraint_bytecode::
            CommitProgramTableForExternalAndRecursiveUse(table);
    if (!keys.same_canonical_serialization ||
        keys.external_sha256d !=
            pin.program_external_sha256d ||
        keys.recursive_alg_hash !=
            pin.program_recursive_alg_hash ||
        table.role != RCStage3RelationRole::EpisodeExtract ||
        table.current_width !=
            air_quotient::kRcSamplerNumCols ||
        table.challenge_width != 2) {
        table = {};
        return Fail(
            why, "extract_batch:program_key_scale_or_shape");
    }

    relation_roots.reserve(
        episode.column_roots.size());
    for (uint32_t column = 0;
         column < episode.column_roots.size();
         ++column) {
        if (episode.column_roots[column].column !=
                column ||
            episode.column_roots[column].root.IsNull()) {
            table = {};
            relation_roots.clear();
            return Fail(
                why, "extract_batch:relation_root_order");
        }
        relation_roots.push_back(
            episode.column_roots[column].root);
    }
    const std::vector<uint256> base_roots(
        relation_roots.begin(),
        relation_roots.begin() +
            air_quotient::kRcSamplerBaseCols);
    const uint256 episode_seed =
        ComputeRCStage3EpisodeAirSeed(
            statement, episode);
    if (episode_seed.IsNull()) {
        table = {};
        relation_roots.clear();
        return Fail(why, "extract_batch:episode_seed");
    }
    const std::vector<Fp3> challenge{
        EpisodeExtractProgramChallengeV1(
            episode_seed, "airq_gamma",
            base_roots, episode.n_rows,
            episode.n_coeffs),
        EpisodeExtractProgramChallengeV1(
            episode_seed, "airq_alpha",
            base_roots, episode.n_rows,
            episode.n_coeffs),
    };
    if (!constraint_bytecode::
            BuildAirConstraintSystemFromProgramTable(
                table, episode.n_rows, challenge,
                out, why)) {
        table = {};
        relation_roots.clear();
        return Fail(why, "extract_batch:program_air");
    }
    if (out.n_rows != native.n_rows ||
        out.n_columns != native.n_columns ||
        out.constraints.size() !=
            native.constraints.size() ||
        out.QuotientLen() != native.QuotientLen() ||
        out.QuotientLen() >
            episode.n_coeffs) {
        table = {};
        out = {};
        relation_roots.clear();
        return Fail(
            why, "extract_batch:canonical_native_shape");
    }
    // T_M is verifier-regenerated.  Preserve the native preprocessed values
    // while pinning every proof root to the public shard pin.
    out.preprocessed = native.preprocessed;
    out.preprocessed_pin_ood =
        native.preprocessed_pin_ood;
    out.preprocessed_roots.clear();
    for (uint32_t column = 0;
         column < relation_roots.size();
         ++column) {
        out.preprocessed_roots.emplace_back(
            column, relation_roots[column]);
    }
    return true;
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

bool BuildRCStage3SignedRangeDualCtlDirectAliasConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeExecutedCtlBinding& binding,
    AirCS& out,
    RCStage3SignedRangeDualCtlDirectAliasLayout* layout,
    std::string* why)
{
    out = {};
    RCStage3SignedRangeDualCtlDirectAliasLayout local;

    RCStage3SignedRangeCtlBinding manifest_binding;
    manifest_binding.extract_input_shard_root =
        binding.extract_input_shard_root;
    manifest_binding.extract_input_opening_commitment =
        binding.extract_input_opening_commitment;
    const RCStage3CtlManifest ctl_manifest =
        BuildRCStage3SignedRangeCtlManifest(
            manifest, pin, manifest_binding);
    const std::vector<RCStage3CtlChildPin> pins{
        binding.range_child, binding.extract_child};
    RCStage3CtlChallenges challenges;
    if (ctl_manifest.participants.size() != 2 ||
        !DeriveRCStage3CtlChallenges(
            ctl_manifest, pins, challenges, why)) {
        out = {};
        return Fail(why, "dual_alias:ctl_challenges");
    }

    const RCStage3CtlSchedule producer_schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, true);
    const RCStage3CtlSchedule consumer_schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, false);
    if (CommitRCStage3CtlSchedule(producer_schedule) !=
            binding.range_child.schedule_commitment ||
        CommitRCStage3CtlSchedule(consumer_schedule) !=
            binding.extract_child.schedule_commitment) {
        return Fail(why, "dual_alias:schedule_binding");
    }

    AirCS range_cs;
    if (!ResolveRCStage3SignedRangeCtlAlignedConstraintSystem(
            manifest, pin, range_cs, why)) {
        return Fail(why, "dual_alias:range_constraint_system");
    }
    AirCS producer_product;
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            range_cs,
            {producer_schedule, challenges,
             binding.range_child.terminal},
            kRCStage3RangeValue, producer_product,
            &local.producer, why)) {
        return false;
    }
    if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
            producer_product,
            {consumer_schedule, challenges,
             binding.extract_child.terminal},
            kRCStage3RangeValue, out,
            &local.consumer, why)) {
        return false;
    }

    local.range_columns = range_cs.n_columns;
    local.producer_ctl_column_base =
        local.producer.ctl_column_base;
    local.consumer_ctl_column_base =
        local.consumer.ctl_column_base;
    local.total_columns = out.n_columns;
    local.source_column = kRCStage3RangeValue;
    local.same_trace_dual_alias =
        local.producer.same_trace &&
        local.producer.direct_alias &&
        local.consumer.same_trace &&
        local.consumer.direct_alias &&
        local.producer.source_column == local.source_column &&
        local.consumer.source_column == local.source_column &&
        local.producer_ctl_column_base == local.range_columns &&
        local.consumer_ctl_column_base ==
            local.range_columns + stage3_ctl_col::NUM_COLUMNS &&
        local.total_columns ==
            local.range_columns +
                2 * stage3_ctl_col::NUM_COLUMNS;
    if (!local.same_trace_dual_alias) {
        out = {};
        return Fail(why, "dual_alias:internal_layout");
    }
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "signed_range_dual_ctl_constraint_system_ok";
    }
    return true;
}

bool BuildRCStage3SignedRangeDualCtlDirectAliasWitness(
    const RCStage3SignedRangeDualCtlDirectAliasLayout& layout,
    const std::vector<std::vector<Fp3>>& range_columns,
    const RCStage3CtlWitness& producer,
    const RCStage3CtlWitness& consumer,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.same_trace_dual_alias ||
        layout.range_columns != range_columns.size() ||
        layout.source_column != kRCStage3RangeValue ||
        layout.producer.relation_columns != layout.range_columns ||
        layout.consumer.relation_columns !=
            layout.range_columns + stage3_ctl_col::NUM_COLUMNS ||
        layout.total_columns !=
            layout.range_columns +
                2 * stage3_ctl_col::NUM_COLUMNS) {
        return Fail(why, "dual_alias:witness_layout");
    }

    std::vector<std::vector<Fp3>> producer_product;
    if (!BuildRCStage3RelationCtlDirectAliasWitness(
            layout.producer, range_columns, producer,
            producer_product, why)) {
        return false;
    }
    if (!BuildRCStage3RelationCtlDirectAliasWitness(
            layout.consumer, producer_product, consumer,
            out, why)) {
        return false;
    }
    if (out.size() != layout.total_columns) {
        out.clear();
        return Fail(why, "dual_alias:witness_width");
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "signed_range_value_is_both_ctl_values_same_trace";
    }
    return true;
}

uint256 ComputeRCStage3SignedRangeDualCtlDirectAliasSeed(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeExecutedCtlBinding& binding)
{
    RCStage3SignedRangeCtlBinding manifest_binding;
    manifest_binding.extract_input_shard_root =
        binding.extract_input_shard_root;
    manifest_binding.extract_input_opening_commitment =
        binding.extract_input_opening_commitment;
    const RCStage3CtlManifest ctl_manifest =
        BuildRCStage3SignedRangeCtlManifest(
            manifest, pin, manifest_binding);
    const std::vector<RCStage3CtlChildPin> pins{
        binding.range_child, binding.extract_child};
    RCStage3CtlChallenges challenges;
    if (ctl_manifest.participants.size() != 2 ||
        !DeriveRCStage3CtlChallenges(
            ctl_manifest, pins, challenges, nullptr)) {
        return {};
    }
    const RCStage3CtlSchedule producer_schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, true);
    const RCStage3CtlSchedule consumer_schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, false);
    const uint256 producer_seed =
        ComputeRCStage3RelationCtlDirectAliasSeed(
            RCStage3RelationEndpoint::EpisodeGemmSignedRange,
            ComputeRCStage3SignedRangeSeed(pin),
            producer_schedule, challenges,
            binding.range_child.terminal,
            kRCStage3RangeValue);
    if (producer_seed.IsNull()) return {};
    return ComputeRCStage3RelationCtlDirectAliasSeed(
        RCStage3RelationEndpoint::EpisodeGemmSignedRange,
        producer_seed, consumer_schedule, challenges,
        binding.extract_child.terminal,
        kRCStage3RangeValue);
}

uint256 ComputeRCStage3SignedRangeDualCtlAuxiliaryCommitment(
    const air_quotient::AirQuotientProof<Fp3>& proof,
    const RCStage3SignedRangeDualCtlDirectAliasLayout& layout,
    bool producer_lane)
{
    if (!layout.same_trace_dual_alias ||
        layout.total_columns == 0 ||
        proof.batch.columns.size() !=
            static_cast<size_t>(layout.total_columns) + 1 ||
        proof.batch.column_len.size() != proof.batch.columns.size() ||
        proof.batch.n_coeffs == 0) {
        return {};
    }
    const uint32_t ctl_base = producer_lane
        ? layout.producer_ctl_column_base
        : layout.consumer_ctl_column_base;
    if (ctl_base > layout.total_columns ||
        stage3_ctl_col::NUM_COLUMNS >
            layout.total_columns - ctl_base) {
        return {};
    }
    for (uint32_t column = stage3_ctl_col::INVERSE1;
         column <= stage3_ctl_col::RUNNING2; ++column) {
        if (proof.batch.columns[ctl_base + column].root.IsNull()) {
            return {};
        }
    }
    const uint256& quotient_root =
        proof.batch.columns[layout.total_columns].root;
    if (quotient_root.IsNull()) return {};

    HashWriter hash;
    hash << SIGNED_RANGE_DUAL_CTL_AUX_DOMAIN;
    hash << kRCStage3RelationClosureVersion;
    hash << static_cast<uint8_t>(producer_lane ? 1U : 2U);
    hash << layout.range_columns;
    hash << ctl_base;
    hash << layout.total_columns;
    hash << proof.batch.version;
    hash << proof.batch.blowup;
    hash << proof.batch.n_coeffs;
    hash << static_cast<uint32_t>(proof.batch.column_len.size());
    for (const uint32_t length : proof.batch.column_len) {
        hash << length;
    }
    for (uint32_t column = stage3_ctl_col::INVERSE1;
         column <= stage3_ctl_col::RUNNING2; ++column) {
        hash << proof.batch.columns[ctl_base + column].root;
    }
    hash << quotient_root;
    return hash.GetHash();
}

bool VerifyRCStage3SignedRangeDualCtlDirectAliasProof(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeExecutedCtlBinding& binding,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    RCStage3SignedRangeCtlBinding manifest_binding;
    manifest_binding.extract_input_shard_root =
        binding.extract_input_shard_root;
    manifest_binding.extract_input_opening_commitment =
        binding.extract_input_opening_commitment;
    const RCStage3CtlManifest ctl_manifest =
        BuildRCStage3SignedRangeCtlManifest(
            manifest, pin, manifest_binding);
    const std::vector<RCStage3CtlChildPin> pins{
        binding.range_child, binding.extract_child};
    const RCStage3CtlSchedule producer_schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, true);
    const RCStage3CtlSchedule consumer_schedule =
        BuildRCStage3SignedRangeCtlSchedule(manifest, pin, false);

    AirCS combined;
    RCStage3SignedRangeDualCtlDirectAliasLayout layout;
    if (!BuildRCStage3SignedRangeDualCtlDirectAliasConstraintSystem(
            manifest, pin, binding, combined, &layout, why)) {
        return false;
    }
    if (proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1 ||
        proof.batch.column_len.size() != proof.batch.columns.size() ||
        pin.column_roots.size() != layout.range_columns) {
        return Fail(why, "dual_alias:proof_shape");
    }
    for (uint32_t column = 0; column < layout.range_columns; ++column) {
        if (pin.column_roots[column].column != column ||
            pin.column_roots[column].root.IsNull() ||
            proof.batch.columns[column].root !=
                pin.column_roots[column].root) {
            return Fail(why, "dual_alias:range_column_root");
        }
    }
    const uint256& source_root =
        proof.batch.columns[layout.source_column].root;
    if (binding.extract_input_shard_root != source_root ||
        proof.batch.columns[
            layout.producer_ctl_column_base +
            stage3_ctl_col::VALUE].root != source_root ||
        proof.batch.columns[
            layout.consumer_ctl_column_base +
            stage3_ctl_col::VALUE].root != source_root) {
        return Fail(why, "dual_alias:source_value_root");
    }

    const auto trace_commitment =
        [&](const RCStage3CtlSchedule& schedule,
            uint32_t ctl_base) {
            std::array<uint256, 5> roots{};
            for (uint32_t column = stage3_ctl_col::NAMESPACE;
                 column <= stage3_ctl_col::MULTIPLICITY; ++column) {
                roots[column] =
                    proof.batch.columns[ctl_base + column].root;
            }
            return ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
                schedule, proof.batch.column_len[ctl_base],
                proof.batch.n_coeffs, roots);
        };
    if (trace_commitment(
            producer_schedule, layout.producer_ctl_column_base) !=
            binding.range_child.trace_commitment ||
        trace_commitment(
            consumer_schedule, layout.consumer_ctl_column_base) !=
            binding.extract_child.trace_commitment) {
        return Fail(why, "dual_alias:ctl_trace_commitment");
    }
    if (ComputeRCStage3SignedRangeDualCtlAuxiliaryCommitment(
            proof, layout, true) !=
            binding.range_child.auxiliary_commitment ||
        ComputeRCStage3SignedRangeDualCtlAuxiliaryCommitment(
            proof, layout, false) !=
            binding.extract_child.auxiliary_commitment) {
        return Fail(why, "dual_alias:ctl_auxiliary_commitment");
    }
    if (!VerifyRCStage3CtlPublicPinComposition(
            ctl_manifest, pins, why)) {
        return Fail(why, "dual_alias:ctl_composition");
    }

    const uint256 seed =
        ComputeRCStage3SignedRangeDualCtlDirectAliasSeed(
            manifest, pin, binding);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(why, "dual_alias:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "signed_range_value_equals_producer_and_extract_ctl_"
            "same_trace_proof_recursive_consumption_pending";
    }
    return true;
}

bool BuildRCStage3BuilderProgramCtlDirectAliasConstraintSystemV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    const std::array<RCStage3BuilderProgramCtlLaneV1,
                     kRCStage3BuilderProgramAliasLaneCountV1>& lanes,
    AirCS& out,
    RCStage3BuilderProgramCtlDirectAliasLayoutV1* layout,
    std::string* why)
{
    out = {};
    RCStage3BuilderProgramCtlDirectAliasLayoutV1 local;
    constraint_bytecode::ProgramTable table;
    AirCS relation_cs;
    if (!ResolveBuilderProgramAirV1(
            pin, table, relation_cs, why)) {
        return false;
    }

    AirCS current = relation_cs;
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        if (lane.endpoint != BUILDER_ALIAS_ENDPOINTS[lane_index] ||
            lane.participant_index >= lane.pins.size() ||
            lane.pins.size() != lane.manifest.participants.size()) {
            out = {};
            return Fail(why, "builder_alias:lane_shape");
        }
        const auto& participant =
            lane.manifest.participants[lane.participant_index];
        const auto& child = lane.pins[lane.participant_index];
        const uint256 schedule_commitment =
            CommitRCStage3CtlSchedule(lane.schedule);
        if (participant.role !=
                RCStage3RelationRole::EpisodeDeterministicBuilder ||
            child.role != participant.role ||
            child.bus_id != lane.manifest.bus_id ||
            child.schedule_commitment != schedule_commitment ||
            participant.schedule_commitment != schedule_commitment ||
            participant.event_count != child.event_count ||
            participant.send_count != child.send_count ||
            participant.receive_count != child.receive_count) {
            out = {};
            return Fail(
                why, "builder_alias:participant_binding");
        }
        RCStage3CtlChallenges challenges;
        if (!DeriveRCStage3CtlChallenges(
                lane.manifest, lane.pins, challenges, why) ||
            child.challenge_commitment !=
                CommitRCStage3CtlChallenges(challenges)) {
            out = {};
            return Fail(why, "builder_alias:challenge_binding");
        }

        AirCS next;
        if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
                current,
                {lane.schedule, challenges, child.terminal},
                BUILDER_ALIAS_COLUMNS[lane_index],
                next, &local.lanes[lane_index], why)) {
            out = {};
            return false;
        }
        current = std::move(next);
    }
    out = std::move(current);
    local.relation_columns = relation_cs.n_columns;
    local.total_columns = out.n_columns;
    local.canonical_program_selected =
        table.current_width == 21 &&
        table.current_width == relation_cs.n_columns;
    local.all_four_same_trace =
        local.canonical_program_selected &&
        local.total_columns ==
            local.relation_columns +
                lanes.size() * stage3_ctl_col::NUM_COLUMNS;
    for (uint32_t lane_index = 0;
         lane_index < local.lanes.size(); ++lane_index) {
        const auto& lane = local.lanes[lane_index];
        local.all_four_same_trace =
            local.all_four_same_trace &&
            lane.same_trace && lane.direct_alias &&
            lane.source_column ==
                BUILDER_ALIAS_COLUMNS[lane_index] &&
            lane.ctl_column_base ==
                local.relation_columns +
                    lane_index * stage3_ctl_col::NUM_COLUMNS;
    }
    if (!local.all_four_same_trace) {
        out = {};
        return Fail(why, "builder_alias:internal_layout");
    }
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "canonical_builder_program_four_ctl_product_ok";
    }
    return true;
}

bool BuildRCStage3BuilderProgramCtlDirectAliasWitnessV1(
    const RCStage3BuilderProgramCtlDirectAliasLayoutV1& layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3BuilderProgramAliasLaneCountV1>&
        ctl_witnesses,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.canonical_program_selected ||
        !layout.all_four_same_trace ||
        relation_columns.size() != layout.relation_columns ||
        layout.lanes.size() != ctl_witnesses.size()) {
        return Fail(why, "builder_alias:witness_shape");
    }
    out = relation_columns;
    for (uint32_t lane_index = 0;
         lane_index < layout.lanes.size(); ++lane_index) {
        std::vector<std::vector<Fp3>> next;
        if (!BuildRCStage3RelationCtlDirectAliasWitness(
                layout.lanes[lane_index], out,
                ctl_witnesses[lane_index], next, why)) {
            out.clear();
            return false;
        }
        out = std::move(next);
    }
    if (out.size() != layout.total_columns) {
        out.clear();
        return Fail(why, "builder_alias:witness_width");
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "builder_params_seed_xof_trace_are_same_trace_ctl_values";
    }
    return true;
}

uint256 ComputeRCStage3BuilderProgramCtlDirectAliasSeedV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    const std::array<RCStage3BuilderProgramCtlLaneV1,
                     kRCStage3BuilderProgramAliasLaneCountV1>& lanes)
{
    constraint_bytecode::ProgramTable table;
    AirCS relation_cs;
    if (!ResolveBuilderProgramAirV1(
            pin, table, relation_cs, nullptr)) {
        return {};
    }
    HashWriter hash;
    hash << BUILDER_PROGRAM_ALIAS_SEED_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.n_rows;
    hash << pin.program_external_sha256d;
    for (const auto& limb : pin.program_recursive_alg_hash) {
        hash << limb;
    }
    hash << static_cast<uint32_t>(
        pin.relation_column_roots.size());
    for (const auto& root : pin.relation_column_roots) {
        hash << root;
    }
    uint256 seed = hash.GetHash();
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        if (lane.endpoint != BUILDER_ALIAS_ENDPOINTS[lane_index] ||
            lane.participant_index >= lane.pins.size() ||
            lane.pins.size() != lane.manifest.participants.size()) {
            return {};
        }
        const auto& child = lane.pins[lane.participant_index];
        RCStage3CtlChallenges challenges;
        if (!DeriveRCStage3CtlChallenges(
                lane.manifest, lane.pins, challenges, nullptr)) {
            return {};
        }
        seed = ComputeRCStage3RelationCtlDirectAliasSeed(
            lane.endpoint, seed, lane.schedule, challenges,
            child.terminal, BUILDER_ALIAS_COLUMNS[lane_index]);
        if (seed.IsNull()) return {};
    }
    return seed;
}

bool VerifyRCStage3BuilderProgramCtlDirectAliasProofV1(
    const RCStage3BuilderProgramAirPublicPinV1& pin,
    const std::array<RCStage3BuilderProgramCtlLaneV1,
                     kRCStage3BuilderProgramAliasLaneCountV1>& lanes,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    AirCS combined;
    RCStage3BuilderProgramCtlDirectAliasLayoutV1 layout;
    if (!BuildRCStage3BuilderProgramCtlDirectAliasConstraintSystemV1(
            pin, lanes, combined, &layout, why)) {
        return false;
    }
    if (proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1 ||
        proof.batch.column_len.size() != proof.batch.columns.size() ||
        pin.relation_column_roots.size() !=
            layout.relation_columns) {
        return Fail(why, "builder_alias:proof_shape");
    }
    for (uint32_t column = 0;
         column < layout.relation_columns; ++column) {
        if (proof.batch.columns[column].root !=
            pin.relation_column_roots[column]) {
            return Fail(why, "builder_alias:relation_column_root");
        }
    }

    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        const auto& lane_layout = layout.lanes[lane_index];
        const auto& child = lane.pins[lane.participant_index];
        const uint256& source_root =
            proof.batch.columns[
                BUILDER_ALIAS_COLUMNS[lane_index]].root;
        if (proof.batch.columns[
                lane_layout.ctl_value_column].root != source_root) {
            return Fail(why, "builder_alias:source_value_root");
        }
        std::array<uint256, 5> ctl_roots{};
        for (uint32_t column = stage3_ctl_col::NAMESPACE;
             column <= stage3_ctl_col::MULTIPLICITY; ++column) {
            ctl_roots[column] =
                proof.batch.columns[
                    lane_layout.ctl_column_base + column].root;
        }
        if (ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
                lane.schedule,
                proof.batch.column_len[
                    lane_layout.ctl_column_base],
                proof.batch.n_coeffs, ctl_roots) !=
                child.trace_commitment) {
            return Fail(
                why, "builder_alias:ctl_trace_commitment");
        }
        if (ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proof, lane_layout) !=
                child.auxiliary_commitment) {
            return Fail(
                why, "builder_alias:ctl_auxiliary_commitment");
        }
    }

    const uint256 seed =
        ComputeRCStage3BuilderProgramCtlDirectAliasSeedV1(
            pin, lanes);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(why, "builder_alias:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "builder_four_endpoint_program_cells_equal_same_trace_ctl_"
            "values_recursive_consumption_pending";
    }
    return true;
}

RCStage3CtlSchedule
BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    RCStage3RelationEndpoint endpoint,
    bool producer)
{
    RCStage3CtlSchedule out;
    const auto found = std::find(
        EPISODE_GEMM_BATCH_ENDPOINTS.begin(),
        EPISODE_GEMM_BATCH_ENDPOINTS.end(),
        endpoint);
    if (found == EPISODE_GEMM_BATCH_ENDPOINTS.end() ||
        !ValidateRCStage3GemmExtractManifest(
            manifest, nullptr) ||
        range_pin.layer_ordinal >= manifest.layers.size() ||
        range_pin.statement_commitment !=
            manifest.statement_commitment ||
        range_pin.manifest_commitment !=
            ComputeRCStage3GemmExtractManifestCommitment(manifest)) {
        return out;
    }
    const uint32_t lane = static_cast<uint32_t>(
        found - EPISODE_GEMM_BATCH_ENDPOINTS.begin());
    const uint32_t rows =
        endpoint ==
            RCStage3RelationEndpoint::EpisodeGemmSignedRange
        ? range_pin.logical_rows
        : range_pin.n_rows;
    if (rows == 0) return out;
    out.events.reserve(rows);
    for (uint32_t row = 0; row < rows; ++row) {
        out.events.push_back(
            {0x474d4100U + lane,
             range_pin.layer_ordinal,
             row,
             static_cast<int8_t>(producer ? 1 : -1)});
    }
    return out;
}

uint256
ComputeRCStage3EpisodeGemmProgramCtlTranscriptSeedV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    RCStage3RelationEndpoint endpoint)
{
    if (BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
            manifest, range_pin, endpoint, true)
            .events.empty()) {
        return {};
    }
    const uint256 range_commitment =
        ComputeRCStage3SignedRangePinCommitment(range_pin);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (range_commitment.IsNull() ||
        manifest_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << EPISODE_GEMM_PROGRAM_CTL_TRANSCRIPT_DOMAIN;
    hash << manifest.statement_commitment;
    hash << manifest_commitment;
    hash << range_commitment;
    hash << static_cast<uint16_t>(endpoint);
    return hash.GetHash();
}

bool
BuildRCStage3EpisodeGemmProgramCtlDirectAliasConstraintSystemV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeGemmProgramCtlLaneV1,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        lanes,
    AirCS& out,
    RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1* layout,
    std::string* why)
{
    out = {};
    RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1 local;
    std::vector<uint256> relation_roots;
    AirCS relation_cs;
    if (!ResolveEpisodeGemmProgramBatchAirV1(
            manifest, range_pin, pin,
            relation_cs, relation_roots, why)) {
        return false;
    }
    const uint32_t shard_ordinal =
        RCStage3SignedRangeGlobalShardOrdinal(
            manifest, range_pin);
    if (shard_ordinal ==
            std::numeric_limits<uint32_t>::max() ||
        shard_ordinal >
            (std::numeric_limits<uint32_t>::max() -
             kRCStage3EpisodeGemmProgramBatchBusBaseV1 -
             lanes.size()) /
                lanes.size()) {
        return Fail(why, "gemm_batch:shard_ordinal");
    }

    AirCS current = relation_cs;
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        const RCStage3CtlSchedule producer_schedule =
            BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                manifest, range_pin,
                EPISODE_GEMM_BATCH_ENDPOINTS[lane_index],
                true);
        const RCStage3CtlSchedule consumer_schedule =
            BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                manifest, range_pin,
                EPISODE_GEMM_BATCH_ENDPOINTS[lane_index],
                false);
        const uint32_t bus_id =
            kRCStage3EpisodeGemmProgramBatchBusBaseV1 +
            shard_ordinal * lanes.size() + lane_index;
        RCStage3CtlManifest expected;
        expected.bus_id = bus_id;
        expected.transcript_seed =
            ComputeRCStage3EpisodeGemmProgramCtlTranscriptSeedV1(
                manifest, range_pin,
                EPISODE_GEMM_BATCH_ENDPOINTS[lane_index]);
        expected.participants = {
            {RCStage3RelationRole::EpisodeGemm,
             producer_schedule.events.size(),
             producer_schedule.events.size(), 0,
             CommitRCStage3CtlSchedule(producer_schedule)},
            {RCStage3RelationRole::CompositionLink,
             consumer_schedule.events.size(), 0,
             consumer_schedule.events.size(),
             CommitRCStage3CtlSchedule(consumer_schedule)},
        };
        if (lane.endpoint !=
                EPISODE_GEMM_BATCH_ENDPOINTS[lane_index] ||
            lane.manifest != expected ||
            lane.pins.size() !=
                expected.participants.size() ||
            expected.transcript_seed.IsNull()) {
            out = {};
            return Fail(why, "gemm_batch:canonical_lane");
        }
        for (uint32_t participant_index = 0;
             participant_index < lane.pins.size();
             ++participant_index) {
            const auto& participant =
                expected.participants[participant_index];
            const auto& child =
                lane.pins[participant_index];
            if (child.role != participant.role ||
                child.bus_id != expected.bus_id ||
                child.event_count !=
                    participant.event_count ||
                child.send_count != participant.send_count ||
                child.receive_count !=
                    participant.receive_count ||
                child.schedule_commitment !=
                    participant.schedule_commitment) {
                out = {};
                return Fail(
                    why, "gemm_batch:participant_binding");
            }
        }
        RCStage3CtlChallenges challenges;
        if (!DeriveRCStage3CtlChallenges(
                lane.manifest,
                {lane.pins[0], lane.pins[1]},
                challenges, why) ||
            lane.pins[0].challenge_commitment !=
                CommitRCStage3CtlChallenges(challenges) ||
            lane.pins[1].challenge_commitment !=
                lane.pins[0].challenge_commitment) {
            out = {};
            return Fail(
                why, "gemm_batch:challenge_binding");
        }
        AirCS next;
        if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
                current,
                {producer_schedule, challenges,
                 lane.pins[0].terminal},
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[lane_index],
                next, &local.producer_lanes[lane_index], why)) {
            out = {};
            return false;
        }
        current = std::move(next);
        if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
                current,
                {consumer_schedule, challenges,
                 lane.pins[1].terminal},
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[lane_index],
                next, &local.consumer_lanes[lane_index], why)) {
            out = {};
            return false;
        }
        current = std::move(next);
    }

    out = std::move(current);
    local.gemm_columns =
        EPISODE_GEMM_PROGRAM_COLUMNS;
    local.range_column_base =
        EPISODE_GEMM_PROGRAM_COLUMNS;
    local.range_columns =
        EPISODE_GEMM_RANGE_PROGRAM_COLUMNS;
    local.relation_columns = relation_cs.n_columns;
    local.total_columns = out.n_columns;
    local.canonical_programs_selected =
        local.relation_columns ==
            EPISODE_GEMM_PROGRAM_COLUMNS +
                EPISODE_GEMM_RANGE_PROGRAM_COLUMNS;
    local.manifest_context_bound =
        relation_roots.size() ==
            local.relation_columns &&
        pin.layer_ordinal == range_pin.layer_ordinal &&
        pin.statement_commitment ==
            manifest.statement_commitment;
    local.all_four_dual_port_bus_relations =
        local.canonical_programs_selected &&
        local.manifest_context_bound &&
        local.total_columns ==
            local.relation_columns +
                2 * lanes.size() *
                    stage3_ctl_col::NUM_COLUMNS;
    for (uint32_t lane_index = 0;
         lane_index < local.producer_lanes.size();
         ++lane_index) {
        const auto& producer =
            local.producer_lanes[lane_index];
        const auto& consumer =
            local.consumer_lanes[lane_index];
        const uint32_t producer_base =
            local.relation_columns +
            2 * lane_index * stage3_ctl_col::NUM_COLUMNS;
        local.all_four_dual_port_bus_relations =
            local.all_four_dual_port_bus_relations &&
            producer.same_trace && producer.direct_alias &&
            consumer.same_trace && consumer.direct_alias &&
            producer.source_column ==
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[lane_index] &&
            consumer.source_column ==
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[lane_index] &&
            producer.ctl_column_base == producer_base &&
            consumer.ctl_column_base ==
                producer_base + stage3_ctl_col::NUM_COLUMNS;
    }
    if (!local.all_four_dual_port_bus_relations) {
        out = {};
        return Fail(why, "gemm_batch:internal_layout");
    }
    // This product owns both lookup accumulators, but both VALUE columns are
    // aliases of the EpisodeGemm-side relation.  No CompositionLink relation
    // ProgramTable and no recursive child verifier is present.  Keep those
    // distinctions executable and fail-closed instead of promoting a bus
    // equality milestone into semantic closure.
    local.consumer_relation_programs_included = false;
    local.consumer_arithmetic_owned = false;
    local.recursive_children_consumed = false;
    local.semantic_closure = false;
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "canonical_gemm_range_four_dual_port_bus_relations_ok_"
            "consumer_semantics_pending";
    }
    return true;
}

bool
BuildRCStage3EpisodeGemmProgramCtlDirectAliasWitnessV1(
    const RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1& layout,
    const std::vector<std::vector<Fp3>>& gemm_columns,
    const std::vector<std::vector<Fp3>>&
        signed_range_program_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        producer_ctl_witnesses,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        consumer_ctl_witnesses,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.canonical_programs_selected ||
        !layout.manifest_context_bound ||
        !layout.all_four_dual_port_bus_relations ||
        gemm_columns.size() != layout.gemm_columns ||
        signed_range_program_columns.size() !=
            layout.range_columns) {
        return Fail(why, "gemm_batch:witness_shape");
    }
    out = gemm_columns;
    out.insert(
        out.end(),
        signed_range_program_columns.begin(),
        signed_range_program_columns.end());
    if (out.size() != layout.relation_columns) {
        out.clear();
        return Fail(why, "gemm_batch:relation_width");
    }
    for (uint32_t lane_index = 0;
         lane_index < layout.producer_lanes.size();
         ++lane_index) {
        std::vector<std::vector<Fp3>> next;
        if (!BuildRCStage3RelationCtlDirectAliasWitness(
                layout.producer_lanes[lane_index], out,
                producer_ctl_witnesses[lane_index],
                next, why)) {
            out.clear();
            return false;
        }
        out = std::move(next);
        if (!BuildRCStage3RelationCtlDirectAliasWitness(
                layout.consumer_lanes[lane_index], out,
                consumer_ctl_witnesses[lane_index],
                next, why)) {
            out.clear();
            return false;
        }
        out = std::move(next);
    }
    if (out.size() != layout.total_columns) {
        out.clear();
        return Fail(why, "gemm_batch:witness_width");
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "gemm_a_b_y_range_dual_port_bus_values_"
            "consumer_semantics_pending";
    }
    return true;
}

uint256
ComputeRCStage3EpisodeGemmProgramCtlDirectAliasSeedV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeGemmProgramCtlLaneV1,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        lanes)
{
    AirCS relation;
    std::vector<uint256> roots;
    if (!ResolveEpisodeGemmProgramBatchAirV1(
            manifest, range_pin, pin,
            relation, roots, nullptr)) {
        return {};
    }
    HashWriter hash;
    hash << EPISODE_GEMM_PROGRAM_BATCH_SEED_DOMAIN;
    hash << pin.version;
    hash << pin.statement_commitment;
    hash << pin.n_rows;
    hash << pin.layer_ordinal;
    hash << ComputeRCStage3GemmExtractManifestCommitment(
        manifest);
    hash << ComputeRCStage3SignedRangePinCommitment(
        range_pin);
    hash << pin.gemm_program_external_sha256d;
    for (const auto& limb :
         pin.gemm_program_recursive_alg_hash) {
        hash << limb;
    }
    hash << pin.range_program_external_sha256d;
    for (const auto& limb :
         pin.range_program_recursive_alg_hash) {
        hash << limb;
    }
    for (const auto& root : roots) hash << root;
    uint256 seed = hash.GetHash();
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        RCStage3CtlChallenges challenges;
        if (lane.endpoint !=
                EPISODE_GEMM_BATCH_ENDPOINTS[lane_index] ||
            !DeriveRCStage3CtlChallenges(
                lane.manifest,
                {lane.pins[0], lane.pins[1]},
                challenges, nullptr)) {
            return {};
        }
        const auto producer_schedule =
            BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                manifest, range_pin, lane.endpoint, true);
        seed =
            ComputeRCStage3RelationCtlDirectAliasSeed(
                lane.endpoint, seed, producer_schedule, challenges,
                lane.pins[0].terminal,
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[
                    lane_index]);
        if (seed.IsNull()) return {};
        const auto consumer_schedule =
            BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                manifest, range_pin, lane.endpoint, false);
        seed =
            ComputeRCStage3RelationCtlDirectAliasSeed(
                lane.endpoint, seed, consumer_schedule, challenges,
                lane.pins[1].terminal,
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[
                    lane_index]);
        if (seed.IsNull()) return {};
    }
    return seed;
}

bool
VerifyRCStage3EpisodeGemmProgramCtlDirectAliasProofV1(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& range_pin,
    const RCStage3EpisodeGemmProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeGemmProgramCtlLaneV1,
                     kRCStage3EpisodeGemmProgramBatchLaneCountV1>&
        lanes,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    AirCS combined;
    RCStage3EpisodeGemmProgramCtlDirectAliasLayoutV1 layout;
    if (!BuildRCStage3EpisodeGemmProgramCtlDirectAliasConstraintSystemV1(
            manifest, range_pin, pin, lanes,
            combined, &layout, why)) {
        return false;
    }
    AirCS relation;
    std::vector<uint256> roots;
    if (!ResolveEpisodeGemmProgramBatchAirV1(
            manifest, range_pin, pin,
            relation, roots, why) ||
        proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1 ||
        proof.batch.column_len.size() !=
            proof.batch.columns.size() ||
        roots.size() != layout.relation_columns) {
        return Fail(why, "gemm_batch:proof_shape");
    }
    for (uint32_t column = 0;
         column < roots.size(); ++column) {
        if (proof.batch.columns[column].root !=
            roots[column]) {
            return Fail(
                why, "gemm_batch:relation_column_root");
        }
    }
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        const uint256& source_root =
            proof.batch.columns[
                EPISODE_GEMM_BATCH_SOURCE_COLUMNS[
                    lane_index]].root;
        for (uint32_t participant_index = 0;
             participant_index < 2; ++participant_index) {
            const auto& lane_layout =
                participant_index == 0
                ? layout.producer_lanes[lane_index]
                : layout.consumer_lanes[lane_index];
            if (proof.batch.columns[
                    lane_layout.ctl_value_column].root !=
                source_root) {
                return Fail(
                    why, "gemm_batch:source_value_root");
            }
            const auto schedule =
                BuildRCStage3EpisodeGemmProgramCtlScheduleV1(
                    manifest, range_pin, lane.endpoint,
                    participant_index == 0);
            std::array<uint256, 5> ctl_roots{};
            for (uint32_t column =
                     stage3_ctl_col::NAMESPACE;
                 column <=
                     stage3_ctl_col::MULTIPLICITY;
                 ++column) {
                ctl_roots[column] =
                    proof.batch.columns[
                        lane_layout.ctl_column_base +
                        column].root;
            }
            if (ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
                    schedule,
                    proof.batch.column_len[
                        lane_layout.ctl_column_base],
                    proof.batch.n_coeffs,
                    ctl_roots) !=
                lane.pins[
                    participant_index].trace_commitment) {
                return Fail(
                    why, "gemm_batch:ctl_trace_commitment");
            }
            if (ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                    proof, lane_layout) !=
                lane.pins[
                    participant_index].auxiliary_commitment) {
                return Fail(
                    why, "gemm_batch:ctl_auxiliary_commitment");
            }
        }
    }
    const uint256 seed =
        ComputeRCStage3EpisodeGemmProgramCtlDirectAliasSeedV1(
            manifest, range_pin, pin, lanes);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(
            why, "gemm_batch:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "gemm_four_endpoint_dual_port_same_trace_batch_ok_"
            "recursive_consumption_pending";
    }
    return true;
}

RCStage3CtlSchedule
BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    RCStage3RelationEndpoint endpoint,
    bool producer)
{
    RCStage3CtlSchedule out;
    const auto found = std::find(
        EPISODE_EXTRACT_BATCH_ENDPOINTS.begin(),
        EPISODE_EXTRACT_BATCH_ENDPOINTS.end(),
        endpoint);
    const uint256 pin_commitment =
        ComputeRCStage3EpisodeAirPinCommitment(
            pin.episode_air);
    if (found ==
            EPISODE_EXTRACT_BATCH_ENDPOINTS.end() ||
        pin.version !=
            kRCStage3EpisodeExtractProgramBatchVersionV1 ||
        pin.episode_air.role !=
            RCStage3RelationRole::EpisodeExtract ||
        pin.episode_air.family !=
            RCStage3EpisodeAirFamily::
                ExtractSamplerCoreFp3V1 ||
        pin.episode_air.n_rows < 2 ||
        pin_commitment.IsNull()) {
        return out;
    }
    const uint32_t lane = static_cast<uint32_t>(
        found - EPISODE_EXTRACT_BATCH_ENDPOINTS.begin());
    out.events.reserve(pin.episode_air.n_rows);
    for (uint32_t row = 0;
         row < pin.episode_air.n_rows; ++row) {
        out.events.push_back(
            {0x45584300U + lane,
             pin.episode_air.shard_index,
             row,
             static_cast<int8_t>(
                 producer ? 1 : -1)});
    }
    return out;
}

uint256
ComputeRCStage3EpisodeExtractProgramCtlTranscriptSeedV1(
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    RCStage3RelationEndpoint endpoint)
{
    if (BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
            pin, endpoint, true).events.empty()) {
        return {};
    }
    constraint_bytecode::ProgramTable table;
    if (!BuildRCStage3EpisodeExtractLocalKernelProgramTable(
            pin.episode_air.extract_scale_e,
            table, nullptr)) {
        return {};
    }
    const auto keys =
        constraint_bytecode::
            CommitProgramTableForExternalAndRecursiveUse(table);
    if (!keys.same_canonical_serialization ||
        keys.external_sha256d !=
            pin.program_external_sha256d ||
        keys.recursive_alg_hash !=
            pin.program_recursive_alg_hash) {
        return {};
    }
    const uint256 pin_commitment =
        ComputeRCStage3EpisodeAirPinCommitment(
            pin.episode_air);
    if (pin_commitment.IsNull()) return {};
    HashWriter hash;
    hash << EPISODE_EXTRACT_PROGRAM_CTL_TRANSCRIPT_DOMAIN;
    hash << pin.version;
    hash << pin_commitment;
    hash << pin.program_external_sha256d;
    for (const auto& limb :
         pin.program_recursive_alg_hash) {
        hash << limb;
    }
    hash << static_cast<uint16_t>(endpoint);
    return hash.GetHash();
}

bool
BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        lanes,
    AirCS& out,
    RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1* layout,
    std::string* why)
{
    out = {};
    RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1 local;
    constraint_bytecode::ProgramTable table;
    AirCS relation;
    std::vector<uint256> roots;
    if (!ResolveEpisodeExtractProgramBatchAirV1(
            statement, pin, table,
            relation, roots, why)) {
        return false;
    }
    const uint32_t shard = pin.episode_air.shard_index;
    if (shard >
        (std::numeric_limits<uint32_t>::max() -
         kRCStage3EpisodeExtractProgramBatchBusBaseV1 -
         lanes.size()) /
            lanes.size()) {
        return Fail(why, "extract_batch:shard_ordinal");
    }

    AirCS current = relation;
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        const auto producer_schedule =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin,
                EPISODE_EXTRACT_BATCH_ENDPOINTS[
                    lane_index],
                true);
        const auto counterparty_schedule =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin,
                EPISODE_EXTRACT_BATCH_ENDPOINTS[
                    lane_index],
                false);
        const uint32_t bus_id =
            kRCStage3EpisodeExtractProgramBatchBusBaseV1 +
            shard * lanes.size() + lane_index;
        RCStage3CtlManifest expected;
        expected.bus_id = bus_id;
        expected.transcript_seed =
            ComputeRCStage3EpisodeExtractProgramCtlTranscriptSeedV1(
                pin,
                EPISODE_EXTRACT_BATCH_ENDPOINTS[
                    lane_index]);
        expected.participants = {
            {RCStage3RelationRole::EpisodeExtract,
             producer_schedule.events.size(),
             producer_schedule.events.size(), 0,
             CommitRCStage3CtlSchedule(
                 producer_schedule)},
            {RCStage3RelationRole::CompositionLink,
             counterparty_schedule.events.size(), 0,
             counterparty_schedule.events.size(),
             CommitRCStage3CtlSchedule(
                 counterparty_schedule)},
        };
        if (lane.endpoint !=
                EPISODE_EXTRACT_BATCH_ENDPOINTS[
                    lane_index] ||
            lane.manifest != expected ||
            expected.transcript_seed.IsNull()) {
            out = {};
            return Fail(
                why, "extract_batch:canonical_lane");
        }
        for (uint32_t participant_index = 0;
             participant_index < 2;
             ++participant_index) {
            const auto& participant =
                expected.participants[
                    participant_index];
            const auto& child =
                lane.pins[participant_index];
            if (child.role != participant.role ||
                child.bus_id != expected.bus_id ||
                child.event_count !=
                    participant.event_count ||
                child.send_count !=
                    participant.send_count ||
                child.receive_count !=
                    participant.receive_count ||
                child.schedule_commitment !=
                    participant.schedule_commitment) {
                out = {};
                return Fail(
                    why,
                    "extract_batch:participant_binding");
            }
        }
        RCStage3CtlChallenges challenges;
        if (!DeriveRCStage3CtlChallenges(
                lane.manifest,
                {lane.pins[0], lane.pins[1]},
                challenges, why) ||
            lane.pins[0].challenge_commitment !=
                CommitRCStage3CtlChallenges(challenges) ||
            lane.pins[1].challenge_commitment !=
                lane.pins[0].challenge_commitment) {
            out = {};
            return Fail(
                why, "extract_batch:challenge_binding");
        }
        AirCS next;
        if (!BuildRCStage3RelationCtlDirectAliasConstraintSystem(
                current,
                {producer_schedule, challenges,
                 lane.pins[0].terminal},
                EPISODE_EXTRACT_BATCH_SOURCE_COLUMNS[
                    lane_index],
                next, &local.producer_lanes[lane_index],
                why)) {
            out = {};
            return false;
        }
        current = std::move(next);
    }

    out = std::move(current);
    local.relation_columns = relation.n_columns;
    local.total_columns = out.n_columns;
    local.canonical_program_selected =
        table.role == RCStage3RelationRole::EpisodeExtract &&
        table.current_width ==
            air_quotient::kRcSamplerNumCols &&
        table.challenge_width == 2 &&
        local.relation_columns ==
            table.current_width;
    local.verifier_scale_bound =
        pin.episode_air.extract_scale_e <= 3 &&
        !pin.program_external_sha256d.IsNull() &&
        pin.program_recursive_alg_hash !=
            alg_hash::Digest{};
    local.all_four_producer_same_trace =
        local.canonical_program_selected &&
        local.verifier_scale_bound &&
        local.total_columns ==
            local.relation_columns +
                lanes.size() *
                    stage3_ctl_col::NUM_COLUMNS;
    for (uint32_t lane_index = 0;
         lane_index < local.producer_lanes.size();
         ++lane_index) {
        const auto& lane =
            local.producer_lanes[lane_index];
        local.all_four_producer_same_trace =
            local.all_four_producer_same_trace &&
            lane.same_trace && lane.direct_alias &&
            lane.source_column ==
                EPISODE_EXTRACT_BATCH_SOURCE_COLUMNS[
                    lane_index] &&
            lane.ctl_column_base ==
                local.relation_columns +
                    lane_index *
                        stage3_ctl_col::NUM_COLUMNS;
    }
    local.chacha_provenance_included = false;
    local.recursive_children_consumed = false;
    local.role_complete = false;
    if (!local.all_four_producer_same_trace) {
        out = {};
        return Fail(
            why, "extract_batch:internal_layout");
    }
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "canonical_extract_core_four_producer_ctl_"
            "product_ok_chacha_and_recursion_pending";
    }
    return true;
}

bool
BuildRCStage3EpisodeExtractProgramCtlDirectAliasWitnessV1(
    const RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1&
        layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        producer_ctl_witnesses,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.canonical_program_selected ||
        !layout.verifier_scale_bound ||
        !layout.all_four_producer_same_trace ||
        layout.chacha_provenance_included ||
        layout.recursive_children_consumed ||
        layout.role_complete ||
        relation_columns.size() !=
            layout.relation_columns ||
        relation_columns.empty()) {
        return Fail(
            why, "extract_batch:witness_shape");
    }
    const size_t rows =
        relation_columns.front().size();
    if (rows < 2) {
        return Fail(
            why, "extract_batch:witness_rows");
    }
    for (const auto& column : relation_columns) {
        if (column.size() != rows) {
            return Fail(
                why,
                "extract_batch:relation_column_rows");
        }
        if (!std::all_of(
                column.begin(), column.end(),
                Canonical)) {
            return Fail(
                why,
                "extract_batch:"
                "noncanonical_relation_cell");
        }
    }
    for (const auto& witness :
         producer_ctl_witnesses) {
        if (!witness.ok ||
            witness.columns.size() !=
                stage3_ctl_col::NUM_COLUMNS) {
            return Fail(
                why, "extract_batch:ctl_witness_shape");
        }
        for (const auto& column : witness.columns) {
            if (column.size() != rows ||
                !std::all_of(
                    column.begin(), column.end(),
                    Canonical)) {
                return Fail(
                    why,
                    "extract_batch:"
                    "noncanonical_ctl_cell");
            }
        }
    }
    out = relation_columns;
    for (uint32_t lane_index = 0;
         lane_index < layout.producer_lanes.size();
         ++lane_index) {
        std::vector<std::vector<Fp3>> next;
        if (!BuildRCStage3RelationCtlDirectAliasWitness(
                layout.producer_lanes[lane_index],
                out,
                producer_ctl_witnesses[lane_index],
                next, why)) {
            out.clear();
            return false;
        }
        out = std::move(next);
    }
    if (out.size() != layout.total_columns) {
        out.clear();
        return Fail(
            why, "extract_batch:witness_width");
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "extract_input_sampler_scale_output_are_"
            "canonical_same_trace_producer_ctl_values";
    }
    return true;
}

uint256
ComputeRCStage3EpisodeExtractProgramCtlDirectAliasSeedV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        lanes)
{
    constraint_bytecode::ProgramTable table;
    AirCS relation;
    std::vector<uint256> roots;
    if (!ResolveEpisodeExtractProgramBatchAirV1(
            statement, pin, table,
            relation, roots, nullptr)) {
        return {};
    }
    const uint256 pin_commitment =
        ComputeRCStage3EpisodeAirPinCommitment(
            pin.episode_air);
    if (pin_commitment.IsNull()) return {};
    HashWriter hash;
    hash << EPISODE_EXTRACT_PROGRAM_BATCH_SEED_DOMAIN;
    hash << pin.version;
    hash << pin_commitment;
    hash << pin.program_external_sha256d;
    for (const auto& limb :
         pin.program_recursive_alg_hash) {
        hash << limb;
    }
    hash << static_cast<uint32_t>(roots.size());
    for (const auto& root : roots) hash << root;
    uint256 seed = hash.GetHash();
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        if (lane.endpoint !=
            EPISODE_EXTRACT_BATCH_ENDPOINTS[
                lane_index]) {
            return {};
        }
        RCStage3CtlChallenges challenges;
        if (!DeriveRCStage3CtlChallenges(
                lane.manifest,
                {lane.pins[0], lane.pins[1]},
                challenges, nullptr)) {
            return {};
        }
        const auto schedule =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin, lane.endpoint, true);
        seed =
            ComputeRCStage3RelationCtlDirectAliasSeed(
                lane.endpoint, seed, schedule,
                challenges, lane.pins[0].terminal,
                EPISODE_EXTRACT_BATCH_SOURCE_COLUMNS[
                    lane_index]);
        if (seed.IsNull()) return {};
    }
    return seed;
}

bool
VerifyRCStage3EpisodeExtractProgramCtlDirectAliasProofV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        lanes,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    std::string* why)
{
    AirCS combined;
    RCStage3EpisodeExtractProgramCtlDirectAliasLayoutV1
        layout;
    if (!BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, lanes,
            combined, &layout, why)) {
        return false;
    }
    constraint_bytecode::ProgramTable table;
    AirCS relation;
    std::vector<uint256> roots;
    if (!ResolveEpisodeExtractProgramBatchAirV1(
            statement, pin, table,
            relation, roots, why) ||
        proof.batch.columns.size() !=
            static_cast<size_t>(
                combined.n_columns) + 1 ||
        proof.batch.column_len.size() !=
            proof.batch.columns.size() ||
        proof.batch.n_coeffs !=
            pin.episode_air.n_coeffs ||
        roots.size() !=
            layout.relation_columns) {
        return Fail(
            why, "extract_batch:proof_shape");
    }
    for (uint32_t column = 0;
         column < roots.size(); ++column) {
        if (proof.batch.columns[column].root !=
            roots[column]) {
            return Fail(
                why,
                "extract_batch:relation_column_root");
        }
    }
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        const auto& lane_layout =
            layout.producer_lanes[lane_index];
        const uint256& source_root =
            proof.batch.columns[
                EPISODE_EXTRACT_BATCH_SOURCE_COLUMNS[
                    lane_index]].root;
        if (proof.batch.columns[
                lane_layout.ctl_value_column].root !=
            source_root) {
            return Fail(
                why, "extract_batch:source_value_root");
        }
        const auto schedule =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin, lane.endpoint, true);
        std::array<uint256, 5> ctl_roots{};
        for (uint32_t column =
                 stage3_ctl_col::NAMESPACE;
             column <=
                 stage3_ctl_col::MULTIPLICITY;
             ++column) {
            ctl_roots[column] =
                proof.batch.columns[
                    lane_layout.ctl_column_base +
                    column].root;
        }
        if (ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
                schedule,
                proof.batch.column_len[
                    lane_layout.ctl_column_base],
                proof.batch.n_coeffs,
                ctl_roots) !=
            lane.pins[0].trace_commitment) {
            return Fail(
                why,
                "extract_batch:ctl_trace_commitment");
        }
        if (ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proof, lane_layout) !=
            lane.pins[0].auxiliary_commitment) {
            return Fail(
                why,
                "extract_batch:"
                "ctl_auxiliary_commitment");
        }
    }
    const uint256 seed =
        ComputeRCStage3EpisodeExtractProgramCtlDirectAliasSeedV1(
            statement, pin, lanes);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(
            why, "extract_batch:air:" + air_why);
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "extract_core_four_producer_cells_equal_"
            "same_trace_ctl_values_chacha_and_"
            "recursive_consumption_pending";
    }
    return true;
}

namespace {

RCStage3CtlSchedule ExtractOutputReceiverSchedule(
    uint32_t global_stream_tile,
    int8_t multiplicity)
{
    RCStage3CtlSchedule out;
    out.events.reserve(kRCMxBlockLen);
    for (uint32_t row = 0; row < kRCMxBlockLen; ++row) {
        out.events.push_back(
            {kRCStage3ExtractStreamCtlBusId,
             global_stream_tile, row, multiplicity});
    }
    return out;
}

bool ResolveExtractOutputReceiverV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    RCStage3CtlChallenges& challenges,
    std::string* why)
{
    challenges = {};
    std::string receiver_why;
    if (!VerifyRCStage3ExtractStreamCtlTile(
            statement, manifest, extract, tile_stream,
            global_stream_tile, receiver,
            &receiver_why)) {
        return Fail(
            why, "extract_output_receiver:receiver:" +
                receiver_why);
    }
    if (receiver.extract_tile_ordinal >=
            extract.tiles.size() ||
        receiver.global_stream_tile !=
            global_stream_tile ||
        pin.episode_air !=
            extract.tiles[receiver.extract_tile_ordinal]
                .sampler_pin ||
        pin.episode_air.shard_index !=
            receiver.extract_tile_ordinal ||
        pin.episode_air.column_roots.size() <=
            air_quotient::kColOut ||
        receiver.pins.size() != 2) {
        return Fail(
            why,
            "extract_output_receiver:producer_identity");
    }
    const auto send = ExtractOutputReceiverSchedule(
        global_stream_tile, 1);
    const auto receive = ExtractOutputReceiverSchedule(
        global_stream_tile, -1);
    if (receiver.manifest.bus_id !=
            kRCStage3ExtractStreamCtlBusId ||
        receiver.manifest.participants.size() != 2 ||
        receiver.manifest.participants[0].role !=
            RCStage3RelationRole::EpisodeExtract ||
        receiver.manifest.participants[1].role !=
            RCStage3RelationRole::EpisodeTileTree ||
        receiver.manifest.participants[0].event_count !=
            kRCMxBlockLen ||
        receiver.manifest.participants[0].send_count !=
            kRCMxBlockLen ||
        receiver.manifest.participants[0].receive_count != 0 ||
        receiver.manifest.participants[1].event_count !=
            kRCMxBlockLen ||
        receiver.manifest.participants[1].send_count != 0 ||
        receiver.manifest.participants[1].receive_count !=
            kRCMxBlockLen ||
        receiver.manifest.participants[0].schedule_commitment !=
            CommitRCStage3CtlSchedule(send) ||
        receiver.manifest.participants[1].schedule_commitment !=
            CommitRCStage3CtlSchedule(receive)) {
        return Fail(
            why,
            "extract_output_receiver:selected_schedule");
    }
    if (!DeriveRCStage3CtlChallenges(
            receiver.manifest, receiver.pins,
            challenges, why)) {
        return false;
    }
    const uint256 challenge_commitment =
        CommitRCStage3CtlChallenges(challenges);
    const auto& producer_pin = receiver.pins[0];
    const auto& consumer_pin = receiver.pins[1];
    if (producer_pin.challenge_commitment !=
            challenge_commitment ||
        consumer_pin.challenge_commitment !=
            challenge_commitment ||
        producer_pin.trace_commitment !=
            receiver.sampler_output_root ||
        consumer_pin.trace_commitment !=
            receiver.memory_value_root ||
        !Canonical(producer_pin.terminal.alpha1_sum) ||
        !Canonical(producer_pin.terminal.alpha2_sum) ||
        !Canonical(consumer_pin.terminal.alpha1_sum) ||
        !Canonical(consumer_pin.terminal.alpha2_sum) ||
        !gkr_field::IsZero(gkr_field::Add(
            producer_pin.terminal.alpha1_sum,
            consumer_pin.terminal.alpha1_sum)) ||
        !gkr_field::IsZero(gkr_field::Add(
            producer_pin.terminal.alpha2_sum,
            consumer_pin.terminal.alpha2_sum))) {
        return Fail(
            why,
            "extract_output_receiver:challenge_terminal");
    }
    const uint256& output_root =
        pin.episode_air
            .column_roots[air_quotient::kColOut]
            .root;
    if (output_root.IsNull() ||
        output_root != receiver.sampler_output_root ||
        receiver.producer_product.batch.columns.size() <=
            air_quotient::kColOut ||
        receiver.producer_product.batch
                .columns[air_quotient::kColOut]
                .root != output_root ||
        receiver.consumer_product.batch.columns.size() <=
            kRCStage3EpisodeMemoryExport ||
        receiver.consumer_product.batch
                .columns[kRCStage3EpisodeMemoryExport]
                .root.IsNull() ||
        receiver.memory_value_root.IsNull() ||
        receiver.producer_product_commitment.IsNull() ||
        receiver.consumer_product_commitment.IsNull() ||
        producer_pin.auxiliary_commitment !=
            receiver.producer_product_commitment ||
        consumer_pin.auxiliary_commitment !=
            receiver.consumer_product_commitment) {
        return Fail(
            why,
            "extract_output_receiver:proof_owned_roots");
    }
    return true;
}

} // namespace

bool
BuildRCStage3EpisodeExtractOutputReceiverConstraintSystemV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        lanes,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    AirCS& out,
    RCStage3EpisodeExtractOutputReceiverLayoutV1* layout,
    std::string* why)
{
    out = {};
    RCStage3EpisodeExtractOutputReceiverLayoutV1 local;
    RCStage3CtlChallenges challenges;
    if (!ResolveExtractOutputReceiverV1(
            statement, pin, manifest, extract,
            tile_stream, global_stream_tile,
            receiver, challenges, why) ||
        !BuildRCStage3EpisodeExtractProgramCtlDirectAliasConstraintSystemV1(
            statement, pin, lanes, out,
            &local.producer, why)) {
        out = {};
        return false;
    }
    const uint32_t base = out.n_columns;
    AirCS selected =
        BuildRCStage3ExtractStreamSelectedCtlConstraintSystem(
            base, out.n_rows,
            air_quotient::kColOut,
            global_stream_tile, 1,
            challenges, receiver.pins[0].terminal);
    if (selected.n_rows != out.n_rows ||
        selected.n_columns != base + 6 ||
        selected.constraints.size() != 12 ||
        selected.preprocessed.size() != 2) {
        out = {};
        return Fail(
            why,
            "extract_output_receiver:selected_air_shape");
    }
    out.n_columns = selected.n_columns;
    out.constraints.insert(
        out.constraints.end(),
        selected.constraints.begin(),
        selected.constraints.end());
    out.preprocessed.insert(
        out.preprocessed.end(),
        selected.preprocessed.begin(),
        selected.preprocessed.end());
    local.receiver_mask_column = base;
    local.receiver_address_column = base + 1;
    local.receiver_inverse1_column = base + 2;
    local.receiver_inverse2_column = base + 3;
    local.receiver_running1_column = base + 4;
    local.receiver_running2_column = base + 5;
    local.total_columns = out.n_columns;
    local.receiver_proof_executed = true;
    local.exact_selected_schedule = true;
    local.output_source_same_trace =
        air_quotient::kColOut <
        local.producer.relation_columns;
    local.shared_dual_fp3_challenges =
        receiver.pins[0].challenge_commitment ==
        receiver.pins[1].challenge_commitment;
    local.opposing_terminals =
        gkr_field::IsZero(gkr_field::Add(
            receiver.pins[0].terminal.alpha1_sum,
            receiver.pins[1].terminal.alpha1_sum)) &&
        gkr_field::IsZero(gkr_field::Add(
            receiver.pins[0].terminal.alpha2_sum,
            receiver.pins[1].terminal.alpha2_sum));
    if (!local.output_source_same_trace ||
        !local.shared_dual_fp3_challenges ||
        !local.opposing_terminals) {
        out = {};
        return Fail(
            why,
            "extract_output_receiver:closure_layout");
    }
    if (layout != nullptr) *layout = local;
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "extract_output_14_to_tile_stream_19_"
            "same_trace_two_sided_ctl_ok_"
            "fixed_program_and_recursion_pending";
    }
    return true;
}

bool
BuildRCStage3EpisodeExtractOutputReceiverWitnessV1(
    const RCStage3EpisodeExtractOutputReceiverLayoutV1& layout,
    const std::vector<std::vector<Fp3>>& relation_columns,
    const std::array<RCStage3CtlWitness,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        producer_ctl_witnesses,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    std::vector<std::vector<Fp3>>& out,
    std::string* why)
{
    out.clear();
    if (!layout.receiver_proof_executed ||
        !layout.exact_selected_schedule ||
        !layout.output_source_same_trace ||
        !layout.shared_dual_fp3_challenges ||
        !layout.opposing_terminals ||
        layout.total_columns !=
            layout.producer.total_columns + 6 ||
        relation_columns.size() <=
            air_quotient::kColOut ||
        receiver.pins.size() != 2 ||
        relation_columns[air_quotient::kColOut].size() <
            kRCMxBlockLen) {
        return Fail(
            why,
            "extract_output_receiver:witness_shape");
    }
    if (!BuildRCStage3EpisodeExtractProgramCtlDirectAliasWitnessV1(
            layout.producer, relation_columns,
            producer_ctl_witnesses, out, why)) {
        return false;
    }
    RCStage3CtlChallenges challenges;
    if (!DeriveRCStage3CtlChallenges(
            receiver.manifest, receiver.pins,
            challenges, why)) {
        out.clear();
        return false;
    }
    const auto schedule =
        ExtractOutputReceiverSchedule(
            receiver.global_stream_tile, 1);
    std::vector<Fp3> values(
        relation_columns[air_quotient::kColOut].begin(),
        relation_columns[air_quotient::kColOut].begin() +
            kRCMxBlockLen);
    const RCStage3CtlWitness selected =
        BuildRCStage3CtlWitness(
            schedule, values, challenges);
    if (!selected.ok ||
        selected.columns.size() !=
            stage3_ctl_col::NUM_COLUMNS ||
        selected.columns[stage3_ctl_col::INVERSE1].size() !=
            kRCMxBlockLen ||
        !(selected.terminal ==
          receiver.pins[0].terminal)) {
        out.clear();
        return Fail(
            why,
            "extract_output_receiver:selected_witness");
    }
    const size_t rows =
        relation_columns[air_quotient::kColOut].size();
    std::array<std::vector<Fp3>, 6> columns;
    for (auto& column : columns) {
        column.assign(rows, Fp3::Zero());
    }
    for (uint32_t row = 0; row < kRCMxBlockLen; ++row) {
        columns[0][row] = Fp3::One();
        columns[1][row] =
            Fp3::FromFp(gkr_field::FromU64(row));
        columns[2][row] =
            selected.columns[stage3_ctl_col::INVERSE1][row];
        columns[3][row] =
            selected.columns[stage3_ctl_col::INVERSE2][row];
        columns[4][row] =
            selected.columns[stage3_ctl_col::RUNNING1][row];
        columns[5][row] =
            selected.columns[stage3_ctl_col::RUNNING2][row];
    }
    for (uint32_t row = kRCMxBlockLen;
         row < rows; ++row) {
        columns[4][row] =
            receiver.pins[0].terminal.alpha1_sum;
        columns[5][row] =
            receiver.pins[0].terminal.alpha2_sum;
    }
    for (auto& column : columns) {
        out.push_back(std::move(column));
    }
    if (out.size() != layout.total_columns) {
        out.clear();
        return Fail(
            why,
            "extract_output_receiver:witness_width");
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "extract_output_selected_receiver_witness_ok";
    }
    return true;
}

uint256
ComputeRCStage3EpisodeExtractOutputReceiverSeedV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        lanes,
    const RCStage3ExtractStreamCtlTileProof& receiver)
{
    const uint256 base =
        ComputeRCStage3EpisodeExtractProgramCtlDirectAliasSeedV1(
            statement, pin, lanes);
    if (base.IsNull() ||
        receiver.proof_commitment.IsNull() ||
        receiver.producer_product_commitment.IsNull() ||
        receiver.consumer_product_commitment.IsNull() ||
        receiver.pins.size() != 2) {
        return {};
    }
    HashWriter hash;
    hash << EPISODE_EXTRACT_OUTPUT_RECEIVER_SEED_DOMAIN;
    hash << base;
    hash << receiver.global_stream_tile;
    hash << receiver.extract_tile_ordinal;
    hash << receiver.memory_row_begin;
    hash << receiver.sampler_output_root;
    hash << receiver.memory_value_root;
    hash << receiver.manifest.transcript_seed;
    hash << receiver.pins[0].challenge_commitment;
    HashFp3(hash, receiver.pins[0].terminal.alpha1_sum);
    HashFp3(hash, receiver.pins[0].terminal.alpha2_sum);
    HashFp3(hash, receiver.pins[1].terminal.alpha1_sum);
    HashFp3(hash, receiver.pins[1].terminal.alpha2_sum);
    hash << receiver.producer_product_commitment;
    hash << receiver.consumer_product_commitment;
    hash << receiver.proof_commitment;
    return hash.GetHash();
}

bool
VerifyRCStage3EpisodeExtractOutputReceiverProofV1(
    const RCStage3SuccinctProof& statement,
    const RCStage3EpisodeExtractProgramAirPublicPinV1& pin,
    const std::array<RCStage3EpisodeExtractProgramCtlLaneV1,
                     kRCStage3EpisodeExtractProgramBatchLaneCountV1>&
        lanes,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    uint32_t global_stream_tile,
    const RCStage3ExtractStreamCtlTileProof& receiver,
    const air_quotient::AirQuotientProof<Fp3>& proof,
    RCStage3EpisodeExtractOutputReceiverAuditV1* audit,
    std::string* why)
{
    if (audit != nullptr) *audit = {};
    AirCS combined;
    RCStage3EpisodeExtractOutputReceiverLayoutV1 layout;
    if (!BuildRCStage3EpisodeExtractOutputReceiverConstraintSystemV1(
            statement, pin, lanes, manifest,
            extract, tile_stream, global_stream_tile,
            receiver, combined, &layout, why)) {
        return false;
    }
    constraint_bytecode::ProgramTable table;
    AirCS relation;
    std::vector<uint256> roots;
    if (!ResolveEpisodeExtractProgramBatchAirV1(
            statement, pin, table,
            relation, roots, why) ||
        proof.batch.columns.size() !=
            static_cast<size_t>(combined.n_columns) + 1 ||
        proof.batch.column_len.size() !=
            proof.batch.columns.size() ||
        proof.batch.n_coeffs !=
            pin.episode_air.n_coeffs ||
        roots.size() !=
            layout.producer.relation_columns) {
        return Fail(
            why,
            "extract_output_receiver:proof_shape");
    }
    for (uint32_t column = 0;
         column < roots.size(); ++column) {
        if (proof.batch.columns[column].root !=
            roots[column]) {
            return Fail(
                why,
                "extract_output_receiver:"
                "relation_column_root");
        }
    }
    for (uint32_t lane_index = 0;
         lane_index < lanes.size(); ++lane_index) {
        const auto& lane = lanes[lane_index];
        const auto& lane_layout =
            layout.producer.producer_lanes[lane_index];
        const uint256& source_root =
            proof.batch.columns[
                EPISODE_EXTRACT_BATCH_SOURCE_COLUMNS[
                    lane_index]].root;
        if (proof.batch.columns[
                lane_layout.ctl_value_column].root !=
                source_root) {
            return Fail(
                why,
                "extract_output_receiver:"
                "source_value_root");
        }
        const auto schedule =
            BuildRCStage3EpisodeExtractProgramCtlScheduleV1(
                pin, lane.endpoint, true);
        std::array<uint256, 5> ctl_roots{};
        for (uint32_t column =
                 stage3_ctl_col::NAMESPACE;
             column <=
                 stage3_ctl_col::MULTIPLICITY;
             ++column) {
            ctl_roots[column] =
                proof.batch.columns[
                    lane_layout.ctl_column_base +
                    column].root;
        }
        if (ComputeRCStage3CtlPrechallengeTraceCommitmentFromRoots(
                schedule,
                proof.batch.column_len[
                    lane_layout.ctl_column_base],
                proof.batch.n_coeffs,
                ctl_roots) !=
                lane.pins[0].trace_commitment ||
            ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
                proof, lane_layout) !=
                lane.pins[0].auxiliary_commitment) {
            return Fail(
                why,
                "extract_output_receiver:"
                "producer_alias_binding");
        }
    }
    const uint256 seed =
        ComputeRCStage3EpisodeExtractOutputReceiverSeedV1(
            statement, pin, lanes, receiver);
    std::string air_why;
    if (seed.IsNull() ||
        !air_quotient::AirQuotientVerify<Fp3>(
            combined, proof, seed, &air_why)) {
        return Fail(
            why,
            "extract_output_receiver:air:" +
                air_why);
    }
    if (audit != nullptr) {
        audit->producer_endpoint_families =
            kRCStage3EpisodeExtractProgramBatchLaneCountV1;
        audit->strictly_transitive_endpoint_families = 1;
        audit->producer_endpoint =
            RCStage3RelationEndpoint::EpisodeExtractOutput;
        audit->receiver_endpoint =
            RCStage3RelationEndpoint::EpisodeTileTreeStream;
        audit->producer_alias_product_verified = true;
        audit->authoritative_receiver_product_verified =
            layout.receiver_proof_executed;
        audit->sampler_output_root_equal = true;
        audit->semantic_value_root_bound = true;
        audit->semantic_export_root_bound = true;
        audit->exact_selected_schedule =
            layout.exact_selected_schedule;
        audit->shared_dual_fp3_challenges =
            layout.shared_dual_fp3_challenges;
        audit->opposing_terminals =
            layout.opposing_terminals;
        audit->chacha_output_proof_owned = false;
        audit->scale_output_proof_owned = false;
        audit->recursive_children_consumed = false;
        audit->role_complete = false;
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "strict_transitive_endpoint_14_to_19_ok_"
            "endpoints_10_11_13_and_recursion_residual";
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

uint256 ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
    const air_quotient::AirQuotientProof<Fp3>& proof,
    const RCStage3RelationCtlDirectAliasLayout& layout)
{
    const uint32_t proof_total_columns =
        proof.batch.columns.empty()
        ? 0
        : static_cast<uint32_t>(
              proof.batch.columns.size() - 1);
    if (!layout.same_trace || !layout.direct_alias ||
        layout.total_columns == 0 ||
        proof_total_columns < layout.total_columns ||
        proof.batch.column_len.size() != proof.batch.columns.size() ||
        proof.batch.n_coeffs == 0 ||
        layout.ctl_column_base > layout.total_columns ||
        stage3_ctl_col::NUM_COLUMNS >
            layout.total_columns - layout.ctl_column_base) {
        return {};
    }
    for (uint32_t column = stage3_ctl_col::INVERSE1;
         column <= stage3_ctl_col::RUNNING2; ++column) {
        if (proof.batch.columns[
                layout.ctl_column_base + column].root.IsNull()) {
            return {};
        }
    }
    const uint256& quotient_root =
        proof.batch.columns[proof_total_columns].root;
    if (quotient_root.IsNull()) return {};

    HashWriter hash;
    hash << DIRECT_ALIAS_AUX_DOMAIN;
    hash << kRCStage3RelationClosureVersion;
    hash << layout.relation_columns;
    hash << layout.ctl_column_base;
    hash << layout.total_columns;
    hash << proof_total_columns;
    hash << layout.source_column;
    hash << proof.batch.version;
    hash << proof.batch.blowup;
    hash << proof.batch.n_coeffs;
    hash << static_cast<uint32_t>(proof.batch.column_len.size());
    for (const uint32_t length : proof.batch.column_len) {
        hash << length;
    }
    for (uint32_t column = stage3_ctl_col::INVERSE1;
         column <= stage3_ctl_col::RUNNING2; ++column) {
        hash << proof.batch.columns[
            layout.ctl_column_base + column].root;
    }
    hash << quotient_root;
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
    if (ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
            proof, layout) != ctl_pin.auxiliary_commitment) {
        return Fail(why, "direct_alias:ctl_auxiliary_commitment");
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
    if (ComputeRCStage3RelationCtlDirectAliasAuxiliaryCommitment(
            proof, layout) != ctl_pin.auxiliary_commitment) {
        return Fail(why, "coupled_alias:ctl_auxiliary_commitment");
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
    // Measured from the endpoint cell audit. Each role is complete only when
    // every required endpoint is (a) strict-transitively complete, (b)
    // same-trace CTL aliased, and (c) recursively consumed by the complete
    // fixed-point parent. Recursive execution is preservation of a semantic
    // claim, not a way to manufacture missing all-instance provenance.
    std::vector<RCStage3RelationClosureRoleAudit> out;
    out.reserve(kRCStage3RelationClosureRoleCount);
    const auto cells = CurrentRCStage3RelationEndpointCellAudit();
    for (const RCStage3RelationRole role : RCStage3UnifiedRoleOrder()) {
        RCStage3RelationClosureRoleAudit audit;
        audit.role = role;
        uint16_t required = 0;
        uint16_t ctl = 0;
        uint16_t strict = 0;
        uint16_t recursive_strict = 0;
        for (const auto& cell : cells) {
            if (cell.role != role) continue;
            ++required;
            ctl += cell.same_trace_ctl_alias ? 1 : 0;
            strict += cell.strict_transitive_complete ? 1 : 0;
            recursive_strict +=
                cell.strict_transitive_complete &&
                        cell.recursive_child_consumed
                    ? 1
                    : 0;
        }
        audit.required_endpoints = required;
        audit.proof_derived_ctl_endpoints = ctl;
        audit.strict_transitive_endpoints = strict;
        audit.recursively_consumed_strict_endpoints =
            recursive_strict;
        // Living from CellAudit evidence bits. Do not OR-in the constexpr
        // gate here — that invented RoleAudit 14/14 while counters stayed 0.
        audit.recursive_ctl_consumption =
            required > 0 && recursive_strict == required;
        audit.role_complete =
            audit.recursive_ctl_consumption &&
            audit.proof_derived_ctl_endpoints ==
                audit.required_endpoints &&
            audit.strict_transitive_endpoints ==
                audit.required_endpoints &&
            audit.recursively_consumed_strict_endpoints ==
                audit.required_endpoints &&
            kRCStage3RelationClosureRecursiveChildrenExecutable;
        audit.remaining =
            audit.role_complete
                ? "strict transitive semantic provenance, role CTL export, "
                  "and recursive child consumption closed; consensus "
                  "authority remains fail-closed"
                : "strict transitive semantic provenance, role CTL alias, "
                  "or recursive child consumption still open";
        out.push_back(std::move(audit));
    }
    return out;
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

RCStage3RelationClosureRecursiveConsumptionMeasureV1
MeasureRCStage3RelationClosureRecursiveConsumptionV1()
{
    RCStage3RelationClosureRecursiveConsumptionMeasureV1 out;
    const auto cells = CurrentRCStage3RelationEndpointCellAudit();
    for (const auto& cell : cells) {
        out.recursively_consumed_endpoints +=
            cell.recursive_child_consumed ? 1 : 0;
    }
    const auto roles = CurrentRCStage3RelationClosureRoleAudit();
    uint16_t roles_recursive = 0;
    for (const auto& role : roles) {
        roles_recursive += role.recursive_ctl_consumption ? 1 : 0;
    }
    out.recursively_consumed_roles = roles_recursive;
    out.role_audit_reports_full_recursive_consumption =
        out.roles_required > 0 &&
        out.recursively_consumed_roles == out.roles_required;
    out.counter_note =
        "recursive_counters_" +
        std::to_string(out.recursively_consumed_endpoints) +
        "_of_" +
        std::to_string(out.endpoints_required) +
        "_and_" +
        std::to_string(out.recursively_consumed_roles) +
        "_of_" +
        std::to_string(out.roles_required);
    out.complete =
        out.recursively_consumed_endpoints == out.endpoints_required &&
        out.recursively_consumed_roles == out.roles_required &&
        out.role_audit_reports_full_recursive_consumption &&
        kRCStage3RelationClosureRecursiveChildrenExecutable;
    out.note =
        std::string("stage3:relation_closure:") + out.counter_note +
        (out.complete
             ? ";recursive_consumption_complete;authority_ready=false"
             : ";recursive_consumption_open;"
               "parent_verified_child_evidence_required");
    return out;
}

bool ValidateRCStage3RelationClosureRecursiveConsumptionInterlockV1(
    const RCStage3RelationClosureRecursiveConsumptionMeasureV1& measure,
    uint16_t capability_recursively_consumed_endpoints,
    uint16_t capability_recursively_consumed_roles,
    std::string* why)
{
    // Dishonest posture: RoleAudit claims full recursive consumption while
    // capability counters still report zero (constexpr-only CellAudit lie).
    if (measure.role_audit_reports_full_recursive_consumption &&
        capability_recursively_consumed_endpoints == 0 &&
        capability_recursively_consumed_roles == 0) {
        if (why != nullptr) {
            *why =
                "stage3:relation_closure:"
                "recursive_consumption_interlock:"
                "role_audit_full_while_capability_counters_zero";
        }
        return false;
    }
    // Living counters must agree with the capability audit's measured fields.
    if (measure.recursively_consumed_endpoints !=
            capability_recursively_consumed_endpoints ||
        measure.recursively_consumed_roles !=
            capability_recursively_consumed_roles) {
        if (why != nullptr) {
            *why =
                "stage3:relation_closure:"
                "recursive_consumption_interlock:"
                "cell_audit_vs_capability_counter_mismatch";
        }
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:relation_closure:"
            "recursive_consumption_interlock_ok;" +
            measure.counter_note;
    }
    return true;
}

bool RCStage3EndpointParentVerifiedRecursiveChildEvidenceV1(
    RCStage3RelationEndpoint endpoint)
{
    const uint16_t index = EndpointEvidenceIndex(endpoint);
    if (index >= kRCStage3RelationClosureEndpointCount) {
        return false;
    }
    return g_parent_verified_recursive_child_evidence[index];
}

bool RegisterRCStage3ParentVerifiedRecursiveChildEvidenceV1(
    RCStage3RelationEndpoint endpoint)
{
    const uint16_t index = EndpointEvidenceIndex(endpoint);
    if (index >= kRCStage3RelationClosureEndpointCount) {
        return false;
    }
    g_parent_verified_recursive_child_evidence[index] = true;
    return true;
}

void ClearRCStage3ParentVerifiedRecursiveChildEvidenceV1()
{
    g_parent_verified_recursive_child_evidence.fill(false);
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
    uint32_t next_col = kernel_w;
    for (const RCStage3RelationEndpoint e : required) {
        if (e == RCStage3RelationEndpoint::EpisodeGemmSumcheck) {
            out.endpoint_value_columns.push_back(next_col);
            for (const auto& col : sumcheck.witness) witness.push_back(col);
            next_col += sumcheck.cs.n_columns;
        } else if (e == RCStage3RelationEndpoint::EpisodeGemmSignedRange) {
            out.endpoint_value_columns.push_back(next_col);
            for (const auto& col : signed_range.witness) witness.push_back(col);
            next_col += signed_range.cs.n_columns;
        } else {
            out.endpoint_value_columns.push_back(
                next_col + kRCStage3OpeningValueColumn);
            const std::vector<std::vector<gf::Fp3>> ow = BuildOpeningWitness(
                scalar_cells[scalar_i], scalar_cells[scalar_i],
                scalar_manifests[scalar_i]);
            for (const auto& col : ow) witness.push_back(col);
            next_col += kRCStage3OpeningWidth;
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
    uint32_t next_col = kernel_w;
    for (const RCStage3RelationEndpoint e : required) {
        const RCStage3SpongeProduct* sp = nullptr;
        switch (e) {
        case RCStage3RelationEndpoint::EpisodeWiringCopy: {
            out.endpoint_value_columns.push_back(
                next_col + kRCStage3OpeningValueColumn);
            const std::vector<std::vector<gf::Fp3>> ow =
                BuildOpeningWitness(copy, copy, copy_manifest);
            for (const auto& col : ow) witness.push_back(col);
            next_col += kRCStage3OpeningWidth;
            break;
        }
        case RCStage3RelationEndpoint::EpisodeWiringTranspose: sp = &transpose; break;
        case RCStage3RelationEndpoint::EpisodeWiringResidual: sp = &residual; break;
        case RCStage3RelationEndpoint::EpisodeWiringRoundOrder: sp = &round_order; break;
        default: break;
        }
        if (sp != nullptr) {
            out.endpoint_value_columns.push_back(next_col);
            for (const auto& col : sp->witness) witness.push_back(col);
            next_col += sp->cs.n_columns;
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
    uint32_t next_col = 0;
    for (const auto& fw : frag_witnesses) {
        out.endpoint_value_columns.push_back(
            next_col + kRCStage3StreamEndpointBindValueColumn);
        for (const auto& col : fw) witness.push_back(col);
        next_col += kRCStage3StreamEndpointBindWidth;
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
    uint32_t next_col = 0;
    for (const auto& fw : frag_witnesses) {
        out.endpoint_value_columns.push_back(
            next_col + kRCStage3StreamEndpointBindValueColumn);
        for (const auto& col : fw) witness.push_back(col);
        next_col += kRCStage3StreamEndpointBindWidth;
    }

    out.endpoint_committed_roots = std::move(roots);
    out.fragment_columns = 0;
    out.opening_blocks = static_cast<uint32_t>(out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled_real";
    return out;
}

RCStage3RoleAirProduct
BuildRCStage3PureStreamRoleAirFromManifests(
    RCStage3RelationRole role,
    const std::vector<RCStage3StreamEndpointManifest>&
        endpoint_manifests,
    std::string* why)
{
    RCStage3RoleAirProduct out;
    out.role = role;
    if (!RCStage3RoleIsPureStream(role)) {
        out.note = "not_pure_stream";
        if (why != nullptr) {
            *why =
                "stage3:stream_manifest:"
                "not_pure_stream";
        }
        return out;
    }
    const auto& required =
        RequiredRCStage3RelationEndpoints(role);
    if (endpoint_manifests.size() !=
        required.size()) {
        out.note = "manifest_count";
        if (why != nullptr) {
            *why =
                "stage3:stream_manifest:"
                "manifest_count";
        }
        return out;
    }

    std::vector<ah::Digest> roots;
    std::vector<
        std::vector<std::vector<gf::Fp3>>>
        frag_witnesses;
    roots.reserve(required.size());
    frag_witnesses.reserve(required.size());
    for (uint32_t i = 0;
         i < required.size(); ++i) {
        const RCStage3StreamFamily family =
            StreamFamilyForEndpoint(required[i]);
        std::array<uint32_t, 8> root8{};
        std::string rwhy;
        if (!RCStage3StreamEndpointCommittedRoot(
                family, endpoint_manifests[i],
                root8, &rwhy)) {
            out.note =
                "committed_root:" + rwhy;
            if (why != nullptr) *why = out.note;
            return out;
        }
        frag_witnesses.push_back(
            BuildRCStage3StreamEndpointWitness(
                root8,
                RCStage3StreamEndpointCtlValue(
                    endpoint_manifests[i])));
        roots.push_back(PackStreamRoot(root8));
        out.endpoints.push_back(required[i]);
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3PureStreamRoleAirCS(
            role, roots, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }
    std::vector<std::vector<gf::Fp3>> witness;
    uint32_t next_col = 0;
    for (const auto& fw : frag_witnesses) {
        out.endpoint_value_columns.push_back(
            next_col +
            kRCStage3StreamEndpointBindValueColumn);
        for (const auto& col : fw) {
            witness.push_back(col);
        }
        next_col +=
            kRCStage3StreamEndpointBindWidth;
    }
    out.endpoint_committed_roots =
        std::move(roots);
    out.fragment_columns = 0;
    out.opening_blocks =
        static_cast<uint32_t>(
            out.endpoints.size());
    out.cs = std::move(product);
    out.witness = std::move(witness);
    out.ok = true;
    out.note = "assembled_real_manifests";
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
         [](const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) { return cur[index_col]; }});
    product.constraints.push_back(
        {"composition_link:pad_pin", aq::AirKind::kFirstRow, 1,
         [](const std::vector<gf::Fp3>& cur,
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
    uint32_t next_col = kernel_w;
    for (uint32_t i = 0; i < pieces.size(); ++i) {
        const RCStage3RelationEndpoint endpoint = required[i];
        const auto& piece = pieces[i];
        out.endpoint_value_columns.push_back(
            next_col +
            (IsInCsStreamEndpoint(endpoint)
                 ? kRCStage3StreamEndpointBindValueColumn
                 : kRCStage3OpeningValueColumn));
        for (const auto& col : piece) witness.push_back(col);
        next_col += static_cast<uint32_t>(piece.size());
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
    const std::vector<std::array<uint32_t, 8>>* real_stream_roots,
    const std::vector<RCStage3StreamEndpointManifest>*
        real_stream_manifests)
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
            gf::Fp3 ctl_value =
                gf::Fp3::FromFp(gf::FromU64(9));
            if (real_stream_manifests != nullptr) {
                if (stream_ix >=
                    real_stream_manifests->size()) {
                    out.note = "stream_manifest_count";
                    if (why != nullptr) {
                        *why =
                            "stage3:nokernel:"
                            "stream_manifest_count";
                    }
                    return out;
                }
                const auto& manifest =
                    (*real_stream_manifests)[stream_ix];
                std::string rwhy;
                if (!RCStage3StreamEndpointCommittedRoot(
                        family, manifest, root8, &rwhy)) {
                    out.note =
                        "committed_root:" + rwhy;
                    return out;
                }
                if (real_stream_roots != nullptr &&
                    (stream_ix >=
                         real_stream_roots->size() ||
                     (*real_stream_roots)[stream_ix] !=
                         root8)) {
                    out.note = "stream_root_manifest_mismatch";
                    if (why != nullptr) {
                        *why =
                            "stage3:nokernel:"
                            "stream_root_manifest_mismatch";
                    }
                    return out;
                }
                ctl_value =
                    RCStage3StreamEndpointCtlValue(
                        manifest);
            } else if (real_stream_roots != nullptr &&
                       stream_ix <
                           real_stream_roots->size()) {
                root8 =
                    (*real_stream_roots)[stream_ix];
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
                ctl_value =
                    RCStage3StreamEndpointCtlValue(
                        manifest);
            }
            ++stream_ix;
            const std::vector<std::vector<gf::Fp3>> fw =
                BuildRCStage3StreamEndpointWitness(
                    root8, ctl_value);
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
    if (real_stream_manifests != nullptr &&
        stream_ix != real_stream_manifests->size()) {
        out.note = "stream_manifest_count";
        if (why != nullptr) {
            *why =
                "stage3:nokernel:"
                "stream_manifest_count";
        }
        return out;
    }

    aq::AirConstraintSystem<gf::Fp3> product;
    std::string awhy;
    if (!BuildRCStage3NoKernelRoleAirCS(role, roots, path_len, product, &awhy)) {
        out.note = "assemble:" + awhy;
        if (why != nullptr) *why = awhy;
        return out;
    }

    std::vector<std::vector<gf::Fp3>> witness;
    uint32_t next_col = 0;
    for (uint32_t i = 0; i < pieces.size(); ++i) {
        const RCStage3RelationEndpoint endpoint = required[i];
        const auto& piece = pieces[i];
        out.endpoint_value_columns.push_back(
            next_col +
            (IsInCsStreamEndpoint(endpoint)
                 ? kRCStage3StreamEndpointBindValueColumn
                 : (WiredEndpointLeafLanes(endpoint) != 0
                        ? 0U
                        : kRCStage3OpeningValueColumn)));
        for (const auto& col : piece) witness.push_back(col);
        next_col += static_cast<uint32_t>(piece.size());
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
