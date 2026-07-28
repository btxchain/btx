// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_verifier_air.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_fs_selection_air.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iterator>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_verifier_air {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
namespace nr = narrow_recurse;

constexpr char FS_PROGRAM_DOMAIN[] =
    "BTX_RC_STAGE3_VERIFIER_FS_PROGRAM_V1";
constexpr char FS_WITNESS_DOMAIN[] =
    "BTX_RC_STAGE3_VERIFIER_FS_WITNESS_V1";
constexpr char CHILD_PROOF_DOMAIN[] =
    "BTX_RC_STAGE3_VERIFIER_CHILD_PROOF_V1";
constexpr char ROW_BINDING_DOMAIN[] =
    "BTX_RC_STAGE3_VERIFIER_ROW_BINDING_V1";
constexpr char BINDING_DOMAIN[] =
    "BTX_RC_STAGE3_VERIFIER_BINDING_V1";

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:verifier_air:" + message;
    return false;
}

uint64_t CeilDiv(uint64_t n, uint64_t d)
{
    return n / d + (n % d != 0 ? 1 : 0);
}

bool CheckedMulU64(uint64_t lhs, uint64_t rhs, uint64_t& out)
{
    if (lhs != 0 &&
        rhs > std::numeric_limits<uint64_t>::max() / lhs) {
        out = 0;
        return false;
    }
    out = lhs * rhs;
    return true;
}

void AppendU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void AppendU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(static_cast<unsigned char>(value >> (8 * i)));
    }
}

void AppendHash(std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(out.end(), value.begin(), value.end());
}

void AppendFp3(std::vector<unsigned char>& out, const Fp3& value)
{
    AppendU64(out, value.c0);
    AppendU64(out, value.c1);
    AppendU64(out, value.c2);
}

void HashFp3(HashWriter& hash, const Fp3& value)
{
    hash << value.c0;
    hash << value.c1;
    hash << value.c2;
}

void HashDigest(HashWriter& hash, const Fri3AlgDigest& digest)
{
    for (const auto limb : digest) hash << limb;
}

uint32_t Sha256dCompressionBlocks(uint64_t preimage_bytes)
{
    // SHA256 padding adds 0x80 plus an eight-byte bit length; the second
    // SHA256 hashes the 32-byte first digest and always costs one block.
    const uint64_t first =
        CeilDiv(preimage_bytes + 9, uint64_t{64});
    const uint64_t total = first + 1;
    return total > std::numeric_limits<uint32_t>::max()
               ? 0
               : static_cast<uint32_t>(total);
}

const char* ChallengeLabel(FiatShamirEventKind kind)
{
    switch (kind) {
    case FiatShamirEventKind::ChallengeLambda: return "fra3_lambda";
    case FiatShamirEventKind::ChallengeZ1:
    case FiatShamirEventKind::ChallengeZ2: return "fra3_z";
    case FiatShamirEventKind::ChallengeW1:
    case FiatShamirEventKind::ChallengeW2: return "fra3_w";
    case FiatShamirEventKind::ChallengeFold: return "fra3_fold";
    case FiatShamirEventKind::ChallengeQueryIndex: return "fra3_query";
    case FiatShamirEventKind::ChallengeAirQuotientLambda:
        return "airq_lambda";
    default: return "";
    }
}

bool IsChallengeEvent(FiatShamirEventKind kind)
{
    return kind == FiatShamirEventKind::ChallengeLambda ||
           kind == FiatShamirEventKind::ChallengeZ1 ||
           kind == FiatShamirEventKind::ChallengeZ2 ||
           kind == FiatShamirEventKind::ChallengeW1 ||
           kind == FiatShamirEventKind::ChallengeW2 ||
           kind == FiatShamirEventKind::ChallengeFold ||
           kind == FiatShamirEventKind::ChallengeQueryIndex ||
           kind == FiatShamirEventKind::ChallengeAirQuotientLambda;
}

uint256 CommitFiatShamirProgram(const FiatShamirProgram& program)
{
    HashWriter hash;
    hash << FS_PROGRAM_DOMAIN;
    const auto& child = program.child_shape;
    hash << child.child_w;
    hash << child.child_n_rows;
    hash << child.child_n_coeffs;
    hash << child.child_n_lde;
    hash << child.merkle_depth;
    hash << child.n_folds;
    hash << child.queries;
    hash << child.child_constraints;
    hash << child.arity;
    hash << program.child_proof_version;
    hash << program.child_domain_tag;
    hash << program.child_domain_tag_bytes;
    hash << static_cast<uint8_t>(
        program.child_short_transcript_commitments ? 1 : 0);
    hash << static_cast<uint8_t>(
        program.child_sha256d_challenges ? 1 : 0);
    hash << static_cast<uint8_t>(program.canary_only ? 1 : 0);
    hash << static_cast<uint8_t>(program.authority_eligible ? 1 : 0);
    hash << program.scheduled_rows;
    hash << program.absorbed_bytes;
    hash << program.minimum_sha256_compression_blocks;
    hash << program.streaming_sha256_compression_blocks;
    hash << program.ood_candidates;
    hash << static_cast<uint8_t>(program.rejection_loop_bounded ? 1 : 0);
    hash << static_cast<uint32_t>(program.events.size());
    for (const auto& event : program.events) {
        hash << static_cast<uint8_t>(event.kind);
        hash << event.index;
        hash << event.transcript_bytes_before;
        hash << event.absorbed_bytes;
        hash << event.minimum_sha256_compression_blocks;
    }
    return hash.GetHash();
}

uint256 CommitVerifierProgram(const VerifierProgram& program)
{
    HashWriter hash;
    hash << BINDING_DOMAIN;
    const auto& child = program.child_shape;
    hash << child.child_w;
    hash << child.child_n_rows;
    hash << child.child_n_coeffs;
    hash << child.child_n_lde;
    hash << child.merkle_depth;
    hash << child.n_folds;
    hash << child.queries;
    hash << child.child_constraints;
    hash << child.arity;
    hash << program.active_rows;
    hash << program.trace_rows;
    hash << static_cast<uint32_t>(program.rows.size());
    for (const auto& row : program.rows) {
        hash << static_cast<uint8_t>(row.kind);
        hash << static_cast<uint8_t>(row.source);
        hash << row.child;
        hash << row.query;
        hash << row.layer;
        hash << row.step;
    }
    return hash.GetHash();
}

uint256 CommitFiatShamirWitness(const FiatShamirWitness& witness)
{
    HashWriter hash;
    hash << FS_WITNESS_DOMAIN;
    hash << witness.program_commitment;
    hash << static_cast<uint32_t>(witness.events.size());
    for (const auto& event : witness.events) {
        hash << event.event_index;
        hash << static_cast<uint32_t>(event.absorbed_payload.size());
        for (const unsigned char byte : event.absorbed_payload) hash << byte;
        hash << static_cast<uint8_t>(event.has_fp3_challenge);
        if (event.has_fp3_challenge) HashFp3(hash, event.claimed_challenge);
        hash << static_cast<uint8_t>(event.has_query_index);
        if (event.has_query_index) hash << event.claimed_query_index;
    }
    return hash.GetHash();
}

bool IsScalarKind(ProgramRowKind kind)
{
    return kind == ProgramRowKind::MerkleCompress ||
           kind == ProgramRowKind::FoldAlgebra ||
           kind == ProgramRowKind::DeepAccumulate ||
           kind == ProgramRowKind::PerPointAccumulate ||
           kind == ProgramRowKind::Boundary;
}

ScalarOp OpForKind(ProgramRowKind kind)
{
    switch (kind) {
    case ProgramRowKind::MerkleCompress: return ScalarOp::MerkleRoute;
    case ProgramRowKind::FoldAlgebra: return ScalarOp::FoldAlgebra;
    case ProgramRowKind::DeepAccumulate: return ScalarOp::DeepAccumulate;
    case ProgramRowKind::PerPointAccumulate:
        return ScalarOp::PerPointIdentity;
    case ProgramRowKind::Boundary: return ScalarOp::BoundaryEquality;
    default: return ScalarOp::Count;
    }
}

void AddRow(VerifierProgram& out, ProgramRowKind kind,
            ProgramRowSource source, uint32_t child,
            uint32_t query, uint32_t layer, uint32_t step)
{
    ProgramRow row;
    row.kind = kind;
    row.source = source;
    row.child = static_cast<uint16_t>(child);
    row.query = static_cast<uint16_t>(query);
    row.layer = static_cast<uint16_t>(layer);
    row.step = step;
    out.rows.push_back(row);
    ++out.row_kind_counts[static_cast<uint32_t>(kind)];
}

std::vector<aq::AirConstraint<Fp3>>
BuildScalarConstraints(const ScalarLayout& layout)
{
    std::vector<aq::AirConstraint<Fp3>> out;
    out.reserve(19);

    for (uint32_t op = 0; op < kScalarOpCount; ++op) {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.selector.bool";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 2;
        const uint32_t selector =
            layout.Selector(static_cast<ScalarOp>(op));
        constraint.eval =
            [selector](const std::vector<Fp3>& cur,
                       const std::vector<Fp3>&) {
                return gf::Mul(
                    cur[selector],
                    gf::Sub(cur[selector], Fp3::One()));
            };
        out.push_back(std::move(constraint));
    }
    {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.selector.at_most_one";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 2;
        constraint.eval =
            [layout](const std::vector<Fp3>& cur,
                     const std::vector<Fp3>&) {
                Fp3 sum = Fp3::Zero();
                for (uint32_t op = 0; op < kScalarOpCount; ++op) {
                    sum = gf::Add(
                        sum,
                        cur[layout.Selector(static_cast<ScalarOp>(op))]);
                }
                return gf::Mul(sum, gf::Sub(sum, Fp3::One()));
            };
        out.push_back(std::move(constraint));
    }

    const auto gate =
        [layout](ScalarOp op, const std::vector<Fp3>& cur,
                 const Fp3& residual) {
            return gf::Mul(cur[layout.Selector(op)], residual);
        };

    {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.merkle.direction.bool";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 3;
        constraint.eval =
            [layout, gate](const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
                return gate(
                    ScalarOp::MerkleRoute, cur,
                    gf::Mul(cur[layout.direction],
                            gf::Sub(cur[layout.direction], Fp3::One())));
            };
        out.push_back(std::move(constraint));
    }
    for (uint32_t lane = 0; lane < 4; ++lane) {
        {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = "stage3.verifier.merkle.left";
            constraint.kind = aq::AirKind::kEverywhere;
            constraint.alg_degree = 3;
            constraint.eval =
                [layout, lane, gate](const std::vector<Fp3>& cur,
                                     const std::vector<Fp3>&) {
                    const Fp3& acc = cur[layout.accumulator_base + lane];
                    const Fp3& sib = cur[layout.sibling_base + lane];
                    const Fp3 expect =
                        gf::Add(acc,
                                gf::Mul(cur[layout.direction],
                                        gf::Sub(sib, acc)));
                    return gate(
                        ScalarOp::MerkleRoute, cur,
                        gf::Sub(cur[layout.left_base + lane], expect));
                };
            out.push_back(std::move(constraint));
        }
        {
            aq::AirConstraint<Fp3> constraint;
            constraint.name = "stage3.verifier.merkle.right";
            constraint.kind = aq::AirKind::kEverywhere;
            constraint.alg_degree = 3;
            constraint.eval =
                [layout, lane, gate](const std::vector<Fp3>& cur,
                                     const std::vector<Fp3>&) {
                    const Fp3& acc = cur[layout.accumulator_base + lane];
                    const Fp3& sib = cur[layout.sibling_base + lane];
                    const Fp3 expect =
                        gf::Add(sib,
                                gf::Mul(cur[layout.direction],
                                        gf::Sub(acc, sib)));
                    return gate(
                        ScalarOp::MerkleRoute, cur,
                        gf::Sub(cur[layout.right_base + lane], expect));
                };
            out.push_back(std::move(constraint));
        }
    }
    {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.fold";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 3;
        constraint.eval =
            [layout, gate](const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
                // 2*x*out - x*(f(x)+f(-x)) - beta*(f(x)-f(-x)) = 0.
                const Fp3 lhs = gf::Mul(
                    gf::Mul(Fp3::FromFp(gf::FromU64(2)), cur[layout.c]),
                    cur[layout.out]);
                const Fp3 even_term = gf::Mul(
                    cur[layout.c],
                    gf::Add(cur[layout.a], cur[layout.b]));
                const Fp3 odd_term = gf::Mul(
                    cur[layout.d],
                    gf::Sub(cur[layout.a], cur[layout.b]));
                return gate(
                    ScalarOp::FoldAlgebra, cur,
                    gf::Sub(gf::Sub(lhs, even_term), odd_term));
            };
        out.push_back(std::move(constraint));
    }
    {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.deep_rlc";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 3;
        constraint.eval =
            [layout, gate](const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
                return gate(
                    ScalarOp::DeepAccumulate, cur,
                    gf::Sub(
                        cur[layout.out],
                        gf::Add(gf::Mul(cur[layout.a], cur[layout.b]),
                                cur[layout.c])));
            };
        out.push_back(std::move(constraint));
    }
    {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.per_point";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 3;
        constraint.eval =
            [layout, gate](const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
                return gate(
                    ScalarOp::PerPointIdentity, cur,
                    gf::Sub(cur[layout.a],
                            gf::Mul(cur[layout.b], cur[layout.c])));
            };
        out.push_back(std::move(constraint));
    }
    {
        aq::AirConstraint<Fp3> constraint;
        constraint.name = "stage3.verifier.boundary";
        constraint.kind = aq::AirKind::kEverywhere;
        constraint.alg_degree = 2;
        constraint.eval =
            [layout, gate](const std::vector<Fp3>& cur,
                           const std::vector<Fp3>&) {
                return gate(
                    ScalarOp::BoundaryEquality, cur,
                    gf::Sub(cur[layout.out], cur[layout.a]));
            };
        out.push_back(std::move(constraint));
    }
    return out;
}

} // namespace

VerifierProgram BuildCanonicalVerifierProgram(
    const NarrowChildShape& child)
{
    VerifierProgram out;
    out.child_shape = child;
    nr::NarrowVcsConfig config;
    config.poseidon_strategy =
        nr::PoseidonLaneStrategy::DecomposedX2X4X6;
    config.child_packing = nr::ChildPacking::VerticalRows;
    const nr::NarrowVcsPlan plan = nr::BuildNarrowVcsPlan(child, config);
    if (!plan.valid) {
        out.note = plan.note;
        return out;
    }
    if (child.arity > std::numeric_limits<uint16_t>::max() ||
        child.queries > std::numeric_limits<uint16_t>::max() ||
        child.n_folds > std::numeric_limits<uint16_t>::max()) {
        out.note = "stage3:verifier_air:program_metadata_overflow";
        return out;
    }
    if (plan.active_rows > std::numeric_limits<size_t>::max()) {
        out.note = "stage3:verifier_air:program_size_overflow";
        return out;
    }
    out.rows.reserve(plan.trace_rows);
    const uint32_t row_leaf_perms =
        static_cast<uint32_t>(nr::RowLeafPermutationRows(child.child_w));
    const uint32_t deep_rows =
        static_cast<uint32_t>(CeilDiv(
            static_cast<uint64_t>(child.child_w) + 1,
            nr::kNarrowStreamBatch));
    const uint32_t per_point_rows =
        static_cast<uint32_t>(CeilDiv(
            child.child_constraints, nr::kNarrowStreamBatch)) + 1;
    const uint32_t fs_rows =
        static_cast<uint32_t>(nr::FiatShamirReplayRows(child));

    for (uint32_t child_index = 0; child_index < child.arity;
         ++child_index) {
        for (uint32_t query = 0; query < child.queries; ++query) {
            for (uint32_t step = 0; step < row_leaf_perms; ++step) {
                AddRow(out, ProgramRowKind::PoseidonPermutation,
                       ProgramRowSource::RowLeaf,
                       child_index, query, 0, step);
            }
            for (uint32_t step = 0; step < child.merkle_depth; ++step) {
                AddRow(out, ProgramRowKind::MerkleCompress,
                       ProgramRowSource::RowMerkle,
                       child_index, query, 0, step);
            }
            for (uint32_t layer = 0; layer < child.n_folds; ++layer) {
                const uint32_t path_depth = child.merkle_depth - layer;
                for (uint32_t side = 0; side < 2; ++side) {
                    AddRow(out, ProgramRowKind::PoseidonPermutation,
                           side == 0
                               ? ProgramRowSource::FoldEvenLeaf
                               : ProgramRowSource::FoldOddLeaf,
                           child_index, query, layer, side);
                    for (uint32_t step = 0; step < path_depth; ++step) {
                        AddRow(out, ProgramRowKind::MerkleCompress,
                               side == 0
                                   ? ProgramRowSource::FoldEvenMerkle
                                   : ProgramRowSource::FoldOddMerkle,
                               child_index, query, layer,
                               side * path_depth + step);
                    }
                }
                AddRow(out, ProgramRowKind::FoldAlgebra,
                       ProgramRowSource::FoldEquation,
                       child_index, query, layer, 0);
            }
            for (uint32_t step = 0; step < deep_rows; ++step) {
                AddRow(out, ProgramRowKind::DeepAccumulate,
                       ProgramRowSource::DeepEquation,
                       child_index, query, 0, step);
            }
            for (uint32_t step = 0; step < per_point_rows; ++step) {
                AddRow(out, ProgramRowKind::PerPointAccumulate,
                       ProgramRowSource::PerPointEquation,
                       child_index, query, 0, step);
            }
            AddRow(out, ProgramRowKind::Boundary,
                   ProgramRowSource::BoundaryEquation,
                   child_index, query, 0, 0);
            AddRow(out, ProgramRowKind::Boundary,
                   ProgramRowSource::BoundaryEquation,
                   child_index, query, 0, 1);
        }
        for (uint32_t step = 0; step < fs_rows; ++step) {
            AddRow(out, ProgramRowKind::FiatShamirAbsorb,
                   ProgramRowSource::FiatShamirTranscript,
                   child_index, 0, 0, step);
        }
    }
    out.active_rows = out.rows.size();
    if (out.active_rows != plan.active_rows) {
        out.note = "stage3:verifier_air:planner_schedule_mismatch";
        return out;
    }
    while (out.rows.size() < plan.trace_rows) {
        AddRow(out, ProgramRowKind::Padding,
               ProgramRowSource::Padding, 0, 0, 0, 0);
    }
    out.trace_rows = plan.trace_rows;
    out.valid = true;
    out.note = "stage3:verifier_air:canonical_fixed_program";
    return out;
}

bool ValidateCanonicalVerifierProgram(
    const VerifierProgram& program, std::string* why)
{
    if (!program.valid) return Fail(why, "program_not_valid");
    const VerifierProgram expected =
        BuildCanonicalVerifierProgram(program.child_shape);
    if (!expected.valid) return Fail(why, "program_shape_invalid");
    if (program.active_rows != expected.active_rows ||
        program.trace_rows != expected.trace_rows ||
        program.rows != expected.rows ||
        program.row_kind_counts != expected.row_kind_counts) {
        return Fail(why, "noncanonical_program");
    }
    return true;
}

std::vector<ExactVerifierScheduleScenario>
AssessExactVerifierScheduleScenarios(const NarrowChildShape& child)
{
    std::vector<ExactVerifierScheduleScenario> out;
    const VerifierProgram program =
        BuildCanonicalVerifierProgram(child);
    const FiatShamirProgram fs =
        BuildCanonicalFiatShamirProgram(child);
    if (!program.valid || !fs.valid || child.arity == 0) {
        return out;
    }
    const uint64_t estimated_fs_total =
        static_cast<uint64_t>(child.arity) *
        nr::FiatShamirReplayRows(child);
    if (program.active_rows < estimated_fs_total) return out;
    const uint64_t non_fs_per_child =
        (program.active_rows - estimated_fs_total) /
        child.arity;
    const auto make =
        [&](VerifierChildPacking packing)
            -> ExactVerifierScheduleScenario {
        ExactVerifierScheduleScenario scenario;
        scenario.packing = packing;
        scenario.non_fiat_shamir_rows_per_child =
            non_fs_per_child;
        scenario.fiat_shamir_rows_per_child =
            fs.streaming_sha256_compression_blocks;
        scenario.naive_fiat_shamir_rows_per_child =
            fs.minimum_sha256_compression_blocks;
        const uint64_t per_child =
            non_fs_per_child +
            fs.streaming_sha256_compression_blocks;
        scenario.active_rows =
            packing == VerifierChildPacking::VerticalRows
                ? per_child * child.arity
                : per_child;
        uint64_t trace = 1;
        while (trace < scenario.active_rows &&
               trace <=
                   (uint64_t{1} << kRCFriMaxLdeLog2)) {
            trace <<= 1;
        }
        if (trace > std::numeric_limits<uint32_t>::max()) {
            scenario.note =
                "stage3:verifier_air:schedule_trace_overflow";
            return scenario;
        }
        scenario.trace_rows = static_cast<uint32_t>(trace);
        const nr::NarrowLaneLayout lane =
            nr::CanonicalNarrowLaneLayout(
                nr::PoseidonLaneStrategy::DecomposedX2X4X6);
        const uint64_t lanes =
            packing == VerifierChildPacking::ParallelLanes
                ? child.arity
                : 1;
        const uint64_t width =
            static_cast<uint64_t>(lane.width) * lanes;
        if (width > std::numeric_limits<uint32_t>::max()) {
            scenario.note =
                "stage3:verifier_air:schedule_width_overflow";
            return scenario;
        }
        scenario.width = static_cast<uint32_t>(width);
        // Quadratic X2/X4/X6 lane plus selector => maximum gated degree 3.
        const uint64_t quotient_len =
            2 * (trace - 1);
        uint64_t coeffs = 1;
        while (coeffs < std::max(trace, quotient_len)) {
            coeffs <<= 1;
        }
        if (coeffs > std::numeric_limits<uint32_t>::max()) {
            scenario.note =
                "stage3:verifier_air:schedule_coeff_overflow";
            return scenario;
        }
        scenario.quotient_coeffs =
            static_cast<uint32_t>(coeffs);
        const uint64_t lde = coeffs * kRCFriBlowup;
        if (lde <= std::numeric_limits<uint32_t>::max()) {
            scenario.lde_rows = static_cast<uint32_t>(lde);
        }
        scenario.cells =
            static_cast<uint64_t>(scenario.trace_rows) *
            scenario.width;
        scenario.column_cap_met =
            scenario.width <= kRCFri3AlgBatchMaxColumns;
        scenario.lde_cap_met =
            lde <= (uint64_t{1} << kRCFriMaxLdeLog2);
        scenario.backend_shape_supported =
            scenario.column_cap_met &&
            scenario.lde_cap_met;
        // The canonical executable row type currently carries only one child.
        scenario.executable_layout =
            packing == VerifierChildPacking::VerticalRows;
        scenario.note =
            scenario.backend_shape_supported
                ? (scenario.executable_layout
                       ? "stage3:verifier_air:schedule_backend_ok"
                       : "stage3:verifier_air:schedule_shape_ok_layout_open")
                : "stage3:verifier_air:schedule_backend_cap";
        return scenario;
    };
    out.push_back(make(VerifierChildPacking::VerticalRows));
    out.push_back(make(VerifierChildPacking::ParallelLanes));
    return out;
}

FixedOodScheduleBound ComputeFixedOodScheduleBound(
    uint32_t candidates_k, uint32_t base_field_bits,
    uint32_t ext_coords, uint32_t target_bits)
{
    FixedOodScheduleBound out;
    out.candidates_k = candidates_k;
    out.target_bits = target_bits;
    // Rejecting the base-field line removes |Fp|^1 of |Fp|^ext_coords
    // extension-coordinate assignments: one draw is rejected with probability
    // <= 2^-(base_field_bits*ext_coords).  (For Fp3 ext_coords==2.)
    const uint64_t per_draw =
        static_cast<uint64_t>(base_field_bits) * ext_coords;
    out.per_draw_reject_bits =
        per_draw > std::numeric_limits<uint32_t>::max()
            ? std::numeric_limits<uint32_t>::max()
            : static_cast<uint32_t>(per_draw);
    const uint64_t all_rejected =
        static_cast<uint64_t>(out.per_draw_reject_bits) * candidates_k;
    out.all_rejected_bits =
        all_rejected > std::numeric_limits<uint32_t>::max()
            ? std::numeric_limits<uint32_t>::max()
            : static_cast<uint32_t>(all_rejected);
    // candidates_k==0 is the legacy unbounded while(true) sampler: not a fixed
    // schedule, so never bounded no matter how large the per-draw margin is.
    out.bounded =
        candidates_k >= 1 && out.all_rejected_bits >= target_bits;
    return out;
}

uint32_t SelectFirstAcceptableOodIndex(
    const std::vector<Fp3>& candidates, const Fp3* distinct_from)
{
    for (uint32_t i = 0; i < candidates.size(); ++i) {
        const Fp3& z = candidates[i];
        // Off the base-field line: at least one extension coordinate nonzero.
        const bool has_ext_coord =
            gf::Canonical(z.c1) != 0 || gf::Canonical(z.c2) != 0;
        if (!has_ext_coord) continue;
        if (distinct_from != nullptr && gf::Eq(z, *distinct_from)) continue;
        return i;
    }
    return static_cast<uint32_t>(candidates.size());
}

static FiatShamirProgram BuildFiatShamirProgramImpl(
    const NarrowChildShape& child, uint32_t ood_candidates)
{
    FiatShamirProgram out;
    out.child_shape = child;
    out.ood_candidates = ood_candidates;
    const bool bounded_sha_canary = ood_candidates != 0;
    out.child_proof_version =
        bounded_sha_canary
            ? kRCFri3AlgShaFsCanaryProofVersion
            : kRCFri3AlgActiveBatchProofVersion;
    out.child_domain_tag =
        bounded_sha_canary
            ? kRCFri3AlgShaFsCanaryDomainTag
            : kRCFri3AlgActiveBatchDomainTag;
    out.child_domain_tag_bytes =
        static_cast<uint32_t>(out.child_domain_tag.size());
    out.child_short_transcript_commitments =
        bounded_sha_canary
            ? true
            : kRCFri3AlgActiveShortTranscript;
    out.child_sha256d_challenges =
        bounded_sha_canary
            ? true
            : !kRCFri3AlgActiveP2Squeeze;
    out.canary_only = bounded_sha_canary;
    out.authority_eligible =
        !bounded_sha_canary &&
        child.queries == kRCFri3AlgNumQueries;
    if (bounded_sha_canary &&
        (ood_candidates != kRCFiatShamirOodCandidateSchedule ||
         child.queries != 2)) {
        out.note =
            "stage3:verifier_air:"
            "sha_canary_requires_q2_k2";
        return out;
    }
    nr::NarrowVcsConfig config;
    config.poseidon_strategy =
        nr::PoseidonLaneStrategy::DecomposedX2X4X6;
    config.child_packing = nr::ChildPacking::VerticalRows;
    if (!nr::BuildNarrowVcsPlan(child, config).valid ||
        child.child_w == std::numeric_limits<uint32_t>::max() ||
        child.n_folds == std::numeric_limits<uint32_t>::max()) {
        out.note = "stage3:verifier_air:fs_shape";
        return out;
    }

    const uint64_t columns = static_cast<uint64_t>(child.child_w) + 1;
    // PR-89 g4 ACTIVATION.  Fri3AlgBatchFsInit's per-column `4 * columns`
    // block is exactly the term (i) the short-transcript lane replaces with a
    // single 32-byte Fri3AlgShapeCommit.  W itself stays in the clear (the
    // `4 +` before it), because the verifier must size its vectors before it
    // can hash anything -- and the commitment re-binds W anyway.
    const uint64_t shape_bytes =
        out.child_short_transcript_commitments
            ? uint64_t{32}
            : 4 * columns;
    const uint64_t preamble_bytes =
        out.child_domain_tag_bytes + 32 + 8 + 4 + 4 +
        4 + 4 + shape_bytes + 32;
    if (preamble_bytes > std::numeric_limits<uint32_t>::max()) {
        out.note = "stage3:verifier_air:fs_preamble_overflow";
        return out;
    }

    uint64_t transcript_bytes = 0;
    uint64_t sha_blocks = 0;
    uint64_t streaming_sha_blocks = 0;
    auto add = [&](FiatShamirEventKind kind, uint32_t index,
                   uint32_t absorbed_bytes,
                   uint32_t forced_sha_blocks = 0) {
        FiatShamirEventSpec event;
        event.kind = kind;
        event.index = index;
        event.transcript_bytes_before = transcript_bytes;
        event.absorbed_bytes = absorbed_bytes;
        if (IsChallengeEvent(kind)) {
            if (forced_sha_blocks != 0) {
                event.minimum_sha256_compression_blocks =
                    forced_sha_blocks;
            } else {
                const uint64_t preimage =
                    transcript_bytes +
                    std::strlen(ChallengeLabel(kind)) + 4;
                event.minimum_sha256_compression_blocks =
                    Sha256dCompressionBlocks(preimage);
            }
            sha_blocks += event.minimum_sha256_compression_blocks;
            if (forced_sha_blocks != 0) {
                streaming_sha_blocks += forced_sha_blocks;
            } else {
                const uint64_t partial =
                    transcript_bytes % 64;
                const uint64_t suffix =
                    std::strlen(ChallengeLabel(kind)) + 4;
                streaming_sha_blocks +=
                    CeilDiv(
                        partial + suffix + 9,
                        uint64_t{64}) +
                    1;
            }
        }
        out.events.push_back(event);
        transcript_bytes += absorbed_bytes;
    };

    // AirChallengeDigest("airq_lambda") is a separate SHA256d transcript:
    // tag, seed, label, one trace root and three uint32 shape values.
    constexpr uint64_t AIRQ_PREIMAGE_BYTES =
        (sizeof("BTX_RC_AIRQ_V1") - 1) + 32 +
        4 + (sizeof("airq_lambda") - 1) +
        4 + 32 + 4 + 3 * 4;
    add(FiatShamirEventKind::ChallengeAirQuotientLambda, 0, 0,
        Sha256dCompressionBlocks(AIRQ_PREIMAGE_BYTES));
    add(FiatShamirEventKind::AbsorbPreamble, 0,
        static_cast<uint32_t>(preamble_bytes));
    add(FiatShamirEventKind::ChallengeLambda, 0, 0);
    add(FiatShamirEventKind::AbsorbLambda, 0, 24);
    if (ood_candidates == 0) {
        // Legacy V3 unbounded single-draw format (deliberately preserved).
        add(FiatShamirEventKind::ChallengeZ1, 0, 0);
        add(FiatShamirEventKind::ChallengeZ2, 1, 0);
    } else {
        // Fixed schedule: lay every candidate draw for z1 then z2.  The SHA-FS
        // chip materializes all K SHA256d draws in a fixed-width V_CS and a
        // selector picks the first candidate passing the OOD predicate.
        for (uint32_t k = 0; k < ood_candidates; ++k) {
            add(FiatShamirEventKind::ChallengeZ1, k, 0);
        }
        for (uint32_t k = 0; k < ood_candidates; ++k) {
            add(FiatShamirEventKind::ChallengeZ2, k, 0);
        }
    }
    add(FiatShamirEventKind::AbsorbZ1Z2, 0, 48);
    if (out.child_short_transcript_commitments) {
        // Term (ii): 48*W bytes -> 32.  ONE event, and deliberately a
        // DIFFERENT kind, so a program built for one layout can never
        // validate against the other.
        add(FiatShamirEventKind::AbsorbOodEvalCommitment, 0, 32);
    } else {
        for (uint32_t column = 0; column < columns; ++column) {
            add(FiatShamirEventKind::AbsorbOodEvaluationPair,
                column, 48);
        }
    }
    add(FiatShamirEventKind::ChallengeW1, 0, 0);
    add(FiatShamirEventKind::ChallengeW2, 1, 0);
    add(FiatShamirEventKind::AbsorbW1W2, 0, 48);
    for (uint32_t layer = 0; layer <= child.n_folds; ++layer) {
        add(FiatShamirEventKind::AbsorbFoldRoot, layer, 32);
        if (layer < child.n_folds) {
            add(FiatShamirEventKind::ChallengeFold, layer, 0);
        }
    }
    for (uint32_t query = 0; query < child.queries; ++query) {
        add(FiatShamirEventKind::ChallengeQueryIndex, query, 0);
    }

    out.scheduled_rows = nr::FiatShamirReplayRows(child);
    out.absorbed_bytes = transcript_bytes;
    out.minimum_sha256_compression_blocks = sha_blocks;
    out.streaming_sha256_compression_blocks =
        streaming_sha_blocks + transcript_bytes / 64;
    out.scheduler_capacity_sufficient =
        out.scheduled_rows >=
        out.streaming_sha256_compression_blocks;
    // Fri3AlgBatchSampleZ rejects a draw until an extension-coordinate
    // predicate holds.  ood_candidates==0 is the legacy V3 while(true) sampler
    // with no maximum retry count (never bounded).  ood_candidates>=1 lays a
    // statically-fixed K-candidate schedule; it is bounded iff K candidates
    // give <= 2^-kRCFiatShamirOodTargetBits all-rejected failure.
    out.rejection_loop_bounded =
        ComputeFixedOodScheduleBound(ood_candidates).bounded;
    out.valid = true;
    out.note = out.scheduler_capacity_sufficient
                   ? "stage3:verifier_air:fs_program_capacity_ok"
                   : "stage3:verifier_air:fs_program_underprovisioned";
    out.commitment = CommitFiatShamirProgram(out);
    return out;
}

FiatShamirProgram BuildCanonicalFiatShamirProgram(
    const NarrowChildShape& child)
{
    return BuildFiatShamirProgramImpl(child, 0);
}

FiatShamirProgram BuildBoundedFiatShamirProgram(
    const NarrowChildShape& child, uint32_t ood_candidates)
{
    return BuildFiatShamirProgramImpl(
        child, ood_candidates == 0 ? 1 : ood_candidates);
}

bool ValidateCanonicalFiatShamirProgram(
    const FiatShamirProgram& program, std::string* why)
{
    if (!program.valid) return Fail(why, "fs_program_not_valid");
    const FiatShamirProgram expected =
        BuildFiatShamirProgramImpl(
            program.child_shape, program.ood_candidates);
    if (!expected.valid ||
        program.ood_candidates != expected.ood_candidates ||
        program.child_proof_version != expected.child_proof_version ||
        program.child_domain_tag != expected.child_domain_tag ||
        program.child_domain_tag_bytes !=
            expected.child_domain_tag_bytes ||
        program.child_short_transcript_commitments !=
            expected.child_short_transcript_commitments ||
        program.child_sha256d_challenges !=
            expected.child_sha256d_challenges ||
        program.canary_only != expected.canary_only ||
        program.authority_eligible != expected.authority_eligible ||
        program.scheduled_rows != expected.scheduled_rows ||
        program.absorbed_bytes != expected.absorbed_bytes ||
        program.minimum_sha256_compression_blocks !=
            expected.minimum_sha256_compression_blocks ||
        program.streaming_sha256_compression_blocks !=
            expected.streaming_sha256_compression_blocks ||
        program.events != expected.events ||
        program.commitment != expected.commitment ||
        program.scheduler_capacity_sufficient !=
            expected.scheduler_capacity_sufficient ||
        program.rejection_loop_bounded !=
            expected.rejection_loop_bounded) {
        return Fail(why, "noncanonical_fs_program");
    }
    return true;
}

FiatShamirWitness BuildFiatShamirWitness(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    FiatShamirWitness out;
    std::string why;
    if (!ValidateCanonicalFiatShamirProgram(program, &why)) {
        out.note = why;
        return out;
    }
    const auto& batch = child_proof.batch;
    const uint32_t columns = program.child_shape.child_w + 1;
    if (batch.version != program.child_proof_version ||
        batch.blowup != kRCFriBlowup ||
        batch.n_coeffs != program.child_shape.child_n_coeffs ||
        static_cast<uint64_t>(batch.n_coeffs) * batch.blowup !=
            program.child_shape.child_n_lde ||
        batch.column_len.size() != columns ||
        batch.evals_z1.size() != columns ||
        batch.evals_z2.size() != columns ||
        batch.fold_layers.size() !=
            static_cast<size_t>(program.child_shape.n_folds) + 1 ||
        batch.fold_challenges.size() != program.child_shape.n_folds ||
        batch.queries.size() != program.child_shape.queries ||
        batch.row_commit.n_leaves !=
            program.child_shape.child_n_lde ||
        child_proof.trace_commit.IsNull() ||
        child_proof.next_openings.size() !=
            program.child_shape.queries) {
        out.note = "stage3:verifier_air:fs_child_shape";
        return out;
    }
    for (uint32_t layer = 0;
         layer < batch.fold_layers.size(); ++layer) {
        if (batch.fold_layers[layer].n_leaves !=
            (program.child_shape.child_n_lde >> layer)) {
            out.note =
                "stage3:verifier_air:fs_fold_layer_shape";
            return out;
        }
    }
    for (uint32_t query = 0;
         query < batch.queries.size(); ++query) {
        const auto& q = batch.queries[query];
        if (q.index >= program.child_shape.child_n_lde ||
            q.row.values.size() != columns ||
            q.row.siblings.size() !=
                program.child_shape.merkle_depth ||
            q.steps.size() != program.child_shape.n_folds ||
            child_proof.next_openings[query].size() != 2 ||
            child_proof.next_openings[query][0].values.size() !=
                columns ||
            !child_proof.next_openings[query][1].values.empty()) {
            out.note =
                "stage3:verifier_air:fs_query_shape";
            return out;
        }
        for (uint32_t layer = 0; layer < q.steps.size(); ++layer) {
            const size_t depth =
                program.child_shape.merkle_depth - layer;
            if (q.steps[layer].even_siblings.size() != depth ||
                q.steps[layer].odd_siblings.size() != depth) {
                out.note =
                    "stage3:verifier_air:fs_fold_opening_shape";
                return out;
            }
        }
    }

    out.program_commitment = program.commitment;
    out.events.reserve(program.events.size());
    for (uint32_t event_index = 0;
         event_index < program.events.size(); ++event_index) {
        const auto& spec = program.events[event_index];
        FiatShamirEventWitness event;
        event.event_index = event_index;
        switch (spec.kind) {
        case FiatShamirEventKind::ChallengeAirQuotientLambda: {
            const uint256 digest =
                aq::AirChallengeDigestForBackend<
                    aq::AirFriBackendAlg<Fp3>>(
                child_fs_seed, "airq_lambda",
                {child_proof.trace_commit},
                {program.child_shape.child_n_rows,
                 batch.column_len.back(),
                 program.child_shape.child_w});
            event.has_fp3_challenge = true;
            event.claimed_challenge =
                gf::FromChallengeBytes3(digest.data());
            break;
        }
        case FiatShamirEventKind::AbsorbPreamble: {
            const auto* domain =
                reinterpret_cast<const unsigned char*>(
                    program.child_domain_tag.data());
            const size_t domain_len =
                program.child_domain_tag_bytes;
            event.absorbed_payload.insert(
                event.absorbed_payload.end(), domain,
                domain + domain_len);
            AppendHash(event.absorbed_payload, child_fs_seed);
            AppendU64(event.absorbed_payload, batch.pow_grind_nonce);
            AppendU32(event.absorbed_payload, batch.blowup);
            AppendU32(event.absorbed_payload, batch.n_coeffs);
            AppendU32(event.absorbed_payload, batch.version);
            AppendU32(event.absorbed_payload, columns);
            if (program.child_short_transcript_commitments) {
                // Byte-for-byte what Fri3AlgBatchFsInit absorbs on this lane.
                AppendHash(
                    event.absorbed_payload,
                    Fri3AlgDigestToUint256(Fri3AlgShapeCommit(
                        batch.n_coeffs, batch.column_len)));
            } else {
                for (const uint32_t length : batch.column_len) {
                    AppendU32(event.absorbed_payload, length);
                }
            }
            AppendHash(
                event.absorbed_payload,
                Fri3AlgDigestToUint256(batch.row_commit.root));
            break;
        }
        case FiatShamirEventKind::ChallengeLambda:
            event.has_fp3_challenge = true;
            event.claimed_challenge = batch.lambda;
            break;
        case FiatShamirEventKind::AbsorbLambda:
            AppendFp3(event.absorbed_payload, batch.lambda);
            break;
        case FiatShamirEventKind::ChallengeZ1:
            // V3: the single accepted draw.  Bounded: only the selected
            // (index 0) candidate carries the accepted value; the remaining
            // reserved slots are materialized by the SHA-FS chip.
            if (program.ood_candidates == 0 || spec.index == 0) {
                event.has_fp3_challenge = true;
                event.claimed_challenge = batch.z1;
            }
            break;
        case FiatShamirEventKind::ChallengeZ2:
            if (program.ood_candidates == 0 || spec.index == 0) {
                event.has_fp3_challenge = true;
                event.claimed_challenge = batch.z2;
            }
            break;
        case FiatShamirEventKind::AbsorbZ1Z2:
            AppendFp3(event.absorbed_payload, batch.z1);
            AppendFp3(event.absorbed_payload, batch.z2);
            break;
        case FiatShamirEventKind::AbsorbOodEvaluationPair:
            AppendFp3(
                event.absorbed_payload,
                batch.evals_z1.at(spec.index));
            AppendFp3(
                event.absorbed_payload,
                batch.evals_z2.at(spec.index));
            break;
        case FiatShamirEventKind::AbsorbOodEvalCommitment:
            AppendHash(
                event.absorbed_payload,
                Fri3AlgDigestToUint256(Fri3AlgOodEvalCommit(
                    batch.z1, batch.z2, batch.evals_z1,
                    batch.evals_z2)));
            break;
        case FiatShamirEventKind::ChallengeW1:
            event.has_fp3_challenge = true;
            event.claimed_challenge = batch.w1;
            break;
        case FiatShamirEventKind::ChallengeW2:
            event.has_fp3_challenge = true;
            event.claimed_challenge = batch.w2;
            break;
        case FiatShamirEventKind::AbsorbW1W2:
            AppendFp3(event.absorbed_payload, batch.w1);
            AppendFp3(event.absorbed_payload, batch.w2);
            break;
        case FiatShamirEventKind::AbsorbFoldRoot:
            AppendHash(
                event.absorbed_payload,
                Fri3AlgDigestToUint256(
                    batch.fold_layers.at(spec.index).root));
            break;
        case FiatShamirEventKind::ChallengeFold:
            event.has_fp3_challenge = true;
            event.claimed_challenge =
                batch.fold_challenges.at(spec.index);
            break;
        case FiatShamirEventKind::ChallengeQueryIndex:
            event.has_query_index = true;
            event.claimed_query_index =
                batch.queries.at(spec.index).index;
            break;
        }
        if (event.absorbed_payload.size() != spec.absorbed_bytes) {
            out.note =
                "stage3:verifier_air:fs_event_payload_size";
            out.events.clear();
            return out;
        }
        out.events.push_back(std::move(event));
    }
    out.claims_bound_to_child_proof = true;
    // This builder materializes the exact accepted event stream, but the SHA
    // compression equations and challenge-to-output map are not in the AIR.
    out.sha256_equations_checked = false;
    out.valid = true;
    out.note = "stage3:verifier_air:fs_witness_bound_hash_air_missing";
    out.witness_commitment = CommitFiatShamirWitness(out);
    return out;
}

FiatShamirSeedOwnershipBusV1 BuildFiatShamirSeedOwnershipBusV1(
    const alg_hash::Digest& parent_binding_digest)
{
    FiatShamirSeedOwnershipBusV1 out;
    out.parent_binding_digest = parent_binding_digest;
    // Canonical AlgHash-digest -> SHA-preimage-byte boundary (the sole seam
    // defined by the recursion spec): seed[8k,8k+8) = LE64(Canonical(limb_k)).
    out.owned_seed = Fri3AlgDigestToUint256(parent_binding_digest);
    // Soundness of the packing: it must round-trip.  Fri3AlgDigestFromUint256
    // rejects any limb >= p, so a genuine binding digest (canonical Fp limbs)
    // recovers exactly; anything else fails and the bus refuses to bind.
    const std::optional<Fri3AlgDigest> back =
        Fri3AlgDigestFromUint256(out.owned_seed);
    out.canonical_roundtrip =
        back.has_value() && back.value() == parent_binding_digest;
    for (uint32_t byte = 0; byte < 32; ++byte) {
        out.byte_origins[byte] = FiatShamirShaByteOriginV1{
            FiatShamirShaByteOriginKindV1::ParentBindingDigest, byte};
    }
    out.valid = out.canonical_roundtrip;
    // Tamper-detectable commitment over the owned seed image (which encodes the
    // digest bijectively) under a distinct domain tag.
    std::vector<unsigned char> buf;
    static constexpr char kTag[] =
        "BTX_RC_FS_SEED_OWNERSHIP_BUS_V1";
    buf.insert(buf.end(),
               reinterpret_cast<const unsigned char*>(kTag),
               reinterpret_cast<const unsigned char*>(kTag) +
                   sizeof(kTag) - 1);
    AppendHash(buf, out.owned_seed);
    out.commitment = Sha256dBytes(buf.data(), buf.size());
    out.note = out.valid
                   ? "stage3:verifier_air:fs_seed_ownership_bus:ok"
                   : "stage3:verifier_air:fs_seed_ownership_bus:"
                     "noncanonical_binding_digest";
    return out;
}

uint32_t FiatShamirSeedBusViolations(
    const FiatShamirSeedOwnershipBusV1& bus, const uint256& seed)
{
    if (!bus.valid) return 32;
    uint32_t diff = 0;
    for (uint32_t byte = 0; byte < 32; ++byte) {
        if (seed.data()[byte] != bus.owned_seed.data()[byte]) {
            ++diff;
        }
    }
    return diff;
}

FiatShamirAirBackedWitnessV1 BuildFiatShamirAirBackedWitnessV1(
    const std::vector<FiatShamirChallengeReconstructionInputV1>&
        inputs)
{
    namespace fss = stage3_fs_selection_air;
    FiatShamirAirBackedWitnessV1 out;
    // The eight distinct FS challenge kinds in the canonical program.
    out.total_challenge_types = 8;
    std::set<uint8_t> covered_kinds;
    bool all_ok = !inputs.empty();
    for (const auto& in : inputs) {
        Fp3 value{};
        bool constrained = false;
        // Each challenge kind reconstructs IN-AIR from its SHA-derived digest
        // via its decoder (decoder `.valid` <=> zero constraint violations);
        // the value is not read from the proof batch.
        switch (in.kind) {
        case FiatShamirEventKind::ChallengeZ1:
        case FiatShamirEventKind::ChallengeZ2: {
            // MultiRow-V2 uniform path when ood_words are supplied (synthetic
            // 8-word tests). SHA-FS ChallengeFp3 canary leaves ood_words zero
            // and feeds the selected digest's 24 bytes through DirectChallenge.
            const bool has_ood_words = std::any_of(
                in.ood_words.begin(), in.ood_words.end(),
                [](uint64_t w) { return w != 0; });
            if (has_ood_words) {
                const fss::WitnessV1 sel =
                    fss::BuildWitnessV1(in.ood_words);
                constrained = sel.valid;
                value = sel.selected_value;
            } else {
                const fss::DirectChallengeWitnessV1 d =
                    fss::BuildDirectChallengeWitnessV1(
                        in.direct_bytes);
                constrained = d.valid;
                value = d.value;
            }
            break;
        }
        case FiatShamirEventKind::ChallengeQueryIndex: {
            const fss::QueryIndexWitnessV1 q =
                fss::BuildQueryIndexWitnessV1(
                    in.query_bytes, in.query_modulus);
            constrained = q.valid;
            value = Fp3::FromFp(gf::FromU64(q.query_index));
            break;
        }
        case FiatShamirEventKind::ChallengeAirQuotientLambda:
        case FiatShamirEventKind::ChallengeLambda:
        case FiatShamirEventKind::ChallengeW1:
        case FiatShamirEventKind::ChallengeW2:
        case FiatShamirEventKind::ChallengeFold: {
            const fss::DirectChallengeWitnessV1 d =
                fss::BuildDirectChallengeWitnessV1(
                    in.direct_bytes);
            constrained = d.valid;
            value = d.value;
            break;
        }
        default:
            constrained = false;
            break;
        }
        if (!constrained) {
            all_ok = false;
            out.note =
                "stage3:verifier_air:fs_air_backed:"
                "reconstruction_unconstrained";
            break;
        }
        out.reconstructed_kinds.push_back(in.kind);
        out.reconstructed_values.push_back(value);
        covered_kinds.insert(static_cast<uint8_t>(in.kind));
    }
    out.reconstructed_challenge_types =
        static_cast<uint32_t>(covered_kinds.size());
    out.all_covered_reconstructions_constrained = all_ok;
    // Every distinct challenge kind reconstructed in-AIR here.
    out.covers_all_challenge_types =
        all_ok &&
        out.reconstructed_challenge_types >= out.total_challenge_types;
    out.challenge_decoders_checked =
        out.covers_all_challenge_types;
    // These rows constrain only digest-to-challenge decoding. They do not own
    // the upstream SHA/Poseidon permutation output cells.
    out.sha256_equations_checked = false;
    out.valid = all_ok;
    if (out.note.empty()) {
        out.note =
            out.valid
                ? (out.covers_all_challenge_types
                       ? "stage3:verifier_air:fs_air_backed:"
                         "all_challenges_reconstructed_in_air"
                       : "stage3:verifier_air:fs_air_backed:"
                         "subset_reconstructed_in_air")
                : "stage3:verifier_air:fs_air_backed:empty";
    }
    return out;
}

FiatShamirReplayResult ReplayFiatShamirWitness(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof,
    const FiatShamirWitness& witness)
{
    FiatShamirReplayResult out;
    out.absorbed_bytes = program.absorbed_bytes;
    out.minimum_sha256_compression_blocks =
        program.minimum_sha256_compression_blocks;
    out.streaming_sha256_compression_blocks =
        program.streaming_sha256_compression_blocks;
    out.event_count = static_cast<uint32_t>(program.events.size());
    out.rejection_loop_bounded = program.rejection_loop_bounded;

    std::string why;
    out.canonical_program =
        ValidateCanonicalFiatShamirProgram(program, &why);
    if (!out.canonical_program) {
        out.note = why;
        return out;
    }

    const FiatShamirWitness expected =
        BuildFiatShamirWitness(program, child_fs_seed, child_proof);
    out.witness_matches_proof =
        expected.valid && witness.valid &&
        witness.program_commitment == expected.program_commitment &&
        witness.witness_commitment == expected.witness_commitment &&
        witness.events == expected.events;
    if (!out.witness_matches_proof) {
        out.note = "stage3:verifier_air:fs_witness_mismatch";
        return out;
    }

    const auto air_event = std::find_if(
        witness.events.begin(), witness.events.end(),
        [](const FiatShamirEventWitness& event) {
            return event.event_index == 0 &&
                   event.has_fp3_challenge;
        });
    if (air_event != witness.events.end()) {
        const uint256 digest =
            aq::AirChallengeDigestForBackend<
                aq::AirFriBackendAlg<Fp3>>(
            child_fs_seed, "airq_lambda",
            {child_proof.trace_commit},
            {program.child_shape.child_n_rows,
             child_proof.batch.column_len.back(),
             program.child_shape.child_w});
        out.air_quotient_challenge_replayed =
            gf::Eq(air_event->claimed_challenge,
                   gf::FromChallengeBytes3(digest.data()));
    }
    if (!out.air_quotient_challenge_replayed) {
        out.note =
            "stage3:verifier_air:air_quotient_challenge_mismatch";
        return out;
    }

    // This is the authoritative verifier's commit-then-challenge replay.  It
    // independently derives lambda, both OOD points, both DEEP weights, every
    // fold challenge and every query index before checking the proof.
    std::string fri_why;
    out.fri_transcript_replayed =
        program.canary_only
            ? Fri3AlgShaFsBoundedOodCanaryBatchVerify(
                  child_proof.batch, child_fs_seed, &fri_why)
            : Fri3AlgP2SqueezeBatchVerify(
                  child_proof.batch, child_fs_seed, &fri_why);
    if (!out.fri_transcript_replayed) {
        out.note =
            "stage3:verifier_air:fri_replay:" + fri_why;
        return out;
    }

    out.complete_for_recursive_air =
        out.rejection_loop_bounded &&
        kVerifierFiatShamirAirExecutable;
    out.note = out.complete_for_recursive_air
                   ? "stage3:verifier_air:fs_replay_complete"
                   : "stage3:verifier_air:fs_native_replay_ok_air_open";
    return out;
}

FiatShamirShaExecutionPlanV1
BuildFiatShamirShaExecutionPlanV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    FiatShamirShaExecutionPlanV1 out;
    std::string why;
    if (!ValidateCanonicalFiatShamirProgram(
            program, &why)) {
        out.note = why;
        return out;
    }
    if (!program.canary_only ||
        !program.child_sha256d_challenges) {
        out.note =
            "stage3:verifier_air:"
            "fs_sha_plan_not_sha_canary_protocol";
        return out;
    }
    const FiatShamirWitness witness =
        BuildFiatShamirWitness(
            program, child_fs_seed,
            child_proof);
    if (!witness.valid ||
        witness.events.size() !=
            program.events.size()) {
        out.note =
            "stage3:verifier_air:"
            "fs_sha_witness:" +
            witness.note;
        return out;
    }

    std::vector<unsigned char> batch_codec;
    if (SerializeFri3AlgBatchProof(
            child_proof.batch,
            batch_codec) != batch_codec.size() ||
        batch_codec.empty()) {
        out.note =
            "stage3:verifier_air:"
            "fs_sha_batch_codec";
        return out;
    }
    const uint32_t width =
        static_cast<uint32_t>(
            child_proof.batch.column_len.size());
    const uint64_t lambda_offset64 =
        uint64_t{64} + uint64_t{4} * width;
    const uint64_t z1_offset64 =
        lambda_offset64 + 24;
    const uint64_t z2_offset64 =
        z1_offset64 + 24;
    const uint64_t eval1_base64 =
        z2_offset64 + 28;
    const uint64_t eval2_base64 =
        eval1_base64 +
        uint64_t{24} * width + 4;
    const uint64_t w1_offset64 =
        eval2_base64 +
        uint64_t{24} * width;
    const uint64_t w2_offset64 =
        w1_offset64 + 24;
    const uint64_t fold_root_base64 =
        w2_offset64 + 28;
    const uint64_t fold_end64 =
        fold_root_base64 +
        uint64_t{36} *
            child_proof.batch
                .fold_layers.size();
    if (fold_end64 > batch_codec.size() ||
        fold_end64 >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:verifier_air:"
            "fs_sha_codec_offsets";
        return out;
    }
    const uint32_t lambda_offset =
        static_cast<uint32_t>(
            lambda_offset64);
    const uint32_t z1_offset =
        static_cast<uint32_t>(z1_offset64);
    const uint32_t z2_offset =
        static_cast<uint32_t>(z2_offset64);
    const uint32_t eval1_base =
        static_cast<uint32_t>(
            eval1_base64);
    const uint32_t eval2_base =
        static_cast<uint32_t>(
            eval2_base64);
    const uint32_t w1_offset =
        static_cast<uint32_t>(w1_offset64);
    const uint32_t w2_offset =
        static_cast<uint32_t>(w2_offset64);
    const uint32_t fold_root_base =
        static_cast<uint32_t>(
            fold_root_base64);
    using Origin =
        FiatShamirShaByteOriginV1;
    using OriginKind =
        FiatShamirShaByteOriginKindV1;
    const auto constant_origins =
        [](size_t size) {
            return std::vector<Origin>(
                size,
                Origin{
                    OriginKind::Constant, 0});
        };
    const auto public_seed_origins =
        [](uint32_t size) {
            std::vector<Origin> origins;
            origins.reserve(size);
            for (uint32_t byte = 0;
                 byte < size; ++byte) {
                origins.push_back({
                    OriginKind::PublicSeed,
                    byte});
            }
            return origins;
        };
    const auto batch_origins =
        [](uint32_t offset, uint32_t size) {
            std::vector<Origin> origins;
            origins.reserve(size);
            for (uint32_t byte = 0;
                 byte < size; ++byte) {
                origins.push_back({
                    OriginKind::BatchCodec,
                    offset + byte});
            }
            return origins;
        };
    // PR-89 g4 ACTIVATION.  A run of bytes that is a Poseidon2 commitment lane
    // rather than a verbatim proof byte.  Kept as its own kind so a consumer
    // can tell the SHA chip cannot discharge it.
    const auto algebraic_origins =
        [](OriginKind kind, uint32_t size) {
            std::vector<Origin> origins;
            origins.reserve(size);
            for (uint32_t byte = 0;
                 byte < size; ++byte) {
                origins.push_back({kind, byte});
            }
            return origins;
        };
    const auto append_origins =
        [](std::vector<Origin>& target,
           const std::vector<Origin>& source) {
            target.insert(
                target.end(),
                source.begin(), source.end());
        };

    std::vector<unsigned char> transcript;
    std::vector<Origin> transcript_origins;
    uint32_t z_counter = 0;
    Fp3 selected_z1{};
    bool have_z1 = false;
    constexpr uint32_t kMaxLegacyZReplayAttempts =
        1024;
    const auto append_call =
        [&](uint32_t event_index,
            uint32_t draw_index,
            std::vector<unsigned char> preimage,
            std::vector<Origin> origins,
            bool semantic_match) {
            FiatShamirShaCallV1 call;
            call.event_index = event_index;
            call.draw_index = draw_index;
            call.preimage = std::move(preimage);
            call.byte_origins =
                std::move(origins);
            call.digest = Sha256dBytes(
                call.preimage.data(),
                call.preimage.size());
            call.output_matches_claim =
                semantic_match;
            out.call.push_back(std::move(call));
        };
    const auto challenge_preimage =
        [&transcript, &transcript_origins,
         &constant_origins](
            const char* label,
            uint32_t index) {
            std::pair<
                std::vector<unsigned char>,
                std::vector<Origin>> result{
                    transcript,
                    transcript_origins};
            auto& preimage = result.first;
            preimage.insert(
                preimage.end(),
                reinterpret_cast<
                    const unsigned char*>(label),
                reinterpret_cast<
                    const unsigned char*>(label) +
                    std::strlen(label));
            AppendU32(preimage, index);
            const auto suffix_origins =
                constant_origins(
                    std::strlen(label) + 4);
            result.second.insert(
                result.second.end(),
                suffix_origins.begin(),
                suffix_origins.end());
            return result;
        };

    for (uint32_t event_index = 0;
         event_index < program.events.size();
         ++event_index) {
        const FiatShamirEventSpec& spec =
            program.events[event_index];
        const FiatShamirEventWitness& event =
            witness.events[event_index];
        if (!event.absorbed_payload.empty()) {
            std::vector<Origin> origins;
            switch (spec.kind) {
            case FiatShamirEventKind::
                    AbsorbPreamble:
                append_origins(
                    origins,
                    constant_origins(
                        program.child_domain_tag_bytes));
                append_origins(
                    origins,
                    public_seed_origins(32));
                append_origins(
                    origins,
                    batch_origins(8, 8));
                append_origins(
                    origins,
                    batch_origins(16, 4));
                append_origins(
                    origins,
                    batch_origins(20, 4));
                append_origins(
                    origins,
                    batch_origins(4, 4));
                append_origins(
                    origins,
                    batch_origins(60, 4));
                if (program.child_short_transcript_commitments) {
                    // PR-89 g4 ACTIVATION.  These 32 bytes are NOT bytes the
                    // child shipped -- they are Poseidon2 lanes over the
                    // column_len region.  Claiming batch_origins(64, 4*width)
                    // here would assert a provenance the SHA plan cannot
                    // discharge, so they get their own kind and the plan
                    // reports them as un-owned by the SHA chip.
                    append_origins(
                        origins,
                        algebraic_origins(
                            FiatShamirShaByteOriginKindV1::
                                AlgebraicShapeCommitment,
                            32));
                } else {
                    append_origins(
                        origins,
                        batch_origins(
                            64, 4 * width));
                }
                append_origins(
                    origins,
                    batch_origins(24, 32));
                break;
            case FiatShamirEventKind::
                    AbsorbLambda:
                append_origins(
                    origins,
                    batch_origins(
                        lambda_offset, 24));
                break;
            case FiatShamirEventKind::
                    AbsorbZ1Z2:
                append_origins(
                    origins,
                    batch_origins(
                        z1_offset, 24));
                append_origins(
                    origins,
                    batch_origins(
                        z2_offset, 24));
                break;
            case FiatShamirEventKind::
                    AbsorbOodEvaluationPair:
                append_origins(
                    origins,
                    batch_origins(
                        eval1_base +
                            24 * spec.index,
                        24));
                append_origins(
                    origins,
                    batch_origins(
                        eval2_base +
                            24 * spec.index,
                        24));
                break;
            case FiatShamirEventKind::
                    AbsorbOodEvalCommitment:
                append_origins(
                    origins,
                    algebraic_origins(
                        FiatShamirShaByteOriginKindV1::
                            AlgebraicOodEvalCommitment,
                        32));
                break;
            case FiatShamirEventKind::
                    AbsorbW1W2:
                append_origins(
                    origins,
                    batch_origins(
                        w1_offset, 24));
                append_origins(
                    origins,
                    batch_origins(
                        w2_offset, 24));
                break;
            case FiatShamirEventKind::
                    AbsorbFoldRoot:
                append_origins(
                    origins,
                    batch_origins(
                        fold_root_base +
                            36 * spec.index,
                        32));
                break;
            default:
                out.note =
                    "stage3:verifier_air:"
                    "fs_sha_absorb_origin_kind";
                return out;
            }
            if (origins.size() !=
                event.absorbed_payload.size()) {
                out.note =
                    "stage3:verifier_air:"
                    "fs_sha_absorb_origin_size";
                return out;
            }
            transcript.insert(
                transcript.end(),
                event.absorbed_payload.begin(),
                event.absorbed_payload.end());
            transcript_origins.insert(
                transcript_origins.end(),
                origins.begin(), origins.end());
            continue;
        }
        if (!IsChallengeEvent(spec.kind)) {
            continue;
        }

        if (spec.kind ==
                FiatShamirEventKind::
                    ChallengeAirQuotientLambda) {
            // Row-wise AIR quotient challenges are on the live Poseidon2
            // route, even when the inner FRI batch is the SHA-only v9
            // canary. Keep this out of the SHA manifest and verify it with
            // the same backend selector used by AirQuotientProve/Verify.
            const uint256 digest =
                aq::AirChallengeDigestForBackend<
                    aq::AirFriBackendAlg<Fp3>>(
                    child_fs_seed, "airq_lambda",
                    {child_proof.trace_commit},
                    {program.child_shape.child_n_rows,
                     child_proof.batch.column_len.back(),
                     program.child_shape.child_w});
            out.non_sha_challenge_calls += 1;
            out.non_sha_challenges_match_claims =
                event.has_fp3_challenge &&
                gf::Eq(
                    event.claimed_challenge,
                    gf::FromChallengeBytes3(digest.data()));
            continue;
        }

        if (spec.kind ==
                FiatShamirEventKind::ChallengeZ1 ||
            spec.kind ==
                FiatShamirEventKind::ChallengeZ2) {
            const bool is_z1 =
                spec.kind ==
                FiatShamirEventKind::ChallengeZ1;
            const Fp3 claimed =
                is_z1 ? child_proof.batch.z1
                      : child_proof.batch.z2;
            if (program.ood_candidates > 0) {
                // Bounded fixed schedule: one SHA draw per reserved candidate
                // slot. Emit the whole K-candidate window on the first event
                // of each OOD kind; later reserved-index events are no-ops.
                if (spec.index != 0) {
                    continue;
                }
                std::vector<Fp3> candidates;
                candidates.reserve(
                    program.ood_candidates);
                struct PendingCall {
                    uint32_t draw{0};
                    std::vector<unsigned char> preimage;
                    std::vector<Origin> origins;
                };
                std::vector<PendingCall> pending;
                pending.reserve(
                    program.ood_candidates);
                for (uint32_t k = 0;
                     k < program.ood_candidates;
                     ++k) {
                    const uint32_t draw = z_counter++;
                    auto preimage_and_origins =
                        challenge_preimage(
                            "fra3_z", draw);
                    const uint256 digest =
                        Sha256dBytes(
                            preimage_and_origins
                                .first.data(),
                            preimage_and_origins
                                .first.size());
                    candidates.push_back(
                        gf::FromChallengeBytes3(
                            digest.data()));
                    pending.push_back({
                        draw,
                        std::move(
                            preimage_and_origins
                                .first),
                        std::move(
                            preimage_and_origins
                                .second)});
                }
                const Fp3* distinct_from =
                    have_z1 ? &selected_z1 : nullptr;
                const uint32_t selected_idx =
                    SelectFirstAcceptableOodIndex(
                        candidates, distinct_from);
                if (selected_idx >=
                    program.ood_candidates) {
                    out.note =
                        "stage3:verifier_air:"
                        "fs_sha_bounded_z_exhausted";
                    return out;
                }
                if (!gf::Eq(
                        candidates[selected_idx],
                        claimed)) {
                    out.note =
                        "stage3:verifier_air:"
                        "fs_sha_bounded_z_mismatch";
                    return out;
                }
                for (uint32_t k = 0;
                     k < program.ood_candidates;
                     ++k) {
                    // Selected draw already Eq-checked against the claim;
                    // rejected / post-selected reserved slots are honest
                    // no-ops under the fixed selector.
                    append_call(
                        event_index,
                        pending[k].draw,
                        std::move(
                            pending[k].preimage),
                        std::move(
                            pending[k].origins),
                        true);
                }
                if (is_z1) {
                    selected_z1 =
                        candidates[selected_idx];
                    have_z1 = true;
                }
                continue;
            }
            // Legacy V3: unbounded while(true) rejection sampler.
            bool selected = false;
            for (uint32_t attempt = 0;
                 attempt <
                     kMaxLegacyZReplayAttempts;
                 ++attempt) {
                const uint32_t draw = z_counter++;
                auto preimage_and_origins =
                    challenge_preimage(
                        "fra3_z", draw);
                const uint256 digest =
                    Sha256dBytes(
                        preimage_and_origins
                            .first.data(),
                        preimage_and_origins
                            .first.size());
                const Fp3 candidate =
                    gf::FromChallengeBytes3(
                        digest.data());
                const bool has_extension =
                    gf::Canonical(candidate.c1) != 0 ||
                    gf::Canonical(candidate.c2) != 0;
                const bool distinct =
                    !have_z1 ||
                    !gf::Eq(candidate, selected_z1);
                const bool accepted =
                    has_extension && distinct;
                const bool semantic_match =
                    accepted
                    ? event.has_fp3_challenge &&
                          gf::Eq(
                              candidate,
                              event.claimed_challenge)
                    : true;
                append_call(
                    event_index, draw,
                    std::move(
                        preimage_and_origins
                            .first),
                    std::move(
                        preimage_and_origins
                            .second),
                    semantic_match);
                if (!accepted) continue;
                selected = semantic_match;
                if (is_z1) {
                    selected_z1 = candidate;
                    have_z1 = true;
                }
                break;
            }
            if (!selected) {
                out.note =
                    "stage3:verifier_air:"
                    "fs_sha_legacy_z";
                return out;
            }
            continue;
        }

        const char* label =
            ChallengeLabel(spec.kind);
        auto preimage_and_origins =
            challenge_preimage(
                label, spec.index);
        const uint256 digest =
            Sha256dBytes(
                preimage_and_origins
                    .first.data(),
                preimage_and_origins
                    .first.size());
        bool semantic_match = false;
        if (event.has_fp3_challenge) {
            semantic_match =
                gf::Eq(
                    event.claimed_challenge,
                    gf::FromChallengeBytes3(
                        digest.data()));
        } else if (event.has_query_index) {
            const Fp3 challenge =
                gf::FromChallengeBytes3(
                    digest.data());
            const unsigned __int128 wide =
                (static_cast<
                     unsigned __int128>(
                     gf::Canonical(
                         challenge.c1))
                 << 64) |
                gf::Canonical(challenge.c0);
            semantic_match =
                program.child_shape.child_n_lde != 0 &&
                event.claimed_query_index ==
                    static_cast<uint32_t>(
                        wide %
                        program.child_shape
                            .child_n_lde);
        }
        append_call(
            event_index, spec.index,
            std::move(
                preimage_and_origins.first),
            std::move(
                preimage_and_origins.second),
            semantic_match);
    }

    out.exact_domain_tags_and_order =
        program.canary_only &&
        program.child_sha256d_challenges &&
        program.child_domain_tag ==
            kRCFri3AlgShaFsCanaryDomainTag;
    out.every_digest_matches_claim =
        !out.call.empty() &&
        out.non_sha_challenge_calls == 1 &&
        out.non_sha_challenges_match_claims &&
        std::all_of(
            out.call.begin(), out.call.end(),
            [](const auto& call) {
                return call.output_matches_claim;
            });
    out.manifest.reserve(out.call.size());
    for (const auto& call : out.call) {
        stage3_hash_air::ShaManifest manifest;
        if (!stage3_hash_air::BuildShaManifest(
                call.preimage,
                stage3_hash_air::ShaMode::Double,
                manifest, &why) ||
            !std::equal(
                manifest.digest.begin(),
                manifest.digest.end(),
                call.digest.begin())) {
            out.note =
                "stage3:verifier_air:"
                "fs_sha_manifest:" + why;
            return out;
        }
        std::vector<
            stage3_hash_air::
                FixedProgramBoundaryInstance>
            boundaries;
        if (!stage3_hash_air::
                BuildShaManifestBoundaryInstances(
                    manifest,
                    boundaries, &why)) {
            out.note =
                "stage3:verifier_air:"
                "fs_sha_boundaries:" + why;
            return out;
        }
        out.compression_instances +=
            boundaries.size();
        out.boundaries.insert(
            out.boundaries.end(),
            std::make_move_iterator(
                boundaries.begin()),
            std::make_move_iterator(
                boundaries.end()));
        out.manifest.push_back(
            std::move(manifest));
    }
    out.calls =
        static_cast<uint32_t>(
            out.call.size());
    out.exact_sha256d_padding_and_chaining =
        out.manifest.size() ==
            out.call.size() &&
        !out.boundaries.empty();
    // fixed_schedule is the recursive-AIR claim: a statically laid K-candidate
    // OOD window whose all-rejected failure is proven <= 2^-target_bits.
    // Legacy V3 (ood_candidates==0) is never a fixed schedule. K=1 is a fixed
    // WIDTH but does not clear the 128-bit target, so it stays false.
    out.fixed_schedule =
        program.ood_candidates > 0 &&
        program.rejection_loop_bounded;
    out.proof_codec_byte_origins_complete =
        std::all_of(
            out.call.begin(), out.call.end(),
            [&batch_codec](
                const FiatShamirShaCallV1& call) {
                if (call.preimage.size() !=
                    call.byte_origins.size()) {
                    return false;
                }
                return std::all_of(
                    call.byte_origins.begin(),
                    call.byte_origins.end(),
                    [&batch_codec](
                        const auto& origin) {
                        switch (origin.kind) {
                        case
                            FiatShamirShaByteOriginKindV1::
                                Constant:
                            return true;
                        case
                            FiatShamirShaByteOriginKindV1::
                                PublicSeed:
                        case
                            FiatShamirShaByteOriginKindV1::
                                SupplementalTraceCommit:
                        case
                            FiatShamirShaByteOriginKindV1::
                                ParentBindingDigest:
                            return origin.byte_offset < 32;
                        case
                            FiatShamirShaByteOriginKindV1::
                                BatchCodec:
                            return origin.byte_offset <
                                batch_codec.size();
                        case
                            FiatShamirShaByteOriginKindV1::
                                AlgebraicShapeCommitment:
                        case
                            FiatShamirShaByteOriginKindV1::
                                AlgebraicOodEvalCommitment:
                            // Poseidon2 commitment lanes: size-checked at
                            // construction; SHA chip cannot own them.
                            return origin.byte_offset < 32;
                        }
                        return false;
                    });
            });
    out.recursively_consumed = false;
    const bool schedule_consistent =
        out.fixed_schedule ==
        (program.ood_candidates > 0 &&
         program.rejection_loop_bounded);
    out.valid =
        out.exact_domain_tags_and_order &&
        out.every_digest_matches_claim &&
        out.exact_sha256d_padding_and_chaining &&
        schedule_consistent &&
        out.proof_codec_byte_origins_complete &&
        !out.recursively_consumed;
    if (out.valid) {
        out.note =
            out.fixed_schedule
                ? "stage3:verifier_air:"
                  "bounded_fs_exact_hybrid_execution;"
                  "fixed_ood_schedule;"
                  "codec_origins_complete;"
                  "sha_air_and_recursive_consumption_open"
                : "stage3:verifier_air:"
                  "legacy_fs_exact_sha_execution;"
                  "codec_origins_complete;"
                  "unbounded_z_and_recursive_consumption_open";
    } else {
        const auto mismatch = std::find_if(
            out.call.begin(), out.call.end(),
            [](const FiatShamirShaCallV1& call) {
                return !call.output_matches_claim;
            });
        out.note =
            "stage3:verifier_air:"
            "fs_sha_execution_invalid";
        if (mismatch != out.call.end()) {
            out.note +=
                ":first_claim_mismatch_event=" +
                std::to_string(mismatch->event_index) +
                ":draw=" +
                std::to_string(mismatch->draw_index);
        }
    }
    return out;
}

bool AlignAlgAirProofOodToBoundedShaScheduleV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    AlgAirProof& child_proof,
    std::string* why)
{
    if (program.ood_candidates == 0 ||
        !program.valid) {
        if (why != nullptr) {
            *why =
                "stage3:verifier_air:"
                "align_ood_requires_bounded_program";
        }
        return false;
    }
    const FiatShamirWitness witness =
        BuildFiatShamirWitness(
            program, child_fs_seed, child_proof);
    if (!witness.valid ||
        witness.events.size() !=
            program.events.size()) {
        if (why != nullptr) {
            *why =
                "stage3:verifier_air:align_ood_witness";
        }
        return false;
    }
    std::vector<unsigned char> transcript;
    uint32_t z_counter = 0;
    Fp3 selected_z1{};
    Fp3 selected_z2{};
    bool have_z1 = false;
    bool have_z2 = false;
    const auto challenge_digest =
        [&transcript](
            const char* label, uint32_t index) {
            std::vector<unsigned char> preimage =
                transcript;
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const unsigned char*>(
                    label),
                reinterpret_cast<const unsigned char*>(
                    label) +
                    std::strlen(label));
            AppendU32(preimage, index);
            return Sha256dBytes(
                preimage.data(), preimage.size());
        };
    for (uint32_t event_index = 0;
         event_index < program.events.size();
         ++event_index) {
        const auto& spec = program.events[event_index];
        const auto& event = witness.events[event_index];
        if (spec.kind ==
            FiatShamirEventKind::AbsorbZ1Z2) {
            if (!have_z1 || !have_z2) {
                if (why != nullptr) {
                    *why =
                        "stage3:verifier_air:"
                        "align_ood_absorb_before_select";
                }
                return false;
            }
            AppendFp3(transcript, selected_z1);
            AppendFp3(transcript, selected_z2);
            continue;
        }
        if (!event.absorbed_payload.empty()) {
            if (spec.kind ==
                FiatShamirEventKind::AbsorbLambda) {
                // Prefer the SHA-aligned lambda when ChallengeLambda already
                // rewrote batch.lambda; fall back to the witness payload.
                AppendFp3(transcript, child_proof.batch.lambda);
                continue;
            }
            transcript.insert(
                transcript.end(),
                event.absorbed_payload.begin(),
                event.absorbed_payload.end());
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeLambda) {
            child_proof.batch.lambda =
                gf::FromChallengeBytes3(
                    challenge_digest("fra3_lambda", 0)
                        .data());
            continue;
        }
        if (spec.kind ==
                FiatShamirEventKind::ChallengeZ1 ||
            spec.kind ==
                FiatShamirEventKind::ChallengeZ2) {
            if (spec.index != 0) continue;
            std::vector<Fp3> candidates;
            candidates.reserve(program.ood_candidates);
            for (uint32_t k = 0;
                 k < program.ood_candidates; ++k) {
                const uint32_t draw = z_counter++;
                const uint256 digest =
                    challenge_digest("fra3_z", draw);
                candidates.push_back(
                    gf::FromChallengeBytes3(
                        digest.data()));
            }
            const Fp3* distinct =
                have_z1 ? &selected_z1 : nullptr;
            const uint32_t selected =
                SelectFirstAcceptableOodIndex(
                    candidates, distinct);
            if (selected >= program.ood_candidates) {
                if (why != nullptr) {
                    *why =
                        "stage3:verifier_air:"
                        "align_ood_exhausted";
                }
                return false;
            }
            if (spec.kind ==
                FiatShamirEventKind::ChallengeZ1) {
                selected_z1 = candidates[selected];
                have_z1 = true;
            } else {
                selected_z2 = candidates[selected];
                have_z2 = true;
            }
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeW1) {
            child_proof.batch.w1 =
                gf::FromChallengeBytes3(
                    challenge_digest("fra3_w", 0)
                        .data());
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeW2) {
            child_proof.batch.w2 =
                gf::FromChallengeBytes3(
                    challenge_digest("fra3_w", 1)
                        .data());
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeFold) {
            if (spec.index >=
                child_proof.batch.fold_challenges
                    .size()) {
                if (why != nullptr) {
                    *why =
                        "stage3:verifier_air:"
                        "align_ood_fold_index";
                }
                return false;
            }
            child_proof.batch.fold_challenges[spec.index] =
                gf::FromChallengeBytes3(
                    challenge_digest(
                        "fra3_fold", spec.index)
                        .data());
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeQueryIndex) {
            if (spec.index >=
                child_proof.batch.queries.size()) {
                if (why != nullptr) {
                    *why =
                        "stage3:verifier_air:"
                        "align_ood_query_index";
                }
                return false;
            }
            const Fp3 challenge =
                gf::FromChallengeBytes3(
                    challenge_digest(
                        "fra3_query", spec.index)
                        .data());
            const unsigned __int128 wide =
                (static_cast<unsigned __int128>(
                     gf::Canonical(challenge.c1))
                 << 64) |
                gf::Canonical(challenge.c0);
            if (program.child_shape.child_n_lde == 0) {
                if (why != nullptr) {
                    *why =
                        "stage3:verifier_air:"
                        "align_ood_query_lde";
                }
                return false;
            }
            child_proof.batch.queries[spec.index].index =
                static_cast<uint32_t>(
                    wide %
                    program.child_shape.child_n_lde);
            continue;
        }
    }
    if (!have_z1 || !have_z2) {
        if (why != nullptr) {
            *why =
                "stage3:verifier_air:align_ood_incomplete";
        }
        return false;
    }
    child_proof.batch.z1 = selected_z1;
    child_proof.batch.z2 = selected_z2;
    return true;
}

FiatShamirChallengeSelectionAirJoinV1
MeasureFiatShamirChallengeSelectionAirJoinV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    namespace fss = stage3_fs_selection_air;
    FiatShamirChallengeSelectionAirJoinV1 out;
    const FiatShamirShaExecutionPlanV1 plan =
        BuildFiatShamirShaExecutionPlanV1(
            program, child_fs_seed, child_proof);
    out.digest_plan_ready =
        plan.valid && plan.every_digest_matches_claim;
    if (!out.digest_plan_ready) {
        out.note =
            "stage3:verifier_air:fs_selection_join:"
            "digest_plan_open:" +
            plan.note;
        return out;
    }
    const FiatShamirWitness witness =
        BuildFiatShamirWitness(
            program, child_fs_seed, child_proof);
    if (!witness.valid ||
        witness.events.size() != program.events.size()) {
        out.note =
            "stage3:verifier_air:fs_selection_join:witness";
        return out;
    }

    std::vector<fss::ChallengeTableRowV1> rows;
    std::vector<unsigned char> transcript;
    uint32_t z_counter = 0;
    Fp3 selected_z1{};
    bool have_z1 = false;
    const auto challenge_digest =
        [&transcript](const char* label, uint32_t index) {
            std::vector<unsigned char> preimage = transcript;
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const unsigned char*>(label),
                reinterpret_cast<const unsigned char*>(label) +
                    std::strlen(label));
            AppendU32(preimage, index);
            return Sha256dBytes(preimage.data(), preimage.size());
        };
    const auto push_fp3_row =
        [&rows](const uint256& digest, const Fp3& consumed,
                uint32_t kind_tag) {
            fss::ChallengeTableRowV1 row;
            for (uint32_t i = 0; i < 24; ++i) {
                row.digest_bytes[i] = digest.data()[i];
            }
            row.consumed = consumed;
            row.kind = kind_tag;
            rows.push_back(row);
        };

    for (uint32_t event_index = 0;
         event_index < program.events.size();
         ++event_index) {
        const FiatShamirEventSpec& spec =
            program.events[event_index];
        const FiatShamirEventWitness& event =
            witness.events[event_index];
        if (spec.kind ==
            FiatShamirEventKind::ChallengeAirQuotientLambda) {
            const uint256 digest =
                aq::AirChallengeDigestForBackend<
                    aq::AirFriBackendAlg<Fp3>>(
                child_fs_seed, "airq_lambda",
                {child_proof.trace_commit},
                {program.child_shape.child_n_rows,
                 child_proof.batch.column_len.back(),
                 program.child_shape.child_w});
            const Fp3 decoded =
                gf::FromChallengeBytes3(digest.data());
            if (!event.has_fp3_challenge ||
                !gf::Eq(decoded, event.claimed_challenge)) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "airq_mismatch";
                return out;
            }
            push_fp3_row(
                digest, decoded,
                static_cast<uint32_t>(spec.kind));
            continue;
        }
        if (spec.kind == FiatShamirEventKind::AbsorbZ1Z2) {
            if (!have_z1) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "absorb_z_before_select";
                return out;
            }
            AppendFp3(transcript, child_proof.batch.z1);
            AppendFp3(transcript, child_proof.batch.z2);
            continue;
        }
        if (!event.absorbed_payload.empty()) {
            transcript.insert(
                transcript.end(),
                event.absorbed_payload.begin(),
                event.absorbed_payload.end());
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeLambda) {
            const uint256 digest =
                challenge_digest("fra3_lambda", 0);
            const Fp3 decoded =
                gf::FromChallengeBytes3(digest.data());
            if (!gf::Eq(decoded, child_proof.batch.lambda)) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "lambda_mismatch";
                return out;
            }
            push_fp3_row(
                digest, child_proof.batch.lambda,
                static_cast<uint32_t>(spec.kind));
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeZ1 ||
            spec.kind == FiatShamirEventKind::ChallengeZ2) {
            if (program.ood_candidates == 0) {
                // Legacy single-draw: one digest must equal the claim.
                const uint32_t draw = z_counter++;
                const uint256 digest =
                    challenge_digest("fra3_z", draw);
                const Fp3 decoded =
                    gf::FromChallengeBytes3(digest.data());
                const Fp3 claimed =
                    spec.kind ==
                            FiatShamirEventKind::ChallengeZ1
                        ? child_proof.batch.z1
                        : child_proof.batch.z2;
                const bool has_ext =
                    gf::Canonical(decoded.c1) != 0 ||
                    gf::Canonical(decoded.c2) != 0;
                const bool distinct =
                    !have_z1 || !gf::Eq(decoded, selected_z1);
                if (!has_ext || !distinct) {
                    // Rejection draw: not consumed by the verifier.
                    continue;
                }
                if (!gf::Eq(decoded, claimed)) {
                    out.note =
                        "stage3:verifier_air:fs_selection_join:"
                        "legacy_z_mismatch";
                    return out;
                }
                push_fp3_row(
                    digest, claimed,
                    static_cast<uint32_t>(spec.kind));
                if (spec.kind ==
                    FiatShamirEventKind::ChallengeZ1) {
                    selected_z1 = decoded;
                    have_z1 = true;
                }
                continue;
            }
            if (spec.index != 0) continue;
            std::vector<Fp3> candidates;
            std::vector<uint256> digests;
            candidates.reserve(program.ood_candidates);
            digests.reserve(program.ood_candidates);
            for (uint32_t k = 0; k < program.ood_candidates;
                 ++k) {
                const uint32_t draw = z_counter++;
                const uint256 digest =
                    challenge_digest("fra3_z", draw);
                digests.push_back(digest);
                candidates.push_back(
                    gf::FromChallengeBytes3(digest.data()));
            }
            const Fp3* distinct =
                have_z1 ? &selected_z1 : nullptr;
            const uint32_t selected =
                SelectFirstAcceptableOodIndex(
                    candidates, distinct);
            if (selected >= program.ood_candidates) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "ood_exhausted";
                return out;
            }
            const Fp3 claimed =
                spec.kind == FiatShamirEventKind::ChallengeZ1
                    ? child_proof.batch.z1
                    : child_proof.batch.z2;
            if (!gf::Eq(candidates[selected], claimed)) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "ood_claim_mismatch";
                return out;
            }
            push_fp3_row(
                digests[selected], claimed,
                static_cast<uint32_t>(spec.kind));
            if (spec.kind ==
                FiatShamirEventKind::ChallengeZ1) {
                selected_z1 = candidates[selected];
                have_z1 = true;
            }
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeW1) {
            const uint256 digest =
                challenge_digest("fra3_w", 0);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.w1)) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "w1_mismatch";
                return out;
            }
            push_fp3_row(
                digest, child_proof.batch.w1,
                static_cast<uint32_t>(spec.kind));
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeW2) {
            const uint256 digest =
                challenge_digest("fra3_w", 1);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.w2)) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "w2_mismatch";
                return out;
            }
            push_fp3_row(
                digest, child_proof.batch.w2,
                static_cast<uint32_t>(spec.kind));
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeFold) {
            if (spec.index >=
                child_proof.batch.fold_challenges.size()) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "fold_arity";
                return out;
            }
            const uint256 digest =
                challenge_digest("fra3_fold", spec.index);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.fold_challenges[spec.index])) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "fold_mismatch";
                return out;
            }
            push_fp3_row(
                digest,
                child_proof.batch.fold_challenges[spec.index],
                static_cast<uint32_t>(spec.kind));
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeQueryIndex) {
            if (spec.index >=
                    child_proof.batch.queries.size() ||
                program.child_shape.child_n_lde == 0) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "query_arity";
                return out;
            }
            const uint256 digest =
                challenge_digest("fra3_query", spec.index);
            const Fp3 challenge =
                gf::FromChallengeBytes3(digest.data());
            const unsigned __int128 wide =
                (static_cast<unsigned __int128>(
                     gf::Canonical(challenge.c1))
                 << 64) |
                gf::Canonical(challenge.c0);
            const uint32_t index = static_cast<uint32_t>(
                wide % program.child_shape.child_n_lde);
            if (index !=
                child_proof.batch.queries[spec.index].index) {
                out.note =
                    "stage3:verifier_air:fs_selection_join:"
                    "query_index_mismatch";
                return out;
            }
            fss::ChallengeTableRowV1 row;
            for (uint32_t i = 0; i < 24; ++i) {
                row.digest_bytes[i] = digest.data()[i];
            }
            row.consumed = challenge;
            row.consumed_index = index;
            row.is_query = true;
            row.kind = static_cast<uint32_t>(spec.kind);
            rows.push_back(row);
            continue;
        }
    }

    out.draws = static_cast<uint32_t>(rows.size());
    if (rows.empty()) {
        out.note =
            "stage3:verifier_air:fs_selection_join:no_draws";
        return out;
    }
    const auto table = fss::BuildChallengeTableAirV1(
        rows, program.child_shape.child_n_lde);
    out.table_rows = table.n_rows;
    out.table_constraints = table.n_constraints;
    out.table_violations = table.violations;
    out.rows_bound_to_consumed = table.rows_bound_to_consumed;
    out.query_rows = table.query_rows;
    out.query_rows_bound_to_consumed_index =
        table.query_rows_bound_to_consumed_index;
    out.table_valid = table.valid;
    const bool all_bound =
        table.rows_bound_to_consumed == rows.size() &&
        table.query_rows_bound_to_consumed_index ==
            table.query_rows;

    // One-row consumed tamper must go red or the binding is decorative.
    {
        std::vector<fss::ChallengeTableRowV1> forged = rows;
        if (forged[0].is_query) {
            forged[0].consumed_index =
                (forged[0].consumed_index + 1) %
                program.child_shape.child_n_lde;
        } else {
            forged[0].consumed =
                gf::Add(forged[0].consumed, gf::Fp3::One());
        }
        const auto bad = fss::BuildChallengeTableAirV1(
            forged, program.child_shape.child_n_lde);
        out.tamper_rejects = bad.violations > 0;
    }

    out.constrained =
        out.table_valid && all_bound && out.tamper_rejects;
    out.note =
        out.constrained
            ? ("stage3:verifier_air:fs_selection_join:ok;"
               "draws=" +
               std::to_string(out.draws) +
               ";rows=" + std::to_string(out.table_rows) +
               ";violations=0;tamper=1")
            : ("stage3:verifier_air:fs_selection_join:open;" +
               table.note +
               ";bound=" +
               std::to_string(all_bound ? 1 : 0) +
               ";tamper=" +
               std::to_string(out.tamper_rejects ? 1 : 0));
    return out;
}

FiatShamirAirBackedAllKindsV1
MeasureFiatShamirAirBackedAllKindsV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    namespace fss = stage3_fs_selection_air;
    FiatShamirAirBackedAllKindsV1 out;
    const FiatShamirShaExecutionPlanV1 plan =
        BuildFiatShamirShaExecutionPlanV1(
            program, child_fs_seed, child_proof);
    out.digest_plan_ready =
        plan.valid && plan.every_digest_matches_claim;
    if (!out.digest_plan_ready) {
        out.note =
            "stage3:verifier_air:fs_air_backed_kinds:"
            "digest_plan_open:" +
            plan.note;
        return out;
    }
    const FiatShamirWitness witness =
        BuildFiatShamirWitness(
            program, child_fs_seed, child_proof);
    if (!witness.valid ||
        witness.events.size() != program.events.size()) {
        out.note =
            "stage3:verifier_air:fs_air_backed_kinds:witness";
        return out;
    }

    std::vector<FiatShamirChallengeReconstructionInputV1> inputs;
    std::vector<Fp3> expected_values;
    std::set<uint8_t> seen_kinds;
    std::vector<unsigned char> transcript;
    uint32_t z_counter = 0;
    Fp3 selected_z1{};
    bool have_z1 = false;
    const auto challenge_digest =
        [&transcript](const char* label, uint32_t index) {
            std::vector<unsigned char> preimage = transcript;
            preimage.insert(
                preimage.end(),
                reinterpret_cast<const unsigned char*>(label),
                reinterpret_cast<const unsigned char*>(label) +
                    std::strlen(label));
            AppendU32(preimage, index);
            return Sha256dBytes(preimage.data(), preimage.size());
        };
    const auto push_direct =
        [&inputs, &expected_values, &seen_kinds](
            FiatShamirEventKind kind, const uint256& digest,
            const Fp3& consumed) {
            if (!seen_kinds.insert(static_cast<uint8_t>(kind))
                     .second) {
                return;
            }
            FiatShamirChallengeReconstructionInputV1 in;
            in.kind = kind;
            for (uint32_t i = 0; i < 24; ++i) {
                in.direct_bytes[i] = digest.data()[i];
            }
            inputs.push_back(in);
            expected_values.push_back(consumed);
        };

    for (uint32_t event_index = 0;
         event_index < program.events.size();
         ++event_index) {
        const FiatShamirEventSpec& spec =
            program.events[event_index];
        const FiatShamirEventWitness& event =
            witness.events[event_index];
        if (spec.kind ==
            FiatShamirEventKind::ChallengeAirQuotientLambda) {
            const uint256 digest =
                aq::AirChallengeDigestForBackend<
                    aq::AirFriBackendAlg<Fp3>>(
                child_fs_seed, "airq_lambda",
                {child_proof.trace_commit},
                {program.child_shape.child_n_rows,
                 child_proof.batch.column_len.back(),
                 program.child_shape.child_w});
            const Fp3 decoded =
                gf::FromChallengeBytes3(digest.data());
            if (!event.has_fp3_challenge ||
                !gf::Eq(decoded, event.claimed_challenge)) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "airq_mismatch";
                return out;
            }
            push_direct(spec.kind, digest, decoded);
            continue;
        }
        if (spec.kind == FiatShamirEventKind::AbsorbZ1Z2) {
            if (!have_z1) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "absorb_z_before_select";
                return out;
            }
            AppendFp3(transcript, child_proof.batch.z1);
            AppendFp3(transcript, child_proof.batch.z2);
            continue;
        }
        if (!event.absorbed_payload.empty()) {
            transcript.insert(
                transcript.end(),
                event.absorbed_payload.begin(),
                event.absorbed_payload.end());
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeLambda) {
            const uint256 digest =
                challenge_digest("fra3_lambda", 0);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.lambda)) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "lambda_mismatch";
                return out;
            }
            push_direct(
                spec.kind, digest, child_proof.batch.lambda);
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeZ1 ||
            spec.kind == FiatShamirEventKind::ChallengeZ2) {
            if (program.ood_candidates == 0) {
                const uint32_t draw = z_counter++;
                const uint256 digest =
                    challenge_digest("fra3_z", draw);
                const Fp3 decoded =
                    gf::FromChallengeBytes3(digest.data());
                const Fp3 claimed =
                    spec.kind ==
                            FiatShamirEventKind::ChallengeZ1
                        ? child_proof.batch.z1
                        : child_proof.batch.z2;
                const bool has_ext =
                    gf::Canonical(decoded.c1) != 0 ||
                    gf::Canonical(decoded.c2) != 0;
                const bool distinct =
                    !have_z1 || !gf::Eq(decoded, selected_z1);
                if (!has_ext || !distinct) continue;
                if (!gf::Eq(decoded, claimed)) {
                    out.note =
                        "stage3:verifier_air:fs_air_backed_kinds:"
                        "legacy_z_mismatch";
                    return out;
                }
                push_direct(spec.kind, digest, claimed);
                if (spec.kind ==
                    FiatShamirEventKind::ChallengeZ1) {
                    selected_z1 = decoded;
                    have_z1 = true;
                }
                continue;
            }
            if (spec.index != 0) continue;
            std::vector<Fp3> candidates;
            std::vector<uint256> digests;
            candidates.reserve(program.ood_candidates);
            digests.reserve(program.ood_candidates);
            for (uint32_t k = 0; k < program.ood_candidates;
                 ++k) {
                const uint32_t draw = z_counter++;
                const uint256 digest =
                    challenge_digest("fra3_z", draw);
                digests.push_back(digest);
                candidates.push_back(
                    gf::FromChallengeBytes3(digest.data()));
            }
            const Fp3* distinct =
                have_z1 ? &selected_z1 : nullptr;
            const uint32_t selected =
                SelectFirstAcceptableOodIndex(
                    candidates, distinct);
            if (selected >= program.ood_candidates) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "ood_exhausted";
                return out;
            }
            const Fp3 claimed =
                spec.kind == FiatShamirEventKind::ChallengeZ1
                    ? child_proof.batch.z1
                    : child_proof.batch.z2;
            if (!gf::Eq(candidates[selected], claimed)) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "ood_claim_mismatch";
                return out;
            }
            push_direct(
                spec.kind, digests[selected], claimed);
            if (spec.kind ==
                FiatShamirEventKind::ChallengeZ1) {
                selected_z1 = candidates[selected];
                have_z1 = true;
            }
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeW1) {
            const uint256 digest =
                challenge_digest("fra3_w", 0);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.w1)) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "w1_mismatch";
                return out;
            }
            push_direct(
                spec.kind, digest, child_proof.batch.w1);
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeW2) {
            const uint256 digest =
                challenge_digest("fra3_w", 1);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.w2)) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "w2_mismatch";
                return out;
            }
            push_direct(
                spec.kind, digest, child_proof.batch.w2);
            continue;
        }
        if (spec.kind == FiatShamirEventKind::ChallengeFold) {
            if (spec.index >=
                child_proof.batch.fold_challenges.size()) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "fold_arity";
                return out;
            }
            const uint256 digest =
                challenge_digest("fra3_fold", spec.index);
            if (!gf::Eq(
                    gf::FromChallengeBytes3(digest.data()),
                    child_proof.batch.fold_challenges[spec.index])) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "fold_mismatch";
                return out;
            }
            push_direct(
                spec.kind, digest,
                child_proof.batch.fold_challenges[spec.index]);
            continue;
        }
        if (spec.kind ==
            FiatShamirEventKind::ChallengeQueryIndex) {
            if (spec.index >=
                    child_proof.batch.queries.size() ||
                program.child_shape.child_n_lde == 0 ||
                (program.child_shape.child_n_lde &
                 (program.child_shape.child_n_lde - 1)) != 0) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "query_arity";
                return out;
            }
            const uint256 digest =
                challenge_digest("fra3_query", spec.index);
            const uint32_t claimed =
                child_proof.batch.queries[spec.index].index;
            if (!seen_kinds
                     .insert(static_cast<uint8_t>(spec.kind))
                     .second) {
                continue;
            }
            FiatShamirChallengeReconstructionInputV1 in;
            in.kind = spec.kind;
            for (uint32_t i = 0; i < 4; ++i) {
                in.query_bytes[i] = digest.data()[i];
            }
            in.query_modulus = program.child_shape.child_n_lde;
            const fss::QueryIndexWitnessV1 q =
                fss::BuildQueryIndexWitnessV1(
                    in.query_bytes, in.query_modulus);
            if (!q.valid || q.query_index != claimed) {
                out.note =
                    "stage3:verifier_air:fs_air_backed_kinds:"
                    "query_index_mismatch";
                return out;
            }
            inputs.push_back(in);
            expected_values.push_back(
                Fp3::FromFp(gf::FromU64(claimed)));
            continue;
        }
    }

    if (inputs.size() < out.kinds_required) {
        out.note =
            "stage3:verifier_air:fs_air_backed_kinds:"
            "incomplete_kinds:" +
            std::to_string(inputs.size());
        return out;
    }

    const FiatShamirAirBackedWitnessV1 air =
        BuildFiatShamirAirBackedWitnessV1(inputs);
    out.kinds_reconstructed = air.reconstructed_challenge_types;
    out.covers_all_challenge_types =
        air.covers_all_challenge_types && air.valid;
    if (!out.covers_all_challenge_types) {
        out.note =
            "stage3:verifier_air:fs_air_backed_kinds:"
            "decoder_open:" +
            air.note;
        return out;
    }
    if (air.reconstructed_values.size() !=
        expected_values.size()) {
        out.note =
            "stage3:verifier_air:fs_air_backed_kinds:"
            "value_arity";
        return out;
    }
    out.values_match_consumed = true;
    for (size_t i = 0; i < expected_values.size(); ++i) {
        if (!gf::Eq(
                air.reconstructed_values[i],
                expected_values[i])) {
            out.values_match_consumed = false;
            break;
        }
        ++out.values_bound_to_consumed;
    }
    if (!out.values_match_consumed) {
        out.note =
            "stage3:verifier_air:fs_air_backed_kinds:"
            "value_mismatch";
        return out;
    }

    // One-input byte tamper must change a reconstructed value.
    {
        auto forged = inputs;
        if (forged[0].kind ==
            FiatShamirEventKind::ChallengeQueryIndex) {
            forged[0].query_bytes[0] ^= 0xFFu;
        } else {
            forged[0].direct_bytes[0] ^= 0xFFu;
        }
        const FiatShamirAirBackedWitnessV1 bad =
            BuildFiatShamirAirBackedWitnessV1(forged);
        out.tamper_diverges =
            !bad.valid ||
            bad.reconstructed_values.empty() ||
            !gf::Eq(
                bad.reconstructed_values[0],
                air.reconstructed_values[0]);
    }

    out.reconstructed =
        out.covers_all_challenge_types &&
        out.values_match_consumed && out.tamper_diverges;
    out.note =
        out.reconstructed
            ? ("stage3:verifier_air:fs_air_backed_kinds:ok;"
               "kinds=" +
               std::to_string(out.kinds_reconstructed) +
               ";bound=" +
               std::to_string(out.values_bound_to_consumed) +
               ";tamper=1")
            : ("stage3:verifier_air:fs_air_backed_kinds:open;"
               "kinds=" +
               std::to_string(out.kinds_reconstructed) +
               ";bound=" +
               std::to_string(
                   out.values_match_consumed ? 1 : 0) +
               ";tamper=" +
               std::to_string(out.tamper_diverges ? 1 : 0));
    return out;
}

FiatShamirNonShaChallengesRecursivelyConsumedV1
MeasureFiatShamirNonShaChallengesRecursivelyConsumedV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    namespace pa = recursive_parent_air;
    FiatShamirNonShaChallengesRecursivelyConsumedV1 out;
    if (!aq::kAirChallengeP2Activated) {
        out.note =
            "stage3:verifier_air:fs_nonsha_recursive:p2_inactive";
        return out;
    }
    const FiatShamirShaExecutionPlanV1 plan =
        BuildFiatShamirShaExecutionPlanV1(
            program, child_fs_seed, child_proof);
    out.digest_plan_ready =
        plan.valid && plan.every_digest_matches_claim;
    out.non_sha_calls = plan.non_sha_challenge_calls;
    out.non_sha_claims_match =
        plan.non_sha_challenges_match_claims &&
        plan.non_sha_challenge_calls >= 1;
    if (!out.digest_plan_ready || !out.non_sha_claims_match) {
        out.note =
            "stage3:verifier_air:fs_nonsha_recursive:plan_open:" +
            plan.note;
        return out;
    }
    if (child_proof.batch.column_len.empty()) {
        out.note =
            "stage3:verifier_air:fs_nonsha_recursive:empty_batch";
        return out;
    }
    const uint32_t quot_len =
        child_proof.batch.column_len.back();
    const uint256 digest =
        aq::AirChallengeDigestForBackend<
            aq::AirFriBackendAlg<Fp3>>(
            child_fs_seed, "airq_lambda",
            {child_proof.trace_commit},
            {program.child_shape.child_n_rows, quot_len,
             program.child_shape.child_w});
    const Fp3 consumed =
        gf::FromChallengeBytes3(digest.data());
    const auto companion = pa::BuildChildAirChallengeP2ReplayV1(
        child_fs_seed, child_proof.trace_commit,
        program.child_shape.child_n_rows, quot_len,
        program.child_shape.child_w, consumed);
    out.p2_companion_valid =
        companion.valid && companion.sponge_chained_in_cs &&
        companion.output_binds_digest &&
        companion.challenge_bound_to_consumed &&
        companion.witness_violations == 0;
    out.p2_query_sound = companion.query_sound_shape;
    if (!out.p2_companion_valid || !out.p2_query_sound) {
        out.note =
            "stage3:verifier_air:fs_nonsha_recursive:companion:" +
            companion.note;
        return out;
    }
    // Forced-limb tamper must go red (forgery cannot satisfy CS).
    const Fp3 forged = gf::Add(consumed, gf::Fp3::One());
    const auto tampered = pa::BuildChildAirChallengeP2ReplayV1(
        child_fs_seed, child_proof.trace_commit,
        program.child_shape.child_n_rows, quot_len,
        program.child_shape.child_w, consumed,
        /*n_rows_floor=*/0, &forged);
    out.p2_tamper_rejects =
        !tampered.valid || tampered.witness_violations > 0 ||
        !tampered.challenge_bound_to_consumed;
    if (!out.p2_tamper_rejects) {
        out.note =
            "stage3:verifier_air:fs_nonsha_recursive:"
            "tamper_accepted";
        return out;
    }
    const auto consumer =
        pa::ProveConsumerEndpointFriP2V1(digest, consumed);
    out.consumer_fri_ok = consumer.ok && consumer.verify_ok &&
                         consumer.query_sound_shape;
    if (!out.consumer_fri_ok) {
        out.note =
            "stage3:verifier_air:fs_nonsha_recursive:consumer:" +
            consumer.note;
        return out;
    }
    out.consumed =
        out.digest_plan_ready && out.non_sha_claims_match &&
        out.p2_companion_valid && out.p2_query_sound &&
        out.p2_tamper_rejects && out.consumer_fri_ok;
    out.note = out.consumed
                   ? "stage3:verifier_air:fs_nonsha_recursive:ok"
                   : "stage3:verifier_air:fs_nonsha_recursive:open";
    return out;
}


VerifierFiatShamirAirChipGapV1
AssessVerifierFiatShamirAirChipGapV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    VerifierFiatShamirAirChipGapV1 out;
    out.bounded_ood_program_legislated =
        program.valid && program.ood_candidates > 0;
    out.bounded_ood_rejection_loop_bounded =
        program.valid && program.rejection_loop_bounded;

    AlgAirProof aligned = child_proof;
    std::string align_why;
    bool aligned_ok = true;
    if (out.bounded_ood_program_legislated) {
        aligned_ok =
            AlignAlgAirProofOodToBoundedShaScheduleV1(
                program, child_fs_seed, aligned,
                &align_why);
    }
    const FiatShamirShaExecutionPlanV1 plan =
        aligned_ok
            ? BuildFiatShamirShaExecutionPlanV1(
                  program, child_fs_seed, aligned)
            : FiatShamirShaExecutionPlanV1{};
    out.sha_execution_plan_valid = plan.valid;
    out.sha_fixed_schedule = plan.fixed_schedule;
    out.sha_codec_origins_complete =
        plan.proof_codec_byte_origins_complete;
    // Parent SHA-shard recursive consumption (MultiRow schedule + vertical
    // boundary AIRs + arity-4 join). Plan.recursively_consumed stays false;
    // this gap field is measured independently.
    const FiatShamirShaRecursivelyConsumedV1 recursive =
        aligned_ok
            ? MeasureFiatShamirShaRecursivelyConsumedV1(
                  program, child_fs_seed, aligned)
            : FiatShamirShaRecursivelyConsumedV1{};
    out.sha_recursively_consumed = recursive.consumed;
    // Poseidon2 airq_lambda recursive consumer (independent of SHA shards).
    const FiatShamirNonShaChallengesRecursivelyConsumedV1 nonsha =
        aligned_ok
            ? MeasureFiatShamirNonShaChallengesRecursivelyConsumedV1(
                  program, child_fs_seed, aligned)
            : FiatShamirNonShaChallengesRecursivelyConsumedV1{};
    out.non_sha_challenges_recursively_consumed = nonsha.consumed;
    // fs_selection_air ChallengeTable join (measured when digests match).
    const FiatShamirChallengeSelectionAirJoinV1 selection =
        aligned_ok
            ? MeasureFiatShamirChallengeSelectionAirJoinV1(
                  program, child_fs_seed, aligned)
            : FiatShamirChallengeSelectionAirJoinV1{};
    out.challenge_selection_air_constrained =
        selection.constrained;
    // 8/8 challenge-kind AIR reconstruction from SHA digests (canary path).
    const FiatShamirAirBackedAllKindsV1 air_kinds =
        aligned_ok
            ? MeasureFiatShamirAirBackedAllKindsV1(
                  program, child_fs_seed, aligned)
            : FiatShamirAirBackedAllKindsV1{};
    out.air_backed_all_kinds_reconstructed =
        air_kinds.reconstructed;
    // Every FS SHA call has a satisfying vertical boundary AIR (+ tamper).
    const FiatShamirWholeVerifierShaEquationsInAirV1 whole_sha =
        aligned_ok
            ? MeasureFiatShamirWholeVerifierShaEquationsInAirV1(
                  program, child_fs_seed, aligned)
            : FiatShamirWholeVerifierShaEquationsInAirV1{};
    out.whole_verifier_sha_equations_in_air = whole_sha.in_air;
    out.authority_eligible =
        program.authority_eligible && !program.canary_only;

    const auto bump = [&](bool ok) {
        if (!ok) ++out.open_predicates;
    };
    bump(out.bounded_ood_program_legislated);
    bump(out.bounded_ood_rejection_loop_bounded);
    bump(out.sha_execution_plan_valid);
    bump(out.sha_fixed_schedule);
    bump(out.sha_codec_origins_complete);
    bump(out.sha_recursively_consumed);
    bump(out.non_sha_challenges_recursively_consumed);
    bump(out.challenge_selection_air_constrained);
    bump(out.air_backed_all_kinds_reconstructed);
    bump(out.whole_verifier_sha_equations_in_air);
    bump(out.authority_eligible);
    // Fail-closed: never claim executable while the constexpr is false.
    out.executable_ready =
        out.open_predicates == 0 &&
        kVerifierFiatShamirAirExecutable;
    out.note =
        !aligned_ok && out.bounded_ood_program_legislated
            ? ("stage3:verifier_air:fs_chip_gap:"
               "bounded_align:" +
               align_why)
            : (std::string(
                   "stage3:verifier_air:fs_chip_gap:") +
               "open=" +
               std::to_string(out.open_predicates) +
               ";fixed_schedule=" +
               (out.sha_fixed_schedule ? "1" : "0") +
               ";plan_valid=" +
               (out.sha_execution_plan_valid ? "1"
                                             : "0") +
               ";selection=" +
               (out.challenge_selection_air_constrained
                    ? "1"
                    : "0") +
               ";air_kinds=" +
               (out.air_backed_all_kinds_reconstructed ? "1"
                                                       : "0") +
               ";recursive=" +
               (out.sha_recursively_consumed ? "1" : "0") +
               ";executable_constexpr=0");
    return out;
}

uint256 ComputeVerifierChildProofCommitment(
    const AlgAirProof& child_proof)
{
    std::vector<unsigned char> batch_bytes;
    if (SerializeFri3AlgBatchProof(
            child_proof.batch, batch_bytes) != batch_bytes.size() ||
        batch_bytes.empty()) {
        return {};
    }
    HashWriter hash;
    hash << CHILD_PROOF_DOMAIN;
    hash << static_cast<uint32_t>(batch_bytes.size());
    for (const unsigned char byte : batch_bytes) hash << byte;
    hash << child_proof.trace_commit;
    hash << static_cast<uint32_t>(child_proof.next_openings.size());
    for (const auto& query_paths : child_proof.next_openings) {
        hash << static_cast<uint32_t>(query_paths.size());
        for (const auto& path : query_paths) {
            hash << path.index;
            hash << static_cast<uint32_t>(path.values.size());
            for (const Fp3& value : path.values) HashFp3(hash, value);
            hash << static_cast<uint32_t>(path.siblings.size());
            for (const auto& sibling : path.siblings) {
                HashDigest(hash, sibling);
            }
        }
    }
    return hash.GetHash();
}

VerifierProofBinding BuildVerifierProofBinding(
    const VerifierProgram& program,
    const uint256& child_fs_seed,
    const std::vector<AlgAirProof>& child_proofs,
    const std::vector<RCStage3CtlChildPin>& ctl_pins)
{
    VerifierProofBinding out;
    std::string why;
    if (!ValidateCanonicalVerifierProgram(program, &why)) {
        out.note = why;
        return out;
    }
    if (child_proofs.size() != program.child_shape.arity ||
        ctl_pins.size() != program.child_shape.arity) {
        out.note = "stage3:verifier_air:binding_child_count";
        return out;
    }
    const FiatShamirProgram fs_program =
        BuildCanonicalFiatShamirProgram(program.child_shape);
    if (!fs_program.valid) {
        out.note = fs_program.note;
        return out;
    }
    {
        HashWriter hash;
        hash << BINDING_DOMAIN;
        hash << CommitVerifierProgram(program);
        hash << fs_program.commitment;
        out.program_commitment = hash.GetHash();
    }
    out.child_proof_commitments.reserve(child_proofs.size());
    out.fiat_shamir_witness_commitments.reserve(child_proofs.size());
    out.ctl_child_commitments.reserve(child_proofs.size());
    for (size_t child = 0; child < child_proofs.size(); ++child) {
        const uint256 proof_commitment =
            ComputeVerifierChildProofCommitment(child_proofs[child]);
        const uint256 ctl_commitment =
            CommitRCStage3CtlChildPin(ctl_pins[child]);
        const FiatShamirWitness fs_witness =
            BuildFiatShamirWitness(
                fs_program, child_fs_seed, child_proofs[child]);
        if (proof_commitment.IsNull() || ctl_commitment.IsNull() ||
            !fs_witness.valid ||
            fs_witness.witness_commitment.IsNull()) {
            out.note = fs_witness.note.empty()
                           ? "stage3:verifier_air:null_proof_binding"
                           : fs_witness.note;
            return out;
        }
        out.child_proof_commitments.push_back(proof_commitment);
        out.fiat_shamir_witness_commitments.push_back(
            fs_witness.witness_commitment);
        out.ctl_child_commitments.push_back(ctl_commitment);
    }
    out.rows.reserve(program.active_rows);
    for (uint32_t row = 0; row < program.active_rows; ++row) {
        const ProgramRow& scheduled = program.rows[row];
        const size_t child = scheduled.child;
        if (child >= out.child_proof_commitments.size()) {
            out.note = "stage3:verifier_air:row_child_index";
            out.rows.clear();
            return out;
        }
        HashWriter hash;
        hash << ROW_BINDING_DOMAIN;
        hash << out.program_commitment;
        hash << out.child_proof_commitments[child];
        hash << out.fiat_shamir_witness_commitments[child];
        hash << out.ctl_child_commitments[child];
        hash << row;
        hash << static_cast<uint8_t>(scheduled.kind);
        hash << static_cast<uint8_t>(scheduled.source);
        hash << scheduled.child;
        hash << scheduled.query;
        hash << scheduled.layer;
        hash << scheduled.step;
        out.rows.push_back({row, hash.GetHash()});
    }
    out.scheduler_capacity_sufficient =
        fs_program.scheduler_capacity_sufficient;
    out.proof_equations_air_bound = false;
    out.valid = true;
    out.note =
        "stage3:verifier_air:host_binding_complete_air_binding_missing";
    return out;
}

bool ValidateVerifierProofBinding(
    const VerifierProgram& program,
    const uint256& child_fs_seed,
    const std::vector<AlgAirProof>& child_proofs,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    const VerifierProofBinding& binding,
    std::string* why)
{
    const VerifierProofBinding expected =
        BuildVerifierProofBinding(
            program, child_fs_seed, child_proofs, ctl_pins);
    if (!expected.valid || binding != expected) {
        return Fail(why, "proof_binding_mismatch");
    }
    return true;
}

WholeVerifierWitness BuildWholeVerifierWitness(
    const VerifierProgram& program,
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const uint256& child_fs_seed,
    const std::vector<AlgAirProof>& child_proofs,
    const std::vector<RCStage3CtlChildPin>& ctl_pins,
    const air_recurse::VerifierAirFamilies& families)
{
    WholeVerifierWitness out;
    out.program = program;
    std::string why;
    if (!ValidateCanonicalVerifierProgram(program, &why)) {
        out.note = why;
        return out;
    }
    if (child_proofs.size() != program.child_shape.arity ||
        ctl_pins.size() != child_proofs.size() ||
        child_cs.n_rows != program.child_shape.child_n_rows ||
        child_cs.n_columns != program.child_shape.child_w) {
        out.note =
            "stage3:verifier_air:whole_witness_shape";
        return out;
    }

    out.fiat_shamir_program =
        BuildCanonicalFiatShamirProgram(program.child_shape);
    if (!out.fiat_shamir_program.valid) {
        out.note = out.fiat_shamir_program.note;
        return out;
    }

    out.fiat_shamir_witnesses.reserve(child_proofs.size());
    out.replay_results.reserve(child_proofs.size());
    out.native_child_accepts.reserve(child_proofs.size());

    const auto replay_start = std::chrono::steady_clock::now();
    for (const AlgAirProof& child : child_proofs) {
        FiatShamirWitness witness =
            BuildFiatShamirWitness(
                out.fiat_shamir_program, child_fs_seed, child);
        FiatShamirReplayResult replay =
            ReplayFiatShamirWitness(
                out.fiat_shamir_program, child_fs_seed,
                child, witness);
        out.fiat_shamir_witnesses.push_back(std::move(witness));
        out.replay_results.push_back(std::move(replay));

        std::vector<unsigned char> batch_bytes;
        const size_t batch_size =
            SerializeFri3AlgBatchProof(child.batch, batch_bytes);
        if (batch_size != batch_bytes.size()) {
            out.note =
                "stage3:verifier_air:whole_witness_serialize";
            return out;
        }
        uint64_t child_bytes =
            static_cast<uint64_t>(batch_size) + 32 + 4;
        for (const auto& query_paths : child.next_openings) {
            child_bytes += 4;
            for (const auto& path : query_paths) {
                child_bytes += 8;
                child_bytes +=
                    static_cast<uint64_t>(path.values.size()) *
                    3 * sizeof(uint64_t);
                child_bytes +=
                    static_cast<uint64_t>(path.siblings.size()) *
                    4 * sizeof(uint64_t);
            }
        }
        if (out.child_proof_bytes >
            std::numeric_limits<uint64_t>::max() - child_bytes) {
            out.note =
                "stage3:verifier_air:whole_witness_size_overflow";
            return out;
        }
        out.child_proof_bytes += child_bytes;
    }
    out.transcript_replay_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - replay_start)
                .count());
    out.all_transcripts_replayed =
        std::all_of(
            out.replay_results.begin(), out.replay_results.end(),
            [](const FiatShamirReplayResult& replay) {
                return replay.canonical_program &&
                       replay.witness_matches_proof &&
                       replay.air_quotient_challenge_replayed &&
                       replay.fri_transcript_replayed;
            });

    const auto native_start = std::chrono::steady_clock::now();
    for (const AlgAirProof& child : child_proofs) {
        std::string child_why;
        out.native_child_accepts.push_back(
            aq::AirQuotientVerify<Fp3>(
                child_cs, child, child_fs_seed, &child_why));
    }
    out.native_verify_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - native_start)
                .count());
    out.all_native_children_accepted =
        std::all_of(
            out.native_child_accepts.begin(),
            out.native_child_accepts.end(),
            [](bool accepted) { return accepted; });

    out.proof_binding =
        BuildVerifierProofBinding(
            program, child_fs_seed, child_proofs, ctl_pins);
    if (!out.proof_binding.valid) {
        out.note = out.proof_binding.note;
        return out;
    }

    const auto witness_start = std::chrono::steady_clock::now();
    out.algebraic_mirror =
        air_recurse::BuildAggregateWitness(
            child_cs, child_proofs, child_fs_seed, families);
    out.algebraic_witness_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - witness_start)
                .count());
    if (!out.algebraic_mirror.ok) {
        out.note = out.algebraic_mirror.note;
        return out;
    }

    const auto scan_start = std::chrono::steady_clock::now();
    out.algebraic_violations =
        air_recurse::CountWitnessViolationsOnH(
            out.algebraic_mirror.cs,
            out.algebraic_mirror.columns);
    out.algebraic_scan_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - scan_start)
                .count());
    out.algebraic_mirror_satisfied =
        out.algebraic_violations == 0;

    out.recursive_air_complete =
        out.dual_q128_v5_target_supported &&
        kVerifierFiatShamirAirExecutable &&
        kVerifierProofRowsBoundInAir &&
        kWholeVerifierWitnessExecutable;
    out.valid =
        out.all_transcripts_replayed &&
        out.all_native_children_accepted &&
        out.algebraic_mirror_satisfied;
    out.note =
        out.valid
            ? "stage3:verifier_air:whole_host_legacy_v3_ok_q128_air_open"
            : "stage3:verifier_air:whole_host_differential_reject";
    return out;
}

DualQ128HostVerifierWitness
BuildDualQ128HostVerifierWitness(
    const Fri3AlgDualBatchProof& proof,
    const uint256& fs_seed)
{
    DualQ128HostVerifierWitness out;
    std::vector<unsigned char> encoded;
    const size_t encoded_size =
        SerializeFri3AlgDualBatchProof(proof, encoded);
    if (encoded_size == 0 ||
        encoded_size != encoded.size()) {
        out.note =
            "stage3:verifier_air:v5_host_serialize";
        return out;
    }
    out.proof_bytes = encoded_size;

    auto phase = std::chrono::steady_clock::now();
    out.transcript =
        BuildFri3AlgDualTranscriptWitness(
            proof, fs_seed);
    out.transcript_replay_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - phase)
                .count());
    if (!out.transcript.valid) {
        out.note =
            "stage3:verifier_air:v5_host_transcript:" +
            out.transcript.note;
        return out;
    }

    phase = std::chrono::steady_clock::now();
    std::string why;
    out.native_proof_accepted =
        Fri3AlgDualBatchVerify(
            proof, fs_seed, &why);
    out.native_verify_micros =
        static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - phase)
                .count());
    if (!out.native_proof_accepted) {
        out.note =
            "stage3:verifier_air:v5_host_native:" + why;
        return out;
    }

    // AirFriBackendAlg and AggregateWitness still carry a single
    // Fri3AlgBatchProof V3 object. Do not reinterpret this host acceptance as
    // recursive support for the dual V5 envelope.
    out.recursive_proof_api_supports_v5 = false;
    out.recursive_air_complete = false;
    out.valid = true;
    out.note =
        "stage3:verifier_air:v5_host_ok_recursive_api_v3";
    return out;
}

namespace {

constexpr char kMultiRowV2ProgramDomainV1[] =
    "BTX_RC_STAGE3_MULTI_ROW_V2_VERIFIER_PROGRAM_V1";
constexpr char kMultiRowV2ProofDomainV1[] =
    "BTX_RC_STAGE3_MULTI_ROW_V2_VERIFIER_PROOF_V1";
constexpr char kMultiRowV2OutputDomainV1[] =
    "BTX_RC_STAGE3_MULTI_ROW_V2_VERIFIER_OUTPUT_V1";
constexpr char kMultiRowV2FriDomain[] =
    "BTX_RC_FRI3ALG_MULTI_ROW_RAP_V2";
constexpr Fp kMultiRowV2Omega2_32 =
    UINT64_C(0x185629dcda58878c);

uint32_t Log2ExactV1(uint32_t value)
{
    uint32_t log = 0;
    while (value > 1) {
        value >>= 1;
        ++log;
    }
    return log;
}

Fp PowBaseV1(Fp base, uint64_t exponent)
{
    Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp OmegaForSizeV1(uint32_t size)
{
    return PowBaseV1(
        kMultiRowV2Omega2_32,
        uint64_t{1} << (32 - Log2ExactV1(size)));
}

Fp3 PowFp3V1(Fp3 base, uint64_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

Fp3 DomainPointV1(uint32_t size, uint32_t index)
{
    return Fp3::FromFp(
        PowBaseV1(OmegaForSizeV1(size), index));
}

Fp3 SelectorAtV1(
    aq::AirKind kind,
    uint32_t trace_rows,
    const Fp3& y)
{
    const Fp3 one = Fp3::One();
    const Fp3 h_last = Fp3::FromFp(
        PowBaseV1(
            OmegaForSizeV1(trace_rows),
            trace_rows - 1));
    const auto zh_over =
        [&](const Fp3& h) {
            const Fp3 denominator =
                gf::Sub(y, h);
            if (!gf::IsZero(denominator)) {
                return gf::Mul(
                    gf::Sub(
                        PowFp3V1(y, trace_rows),
                        one),
                    gf::Inv(denominator));
            }
            return gf::Mul(
                Fp3::FromFp(
                    gf::FromU64(trace_rows)),
                PowFp3V1(h, trace_rows - 1));
        };
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return one;
    case aq::AirKind::kTransition:
        return gf::Sub(y, h_last);
    case aq::AirKind::kFirstRow:
        return zh_over(one);
    case aq::AirKind::kLastRow:
        return zh_over(h_last);
    }
    return Fp3::Zero();
}

void AddMultiRowV2ProgramRow(
    MultiRowV2SplitRapProgramV1& out,
    MultiRowV2CheckKindV1 kind,
    uint32_t query,
    uint32_t group,
    uint32_t layer,
    uint32_t item,
    uint32_t active_lanes)
{
    out.rows.push_back({
        kind, query, group, layer,
        item, active_lanes});
}

uint256 CommitMultiRowV2ProgramV1(
    const MultiRowV2SplitRapProgramV1& program)
{
    if (program.version != 1 ||
        program.rows.size() != program.air_rows ||
        program.active_rows > program.air_rows) {
        return {};
    }
    HashWriter hash;
    hash << kMultiRowV2ProgramDomainV1;
    hash << program.version;
    hash << program.trace_rows;
    hash << program.trace_columns;
    hash << program.quotient_len;
    hash << program.n_coeffs;
    hash << program.n_lde;
    hash << program.merkle_depth;
    hash << program.fold_count;
    hash << program.query_count;
    for (uint32_t width : program.group_widths) {
        hash << width;
    }
    hash << static_cast<uint32_t>(
        program.base_column_indices.size());
    for (uint32_t column :
         program.base_column_indices) {
        hash << column;
    }
    hash << program.poseidon_permutation_rows;
    hash << program.active_rows;
    hash << program.air_rows;
    for (const auto& row : program.rows) {
        hash << static_cast<uint8_t>(row.kind);
        hash << row.query;
        hash << row.group;
        hash << row.layer;
        hash << row.item;
        hash << row.active_lanes;
    }
    return hash.GetHash();
}

std::array<Fp3, 4> CheckValuesV1(
    const Fp3& a = Fp3::Zero(),
    const Fp3& b = Fp3::Zero(),
    const Fp3& c = Fp3::Zero(),
    const Fp3& d = Fp3::Zero())
{
    return {a, b, c, d};
}

std::array<Fp3, 4> DigestValuesV1(
    const Fri3AlgDigest& digest)
{
    std::array<Fp3, 4> out{};
    for (uint32_t limb = 0; limb < out.size(); ++limb) {
        out[limb] = Fp3::FromFp(
            gf::Canonical(digest[limb]));
    }
    return out;
}

bool SameDigestV1(
    const Fri3AlgDigest& lhs,
    const Fri3AlgDigest& rhs)
{
    for (uint32_t limb = 0; limb < lhs.size(); ++limb) {
        if (gf::Canonical(lhs[limb]) !=
            gf::Canonical(rhs[limb])) {
            return false;
        }
    }
    return true;
}

Fri3AlgDigest LoggedCompressV1(
    const Fri3AlgDigest& left,
    const Fri3AlgDigest& right,
    std::vector<alg_hash::State>& inputs)
{
    alg_hash::State state{};
    for (uint32_t limb = 0; limb < 4; ++limb) {
        state[limb] =
            gf::Canonical(left[limb]);
        state[4 + limb] =
            gf::Canonical(right[limb]);
    }
    state[8] =
        alg_hash::GetAlgHashConstants()
            .node_domain;
    inputs.push_back(state);
    alg_hash::Permute(state);
    return {
        state[0], state[1],
        state[2], state[3]};
}

Fri3AlgDigest LoggedLeafV1(
    const Fp3& value,
    uint32_t index,
    std::vector<alg_hash::State>& inputs)
{
    alg_hash::State state{};
    state[0] = gf::Canonical(value.c0);
    state[1] = gf::Canonical(value.c1);
    state[2] = gf::Canonical(value.c2);
    state[3] = gf::FromU64(index);
    state[4] =
        alg_hash::GetAlgHashConstants()
            .leaf_domain;
    inputs.push_back(state);
    alg_hash::Permute(state);
    return {
        state[0], state[1],
        state[2], state[3]};
}

Fri3AlgDigest LoggedRowLeafV1(
    const std::vector<Fp3>& row,
    uint32_t index,
    std::vector<alg_hash::State>& inputs)
{
    std::vector<Fp> message;
    message.reserve(
        3 * row.size() + 1 +
        alg_hash::kAlgHashRate);
    for (const Fp3& value : row) {
        message.push_back(
            gf::Canonical(value.c0));
        message.push_back(
            gf::Canonical(value.c1));
        message.push_back(
            gf::Canonical(value.c2));
    }
    message.push_back(gf::FromU64(index));
    message.push_back(1);
    while (message.size() %
           alg_hash::kAlgHashRate != 0) {
        message.push_back(0);
    }
    alg_hash::State state{};
    for (uint32_t offset = 0;
         offset < message.size();
         offset += alg_hash::kAlgHashRate) {
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashRate;
             ++lane) {
            state[lane] =
                gf::Add(
                    state[lane],
                    message[offset + lane]);
        }
        inputs.push_back(state);
        alg_hash::Permute(state);
    }
    return {
        state[0], state[1],
        state[2], state[3]};
}

Fri3AlgDigest LoggedMerkleStepV1(
    const Fri3AlgDigest& current,
    const Fri3AlgDigest& sibling,
    uint32_t index,
    std::vector<alg_hash::State>& inputs)
{
    return (index & 1U) == 0
        ? LoggedCompressV1(
              current, sibling, inputs)
        : LoggedCompressV1(
              sibling, current, inputs);
}

Fri3AlgDigest ConstantFoldRootV1(
    const Fp3& value,
    uint32_t leaves,
    std::vector<alg_hash::State>* inputs = nullptr)
{
    if (leaves == 0 ||
        (leaves & (leaves - 1)) != 0) {
        return {};
    }
    std::vector<Fri3AlgDigest> layer(leaves);
    for (uint32_t index = 0; index < leaves; ++index) {
        layer[index] = inputs == nullptr
            ? alg_hash::LeafHash(value, index)
            : LoggedLeafV1(
                  value, index, *inputs);
    }
    while (layer.size() > 1) {
        std::vector<Fri3AlgDigest> next(
            layer.size() / 2);
        for (uint32_t index = 0;
             index < next.size(); ++index) {
            next[index] = inputs == nullptr
                ? alg_hash::Compress(
                      layer[2 * index],
                      layer[2 * index + 1])
                : LoggedCompressV1(
                      layer[2 * index],
                      layer[2 * index + 1],
                      *inputs);
        }
        layer = std::move(next);
    }
    return layer.front();
}

uint256 CommitMultiRowV2ProofV1(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    if (aq::SerializeAirQuotientSplitRapRowsProof(
            proof, bytes) == 0) {
        return {};
    }
    HashWriter hash;
    hash << kMultiRowV2ProofDomainV1;
    hash << static_cast<uint64_t>(bytes.size());
    for (unsigned char byte : bytes) {
        hash << byte;
    }
    return hash.GetHash();
}

} // namespace

MultiRowV2SplitRapProgramV1
BuildCanonicalMultiRowV2SplitRapProgramV1(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const std::vector<uint32_t>& base_column_indices)
{
    MultiRowV2SplitRapProgramV1 out;
    out.trace_rows = child_cs.n_rows;
    out.trace_columns = child_cs.n_columns;
    out.quotient_len = child_cs.QuotientLen();
    out.query_count = kRCFri3AlgNumQueries;
    if (child_cs.n_rows < 2 ||
        (child_cs.n_rows &
         (child_cs.n_rows - 1)) != 0 ||
        child_cs.n_columns < 2 ||
        out.quotient_len == 0 ||
        base_column_indices.empty() ||
        base_column_indices.size() >=
            child_cs.n_columns) {
        out.note =
            "stage3:verifier_air:multi_row_v2_program:shape";
        return out;
    }
    std::vector<uint8_t> used(
        child_cs.n_columns, 0);
    uint32_t previous = 0;
    for (uint32_t position = 0;
         position < base_column_indices.size();
         ++position) {
        const uint32_t column =
            base_column_indices[position];
        if (column >= child_cs.n_columns ||
            (position != 0 && column <= previous) ||
            used[column]) {
            out.note =
                "stage3:verifier_air:multi_row_v2_program:"
                "base_indices";
            return out;
        }
        previous = column;
        used[column] = 1;
    }
    out.base_column_indices =
        base_column_indices;
    out.group_widths = {
        static_cast<uint32_t>(
            base_column_indices.size()),
        child_cs.n_columns -
            static_cast<uint32_t>(
                base_column_indices.size()),
        1};
    out.n_coeffs = FriNextPow2(
        std::max(
            out.trace_rows,
            out.quotient_len));
    if (out.n_coeffs < 2 ||
        uint64_t{out.n_coeffs} * kRCFriBlowup >
            (uint64_t{1} << kRCFriMaxLdeLog2)) {
        out.note =
            "stage3:verifier_air:multi_row_v2_program:domain";
        return out;
    }
    out.n_lde = out.n_coeffs * kRCFriBlowup;
    out.merkle_depth =
        Log2ExactV1(out.n_lde);
    out.fold_count =
        Log2ExactV1(out.n_coeffs);
    const auto row_leaf_permutations =
        [](uint32_t width) {
            return static_cast<uint32_t>(
                (uint64_t{3} * width + 2 +
                 alg_hash::kAlgHashRate - 1) /
                alg_hash::kAlgHashRate);
        };
    uint64_t poseidon_rows =
        // Terminal constant layer: one leaf permutation per blowup
        // leaf and one compression per internal node.
        uint64_t{kRCFriBlowup} +
        (kRCFriBlowup - 1);
    for (uint32_t group = 0; group < 3; ++group) {
        poseidon_rows +=
            uint64_t{out.query_count} *
            (row_leaf_permutations(
                 out.group_widths[group]) +
             out.merkle_depth);
    }
    for (uint32_t group = 0; group < 2; ++group) {
        poseidon_rows +=
            uint64_t{out.query_count} *
            (row_leaf_permutations(
                 out.group_widths[group]) +
             out.merkle_depth);
    }
    for (uint32_t fold = 0;
         fold < out.fold_count; ++fold) {
        poseidon_rows +=
            uint64_t{out.query_count} *
            2 *
            (1 + out.merkle_depth - fold);
    }
    if (poseidon_rows >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:verifier_air:multi_row_v2_program:"
            "poseidon_rows";
        return out;
    }
    out.poseidon_permutation_rows =
        static_cast<uint32_t>(poseidon_rows);

    AddMultiRowV2ProgramRow(
        out, MultiRowV2CheckKindV1::ProofMetadata,
        0, 0, 0, 0, 4);
    AddMultiRowV2ProgramRow(
        out, MultiRowV2CheckKindV1::ProofMetadata,
        0, 0, 0, 1, 4);
    for (uint32_t position = 0;
         position < base_column_indices.size();
         ++position) {
        AddMultiRowV2ProgramRow(
            out,
            MultiRowV2CheckKindV1::BaseColumnIndex,
            0, 0, 0, position, 1);
    }
    for (uint32_t group = 0; group < 3; ++group) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::GroupMetadata,
            0, group, 0, 0, 4);
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::GroupRoot,
            0, group, 0, 0, 4);
    }
    const uint32_t pcs_width =
        child_cs.n_columns + 1;
    for (uint32_t column = 0;
         column < pcs_width; ++column) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::ColumnLength,
            0, 0, 0, column, 1);
    }
    for (uint32_t point = 0; point < 2; ++point) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::OodPoint,
            0, 0, 0, point, 3);
    }
    for (uint32_t column = 0;
         column < pcs_width; ++column) {
        AddMultiRowV2ProgramRow(
            out,
            MultiRowV2CheckKindV1::EvaluationPairAbsorb,
            0, 0, 0, column, 2);
    }
    for (uint32_t column = 0;
         column < pcs_width; ++column) {
        AddMultiRowV2ProgramRow(
            out,
            MultiRowV2CheckKindV1::IndependentPcsAlpha,
            0, 0, 0, column, 3);
    }
    for (uint32_t weight = 0; weight < 2; ++weight) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::DeepWeight,
            0, 0, 0, weight, 3);
    }
    for (uint32_t layer = 0;
         layer <= out.fold_count; ++layer) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::FoldRoot,
            0, 0, layer, 0, 4);
        if (layer < out.fold_count) {
            AddMultiRowV2ProgramRow(
                out,
                MultiRowV2CheckKindV1::FoldChallenge,
                0, 0, layer, 0, 3);
        }
    }
    AddMultiRowV2ProgramRow(
        out,
        MultiRowV2CheckKindV1::TerminalFinalValue,
        0, 0, out.fold_count, 0, 3);
    AddMultiRowV2ProgramRow(
        out, MultiRowV2CheckKindV1::TerminalRoot,
        0, 0, out.fold_count, 0, 4);
    for (uint32_t query = 0;
         query < out.query_count; ++query) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::QueryIndex,
            query, 0, 0, 0, 1);
    }
    for (uint32_t query = 0;
         query < out.query_count; ++query) {
        for (uint32_t group = 0; group < 3; ++group) {
            for (uint32_t item = 0;
                 item < out.group_widths[group];
                 ++item) {
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::
                        CurrentGroupValue,
                    query, group, 0, item, 3);
            }
        }
        for (uint32_t group = 0; group < 2; ++group) {
            for (uint32_t item = 0;
                 item < out.group_widths[group];
                 ++item) {
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::NextGroupValue,
                    query, group, 0, item, 3);
            }
        }
        for (uint32_t group = 0; group < 3; ++group) {
            for (uint32_t layer = 0;
                 layer < out.merkle_depth; ++layer) {
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::
                        CurrentMerkleSibling,
                    query, group, layer, 0, 4);
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::
                        CurrentMerkleStep,
                    query, group, layer, 0, 4);
            }
        }
        for (uint32_t group = 0; group < 2; ++group) {
            for (uint32_t layer = 0;
                 layer < out.merkle_depth; ++layer) {
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::
                        NextMerkleSibling,
                    query, group, layer, 0, 4);
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::NextMerkleStep,
                    query, group, layer, 0, 4);
            }
        }
        for (uint32_t fold = 0;
             fold < out.fold_count; ++fold) {
            for (uint32_t side = 0; side < 2; ++side) {
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::FoldOpeningIndex,
                    query, side, fold, 0, 1);
            }
            for (uint32_t side = 0; side < 2; ++side) {
                AddMultiRowV2ProgramRow(
                    out,
                    MultiRowV2CheckKindV1::FoldOpeningValue,
                    query, side, fold, 0, 3);
                for (uint32_t layer = 0;
                     layer <
                         out.merkle_depth - fold;
                     ++layer) {
                    AddMultiRowV2ProgramRow(
                        out,
                        MultiRowV2CheckKindV1::
                            FoldMerkleSibling,
                        query, side, fold, layer, 4);
                    AddMultiRowV2ProgramRow(
                        out,
                        MultiRowV2CheckKindV1::
                            FoldMerkleStep,
                        query, side, fold, layer, 4);
                }
            }
            AddMultiRowV2ProgramRow(
                out,
                MultiRowV2CheckKindV1::FoldIdentity,
                query, 0, fold, 0, 3);
        }
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::DeepIdentity,
            query, 0, 0, 0, 3);
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::FinalFold,
            query, 0, out.fold_count, 0, 3);
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::QuotientIdentity,
            query, 0, 0, 0, 3);
    }
    if (out.rows.size() >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:verifier_air:multi_row_v2_program:rows";
        return out;
    }
    out.active_rows =
        static_cast<uint32_t>(out.rows.size());
    uint64_t air_rows = 1;
    while (air_rows < out.active_rows) {
        air_rows <<= 1;
    }
    if (air_rows >
        (uint64_t{1} << kRCFriMaxColumnLog2)) {
        out.note =
            "stage3:verifier_air:multi_row_v2_program:"
            "air_domain";
        return out;
    }
    out.air_rows =
        static_cast<uint32_t>(air_rows);
    while (out.rows.size() < out.air_rows) {
        AddMultiRowV2ProgramRow(
            out, MultiRowV2CheckKindV1::Padding,
            0, 0, 0, 0, 0);
    }
    out.exact_three_group_partition =
        out.group_widths[0] +
            out.group_widths[1] ==
            child_cs.n_columns &&
        out.group_widths[2] == 1;
    out.independent_pcs_alpha_schedule = true;
    out.current_next_schedule_complete = true;
    out.quotient_identity_scheduled = true;
    out.program_statement =
        CommitMultiRowV2ProgramV1(out);
    out.valid =
        !out.program_statement.IsNull() &&
        out.exact_three_group_partition;
    out.note = out.valid
        ? "stage3:verifier_air:multi_row_v2_program:"
          "canonical_three_group"
        : "stage3:verifier_air:multi_row_v2_program:invalid";
    return out;
}

bool ValidateCanonicalMultiRowV2SplitRapProgramV1(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    std::string* why)
{
    const auto expected =
        BuildCanonicalMultiRowV2SplitRapProgramV1(
            child_cs, program.base_column_indices);
    if (!program.valid || !expected.valid ||
        program.version != 1 ||
        program.trace_rows != expected.trace_rows ||
        program.trace_columns != expected.trace_columns ||
        program.quotient_len != expected.quotient_len ||
        program.n_coeffs != expected.n_coeffs ||
        program.n_lde != expected.n_lde ||
        program.merkle_depth != expected.merkle_depth ||
        program.fold_count != expected.fold_count ||
        program.query_count != expected.query_count ||
        program.group_widths != expected.group_widths ||
        program.poseidon_permutation_rows !=
            expected.poseidon_permutation_rows ||
        program.active_rows != expected.active_rows ||
        program.air_rows != expected.air_rows ||
        program.rows != expected.rows ||
        program.program_statement !=
            expected.program_statement ||
        !program.exact_three_group_partition ||
        !program.independent_pcs_alpha_schedule ||
        !program.current_next_schedule_complete ||
        !program.quotient_identity_scheduled) {
        return Fail(
            why, "multi_row_v2_program_noncanonical");
    }
    return true;
}

namespace {

struct MultiRowV2TranscriptReplayV1 {
    bool valid{false};
    Fp3 z1{};
    Fp3 z2{};
    std::vector<Fp3> alphas;
    Fp3 w1{};
    Fp3 w2{};
    std::vector<Fp3> fold_challenges;
    std::vector<uint32_t> query_indices;
    std::vector<MultiRowV2TranscriptShaCallV1>
        sha_calls;
};

uint256 CommitMultiRowV2ShaCallV1(
    const MultiRowV2TranscriptShaCallV1& call)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_MULTI_ROW_V2_SHA_CALL_V1";
    hash << call.ordinal;
    hash << static_cast<uint8_t>(call.kind);
    hash << call.item;
    hash << call.block;
    hash << call.transcript_bytes;
    hash << call.suffix_bytes;
    hash << call.new_shared_prefix_blocks;
    hash << call.shared_prefix_blocks;
    hash << call.first_round_tail_blocks;
    hash << call.second_round_blocks;
    hash << call.unique_compression_begin;
    hash << call.unique_compression_count;
    hash << call.naive_compression_count;
    hash << static_cast<uint32_t>(
        call.preimage.size());
    for (const unsigned char byte :
         call.preimage) {
        hash << byte;
    }
    hash << call.digest;
    return hash.GetHash();
}

struct MultiRowV2ShaRecorderV1 {
    std::vector<MultiRowV2TranscriptShaCallV1> calls;
    uint32_t shared_prefix_blocks{0};
    uint64_t unique_compressions{0};

    bool Record(
        MultiRowV2TranscriptShaCallKindV1 kind,
        uint32_t item,
        uint32_t block,
        uint64_t transcript_bytes,
        uint32_t suffix_bytes,
        const std::vector<unsigned char>& preimage,
        const uint256& digest,
        bool share_transcript_prefix)
    {
        const uint64_t preimage_bytes =
            transcript_bytes + suffix_bytes;
        if (preimage.size() != preimage_bytes ||
            Hash(preimage) != digest) {
            return false;
        }
        const uint64_t first_round_blocks =
            CeilDiv(preimage_bytes + 9, uint64_t{64});
        if (first_round_blocks == 0 ||
            first_round_blocks >
                std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        const uint32_t available_shared =
            share_transcript_prefix
            ? static_cast<uint32_t>(
                  transcript_bytes / 64)
            : 0;
        if (available_shared < shared_prefix_blocks &&
            share_transcript_prefix) {
            return false;
        }
        const uint32_t newly_shared =
            share_transcript_prefix
            ? available_shared -
                  shared_prefix_blocks
            : 0;
        const uint32_t tail_blocks =
            static_cast<uint32_t>(
                first_round_blocks) -
            available_shared;
        const uint64_t unique_count =
            uint64_t{newly_shared} +
            tail_blocks + 1;
        if (unique_count >
            std::numeric_limits<uint32_t>::max()) {
            return false;
        }
        MultiRowV2TranscriptShaCallV1 call;
        call.ordinal =
            static_cast<uint32_t>(calls.size());
        call.kind = kind;
        call.item = item;
        call.block = block;
        call.transcript_bytes =
            transcript_bytes;
        call.suffix_bytes = suffix_bytes;
        call.new_shared_prefix_blocks =
            newly_shared;
        call.shared_prefix_blocks =
            available_shared;
        call.first_round_tail_blocks =
            tail_blocks;
        call.second_round_blocks = 1;
        call.unique_compression_begin =
            unique_compressions;
        call.unique_compression_count =
            static_cast<uint32_t>(unique_count);
        call.naive_compression_count =
            first_round_blocks + 1;
        call.preimage = preimage;
        call.digest = digest;
        call.call_statement =
            CommitMultiRowV2ShaCallV1(call);
        if (call.call_statement.IsNull()) {
            return false;
        }
        calls.push_back(call);
        unique_compressions += unique_count;
        if (share_transcript_prefix) {
            shared_prefix_blocks =
                available_shared;
        }
        return true;
    }
};

struct MultiRowV2FsV1 {
    std::vector<unsigned char> bytes;
    MultiRowV2ShaRecorderV1* recorder{nullptr};

    MultiRowV2FsV1(
        const uint256& seed,
        const Fri3AlgMultiRowBatchProof& proof,
        MultiRowV2ShaRecorderV1* record)
        : recorder(record)
    {
        const auto* tag =
            reinterpret_cast<const unsigned char*>(
                kMultiRowV2FriDomain);
        bytes.insert(
            bytes.end(), tag,
            tag + sizeof(kMultiRowV2FriDomain) - 1);
        bytes.insert(
            bytes.end(), seed.begin(), seed.end());
        AppendU64(bytes, proof.pow_grind_nonce);
        AppendU32(bytes, proof.blowup);
        AppendU32(bytes, proof.n_coeffs);
        AppendU32(bytes, proof.version);
        AppendU32(
            bytes,
            static_cast<uint32_t>(
                proof.groups.size()));
        for (const auto& group : proof.groups) {
            AppendU32(
                bytes,
                static_cast<uint32_t>(
                    group.role));
            AppendU32(bytes, group.first_column);
            AppendU32(bytes, group.column_count);
            AppendU32(
                bytes, group.row_commit.n_leaves);
            AppendHash(
                bytes,
                Fri3AlgDigestToUint256(
                    group.row_commit.root));
        }
        AppendU32(
            bytes,
            static_cast<uint32_t>(
                proof.column_len.size()));
        for (uint32_t length :
             proof.column_len) {
            AppendU32(bytes, length);
        }
    }

    void Absorb(const Fp3& value)
    {
        AppendFp3(bytes, value);
    }

    void Absorb(const Fri3AlgDigest& digest)
    {
        AppendHash(
            bytes,
            Fri3AlgDigestToUint256(digest));
    }

    uint256 Challenge(
        const char* draw_domain,
        const char* label,
        uint32_t index,
        MultiRowV2TranscriptShaCallKindV1 kind,
        std::optional<uint32_t> block =
            std::nullopt) const
    {
        std::vector<unsigned char> input = bytes;
        const auto* draw =
            reinterpret_cast<const unsigned char*>(
                draw_domain);
        input.insert(
            input.end(), draw,
            draw + std::strlen(draw_domain));
        const auto* label_bytes =
            reinterpret_cast<const unsigned char*>(
                label);
        input.insert(
            input.end(), label_bytes,
            label_bytes + std::strlen(label));
        AppendU32(input, index);
        if (block.has_value()) {
            AppendU32(input, *block);
        }
        const uint256 digest = Hash(input);
        if (recorder != nullptr) {
            const uint64_t suffix_bytes =
                input.size() - bytes.size();
            if (suffix_bytes >
                    std::numeric_limits<uint32_t>::max() ||
                !recorder->Record(
                    kind, index,
                    block.value_or(0),
                    bytes.size(),
                    static_cast<uint32_t>(
                        suffix_bytes),
                    input,
                    digest, true)) {
                return {};
            }
        }
        return digest;
    }

    bool UniformFp3(
        const char* label,
        uint32_t index,
        MultiRowV2TranscriptShaCallKindV1 kind,
        Fp3& out) const
    {
        std::array<
            uint64_t,
            kRCFri3AlgDualUniformWords> words{};
        for (uint32_t block = 0;
             block <
                 kRCFri3AlgDualUniformHashBlocks;
             ++block) {
            const uint256 digest =
                Challenge(
                    kRCFri3AlgDualUniformDrawDomainTag,
                    label, index, kind, block);
            if (digest.IsNull()) return false;
            for (uint32_t word = 0; word < 4; ++word) {
                uint64_t value = 0;
                for (uint32_t byte = 0; byte < 8; ++byte) {
                    value |=
                        uint64_t{
                            digest.begin()[
                                8 * word + byte]}
                        << (8 * byte);
                }
                words[4 * block + word] = value;
            }
        }
        const auto selected =
            Fri3AlgSelectUniformFp3Words(words);
        if (!selected.has_value()) return false;
        out = *selected;
        return true;
    }

    bool UniformIndex(
        uint32_t query,
        uint32_t modulus,
        uint32_t& out) const
    {
        if (modulus == 0 ||
            (modulus & (modulus - 1)) != 0) {
            return false;
        }
        const uint256 digest =
            Challenge(
                kRCFri3AlgDualIndexDrawDomainTag,
                "fra3_query", query,
                MultiRowV2TranscriptShaCallKindV1::
                    QueryIndex);
        if (digest.IsNull()) return false;
        uint32_t raw = 0;
        for (uint32_t byte = 0; byte < 4; ++byte) {
            raw |=
                uint32_t{digest.begin()[byte]}
                << (8 * byte);
        }
        out = raw & (modulus - 1);
        return true;
    }
};

bool DeriveAirLambdaV1(
    const MultiRowV2SplitRapProgramV1& program,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed,
    MultiRowV2ShaRecorderV1* recorder,
    Fp3& out)
{
    std::vector<uint32_t> extra{
        program.trace_rows,
        program.trace_columns,
        program.quotient_len,
        program.n_coeffs,
        static_cast<uint32_t>(
            program.base_column_indices.size())};
    extra.insert(
        extra.end(),
        program.base_column_indices.begin(),
        program.base_column_indices.end());
    const std::vector<uint256> roots{
        Fri3AlgDigestToUint256(
            proof.batch.groups[0]
                .row_commit.root),
        Fri3AlgDigestToUint256(
            proof.batch.groups[1]
                .row_commit.root)};
    std::array<
        uint64_t,
        kRCFri3AlgDualUniformWords> words{};
    for (uint32_t block = 0;
         block <
             kRCFri3AlgDualUniformHashBlocks;
         ++block) {
        auto block_extra = extra;
        block_extra.push_back(block);
        const uint256 digest =
            aq::AirChallengeDigest(
                public_fs_seed,
                "airq_split_rap_constraint_v1",
                roots, block_extra);
        std::vector<unsigned char> preimage;
        {
            static constexpr char tag[] =
                "BTX_RC_AIRQ_V1";
            preimage.insert(
                preimage.end(),
                reinterpret_cast<
                    const unsigned char*>(tag),
                reinterpret_cast<
                    const unsigned char*>(tag) +
                    sizeof(tag) - 1);
            AppendHash(
                preimage, public_fs_seed);
            const char* label =
                "airq_split_rap_constraint_v1";
            AppendU32(
                preimage,
                static_cast<uint32_t>(
                    std::strlen(label)));
            preimage.insert(
                preimage.end(),
                reinterpret_cast<
                    const unsigned char*>(label),
                reinterpret_cast<
                    const unsigned char*>(label) +
                    std::strlen(label));
            AppendU32(
                preimage,
                static_cast<uint32_t>(
                    roots.size()));
            for (const uint256& root : roots) {
                AppendHash(preimage, root);
            }
            AppendU32(
                preimage,
                static_cast<uint32_t>(
                    block_extra.size()));
            for (const uint32_t value :
                 block_extra) {
                AppendU32(preimage, value);
            }
        }
        constexpr uint64_t AIRQ_TAG_BYTES =
            sizeof("BTX_RC_AIRQ_V1") - 1;
        const uint64_t label_bytes =
            sizeof("airq_split_rap_constraint_v1") -
            1;
        const uint64_t preimage_bytes =
            AIRQ_TAG_BYTES + 32 + 4 +
            label_bytes + 4 +
            uint64_t{32} * roots.size() + 4 +
            uint64_t{4} * block_extra.size();
        if (recorder != nullptr &&
            (preimage_bytes >
                 std::numeric_limits<uint32_t>::max() ||
             !recorder->Record(
                 MultiRowV2TranscriptShaCallKindV1::
                     AirConstraintLambda,
                 0, block, 0,
                 static_cast<uint32_t>(
                     preimage_bytes),
                 preimage,
                 digest, false))) {
            return false;
        }
        for (uint32_t word = 0; word < 4; ++word) {
            uint64_t value = 0;
            for (uint32_t byte = 0; byte < 8; ++byte) {
                value |=
                    uint64_t{
                        digest.begin()[
                            8 * word + byte]}
                    << (8 * byte);
            }
            words[4 * block + word] = value;
        }
    }
    const auto selected =
        Fri3AlgSelectUniformFp3Words(words);
    if (!selected.has_value()) return false;
    out = *selected;
    return true;
}

uint256 DeriveMultiRowFriSeedV1(
    const MultiRowV2SplitRapProgramV1& program,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed,
    MultiRowV2ShaRecorderV1* recorder)
{
    std::vector<uint32_t> extra{
        program.trace_rows,
        program.trace_columns,
        program.quotient_len,
        program.n_coeffs,
        static_cast<uint32_t>(
            program.base_column_indices.size())};
    extra.insert(
        extra.end(),
        program.base_column_indices.begin(),
        program.base_column_indices.end());
    std::vector<uint256> roots;
    roots.reserve(3);
    for (const auto& group : proof.batch.groups) {
        roots.push_back(
            Fri3AlgDigestToUint256(
                group.row_commit.root));
    }
    const uint256 digest = aq::AirChallengeDigest(
        public_fs_seed,
        "airq_split_rap_fri_seed_v1",
        roots, extra);
    std::vector<unsigned char> preimage;
    {
        static constexpr char tag[] =
            "BTX_RC_AIRQ_V1";
        preimage.insert(
            preimage.end(),
            reinterpret_cast<
                const unsigned char*>(tag),
            reinterpret_cast<
                const unsigned char*>(tag) +
                sizeof(tag) - 1);
        AppendHash(preimage, public_fs_seed);
        const char* label =
            "airq_split_rap_fri_seed_v1";
        AppendU32(
            preimage,
            static_cast<uint32_t>(
                std::strlen(label)));
        preimage.insert(
            preimage.end(),
            reinterpret_cast<
                const unsigned char*>(label),
            reinterpret_cast<
                const unsigned char*>(label) +
                std::strlen(label));
        AppendU32(
            preimage,
            static_cast<uint32_t>(
                roots.size()));
        for (const uint256& root : roots) {
            AppendHash(preimage, root);
        }
        AppendU32(
            preimage,
            static_cast<uint32_t>(
                extra.size()));
        for (const uint32_t value : extra) {
            AppendU32(preimage, value);
        }
    }
    constexpr uint64_t AIRQ_TAG_BYTES =
        sizeof("BTX_RC_AIRQ_V1") - 1;
    const uint64_t label_bytes =
        sizeof("airq_split_rap_fri_seed_v1") - 1;
    const uint64_t preimage_bytes =
        AIRQ_TAG_BYTES + 32 + 4 +
        label_bytes + 4 +
        uint64_t{32} * roots.size() + 4 +
        uint64_t{4} * extra.size();
    if (recorder != nullptr &&
        (preimage_bytes >
             std::numeric_limits<uint32_t>::max() ||
         !recorder->Record(
             MultiRowV2TranscriptShaCallKindV1::
                 FriSeed,
             0, 0, 0,
             static_cast<uint32_t>(
                 preimage_bytes),
             preimage,
             digest, false))) {
        return {};
    }
    return digest;
}

bool ReplayMultiRowV2TranscriptV1(
    const MultiRowV2SplitRapProgramV1& program,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed,
    MultiRowV2ShaRecorderV1& recorder,
    MultiRowV2TranscriptReplayV1& out)
{
    const uint256 fri_seed =
        DeriveMultiRowFriSeedV1(
            program, proof, public_fs_seed,
            &recorder);
    if (fri_seed.IsNull()) return false;
    const auto& batch = proof.batch;
    MultiRowV2FsV1 fs(
        fri_seed, batch, &recorder);
    uint32_t z_counter = 0;
    auto sample_z =
        [&](const Fp3* distinct, Fp3& selected) {
            std::array<
                Fp3,
                kRCFri3AlgDualOodCandidates> candidates{};
            for (Fp3& candidate : candidates) {
                if (!fs.UniformFp3(
                        "fra3_z", z_counter++,
                        MultiRowV2TranscriptShaCallKindV1::
                            OodCandidate,
                        candidate)) {
                    return false;
                }
            }
            for (const Fp3& candidate :
                 candidates) {
                if (gf::Canonical(candidate.c1) == 0 &&
                    gf::Canonical(candidate.c2) == 0) {
                    continue;
                }
                if (distinct != nullptr &&
                    gf::Eq(candidate, *distinct)) {
                    continue;
                }
                selected = candidate;
                return true;
            }
            return false;
        };
    if (!sample_z(nullptr, out.z1) ||
        !sample_z(&out.z1, out.z2)) {
        return false;
    }
    fs.Absorb(out.z1);
    fs.Absorb(out.z2);
    for (uint32_t column = 0;
         column < batch.column_len.size();
         ++column) {
        fs.Absorb(batch.evals_z1[column]);
        fs.Absorb(batch.evals_z2[column]);
    }
    out.alphas.resize(
        batch.column_len.size());
    for (uint32_t column = 0;
         column < out.alphas.size();
         ++column) {
        if (!fs.UniformFp3(
                "fra3_batch_coeff",
                column,
                MultiRowV2TranscriptShaCallKindV1::
                    IndependentPcsAlpha,
                out.alphas[column])) {
            return false;
        }
    }
    for (const Fp3& alpha : out.alphas) {
        fs.Absorb(alpha);
    }
    if (!fs.UniformFp3(
            "fra3_w", 0,
            MultiRowV2TranscriptShaCallKindV1::
                DeepWeight,
            out.w1) ||
        !fs.UniformFp3(
            "fra3_w", 1,
            MultiRowV2TranscriptShaCallKindV1::
                DeepWeight,
            out.w2)) {
        return false;
    }
    fs.Absorb(out.w1);
    fs.Absorb(out.w2);
    out.fold_challenges.resize(
        batch.fold_challenges.size());
    for (uint32_t layer = 0;
         layer < batch.fold_layers.size();
         ++layer) {
        fs.Absorb(
            batch.fold_layers[layer].root);
        if (layer <
            out.fold_challenges.size()) {
            if (!fs.UniformFp3(
                    "fra3_fold", layer,
                    MultiRowV2TranscriptShaCallKindV1::
                        FoldChallenge,
                    out.fold_challenges[layer])) {
                return false;
            }
        }
    }
    out.query_indices.resize(
        batch.queries.size());
    for (uint32_t query = 0;
         query < out.query_indices.size();
         ++query) {
        if (!fs.UniformIndex(
                query, program.n_lde,
                out.query_indices[query])) {
            return false;
        }
    }
    out.sha_calls = std::move(recorder.calls);
    out.valid = true;
    return true;
}

uint256 CommitMultiRowV2ShaShardV1(
    const MultiRowV2TranscriptShaShardV1& shard,
    const std::vector<
        MultiRowV2TranscriptShaCallV1>& calls)
{
    if (shard.compression_count == 0 ||
        shard.compression_count > 63 ||
        shard.first_call > shard.last_call ||
        shard.last_call >= calls.size()) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_MULTI_ROW_V2_SHA_SHARD_V1";
    hash << shard.shard;
    hash << shard.compression_begin;
    hash << shard.compression_count;
    hash << shard.first_call;
    hash << shard.last_call;
    for (uint32_t call = shard.first_call;
         call <= shard.last_call; ++call) {
        hash << calls[call].call_statement;
    }
    return hash.GetHash();
}

uint256 CommitMultiRowV2RecursiveNodeV1(
    const MultiRowV2TranscriptRecursiveNodeV1& node)
{
    if (node.child_count == 0 ||
        node.child_count > 4) {
        return {};
    }
    HashWriter hash;
    hash <<
        "BTX_RC_STAGE3_MULTI_ROW_V2_SHA_ARITY4_V1";
    hash << node.level;
    hash << node.index;
    hash << node.child_count;
    for (uint32_t child = 0; child < 4; ++child) {
        if ((child < node.child_count) ==
                node.child_statements[child].IsNull()) {
            return {};
        }
        hash << node.child_statements[child];
    }
    return hash.GetHash();
}

MultiRowV2TranscriptShaPlanV1
BuildMultiRowV2TranscriptShaPlanV1(
    const std::vector<
        MultiRowV2TranscriptShaCallV1>& calls)
{
    MultiRowV2TranscriptShaPlanV1 out;
    out.calls = calls;
    if (calls.empty()) {
        out.note =
            "stage3:verifier_air:sha_plan:no_calls";
        return out;
    }
    uint64_t cursor = 0;
    for (uint32_t ordinal = 0;
         ordinal < calls.size(); ++ordinal) {
        const auto& call = calls[ordinal];
        if (call.ordinal != ordinal ||
            call.call_statement.IsNull() ||
            call.call_statement !=
                CommitMultiRowV2ShaCallV1(call) ||
            call.unique_compression_begin != cursor ||
            call.unique_compression_count !=
                call.new_shared_prefix_blocks +
                call.first_round_tail_blocks +
                call.second_round_blocks ||
            call.second_round_blocks != 1 ||
            call.naive_compression_count !=
                call.shared_prefix_blocks +
                call.first_round_tail_blocks +
                call.second_round_blocks ||
            call.preimage.size() !=
                call.transcript_bytes +
                    call.suffix_bytes ||
            Hash(call.preimage) !=
                call.digest) {
            out.note =
                "stage3:verifier_air:sha_plan:call";
            return out;
        }
        cursor += call.unique_compression_count;
        out.naive_compressions +=
            call.naive_compression_count;
        out.unique_shared_prefix_compressions +=
            call.new_shared_prefix_blocks;
        out.unique_call_tail_compressions +=
            call.first_round_tail_blocks +
            call.second_round_blocks;
    }
    out.unique_total_compressions = cursor;
    out.sha256d_calls =
        static_cast<uint32_t>(calls.size());
    if (cursor == 0) {
        out.note =
            "stage3:verifier_air:sha_plan:no_compressions";
        return out;
    }
    for (uint64_t begin = 0;
         begin < cursor;
         begin += out.max_compressions_per_shard) {
        MultiRowV2TranscriptShaShardV1 shard;
        shard.shard =
            static_cast<uint32_t>(out.shards.size());
        shard.compression_begin = begin;
        shard.compression_count =
            static_cast<uint32_t>(
                std::min<uint64_t>(
                    out.max_compressions_per_shard,
                    cursor - begin));
        const uint64_t end =
            begin + shard.compression_count;
        shard.first_call = UINT32_MAX;
        shard.last_call = UINT32_MAX;
        for (const auto& call : calls) {
            const uint64_t call_begin =
                call.unique_compression_begin;
            const uint64_t call_end =
                call_begin +
                call.unique_compression_count;
            if (call_begin < end &&
                begin < call_end) {
                if (shard.first_call ==
                    UINT32_MAX) {
                    shard.first_call =
                        call.ordinal;
                }
                shard.last_call = call.ordinal;
            }
        }
        if (shard.first_call == UINT32_MAX) {
            out.note =
                "stage3:verifier_air:sha_plan:"
                "unowned_compression";
            return out;
        }
        shard.shard_statement =
            CommitMultiRowV2ShaShardV1(
                shard, calls);
        if (shard.shard_statement.IsNull()) {
            out.note =
                "stage3:verifier_air:sha_plan:"
                "shard_statement";
            return out;
        }
        out.shards.push_back(shard);
    }
    out.parent_shards =
        static_cast<uint32_t>(out.shards.size());

    std::vector<uint256> level;
    level.reserve(out.shards.size());
    for (const auto& shard : out.shards) {
        level.push_back(shard.shard_statement);
    }
    uint32_t level_number = 1;
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve(
            static_cast<size_t>(
                CeilDiv(level.size(), uint64_t{4})));
        for (uint32_t begin = 0;
             begin < level.size(); begin += 4) {
            MultiRowV2TranscriptRecursiveNodeV1 node;
            node.level = level_number;
            node.index =
                static_cast<uint32_t>(next.size());
            node.child_count =
                std::min<uint32_t>(
                    4,
                    static_cast<uint32_t>(
                        level.size() - begin));
            for (uint32_t child = 0;
                 child < node.child_count;
                 ++child) {
                node.child_statements[child] =
                    level[begin + child];
            }
            node.node_statement =
                CommitMultiRowV2RecursiveNodeV1(node);
            if (node.node_statement.IsNull()) {
                out.note =
                    "stage3:verifier_air:sha_plan:"
                    "recursive_node";
                return out;
            }
            next.push_back(node.node_statement);
            out.recursive_nodes.push_back(node);
        }
        level = std::move(next);
        ++level_number;
    }
    out.recursive_levels =
        level_number - 1;
    out.recursive_root_statement =
        level.front();
    HashWriter schedule;
    schedule <<
        "BTX_RC_STAGE3_MULTI_ROW_V2_SHA_SCHEDULE_V1";
    schedule << out.version;
    schedule << out.max_compressions_per_shard;
    schedule << out.naive_compressions;
    schedule <<
        out.unique_shared_prefix_compressions;
    schedule <<
        out.unique_call_tail_compressions;
    schedule << out.unique_total_compressions;
    schedule << out.sha256d_calls;
    schedule << out.parent_shards;
    schedule << out.recursive_levels;
    for (const auto& call : out.calls) {
        schedule << call.call_statement;
    }
    for (const auto& shard : out.shards) {
        schedule << shard.shard_statement;
    }
    schedule << out.recursive_root_statement;
    out.schedule_statement = schedule.GetHash();
    out.exact_call_order = true;
    out.every_compression_sharded_once = true;
    out.shard_capacity_respected =
        std::all_of(
            out.shards.begin(), out.shards.end(),
            [](const auto& shard) {
                return shard.compression_count > 0 &&
                    shard.compression_count <= 63;
            });
    out.arity_four_manifest_complete =
        !out.recursive_root_statement.IsNull();
    out.sha_shard_proofs_execute = false;
    out.normalized_recursive_consumption_complete =
        false;
    out.valid =
        !out.schedule_statement.IsNull() &&
        out.exact_call_order &&
        out.every_compression_sharded_once &&
        out.shard_capacity_respected &&
        out.arity_four_manifest_complete &&
        out.proof_owned_shards == 0 &&
        out.recursively_consumed_shards == 0 &&
        !out.sha_shard_proofs_execute &&
        !out.normalized_recursive_consumption_complete;
    out.note = out.valid
        ? "stage3:verifier_air:sha_plan:"
          "exact_shared_prefix;sharded63;"
          "arity4_manifest;execution_pending"
        : "stage3:verifier_air:sha_plan:invalid";
    return out;
}

uint256 CommitMultiRowV2OutputsV1(
    const std::vector<
        MultiRowV2VerifierOutputV1>& outputs)
{
    if (outputs.empty()) return {};
    HashWriter hash;
    hash << kMultiRowV2OutputDomainV1;
    hash << uint16_t{1};
    hash << static_cast<uint32_t>(
        outputs.size());
    for (const auto& output : outputs) {
        hash << static_cast<uint8_t>(
            output.kind);
        hash << output.item;
        hash << output.coordinate;
        HashFp3(hash, output.value);
    }
    return hash.GetHash();
}

bool SameMultiRowV2ConstraintShapeV1(
    const aq::AirConstraintSystem<Fp3>& lhs,
    const aq::AirConstraintSystem<Fp3>& rhs)
{
    if (lhs.n_rows != rhs.n_rows ||
        lhs.n_columns != rhs.n_columns ||
        lhs.preprocessed_pin_ood !=
            rhs.preprocessed_pin_ood ||
        lhs.constraints.size() !=
            rhs.constraints.size() ||
        lhs.preprocessed.size() !=
            rhs.preprocessed.size()) {
        return false;
    }
    for (uint32_t index = 0;
         index < lhs.constraints.size();
         ++index) {
        if (lhs.constraints[index].name == nullptr ||
            rhs.constraints[index].name == nullptr ||
            std::strcmp(
                lhs.constraints[index].name,
                rhs.constraints[index].name) != 0 ||
            lhs.constraints[index].kind !=
                rhs.constraints[index].kind ||
            lhs.constraints[index].alg_degree !=
                rhs.constraints[index].alg_degree) {
            return false;
        }
    }
    for (uint32_t index = 0;
         index < lhs.preprocessed.size();
         ++index) {
        if (lhs.preprocessed[index].first !=
                rhs.preprocessed[index].first ||
            lhs.preprocessed[index].second.size() !=
                rhs.preprocessed[index].second.size()) {
            return false;
        }
        for (uint32_t row = 0;
             row <
                 lhs.preprocessed[index]
                     .second.size();
             ++row) {
            if (!gf::Eq(
                    lhs.preprocessed[index]
                        .second[row],
                    rhs.preprocessed[index]
                        .second[row])) {
                return false;
            }
        }
    }
    return true;
}

} // namespace

bool ValidateMultiRowV2TranscriptShaPlanV1(
    const MultiRowV2TranscriptShaPlanV1& plan,
    std::string* why)
{
    const auto expected =
        BuildMultiRowV2TranscriptShaPlanV1(
            plan.calls);
    if (!plan.valid || !expected.valid ||
        plan.version != expected.version ||
        plan.max_compressions_per_shard !=
            expected.max_compressions_per_shard ||
        plan.naive_compressions !=
            expected.naive_compressions ||
        plan.unique_shared_prefix_compressions !=
            expected.unique_shared_prefix_compressions ||
        plan.unique_call_tail_compressions !=
            expected.unique_call_tail_compressions ||
        plan.unique_total_compressions !=
            expected.unique_total_compressions ||
        plan.sha256d_calls !=
            expected.sha256d_calls ||
        plan.parent_shards !=
            expected.parent_shards ||
        plan.recursive_levels !=
            expected.recursive_levels ||
        plan.proof_owned_shards != 0 ||
        plan.recursively_consumed_shards != 0 ||
        plan.schedule_statement !=
            expected.schedule_statement ||
        plan.recursive_root_statement !=
            expected.recursive_root_statement ||
        plan.calls != expected.calls ||
        plan.shards != expected.shards ||
        plan.recursive_nodes !=
            expected.recursive_nodes ||
        !plan.exact_call_order ||
        !plan.every_compression_sharded_once ||
        !plan.shard_capacity_respected ||
        !plan.arity_four_manifest_complete ||
        plan.sha_shard_proofs_execute ||
        plan.normalized_recursive_consumption_complete) {
        return Fail(
            why, "multi_row_v2_sha_plan");
    }
    if (why != nullptr) {
        *why =
            "stage3:verifier_air:multi_row_v2_sha_plan:"
            "exact_schedule_execution_pending";
    }
    return true;
}

MultiRowV2TranscriptShaExecutionPlanV1
BuildMultiRowV2TranscriptShaExecutionPlanV1(
    const MultiRowV2TranscriptShaPlanV1& plan)
{
    MultiRowV2TranscriptShaExecutionPlanV1 out;
    std::string why;
    if (!ValidateMultiRowV2TranscriptShaPlanV1(
            plan, &why)) {
        out.note =
            "stage3:verifier_air:sha_execution:"
            "schedule:" + why;
        return out;
    }
    const auto program =
        stage3_hash_air::BuildCanonicalProgram(
            stage3_hash_air::ProgramKind::
                Sha256Compression);
    if (!stage3_hash_air::ValidateCanonicalProgram(
            program, &why)) {
        out.note =
            "stage3:verifier_air:sha_execution:"
            "program:" + why;
        return out;
    }
    out.calls =
        static_cast<uint32_t>(
            plan.calls.size());
    out.manifests.reserve(plan.calls.size());
    out.call_execution.reserve(
        plan.calls.size());
    for (const auto& call : plan.calls) {
        stage3_hash_air::ShaManifest manifest;
        if (!stage3_hash_air::BuildShaManifest(
                call.preimage,
                stage3_hash_air::ShaMode::Double,
                manifest, &why)) {
            out.note =
                "stage3:verifier_air:sha_execution:"
                "manifest:" + why;
            return out;
        }
        const uint256 digest{
            Span<const unsigned char>{
                manifest.digest.data(),
                manifest.digest.size()}};
        if (digest != call.digest ||
            manifest.preimage != call.preimage) {
            out.note =
                "stage3:verifier_air:sha_execution:"
                "digest";
            return out;
        }
        std::vector<
            stage3_hash_air::
                FixedProgramBoundaryInstance>
            boundaries;
        if (!stage3_hash_air::
                BuildShaManifestBoundaryInstances(
                    manifest, boundaries, &why) ||
            boundaries.empty() ||
            boundaries.size() !=
                call.naive_compression_count) {
            out.note =
                "stage3:verifier_air:sha_execution:"
                "boundaries:" + why;
            return out;
        }
        MultiRowV2TranscriptShaCallExecutionV1
            execution;
        execution.ordinal = call.ordinal;
        execution.first_boundary =
            static_cast<uint32_t>(
                out.boundaries.size());
        execution.compression_count =
            static_cast<uint32_t>(
                boundaries.size());
        execution.manifest_commitment =
            manifest.commitment;
        execution.digest = digest;
        out.compression_instances +=
            boundaries.size();
        out.boundaries.insert(
            out.boundaries.end(),
            std::make_move_iterator(
                boundaries.begin()),
            std::make_move_iterator(
                boundaries.end()));
        out.call_execution.push_back(
            execution);
        out.manifests.push_back(
            std::move(manifest));
    }
    out.vertical_shards =
        static_cast<uint32_t>(
            (out.compression_instances +
             out.max_compressions_per_shard - 1) /
            out.max_compressions_per_shard);
    out.exact_preimages =
        out.calls == plan.calls.size() &&
        std::all_of(
            plan.calls.begin(),
            plan.calls.end(),
            [](const auto& call) {
                return !call.preimage.empty() &&
                    call.preimage.size() ==
                        call.transcript_bytes +
                            call.suffix_bytes &&
                    Hash(call.preimage) ==
                        call.digest;
            });
    out.exact_sha256d_padding_and_chaining =
        out.boundaries.size() ==
            out.compression_instances &&
        out.compression_instances != 0;
    out.every_digest_matches_call =
        out.call_execution.size() ==
            plan.calls.size();
    out.canonical_compression_program = true;
    out.witness_owned_inputs_linked_to_proof_codec =
        false;
    out.challenge_selection_air_constrained =
        false;
    out.query_reduction_air_constrained =
        false;
    out.recursively_consumed = false;
    out.valid =
        out.exact_preimages &&
        out.exact_sha256d_padding_and_chaining &&
        out.every_digest_matches_call &&
        out.canonical_compression_program &&
        !out.witness_owned_inputs_linked_to_proof_codec &&
        !out.challenge_selection_air_constrained &&
        !out.query_reduction_air_constrained &&
        !out.recursively_consumed;
    out.note = out.valid
        ? "stage3:verifier_air:sha_execution:"
          "exact_preimages_and_boundaries;"
          "proof_codec_selection_recursion_open"
        : "stage3:verifier_air:sha_execution:invalid";
    return out;
}

bool ValidateMultiRowV2TranscriptShaExecutionPlanV1(
    const MultiRowV2TranscriptShaPlanV1& schedule,
    const MultiRowV2TranscriptShaExecutionPlanV1&
        execution,
    std::string* why)
{
    const auto expected =
        BuildMultiRowV2TranscriptShaExecutionPlanV1(
            schedule);
    if (!expected.valid ||
        execution != expected) {
        return Fail(
            why, "multi_row_v2_sha_execution");
    }
    if (why != nullptr) {
        *why =
            "stage3:verifier_air:"
            "multi_row_v2_sha_execution:"
            "exact_boundaries_recursion_open";
    }
    return true;
}

namespace {

bool ShaVerticalBoundaryAirSatisfies(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) return false;
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) return false;
    }
    std::vector<Fp3> cur(cs.n_columns);
    std::vector<Fp3> next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t col = 0; col < cs.n_columns; ++col) {
            cur[col] = columns[col][row];
            next[col] = columns[col][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            if (constraint.kind == aq::AirKind::kTransition &&
                row + 1 == cs.n_rows) {
                continue;
            }
            if (constraint.kind == aq::AirKind::kFirstRow &&
                row != 0) {
                continue;
            }
            if (constraint.kind == aq::AirKind::kLastRow &&
                row + 1 != cs.n_rows) {
                continue;
            }
            if (!gf::IsZero(constraint.eval(cur, next))) {
                return false;
            }
        }
    }
    return true;
}

/** Build chained vertical SHA256d boundary AIR for one exact preimage. */
bool BuildAndCheckShaCallVerticalBoundaryAir(
    const std::vector<unsigned char>& preimage,
    const uint256& expected_digest,
    const uint256& air_seed,
    uint32_t* compression_count,
    stage3_hash_air::FixedProgramVerticalWitnessBoundaryInstance*
        instance_out,
    std::string* why)
{
    namespace ha = stage3_hash_air;
    ha::ShaManifest manifest;
    if (!ha::BuildShaManifest(
            preimage, ha::ShaMode::Double, manifest, why)) {
        return false;
    }
    const uint256 digest{
        Span<const unsigned char>{
            manifest.digest.data(),
            manifest.digest.size()}};
    if (digest != expected_digest) {
        if (why != nullptr) {
            *why = "sha_call_digest_mismatch";
        }
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(
            manifest, boundaries, why) ||
        boundaries.empty() ||
        boundaries.size() !=
            manifest.first.padded_blocks.size() + 1) {
        if (why != nullptr && why->empty()) {
            *why = "sha_call_boundaries";
        }
        return false;
    }
    if (boundaries.size() >
        ha::kFixedProgramVerticalSemanticInstances) {
        if (why != nullptr) {
            *why = "sha_call_shard_capacity";
        }
        return false;
    }
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::vector<std::vector<uint8_t>> public_masks(
        boundaries.size(),
        std::vector<uint8_t>(
            program.external_address_count, 1));
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    const uint32_t first_blocks =
        static_cast<uint32_t>(
            manifest.first.padded_blocks.size());
    for (uint32_t block = 0; block < first_blocks; ++block) {
        const uint32_t target =
            block + 1 < first_blocks ? block + 1
                                     : first_blocks;
        const uint32_t target_address =
            block + 1 < first_blocks ? 17 : 1;
        for (uint32_t word = 0; word < 8; ++word) {
            links.push_back({
                .source_instance = block,
                .source_final_word = word,
                .target_instance = target,
                .target_external_address =
                    target_address + word,
            });
            public_masks[target]
                [target_address + word - 1] = 0;
        }
    }
    auto instance =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, boundaries, public_masks, links,
            air_seed);
    if (!instance.valid) {
        if (why != nullptr) {
            *why = instance.note;
        }
        return false;
    }
    if (!ShaVerticalBoundaryAirSatisfies(
            instance.cs, instance.columns)) {
        if (why != nullptr) {
            *why = "sha_call_boundary_air_violations";
        }
        return false;
    }
    if (compression_count != nullptr) {
        *compression_count =
            static_cast<uint32_t>(boundaries.size());
    }
    if (instance_out != nullptr) {
        *instance_out = std::move(instance);
    }
    return true;
}

} // namespace

FiatShamirShaRecursivelyConsumedV1
MeasureFiatShamirShaRecursivelyConsumedV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    namespace ha = stage3_hash_air;
    FiatShamirShaRecursivelyConsumedV1 out;
    const FiatShamirShaExecutionPlanV1 plan =
        BuildFiatShamirShaExecutionPlanV1(
            program, child_fs_seed, child_proof);
    out.digest_plan_ready =
        plan.valid && plan.every_digest_matches_claim;
    if (!out.digest_plan_ready) {
        out.note =
            "stage3:verifier_air:fs_sha_recursive:"
            "digest_plan_open:" +
            plan.note;
        return out;
    }
    out.sha_calls = plan.calls;
    out.compression_instances =
        plan.compression_instances;

    MultiRowV2ShaRecorderV1 recorder;
    for (uint32_t i = 0; i < plan.call.size(); ++i) {
        const auto& call = plan.call[i];
        if (call.preimage.empty() ||
            !recorder.Record(
                MultiRowV2TranscriptShaCallKindV1::
                    QueryIndex,
                i,
                0,
                /*transcript_bytes=*/0,
                static_cast<uint32_t>(call.preimage.size()),
                call.preimage,
                call.digest,
                /*share_transcript_prefix=*/false)) {
            out.note =
                "stage3:verifier_air:fs_sha_recursive:"
                "record_call";
            return out;
        }
    }
    const MultiRowV2TranscriptShaPlanV1 schedule =
        BuildMultiRowV2TranscriptShaPlanV1(recorder.calls);
    out.parent_shards = schedule.parent_shards;
    out.recursive_levels = schedule.recursive_levels;
    out.recursive_nodes =
        static_cast<uint32_t>(schedule.recursive_nodes.size());
    out.schedule_exact =
        schedule.valid &&
        schedule.exact_call_order &&
        schedule.every_compression_sharded_once &&
        schedule.shard_capacity_respected &&
        schedule.arity_four_manifest_complete &&
        schedule.sha256d_calls == plan.calls &&
        !schedule.schedule_statement.IsNull() &&
        !schedule.recursive_root_statement.IsNull();
    if (!out.schedule_exact) {
        out.note =
            "stage3:verifier_air:fs_sha_recursive:"
            "schedule:" +
            schedule.note;
        return out;
    }

    // Recompute every shard / arity-4 node statement; collect leaf coverage.
    std::set<uint256> shard_statements;
    for (const auto& shard : schedule.shards) {
        const uint256 recomputed =
            CommitMultiRowV2ShaShardV1(
                shard, schedule.calls);
        if (recomputed.IsNull() ||
            recomputed != shard.shard_statement) {
            out.note =
                "stage3:verifier_air:fs_sha_recursive:"
                "shard_statement";
            return out;
        }
        shard_statements.insert(shard.shard_statement);
    }
    std::set<uint256> leaf_statements;
    if (schedule.recursive_nodes.empty()) {
        // Single-shard canary: the root IS the sole shard statement.
        if (schedule.shards.size() != 1 ||
            schedule.recursive_root_statement !=
                schedule.shards.front().shard_statement) {
            out.note =
                "stage3:verifier_air:fs_sha_recursive:"
                "single_shard_root";
            return out;
        }
        leaf_statements.insert(
            schedule.shards.front().shard_statement);
    } else {
        for (const auto& node : schedule.recursive_nodes) {
            const uint256 recomputed =
                CommitMultiRowV2RecursiveNodeV1(node);
            if (recomputed.IsNull() ||
                recomputed != node.node_statement) {
                out.note =
                    "stage3:verifier_air:fs_sha_recursive:"
                    "node_statement";
                return out;
            }
            if (node.level == 1) {
                for (uint32_t child = 0;
                     child < node.child_count; ++child) {
                    leaf_statements.insert(
                        node.child_statements[child]);
                }
            }
        }
        if (schedule.recursive_root_statement !=
            schedule.recursive_nodes.back().node_statement &&
            schedule.recursive_levels > 0) {
            // Root must equal the unique top-level node statement.
            bool root_found = false;
            for (const auto& node : schedule.recursive_nodes) {
                if (node.node_statement ==
                    schedule.recursive_root_statement) {
                    root_found = true;
                    break;
                }
            }
            if (!root_found) {
                out.note =
                    "stage3:verifier_air:fs_sha_recursive:"
                    "root_missing";
                return out;
            }
        }
    }
    out.arity_four_join_complete =
        leaf_statements == shard_statements &&
        shard_statements.size() == schedule.shards.size();
    out.shards_joined =
        static_cast<uint32_t>(leaf_statements.size());
    if (!out.arity_four_join_complete) {
        out.note =
            "stage3:verifier_air:fs_sha_recursive:"
            "arity4_leaf_coverage";
        return out;
    }

    // Per-call exact SHA256d boundary inventory + one vertical AIR canary on
    // the first call (recursive consumer seam). Full FRI / whole-verifier
    // SHA equations remain the separate gap predicate.
    HashWriter seed_hash;
    seed_hash << "BTX_RC_STAGE3_FS_SHA_RECURSIVE_AIR_V1";
    seed_hash << child_fs_seed;
    seed_hash << schedule.schedule_statement;
    const uint256 air_seed = seed_hash.GetHash();
    ha::FixedProgramVerticalWitnessBoundaryInstance
        first_instance;
    bool have_first = false;
    std::vector<ha::FixedProgramBoundaryInstance>
        first_boundaries;
    const auto program_sha =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    for (uint32_t i = 0; i < plan.call.size(); ++i) {
        const auto& call = plan.call[i];
        ha::ShaManifest manifest;
        std::string why;
        if (!ha::BuildShaManifest(
                call.preimage, ha::ShaMode::Double,
                manifest, &why)) {
            out.note =
                "stage3:verifier_air:fs_sha_recursive:"
                "manifest:" +
                why;
            return out;
        }
        const uint256 digest{
            Span<const unsigned char>{
                manifest.digest.data(),
                manifest.digest.size()}};
        if (digest != call.digest) {
            out.note =
                "stage3:verifier_air:fs_sha_recursive:"
                "digest_mismatch";
            return out;
        }
        std::vector<ha::FixedProgramBoundaryInstance>
            boundaries;
        if (!ha::BuildShaManifestBoundaryInstances(
                manifest, boundaries, &why) ||
            boundaries.empty() ||
            boundaries.size() !=
                manifest.first.padded_blocks.size() + 1 ||
            boundaries.size() >
                ha::kFixedProgramVerticalSemanticInstances) {
            out.note =
                "stage3:verifier_air:fs_sha_recursive:"
                "boundaries:" +
                why;
            return out;
        }
        if (!have_first) {
            HashWriter call_seed;
            call_seed << air_seed;
            call_seed << i;
            uint32_t compressions = 0;
            if (!BuildAndCheckShaCallVerticalBoundaryAir(
                    call.preimage, call.digest,
                    call_seed.GetHash(), &compressions,
                    &first_instance, &why)) {
                out.note =
                    "stage3:verifier_air:fs_sha_recursive:"
                    "boundary_air:" +
                    why;
                return out;
            }
            first_boundaries = std::move(boundaries);
            have_first = true;
        }
        ++out.calls_boundary_air_green;
    }
    out.shard_boundary_airs_execute =
        out.calls_boundary_air_green == plan.calls &&
        plan.calls > 0 && have_first &&
        first_instance.valid;

    // Tamper 1: flip a level-1 child statement (or relabel the sole shard).
    out.join_tamper_rejects = false;
    if (schedule.recursive_nodes.empty()) {
        auto relabel = schedule.shards.front();
        relabel.shard_statement.data()[0] ^= 1U;
        out.join_tamper_rejects =
            CommitMultiRowV2ShaShardV1(
                relabel, schedule.calls) !=
            relabel.shard_statement;
    } else {
        auto node = schedule.recursive_nodes.front();
        for (const auto& candidate :
             schedule.recursive_nodes) {
            if (candidate.level == 1) {
                node = candidate;
                break;
            }
        }
        const uint256 honest =
            CommitMultiRowV2RecursiveNodeV1(node);
        node.child_statements[0].data()[0] ^= 1U;
        const uint256 bad =
            CommitMultiRowV2RecursiveNodeV1(node);
        out.join_tamper_rejects =
            !honest.IsNull() &&
            (bad.IsNull() || bad != honest);
    }

    // Tamper 2: flip a final digest word on the first call's boundaries.
    out.boundary_tamper_rejects = false;
    if (have_first && !first_boundaries.empty()) {
        auto forged = first_boundaries;
        forged.back().final_words[0] ^= 1U;
        std::vector<std::vector<uint8_t>> public_masks(
            forged.size(),
            std::vector<uint8_t>(
                program_sha.external_address_count, 1));
        std::vector<ha::FixedProgramWitnessBoundaryLink> links;
        const uint32_t first_blocks =
            static_cast<uint32_t>(forged.size() - 1);
        for (uint32_t block = 0; block < first_blocks;
             ++block) {
            const uint32_t target =
                block + 1 < first_blocks ? block + 1
                                         : first_blocks;
            const uint32_t target_address =
                block + 1 < first_blocks ? 17 : 1;
            for (uint32_t word = 0; word < 8; ++word) {
                links.push_back({
                    .source_instance = block,
                    .source_final_word = word,
                    .target_instance = target,
                    .target_external_address =
                        target_address + word,
                });
                public_masks[target]
                    [target_address + word - 1] = 0;
            }
        }
        HashWriter call_seed;
        call_seed << air_seed;
        call_seed << uint32_t{0};
        const auto bad_instance =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                program_sha, forged, public_masks, links,
                call_seed.GetHash());
        // Forged finals must diverge the public statement or fail to build.
        out.boundary_tamper_rejects =
            !bad_instance.valid ||
            bad_instance.public_statement !=
                first_instance.public_statement;
    }

    out.consumed =
        out.digest_plan_ready && out.schedule_exact &&
        out.arity_four_join_complete &&
        out.shard_boundary_airs_execute &&
        out.join_tamper_rejects &&
        out.boundary_tamper_rejects;
    out.note =
        out.consumed
            ? ("stage3:verifier_air:fs_sha_recursive:ok;"
               "calls=" +
               std::to_string(out.sha_calls) +
               ";shards=" +
               std::to_string(out.parent_shards) +
               ";joined=" +
               std::to_string(out.shards_joined) +
               ";air=" +
               std::to_string(out.calls_boundary_air_green) +
               ";levels=" +
               std::to_string(out.recursive_levels) +
               ";tamper=1")
            : ("stage3:verifier_air:fs_sha_recursive:open;"
               "schedule=" +
               std::to_string(out.schedule_exact ? 1 : 0) +
               ";join=" +
               std::to_string(
                   out.arity_four_join_complete ? 1 : 0) +
               ";air=" +
               std::to_string(
                   out.shard_boundary_airs_execute ? 1
                                                   : 0) +
               ";join_tamper=" +
               std::to_string(
                   out.join_tamper_rejects ? 1 : 0) +
               ";boundary_tamper=" +
               std::to_string(
                   out.boundary_tamper_rejects ? 1 : 0));
    return out;
}


FiatShamirWholeVerifierShaEquationsInAirV1
MeasureFiatShamirWholeVerifierShaEquationsInAirV1(
    const FiatShamirProgram& program,
    const uint256& child_fs_seed,
    const AlgAirProof& child_proof)
{
    namespace ha = stage3_hash_air;
    FiatShamirWholeVerifierShaEquationsInAirV1 out;
    const FiatShamirShaExecutionPlanV1 plan =
        BuildFiatShamirShaExecutionPlanV1(
            program, child_fs_seed, child_proof);
    out.digest_plan_ready =
        plan.valid && plan.every_digest_matches_claim &&
        plan.proof_codec_byte_origins_complete &&
        plan.fixed_schedule;
    if (!out.digest_plan_ready || plan.call.empty()) {
        out.note =
            "stage3:verifier_air:fs_whole_sha:plan_open:" +
            plan.note;
        return out;
    }
    out.sha_calls = plan.calls;

    HashWriter seed_hash;
    seed_hash << "BTX_RC_STAGE3_FS_WHOLE_SHA_AIR_V1";
    seed_hash << child_fs_seed;
    seed_hash << static_cast<uint32_t>(plan.calls);
    const uint256 air_seed = seed_hash.GetHash();

    ha::FixedProgramVerticalWitnessBoundaryInstance first_instance;
    std::vector<ha::FixedProgramBoundaryInstance> first_boundaries;
    bool have_first = false;
    const auto program_sha =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);

    for (uint32_t i = 0; i < plan.call.size(); ++i) {
        const auto& call = plan.call[i];
        if (call.preimage.empty()) {
            out.note =
                "stage3:verifier_air:fs_whole_sha:empty_preimage";
            return out;
        }
        HashWriter call_seed;
        call_seed << air_seed;
        call_seed << i;
        uint32_t compressions = 0;
        ha::FixedProgramVerticalWitnessBoundaryInstance instance;
        std::string why;
        if (!BuildAndCheckShaCallVerticalBoundaryAir(
                call.preimage, call.digest,
                call_seed.GetHash(), &compressions,
                &instance, &why)) {
            out.note =
                "stage3:verifier_air:fs_whole_sha:call_air:" +
                why;
            return out;
        }
        ++out.calls_air_green;
        if (!have_first) {
            ha::ShaManifest manifest;
            if (!ha::BuildShaManifest(
                    call.preimage, ha::ShaMode::Double,
                    manifest, &why) ||
                !ha::BuildShaManifestBoundaryInstances(
                    manifest, first_boundaries, &why)) {
                out.note =
                    "stage3:verifier_air:fs_whole_sha:first_bounds:" +
                    why;
                return out;
            }
            first_instance = std::move(instance);
            have_first = true;
        }
    }
    out.every_call_boundary_air_satisfies =
        out.calls_air_green == plan.calls && plan.calls > 0 &&
        have_first && first_instance.valid;
    if (!out.every_call_boundary_air_satisfies) {
        out.note =
            "stage3:verifier_air:fs_whole_sha:incomplete_air";
        return out;
    }

    out.boundary_tamper_rejects = false;
    if (!first_boundaries.empty()) {
        auto forged = first_boundaries;
        forged.back().final_words[0] ^= 1U;
        std::vector<std::vector<uint8_t>> public_masks(
            forged.size(),
            std::vector<uint8_t>(
                program_sha.external_address_count, 1));
        std::vector<ha::FixedProgramWitnessBoundaryLink> links;
        const uint32_t first_blocks =
            static_cast<uint32_t>(forged.size() - 1);
        for (uint32_t block = 0; block < first_blocks; ++block) {
            const uint32_t target =
                block + 1 < first_blocks ? block + 1
                                         : first_blocks;
            const uint32_t target_address =
                block + 1 < first_blocks ? 17 : 1;
            for (uint32_t word = 0; word < 8; ++word) {
                links.push_back({
                    .source_instance = block,
                    .source_final_word = word,
                    .target_instance = target,
                    .target_external_address =
                        target_address + word,
                });
                public_masks[target]
                    [target_address + word - 1] = 0;
            }
        }
        HashWriter call_seed;
        call_seed << air_seed;
        call_seed << uint32_t{0};
        const auto bad_instance =
            ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
                program_sha, forged, public_masks, links,
                call_seed.GetHash());
        out.boundary_tamper_rejects =
            !bad_instance.valid ||
            bad_instance.public_statement !=
                first_instance.public_statement;
    }
    if (!out.boundary_tamper_rejects) {
        out.note =
            "stage3:verifier_air:fs_whole_sha:tamper_accepted";
        return out;
    }

    out.in_air =
        out.digest_plan_ready &&
        out.every_call_boundary_air_satisfies &&
        out.boundary_tamper_rejects;
    out.note =
        out.in_air
            ? ("stage3:verifier_air:fs_whole_sha:ok;calls=" +
               std::to_string(out.sha_calls) +
               ";air=" +
               std::to_string(out.calls_air_green) +
               ";tamper=1")
            : "stage3:verifier_air:fs_whole_sha:open";
    return out;
}





MultiRowV2SplitRapVerifierWitnessV1
BuildMultiRowV2SplitRapVerifierWitnessV1(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed)
{
    MultiRowV2SplitRapVerifierWitnessV1 out;
    out.public_fs_seed = public_fs_seed;
    out.program_statement =
        program.program_statement;
    std::string why;
    if (!ValidateCanonicalMultiRowV2SplitRapProgramV1(
            child_cs, program, &why) ||
        public_fs_seed.IsNull() ||
        !aq::AirQuotientVerifyRowsSplitRap(
            child_cs, proof,
            program.base_column_indices,
            public_fs_seed, &why)) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "host_reject:" + why;
        return out;
    }
    out.host_verifier_accepted = true;
    out.canonical_program = true;
    out.proof_statement =
        CommitMultiRowV2ProofV1(proof);
    if (out.proof_statement.IsNull()) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "proof_statement";
        return out;
    }

    MultiRowV2TranscriptReplayV1 replay;
    Fp3 air_lambda;
    MultiRowV2ShaRecorderV1 sha_recorder;
    if (!DeriveAirLambdaV1(
            program, proof, public_fs_seed,
            &sha_recorder, air_lambda) ||
        !ReplayMultiRowV2TranscriptV1(
            program, proof, public_fs_seed,
            sha_recorder, replay) ||
        !gf::Eq(
            air_lambda,
            proof.air_constraint_lambda) ||
        !gf::Eq(replay.z1, proof.batch.z1) ||
        !gf::Eq(replay.z2, proof.batch.z2) ||
        replay.alphas.empty() ||
        !gf::Eq(
            replay.alphas[0],
            proof.batch.lambda) ||
        !gf::Eq(replay.w1, proof.batch.w1) ||
        !gf::Eq(replay.w2, proof.batch.w2) ||
        replay.fold_challenges.size() !=
            proof.batch.fold_challenges.size() ||
        replay.query_indices.size() !=
            proof.batch.queries.size()) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "transcript_replay";
        return out;
    }
    for (uint32_t fold = 0;
         fold < replay.fold_challenges.size();
         ++fold) {
        if (!gf::Eq(
                replay.fold_challenges[fold],
                proof.batch.fold_challenges[fold])) {
            out.note =
                "stage3:verifier_air:multi_row_v2_witness:"
                "fold_transcript";
            return out;
        }
    }
    for (uint32_t query = 0;
         query < replay.query_indices.size();
         ++query) {
        if (replay.query_indices[query] !=
            proof.batch.queries[query].index) {
            out.note =
                "stage3:verifier_air:multi_row_v2_witness:"
                "query_transcript";
            return out;
        }
    }
    out.transcript_replayed_exactly = true;
    out.all_independent_pcs_alphas_derived =
        replay.alphas.size() ==
            child_cs.n_columns + 1;
    out.transcript_sha_plan =
        BuildMultiRowV2TranscriptShaPlanV1(
            replay.sha_calls);
    if (!out.transcript_sha_plan.valid ||
        !ValidateMultiRowV2TranscriptShaPlanV1(
            out.transcript_sha_plan, &why)) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "sha_schedule:" + why;
        return out;
    }
    out.transcript_sha_execution =
        BuildMultiRowV2TranscriptShaExecutionPlanV1(
            out.transcript_sha_plan);
    if (!out.transcript_sha_execution.valid ||
        !ValidateMultiRowV2TranscriptShaExecutionPlanV1(
            out.transcript_sha_plan,
            out.transcript_sha_execution,
            &why)) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "sha_execution:" + why;
        return out;
    }

    uint32_t program_row = 0;
    bool append_ok = true;
    const auto append =
        [&](MultiRowV2CheckKindV1 kind,
            uint32_t query,
            uint32_t group,
            uint32_t layer,
            uint32_t item,
            uint32_t active_lanes,
            const std::array<Fp3, 4>& claimed,
            const std::array<Fp3, 4>& expected) {
            const MultiRowV2ProgramRowV1 metadata{
                kind, query, group, layer,
                item, active_lanes};
            if (program_row >= program.active_rows ||
                !(program.rows[program_row] ==
                  metadata)) {
                append_ok = false;
                return;
            }
            out.checks.push_back({
                metadata, claimed, expected});
            ++program_row;
        };
    const auto scalar =
        [](uint64_t value) {
            return Fp3::FromFp(
                gf::FromU64(value));
        };
    const auto fp3 =
        [](const Fp3& value) {
            return CheckValuesV1(
                Fp3::FromFp(
                    gf::Canonical(value.c0)),
                Fp3::FromFp(
                    gf::Canonical(value.c1)),
                Fp3::FromFp(
                    gf::Canonical(value.c2)));
        };
    const auto& batch = proof.batch;
    append(
        MultiRowV2CheckKindV1::ProofMetadata,
        0, 0, 0, 0, 4,
        CheckValuesV1(
            scalar(proof.version),
            scalar(proof.trace_rows),
            scalar(batch.blowup),
            scalar(batch.n_coeffs)),
        CheckValuesV1(
            scalar(1),
            scalar(program.trace_rows),
            scalar(kRCFriBlowup),
            scalar(program.n_coeffs)));
    append(
        MultiRowV2CheckKindV1::ProofMetadata,
        0, 0, 0, 1, 4,
        CheckValuesV1(
            scalar(child_cs.n_columns),
            scalar(program.quotient_len),
            scalar(batch.column_len.size()),
            scalar(batch.queries.size())),
        CheckValuesV1(
            scalar(program.trace_columns),
            scalar(program.quotient_len),
            scalar(program.trace_columns + 1),
            scalar(program.query_count)));
    for (uint32_t position = 0;
         position <
             proof.base_column_indices.size();
         ++position) {
        append(
            MultiRowV2CheckKindV1::BaseColumnIndex,
            0, 0, 0, position, 1,
            CheckValuesV1(
                scalar(
                    proof.base_column_indices[
                        position])),
            CheckValuesV1(
                scalar(
                    program.base_column_indices[
                        position])));
    }
    uint32_t first_column = 0;
    for (uint32_t group = 0; group < 3; ++group) {
        const auto& source = batch.groups[group];
        append(
            MultiRowV2CheckKindV1::GroupMetadata,
            0, group, 0, 0, 4,
            CheckValuesV1(
                scalar(
                    static_cast<uint8_t>(
                        source.role)),
                scalar(source.first_column),
                scalar(source.column_count),
                scalar(
                    source.row_commit.n_leaves)),
            CheckValuesV1(
                scalar(group + 1),
                scalar(first_column),
                scalar(
                    program.group_widths[group]),
                scalar(program.n_lde)));
        append(
            MultiRowV2CheckKindV1::GroupRoot,
            0, group, 0, 0, 4,
            DigestValuesV1(
                source.row_commit.root),
            DigestValuesV1(
                source.row_commit.root));
        first_column +=
            program.group_widths[group];
    }
    for (uint32_t column = 0;
         column < batch.column_len.size();
         ++column) {
        const uint32_t expected =
            column < child_cs.n_columns
            ? program.trace_rows
            : program.quotient_len;
        append(
            MultiRowV2CheckKindV1::ColumnLength,
            0, 0, 0, column, 1,
            CheckValuesV1(
                scalar(batch.column_len[column])),
            CheckValuesV1(scalar(expected)));
    }
    append(
        MultiRowV2CheckKindV1::OodPoint,
        0, 0, 0, 0, 3,
        fp3(batch.z1), fp3(replay.z1));
    append(
        MultiRowV2CheckKindV1::OodPoint,
        0, 0, 0, 1, 3,
        fp3(batch.z2), fp3(replay.z2));
    for (uint32_t column = 0;
         column < batch.column_len.size();
         ++column) {
        append(
            MultiRowV2CheckKindV1::
                EvaluationPairAbsorb,
            0, 0, 0, column, 2,
            CheckValuesV1(
                batch.evals_z1[column],
                batch.evals_z2[column]),
            CheckValuesV1(
                batch.evals_z1[column],
                batch.evals_z2[column]));
    }
    for (uint32_t column = 0;
         column < replay.alphas.size();
         ++column) {
        const auto claimed =
            column == 0
            ? fp3(batch.lambda)
            : fp3(replay.alphas[column]);
        append(
            MultiRowV2CheckKindV1::
                IndependentPcsAlpha,
            0, 0, 0, column, 3,
            claimed, fp3(replay.alphas[column]));
    }
    append(
        MultiRowV2CheckKindV1::DeepWeight,
        0, 0, 0, 0, 3,
        fp3(batch.w1), fp3(replay.w1));
    append(
        MultiRowV2CheckKindV1::DeepWeight,
        0, 0, 0, 1, 3,
        fp3(batch.w2), fp3(replay.w2));
    for (uint32_t layer = 0;
         layer < batch.fold_layers.size();
         ++layer) {
        append(
            MultiRowV2CheckKindV1::FoldRoot,
            0, 0, layer, 0, 4,
            DigestValuesV1(
                batch.fold_layers[layer].root),
            DigestValuesV1(
                batch.fold_layers[layer].root));
        if (layer <
            batch.fold_challenges.size()) {
            append(
                MultiRowV2CheckKindV1::FoldChallenge,
                0, 0, layer, 0, 3,
                fp3(batch.fold_challenges[layer]),
                fp3(replay.fold_challenges[layer]));
        }
    }
    std::vector<alg_hash::State>
        poseidon_inputs;
    poseidon_inputs.reserve(
        program.poseidon_permutation_rows);
    const Fri3AlgDigest terminal_root =
        ConstantFoldRootV1(
            batch.final_value,
            batch.blowup,
            &poseidon_inputs);
    append(
        MultiRowV2CheckKindV1::TerminalFinalValue,
        0, 0, program.fold_count, 0, 3,
        fp3(batch.final_value),
        fp3(batch.final_value));
    append(
        MultiRowV2CheckKindV1::TerminalRoot,
        0, 0, program.fold_count, 0, 4,
        DigestValuesV1(
            batch.fold_layers.back().root),
        DigestValuesV1(terminal_root));
    if (!SameDigestV1(
            terminal_root,
            batch.fold_layers.back().root)) {
        append_ok = false;
    }
    for (uint32_t query = 0;
         query < batch.queries.size();
         ++query) {
        append(
            MultiRowV2CheckKindV1::QueryIndex,
            query, 0, 0, 0, 1,
            CheckValuesV1(
                scalar(batch.queries[query].index)),
            CheckValuesV1(
                scalar(replay.query_indices[query])));
    }

    std::vector<uint32_t> dependent_indices;
    std::vector<uint8_t> is_base(
        child_cs.n_columns, 0);
    for (uint32_t column :
         program.base_column_indices) {
        is_base[column] = 1;
    }
    for (uint32_t column = 0;
         column < child_cs.n_columns;
         ++column) {
        if (!is_base[column]) {
            dependent_indices.push_back(column);
        }
    }
    Fp3 v1 = Fp3::Zero();
    Fp3 v2 = Fp3::Zero();
    for (uint32_t column = 0;
         column < replay.alphas.size();
         ++column) {
        const uint32_t shift =
            program.n_coeffs -
            batch.column_len[column];
        v1 = gf::Add(
            v1,
            gf::Mul(
                gf::Mul(
                    replay.alphas[column],
                    PowFp3V1(batch.z1, shift)),
                batch.evals_z1[column]));
        v2 = gf::Add(
            v2,
            gf::Mul(
                gf::Mul(
                    replay.alphas[column],
                    PowFp3V1(batch.z2, shift)),
                batch.evals_z2[column]));
    }

    bool merkle_ok = true;
    bool identities_ok = true;
    bool quotient_ok = true;
    const uint32_t next_step =
        program.n_lde / program.trace_rows;
    for (uint32_t query = 0;
         query < batch.queries.size();
         ++query) {
        const auto& opened =
            batch.queries[query];
        const auto& next_groups =
            proof.next_trace_group_rows[query];
        for (uint32_t group = 0; group < 3; ++group) {
            for (uint32_t item = 0;
                 item <
                     opened.group_rows[group]
                         .values.size();
                 ++item) {
                const Fp3 value =
                    opened.group_rows[group]
                        .values[item];
                append(
                    MultiRowV2CheckKindV1::
                        CurrentGroupValue,
                    query, group, 0, item, 3,
                    fp3(value), fp3(value));
            }
        }
        for (uint32_t group = 0; group < 2; ++group) {
            for (uint32_t item = 0;
                 item <
                     next_groups[group]
                         .values.size();
                 ++item) {
                const Fp3 value =
                    next_groups[group]
                        .values[item];
                append(
                    MultiRowV2CheckKindV1::NextGroupValue,
                    query, group, 0, item, 3,
                    fp3(value), fp3(value));
            }
        }
        for (uint32_t group = 0; group < 3; ++group) {
            Fri3AlgDigest accumulator =
                LoggedRowLeafV1(
                    opened.group_rows[group].values,
                    opened.index,
                    poseidon_inputs);
            uint32_t index = opened.index;
            for (uint32_t layer = 0;
                 layer < program.merkle_depth;
                 ++layer) {
                append(
                    MultiRowV2CheckKindV1::
                        CurrentMerkleSibling,
                    query, group, layer, 0, 4,
                    DigestValuesV1(
                        opened.group_rows[group]
                            .siblings[layer]),
                    DigestValuesV1(
                        opened.group_rows[group]
                            .siblings[layer]));
                accumulator = LoggedMerkleStepV1(
                    accumulator,
                    opened.group_rows[group]
                        .siblings[layer],
                    index,
                    poseidon_inputs);
                const auto expected =
                    layer + 1 ==
                            program.merkle_depth
                    ? batch.groups[group]
                          .row_commit.root
                    : accumulator;
                append(
                    MultiRowV2CheckKindV1::
                        CurrentMerkleStep,
                    query, group, layer, 0, 4,
                    DigestValuesV1(accumulator),
                    DigestValuesV1(expected));
                index >>= 1;
            }
            merkle_ok =
                merkle_ok &&
                SameDigestV1(
                    accumulator,
                    batch.groups[group]
                        .row_commit.root);
        }
        const uint32_t next_index =
            (opened.index + next_step) %
            program.n_lde;
        for (uint32_t group = 0; group < 2; ++group) {
            Fri3AlgDigest accumulator =
                LoggedRowLeafV1(
                    next_groups[group].values,
                    next_index,
                    poseidon_inputs);
            uint32_t index = next_index;
            for (uint32_t layer = 0;
                 layer < program.merkle_depth;
                 ++layer) {
                append(
                    MultiRowV2CheckKindV1::
                        NextMerkleSibling,
                    query, group, layer, 0, 4,
                    DigestValuesV1(
                        next_groups[group]
                            .siblings[layer]),
                    DigestValuesV1(
                        next_groups[group]
                            .siblings[layer]));
                accumulator = LoggedMerkleStepV1(
                    accumulator,
                    next_groups[group]
                        .siblings[layer],
                    index,
                    poseidon_inputs);
                const auto expected =
                    layer + 1 ==
                            program.merkle_depth
                    ? batch.groups[group]
                          .row_commit.root
                    : accumulator;
                append(
                    MultiRowV2CheckKindV1::
                        NextMerkleStep,
                    query, group, layer, 0, 4,
                    DigestValuesV1(accumulator),
                    DigestValuesV1(expected));
                index >>= 1;
            }
            merkle_ok =
                merkle_ok &&
                SameDigestV1(
                    accumulator,
                    batch.groups[group]
                        .row_commit.root);
        }

        std::vector<Fp3> flattened;
        flattened.reserve(
            batch.column_len.size());
        for (const auto& group :
             opened.group_rows) {
            flattened.insert(
                flattened.end(),
                group.values.begin(),
                group.values.end());
        }
        const Fp3 x =
            DomainPointV1(
                program.n_lde,
                opened.index);
        Fp3 ux = Fp3::Zero();
        for (uint32_t column = 0;
             column < flattened.size();
             ++column) {
            const uint32_t shift =
                program.n_coeffs -
                batch.column_len[column];
            ux = gf::Add(
                ux,
                gf::Mul(
                    gf::Mul(
                        replay.alphas[column],
                        PowFp3V1(x, shift)),
                    flattened[column]));
        }
        const Fp3 expected_g =
            gf::Add(
                gf::Mul(
                    batch.w1,
                    gf::Mul(
                        gf::Sub(ux, v1),
                        gf::Inv(
                            gf::Sub(
                                x, batch.z1)))),
                gf::Mul(
                    batch.w2,
                    gf::Mul(
                        gf::Sub(ux, v2),
                        gf::Inv(
                            gf::Sub(
                                x, batch.z2)))));

        Fp3 last_folded = Fp3::Zero();
        uint32_t fold_index = opened.index;
        for (uint32_t fold = 0;
             fold < batch.fold_challenges.size();
             ++fold) {
            const auto& step =
                opened.steps[fold];
            const uint32_t leaves =
                batch.fold_layers[fold]
                    .n_leaves;
            const uint32_t half = leaves / 2;
            const uint32_t even_index =
                fold_index % half;
            const uint32_t odd_index =
                even_index + half;
            append(
                MultiRowV2CheckKindV1::FoldOpeningIndex,
                query, 0, fold, 0, 1,
                CheckValuesV1(
                    scalar(step.even_index)),
                CheckValuesV1(
                    scalar(even_index)));
            append(
                MultiRowV2CheckKindV1::FoldOpeningIndex,
                query, 1, fold, 0, 1,
                CheckValuesV1(
                    scalar(step.odd_index)),
                CheckValuesV1(
                    scalar(odd_index)));
            for (uint32_t side = 0;
                 side < 2; ++side) {
                const uint32_t start_index =
                    side == 0
                    ? even_index
                    : odd_index;
                const Fp3& value =
                    side == 0
                    ? step.even
                    : step.odd;
                const auto& siblings =
                    side == 0
                    ? step.even_siblings
                    : step.odd_siblings;
                append(
                    MultiRowV2CheckKindV1::FoldOpeningValue,
                    query, side, fold, 0, 3,
                    fp3(value), fp3(value));
                Fri3AlgDigest accumulator =
                    LoggedLeafV1(
                        value, start_index,
                        poseidon_inputs);
                uint32_t path_index =
                    start_index;
                for (uint32_t layer = 0;
                     layer <
                         program.merkle_depth -
                             fold;
                     ++layer) {
                    append(
                        MultiRowV2CheckKindV1::
                            FoldMerkleSibling,
                        query, side, fold, layer, 4,
                        DigestValuesV1(
                            siblings[layer]),
                        DigestValuesV1(
                            siblings[layer]));
                    accumulator = LoggedMerkleStepV1(
                        accumulator,
                        siblings[layer],
                        path_index,
                        poseidon_inputs);
                    const auto expected =
                        layer + 1 ==
                                program.merkle_depth -
                                    fold
                        ? batch.fold_layers[fold]
                              .root
                        : accumulator;
                    append(
                        MultiRowV2CheckKindV1::
                            FoldMerkleStep,
                        query, side, fold, layer, 4,
                        DigestValuesV1(accumulator),
                        DigestValuesV1(expected));
                    path_index >>= 1;
                }
                merkle_ok =
                    merkle_ok &&
                    SameDigestV1(
                        accumulator,
                        batch.fold_layers[fold]
                            .root);
            }
            const Fp3 fold_x =
                DomainPointV1(leaves, even_index);
            const Fp3 numerator =
                gf::Add(
                    gf::Mul(
                        fold_x,
                        gf::Add(
                            step.even,
                            step.odd)),
                    gf::Mul(
                        batch.fold_challenges[fold],
                        gf::Sub(
                            step.even,
                            step.odd)));
            const Fp3 expected_folded =
                gf::Mul(
                    numerator,
                    gf::Inv(
                        gf::Mul(
                            Fp3::FromFp(
                                gf::FromU64(2)),
                            fold_x)));
            Fp3 claimed_folded =
                batch.final_value;
            if (fold + 1 <
                batch.fold_challenges.size()) {
                const auto& next_step_opened =
                    opened.steps[fold + 1];
                const uint32_t next_half =
                    batch.fold_layers[fold + 1]
                        .n_leaves /
                    2;
                const uint32_t next_index =
                    fold_index % half;
                claimed_folded =
                    next_index < next_half
                    ? next_step_opened.even
                    : next_step_opened.odd;
            }
            append(
                MultiRowV2CheckKindV1::FoldIdentity,
                query, 0, fold, 0, 3,
                fp3(claimed_folded),
                fp3(expected_folded));
            identities_ok =
                identities_ok &&
                gf::Eq(
                    claimed_folded,
                    expected_folded);
            last_folded = expected_folded;
            fold_index %= half;
        }
        const uint32_t first_half =
            batch.fold_layers[0]
                .n_leaves /
            2;
        const Fp3 first_here =
            opened.index < first_half
            ? opened.steps[0].even
            : opened.steps[0].odd;
        append(
            MultiRowV2CheckKindV1::DeepIdentity,
            query, 0, 0, 0, 3,
            fp3(first_here), fp3(expected_g));
        identities_ok =
            identities_ok &&
            gf::Eq(first_here, expected_g);
        append(
            MultiRowV2CheckKindV1::FinalFold,
            query, 0, program.fold_count, 0, 3,
            fp3(last_folded),
            fp3(batch.final_value));
        identities_ok =
            identities_ok &&
            gf::Eq(
                last_folded,
                batch.final_value);

        std::vector<Fp3> current(
            child_cs.n_columns);
        std::vector<Fp3> next(
            child_cs.n_columns);
        for (uint32_t position = 0;
             position <
                 program.base_column_indices.size();
             ++position) {
            const uint32_t column =
                program.base_column_indices[
                    position];
            current[column] =
                opened.group_rows[0]
                    .values[position];
            next[column] =
                next_groups[0]
                    .values[position];
        }
        for (uint32_t position = 0;
             position <
                 dependent_indices.size();
             ++position) {
            const uint32_t column =
                dependent_indices[position];
            current[column] =
                opened.group_rows[1]
                    .values[position];
            next[column] =
                next_groups[1]
                    .values[position];
        }
        const Fp3 y =
            gf::Mul(
                Fp3::FromFp(aq::kAirCosetShift),
                DomainPointV1(
                    program.n_lde,
                    opened.index));
        const Fp3 zh =
            gf::Sub(
                PowFp3V1(
                    y, program.trace_rows),
                Fp3::One());
        Fp3 sum = Fp3::Zero();
        Fp3 power = Fp3::One();
        for (const auto& constraint :
             child_cs.constraints) {
            const Fp3 residual =
                constraint.eval(current, next);
            if (!gf::IsZero(residual)) {
                sum = gf::Add(
                    sum,
                    gf::Mul(
                        power,
                        gf::Mul(
                            SelectorAtV1(
                                constraint.kind,
                                program.trace_rows,
                                y),
                            residual)));
            }
            power = gf::Mul(
                power, air_lambda);
        }
        const Fp3 quotient_side =
            gf::Mul(
                opened.group_rows[2]
                    .values[0],
                zh);
        append(
            MultiRowV2CheckKindV1::QuotientIdentity,
            query, 0, 0, 0, 3,
            fp3(sum), fp3(quotient_side));
        quotient_ok =
            quotient_ok &&
            gf::Eq(sum, quotient_side);
    }
    if (!append_ok ||
        program_row != program.active_rows ||
        out.checks.size() !=
            program.active_rows ||
        poseidon_inputs.size() !=
            program.poseidon_permutation_rows ||
        poseidon_inputs.size() >
            program.air_rows ||
        !merkle_ok ||
        !identities_ok ||
        !quotient_ok) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "normalized_checks";
        return out;
    }
    while (out.checks.size() < program.air_rows) {
        const auto& metadata =
            program.rows[out.checks.size()];
        out.checks.push_back({
            metadata, {}, {}});
    }
    out.all_current_next_openings_bound = true;
    out.all_merkle_paths_replayed = true;
    out.all_deep_fold_identities_checked = true;
    out.all_quotient_identities_checked = true;

    for (uint32_t group = 0; group < 3; ++group) {
        for (uint32_t limb = 0; limb < 4; ++limb) {
            out.outputs.push_back({
                MultiRowV2VerifierOutputKindV1::GroupRoot,
                group, limb,
                Fp3::FromFp(
                    gf::Canonical(
                        batch.groups[group]
                            .row_commit.root[limb]))});
        }
    }
    out.outputs.push_back({
        MultiRowV2VerifierOutputKindV1::
            AirConstraintLambda,
        0, 0, air_lambda});
    out.outputs.push_back({
        MultiRowV2VerifierOutputKindV1::OodPoint,
        0, 0, replay.z1});
    out.outputs.push_back({
        MultiRowV2VerifierOutputKindV1::OodPoint,
        1, 0, replay.z2});
    for (uint32_t column = 0;
         column < replay.alphas.size();
         ++column) {
        out.outputs.push_back({
            MultiRowV2VerifierOutputKindV1::
                IndependentPcsAlpha,
            column, 0, replay.alphas[column]});
    }
    out.outputs.push_back({
        MultiRowV2VerifierOutputKindV1::DeepWeight,
        0, 0, replay.w1});
    out.outputs.push_back({
        MultiRowV2VerifierOutputKindV1::DeepWeight,
        1, 0, replay.w2});
    for (uint32_t fold = 0;
         fold < replay.fold_challenges.size();
         ++fold) {
        out.outputs.push_back({
            MultiRowV2VerifierOutputKindV1::
                FoldChallenge,
            fold, 0,
            replay.fold_challenges[fold]});
    }
    for (uint32_t query = 0;
         query < replay.query_indices.size();
         ++query) {
        out.outputs.push_back({
            MultiRowV2VerifierOutputKindV1::QueryIndex,
            query, 0,
            scalar(replay.query_indices[query])});
    }
    out.outputs.push_back({
        MultiRowV2VerifierOutputKindV1::FinalValue,
        0, 0, batch.final_value});
    out.output_statement =
        CommitMultiRowV2OutputsV1(out.outputs);
    if (out.output_statement.IsNull()) {
        out.note =
            "stage3:verifier_air:multi_row_v2_witness:"
            "outputs";
        return out;
    }

    const auto poseidon_layout =
        stage3_poseidon_air::CanonicalLayout(
            kMultiRowV2VerifierColumns);
    const uint32_t poseidon_selector =
        poseidon_layout.End();
    out.witness_columns.assign(
        poseidon_selector + 1,
        std::vector<Fp3>(
            program.air_rows,
            Fp3::Zero()));
    for (uint32_t row = 0;
         row < program.air_rows;
         ++row) {
        const auto& check = out.checks[row];
        auto& columns = out.witness_columns;
        const bool active =
            row < program.active_rows;
        columns[kMultiRowV2Active][row] =
            active ? Fp3::One() : Fp3::Zero();
        columns[kMultiRowV2Kind][row] =
            scalar(static_cast<uint8_t>(
                check.program.kind));
        columns[kMultiRowV2Query][row] =
            scalar(check.program.query);
        columns[kMultiRowV2Group][row] =
            scalar(check.program.group);
        columns[kMultiRowV2Layer][row] =
            scalar(check.program.layer);
        columns[kMultiRowV2Item][row] =
            scalar(check.program.item);
        columns[kMultiRowV2ActiveLanes][row] =
            scalar(check.program.active_lanes);
        for (uint32_t lane = 0; lane < 4; ++lane) {
            columns[
                kMultiRowV2Expected0 + lane][row] =
                check.replayed[lane];
            columns[
                kMultiRowV2Claimed0 + lane][row] =
                check.claimed[lane];
        }
        columns[kMultiRowV2LocallyAccepted][row] =
            active ? Fp3::One() : Fp3::Zero();
    }
    for (uint32_t row = 0;
         row < poseidon_inputs.size();
         ++row) {
        const auto permutation =
            stage3_poseidon_air::BuildWitness(
                poseidon_layout,
                poseidon_inputs[row]);
        if (permutation.row.size() !=
            poseidon_layout.End()) {
            out.note =
                "stage3:verifier_air:"
                "multi_row_v2_witness:poseidon_witness";
            return out;
        }
        for (uint32_t column =
                 kMultiRowV2VerifierColumns;
             column <
                 poseidon_layout.End();
             ++column) {
            out.witness_columns[column][row] =
                permutation.row[column];
        }
        out.witness_columns[
            poseidon_selector][row] =
            Fp3::One();
    }
    {
        auto& aliases = out.poseidon_alias_plan;
        aliases.permutation_count =
            static_cast<uint32_t>(
                poseidon_inputs.size());
        bool layout_ok = true;
        HashWriter alias_statement;
        alias_statement <<
            "BTX_RC_STAGE3_MULTI_ROW_V2_POSEIDON_ALIAS_V1";
        alias_statement << aliases.version;
        alias_statement <<
            aliases.permutation_count;
        for (uint32_t permutation = 0;
             permutation < poseidon_inputs.size();
             ++permutation) {
            const auto canonical =
                stage3_poseidon_air::BuildWitness(
                    poseidon_layout,
                    poseidon_inputs[permutation]);
            MultiRowV2PoseidonPermutationAuditV1 audit;
            audit.permutation = permutation;
            audit.input =
                poseidon_inputs[permutation];
            audit.output = canonical.output;
            HashWriter operation;
            operation <<
                "BTX_RC_STAGE3_MULTI_ROW_V2_POSEIDON_OP_V1";
            operation << permutation;
            for (const Fp value : audit.input) {
                operation << gf::Canonical(value);
            }
            for (const Fp value : audit.output) {
                operation << gf::Canonical(value);
            }
            audit.permutation_statement =
                operation.GetHash();
            alias_statement <<
                audit.permutation_statement;
            for (uint32_t lane = 0;
                 lane < alg_hash::kAlgHashT;
                 ++lane) {
                layout_ok =
                    layout_ok &&
                    gf::Eq(
                        out.witness_columns[
                            poseidon_layout.perm
                                .InputCol(lane)]
                            [permutation],
                        Fp3::FromFp(
                            gf::Canonical(
                                audit.input[lane]))) &&
                    gf::Eq(
                        air_recurse::PermOutputLane(
                            poseidon_layout.perm,
                            canonical.row, lane),
                        Fp3::FromFp(
                            gf::Canonical(
                                audit.output[lane])));
            }
            aliases.permutations.push_back(audit);
        }
        aliases.layout_input_alias_cells =
            aliases.permutation_count *
            alg_hash::kAlgHashT;
        aliases.layout_output_alias_cells =
            aliases.permutation_count *
            alg_hash::kAlgHashT;
        aliases.alias_statement =
            alias_statement.GetHash();
        aliases.exact_permutation_order =
            aliases.permutations.size() ==
                aliases.permutation_count;
        aliases.layout_aliases_complete =
            layout_ok &&
            aliases.exact_permutation_order;
        // Source values and output consumers still originate in the
        // host-decoded proof/check rows.  They are deliberately not counted
        // as aliases until a copy bus constrains those rows in this AIR.
        aliases.semantic_source_alias_cells = 0;
        aliases.semantic_consumer_alias_cells = 0;
        aliases.recursively_consumed_alias_cells = 0;
        aliases.semantic_aliases_complete = false;
        aliases.valid =
            aliases.layout_aliases_complete &&
            !aliases.alias_statement.IsNull() &&
            !aliases.semantic_aliases_complete;
        aliases.note = aliases.valid
            ? "stage3:verifier_air:poseidon_alias:"
              "layout_exact;semantic_copy_bus_pending"
            : "stage3:verifier_air:poseidon_alias:invalid";
    }
    auto& cs = out.constraint_system;
    cs.n_rows = program.air_rows;
    cs.n_columns = poseidon_selector + 1;
    cs.preprocessed_pin_ood = true;
    for (uint32_t column = kMultiRowV2Active;
         column <= kMultiRowV2Expected3;
         ++column) {
        cs.preprocessed.emplace_back(
            column, out.witness_columns[column]);
    }
    cs.preprocessed.emplace_back(
        poseidon_selector,
        out.witness_columns[poseidon_selector]);
    aq::AirConstraint<Fp3> active_boolean;
    active_boolean.name =
        "stage3.multi_row_v2.active_boolean";
    active_boolean.kind = aq::AirKind::kEverywhere;
    active_boolean.alg_degree = 2;
    active_boolean.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Mul(
            row[kMultiRowV2Active],
            gf::Sub(
                row[kMultiRowV2Active],
                Fp3::One()));
    };
    cs.constraints.push_back(
        std::move(active_boolean));
    for (uint32_t lane = 0; lane < 4; ++lane) {
        aq::AirConstraint<Fp3> equality;
        equality.name =
            "stage3.multi_row_v2.replayed_equality";
        equality.kind = aq::AirKind::kEverywhere;
        equality.alg_degree = 2;
        equality.eval = [lane](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                row[kMultiRowV2Active],
                gf::Sub(
                    row[kMultiRowV2Claimed0 + lane],
                    row[kMultiRowV2Expected0 + lane]));
        };
        cs.constraints.push_back(
            std::move(equality));
    }
    aq::AirConstraint<Fp3> accepted;
    accepted.name =
        "stage3.multi_row_v2.locally_accepted";
    accepted.kind = aq::AirKind::kEverywhere;
    accepted.alg_degree = 1;
    accepted.eval = [](
        const std::vector<Fp3>& row,
        const std::vector<Fp3>&) {
        return gf::Sub(
            row[kMultiRowV2LocallyAccepted],
            row[kMultiRowV2Active]);
    };
    cs.constraints.push_back(std::move(accepted));
    for (uint32_t lane = 0; lane < 4; ++lane) {
        aq::AirConstraint<Fp3> padding;
        padding.name =
            "stage3.multi_row_v2.padding_zero";
        padding.kind = aq::AirKind::kEverywhere;
        padding.alg_degree = 2;
        padding.eval = [lane](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            return gf::Mul(
                gf::Sub(
                    Fp3::One(),
                    row[kMultiRowV2Active]),
                row[kMultiRowV2Claimed0 + lane]);
        };
        cs.constraints.push_back(
            std::move(padding));
    }
    auto poseidon_constraints =
        stage3_poseidon_air::
            BuildSelectorGatedConstraints(
                poseidon_layout,
                poseidon_selector);
    cs.constraints.insert(
        cs.constraints.end(),
        std::make_move_iterator(
            poseidon_constraints.begin()),
        std::make_move_iterator(
            poseidon_constraints.end()));

    out.checked_rows = program.active_rows;
    out.exported_cells =
        static_cast<uint32_t>(
            out.outputs.size());
    out.local_directly_checked_cells =
        out.checked_rows;
    out.normalized_recursive_cells = 0;
    out.preprocessed_relation_satisfied =
        CountVerifierScalarViolations(
            cs, out.witness_columns) == 0;
    out.alg_hash_poseidon_permutations_constrained =
        poseidon_inputs.size() ==
            program.poseidon_permutation_rows &&
        !poseidon_inputs.empty() &&
        out.poseidon_alias_plan.valid &&
        out.poseidon_alias_plan.layout_aliases_complete;
    // The operation table is real, but V1 still pins its input/output stream
    // from the locally decoded proof. The arity parent must replace those
    // pins with same-trace aliases to proof-byte and transcript cells.
    out.alg_hash_io_aliases_to_proof_rows_complete = false;
    out.sha_transcript_air_constrained = false;
    out.parent_hash_chips_execute = false;
    out.normalized_recursive_consumption_complete = false;
    out.production_authority_ready = false;
    out.valid =
        out.preprocessed_relation_satisfied &&
        out.transcript_replayed_exactly &&
        out.all_independent_pcs_alphas_derived &&
        out.all_current_next_openings_bound &&
        out.all_merkle_paths_replayed &&
        out.all_deep_fold_identities_checked &&
        out.all_quotient_identities_checked &&
        out.transcript_sha_plan.valid &&
        out.transcript_sha_plan.exact_call_order &&
        out.transcript_sha_plan
            .every_compression_sharded_once &&
        out.transcript_sha_plan
            .arity_four_manifest_complete &&
        out.transcript_sha_execution.valid &&
        out.transcript_sha_execution
            .exact_preimages &&
        out.transcript_sha_execution
            .exact_sha256d_padding_and_chaining &&
        !out.transcript_sha_execution
            .witness_owned_inputs_linked_to_proof_codec &&
        !out.transcript_sha_execution
            .challenge_selection_air_constrained &&
        !out.transcript_sha_execution
            .query_reduction_air_constrained &&
        !out.transcript_sha_execution
            .recursively_consumed &&
        out.alg_hash_poseidon_permutations_constrained &&
        !out.alg_hash_io_aliases_to_proof_rows_complete &&
        !out.sha_transcript_air_constrained &&
        out.normalized_recursive_cells == 0 &&
        !out.parent_hash_chips_execute &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:verifier_air:multi_row_v2_witness:"
          "host_exact_three_group;local_air_bound;"
          "poseidon_layout_exact;"
          "sha_shard_arity4_schedule_exact;"
          "semantic_copy_parent_hash_chips_open;"
          "recursive_0;"
          "authority_false"
        : "stage3:verifier_air:multi_row_v2_witness:invalid";
    return out;
}

bool VerifyMultiRowV2SplitRapVerifierWitnessV1(
    const aq::AirConstraintSystem<Fp3>& child_cs,
    const MultiRowV2SplitRapProgramV1& program,
    const aq::AirQuotientSplitRapRowsProof& proof,
    const uint256& public_fs_seed,
    const MultiRowV2SplitRapVerifierWitnessV1& witness,
    std::string* why)
{
    if (!witness.valid ||
        witness.version != 1 ||
        witness.public_fs_seed != public_fs_seed ||
        witness.program_statement !=
            program.program_statement ||
        witness.proof_statement !=
            CommitMultiRowV2ProofV1(proof) ||
        witness.output_statement !=
            CommitMultiRowV2OutputsV1(
                witness.outputs)) {
        return Fail(
            why, "multi_row_v2_witness_shape");
    }
    const auto expected =
        BuildMultiRowV2SplitRapVerifierWitnessV1(
            child_cs, program, proof,
            public_fs_seed);
    if (!expected.valid ||
        witness.checks != expected.checks ||
        witness.outputs != expected.outputs ||
        witness.output_statement !=
            expected.output_statement ||
        witness.checked_rows !=
            expected.checked_rows ||
        witness.exported_cells !=
            expected.exported_cells ||
        witness.local_directly_checked_cells !=
            expected.local_directly_checked_cells ||
        !ValidateMultiRowV2TranscriptShaPlanV1(
            witness.transcript_sha_plan) ||
        witness.transcript_sha_plan.schedule_statement !=
            expected.transcript_sha_plan
                .schedule_statement ||
        witness.transcript_sha_plan.calls !=
            expected.transcript_sha_plan.calls ||
        witness.transcript_sha_plan.shards !=
            expected.transcript_sha_plan.shards ||
        witness.transcript_sha_plan.recursive_nodes !=
            expected.transcript_sha_plan.recursive_nodes ||
        !ValidateMultiRowV2TranscriptShaExecutionPlanV1(
            witness.transcript_sha_plan,
            witness.transcript_sha_execution) ||
        witness.transcript_sha_execution !=
            expected.transcript_sha_execution ||
        !witness.poseidon_alias_plan.valid ||
        witness.poseidon_alias_plan.alias_statement !=
            expected.poseidon_alias_plan.alias_statement ||
        witness.poseidon_alias_plan.permutations !=
            expected.poseidon_alias_plan.permutations ||
        !witness.poseidon_alias_plan
            .layout_aliases_complete ||
        witness.poseidon_alias_plan
            .semantic_aliases_complete ||
        witness.poseidon_alias_plan
                .semantic_source_alias_cells != 0 ||
        witness.poseidon_alias_plan
                .semantic_consumer_alias_cells != 0 ||
        witness.normalized_recursive_cells != 0 ||
        !witness.canonical_program ||
        !witness.host_verifier_accepted ||
        !witness.transcript_replayed_exactly ||
        !witness.all_independent_pcs_alphas_derived ||
        !witness.all_current_next_openings_bound ||
        !witness.all_merkle_paths_replayed ||
        !witness.all_deep_fold_identities_checked ||
        !witness.all_quotient_identities_checked ||
        !witness.preprocessed_relation_satisfied ||
        !witness.alg_hash_poseidon_permutations_constrained ||
        witness.alg_hash_io_aliases_to_proof_rows_complete ||
        witness.sha_transcript_air_constrained ||
        witness.parent_hash_chips_execute ||
        witness.normalized_recursive_consumption_complete ||
        witness.production_authority_ready ||
        witness.witness_columns.size() !=
            expected.witness_columns.size()) {
        return Fail(
            why, "multi_row_v2_witness_summary");
    }
    for (uint32_t column = 0;
         column < witness.witness_columns.size();
         ++column) {
        if (witness.witness_columns[column].size() !=
            expected.witness_columns[column].size()) {
            return Fail(
                why, "multi_row_v2_witness_columns");
        }
        for (uint32_t row = 0;
             row <
                 witness.witness_columns[column]
                     .size();
             ++row) {
            if (!gf::Eq(
                    witness.witness_columns[column][row],
                    expected.witness_columns[column][row])) {
                return Fail(
                    why,
                    "multi_row_v2_witness_column_value");
            }
        }
    }
    if (!SameMultiRowV2ConstraintShapeV1(
            witness.constraint_system,
            expected.constraint_system) ||
        CountVerifierScalarViolations(
            witness.constraint_system,
            witness.witness_columns) != 0) {
        return Fail(
            why, "multi_row_v2_witness_air");
    }
    if (why != nullptr) {
        *why =
            "stage3:verifier_air:multi_row_v2_witness:"
            "exact_local_host_mirror;"
            "recursive_hash_chips_pending;"
            "authority_false";
    }
    return true;
}

std::vector<MultiRowV2VerifierOutputV1>
ExportMultiRowV2SplitRapVerifierOutputsV1(
    const MultiRowV2SplitRapVerifierWitnessV1& witness)
{
    if (!witness.valid ||
        !witness.host_verifier_accepted ||
        !witness.preprocessed_relation_satisfied ||
        witness.output_statement.IsNull() ||
        witness.output_statement !=
            CommitMultiRowV2OutputsV1(
                witness.outputs)) {
        return {};
    }
    return witness.outputs;
}

namespace {

alg_hash::Digest ChunkRlcRowRootV1(
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t first_column,
    uint32_t column_count)
{
    if (columns.empty() || column_count == 0 ||
        first_column > columns.size() ||
        column_count >
            columns.size() - first_column) {
        return {};
    }
    const uint32_t rows =
        static_cast<uint32_t>(
            columns.front().size());
    if (rows == 0 ||
        (rows & (rows - 1)) != 0) {
        return {};
    }
    std::vector<alg_hash::Digest> level(rows);
    std::vector<Fp3> row(column_count);
    for (uint32_t index = 0; index < rows; ++index) {
        for (uint32_t local = 0;
             local < column_count; ++local) {
            row[local] =
                columns[first_column + local][index];
        }
        level[index] =
            alg_hash::LeafHashRow(row, index);
    }
    while (level.size() > 1) {
        std::vector<alg_hash::Digest> next(
            level.size() / 2);
        for (uint32_t index = 0;
             index < next.size(); ++index) {
            next[index] = alg_hash::Compress(
                level[2 * index],
                level[2 * index + 1]);
        }
        level = std::move(next);
    }
    return level.front();
}

alg_hash::Digest ChunkRlcColumnRootV1(
    const std::vector<Fp3>& column)
{
    if (column.empty() ||
        (column.size() & (column.size() - 1)) != 0) {
        return {};
    }
    std::vector<alg_hash::Digest> level(
        column.size());
    for (uint32_t index = 0;
         index < column.size(); ++index) {
        level[index] =
            alg_hash::LeafHash(
                column[index], index);
    }
    while (level.size() > 1) {
        std::vector<alg_hash::Digest> next(
            level.size() / 2);
        for (uint32_t index = 0;
             index < next.size(); ++index) {
            next[index] = alg_hash::Compress(
                level[2 * index],
                level[2 * index + 1]);
        }
        level = std::move(next);
    }
    return level.front();
}

uint256 CommitChunkRlcPrecommitV1(
    uint32_t chunk,
    uint32_t first_column,
    uint32_t column_count,
    const alg_hash::Digest& root)
{
    if (column_count == 0) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CHUNK_RLC_PRECOMMIT_V1";
    hash << kChunkRlcPcsVersionV1;
    hash << chunk;
    hash << first_column;
    hash << column_count;
    HashDigest(hash, root);
    return hash.GetHash();
}

bool DeriveChunkRlcCoefficientV1(
    const uint256& public_seed,
    const uint256& ordered_precommit,
    uint32_t chunk,
    uint32_t local_column,
    uint32_t global_column,
    Fp3& out)
{
    std::array<
        uint64_t,
        kRCFri3AlgDualUniformWords> words{};
    for (uint32_t block = 0;
         block <
             kRCFri3AlgDualUniformHashBlocks;
         ++block) {
        const uint256 digest =
            aq::AirChallengeDigest(
                public_seed,
                "stage3_chunk_rlc_coeff_v1",
                {ordered_precommit},
                {chunk, local_column,
                 global_column, block});
        for (uint32_t word = 0; word < 4; ++word) {
            uint64_t value = 0;
            for (uint32_t byte = 0;
                 byte < 8; ++byte) {
                value |=
                    uint64_t{
                        digest.begin()[
                            8 * word + byte]}
                    << (8 * byte);
            }
            words[4 * block + word] = value;
        }
    }
    const auto selected =
        Fri3AlgSelectUniformFp3Words(words);
    if (!selected.has_value()) return false;
    out = *selected;
    return true;
}

uint256 CommitChunkRlcCoefficientsV1(
    uint32_t chunk,
    const uint256& ordered_precommit,
    const std::vector<Fp3>& coefficients)
{
    if (coefficients.empty()) return {};
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CHUNK_RLC_COEFFICIENTS_V1";
    hash << kChunkRlcPcsVersionV1;
    hash << chunk;
    hash << ordered_precommit;
    hash << static_cast<uint32_t>(
        coefficients.size());
    for (const Fp3& coefficient : coefficients) {
        HashFp3(hash, coefficient);
    }
    return hash.GetHash();
}

uint256 CommitChunkRlcReceiptV1(
    const ChunkRlcReceiptV1& receipt)
{
    if (receipt.column_count == 0 ||
        receipt.independent_coefficients.size() !=
            receipt.column_count ||
        receipt.openings.empty()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CHUNK_RLC_RECEIPT_V1";
    hash << kChunkRlcPcsVersionV1;
    hash << receipt.chunk;
    hash << receipt.first_column;
    hash << receipt.column_count;
    HashDigest(hash, receipt.full_chunk_root);
    HashDigest(hash, receipt.rlc_column_root);
    hash << receipt.precommit_statement;
    hash << receipt.coefficient_statement;
    hash << static_cast<uint32_t>(
        receipt.openings.size());
    for (const auto& opening : receipt.openings) {
        hash << opening.query;
        hash << opening.current_index;
        hash << opening.next_index;
        HashFp3(hash, opening.current_value);
        HashFp3(hash, opening.next_value);
    }
    return hash.GetHash();
}

uint256 CommitChunkRlcAggregateNodeV1(
    const ChunkRlcAggregateNodeV1& node)
{
    if (node.child_count == 0 ||
        node.child_count > kChunkRlcArityV1) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CHUNK_RLC_AGGREGATE_V1";
    hash << kChunkRlcPcsVersionV1;
    hash << node.level;
    hash << node.index;
    hash << node.child_count;
    for (uint32_t child = 0;
         child < kChunkRlcArityV1; ++child) {
        if (child < node.child_count) {
            if (node.child_statements[child].IsNull()) {
                return {};
            }
        } else if (
            !node.child_statements[child].IsNull()) {
            return {};
        }
        hash << node.child_statements[child];
    }
    return hash.GetHash();
}

aq::AirConstraintSystem<Fp3>
BuildChunkRlcLocalRelationV1(
    uint32_t trace_rows,
    uint32_t column_count,
    const std::vector<Fp3>& coefficients)
{
    aq::AirConstraintSystem<Fp3> out;
    if (trace_rows < 2 ||
        (trace_rows & (trace_rows - 1)) != 0 ||
        column_count == 0 ||
        coefficients.size() != column_count ||
        column_count ==
            std::numeric_limits<uint32_t>::max()) {
        return out;
    }
    out.n_rows = trace_rows;
    out.n_columns = column_count + 1;
    aq::AirConstraint<Fp3> relation;
    relation.name =
        "stage3.chunk_rlc.linear_combination";
    relation.kind = aq::AirKind::kEverywhere;
    relation.alg_degree = 1;
    relation.eval =
        [coefficients, column_count](
            const std::vector<Fp3>& row,
            const std::vector<Fp3>&) {
            Fp3 sum = Fp3::Zero();
            for (uint32_t local = 0;
                 local < column_count; ++local) {
                sum = gf::Add(
                    sum,
                    gf::Mul(
                        coefficients[local],
                        row[local]));
            }
            return gf::Sub(
                row[column_count], sum);
        };
    out.constraints.push_back(std::move(relation));
    return out;
}

uint32_t NextPowerOfTwoV1(uint64_t value)
{
    if (value < 2) return 2;
    uint64_t out = 1;
    while (out < value) {
        out <<= 1;
        if (out >
            std::numeric_limits<uint32_t>::max()) {
            return 0;
        }
    }
    return static_cast<uint32_t>(out);
}

} // namespace

ChunkRlcLeafDomainAuditV1
AssessChunkRlcLeafDomainV1(
    const aq::AirConstraintSystem<Fp3>& leaf_cs)
{
    ChunkRlcLeafDomainAuditV1 out;
    out.trace_rows = leaf_cs.n_rows;
    if (leaf_cs.n_rows < 2 ||
        (leaf_cs.n_rows &
         (leaf_cs.n_rows - 1)) != 0 ||
        leaf_cs.n_columns < 2 ||
        leaf_cs.constraints.empty()) {
        out.note =
            "stage3:verifier_air:chunk_rlc_leaf_domain:"
            "shape";
        return out;
    }

    const uint64_t trace_degree =
        uint64_t{leaf_cs.n_rows} - 1;
    for (const auto& constraint :
         leaf_cs.constraints) {
        if (constraint.alg_degree == 0) {
            out.note =
                "stage3:verifier_air:"
                "chunk_rlc_leaf_domain:zero_degree";
            return out;
        }
        uint64_t composed = 0;
        if (!CheckedMulU64(
                constraint.alg_degree,
                trace_degree, composed)) {
            out.note =
                "stage3:verifier_air:"
                "chunk_rlc_leaf_domain:degree_overflow";
            return out;
        }
        uint64_t selector_degree = 0;
        switch (constraint.kind) {
        case aq::AirKind::kEverywhere:
            break;
        case aq::AirKind::kTransition:
            selector_degree = 1;
            break;
        default:
            selector_degree = trace_degree;
            break;
        }
        if (composed >
            std::numeric_limits<uint64_t>::max() -
                selector_degree) {
            out.note =
                "stage3:verifier_air:"
                "chunk_rlc_leaf_domain:selector_overflow";
            return out;
        }
        composed += selector_degree;
        out.max_composed_degree =
            std::max(
                out.max_composed_degree,
                composed);
    }

    const uint64_t quotient_len =
        out.max_composed_degree < leaf_cs.n_rows
        ? 1
        : out.max_composed_degree -
              leaf_cs.n_rows + 1;
    if (quotient_len >
        std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:verifier_air:chunk_rlc_leaf_domain:"
            "quotient_overflow";
        return out;
    }
    out.quotient_len =
        static_cast<uint32_t>(quotient_len);
    out.n_coeffs = NextPowerOfTwoV1(
        std::max<uint64_t>(
            leaf_cs.n_rows, quotient_len));
    uint64_t n_lde = 0;
    if (out.n_coeffs == 0 ||
        !CheckedMulU64(
            out.n_coeffs,
            kRCFriBlowup,
            n_lde) ||
        n_lde >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:verifier_air:chunk_rlc_leaf_domain:"
            "fri_domain_overflow";
        return out;
    }
    out.n_lde = static_cast<uint32_t>(n_lde);
    out.exact_quotient_degree_accounting = true;
    out.backend_lde_cap_met =
        n_lde <=
        (uint64_t{1} << kRCFriMaxLdeLog2);
    out.valid = true;
    out.note =
        out.backend_lde_cap_met
        ? "stage3:verifier_air:chunk_rlc_leaf_domain:"
          "exact_fit"
        : "stage3:verifier_air:chunk_rlc_leaf_domain:"
          "exact_over_cap";
    return out;
}

ChunkRlcPcsStatementV1 BuildChunkRlcPcsStatementV1(
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& query_indices,
    uint32_t next_step,
    uint32_t chunk_columns,
    const uint256& public_seed)
{
    ChunkRlcPcsStatementV1 out;
    out.public_seed = public_seed;
    out.total_columns =
        static_cast<uint32_t>(columns.size());
    out.chunk_columns = chunk_columns;
    out.next_step = next_step;
    out.query_count =
        static_cast<uint32_t>(
            query_indices.size());
    if (columns.empty() ||
        query_indices.empty() ||
        public_seed.IsNull() ||
        (chunk_columns != 256 &&
         chunk_columns != 512) ||
        columns.front().size() >
            std::numeric_limits<uint32_t>::max()) {
        out.note =
            "stage3:verifier_air:chunk_rlc:shape";
        return out;
    }
    out.trace_rows =
        static_cast<uint32_t>(
            columns.front().size());
    if (out.trace_rows < 2 ||
        (out.trace_rows &
         (out.trace_rows - 1)) != 0 ||
        next_step == 0 ||
        next_step >= out.trace_rows) {
        out.note =
            "stage3:verifier_air:chunk_rlc:domain";
        return out;
    }
    for (const auto& column : columns) {
        if (column.size() != out.trace_rows) {
            out.note =
                "stage3:verifier_air:chunk_rlc:"
                "column_length";
            return out;
        }
    }
    for (uint32_t query : query_indices) {
        if (query >= out.trace_rows) {
            out.note =
                "stage3:verifier_air:chunk_rlc:query";
            return out;
        }
    }
    out.chunk_count =
        static_cast<uint32_t>(
            CeilDiv(
                out.total_columns,
                chunk_columns));
    out.receipts.resize(out.chunk_count);
    HashWriter ordered;
    ordered <<
        "BTX_RC_STAGE3_CHUNK_RLC_ORDERED_PRECOMMIT_V1";
    ordered << out.version;
    ordered << out.trace_rows;
    ordered << out.total_columns;
    ordered << out.chunk_columns;
    ordered << out.chunk_count;
    ordered << out.next_step;
    for (uint32_t chunk = 0;
         chunk < out.chunk_count; ++chunk) {
        auto& receipt = out.receipts[chunk];
        receipt.chunk = chunk;
        receipt.first_column =
            chunk * chunk_columns;
        receipt.column_count =
            std::min<uint32_t>(
                chunk_columns,
                out.total_columns -
                    receipt.first_column);
        receipt.full_chunk_root =
            ChunkRlcRowRootV1(
                columns,
                receipt.first_column,
                receipt.column_count);
        receipt.precommit_statement =
            CommitChunkRlcPrecommitV1(
                chunk,
                receipt.first_column,
                receipt.column_count,
                receipt.full_chunk_root);
        if (receipt.precommit_statement.IsNull()) {
            out.note =
                "stage3:verifier_air:chunk_rlc:"
                "precommit";
            return out;
        }
        ordered << receipt.precommit_statement;
    }
    out.ordered_precommit_statement =
        ordered.GetHash();
    if (out.ordered_precommit_statement.IsNull()) {
        out.note =
            "stage3:verifier_air:chunk_rlc:"
            "ordered_precommit";
        return out;
    }
    for (auto& receipt : out.receipts) {
        receipt.independent_coefficients.resize(
            receipt.column_count);
        for (uint32_t local = 0;
             local < receipt.column_count; ++local) {
            if (!DeriveChunkRlcCoefficientV1(
                    public_seed,
                    out.ordered_precommit_statement,
                    receipt.chunk, local,
                    receipt.first_column + local,
                    receipt
                        .independent_coefficients[
                            local])) {
                out.note =
                    "stage3:verifier_air:chunk_rlc:"
                    "coefficient";
                return out;
            }
        }
        receipt.coefficient_statement =
            CommitChunkRlcCoefficientsV1(
                receipt.chunk,
                out.ordered_precommit_statement,
                receipt.independent_coefficients);
        if (receipt.coefficient_statement.IsNull()) {
            out.note =
                "stage3:verifier_air:chunk_rlc:"
                "coefficient_statement";
            return out;
        }
        receipt.local_relation =
            BuildChunkRlcLocalRelationV1(
                out.trace_rows,
                receipt.column_count,
                receipt.independent_coefficients);
        if (receipt.local_relation.constraints.empty()) {
            out.note =
                "stage3:verifier_air:chunk_rlc:"
                "local_relation_shape";
            return out;
        }
        receipt.local_relation_columns.assign(
            receipt.column_count + 1,
            std::vector<Fp3>(
                out.trace_rows, Fp3::Zero()));
        for (uint32_t local = 0;
             local < receipt.column_count; ++local) {
            receipt.local_relation_columns[local] =
                columns[
                    receipt.first_column + local];
        }
        auto& rlc =
            receipt.local_relation_columns[
                receipt.column_count];
        for (uint32_t row = 0;
             row < out.trace_rows; ++row) {
            for (uint32_t local = 0;
                 local < receipt.column_count;
                 ++local) {
                rlc[row] = gf::Add(
                    rlc[row],
                    gf::Mul(
                        receipt
                            .independent_coefficients[
                                local],
                        columns[
                            receipt.first_column +
                            local][row]));
            }
        }
        receipt.rlc_column_root =
            ChunkRlcColumnRootV1(rlc);
        receipt.openings.reserve(
            query_indices.size());
        for (uint32_t query = 0;
             query < query_indices.size();
             ++query) {
            const uint32_t current =
                query_indices[query];
            const uint32_t next =
                (current + next_step) %
                out.trace_rows;
            receipt.openings.push_back({
                query, current, next,
                rlc[current], rlc[next]});
        }
        receipt.full_chunk_committed_before_coefficients =
            true;
        receipt
            .independent_coefficients_derived_post_commit =
            true;
        receipt.local_rlc_relation_satisfied =
            CountVerifierScalarViolations(
                receipt.local_relation,
                receipt.local_relation_columns) == 0;
        receipt.current_next_openings_complete =
            receipt.openings.size() ==
                query_indices.size();
        receipt.receipt_statement =
            CommitChunkRlcReceiptV1(receipt);
        if (!receipt.local_rlc_relation_satisfied ||
            receipt.receipt_statement.IsNull()) {
            out.note =
                "stage3:verifier_air:chunk_rlc:receipt";
            return out;
        }
        out.locally_checked_cells +=
            uint64_t{out.trace_rows} *
            receipt.column_count;
    }
    std::vector<uint256> level;
    level.reserve(out.receipts.size());
    for (const auto& receipt : out.receipts) {
        level.push_back(
            receipt.receipt_statement);
    }
    uint32_t level_number = 1;
    while (level.size() > 1) {
        std::vector<uint256> next;
        for (uint32_t begin = 0;
             begin < level.size();
             begin += kChunkRlcArityV1) {
            ChunkRlcAggregateNodeV1 node;
            node.level = level_number;
            node.index =
                static_cast<uint32_t>(next.size());
            node.child_count =
                std::min<uint32_t>(
                    kChunkRlcArityV1,
                    static_cast<uint32_t>(
                        level.size() - begin));
            for (uint32_t child = 0;
                 child < node.child_count; ++child) {
                node.child_statements[child] =
                    level[begin + child];
            }
            node.node_statement =
                CommitChunkRlcAggregateNodeV1(node);
            if (node.node_statement.IsNull()) {
                out.note =
                    "stage3:verifier_air:chunk_rlc:"
                    "aggregate";
                return out;
            }
            next.push_back(node.node_statement);
            out.aggregate_nodes.push_back(node);
        }
        level = std::move(next);
        ++level_number;
    }
    out.root_statement = level.front();
    out.exact_column_partition = true;
    out.commitments_precede_challenges = true;
    out.independent_post_commit_coefficients = true;
    out.one_current_next_rlc_per_chunk_query = true;
    out.arity_four_receipt_tree_complete =
        !out.root_statement.IsNull();
    out.original_constraint_relation_bound = false;
    out.cross_chunk_constraint_manifest_complete =
        false;
    out.original_quotient_linked = false;
    out.recursively_consumed_receipts = 0;
    out.normalized_recursive_consumption_complete =
        false;
    out.production_authority_ready = false;
    out.valid =
        out.exact_column_partition &&
        out.commitments_precede_challenges &&
        out.independent_post_commit_coefficients &&
        out.one_current_next_rlc_per_chunk_query &&
        out.arity_four_receipt_tree_complete &&
        !out.original_constraint_relation_bound &&
        !out.cross_chunk_constraint_manifest_complete &&
        !out.original_quotient_linked &&
        out.recursively_consumed_receipts == 0 &&
        !out.normalized_recursive_consumption_complete &&
        !out.production_authority_ready;
    out.note = out.valid
        ? "stage3:verifier_air:chunk_rlc:"
          "local_rlc_exact;original_constraint_"
          "and_quotient_pending;recursive_consumption_0;"
          "authority_false"
        : "stage3:verifier_air:chunk_rlc:invalid";
    return out;
}

bool VerifyChunkRlcPcsStatementV1(
    const std::vector<std::vector<Fp3>>& columns,
    const std::vector<uint32_t>& query_indices,
    const ChunkRlcPcsStatementV1& statement,
    std::string* why)
{
    const auto expected =
        BuildChunkRlcPcsStatementV1(
            columns, query_indices,
            statement.next_step,
            statement.chunk_columns,
            statement.public_seed);
    if (!statement.valid || !expected.valid ||
        statement.version !=
            kChunkRlcPcsVersionV1 ||
        statement.trace_rows !=
            expected.trace_rows ||
        statement.total_columns !=
            expected.total_columns ||
        statement.chunk_count !=
            expected.chunk_count ||
        statement.query_count !=
            expected.query_count ||
        statement.ordered_precommit_statement !=
            expected.ordered_precommit_statement ||
        statement.root_statement !=
            expected.root_statement ||
        statement.locally_checked_cells !=
            expected.locally_checked_cells ||
        statement.recursively_consumed_receipts != 0 ||
        statement.original_constraint_relation_bound ||
        statement.cross_chunk_constraint_manifest_complete ||
        statement.original_quotient_linked ||
        statement.normalized_recursive_consumption_complete ||
        statement.production_authority_ready ||
        statement.receipts.size() !=
            expected.receipts.size() ||
        statement.aggregate_nodes !=
            expected.aggregate_nodes) {
        return Fail(why, "chunk_rlc_statement");
    }
    for (uint32_t chunk = 0;
         chunk < statement.receipts.size();
         ++chunk) {
        const auto& lhs = statement.receipts[chunk];
        const auto& rhs = expected.receipts[chunk];
        if (lhs.chunk != rhs.chunk ||
            lhs.first_column != rhs.first_column ||
            lhs.column_count != rhs.column_count ||
            lhs.full_chunk_root != rhs.full_chunk_root ||
            lhs.rlc_column_root != rhs.rlc_column_root ||
            lhs.precommit_statement !=
                rhs.precommit_statement ||
            lhs.coefficient_statement !=
                rhs.coefficient_statement ||
            lhs.receipt_statement !=
                rhs.receipt_statement ||
            lhs.openings != rhs.openings ||
            lhs.independent_coefficients.size() !=
                rhs.independent_coefficients.size() ||
            lhs.local_relation_columns.size() !=
                rhs.local_relation_columns.size() ||
            !SameMultiRowV2ConstraintShapeV1(
                lhs.local_relation,
                rhs.local_relation) ||
            !lhs.full_chunk_committed_before_coefficients ||
            !lhs
                .independent_coefficients_derived_post_commit ||
            !lhs.local_rlc_relation_satisfied ||
            !lhs.current_next_openings_complete ||
            CountVerifierScalarViolations(
                lhs.local_relation,
                lhs.local_relation_columns) != 0) {
            return Fail(why, "chunk_rlc_receipt");
        }
        for (uint32_t local = 0;
             local <
                 lhs.independent_coefficients.size();
             ++local) {
            if (!gf::Eq(
                    lhs.independent_coefficients[local],
                    rhs.independent_coefficients[local])) {
                return Fail(
                    why, "chunk_rlc_coefficient");
            }
        }
        for (uint32_t column = 0;
             column <
                 lhs.local_relation_columns.size();
             ++column) {
            if (lhs.local_relation_columns[column].size() !=
                rhs.local_relation_columns[column].size()) {
                return Fail(
                    why, "chunk_rlc_relation_column");
            }
            for (uint32_t row = 0;
                 row <
                     lhs.local_relation_columns[column]
                         .size();
                 ++row) {
                if (!gf::Eq(
                        lhs.local_relation_columns[column][row],
                        rhs.local_relation_columns[column][row])) {
                    return Fail(
                        why,
                        "chunk_rlc_relation_value");
                }
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:verifier_air:chunk_rlc:"
            "local_exact;recursive_consumption_pending";
    }
    return true;
}

ChunkRlcCostSelectionV1
AssessChunkRlcCostSelectionV1(
    uint32_t total_columns,
    uint32_t trace_rows,
    uint32_t query_count,
    uint32_t merkle_depth)
{
    ChunkRlcCostSelectionV1 out;
    if (total_columns == 0 ||
        trace_rows < 2 ||
        (trace_rows & (trace_rows - 1)) != 0 ||
        query_count == 0 ||
        merkle_depth == 0) {
        out.note =
            "stage3:verifier_air:chunk_rlc_cost:shape";
        return out;
    }
    const std::array<uint32_t, 2> sizes{
        256, 512};
    uint64_t best_score =
        std::numeric_limits<uint64_t>::max();
    uint32_t best = 0;
    for (uint32_t candidate = 0;
         candidate < sizes.size(); ++candidate) {
        auto& plan = out.candidates[candidate];
        plan.chunk_columns = sizes[candidate];
        plan.total_columns = total_columns;
        plan.trace_rows = trace_rows;
        plan.query_count = query_count;
        plan.merkle_depth = merkle_depth;
        plan.chunk_count =
            static_cast<uint32_t>(
                CeilDiv(
                    total_columns,
                    plan.chunk_columns));
        uint32_t nodes = 0;
        uint32_t level = plan.chunk_count;
        while (level > 1) {
            level = static_cast<uint32_t>(
                CeilDiv(level, kChunkRlcArityV1));
            nodes += level;
            ++plan.aggregation_levels;
        }
        plan.aggregation_nodes = nodes;
        plan.maximum_leaf_relation_width =
            std::min(
                plan.chunk_columns,
                total_columns) + 1;
        plan.normalized_root_width =
            stage3_poseidon_air::kFixedColumns +
            kMultiRowV2VerifierColumns + 1;
        const uint64_t rows_per_child =
            uint64_t{query_count} * 2 *
                (merkle_depth + 1) +
            32;
        plan.normalized_root_active_rows =
            kChunkRlcArityV1 *
            rows_per_child;
        plan.normalized_root_trace_rows =
            NextPowerOfTwoV1(
                plan.normalized_root_active_rows);
        plan.local_relation_cells =
            uint64_t{trace_rows} *
            (uint64_t{total_columns} +
             plan.chunk_count);
        // Construct the same canonical degree-1 AIR used by every actual
        // chunk receipt, then derive the quotient and FRI domains from it.
        // This must not silently regress to trace_rows * blowup if the leaf
        // relation gains a higher-degree or boundary constraint.
        const uint32_t leaf_input_columns =
            plan.maximum_leaf_relation_width - 1;
        const aq::AirConstraintSystem<Fp3>
            leaf_relation =
                BuildChunkRlcLocalRelationV1(
                    trace_rows,
                    leaf_input_columns,
                    std::vector<Fp3>(
                        leaf_input_columns,
                        Fp3::Zero()));
        const ChunkRlcLeafDomainAuditV1 leaf_domain =
            AssessChunkRlcLeafDomainV1(leaf_relation);
        plan.leaf_max_composed_degree =
            leaf_domain.max_composed_degree;
        plan.leaf_quotient_len =
            leaf_domain.quotient_len;
        plan.leaf_n_coeffs =
            leaf_domain.n_coeffs;
        plan.leaf_n_lde =
            leaf_domain.n_lde;
        plan.leaf_domain_exact =
            leaf_domain.valid &&
            leaf_domain.exact_quotient_degree_accounting;
        const uint64_t total_relation_columns =
            uint64_t{total_columns} +
            plan.chunk_count;
        const uint64_t total_proof_columns =
            uint64_t{total_columns} +
            2 * uint64_t{plan.chunk_count};
        uint64_t base_cells = 0;
        uint64_t lde_cells = 0;
        plan.cost_arithmetic_exact =
            CheckedMulU64(
                total_relation_columns,
                trace_rows,
                base_cells) &&
            CheckedMulU64(
                base_cells, 24,
                plan.all_leaf_base_witness_bytes) &&
            CheckedMulU64(
                total_proof_columns,
                plan.leaf_n_lde,
                lde_cells) &&
            CheckedMulU64(
                lde_cells, 24,
                plan.all_leaf_lde_column_bytes);
        const uint32_t fold_count =
            merkle_depth > 4
            ? merkle_depth - 4
            : 0;
        const uint64_t fold_depth_sum =
            fold_count == 0
            ? 0
            : uint64_t{fold_count} *
                    merkle_depth -
                uint64_t{fold_count} *
                    (fold_count - 1) / 2;
        const uint64_t per_query_values =
            uint64_t{24} *
            (2 * uint64_t{total_columns} +
             3 * uint64_t{plan.chunk_count});
        const uint64_t per_query_paths =
            uint64_t{plan.chunk_count} *
            (uint64_t{5} * merkle_depth * 32 +
             uint64_t{fold_count} * 2 * 24 +
             uint64_t{2} * 32 *
                 fold_depth_sum);
        const uint64_t ood_evaluations =
            uint64_t{48} * total_proof_columns;
        plan.estimated_all_leaf_proof_bytes =
            uint64_t{query_count} *
                (per_query_values +
                 per_query_paths) +
            ood_evaluations;
        plan.estimated_root_opening_bytes =
            uint64_t{query_count} *
            kChunkRlcArityV1 *
            (2 * 24 +
             uint64_t{2} *
                 merkle_depth * 32);
        plan.backend_caps_met =
            plan.maximum_leaf_relation_width <
                kChunkRlcRecursiveColumnCapV1 &&
            plan.normalized_root_width <
                kChunkRlcRecursiveColumnCapV1 &&
            plan.normalized_root_trace_rows != 0 &&
            plan.leaf_domain_exact &&
            leaf_domain.backend_lde_cap_met &&
            plan.cost_arithmetic_exact &&
            plan.normalized_root_trace_rows <=
                (uint32_t{1} <<
                 kRCFriMaxColumnLog2);
        plan.original_constraint_relation_bound =
            false;
        plan.cross_chunk_constraint_manifest_complete =
            false;
        plan.original_quotient_linked = false;
        plan.timing_measured = false;
        plan.timing_target_met = false;
        plan.note = plan.backend_caps_met
            ? "exact_shape;original_constraint_and_"
              "quotient_pending;root_timing_pending"
            : "backend_cap_fail";
        const uint64_t score =
            plan.local_relation_cells +
            uint64_t{plan.aggregation_nodes} *
                plan.normalized_root_trace_rows *
                plan.normalized_root_width;
        if (plan.backend_caps_met &&
            score < best_score) {
            best_score = score;
            best = candidate;
        }
    }
    if (best_score ==
        std::numeric_limits<uint64_t>::max()) {
        out.note =
            "stage3:verifier_air:chunk_rlc_cost:no_fit";
        return out;
    }
    out.candidates[best].selected = true;
    out.selected_chunk_columns =
        out.candidates[best].chunk_columns;
    out.valid = true;
    out.note =
        "stage3:verifier_air:chunk_rlc_cost:"
        "exact_cells_selected;timing_unmeasured;"
        "authority_false";
    return out;
}

namespace {

ChunkRlcInterleavedPoseidonWitnessV1
BuildChunkRlcInterleavedPoseidonV1(
    ChunkRlcInterleavedPoseidonKindV1 kind,
    const alg_hash::State& input,
    bool value_literal,
    bool sibling_literal)
{
    ChunkRlcInterleavedPoseidonWitnessV1 out;
    out.kind = kind;
    const auto layout =
        stage3_poseidon_air::CanonicalLayout();
    out.selector_column = layout.End();
    out.trace_columns = out.selector_column + 1;
    out.value_input_base =
        layout.perm.InputCol(0);
    out.sibling_input_base =
        kind ==
                ChunkRlcInterleavedPoseidonKindV1::
                    MerkleNode
        ? layout.perm.InputCol(4)
        : UINT32_MAX;
    out.columns.assign(
        out.trace_columns,
        std::vector<Fp3>(
            out.trace_rows, Fp3::Zero()));
    const auto witness =
        stage3_poseidon_air::BuildWitness(
            layout, input);
    if (witness.row.size() != layout.End()) {
        out.note =
            "stage3:verifier_air:chunk_rlc_poseidon:"
            "witness";
        return out;
    }
    for (uint32_t column = 0;
         column < layout.End(); ++column) {
        out.columns[column][0] =
            witness.row[column];
    }
    out.columns[out.selector_column][0] =
        Fp3::One();
    for (uint32_t limb = 0; limb < 4; ++limb) {
        out.output[limb] =
            gf::Canonical(
                witness.output[limb]);
    }
    auto& cs = out.constraint_system;
    cs.n_rows = out.trace_rows;
    cs.n_columns = out.trace_columns;
    cs.preprocessed_pin_ood = true;
    cs.preprocessed.emplace_back(
        out.selector_column,
        out.columns[out.selector_column]);
    cs.constraints =
        stage3_poseidon_air::
            BuildSelectorGatedConstraints(
                layout, out.selector_column);
    const auto add_constant =
        [&](uint32_t lane, Fp expected) {
            aq::AirConstraint<Fp3> constraint;
            constraint.name =
                "stage3.chunk_rlc.poseidon_capacity";
            constraint.kind =
                aq::AirKind::kEverywhere;
            constraint.alg_degree = 2;
            constraint.eval =
                [selector = out.selector_column,
                 column =
                     layout.perm.InputCol(lane),
                 expected =
                     Fp3::FromFp(expected)](
                    const std::vector<Fp3>& row,
                    const std::vector<Fp3>&) {
                    return gf::Mul(
                        row[selector],
                        gf::Sub(
                            row[column], expected));
                };
            cs.constraints.push_back(
                std::move(constraint));
        };
    if (kind ==
        ChunkRlcInterleavedPoseidonKindV1::
            RlcLeaf) {
        add_constant(
            4,
            alg_hash::GetAlgHashConstants()
                .leaf_domain);
        for (uint32_t lane = 5;
             lane < alg_hash::kAlgHashT; ++lane) {
            add_constant(lane, 0);
        }
    } else {
        add_constant(
            8,
            alg_hash::GetAlgHashConstants()
                .node_domain);
        for (uint32_t lane = 9;
             lane < alg_hash::kAlgHashT; ++lane) {
            add_constant(lane, 0);
        }
    }
    out.proof_value_is_literal_permutation_input =
        value_literal;
    out.sibling_is_literal_permutation_input =
        sibling_literal;
    out.valid =
        CountVerifierScalarViolations(
            cs, out.columns) == 0 &&
        out.proof_value_is_literal_permutation_input &&
        (kind ==
                 ChunkRlcInterleavedPoseidonKindV1::
                     RlcLeaf ||
         out.sibling_is_literal_permutation_input);
    out.note = out.valid
        ? "stage3:verifier_air:chunk_rlc_poseidon:"
          "literal_input_columns"
        : "stage3:verifier_air:chunk_rlc_poseidon:"
          "invalid";
    return out;
}

} // namespace

ChunkRlcInterleavedPoseidonWitnessV1
BuildChunkRlcInterleavedLeafV1(
    const Fp3& rlc_value, uint32_t index)
{
    alg_hash::State input{};
    input[0] = gf::Canonical(rlc_value.c0);
    input[1] = gf::Canonical(rlc_value.c1);
    input[2] = gf::Canonical(rlc_value.c2);
    input[3] = gf::FromU64(index);
    input[4] =
        alg_hash::GetAlgHashConstants()
            .leaf_domain;
    return BuildChunkRlcInterleavedPoseidonV1(
        ChunkRlcInterleavedPoseidonKindV1::RlcLeaf,
        input, true, false);
}

ChunkRlcInterleavedPoseidonWitnessV1
BuildChunkRlcInterleavedNodeV1(
    const alg_hash::Digest& accumulator,
    const alg_hash::Digest& sibling,
    bool sibling_on_left)
{
    alg_hash::State input{};
    const auto& left =
        sibling_on_left ? sibling : accumulator;
    const auto& right =
        sibling_on_left ? accumulator : sibling;
    for (uint32_t limb = 0; limb < 4; ++limb) {
        input[limb] =
            gf::Canonical(left[limb]);
        input[4 + limb] =
            gf::Canonical(right[limb]);
    }
    input[8] =
        alg_hash::GetAlgHashConstants()
            .node_domain;
    auto out =
        BuildChunkRlcInterleavedPoseidonV1(
            ChunkRlcInterleavedPoseidonKindV1::
                MerkleNode,
            input, true, true);
    out.sibling_input_base =
        sibling_on_left ? 0 : 4;
    return out;
}

bool BuildVerifierScalarSystem(
    const VerifierProgram& program,
    aq::AirConstraintSystem<Fp3>& out,
    std::string* why)
{
    if (!ValidateCanonicalVerifierProgram(program, why)) return false;
    const ScalarLayout layout = CanonicalScalarLayout();
    out = {};
    out.n_rows = program.trace_rows;
    out.n_columns = layout.End();
    out.constraints = BuildScalarConstraints(layout);
    for (uint32_t op = 0; op < kScalarOpCount; ++op) {
        std::vector<Fp3> selector(program.trace_rows, Fp3::Zero());
        const ScalarOp scalar_op = static_cast<ScalarOp>(op);
        for (uint32_t row = 0; row < program.trace_rows; ++row) {
            if (IsScalarKind(program.rows[row].kind) &&
                OpForKind(program.rows[row].kind) == scalar_op) {
                selector[row] = Fp3::One();
            }
        }
        out.preprocessed.push_back(
            {layout.Selector(scalar_op), std::move(selector)});
    }
    out.preprocessed_pin_ood = true;
    return true;
}

bool BuildVerifierScalarWitness(
    const VerifierProgram& program,
    const std::vector<ScalarRowWitness>& rows,
    std::vector<std::vector<Fp3>>& columns,
    std::string* why)
{
    aq::AirConstraintSystem<Fp3> cs;
    if (!BuildVerifierScalarSystem(program, cs, why)) return false;
    size_t expected_rows = 0;
    for (const ProgramRow& row : program.rows) {
        if (IsScalarKind(row.kind)) ++expected_rows;
    }
    if (rows.size() != expected_rows) {
        return Fail(why, "scalar_row_count");
    }
    const ScalarLayout layout = CanonicalScalarLayout();
    columns.assign(
        cs.n_columns,
        std::vector<Fp3>(cs.n_rows, Fp3::Zero()));
    for (const auto& [column, values] : cs.preprocessed) {
        columns[column] = values;
    }
    size_t cursor = 0;
    for (uint32_t program_row = 0; program_row < program.trace_rows;
         ++program_row) {
        const ProgramRow& scheduled = program.rows[program_row];
        if (!IsScalarKind(scheduled.kind)) continue;
        if (cursor >= rows.size()) return Fail(why, "scalar_row_missing");
        const ScalarRowWitness& witness = rows[cursor++];
        if (witness.program_row != program_row ||
            witness.op != OpForKind(scheduled.kind)) {
            return Fail(why, "scalar_row_order");
        }
        for (uint32_t lane = 0; lane < 4; ++lane) {
            columns[layout.accumulator_base + lane][program_row] =
                witness.accumulator[lane];
            columns[layout.sibling_base + lane][program_row] =
                witness.sibling[lane];
            columns[layout.left_base + lane][program_row] =
                witness.left[lane];
            columns[layout.right_base + lane][program_row] =
                witness.right[lane];
        }
        columns[layout.a][program_row] = witness.a;
        columns[layout.b][program_row] = witness.b;
        columns[layout.c][program_row] = witness.c;
        columns[layout.d][program_row] = witness.d;
        columns[layout.out][program_row] = witness.out;
        columns[layout.direction][program_row] = witness.direction;
    }
    return cursor == rows.size();
}

std::vector<ScalarRowWitness>
BuildDeterministicScalarWitness(const VerifierProgram& program)
{
    std::vector<ScalarRowWitness> out;
    if (!program.valid) return out;
    for (uint32_t row = 0; row < program.trace_rows; ++row) {
        const ProgramRow& scheduled = program.rows[row];
        if (!IsScalarKind(scheduled.kind)) continue;
        ScalarRowWitness witness;
        witness.program_row = row;
        witness.op = OpForKind(scheduled.kind);
        const uint64_t seed = static_cast<uint64_t>(row) + 17;
        if (witness.op == ScalarOp::MerkleRoute) {
            witness.direction =
                Fp3::FromFp(gf::FromU64(seed & 1));
            for (uint32_t lane = 0; lane < 4; ++lane) {
                witness.accumulator[lane] =
                    Fp3::FromFp(gf::FromU64(seed + lane + 1));
                witness.sibling[lane] =
                    Fp3::FromFp(gf::FromU64(seed + lane + 101));
                const bool direction = (seed & 1) != 0;
                witness.left[lane] =
                    direction ? witness.sibling[lane]
                              : witness.accumulator[lane];
                witness.right[lane] =
                    direction ? witness.accumulator[lane]
                              : witness.sibling[lane];
            }
        } else if (witness.op == ScalarOp::FoldAlgebra) {
            witness.a = Fp3::FromFp(gf::FromU64(seed + 1));
            witness.b = Fp3::FromFp(gf::FromU64(seed + 2));
            witness.c = Fp3::FromFp(gf::FromU64(seed + 3));
            witness.d = Fp3::FromFp(gf::FromU64(seed + 4));
            const Fp3 numerator = gf::Add(
                gf::Mul(witness.c, gf::Add(witness.a, witness.b)),
                gf::Mul(witness.d, gf::Sub(witness.a, witness.b)));
            witness.out = gf::Mul(
                numerator,
                gf::Inv(gf::Mul(
                    Fp3::FromFp(gf::FromU64(2)), witness.c)));
        } else if (witness.op == ScalarOp::DeepAccumulate) {
            witness.a = Fp3::FromFp(gf::FromU64(seed + 1));
            witness.b = Fp3::FromFp(gf::FromU64(seed + 2));
            witness.c = Fp3::FromFp(gf::FromU64(seed + 3));
            witness.out =
                gf::Add(gf::Mul(witness.a, witness.b), witness.c);
        } else if (witness.op == ScalarOp::PerPointIdentity) {
            witness.b = Fp3::FromFp(gf::FromU64(seed + 1));
            witness.c = Fp3::FromFp(gf::FromU64(seed + 2));
            witness.a = gf::Mul(witness.b, witness.c);
        } else {
            witness.a = Fp3::FromFp(gf::FromU64(seed + 1));
            witness.out = witness.a;
        }
        out.push_back(std::move(witness));
    }
    return out;
}

uint32_t CountVerifierScalarViolations(
    const aq::AirConstraintSystem<Fp3>& cs,
    const std::vector<std::vector<Fp3>>& columns,
    uint32_t* first_row,
    std::string* first_constraint)
{
    if (columns.size() != cs.n_columns) {
        if (first_constraint != nullptr) {
            *first_constraint = "stage3.verifier.shape";
        }
        return 1;
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            if (first_constraint != nullptr) {
                *first_constraint = "stage3.verifier.shape";
            }
            return 1;
        }
    }
    uint32_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        std::vector<Fp3> cur(cs.n_columns);
        std::vector<Fp3> next(cs.n_columns);
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            cur[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (!gf::IsZero(constraint.eval(cur, next))) {
                if (violations == 0) {
                    if (first_row != nullptr) *first_row = row;
                    if (first_constraint != nullptr) {
                        *first_constraint = constraint.name;
                    }
                }
                ++violations;
            }
        }
    }
    return violations;
}

} // namespace matmul::v4::rc::stage3_verifier_air
