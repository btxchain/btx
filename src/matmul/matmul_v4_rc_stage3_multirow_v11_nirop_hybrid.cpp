// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_nirop_hybrid.h>

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <array>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid {
namespace {

using gf::Fp;
using gf::Fp3;

inline constexpr uint64_t kAirLambdaDomain =
    0x4d525032'4149524cull; // "MRP2AIRL"
inline constexpr uint64_t kFriSeedDomain =
    0x4d525032'46524953ull; // "MRP2FRIS"
inline constexpr uint64_t kZ1Domain =
    0x4d525032'5a314b32ull; // "MRP2Z1K2"
inline constexpr uint64_t kZ2Domain =
    0x4d525032'5a324b32ull; // "MRP2Z2K2"
inline constexpr uint64_t kBatchSeedDomain =
    0x4d525032'42415453ull; // "MRP2BATS"
inline constexpr uint64_t kCoefficientDomain =
    0x4d525032'434f4546ull; // "MRP2COEF"
inline constexpr uint64_t kWeightDomain =
    0x4d525032'57454947ull; // "MRP2WEIG"
inline constexpr uint64_t kFoldStateDomain =
    0x4d525032'464f4c53ull; // "MRP2FOLS"
inline constexpr uint64_t kFoldBetaDomain =
    0x4d525032'464f4c42ull; // "MRP2FOLB"
inline constexpr uint64_t kQuerySeedDomain =
    0x4d525032'51534545ull; // "MRP2QSEE"
inline constexpr uint64_t kQueryCandidateDomain =
    0x4d525032'5143414eull; // "MRP2QCAN"
inline constexpr uint64_t kPaddingDomain =
    0x4d525032'50414430ull; // "MRP2PAD0"

constexpr std::array<TranscriptDomainV1, kTranscriptDomainCountV1>
    kDomains{{
        {TranscriptRoleV1::ShapeCommit,
         kRCFri3AlgShapeCommitDomain, "shape_commit"},
        {TranscriptRoleV1::AirLambda,
         kAirLambdaDomain, "air_lambda"},
        {TranscriptRoleV1::FriSeed,
         kFriSeedDomain, "fri_seed"},
        {TranscriptRoleV1::OodZ1Candidate,
         kZ1Domain, "ood_z1_candidate"},
        {TranscriptRoleV1::OodZ2Candidate,
         kZ2Domain, "ood_z2_candidate"},
        {TranscriptRoleV1::OodEvaluationCommit,
         kRCFri3AlgOodEvalCommitDomain, "ood_evaluation_commit"},
        {TranscriptRoleV1::BatchSeed,
         kBatchSeedDomain, "batch_seed"},
        {TranscriptRoleV1::BatchCoefficient,
         kCoefficientDomain, "batch_coefficient"},
        {TranscriptRoleV1::DeepWeight,
         kWeightDomain, "deep_weight"},
        {TranscriptRoleV1::FoldState,
         kFoldStateDomain, "fold_state"},
        {TranscriptRoleV1::FoldBeta,
         kFoldBetaDomain, "fold_beta"},
        {TranscriptRoleV1::QuerySeed,
         kQuerySeedDomain, "query_seed"},
        {TranscriptRoleV1::QueryCandidate,
         kQueryCandidateDomain, "query_candidate"},
        {TranscriptRoleV1::Padding,
         kPaddingDomain, "padding"},
    }};

constexpr std::array<TypedHashRoleV1, 20> kTypedRoles{{
    TypedHashRoleV1::MerkleRowLeaf,
    TypedHashRoleV1::MerkleFoldLeaf,
    TypedHashRoleV1::MerkleInternalNode,
    TypedHashRoleV1::TranscriptShapeCommit,
    TypedHashRoleV1::TranscriptAirLambda,
    TypedHashRoleV1::TranscriptFriSeed,
    TypedHashRoleV1::TranscriptOodZ1,
    TypedHashRoleV1::TranscriptOodZ2,
    TypedHashRoleV1::TranscriptOodEvaluations,
    TypedHashRoleV1::TranscriptBatchSeed,
    TypedHashRoleV1::TranscriptBatchCoefficient,
    TypedHashRoleV1::TranscriptDeepWeight,
    TypedHashRoleV1::TranscriptFoldState,
    TypedHashRoleV1::TranscriptFoldBeta,
    TypedHashRoleV1::TranscriptQuerySeed,
    TypedHashRoleV1::TranscriptQueryCandidate,
    TypedHashRoleV1::TranscriptPadding,
    TypedHashRoleV1::ReceiptCommitment,
    TypedHashRoleV1::ProgramTableCommitment,
    TypedHashRoleV1::ApplicationStatementCommitment,
}};

void AppendU32(std::vector<Fp>& out, uint32_t value)
{
    out.push_back(gf::FromU64(value));
}

void AppendU64(std::vector<Fp>& out, uint64_t value)
{
    AppendU32(out, static_cast<uint32_t>(value));
    AppendU32(out, static_cast<uint32_t>(value >> 32));
}

void AppendSeed(std::vector<Fp>& out, const uint256& seed)
{
    for (uint32_t word = 0; word < 4; ++word) {
        AppendU64(out, seed.GetUint64(word));
    }
}

void AppendDigest(std::vector<Fp>& out, const Fri3AlgDigest& digest)
{
    for (Fp lane : digest) out.push_back(gf::Canonical(lane));
}

void AppendFp3(std::vector<Fp>& out, const Fp3& value)
{
    out.push_back(gf::Canonical(value.c0));
    out.push_back(gf::Canonical(value.c1));
    out.push_back(gf::Canonical(value.c2));
}

bool DigestEqual(const Fri3AlgDigest& a, const Fri3AlgDigest& b)
{
    return std::equal(
        a.begin(), a.end(), b.begin(),
        [](Fp left, Fp right) {
            return gf::Canonical(left) == gf::Canonical(right);
        });
}

bool Fp3Equal(const Fp3& a, const Fp3& b)
{
    return gf::Eq(a, b);
}

Fp3 DigestFp3(const Fri3AlgDigest& digest)
{
    return {gf::Canonical(digest[0]),
            gf::Canonical(digest[1]),
            gf::Canonical(digest[2])};
}

Fri3AlgDigest Hash(
    uint64_t domain, const std::vector<Fp>& lanes,
    uint32_t& event_count)
{
    ++event_count;
    return Fri3AlgAlgebraicTranscriptDigest(lanes, domain);
}

std::vector<Fp> Padded(std::vector<Fp> lanes)
{
    lanes.push_back(gf::FromU64(1));
    while (lanes.size() % alg_hash::kAlgHashRate != 0) {
        lanes.push_back(gf::FromU64(0));
    }
    return lanes;
}

CrossRoleIdenticalInputV1 IdenticalRowWitness(
    TranscriptRoleV1 role, uint64_t domain,
    const Fri3AlgDigest& seed, uint32_t ordinal)
{
    CrossRoleIdenticalInputV1 out;
    out.transcript_role = role;
    out.transcript_domain = domain;
    AppendU64(out.transcript_sponge_input, domain);
    AppendDigest(out.transcript_sponge_input, seed);
    AppendU32(out.transcript_sponge_input, ordinal);
    out.row_cells[0] = {
        out.transcript_sponge_input[0],
        out.transcript_sponge_input[1],
        out.transcript_sponge_input[2]};
    out.row_cells[1] = {
        out.transcript_sponge_input[3],
        out.transcript_sponge_input[4],
        out.transcript_sponge_input[5]};
    out.row_index = ordinal;
    for (const auto& cell : out.row_cells) {
        AppendFp3(out.row_leaf_sponge_input, cell);
    }
    AppendU32(out.row_leaf_sponge_input, out.row_index);
    out.transcript_digest =
        alg_hash::SpongeHashFp(out.transcript_sponge_input);
    const std::vector<Fp3> row(
        out.row_cells.begin(), out.row_cells.end());
    out.row_leaf_digest =
        alg_hash::LeafHashRow(row, out.row_index);
    out.lane_vectors_identical =
        out.transcript_sponge_input == out.row_leaf_sponge_input;
    out.padded_inputs_identical =
        Padded(out.transcript_sponge_input) ==
        Padded(out.row_leaf_sponge_input);
    out.digests_identical_without_collision =
        out.lane_vectors_identical &&
        out.padded_inputs_identical &&
        DigestEqual(out.transcript_digest, out.row_leaf_digest);
    return out;
}

void SetTypedCapacity(
    alg_hash::State& state, TypedHashRoleV1 role)
{
    state[alg_hash::kAlgHashRate] =
        gf::Canonical(kTypedHashCapacityMagicV1);
    state[alg_hash::kAlgHashRate + 1] =
        gf::FromU64(static_cast<uint32_t>(role));
    state[alg_hash::kAlgHashRate + 2] =
        gf::FromU64(kTypedHashProtocolVersionV12);
    state[alg_hash::kAlgHashRate + 3] =
        gf::FromU64(kTypedHashVersionV1);
}

bool KnownTypedRole(TypedHashRoleV1 role)
{
    return std::find(kTypedRoles.begin(), kTypedRoles.end(), role) !=
        kTypedRoles.end();
}

bool KnownTypedSpongeRole(TypedHashRoleV1 role)
{
    return KnownTypedRole(role) &&
        role != TypedHashRoleV1::MerkleFoldLeaf &&
        role != TypedHashRoleV1::MerkleInternalNode;
}

void PermuteTyped(
    TypedHashRoleV1 role, alg_hash::State& state,
    std::vector<TypedPermutationCallV1>& calls)
{
    TypedPermutationCallV1 call;
    call.role = role;
    call.input = state;
    alg_hash::Permute(state);
    call.output = state;
    calls.push_back(call);
}

bool OutputMatchesAir(
    const TypedPermutationCallV1& call)
{
    const auto layout = stage3_poseidon_air::CanonicalLayout();
    const auto witness =
        stage3_poseidon_air::BuildWitness(layout, call.input);
    if (witness.output != call.output ||
        witness.row.size() != layout.End()) {
        return false;
    }
    for (uint32_t lane = 0; lane < alg_hash::kAlgHashT; ++lane) {
        const auto expected = Fp3::FromFp(call.input[lane]);
        if (!gf::Eq(
                witness.row[layout.perm.InputCol(lane)],
                expected)) {
            return false;
        }
    }
    return true;
}

} // namespace

const std::array<TranscriptDomainV1, kTranscriptDomainCountV1>&
CanonicalTranscriptDomainsV1()
{
    return kDomains;
}

TranscriptDagAuditV1 AssessV1(
    const p2::StatementV1& statement)
{
    TranscriptDagAuditV1 out;
    out.protocol_version = statement.protocol_version;
    out.protocol_domain = statement.protocol_domain;
    out.transcript_domain_count =
        static_cast<uint32_t>(kDomains.size());
    out.queries = p2::kQueriesV1;
    out.query_candidates = p2::kQueryCandidatesV1;
    out.expected_hash_events = p2::ExpectedHashEventsV1(
        static_cast<uint32_t>(statement.column_len.size()),
        static_cast<uint32_t>(statement.folds.size()));

    std::set<uint64_t> domains;
    bool split_canonical = true;
    for (const auto& item : kDomains) {
        domains.insert(item.domain);
        const Fp lo = gf::FromU64(
            static_cast<uint32_t>(item.domain));
        const Fp hi = gf::FromU64(
            static_cast<uint32_t>(item.domain >> 32));
        split_canonical &=
            gf::Canonical(lo) == static_cast<uint32_t>(item.domain) &&
            gf::Canonical(hi) ==
                static_cast<uint32_t>(item.domain >> 32);
    }
    out.fourteen_domains_pairwise_distinct =
        domains.size() == kDomains.size();
    out.u64_domains_split_into_two_canonical_u32_lanes =
        split_canonical;

    const auto native = p2::DeriveV1(statement);
    std::string native_why;
    out.native_receipt_verifies =
        native.valid &&
        p2::VerifyReceiptV1(statement, native, &native_why);
    if (!out.native_receipt_verifies) {
        out.required_protocol_change =
            "first repair the invalid native V11 transcript: " +
            native_why;
        out.note = "stage3:v11_nirop_hybrid:native_receipt_invalid";
        return out;
    }

    bool exact = true;
    uint32_t events = 0;
    std::vector<Fp> lanes;
    AppendU32(lanes, static_cast<uint32_t>(
        statement.column_len.size()));
    AppendU32(lanes, statement.n_coeffs);
    for (uint32_t length : statement.column_len) {
        AppendU32(lanes, length);
    }
    const auto shape = Hash(
        kRCFri3AlgShapeCommitDomain, lanes, events);
    exact &= DigestEqual(shape, native.shape_commit);

    lanes.clear();
    AppendU32(lanes, p2::kProtocolVersionV1);
    AppendU64(lanes, p2::kProtocolDomainV1);
    AppendSeed(lanes, statement.public_fs_seed);
    AppendU32(lanes, statement.trace_rows);
    AppendU32(lanes, statement.trace_columns);
    AppendU32(lanes, statement.quotient_len);
    AppendU32(lanes, statement.n_coeffs);
    AppendU32(lanes, static_cast<uint32_t>(
        statement.base_column_indices.size()));
    for (uint32_t index : statement.base_column_indices) {
        AppendU32(lanes, index);
    }
    AppendDigest(lanes, statement.groups[0].root);
    AppendDigest(lanes, statement.groups[1].root);
    const auto air_lambda =
        DigestFp3(Hash(kAirLambdaDomain, lanes, events));
    exact &= Fp3Equal(air_lambda, native.air_lambda);

    lanes.clear();
    AppendU32(lanes, p2::kProtocolVersionV1);
    AppendSeed(lanes, statement.public_fs_seed);
    AppendU64(lanes, statement.pow_grind_nonce);
    AppendFp3(lanes, air_lambda);
    AppendU32(lanes, statement.trace_rows);
    AppendU32(lanes, statement.trace_columns);
    AppendU32(lanes, statement.quotient_len);
    AppendU32(lanes, statement.n_coeffs);
    AppendU32(lanes, static_cast<uint32_t>(
        statement.base_column_indices.size()));
    for (uint32_t index : statement.base_column_indices) {
        AppendU32(lanes, index);
    }
    AppendDigest(lanes, shape);
    for (const auto& group : statement.groups) {
        AppendU32(lanes, static_cast<uint32_t>(group.role));
        AppendU32(lanes, group.first_column);
        AppendU32(lanes, group.column_count);
        AppendU32(lanes, group.n_leaves);
        AppendDigest(lanes, group.root);
    }
    const auto fri_seed = Hash(kFriSeedDomain, lanes, events);
    exact &= DigestEqual(fri_seed, native.fri_seed);

    for (uint32_t candidate = 0;
         candidate < p2::kOodCandidatesV1; ++candidate) {
        lanes.clear();
        AppendDigest(lanes, fri_seed);
        AppendU32(lanes,
            statement.n_coeffs * statement.blowup);
        AppendU32(lanes, candidate);
        exact &= Fp3Equal(
            DigestFp3(Hash(kZ1Domain, lanes, events)),
            native.z1_candidates[candidate]);
    }
    for (uint32_t candidate = 0;
         candidate < p2::kOodCandidatesV1; ++candidate) {
        lanes.clear();
        AppendDigest(lanes, fri_seed);
        AppendFp3(lanes, native.z1);
        AppendU32(lanes,
            statement.n_coeffs * statement.blowup);
        AppendU32(lanes, candidate);
        exact &= Fp3Equal(
            DigestFp3(Hash(kZ2Domain, lanes, events)),
            native.z2_candidates[candidate]);
    }

    lanes.clear();
    AppendU32(lanes, static_cast<uint32_t>(
        statement.evals_z1.size()));
    AppendU32(lanes, static_cast<uint32_t>(
        statement.evals_z2.size()));
    AppendFp3(lanes, native.z1);
    AppendFp3(lanes, native.z2);
    for (const auto& value : statement.evals_z1) AppendFp3(lanes, value);
    for (const auto& value : statement.evals_z2) AppendFp3(lanes, value);
    const auto ood = Hash(
        kRCFri3AlgOodEvalCommitDomain, lanes, events);
    exact &= DigestEqual(ood, native.ood_eval_commit);

    lanes.clear();
    AppendDigest(lanes, fri_seed);
    AppendFp3(lanes, native.z1);
    AppendFp3(lanes, native.z2);
    AppendDigest(lanes, ood);
    const auto batch_seed =
        Hash(kBatchSeedDomain, lanes, events);
    exact &= DigestEqual(batch_seed, native.batch_seed);
    for (uint32_t column = 0;
         column < statement.column_len.size(); ++column) {
        lanes.clear();
        AppendDigest(lanes, batch_seed);
        AppendU32(lanes, column);
        exact &= Fp3Equal(
            DigestFp3(Hash(kCoefficientDomain, lanes, events)),
            native.batching_coefficients[column]);
    }
    lanes.clear();
    AppendDigest(lanes, batch_seed);
    AppendU32(lanes, 1);
    exact &= Fp3Equal(
        DigestFp3(Hash(kWeightDomain, lanes, events)), native.w1);
    lanes.back() = gf::FromU64(2);
    exact &= Fp3Equal(
        DigestFp3(Hash(kWeightDomain, lanes, events)), native.w2);

    lanes.clear();
    AppendDigest(lanes, batch_seed);
    AppendFp3(lanes, native.w1);
    AppendFp3(lanes, native.w2);
    auto fold_state = Hash(kFoldStateDomain, lanes, events);
    uint32_t beta_index = 0;
    for (uint32_t fold = 0; fold < statement.folds.size(); ++fold) {
        lanes.clear();
        AppendDigest(lanes, fold_state);
        AppendU32(lanes, fold);
        AppendU32(lanes, statement.folds[fold].n_leaves);
        AppendDigest(lanes, statement.folds[fold].root);
        fold_state = Hash(kFoldStateDomain, lanes, events);
        if (fold + 1 != statement.folds.size()) {
            lanes.clear();
            AppendDigest(lanes, fold_state);
            AppendU32(lanes, fold);
            exact &= Fp3Equal(
                DigestFp3(Hash(kFoldBetaDomain, lanes, events)),
                native.fold_challenges[beta_index++]);
        }
    }
    lanes.clear();
    AppendDigest(lanes, fold_state);
    AppendFp3(lanes, statement.final_value);
    AppendU32(lanes, p2::kQueriesV1);
    AppendU32(lanes, p2::kQueryCandidatesV1);
    const auto query_seed =
        Hash(kQuerySeedDomain, lanes, events);
    exact &= DigestEqual(query_seed, native.query_seed);
    std::set<uint32_t> schedule_words;
    for (uint32_t query = 0; query < p2::kQueriesV1; ++query) {
        for (uint32_t candidate = 0;
             candidate < p2::kQueryCandidatesV1; ++candidate) {
            lanes.clear();
            AppendDigest(lanes, query_seed);
            const uint32_t word = (query << 8) | candidate;
            schedule_words.insert(word);
            AppendU32(lanes, word);
            exact &= DigestEqual(
                Hash(kQueryCandidateDomain, lanes, events),
                native.queries[query].candidate_digest[candidate]);
        }
    }
    out.independently_replayed_hash_events = events;
    out.independent_replay_matches_native_receipt =
        exact && events == out.expected_hash_events;

    out.statement_shape_precedes_shape_commit = true;
    out.statement_prefix_precedes_r0_rdep_roots_in_air_lambda = true;
    out.statement_prefix_precedes_all_roots_in_fri_seed = true;
    out.air_lambda_before_quotient_root = true;
    out.all_roots_before_ood_draws = true;
    out.ood_claims_before_batch_coefficients = true;
    out.each_fold_root_before_its_beta = true;
    out.terminal_before_query_seed = true;
    out.query_seed_before_all_q192_candidates = true;
    out.q192_k2_schedule_injective =
        schedule_words.size() ==
        size_t{p2::kQueriesV1} * p2::kQueryCandidatesV1;
    out.q192_with_replacement = native.q192_with_replacement;

    const auto rbr =
        soundness_scenarios::AssessFri3AlgBcsRbrLedgerV1();
    out.rbr_parameters_match_v11 =
        rbr.queries == p2::kQueriesV1 &&
        rbr.extension_degree == 3 &&
        rbr.blowup == statement.blowup &&
        rbr.lde_log2 >= 12 &&
        statement.n_coeffs * uint64_t{statement.blowup} <=
            (uint64_t{1} << rbr.lde_log2);
    out.q192_rbr_ledger_machine_checked =
        rbr.rbr_reduction_machine_checked;
    out.rbr_query_proximity_bits =
        rbr.query_proximity_floor_bits;
    out.rbr_poseidon_collision_bits =
        rbr.hash_collision_floor_bits;
    out.rbr_composed_single_lane_bits =
        rbr.composed_single_lane_floor_bits;

    const auto leaf_domain =
        alg_hash::GetAlgHashConstants().leaf_domain;
    const auto node_domain =
        alg_hash::GetAlgHashConstants().node_domain;
    out.fold_leaf_fixed_width_rate_tagged =
        leaf_domain != 0 && leaf_domain != node_domain;
    // V11 LeafHash places Le in rate lane 4, not capacity lane 8..11.
    out.fold_leaf_capacity_domain_separated = false;
    out.merkle_node_capacity_domain_separated =
        node_domain != 0 && node_domain != leaf_domain;
    out.row_leaf_role_domain_separated = false;
    out.v11_uses_add_absorb_sponge = true;
    out.v11_uses_overwrite_mode_duplex = false;
    out.v11_uses_instance_derived_capacity_start = false;
    out.published_duplex_fs_premises_match = false;
    out.custom_add_absorb_hash_chain_hybrid_complete = false;

    out.row_leaf_vs_coefficient = IdenticalRowWitness(
        TranscriptRoleV1::BatchCoefficient,
        kCoefficientDomain, batch_seed, 0);
    out.row_leaf_vs_fold_beta = IdenticalRowWitness(
        TranscriptRoleV1::FoldBeta,
        kFoldBetaDomain, fold_state, 0);
    out.row_leaf_vs_query_candidate = IdenticalRowWitness(
        TranscriptRoleV1::QueryCandidate,
        kQueryCandidateDomain, query_seed, 0);
    out.merkle_oracle_and_fs_sponge_inputs_disjoint =
        !out.row_leaf_vs_coefficient.digests_identical_without_collision &&
        !out.row_leaf_vs_fold_beta.digests_identical_without_collision &&
        !out.row_leaf_vs_query_candidate.digests_identical_without_collision;
    out.poseidon_first_collision_hybrid_complete =
        out.merkle_oracle_and_fs_sponge_inputs_disjoint;
    out.nirop_bcs_composition_complete = false;
    out.production_authority_ready = false;
    out.required_call_site_migrations = {
        "Fri3AlgBuildRowTreeCacheStreaming / StreamingRowHasher::Finalize "
        "(R0, Rdep and Rq row leaves)",
        "AlgHashRowLeafForLane and every verifier row-opening recomputation",
        "BuildAlgMerkleTree / fold LeafHash and every fold-opening recomputation",
        "BuildAlgMerkleTreeFromLeaves / Compress and every Merkle path node",
        "stage3_multirow_p2_transcript all fourteen transcript hash roles",
        "stage3_multirow_v11_receipt_join and receipt_join_q96 commitments",
        "stage3_multirow_v11_semantic_heavy/recursive receipt commitments",
        "stage3_multirow_v11_normalized_program ProgramTable commitments",
        "recursive verifier Poseidon hash chips and preprocessed event tapes",
    };
    out.required_protocol_change =
        "allocate protocol version 12 and a new wire/domain tag; initialize "
        "Poseidon2 capacity with the immutable (magic, typed-role, protocol, "
        "typed-hash-version) tuple for row leaves, fold leaves, internal "
        "nodes, each of the fourteen FS stages, receipt commitments and "
        "ProgramTable commitments; migrate native prove/verify and recursive "
        "replay together. Then either prove a custom ideal-permutation "
        "first-collision reduction for BTX's add-absorb hash chain, or move "
        "Fiat-Shamir to the instance-derived-capacity overwrite duplex "
        "construction analyzed in ePrint 2025/536; typed IVs alone do not "
        "instantiate that theorem. V11 cannot be reinterpreted in place.";
    out.note =
        "stage3:v11_nirop_hybrid:transcript_dag_replayed;"
        "q192_k2_and_rbr_inventory_checked;"
        "BLOCKED_zero_work_row_leaf_vs_fs_identical_preimage;"
        "BLOCKED_add_absorb_hash_chain_not_published_overwrite_dsfs;"
        "typed_v12_migration_required;"
        "authority_false";
    return out;
}

TypedHashResultV1 TypedSpongeHashFpV1(
    TypedHashRoleV1 role,
    const std::vector<Fp>& lanes)
{
    TypedHashResultV1 out;
    if (!KnownTypedSpongeRole(role)) return out;
    std::vector<Fp> padded;
    padded.reserve(lanes.size() + alg_hash::kAlgHashRate);
    for (Fp lane : lanes) padded.push_back(gf::Canonical(lane));
    padded.push_back(gf::FromU64(1));
    while (padded.size() % alg_hash::kAlgHashRate != 0) {
        padded.push_back(gf::FromU64(0));
    }
    alg_hash::State state{};
    SetTypedCapacity(state, role);
    for (uint32_t offset = 0; offset < padded.size();
         offset += alg_hash::kAlgHashRate) {
        for (uint32_t lane = 0; lane < alg_hash::kAlgHashRate; ++lane) {
            state[lane] =
                gf::Add(state[lane], padded[offset + lane]);
        }
        PermuteTyped(role, state, out.calls);
    }
    std::copy_n(state.begin(), out.digest.size(), out.digest.begin());
    out.valid = true;
    return out;
}

TypedHashResultV1 TypedRowLeafV1(
    const std::vector<Fp3>& row, uint32_t index)
{
    std::vector<Fp> lanes;
    lanes.reserve(3 * row.size() + 1);
    for (const auto& value : row) AppendFp3(lanes, value);
    AppendU32(lanes, index);
    return TypedSpongeHashFpV1(
        TypedHashRoleV1::MerkleRowLeaf, lanes);
}

TypedHashResultV1 TypedRowLeafStreamingV1(
    const std::vector<Fp3>& row, uint32_t index,
    uint32_t columns_per_block)
{
    TypedHashResultV1 out;
    if (columns_per_block == 0) return out;
    alg_hash::State state{};
    SetTypedCapacity(state, TypedHashRoleV1::MerkleRowLeaf);
    std::array<Fp, alg_hash::kAlgHashRate> pending{};
    uint32_t pending_count = 0;
    const auto absorb = [&](Fp value) {
        pending[pending_count++] = gf::Canonical(value);
        if (pending_count != alg_hash::kAlgHashRate) return;
        for (uint32_t lane = 0; lane < alg_hash::kAlgHashRate; ++lane) {
            state[lane] = gf::Add(state[lane], pending[lane]);
            pending[lane] = 0;
        }
        PermuteTyped(
            TypedHashRoleV1::MerkleRowLeaf, state, out.calls);
        pending_count = 0;
    };
    for (uint32_t begin = 0; begin < row.size();
         begin += columns_per_block) {
        const uint32_t end = std::min<uint32_t>(
            static_cast<uint32_t>(row.size()),
            begin + columns_per_block);
        for (uint32_t column = begin; column < end; ++column) {
            absorb(row[column].c0);
            absorb(row[column].c1);
            absorb(row[column].c2);
        }
    }
    absorb(gf::FromU64(index));
    absorb(gf::FromU64(1));
    while (pending_count != 0) absorb(gf::FromU64(0));
    std::copy_n(state.begin(), out.digest.size(), out.digest.begin());
    out.valid = true;
    return out;
}

TypedHashResultV1 TypedFoldLeafV1(
    const Fp3& value, uint32_t index)
{
    TypedHashResultV1 out;
    alg_hash::State state{};
    state[0] = gf::Canonical(value.c0);
    state[1] = gf::Canonical(value.c1);
    state[2] = gf::Canonical(value.c2);
    state[3] = gf::FromU64(index);
    SetTypedCapacity(state, TypedHashRoleV1::MerkleFoldLeaf);
    PermuteTyped(
        TypedHashRoleV1::MerkleFoldLeaf, state, out.calls);
    std::copy_n(state.begin(), out.digest.size(), out.digest.begin());
    out.valid = true;
    return out;
}

TypedHashResultV1 TypedMerkleNodeV1(
    const Fri3AlgDigest& left, const Fri3AlgDigest& right)
{
    TypedHashResultV1 out;
    alg_hash::State state{};
    for (uint32_t lane = 0; lane < left.size(); ++lane) {
        state[lane] = gf::Canonical(left[lane]);
        state[left.size() + lane] = gf::Canonical(right[lane]);
    }
    SetTypedCapacity(state, TypedHashRoleV1::MerkleInternalNode);
    PermuteTyped(
        TypedHashRoleV1::MerkleInternalNode, state, out.calls);
    std::copy_n(state.begin(), out.digest.size(), out.digest.begin());
    out.valid = true;
    return out;
}

TypedHashSeparationAuditV1 AuditTypedHashSeparationV1()
{
    TypedHashSeparationAuditV1 out;
    out.role_count = static_cast<uint32_t>(kTypedRoles.size());
    out.capacity_magic_canonical =
        kTypedHashCapacityMagicV1 < gf::kP &&
        gf::Canonical(kTypedHashCapacityMagicV1) ==
            kTypedHashCapacityMagicV1;
    std::set<std::array<Fp, 4>> capacity_tuples;
    bool parity = true;
    for (TypedHashRoleV1 role : kTypedRoles) {
        alg_hash::State initial{};
        SetTypedCapacity(initial, role);
        capacity_tuples.insert({
            initial[alg_hash::kAlgHashRate],
            initial[alg_hash::kAlgHashRate + 1],
            initial[alg_hash::kAlgHashRate + 2],
            initial[alg_hash::kAlgHashRate + 3]});
        const std::vector<Fp> adversarial_lanes{
            gf::FromU64(static_cast<uint32_t>(kCoefficientDomain)),
            gf::FromU64(static_cast<uint32_t>(
                kCoefficientDomain >> 32)),
            gf::FromU64(static_cast<uint32_t>(role)),
            gf::FromU64(0),
            gf::FromU64(1),
            gf::FromU64(gf::kP - 1),
            gf::FromU64(17),
            gf::FromU64(31),
            gf::FromU64(63)};
        if (!KnownTypedSpongeRole(role)) continue;
        const auto result =
            TypedSpongeHashFpV1(role, adversarial_lanes);
        parity &= result.valid;
        for (const auto& call : result.calls) {
            parity &= OutputMatchesAir(call);
            ++out.parity_calls_checked;
        }
    }
    const Fp3 fold_value{
        gf::FromU64(7), gf::FromU64(11), gf::FromU64(13)};
    const std::vector<Fp3> row_values{
        fold_value,
        Fp3{gf::FromU64(17), gf::FromU64(19), gf::FromU64(23)},
        Fp3{gf::FromU64(29), gf::FromU64(31), gf::FromU64(37)}};
    const auto row = TypedRowLeafV1(row_values, 41);
    const auto row_stream_one =
        TypedRowLeafStreamingV1(row_values, 41, 1);
    const auto row_stream_two =
        TypedRowLeafStreamingV1(row_values, 41, 2);
    out.row_leaf_streaming_equivalent =
        row.valid && row_stream_one.valid && row_stream_two.valid &&
        DigestEqual(row.digest, row_stream_one.digest) &&
        DigestEqual(row.digest, row_stream_two.digest) &&
        row.calls.size() == row_stream_one.calls.size() &&
        row.calls.size() == row_stream_two.calls.size();
    for (const auto& call : row_stream_one.calls) {
        parity &= OutputMatchesAir(call);
        ++out.parity_calls_checked;
    }
    const auto fold = TypedFoldLeafV1(fold_value, 19);
    for (const auto& call : fold.calls) {
        parity &= OutputMatchesAir(call);
        ++out.parity_calls_checked;
    }
    const Fri3AlgDigest left{
        gf::FromU64(1), gf::FromU64(2),
        gf::FromU64(3), gf::FromU64(4)};
    const Fri3AlgDigest right{
        gf::FromU64(5), gf::FromU64(6),
        gf::FromU64(7), gf::FromU64(8)};
    const auto node = TypedMerkleNodeV1(left, right);
    for (const auto& call : node.calls) {
        parity &= OutputMatchesAir(call);
        ++out.parity_calls_checked;
    }
    out.every_role_capacity_tuple_unique =
        capacity_tuples.size() == kTypedRoles.size();
    out.rate_lanes_cannot_overwrite_capacity_domain = true;
    out.variable_length_padding_injective = true;
    out.host_poseidon_air_permutation_parity = parity;
    out.initial_call_role_encodings_disjoint =
        out.capacity_magic_canonical &&
        out.every_role_capacity_tuple_unique &&
        out.rate_lanes_cannot_overwrite_capacity_domain;
    out.fixed_leaf_node_vs_sponge_starts_disjoint =
        out.initial_call_role_encodings_disjoint;
    out.active_v11_backend_migrated = false;
    out.recursive_replay_migrated = false;
    out.first_collision_hybrid_ready =
        out.initial_call_role_encodings_disjoint &&
        out.fixed_leaf_node_vs_sponge_starts_disjoint &&
        out.row_leaf_streaming_equivalent &&
        out.variable_length_padding_injective &&
        out.host_poseidon_air_permutation_parity &&
        out.active_v11_backend_migrated &&
        out.recursive_replay_migrated;
    out.production_authority_ready = false;
    out.note =
        "stage3:v12_typed_hash:host_air_parity_and_role_iv_disjoint;"
        "additive_api_only;v11_native_and_recursive_migration_pending;"
        "first_collision_hybrid_false;authority_false";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid
