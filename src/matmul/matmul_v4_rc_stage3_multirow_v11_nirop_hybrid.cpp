// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_multirow_v11_nirop_hybrid.h>

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <limits>
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
    uint32_t& event_count,
    std::vector<SafeIoEventV1>* safe_io_events = nullptr)
{
    const uint32_t ordinal = event_count;
    ++event_count;
    if (safe_io_events != nullptr) {
        const auto item = std::find_if(
            kDomains.begin(), kDomains.end(),
            [domain](const TranscriptDomainV1& candidate) {
                return candidate.domain == domain;
            });
        if (item != kDomains.end()) {
            /*
             * Low-delta V12 route: the old rate-domain prefix moves into
             * SAFECore's typed D, while M remains the existing logical
             * `lanes` vector (including any challenge ordinal/seed already
             * present at this call site). IO binds its exact length.
             */
            safe_io_events->push_back({
                item->role,
                ordinal,
                static_cast<uint32_t>(lanes.size()),
                alg_hash::kAlgHashDigestLen});
        }
    }
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
        kRCFri3AlgShapeCommitDomain, lanes, events,
        &out.proposed_safe_io_events);
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
        DigestFp3(Hash(
            kAirLambdaDomain, lanes, events,
            &out.proposed_safe_io_events));
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
    const auto fri_seed = Hash(
        kFriSeedDomain, lanes, events,
        &out.proposed_safe_io_events);
    exact &= DigestEqual(fri_seed, native.fri_seed);

    for (uint32_t candidate = 0;
         candidate < p2::kOodCandidatesV1; ++candidate) {
        lanes.clear();
        AppendDigest(lanes, fri_seed);
        AppendU32(lanes,
            statement.n_coeffs * statement.blowup);
        AppendU32(lanes, candidate);
        exact &= Fp3Equal(
            DigestFp3(Hash(
                kZ1Domain, lanes, events,
                &out.proposed_safe_io_events)),
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
            DigestFp3(Hash(
                kZ2Domain, lanes, events,
                &out.proposed_safe_io_events)),
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
        kRCFri3AlgOodEvalCommitDomain, lanes, events,
        &out.proposed_safe_io_events);
    exact &= DigestEqual(ood, native.ood_eval_commit);

    lanes.clear();
    AppendDigest(lanes, fri_seed);
    AppendFp3(lanes, native.z1);
    AppendFp3(lanes, native.z2);
    AppendDigest(lanes, ood);
    const auto batch_seed =
        Hash(
            kBatchSeedDomain, lanes, events,
            &out.proposed_safe_io_events);
    exact &= DigestEqual(batch_seed, native.batch_seed);
    for (uint32_t column = 0;
         column < statement.column_len.size(); ++column) {
        lanes.clear();
        AppendDigest(lanes, batch_seed);
        AppendU32(lanes, column);
        exact &= Fp3Equal(
            DigestFp3(Hash(
                kCoefficientDomain, lanes, events,
                &out.proposed_safe_io_events)),
            native.batching_coefficients[column]);
    }
    lanes.clear();
    AppendDigest(lanes, batch_seed);
    AppendU32(lanes, 1);
    exact &= Fp3Equal(
        DigestFp3(Hash(
            kWeightDomain, lanes, events,
            &out.proposed_safe_io_events)), native.w1);
    lanes.back() = gf::FromU64(2);
    exact &= Fp3Equal(
        DigestFp3(Hash(
            kWeightDomain, lanes, events,
            &out.proposed_safe_io_events)), native.w2);

    lanes.clear();
    AppendDigest(lanes, batch_seed);
    AppendFp3(lanes, native.w1);
    AppendFp3(lanes, native.w2);
    auto fold_state = Hash(
        kFoldStateDomain, lanes, events,
        &out.proposed_safe_io_events);
    uint32_t beta_index = 0;
    for (uint32_t fold = 0; fold < statement.folds.size(); ++fold) {
        lanes.clear();
        AppendDigest(lanes, fold_state);
        AppendU32(lanes, fold);
        AppendU32(lanes, statement.folds[fold].n_leaves);
        AppendDigest(lanes, statement.folds[fold].root);
        fold_state = Hash(
            kFoldStateDomain, lanes, events,
            &out.proposed_safe_io_events);
        if (fold + 1 != statement.folds.size()) {
            lanes.clear();
            AppendDigest(lanes, fold_state);
            AppendU32(lanes, fold);
            exact &= Fp3Equal(
                DigestFp3(Hash(
                    kFoldBetaDomain, lanes, events,
                    &out.proposed_safe_io_events)),
                native.fold_challenges[beta_index++]);
        }
    }
    lanes.clear();
    AppendDigest(lanes, fold_state);
    AppendFp3(lanes, statement.final_value);
    AppendU32(lanes, p2::kQueriesV1);
    AppendU32(lanes, p2::kQueryCandidatesV1);
    const auto query_seed =
        Hash(
            kQuerySeedDomain, lanes, events,
            &out.proposed_safe_io_events);
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
                Hash(
                    kQueryCandidateDomain, lanes, events,
                    &out.proposed_safe_io_events),
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

TypedAddAbsorbHybridAuditV1 AssessTypedAddAbsorbHybridV1(
    const SharedPermutationBudgetV1& budget)
{
    TypedAddAbsorbHybridAuditV1 out;
    out.budget = budget;
    out.goldilocks_bits =
        static_cast<double>(
            std::log2(static_cast<long double>(gf::kP)));
    out.concrete_poseidon_ideal_permutation_assumption_disclosed = true;
    out.gpu_friendly_poseidon_preserved = true;
    out.assumptions = {
        "Concrete Poseidon2 is assumed to behave as one shared ideal "
        "permutation, subject also to a conservative 128-bit algebraic "
        "security floor; this is an assumption, not a BTX theorem.",
        "Every native, recursive and adversarial call to that shared "
        "permutation must be included in one enforced manifest before the "
        "birthday square. Domain tags are not independent lanes.",
        "The typed add-absorb/hash-chain first-collision reduction for "
        "adaptive multi-block messages remains to be proved in the ideal-"
        "permutation model.",
        "The round-by-round FRI and BCS terms are external published inputs "
        "from ePrint 2023/1071 and do not by themselves establish NIROP "
        "separation for this hash construction."};

    const long double calls_per_site =
        static_cast<long double>(
            budget.fs_permutation_calls_per_site) +
        static_cast<long double>(
            budget.merkle_permutation_calls_per_site) +
        static_cast<long double>(
            budget.receipt_program_calls_per_site) +
        static_cast<long double>(
            budget.adversary_permutation_queries_per_site);
    if (budget.proof_sites == 0 || calls_per_site <= 0.0L) {
        out.note =
            "stage3:v12_typed_add_absorb:invalid_zero_budget;"
            "numeric_screen_false;custom_reduction_false;"
            "native_recursive_false;authority_false";
        return out;
    }

    /*
     * This is deliberately more conservative than a per-site union bound.
     * The permutation is shared, so a cross-role or cross-site first
     * collision can use any pair among
     *
     *     proof_sites * sum(calls_per_site).
     *
     * We therefore square the global total.  More precisely, lazy sampling
     * of a random permutation gives the conservative bad-event bound
     *
     *   2 T (T + 2 R) / p^4,
     *
     * where T is the global query count and R is the number of fixed typed
     * role IVs.  The factor covers both capacity-projection collisions
     * (including an output hitting a fixed IV) and final four-lane digest
     * collisions, including the without-replacement denominator.  It is
     * valid in the only relevant regime T <= p^12/2.  A future reviewed
     * reduction may justify a tighter partition, but this audit does not
     * assume one.
     */
    const long double global_queries_log2 =
        std::log2(static_cast<long double>(budget.proof_sites)) +
        std::log2(calls_per_site);
    out.shared_permutation_queries_log2 =
        static_cast<double>(global_queries_log2);
    const long double global_queries =
        static_cast<long double>(budget.proof_sites) * calls_per_site;
    const long double role_ivs =
        static_cast<long double>(kTypedRoles.size());
    const long double bad_event_numerator_log2 =
        1.0L + std::log2(global_queries) +
        std::log2(global_queries + 2.0L * role_ivs);
    out.generic_capacity_first_collision_bits = std::max(
        0.0,
        4.0 * out.goldilocks_bits -
            static_cast<double>(bad_event_numerator_log2));
    out.poseidon_algebraic_floor_after_site_union_bits = std::max(
        0.0,
        128.0 - std::log2(
            static_cast<double>(budget.proof_sites)));
    out.effective_first_collision_bits = std::min(
        out.generic_capacity_first_collision_bits,
        out.poseidon_algebraic_floor_after_site_union_bits);
    out.all_shared_permutation_queries_summed_before_square = true;
    out.adaptive_multiblock_capacity_collisions_accounted = true;

    const auto typed = AuditTypedHashSeparationV1();
    out.typed_initial_role_ivs_disjoint =
        typed.initial_call_role_encodings_disjoint &&
        typed.fixed_leaf_node_vs_sponge_starts_disjoint;
    out.ten_star_message_encoding_prefix_free =
        typed.variable_length_padding_injective;
    /*
     * For a fixed prior state, coordinate-wise field addition is a
     * bijection in the absorbed block.  This local fact is not the missing
     * global reduction: after a permutation call, adaptive state/capacity
     * collisions still have to be bounded.
     */
    out.add_absorb_next_input_injective_given_prior_state = true;
    out.custom_reduction_formally_complete = false;
    out.exact_global_call_manifest_enforced =
        budget.exact_manifest_derived;
    out.active_native_transcript_matches = false;
    out.recursive_air_transcript_matches = false;
    out.numeric_v1_security_screen_met =
        out.effective_first_collision_bits >= 64.0;
    out.production_theorem_complete =
        out.all_shared_permutation_queries_summed_before_square &&
        out.adaptive_multiblock_capacity_collisions_accounted &&
        out.typed_initial_role_ivs_disjoint &&
        out.ten_star_message_encoding_prefix_free &&
        out.add_absorb_next_input_injective_given_prior_state &&
        out.concrete_poseidon_ideal_permutation_assumption_disclosed &&
        out.custom_reduction_formally_complete &&
        out.exact_global_call_manifest_enforced &&
        out.active_native_transcript_matches &&
        out.recursive_air_transcript_matches &&
        out.numeric_v1_security_screen_met;
    out.note =
        "stage3:v12_typed_add_absorb:global_shared_queries_squared;"
        "capacity4_numeric_screen=" +
        std::to_string(out.effective_first_collision_bits) +
        ";typed_iv_and_10star_foundation_green;"
        "custom_adaptive_reduction_false;"
        "exact_manifest=" +
        std::string(
            out.exact_global_call_manifest_enforced ? "true" : "false") +
        ";native_recursive_false;authority_false";
    return out;
}

OverwriteDuplexFsAuditV1 AssessOverwriteDuplexFsV1()
{
    OverwriteDuplexFsAuditV1 out;
    out.minimum_capacity_lanes = 4;
    out.persistent_duplex_state_lanes =
        static_cast<uint32_t>(alg_hash::kAlgHashT);
    out.poseidon_air_columns_per_parameter_set =
        stage3_poseidon_air::kFixedColumns;
    /*
     * ePrint 2025/536 models (1) the instance hash/random function h,
     * (2) the duplex ideal permutation p,p^-1, and (3) the Merkle
     * compression oracle separately.  Replacing those ideal objects with
     * concrete Poseidon2 families needs three independently justified
     * families, not three domain strings under one unproved permutation.
     */
    out.minimum_independent_oracle_families = 3;
    out.additional_poseidon_parameter_sets_vs_v11 = 2;
    out.published_transform_is_overwrite_mode = true;
    out.published_start_capacity_is_instance_derived = true;
    out.published_bcs_keeps_merkle_compression_separate = true;
    out.current_v11_add_absorb_matches = false;
    out.current_v11_zero_capacity_start_matches = false;
    out.same_parameter_set_domain_tags_are_proven_independent = false;
    out.independent_start_fs_merkle_parameter_sets_executable = false;
    out.native_overwrite_transcript_executable = false;
    out.recursive_overwrite_transcript_executable = false;
    out.gpu_friendly_if_poseidon_parameter_sets_added = true;
    out.published_dsfs_premises_instantiated =
        out.published_transform_is_overwrite_mode &&
        out.published_start_capacity_is_instance_derived &&
        out.published_bcs_keeps_merkle_compression_separate &&
        out.independent_start_fs_merkle_parameter_sets_executable &&
        out.native_overwrite_transcript_executable &&
        out.recursive_overwrite_transcript_executable;
    out.production_theorem_complete = false;
    out.assumptions = {
        "ePrint 2025/536 proves its transform in an ideal "
        "(h,p,p^-1) oracle model, with overwrite-mode duplexing and "
        "capacity initialized from h(instance).",
        "Its BCS composition keeps Merkle compression separate; reusing "
        "one concrete Poseidon2 parameter set with role tags is not shown "
        "to instantiate independent h, duplex and Merkle oracles.",
        "Concrete independently parameterized Poseidon2 families require "
        "their own algebraic-security and cross-family-independence "
        "arguments.",
        "Native and recursive AIR implementations must replay the exact "
        "persistent overwrite state before the published premise applies."};
    out.note =
        "stage3:v12_overwrite_dsfs:published_transform_identified;"
        "requires_3_oracle_families_and_2_additional_p2_parameter_sets;"
        "poseidon_air_columns_each=" +
        std::to_string(out.poseidon_air_columns_per_parameter_set) +
        ";native_recursive_and_independence_false;authority_false";
    return out;
}

SafeCoreMigrationAuditV1 AssessSafeCoreMigrationV1(
    const p2::StatementV1& statement,
    const SharedPermutationBudgetV1& budget)
{
    SafeCoreMigrationAuditV1 out;
    out.rate_lanes = alg_hash::kAlgHashRate;
    out.capacity_lanes = alg_hash::kAlgHashCapacity;
    out.width_lanes = alg_hash::kAlgHashT;
    out.safe_api_spec_tag_lanes =
        alg_hash::kAlgHashCapacity / 2;
    out.proved_safecore_tag_lanes =
        alg_hash::kAlgHashCapacity;
    const double field_bits =
        static_cast<double>(
            std::log2(static_cast<long double>(gf::kP)));
    /*
     * 2023/520, pp. 3-4: hashing (IO,D) into c/2 field elements
     * gives only |Fp|^(c/4) collision security.  Its improved SAFECore
     * hashes into all c elements and proves security to |Fp|^(c/2).
     */
    out.safe_api_spec_query_ceiling_bits =
        field_bits * static_cast<double>(
            out.safe_api_spec_tag_lanes) / 2.0;
    out.proved_safecore_query_ceiling_bits =
        field_bits * static_cast<double>(
            out.proved_safecore_tag_lanes) / 2.0;
    out.safe_api_two_lane_profile_meets_v1_screen =
        out.safe_api_spec_query_ceiling_bits >= 64.0;

    const auto v11 = AssessV1(statement);
    out.v11_transcript_hash_events =
        v11.independently_replayed_hash_events;
    out.proposed_safe_io_absorb_squeeze_events =
        v11.expected_hash_events;
    out.current_v11_resets_state_per_hash_event =
        v11.independent_replay_matches_native_receipt;
    out.current_v11_is_one_continuous_safe_state = false;
    out.current_v11_capacity_is_full_h_io_domain_tag = false;
    out.current_v11_io_pattern_fixed_and_enforced = false;
    out.current_v11_padding_matches_safecore_pad = false;
    out.typed_v12_static_iv_is_full_h_io_domain_tag = false;

    /*
     * Low-delta migration target:
     *  - each replayed V11 hash-DAG event becomes an independent exact
     *    SAFECore Algorithm-3 call C(IO=(I,4), D=typed role, M);
     *  - I is the exact logical message length, so SAFECorePad uses zero
     *    padding to the rate boundary and needs no 10* delimiter;
     *  - the previous digest/seed may remain in M. Theorem 2 covers
     *    multiple SAFECore invocations and arbitrary IO,D; §5.3's one
     *    continuous online SAFE transcript is a sufficient application,
     *    not a requirement imposed on every SAFECore use;
     *  - row leaf, fold leaf, internal node, receipt, ProgramTable and
     *    application statements receive distinct typed D values;
     *  - H(IO,D) fills all four capacity lanes.
     *
     * A continuous online SAFE transcript remains a valid alternative, but
     * is not the recommended prerequisite for migrating this hash DAG.
     */
    out.proposed_stateless_safecore_per_hash_event = true;
    out.proposed_seed_feedback_is_ordinary_message_data = true;
    out.proposed_safecore_zero_padding_fixed_by_io = true;
    out.proposed_fs_is_one_continuous_absorb_squeeze_state = false;
    bool safe_events_well_formed =
        v11.proposed_safe_io_events.size() ==
            v11.expected_hash_events;
    for (uint32_t event = 0;
         event < v11.proposed_safe_io_events.size(); ++event) {
        const auto& item = v11.proposed_safe_io_events[event];
        safe_events_well_formed &=
            item.ordinal == event &&
            item.absorb_lanes != 0 &&
            item.squeeze_lanes == alg_hash::kAlgHashDigestLen &&
            static_cast<uint32_t>(item.role) >=
                static_cast<uint32_t>(TranscriptRoleV1::ShapeCommit) &&
            static_cast<uint32_t>(item.role) <=
                static_cast<uint32_t>(TranscriptRoleV1::Padding);
    }
    out.proposed_fs_has_fixed_io_pattern =
        v11.expected_hash_events != 0 &&
        v11.expected_hash_events ==
            v11.independently_replayed_hash_events &&
        safe_events_well_formed;
    /*
     * No removal is implemented because none is required for the stateless
     * route: feedback is part of M and IO binds |M|. This legacy field stays
     * false to record that the message DAG is unchanged; it is deliberately
     * not a theorem-premise conjunct below.
     */
    out.proposed_native_seed_feedback_removed = false;
    out.proposed_merkle_instances_have_separate_tags = true;
    out.proposed_receipt_program_instances_have_separate_tags = true;
    out.proposed_uses_full_capacity_tag = true;
    out.proposed_tag_hash_to_fp4_is_canonical =
        safe_v12::kFullCapacityTagHashImplementedV12;
    out.proposed_tag_registry_root_pinned = false;
    out.exact_safe_io_pattern_manifest_enforced = false;
    out.native_safe_transcript_executable = false;
    out.recursive_safe_transcript_executable = false;
    out.gpu_friendly_poseidon_preserved = true;
    out.tag_hash_random_oracle_assumption_disclosed = true;
    out.poseidon_random_permutation_assumption_disclosed = true;
    out.conditional_poseidon_algebraic_floor_bits = 128.0;
    out.concrete_tag_hash_reduction_complete = false;
    out.concrete_poseidon_reduction_complete = false;

    const long double calls_per_site =
        static_cast<long double>(
            budget.fs_permutation_calls_per_site) +
        static_cast<long double>(
            budget.merkle_permutation_calls_per_site) +
        static_cast<long double>(
            budget.receipt_program_calls_per_site) +
        static_cast<long double>(
            budget.adversary_permutation_queries_per_site);
    const long double honest_q_h =
        static_cast<long double>(budget.safe_tag_hash_queries);
    const long double honest_q_p =
        static_cast<long double>(budget.proof_sites) *
        calls_per_site;
    const long double adversarial_q_h =
        budget.adversarial_h_query_budget_log2 > 0.0
        ? std::exp2(
              static_cast<long double>(
                  budget.adversarial_h_query_budget_log2))
        : 0.0L;
    const long double adversarial_q_p =
        budget.adversarial_permutation_query_budget_log2 > 0.0
        ? std::exp2(
              static_cast<long double>(
                  budget.adversarial_permutation_query_budget_log2))
        : 0.0L;
    const long double q_h = honest_q_h + adversarial_q_h;
    const long double q_p = honest_q_p + adversarial_q_p;
    out.honest_tag_hash_queries = budget.safe_tag_hash_queries;
    out.theorem_unique_h_queries =
        q_h >= static_cast<long double>(
                   std::numeric_limits<uint64_t>::max())
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(q_h);
    out.adversarial_classical_query_budgets_included =
        budget.adversarial_h_query_budget_log2 >= 64.0 &&
        budget.adversarial_permutation_query_budget_log2 >= 64.0;
    if (q_h > 0.0L && q_p > 0.0L) {
        out.theorem_h_queries_log2 =
            static_cast<double>(std::log2(q_h));
        out.theorem_unique_permutation_queries_log2 =
            static_cast<double>(std::log2(q_p));
        const auto choose_two = [](long double q) {
            return q > 1.0L ? q * (q - 1.0L) / 2.0L : 0.0L;
        };
        /*
         * ePrint 2023/520, Theorem 2:
         *
         *  [3*C(QH,2) + 2*C(QP,2) + 4*QP*QH] / p^c
         *      + 3*C(QP,2) / p^b.
         *
         * Honest manifest calls and separately declared adversarial H/P
         * budgets are summed before this expression. For the V1
         * unconditional classical screen both adversarial budgets are 2^64;
         * an honest tag inventory alone is never treated as attacker cost.
         * Total P calls upper-bound unique P queries.
         */
        const long double capacity_numerator =
            3.0L * choose_two(q_h) +
            2.0L * choose_two(q_p) +
            4.0L * q_p * q_h;
        const long double width_numerator =
            3.0L * choose_two(q_p);
        const long double p =
            static_cast<long double>(gf::kP);
        const long double advantage =
            capacity_numerator /
                std::pow(p, out.capacity_lanes) +
            width_numerator /
                std::pow(p, out.width_lanes);
        if (advantage > 0.0L && std::isfinite(advantage)) {
            out.theorem_indifferentiability_bits =
                std::max(
                    0.0,
                    static_cast<double>(-std::log2(advantage)));
            out.theorem2_bound_computed = true;
            out.conditional_effective_bits = std::min(
                out.theorem_indifferentiability_bits,
                out.conditional_poseidon_algebraic_floor_bits);
            out.theorem2_numeric_v1_screen_met =
                out.conditional_effective_bits >= 64.0;
        }
    }

    out.premise_mismatches = {
        "V11 creates a fresh zero-capacity SpongeHashFp for each event; "
        "the stateless SAFECore replacement must instead initialize all four "
        "capacity lanes with H(IO,D) for every event.",
        "V11 places a role domain in the outer/rate message. SAFECore "
        "initializes the full inner capacity with H(IO,D).",
        "The additive V12 typed IV is a fixed tuple, not an output of the "
        "random-oracle H(IO,D) required by SAFECore Theorem 2.",
        "V11 uses injective 10* padding for independently nested hashes; "
        "SAFECore IO=(I,4) binds I and uses zero padding only.",
        "The standalone native V12 foundation evaluates exact Algorithm 3 "
        "with a canonical full-Fp4 H(IO,D) tag, but no active transcript "
        "call site or recursive AIR consumes it."};
    out.required_protocol_changes = {
        "Version-bump each V11 stateless digest to SAFECore "
        "C(IO=(I,4),D=typed role,M). Preserve existing seed/digest feedback "
        "inside M and derive I from the exact call-site manifest.",
        "Integrate the implemented rejection-sampled H(IO,D)->Fp^4 at every "
        "native and recursive call site, then precompute and consensus-pin "
        "the tag registry root. Do not reduce arbitrary u64 chunks modulo p.",
        "Assign distinct (IO,D) tags to FS, row leaf, fold leaf, Merkle "
        "node, receipt, ProgramTable and application-statement instances.",
        "Implement identical fixed-IO SAFECore zero padding, absorption and "
        "squeeze timing in the native prover/verifier and recursive AIR, "
        "with proof-level rejects for IO length, role, tag and message.",
        "Derive and enforce exact honest global QH/QP manifests, then add "
        "separate adversarial H/P budgets (at least 2^64 each for the V1 "
        "classical screen) before consuming the published advantage bound."};
    out.published_safecore_premises_instantiated =
        out.proposed_tag_hash_to_fp4_is_canonical &&
        out.proposed_tag_registry_root_pinned &&
        out.proposed_stateless_safecore_per_hash_event &&
        out.proposed_seed_feedback_is_ordinary_message_data &&
        out.proposed_safecore_zero_padding_fixed_by_io &&
        out.exact_safe_io_pattern_manifest_enforced &&
        out.native_safe_transcript_executable &&
        out.recursive_safe_transcript_executable &&
        out.concrete_tag_hash_reduction_complete &&
        out.concrete_poseidon_reduction_complete &&
        out.adversarial_classical_query_budgets_included &&
        budget.exact_manifest_derived &&
        out.theorem2_bound_computed &&
        out.theorem2_numeric_v1_screen_met;
    out.production_theorem_complete =
        out.published_safecore_premises_instantiated;
    out.note =
        "stage3:v12_safecore:published_theorem2_bound=" +
        std::to_string(out.theorem_indifferentiability_bits) +
        ";v11_nested_zero_capacity_mismatch;"
        "stateless_alg3_preserves_seed_feedback;"
        "safe_api_c_over_2_tag_profile_below_64;"
        "full_c_tag_native_foundation_true;"
        "io_manifest_tag_registry_native_recursive_false;"
        "concrete_h_p_reductions_false;"
        "authority_false";
    return out;
}

NiropPathComparisonV1 CompareNiropPathsV1(
    const p2::StatementV1& statement,
    const SharedPermutationBudgetV1& budget)
{
    NiropPathComparisonV1 out;
    out.typed_add_absorb =
        AssessTypedAddAbsorbHybridV1(budget);
    out.overwrite_duplex = AssessOverwriteDuplexFsV1();
    out.safe_core =
        AssessSafeCoreMigrationV1(statement, budget);
    /*
     * Stateless SAFECore Algorithm 3 is the V12 engineering recommendation:
     * it preserves the current hash DAG and Poseidon2 backend while replacing
     * the bespoke zero-capacity mode with the published theorem. Theorem 2
     * covers multiple invocations; §5.3's continuous transcript is an
     * application of SAFECore, not a mandatory shape. This is not readiness.
     */
    out.recommended =
        RecommendedNiropPathV1::PublishedSafeCore;
    out.recommendation_preserves_current_gpu_poseidon_path = true;
    out.recommendation_is_production_selectable =
        out.safe_core.production_theorem_complete;
    out.rationale =
        "Prefer one full-capacity stateless SAFECore Algorithm-3 call per "
        "V11 hash-DAG event: IO=(exact absorb length,4), D=typed role, and "
        "the existing message M including seed/digest feedback. Theorem 2 "
        "covers multiple invocations and arbitrary IO,D under random-H/"
        "random-P assumptions, while retaining the Poseidon2 GPU path. "
        "The c/2-lane tag profile in the 2023/522 API is insufficient for "
        "Goldilocks c=4; use SAFECore's full c=4 H(IO,D) tag. This remains "
        "unselectable until the exact IO/tag registry and QH/QP manifest, "
        "native Algorithm 3 and recursive replay are executable. Typed "
        "bespoke add-absorb requires a new proof; independent overwrite "
        "duplex requires a larger transcript/oracle redesign.";
    return out;
}

} // namespace matmul::v4::rc::stage3_multirow_v11_nirop_hybrid
