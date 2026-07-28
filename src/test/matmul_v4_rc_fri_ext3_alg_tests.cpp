// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg_order_audit.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <string>
#include <vector>

// Piece-2 gate tests (Stage-C spec §6): the algebraic-hash batched FRI with
// the ROW-WISE Merkle layout (§2.3) and the Q=192 recursion soundness
// parameters (§5.2). The SHA256d batched FRI keeps its own suite
// (matmul_v4_rc_fri_ext3_tests.cpp) — nothing here touches it.

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;
namespace aq = matmul::v4::rc::air_quotient;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_fri_ext3_alg_tests, BasicTestingSetup)

namespace {

uint256 MakeSeed(uint8_t fill)
{
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = fill;
    return seed;
}

std::vector<std::vector<rc::Fp3>> MakeColumns()
{
    std::vector<std::vector<rc::Fp3>> columns(3);
    columns[0].resize(5);
    columns[1].resize(8);
    columns[2].resize(3);
    for (size_t c = 0; c < columns.size(); ++c) {
        for (size_t j = 0; j < columns[c].size(); ++j) {
            columns[c][j] = gf::FromSigned3(static_cast<int64_t>(7 * c + 3 * j + 1));
        }
    }
    return columns;
}

std::vector<std::vector<rc::Fp3>> MakeMediumColumns()
{
    std::vector<std::vector<rc::Fp3>> columns(16);
    for (size_t c = 0; c < columns.size(); ++c) {
        columns[c].resize(128 - (c % 7));
        for (size_t j = 0; j < columns[c].size(); ++j) {
            columns[c][j] = gf::FromSigned3(
                static_cast<int64_t>(101 * c + 17 * j + 3));
        }
    }
    return columns;
}

std::vector<std::vector<rc::Fp3>> MakeProductionWidthColumns()
{
    std::vector<std::vector<rc::Fp3>> columns(1092);
    for (size_t c = 0; c < columns.size(); ++c) {
        columns[c] = {
            gf::FromSigned3(static_cast<int64_t>(2 * c + 1)),
            gf::FromSigned3(static_cast<int64_t>(2 * c + 2))};
    }
    return columns;
}

std::vector<std::vector<std::vector<rc::Fp3>>>
MakeMultiRowGroups()
{
    return {
        {
            {
                gf::FromSigned3(1),
                gf::FromSigned3(3),
                gf::FromSigned3(5),
                gf::FromSigned3(7),
                gf::FromSigned3(9),
            },
            {
                gf::FromSigned3(2),
                gf::FromSigned3(6),
                gf::FromSigned3(12),
                gf::FromSigned3(20),
                gf::FromSigned3(30),
                gf::FromSigned3(42),
                gf::FromSigned3(56),
                gf::FromSigned3(72),
            },
        },
        {
            {
                gf::FromSigned3(11),
                gf::FromSigned3(13),
                gf::FromSigned3(17),
                gf::FromSigned3(19),
                gf::FromSigned3(23),
                gf::FromSigned3(29),
                gf::FromSigned3(31),
            },
            {
                gf::FromSigned3(4),
                gf::FromSigned3(16),
                gf::FromSigned3(64),
                gf::FromSigned3(256),
            },
        },
        {
            {
                gf::FromSigned3(37),
                gf::FromSigned3(41),
                gf::FromSigned3(43),
                gf::FromSigned3(47),
                gf::FromSigned3(53),
                gf::FromSigned3(59),
                gf::FromSigned3(61),
                gf::FromSigned3(67),
            },
        },
    };
}

std::vector<rc::Fri3AlgMultiRowGroupRole>
MultiRowRoles()
{
    return {
        rc::Fri3AlgMultiRowGroupRole::MainTrace,
        rc::Fri3AlgMultiRowGroupRole::AuxiliaryTrace,
        rc::Fri3AlgMultiRowGroupRole::Quotient,
    };
}

void PutLE32(
    std::vector<unsigned char>& bytes,
    size_t offset,
    uint32_t value)
{
    BOOST_REQUIRE_LE(offset + 4, bytes.size());
    for (uint32_t byte = 0; byte < 4; ++byte) {
        bytes[offset + byte] =
            static_cast<unsigned char>(
                value >> (8 * byte));
    }
}

} // namespace

// Gate (f): the recursion path ships Q=192, g=40, blowup=16 — statically
// asserted in the header, re-checked here against the spec §5.2 arithmetic.
BOOST_AUTO_TEST_CASE(fra3_constants_and_soundness_bits)
{
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgNumQueries, 192u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgBatchProofVersion, 3u);
    BOOST_CHECK_EQUAL(rc::kRCFriGrindingBits, 40u);
    BOOST_CHECK_EQUAL(rc::kRCFriBlowup, 16u);
    // floor(192·log2(32/17)) − 40 = 135; the global ledger separately
    // charges the recursive-site budget and every non-proximity term.
    BOOST_CHECK_EQUAL(rc::Fri3AlgSoundnessBoundBits(), 135);
    BOOST_CHECK_GE(rc::Fri3AlgSoundnessBoundBits(), rc::kRCFri3AlgTargetSoundnessBits);
    BOOST_CHECK(rc::Fri3AlgClaimedBitsMeetTarget());
    // PR-89 gate 3: the single-lane rbr/BCS reduction is machine-checked (see
    // fra3_bcs_rbr_ledger_* below and AssessFri3AlgBcsRbrLedgerV1).
    BOOST_CHECK(rc::kRCFri3AlgFormalSoundnessReady);
    // Path-local hard cap admits Q=192; the SHA cap kRCFriMaxQueriesHard=128
    // is deliberately NOT raised (it guards the SHA paths only).
    BOOST_CHECK_GE(rc::kRCFri3AlgMaxQueriesHard, rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(rc::kRCFriMaxQueriesHard, 128u);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("Q=192") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("blowup=16") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("ROW-WISE") !=
                std::string::npos);
    BOOST_CHECK(std::string(rc::kRCFri3AlgBatchSoundnessStatement).find("Poseidon2") !=
                std::string::npos);
}

// Digest packing: 4×Fp ⇆ uint256 (canonical LE64 limbs) is a bijection onto
// its image — round-trips exactly and rejects non-canonical limbs (≥ p).
BOOST_AUTO_TEST_CASE(fra3_digest_packing_round_trip)
{
    const rc::Fri3AlgDigest d{0x0123456789ABCDEFULL, 0xFFFFFFFF00000000ULL, 1, 0};
    const uint256 u = rc::Fri3AlgDigestToUint256(d);
    const auto back = rc::Fri3AlgDigestFromUint256(u);
    BOOST_REQUIRE(back.has_value());
    for (int k = 0; k < 4; ++k) {
        BOOST_CHECK_EQUAL(gf::Canonical((*back)[k]), gf::Canonical(d[k]));
    }
    uint256 bad = u;
    for (int b = 0; b < 8; ++b) bad.data()[b] = 0xFF; // limb0 = 2^64−1 ≥ p
    BOOST_CHECK(!rc::Fri3AlgDigestFromUint256(bad).has_value());
}

BOOST_AUTO_TEST_CASE(fra3_streaming_sha_prefix_is_byte_identical)
{
    const rc::Fri3AlgStreamingFsAudit audit =
        rc::AuditFri3AlgStreamingFs(MakeSeed(0x3d));
    BOOST_CHECK_MESSAGE(audit.all_match, audit.note);
    BOOST_CHECK(audit.legacy_fp3_match);
    BOOST_CHECK(audit.uniform_fp3_match);
    BOOST_CHECK(audit.uniform_index_match);
    BOOST_CHECK_EQUAL(audit.legacy_fp3_vectors, 6U);
    BOOST_CHECK_EQUAL(audit.uniform_fp3_vectors, 8U);
    BOOST_CHECK_EQUAL(audit.uniform_index_vectors, 1U);
}

BOOST_AUTO_TEST_CASE(fra3_selected_root_streaming_prover_memory_plan)
{
    // Selected two-lane normalized verifier width plus one quotient column.
    const rc::Fri3AlgStreamingProverPlan plan =
        rc::AssessFri3AlgStreamingProverPlan(
            /*batch_columns=*/1093,
            /*n_coeffs=*/1U << 19);
    BOOST_REQUIRE_MESSAGE(plan.shape_valid, plan.note);
    BOOST_CHECK_EQUAL(plan.n_lde, 1U << 23);
    BOOST_CHECK_EQUAL(plan.column_lde_passes, 2U);
    BOOST_CHECK_EQUAL(
        plan.query_openings,
        rc::kRCFri3AlgDualTotalQueries);
    BOOST_CHECK_GT(
        plan.materialized_column_lde_bytes,
        uint64_t{200} << 30);
    BOOST_CHECK_LT(
        plan.streaming_peak_bytes,
        uint64_t{4} << 30);
    BOOST_CHECK_GT(
        plan.materialization_reduction_ratio, 50.0);
    BOOST_CHECK(plan.under_four_gib);
    BOOST_CHECK(plan.executable_row_hash_primitive);
    BOOST_CHECK(!plan.complete_streaming_prover);
    BOOST_TEST_MESSAGE(
        "FRI3ALG_STREAMING_PLAN materialized_bytes="
        << plan.materialized_column_lde_bytes
        << " streaming_peak_bytes="
        << plan.streaming_peak_bytes
        << " reduction_ratio="
        << plan.materialization_reduction_ratio
        << " row_sponge_bytes=" << plan.row_sponge_bytes
        << " row_merkle_bytes=" << plan.row_merkle_bytes
        << " one_column_bytes="
        << plan.one_column_recompute_bytes
        << " fold_peak_bytes="
        << plan.fold_recompute_peak_bytes);
}

// Gate (a): honest commit+verify accepts; serde round-trips byte-exact.
BOOST_AUTO_TEST_CASE(fra3_honest_commit_verify_serde_byte_exact)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed, /*pow_grind_nonce=*/9);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    BOOST_CHECK_EQUAL(c.proof.queries.size(), rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(c.proof.n_coeffs, 8u);
    BOOST_CHECK_EQUAL(c.proof.row_commit.n_leaves, 8u * rc::kRCFriBlowup);
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3AlgBatchVerify(c.proof, seed, &why), why);

    std::vector<unsigned char> ser, ser2;
    const size_t n1 = rc::SerializeFri3AlgBatchProof(c.proof, ser);
    const auto de = rc::DeserializeFri3AlgBatchProof(ser);
    BOOST_REQUIRE(de.has_value());
    const size_t n2 = rc::SerializeFri3AlgBatchProof(*de, ser2);
    BOOST_CHECK_EQUAL(n1, n2);
    BOOST_CHECK(ser == ser2);
    BOOST_CHECK(rc::Fri3AlgBatchVerify(*de, seed, nullptr));
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(c.proof, MakeSeed(0x43), nullptr)); // wrong seed
}

BOOST_AUTO_TEST_CASE(
    fra3_multi_row_rap_honest_and_group_binding)
{
    const auto groups = MakeMultiRowGroups();
    const auto roles = MultiRowRoles();
    const uint256 seed = MakeSeed(0x47);
    const auto committed =
        rc::Fri3AlgMultiRowBatchCommitStreaming(
            groups, roles, seed, 13);
    BOOST_REQUIRE_MESSAGE(
        committed.ok, committed.note);
    BOOST_REQUIRE_EQUAL(
        committed.proof.groups.size(), 3U);
    BOOST_REQUIRE_EQUAL(
        committed.group_row_tree_caches.size(), 3U);
    BOOST_CHECK_EQUAL(
        committed.proof.column_len.size(), 5U);
    BOOST_CHECK_EQUAL(
        committed.proof.n_coeffs, 8U);
    BOOST_CHECK_EQUAL(
        committed.proof.queries.size(),
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        committed.proof.groups[0].first_column, 0U);
    BOOST_CHECK_EQUAL(
        committed.proof.groups[0].column_count, 2U);
    BOOST_CHECK_EQUAL(
        committed.proof.groups[1].first_column, 2U);
    BOOST_CHECK_EQUAL(
        committed.proof.groups[1].column_count, 2U);
    BOOST_CHECK_EQUAL(
        committed.proof.groups[2].first_column, 4U);
    BOOST_CHECK_EQUAL(
        committed.proof.groups[2].column_count, 1U);
    for (const auto& cache :
         committed.group_row_tree_caches) {
        BOOST_REQUIRE(cache != nullptr);
        BOOST_CHECK(cache->valid);
    }

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgMultiRowBatchVerify(
            committed.proof, seed, &why),
        why);
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            committed.proof, MakeSeed(0x48),
            &why));

    // Reusing checked prover-local row trees must preserve the exact
    // transcript proof. A cache cannot bless changed coefficients.
    const auto cached =
        rc::Fri3AlgMultiRowBatchCommitStreaming(
            groups, roles, seed, 13,
            committed.group_row_tree_caches);
    BOOST_REQUIRE_MESSAGE(cached.ok, cached.note);
    BOOST_CHECK(
        cached.proof.groups[0].row_commit.root ==
        committed.proof.groups[0].row_commit.root);
    BOOST_CHECK(
        cached.proof.groups[1].row_commit.root ==
        committed.proof.groups[1].row_commit.root);
    BOOST_CHECK(
        cached.proof.groups[2].row_commit.root ==
        committed.proof.groups[2].row_commit.root);
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgMultiRowBatchVerify(
            cached.proof, seed, &why),
        why);

    // The durable V2 envelope is byte-unique and enforces the complete
    // role/range/domain/fold/query/path shape before allocating vectors.
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_GT(
        rc::SerializeFri3AlgMultiRowBatchProof(
            committed.proof, encoded),
        0U);
    BOOST_CHECK_LE(
        encoded.size(),
        rc::kRCFri3AlgMultiRowMaxProofBytesHard);
    const auto decoded =
        rc::DeserializeFri3AlgMultiRowBatchProof(
            encoded);
    BOOST_REQUIRE(decoded.has_value());
    std::vector<unsigned char> encoded_again;
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            *decoded, encoded_again),
        encoded.size());
    BOOST_CHECK(encoded_again == encoded);
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgMultiRowBatchVerify(
            *decoded, seed, &why),
        why);

    auto malformed = committed.proof;
    malformed.groups[0].role =
        rc::Fri3AlgMultiRowGroupRole::
            AuxiliaryTrace;
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            malformed, encoded_again),
        0U);
    BOOST_CHECK(encoded_again.empty());
    malformed = committed.proof;
    malformed.groups[1].first_column++;
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            malformed, encoded_again),
        0U);
    malformed = committed.proof;
    malformed.fold_layers.pop_back();
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            malformed, encoded_again),
        0U);
    malformed = committed.proof;
    malformed.queries.pop_back();
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            malformed, encoded_again),
        0U);
    malformed = committed.proof;
    malformed.queries[0].group_rows[0]
        .siblings.pop_back();
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            malformed, encoded_again),
        0U);

    const size_t group_bytes =
        committed.proof.groups.size() * 48;
    const size_t column_bytes =
        4 +
        committed.proof.column_len.size() * 4;
    const size_t lambda_offset =
        28 + group_bytes + column_bytes;
    const size_t layer_count_offset =
        lambda_offset + 3 * 24 +
        4 + committed.proof.evals_z1.size() * 24 +
        4 + committed.proof.evals_z2.size() * 24 +
        2 * 24;
    const size_t query_count_offset =
        layer_count_offset + 4 +
        committed.proof.fold_layers.size() * 36 +
        24 + 4 +
        committed.proof.fold_challenges.size() * 24;
    auto bad_wire = encoded;
    std::fill(
        bad_wire.begin() + lambda_offset,
        bad_wire.begin() + lambda_offset + 8,
        0xff);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             bad_wire)
             .has_value());
    bad_wire = encoded;
    PutLE32(
        bad_wire, layer_count_offset,
        static_cast<uint32_t>(
            committed.proof.fold_layers.size() -
            1));
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             bad_wire)
             .has_value());
    bad_wire = encoded;
    PutLE32(
        bad_wire, query_count_offset,
        rc::kRCFri3AlgNumQueries - 1);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             bad_wire)
             .has_value());
    const uint32_t row_depth = 7;
    const size_t first_query =
        query_count_offset + 4;
    const size_t first_row_sibling_count =
        first_query + 4 + 4 + 4 +
        committed.proof.groups[0]
                .column_count *
            24;
    bad_wire = encoded;
    PutLE32(
        bad_wire,
        first_row_sibling_count,
        row_depth + 1);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             bad_wire)
             .has_value());
    size_t first_step_count =
        first_query + 4 + 4;
    for (uint32_t group = 0; group < 3;
         ++group) {
        first_step_count +=
            4 +
            committed.proof.groups[group]
                    .column_count *
                24 +
            4 + row_depth * 32;
    }
    bad_wire = encoded;
    PutLE32(
        bad_wire, first_step_count,
        static_cast<uint32_t>(
            committed.proof.fold_challenges
                .size() -
            1));
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             bad_wire)
             .has_value());
    bad_wire = encoded;
    bad_wire.push_back(0);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             bad_wire)
             .has_value());
    BOOST_CHECK(
        !rc::DeserializeFri3AlgMultiRowBatchProof(
             std::vector<unsigned char>(
                 rc::kRCFri3AlgMultiRowMaxProofBytesHard +
                     1,
                 0))
             .has_value());

    auto changed_groups = groups;
    changed_groups[1][0][0] = gf::Add(
        changed_groups[1][0][0], rc::Fp3::One());
    const auto stale_cache =
        rc::Fri3AlgMultiRowBatchCommitStreaming(
            changed_groups, roles, seed, 13,
            committed.group_row_tree_caches);
    BOOST_CHECK(!stale_cache.ok);

    auto bad_role = committed.proof;
    bad_role.groups[0].role =
        rc::Fri3AlgMultiRowGroupRole::
            AuxiliaryTrace;
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_role, seed, &why));

    auto bad_range = committed.proof;
    bad_range.groups[1].first_column = 3;
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_range, seed, &why));

    auto swapped_roots = committed.proof;
    std::swap(
        swapped_roots.groups[0].row_commit.root,
        swapped_roots.groups[1].row_commit.root);
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            swapped_roots, seed, &why));

    auto bad_length = committed.proof;
    bad_length.column_len[0] = 4;
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_length, seed, &why));

    auto bad_row = committed.proof;
    bad_row.queries[0].group_rows[1]
        .values[0] =
        gf::Add(
            bad_row.queries[0].group_rows[1]
                .values[0],
            rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_row, seed, &why));

    auto bad_path = committed.proof;
    bad_path.queries[0].group_rows[2]
        .siblings[0][0] =
        gf::Add(
            bad_path.queries[0].group_rows[2]
                .siblings[0][0],
            1);
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_path, seed, &why));

    auto bad_fri_lambda = committed.proof;
    bad_fri_lambda.lambda =
        gf::Add(
            bad_fri_lambda.lambda,
            rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_fri_lambda, seed, &why));

    auto bad_eval = committed.proof;
    bad_eval.evals_z2[3] =
        gf::Add(
            bad_eval.evals_z2[3],
            rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_eval, seed, &why));

    auto bad_fold = committed.proof;
    bad_fold.queries[0].steps[0].odd =
        gf::Add(
            bad_fold.queries[0].steps[0].odd,
            rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            bad_fold, seed, &why));

    const auto post_claim_audit =
        rc::AuditFri3AlgMultiRowPostClaimBinding(
            groups, roles, seed, 13);
    BOOST_CHECK_MESSAGE(
        post_claim_audit.valid,
        post_claim_audit.note);
    BOOST_CHECK(
        post_claim_audit
            .legacy_nonzero_kernel_constructed);
    BOOST_CHECK(
        post_claim_audit
            .legacy_aggregate_z1_preserved);
    BOOST_CHECK(
        post_claim_audit
            .legacy_aggregate_z2_preserved);
    BOOST_CHECK(
        post_claim_audit
            .fixed_batch_challenge_changed);
    BOOST_CHECK(
        post_claim_audit
            .fixed_verifier_rejected);
}

BOOST_AUTO_TEST_CASE(
    fra3_multi_row_safe_q192_k2_v13_is_version_separated)
{
    const auto groups = MakeMultiRowGroups();
    const auto roles = MultiRowRoles();
    const uint256 seed = MakeSeed(0x4a);
    const auto committed =
        rc::Fri3AlgMultiRowSafeQ192K2V13BatchCommitStreaming(
            groups, roles, seed, 17);
    BOOST_REQUIRE_MESSAGE(
        committed.ok, committed.note);
    BOOST_CHECK_EQUAL(
        committed.proof.version,
        rc::kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13);
    BOOST_CHECK_EQUAL(
        committed.proof.queries.size(),
        rc::kRCFri3AlgNumQueries);

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
            committed.proof, seed, &why),
        why);
    rc::Fri3AlgSafeV13Replay replay;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerifyReplay(
            committed.proof, seed, replay, &why),
        why);
    BOOST_CHECK(replay.native_verified);
    BOOST_CHECK(replay.exact_event_order);
    BOOST_CHECK_EQUAL(replay.lambda_events, 1U);
    BOOST_CHECK_EQUAL(replay.ood_candidate_events, 4U);
    BOOST_CHECK_EQUAL(replay.deep_weight_events, 2U);
    BOOST_CHECK_EQUAL(
        replay.fold_events,
        committed.proof.fold_challenges.size());
    BOOST_CHECK_EQUAL(replay.query_seed_events, 1U);
    BOOST_CHECK_EQUAL(
        replay.query_candidate_events,
        rc::kRCFri3AlgNumQueries);
    BOOST_REQUIRE_GT(replay.events.size(), 4U);
    BOOST_CHECK(
        replay.events.front().consumer ==
        rc::Fri3AlgSafeV13Consumer::OodZ1);
    BOOST_CHECK(
        replay.events[4].consumer ==
        rc::Fri3AlgSafeV13Consumer::FriLambda);
    BOOST_CHECK(
        gf::Eq(
            replay.events[4].consumed_fp3,
            committed.proof.lambda));
    static constexpr char kMultiRowSafeDomain[] =
        "BTX_RC_FRI3ALG_MULTI_ROW_RAP_SAFE_Q192_K2_V13";
    const auto& first_transcript =
        replay.events.front().transcript_before_draw;
    BOOST_CHECK(
        std::search(
            first_transcript.begin(),
            first_transcript.end(),
            std::begin(kMultiRowSafeDomain),
            std::end(kMultiRowSafeDomain) - 1) ==
        first_transcript.begin());
    uint32_t selected_z1 = 0;
    uint32_t selected_z2 = 0;
    for (uint32_t event = 0; event < 4; ++event) {
        selected_z1 +=
            replay.events[event].consumer ==
                    rc::Fri3AlgSafeV13Consumer::OodZ1 &&
                replay.events[event].selected
            ? 1
            : 0;
        selected_z2 +=
            replay.events[event].consumer ==
                    rc::Fri3AlgSafeV13Consumer::OodZ2 &&
                replay.events[event].selected
            ? 1
            : 0;
    }
    BOOST_CHECK_EQUAL(selected_z1, 1U);
    BOOST_CHECK_EQUAL(selected_z2, 1U);
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            committed.proof, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
            committed.proof, MakeSeed(0x4b), &why));
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerifyReplay(
            committed.proof, MakeSeed(0x4b),
            replay, &why));
    BOOST_CHECK(!replay.native_verified);
    BOOST_CHECK(replay.events.empty());

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_GT(
        rc::SerializeFri3AlgMultiRowBatchProof(
            committed.proof, encoded),
        0U);
    const auto decoded =
        rc::DeserializeFri3AlgMultiRowBatchProof(
            encoded);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(
        decoded->version,
        rc::kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13);
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
            *decoded, seed, &why),
        why);
    std::vector<unsigned char> encoded_again;
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgMultiRowBatchProof(
            *decoded, encoded_again),
        encoded.size());
    BOOST_CHECK(encoded == encoded_again);

    auto bad_eval = committed.proof;
    bad_eval.evals_z1[1] =
        gf::Add(
            bad_eval.evals_z1[1],
            rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
            bad_eval, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerifyReplay(
            bad_eval, seed, replay, &why));
    BOOST_CHECK(!replay.native_verified);
    BOOST_CHECK(replay.events.empty());

    auto bad_query = committed.proof;
    bad_query.queries[0].index ^=
        UINT32_C(1);
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerify(
            bad_query, seed, &why));

    auto downgraded = committed.proof;
    downgraded.version =
        rc::kRCFri3AlgMultiRowBatchProofVersion;
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowBatchVerify(
            downgraded, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgMultiRowSafeQ192K2V13BatchVerifyReplay(
            downgraded, seed, replay, &why));
    BOOST_CHECK(!replay.native_verified);
    BOOST_CHECK(replay.events.empty());
}

// Gate (b): single-eval tamper rejects — both the forge probe (flip one LDE
// eval, recompute only the row root, keep openings) and a direct opened-value
// tamper in one query.
BOOST_AUTO_TEST_CASE(fra3_single_eval_tamper_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgForgeFlippedEvalMustFail(c, seed, /*flip_col=*/1, /*flip_index=*/17, &why),
        why);

    auto forged = c.proof;
    forged.queries[0].row.values[0].c0 ^= 1;
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged, seed, &why));
    BOOST_CHECK_EQUAL(why, "row merkle");
}

// Gate (c): fold-path tamper rejects (opened pair value and fold challenge).
BOOST_AUTO_TEST_CASE(fra3_fold_path_tamper_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;

    auto forged = c.proof;
    forged.queries[0].steps[0].even = gf::Add(forged.queries[0].steps[0].even, gf::Fp3::One());
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold even merkle");

    auto forged2 = c.proof;
    forged2.fold_challenges[0] = gf::Add(forged2.fold_challenges[0], gf::Fp3::One());
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged2, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold challenge mismatch");
}

// Gate (d): sibling / root tamper rejects (row path, fold path, both roots).
BOOST_AUTO_TEST_CASE(fra3_sibling_and_root_tamper_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    std::string why;

    auto forged = c.proof;
    forged.queries[0].row.siblings[0][0] = gf::Add(forged.queries[0].row.siblings[0][0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged, seed, &why));
    BOOST_CHECK_EQUAL(why, "row merkle");

    auto forged2 = c.proof;
    forged2.queries[0].steps[0].even_siblings[0][0] =
        gf::Add(forged2.queries[0].steps[0].even_siblings[0][0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged2, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold even merkle");

    auto forged3 = c.proof;
    forged3.row_commit.root[0] = gf::Add(forged3.row_commit.root[0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged3, seed, &why));
    BOOST_CHECK_EQUAL(why, "batch coefficient mismatch"); // root seeds FS replay

    auto forged4 = c.proof;
    forged4.fold_layers[0].root[0] = gf::Add(forged4.fold_layers[0].root[0], 1);
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(forged4, seed, &why));
    BOOST_CHECK_EQUAL(why, "fold challenge mismatch");
}

// Gate (e): row-wise commitment equivalence — the standalone row-root helper
// (two-epoch discipline; Fri3BatchColumnRoot analogue for the row-wise
// layout) is limb-identical to the full commit's row root, and distinguishes
// distinct column sets.
BOOST_AUTO_TEST_CASE(fra3_row_root_equivalence)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x42);
    const auto c = rc::Fri3AlgBatchCommit(columns, seed);
    BOOST_REQUIRE(c.ok);
    const rc::Fri3AlgDigest standalone = rc::Fri3AlgBatchRowRoot(columns, c.proof.n_coeffs);
    for (int k = 0; k < 4; ++k) {
        BOOST_CHECK_EQUAL(gf::Canonical(standalone[k]),
                          gf::Canonical(c.proof.row_commit.root[k]));
    }
    auto columns2 = columns;
    columns2[2][0] = gf::Add(columns2[2][0], gf::Fp3::One());
    const rc::Fri3AlgDigest other = rc::Fri3AlgBatchRowRoot(columns2, c.proof.n_coeffs);
    bool differs = false;
    for (int k = 0; k < 4; ++k) {
        differs = differs || gf::Canonical(other[k]) != gf::Canonical(standalone[k]);
    }
    BOOST_CHECK(differs);
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_constants_are_experimental_and_fail_closed)
{
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualProofVersion, 2u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualLaneProofVersion, 5u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualNumLanes, 2u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualQueriesPerLane, 128u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualTotalQueries, 256u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualOodCandidates, 2u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualUniformHashBlocks, 2u);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgDualUniformWords, 8u);
    BOOST_CHECK_GE(rc::kRCFri3AlgMaxQueriesHard,
                   rc::kRCFri3AlgDualQueriesPerLane);
    BOOST_CHECK_EQUAL(
        rc::kRCFri3AlgDualMaxProofBytesHard,
        2 * rc::kRCFriMaxProofBytesHard + 128);
    BOOST_CHECK_EQUAL(rc::Fri3AlgDualProximityBoundBits(), 193);
    BOOST_CHECK(!rc::kRCFri3AlgDualFullOracleDomainSeparated);
    BOOST_CHECK(!rc::kRCFri3AlgDualIndependenceReductionReady);
    BOOST_CHECK(!rc::kRCFri3AlgDualFormalSoundnessReady);
    BOOST_CHECK(std::string(rc::kRCFri3AlgDualLane0DomainTag) !=
                std::string(rc::kRCFri3AlgDualLane1DomainTag));
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_uniform_candidate_forced_rejection)
{
    std::array<unsigned char, 24> candidate{};
    candidate[0] = 7;
    candidate[8] = 8;
    candidate[16] = 9;
    const auto accepted = rc::Fri3AlgDecodeUniformFp3Candidate(candidate);
    BOOST_REQUIRE(accepted.has_value());
    BOOST_CHECK_EQUAL(gf::Canonical(accepted->c0), 7u);
    BOOST_CHECK_EQUAL(gf::Canonical(accepted->c1), 8u);
    BOOST_CHECK_EQUAL(gf::Canonical(accepted->c2), 9u);

    // Force candidate limb 1 to p. V5 rejects it; the legacy modulo mapper
    // would reduce exactly the same bytes to zero, demonstrating the semantic
    // difference that removes the ~2^-32-per-limb bias.
    for (uint32_t byte = 0; byte < 8; ++byte) {
        candidate[8 + byte] =
            static_cast<unsigned char>((gf::kP >> (8 * byte)) & 0xFF);
    }
    BOOST_CHECK(!rc::Fri3AlgDecodeUniformFp3Candidate(candidate).has_value());
    const rc::Fp3 legacy = gf::FromChallengeBytes3(candidate.data());
    BOOST_CHECK_EQUAL(gf::Canonical(legacy.c1), 0u);

    std::array<uint64_t, rc::kRCFri3AlgDualUniformWords> words{
        gf::kP, 7, gf::kP, 8, 9, gf::kP, gf::kP, gf::kP};
    const auto selected = rc::Fri3AlgSelectUniformFp3Words(words);
    BOOST_REQUIRE(selected.has_value());
    BOOST_CHECK_EQUAL(gf::Canonical(selected->c0), 7u);
    BOOST_CHECK_EQUAL(gf::Canonical(selected->c1), 8u);
    BOOST_CHECK_EQUAL(gf::Canonical(selected->c2), 9u);
    words = {gf::kP, gf::kP, gf::kP, gf::kP,
             gf::kP, gf::kP, 7, 8};
    BOOST_CHECK(!rc::Fri3AlgSelectUniformFp3Words(words).has_value());
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_honest_verify_and_canonical_serde)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x52);
    const auto c = rc::Fri3AlgDualBatchCommit(columns, seed, /*pow_grind_nonce=*/17);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    BOOST_CHECK_EQUAL(c.proof.lane[0].version, rc::kRCFri3AlgDualLaneProofVersion);
    BOOST_CHECK_EQUAL(c.proof.lane[1].version, rc::kRCFri3AlgDualLaneProofVersion);
    BOOST_CHECK_EQUAL(c.proof.lane[0].queries.size(),
                      rc::kRCFri3AlgDualQueriesPerLane);
    BOOST_CHECK_EQUAL(c.proof.lane[1].queries.size(),
                      rc::kRCFri3AlgDualQueriesPerLane);
    BOOST_CHECK(c.proof.lane[0].row_commit.root ==
                c.proof.lane[1].row_commit.root);
    BOOST_CHECK(c.proof.master_statement_binding != uint256{});
    BOOST_CHECK(c.proof.lane_child_binding[0] !=
                c.proof.lane_child_binding[1]);
    // V5's first encoded batching coordinates come from distinct lane RO
    // domains; this fixed fixture also pins that they are not a replay.
    BOOST_CHECK(!gf::Eq(c.proof.lane[0].lambda, c.proof.lane[1].lambda));
    // Exact power-of-two index derivation vector (raw RO bits & (N-1)), also
    // pins that the two lane prefixes produce different query streams.
    bool query_streams_differ = false;
    for (size_t i = 0; i < 4; ++i) {
        query_streams_differ =
            query_streams_differ ||
            c.proof.lane[0].queries[i].index !=
                c.proof.lane[1].queries[i].index;
    }
    BOOST_CHECK(query_streams_differ);
    for (const auto& lane : c.proof.lane) {
        for (const auto& query : lane.queries) {
            BOOST_CHECK_LT(query.index, c.proof.lane[0].row_commit.n_leaves);
        }
    }
    std::string why;
    BOOST_CHECK_MESSAGE(rc::Fri3AlgDualBatchVerify(c.proof, seed, &why), why);

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_EQUAL(rc::SerializeFri3AlgDualBatchProof(c.proof, encoded),
                        c.proof_bytes);
    const auto parsed = rc::DeserializeFri3AlgDualBatchProof(encoded);
    BOOST_REQUIRE(parsed.has_value());
    std::vector<unsigned char> encoded_again;
    BOOST_CHECK_EQUAL(rc::SerializeFri3AlgDualBatchProof(*parsed, encoded_again),
                      encoded.size());
    BOOST_CHECK(encoded == encoded_again);
    BOOST_CHECK_MESSAGE(rc::Fri3AlgDualBatchVerify(*parsed, seed, &why), why);
}

BOOST_AUTO_TEST_CASE(
    fra3_dual_q128_streaming_prover_is_byte_identical)
{
    const std::array<std::vector<std::vector<rc::Fp3>>, 2> cases{
        MakeColumns(), MakeMediumColumns()};
    for (size_t case_index = 0;
         case_index < cases.size(); ++case_index) {
        const uint256 seed =
            MakeSeed(static_cast<uint8_t>(0x72 + case_index));
        const uint64_t nonce = 41 + case_index;
        const auto materialized =
            rc::Fri3AlgDualBatchCommit(
                cases[case_index], seed, nonce);
        BOOST_REQUIRE_MESSAGE(
            materialized.ok, materialized.note);
        const auto streaming =
            rc::Fri3AlgDualBatchCommitStreamingShared(
                cases[case_index], seed, nonce);
        BOOST_REQUIRE_MESSAGE(streaming.ok, streaming.note);
        BOOST_CHECK(streaming.column_lde.empty());
        BOOST_CHECK_EQUAL(
            streaming.proof_bytes,
            materialized.proof_bytes);
        const auto estimated =
            rc::EstimateFri3AlgDualBatchProofBytes(
                static_cast<uint32_t>(cases[case_index].size()),
                materialized.proof.lane[0].n_coeffs);
        BOOST_REQUIRE(estimated.has_value());
        BOOST_CHECK_EQUAL(
            *estimated, materialized.proof_bytes);

        std::vector<unsigned char> materialized_bytes;
        std::vector<unsigned char> streaming_bytes;
        BOOST_REQUIRE_EQUAL(
            rc::SerializeFri3AlgDualBatchProof(
                materialized.proof, materialized_bytes),
            materialized.proof_bytes);
        BOOST_REQUIRE_EQUAL(
            rc::SerializeFri3AlgDualBatchProof(
                streaming.proof, streaming_bytes),
            streaming.proof_bytes);
        BOOST_CHECK(materialized_bytes == streaming_bytes);

        std::string why;
        BOOST_CHECK_MESSAGE(
            rc::Fri3AlgDualBatchVerify(
                streaming.proof, seed, &why),
            why);
    }
}

BOOST_AUTO_TEST_CASE(
    fra3_q192_streaming_row_tree_session_reuses_checked_paths)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x73);
    const auto dense =
        rc::Fri3AlgBatchCommit(columns, seed, 47);
    BOOST_REQUIRE_MESSAGE(dense.ok, dense.note);
    const auto cached =
        rc::Fri3AlgBatchCommitStreamingSharedCached(
            columns, seed, 47);
    BOOST_REQUIRE_MESSAGE(cached.ok, cached.note);
    BOOST_REQUIRE(cached.row_tree_cache);
    BOOST_CHECK(cached.row_tree_cache->valid);
    BOOST_CHECK(cached.column_lde.empty());
    BOOST_CHECK(
        cached.row_tree_cache->root ==
        cached.proof.row_commit.root);

    std::vector<unsigned char> dense_bytes;
    std::vector<unsigned char> cached_bytes;
    BOOST_REQUIRE_NE(
        rc::SerializeFri3AlgBatchProof(
            dense.proof, dense_bytes),
        0U);
    BOOST_REQUIRE_NE(
        rc::SerializeFri3AlgBatchProof(
            cached.proof, cached_bytes),
        0U);
    BOOST_CHECK(dense_bytes == cached_bytes);

    std::vector<uint32_t> indices;
    indices.reserve(cached.proof.queries.size());
    for (const auto& query : cached.proof.queries) {
        indices.push_back(query.index);
    }
    std::vector<rc::Fri3AlgRowOpening> opened;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgOpenRowsStreamingSharedCached(
            columns, cached.proof.n_coeffs,
            indices, cached.proof.row_commit.root,
            *cached.row_tree_cache, opened, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        opened.size(), cached.proof.queries.size());
    for (size_t query = 0;
         query < opened.size(); ++query) {
        BOOST_CHECK(
            opened[query].siblings ==
            cached.proof.queries[query].row.siblings);
        BOOST_REQUIRE_EQUAL(
            opened[query].values.size(),
            cached.proof.queries[query].
                row.values.size());
        for (size_t column = 0;
             column < opened[query].values.size();
             ++column) {
            BOOST_CHECK(gf::Eq(
                opened[query].values[column],
                cached.proof.queries[query].
                    row.values[column]));
        }
    }

    auto wrong = *cached.row_tree_cache;
    wrong.root[0] =
        gf::Add(wrong.root[0], gf::Fp{1});
    BOOST_CHECK(
        !rc::Fri3AlgOpenRowsStreamingSharedCached(
            columns, cached.proof.n_coeffs,
            indices, cached.proof.row_commit.root,
            wrong, opened, &why));
    wrong = *cached.row_tree_cache;
    wrong.coefficient_commitment.data()[0] ^= 1U;
    BOOST_CHECK(
        !rc::Fri3AlgOpenRowsStreamingSharedCached(
            columns, cached.proof.n_coeffs,
            indices, cached.proof.row_commit.root,
            wrong, opened, &why));
    auto altered = columns;
    altered[0][0].c0 =
        gf::Add(altered[0][0].c0, gf::Fp{1});
    BOOST_CHECK(
        !rc::Fri3AlgOpenRowsStreamingSharedCached(
            altered, cached.proof.n_coeffs,
            indices, cached.proof.row_commit.root,
            *cached.row_tree_cache, opened, &why));
}

BOOST_AUTO_TEST_CASE(
    fra3_dual_fold_layers_spill_and_replay_byte_identically)
{
    static_assert(
        rc::kFri3AlgBoundedFoldSpillReplayAuditExecutable);
    const auto columns = MakeColumns();
    uint32_t n = 1;
    for (const auto& column : columns) {
        n = std::max<uint32_t>(
            n, static_cast<uint32_t>(column.size()));
    }
    n = rc::FriNextPow2(n);
    uint32_t log_n = 0;
    for (uint32_t value = n; value > 1;
         value >>= 1) {
        ++log_n;
    }
    const uint32_t layers = log_n + 1;
    aq::AirFp3ExternalColumnStore store(
        aq::AirExternalStoreBackend::
            kAnonymousTempFile,
        rc::kRCFri3AlgDualNumLanes * layers,
        n * rc::kRCFriBlowup);
    BOOST_REQUIRE(store.IsOpen());
    auto write =
        [&](uint32_t lane, uint32_t layer,
            const std::vector<rc::Fp3>& values,
            std::string* why) {
            return store.Write(
                lane * layers + layer,
                0, values, why);
        };
    auto read =
        [&](uint32_t lane, uint32_t layer,
            uint32_t count,
            std::vector<rc::Fp3>& values,
            std::string* why) {
            return store.Read(
                lane * layers + layer,
                0, count, values, why);
        };
    const auto audit =
        rc::AuditFri3AlgDualFoldSpillReplay(
            columns, MakeSeed(0x74),
            write, read, 43);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.fold_values_roundtrip);
    BOOST_CHECK(audit.layer_roots_identical);
    BOOST_CHECK(audit.query_paths_identical);
    BOOST_CHECK(audit.dense_proof_bytes_identical);
    BOOST_CHECK(audit.streaming_proof_bytes_identical);
    BOOST_CHECK(audit.replayed_proof_verified);
    BOOST_CHECK(audit.executable_bounded_audit);
    BOOST_CHECK_EQUAL(audit.lanes, 2U);
    BOOST_CHECK_EQUAL(
        audit.layers_spilled, 2U * layers);
    BOOST_CHECK_EQUAL(
        audit.paths_replayed,
        2U * rc::kRCFri3AlgDualQueriesPerLane *
            log_n);
    BOOST_CHECK_EQUAL(audit.layers_spilled, 8U);
    BOOST_CHECK_EQUAL(audit.paths_replayed, 768U);
    BOOST_CHECK_EQUAL(audit.evaluations_spilled, 480U);
    BOOST_CHECK_EQUAL(store.ResidentCells(), 0U);
    BOOST_CHECK_EQUAL(
        store.PeakLiveCells(),
        n * rc::kRCFriBlowup);
}

BOOST_AUTO_TEST_CASE(
    fra3_dual_q128_exact_production_shape_size_fits_v1_attachment)
{
    BOOST_CHECK(
        !rc::EstimateFri3AlgDualBatchProofBytes(0, 1)
             .has_value());
    BOOST_CHECK(
        !rc::EstimateFri3AlgDualBatchProofBytes(1, 3)
             .has_value());
    BOOST_CHECK(
        !rc::EstimateFri3AlgDualBatchProofBytes(
             rc::kRCFri3AlgBatchMaxColumns + 1, 1)
             .has_value());

    const auto width_only =
        rc::EstimateFri3AlgDualBatchProofBytes(1092, 2);
    const auto depth_only =
        rc::EstimateFri3AlgDualBatchProofBytes(1, 1U << 16);
    const auto combined =
        rc::EstimateFri3AlgDualBatchProofBytes(
            1092, 1U << 19);
    BOOST_REQUIRE(width_only.has_value());
    BOOST_REQUIRE(depth_only.has_value());
    BOOST_REQUIRE(combined.has_value());
    BOOST_CHECK_EQUAL(*width_only, 6'966'948U);
    BOOST_CHECK_EQUAL(*depth_only, 3'715'700U);
    BOOST_CHECK_EQUAL(*combined, 11'687'700U);
    BOOST_CHECK_LT(*combined, 16U * 1024U * 1024U);

    const auto q136_width_only =
        rc::EstimateFri3AlgDualQ136BatchProofBytes(
            1092, 2);
    const auto q136_depth_only =
        rc::EstimateFri3AlgDualQ136BatchProofBytes(
            1, 1U << 16);
    const auto q136_combined =
        rc::EstimateFri3AlgDualQ136BatchProofBytes(
            1092, 1U << 19);
    BOOST_REQUIRE(q136_width_only.has_value());
    BOOST_REQUIRE(q136_depth_only.has_value());
    BOOST_REQUIRE(q136_combined.has_value());
    BOOST_CHECK_EQUAL(
        *q136_width_only, 7'395'236U);
    BOOST_CHECK_EQUAL(
        *q136_depth_only, 3'947'764U);
    BOOST_CHECK_EQUAL(
        *q136_combined, 12'410'900U);
    BOOST_CHECK_LT(
        *q136_combined,
        16U * 1024U * 1024U);
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_complete_transcript_witness_replays_and_rejects_mutations)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x71);
    const auto committed =
        rc::Fri3AlgDualBatchCommit(
            columns, seed, /*pow_grind_nonce=*/37);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);

    const auto witness =
        rc::BuildFri3AlgDualTranscriptWitness(
            committed.proof, seed);
    BOOST_REQUIRE_MESSAGE(witness.valid, witness.note);
    BOOST_REQUIRE_MESSAGE(
        witness.program.valid, witness.program.note);
    BOOST_CHECK_EQUAL(witness.program.batch_columns, columns.size());
    BOOST_CHECK_EQUAL(
        witness.program.fold_challenges_per_lane,
        committed.proof.lane[0].fold_challenges.size());
    BOOST_CHECK_EQUAL(
        witness.program.independent_batch_draws_per_lane,
        columns.size());
    BOOST_CHECK_EQUAL(
        witness.program.ood_draws_per_lane, 4u);
    BOOST_CHECK_EQUAL(
        witness.program.queries_per_lane,
        rc::kRCFri3AlgDualQueriesPerLane);
    BOOST_CHECK_EQUAL(
        witness.program.uniform_fp3_draws_per_lane,
        columns.size() + 4u + 2u +
            committed.proof.lane[0].fold_challenges.size());
    BOOST_CHECK_EQUAL(
        witness.program.challenge_hashes_total,
        2u *
            (2u *
                 witness.program.uniform_fp3_draws_per_lane +
             rc::kRCFri3AlgDualQueriesPerLane));
    BOOST_CHECK(witness.program.fixed_ood_schedule);
    BOOST_CHECK(witness.program.independent_batching);
    BOOST_CHECK(witness.program.lane_order_semantic);
    BOOST_CHECK(witness.common_statement_bound);
    BOOST_CHECK(witness.ordered_lanes_bound);
    BOOST_CHECK(
        witness.master_statement_binding ==
        committed.proof.master_statement_binding);
    for (uint32_t lane = 0;
         lane < rc::kRCFri3AlgDualNumLanes; ++lane) {
        const auto& lane_witness = witness.lane[lane];
        const auto& lane_proof = committed.proof.lane[lane];
        BOOST_CHECK(lane_witness.valid);
        BOOST_CHECK_EQUAL(lane_witness.lane, lane);
        BOOST_CHECK(
            lane_witness.independent_coefficients_replayed);
        BOOST_CHECK(
            lane_witness.fixed_ood_schedule_replayed);
        BOOST_CHECK(lane_witness.folds_replayed);
        BOOST_CHECK(lane_witness.queries_replayed);
        BOOST_CHECK_EQUAL(
            lane_witness.batch_coefficients.size(),
            lane_proof.column_len.size());
        BOOST_CHECK_EQUAL(
            lane_witness.fold_challenges.size(),
            lane_proof.fold_challenges.size());
        BOOST_CHECK_EQUAL(
            lane_witness.query_indices.size(),
            rc::kRCFri3AlgDualQueriesPerLane);
        BOOST_CHECK(
            gf::Eq(
                lane_witness.selected_z1,
                lane_proof.z1));
        BOOST_CHECK(
            gf::Eq(
                lane_witness.selected_z2,
                lane_proof.z2));
        BOOST_CHECK(
            gf::Eq(lane_witness.w1, lane_proof.w1));
        BOOST_CHECK(
            gf::Eq(lane_witness.w2, lane_proof.w2));
    }
    BOOST_CHECK(
        witness.lane[0].lane_seed !=
        witness.lane[1].lane_seed);
    BOOST_CHECK(
        !gf::Eq(
            witness.lane[0].batch_coefficients[0],
            witness.lane[1].batch_coefficients[0]));

    auto swapped = committed.proof;
    std::swap(swapped.lane[0], swapped.lane[1]);
    const auto swapped_witness =
        rc::BuildFri3AlgDualTranscriptWitness(swapped, seed);
    BOOST_CHECK(!swapped_witness.valid);

    auto coefficient_mutation = committed.proof;
    coefficient_mutation.lane[1].lambda =
        gf::Add(
            coefficient_mutation.lane[1].lambda,
            rc::Fp3::One());
    const auto coefficient_witness =
        rc::BuildFri3AlgDualTranscriptWitness(
            coefficient_mutation, seed);
    BOOST_CHECK(!coefficient_witness.valid);
    BOOST_CHECK_EQUAL(
        coefficient_witness.note,
        "dual transcript lane 1: batch coefficient mismatch");

    auto fold_mutation = committed.proof;
    BOOST_REQUIRE(
        !fold_mutation.lane[0].fold_challenges.empty());
    fold_mutation.lane[0].fold_challenges[0] =
        gf::Add(
            fold_mutation.lane[0].fold_challenges[0],
            rc::Fp3::One());
    const auto fold_witness =
        rc::BuildFri3AlgDualTranscriptWitness(
            fold_mutation, seed);
    BOOST_CHECK(!fold_witness.valid);
    BOOST_CHECK_EQUAL(
        fold_witness.note,
        "dual transcript lane 0: fold challenge mismatch");

    auto query_mutation = committed.proof;
    query_mutation.lane[1].queries[0].index ^=
        1u;
    const auto query_witness =
        rc::BuildFri3AlgDualTranscriptWitness(
            query_mutation, seed);
    BOOST_CHECK(!query_witness.valid);
    BOOST_CHECK_EQUAL(
        query_witness.note,
        "dual transcript lane 1: query-index mismatch");
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_rejects_lane_swap_copy_replay_binding_and_tamper)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x53);
    const auto c = rc::Fri3AlgDualBatchCommit(columns, seed, /*pow_grind_nonce=*/18);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    std::string why;

    auto swapped = c.proof;
    std::swap(swapped.lane[0], swapped.lane[1]);
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(swapped, seed, &why));

    auto copied = c.proof;
    copied.lane[1] = copied.lane[0];
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(copied, seed, &why));

    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(c.proof, MakeSeed(0x54), &why));

    auto tampered = c.proof;
    tampered.lane[1].queries[0].row.values[0].c0 ^= 1;
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(tampered, seed, &why));

    auto replayed_batch_coefficient = c.proof;
    replayed_batch_coefficient.lane[1].lambda =
        replayed_batch_coefficient.lane[0].lambda;
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(
        replayed_batch_coefficient, seed, &why));
    BOOST_CHECK_EQUAL(why, "dual: lane 1: batch coefficient mismatch");

    auto substituted_master = c.proof;
    substituted_master.master_statement_binding.data()[0] ^= 1;
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(substituted_master, seed, &why));
    BOOST_CHECK_EQUAL(why, "dual: master/child binding mismatch");

    auto substituted_child = c.proof;
    substituted_child.lane_child_binding[1] =
        substituted_child.lane_child_binding[0];
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(substituted_child, seed, &why));
    BOOST_CHECK_EQUAL(why, "dual: master/child binding mismatch");

    auto mismatched = c.proof;
    mismatched.lane[1].row_commit.root[0] =
        gf::Add(mismatched.lane[1].row_commit.root[0], 1);
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(mismatched, seed, &why));
    BOOST_CHECK_EQUAL(why, "dual: shared row commitment mismatch");
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_codec_rejects_noncanonical_and_malformed)
{
    const auto c =
        rc::Fri3AlgDualBatchCommit(MakeColumns(), MakeSeed(0x55), /*pow_grind_nonce=*/19);
    BOOST_REQUIRE_MESSAGE(c.ok, c.note);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(rc::SerializeFri3AlgDualBatchProof(c.proof, encoded) > 0);

    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(!rc::DeserializeFri3AlgDualBatchProof(trailing).has_value());

    // Outer layout: magic, version, lane-count, master, two children, then
    // lane-id and lane length.
    auto bad_lane_id = encoded;
    bad_lane_id[108] = 1;
    BOOST_CHECK(!rc::DeserializeFri3AlgDualBatchProof(bad_lane_id).has_value());

    auto oversized_lane = encoded;
    for (size_t i = 112; i < 116; ++i) oversized_lane[i] = 0xFF;
    BOOST_CHECK(!rc::DeserializeFri3AlgDualBatchProof(oversized_lane).has_value());

    std::vector<unsigned char> oversized_outer(
        rc::kRCFri3AlgDualMaxProofBytesHard + 1, 0);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgDualBatchProof(oversized_outer).has_value());

    // Lane 0 starts at byte 116. Its first Fp3 (encoded coefficient[0])
    // starts after:
    // magic/version/nonce/blowup/n/root/nleaves/ncols/three column lengths.
    constexpr size_t kLane0LambdaOffset =
        116 + 4 + 4 + 8 + 4 + 4 + 32 + 4 + 4 + 3 * 4;
    BOOST_REQUIRE_GE(encoded.size(), kLane0LambdaOffset + 8);
    auto noncanonical = encoded;
    const uint64_t p = gf::kP;
    for (int i = 0; i < 8; ++i) {
        noncanonical[kLane0LambdaOffset + i] =
            static_cast<unsigned char>((p >> (8 * i)) & 0xFF);
    }
    BOOST_CHECK(!rc::DeserializeFri3AlgDualBatchProof(noncanonical).has_value());
}

BOOST_AUTO_TEST_CASE(
    fra3_dual_q136_v6_roundtrip_transcript_codec_and_mutations)
{
    static_assert(
        rc::kRCFri3AlgDualQ136QueriesPerLane ==
        136);
    static_assert(
        !rc::kRCFri3AlgDualQ136FormalSoundnessReady);
    BOOST_CHECK_EQUAL(
        rc::kRCFri3AlgDualQ136TotalQueries,
        272U);
    BOOST_CHECK_GT(
        rc::Fri3AlgDualQ136ProximityBoundBits(),
        rc::Fri3AlgDualProximityBoundBits());

    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x76);
    const auto committed =
        rc::Fri3AlgDualQ136BatchCommit(
            columns, seed, 53);
    BOOST_REQUIRE_MESSAGE(
        committed.ok, committed.note);
    BOOST_CHECK_EQUAL(
        committed.proof.version,
        rc::kRCFri3AlgDualQ136ProofVersion);
    for (const auto& lane : committed.proof.lane) {
        BOOST_CHECK_EQUAL(
            lane.version,
            rc::kRCFri3AlgDualQ136LaneProofVersion);
        BOOST_CHECK_EQUAL(
            lane.queries.size(),
            rc::kRCFri3AlgDualQ136QueriesPerLane);
    }

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgDualQ136BatchVerify(
            committed.proof, seed, &why),
        why);
    const auto duplicated =
        rc::Fri3AlgDualQ136BatchCommitForScenario(
            columns, MakeSeed(0x78),
            rc::Fri3AlgDualCommitmentScenario::
                FullyDuplicatedLaneCommitments,
            59);
    BOOST_REQUIRE_MESSAGE(
        duplicated.ok, duplicated.note);
    BOOST_CHECK(
        duplicated.proof.lane[0].row_commit.root !=
        duplicated.proof.lane[1].row_commit.root);
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgDualQ136BatchVerifyForScenario(
            duplicated.proof, MakeSeed(0x78),
            rc::Fri3AlgDualCommitmentScenario::
                FullyDuplicatedLaneCommitments,
            &why),
        why);
    // Commitment topology is transcript data. A duplicated proof must not
    // cross-verify as the shared-master protocol.
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            duplicated.proof, MakeSeed(0x78),
            &why));
    auto duplicated_swapped = duplicated.proof;
    std::swap(
        duplicated_swapped.lane[0],
        duplicated_swapped.lane[1]);
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerifyForScenario(
            duplicated_swapped, MakeSeed(0x78),
            rc::Fri3AlgDualCommitmentScenario::
                FullyDuplicatedLaneCommitments,
            &why));
    const auto streamed =
        rc::Fri3AlgDualQ136BatchCommitStreamingShared(
            columns, seed, 53);
    BOOST_REQUIRE_MESSAGE(
        streamed.ok, streamed.note);
    BOOST_CHECK(streamed.column_lde.empty());
    // Protocol versions are disjoint and never cross-accept.
    BOOST_CHECK(
        !rc::Fri3AlgDualBatchVerify(
            committed.proof, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            committed.proof, MakeSeed(0x77),
            &why));

    const auto transcript =
        rc::BuildFri3AlgDualQ136TranscriptWitness(
            committed.proof, seed);
    BOOST_REQUIRE_MESSAGE(
        transcript.valid, transcript.note);
    BOOST_CHECK_EQUAL(
        transcript.program.envelope_version,
        rc::kRCFri3AlgDualQ136ProofVersion);
    BOOST_CHECK_EQUAL(
        transcript.program.lane_version,
        rc::kRCFri3AlgDualQ136LaneProofVersion);
    BOOST_CHECK_EQUAL(
        transcript.program.queries_per_lane,
        rc::kRCFri3AlgDualQ136QueriesPerLane);
    BOOST_CHECK(
        transcript.lane[0].lane_seed !=
        transcript.lane[1].lane_seed);
    BOOST_CHECK(
        !gf::Eq(
            transcript.lane[0].
                batch_coefficients[0],
            transcript.lane[1].
                batch_coefficients[0]));

    const auto estimate =
        rc::EstimateFri3AlgDualQ136BatchProofBytes(
            columns.size(),
            committed.proof.lane[0].n_coeffs);
    BOOST_REQUIRE(estimate.has_value());
    BOOST_CHECK_EQUAL(
        *estimate, committed.proof_bytes);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_EQUAL(
        rc::SerializeFri3AlgDualQ136BatchProof(
            committed.proof, encoded),
        committed.proof_bytes);
    std::vector<unsigned char> streamed_encoded;
    BOOST_REQUIRE_EQUAL(
        rc::SerializeFri3AlgDualQ136BatchProof(
            streamed.proof, streamed_encoded),
        streamed.proof_bytes);
    BOOST_CHECK(encoded == streamed_encoded);
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgDualQ136BatchVerify(
            streamed.proof, seed, &why),
        why);
    const auto decoded =
        rc::DeserializeFri3AlgDualQ136BatchProof(
            encoded);
    BOOST_REQUIRE(decoded.has_value());
    std::vector<unsigned char> reencoded;
    BOOST_REQUIRE_EQUAL(
        rc::SerializeFri3AlgDualQ136BatchProof(
            *decoded, reencoded),
        encoded.size());
    BOOST_CHECK(encoded == reencoded);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgDualBatchProof(
            encoded)
             .has_value());

    auto bad_magic = encoded;
    bad_magic[0] ^= 1U;
    BOOST_CHECK(
        !rc::DeserializeFri3AlgDualQ136BatchProof(
            bad_magic)
             .has_value());
    auto bad_version = encoded;
    bad_version[4] ^= 1U;
    BOOST_CHECK(
        !rc::DeserializeFri3AlgDualQ136BatchProof(
            bad_version)
             .has_value());

    auto swapped = committed.proof;
    std::swap(
        swapped.lane[0], swapped.lane[1]);
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            swapped, seed, &why));
    auto copied = committed.proof;
    copied.lane[1] = copied.lane[0];
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            copied, seed, &why));

    auto removed = committed.proof;
    removed.lane[0].queries.pop_back();
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            removed, seed, &why));
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgDualQ136BatchProof(
            removed, reencoded),
        0U);
    BOOST_CHECK(
        !rc::BuildFri3AlgDualQ136TranscriptWitness(
             removed, seed)
             .valid);

    auto added = committed.proof;
    added.lane[1].queries.push_back(
        added.lane[1].queries.back());
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            added, seed, &why));
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgDualQ136BatchProof(
            added, reencoded),
        0U);

    auto query_mutation = committed.proof;
    query_mutation.lane[0].queries[0].index ^=
        1U;
    BOOST_CHECK(
        !rc::Fri3AlgDualQ136BatchVerify(
            query_mutation, seed, &why));
    BOOST_CHECK(
        !rc::BuildFri3AlgDualQ136TranscriptWitness(
             query_mutation, seed)
             .valid);

    // Q128 remains on its original envelope and codec.
    const auto q128 =
        rc::Fri3AlgDualBatchCommit(
            columns, seed, 53);
    BOOST_REQUIRE_MESSAGE(q128.ok, q128.note);
    const auto q128_transcript =
        rc::BuildFri3AlgDualTranscriptWitness(
            q128.proof, seed);
    BOOST_REQUIRE_MESSAGE(
        q128_transcript.valid,
        q128_transcript.note);
    for (uint32_t lane = 0;
         lane < rc::kRCFri3AlgDualNumLanes;
         ++lane) {
        BOOST_CHECK(
            q128_transcript.lane[lane].
                lane_seed !=
            transcript.lane[lane].lane_seed);
        BOOST_CHECK(
            !gf::Eq(
                q128_transcript.lane[lane].
                    batch_coefficients[0],
                transcript.lane[lane].
                    batch_coefficients[0]));
    }
    std::vector<unsigned char> q128_encoded;
    BOOST_REQUIRE_NE(
        rc::SerializeFri3AlgDualBatchProof(
            q128.proof, q128_encoded),
        0U);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgDualQ136BatchProof(
            q128_encoded)
             .has_value());
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_oracle_hybrid_scenarios_fail_closed)
{
    const auto duplicated = rc::AssessFri3AlgDualOracleHybrid(
        rc::Fri3AlgDualCommitmentScenario::FullyDuplicatedLaneCommitments,
        /*batch_columns=*/1u << 14,
        /*lde_log2=*/24,
        /*global_site_log2=*/28);
    BOOST_CHECK(duplicated.executable);
    BOOST_CHECK(duplicated.independent_batching_executable);
    BOOST_CHECK(duplicated.all_sha_transcript_calls_lane_prefixed);
    BOOST_CHECK(duplicated.master_statement_binding_executable);
    BOOST_CHECK(duplicated.ordered_child_binding_executable);
    BOOST_CHECK_EQUAL(duplicated.independent_batch_draws_per_lane, 1u << 14);
    BOOST_CHECK_EQUAL(duplicated.uniform_field_draws_per_lane,
                      (1u << 14) + 4u + 2u + 20u);
    BOOST_CHECK_EQUAL(duplicated.sha_transcript_calls_per_lane,
                      1u + 2u * ((1u << 14) + 26u) + 128u);
    BOOST_CHECK_EQUAL(duplicated.common_commitment_union_floor_bits, 99u);
    BOOST_CHECK(duplicated.duplicates_poseidon_row_tree);
    BOOST_CHECK(duplicated.all_poseidon_oracle_calls_lane_prefixed);
    BOOST_CHECK(!duplicated.common_commitment_hybrid_reduction_complete);
    BOOST_CHECK(!duplicated.full_nirop_oracle_separation_proven);
    BOOST_CHECK(!duplicated.formal_soundness_ready);
    const auto duplicated_proof =
        rc::Fri3AlgDualBatchCommitForScenario(
            MakeColumns(), MakeSeed(0x64),
            rc::Fri3AlgDualCommitmentScenario::
                FullyDuplicatedLaneCommitments,
            29);
    BOOST_REQUIRE_MESSAGE(duplicated_proof.ok, duplicated_proof.note);
    BOOST_CHECK(
        duplicated_proof.proof.lane[0].row_commit.root !=
        duplicated_proof.proof.lane[1].row_commit.root);
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgDualBatchVerifyForScenario(
            duplicated_proof.proof, MakeSeed(0x64),
            rc::Fri3AlgDualCommitmentScenario::
                FullyDuplicatedLaneCommitments,
            &why),
        why);
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(
        duplicated_proof.proof, MakeSeed(0x64), &why));

    const auto shared = rc::AssessFri3AlgDualOracleHybrid(
        rc::Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
        /*batch_columns=*/1u << 14,
        /*lde_log2=*/24,
        /*global_site_log2=*/28);
    BOOST_CHECK(shared.executable);
    BOOST_CHECK(!shared.duplicates_poseidon_row_tree);
    BOOST_CHECK_EQUAL(shared.common_commitment_union_floor_bits, 100u);
    BOOST_CHECK(!shared.all_poseidon_oracle_calls_lane_prefixed);
    BOOST_CHECK(!shared.common_commitment_hybrid_reduction_complete);
    BOOST_CHECK(!shared.full_nirop_oracle_separation_proven);
    BOOST_CHECK(!shared.formal_soundness_ready);

    const auto invalid = rc::AssessFri3AlgDualOracleHybrid(
        rc::Fri3AlgDualCommitmentScenario::SharedMasterDerivedChildren,
        /*batch_columns=*/0,
        /*lde_log2=*/24);
    BOOST_CHECK(!invalid.executable);

    const auto unknown_scenario =
        static_cast<rc::Fri3AlgDualCommitmentScenario>(0xff);
    const auto invalid_scenario_assessment =
        rc::AssessFri3AlgDualOracleHybrid(
            unknown_scenario, /*batch_columns=*/3,
            /*lde_log2=*/4);
    BOOST_CHECK(!invalid_scenario_assessment.executable);
    const auto invalid_scenario_proof =
        rc::Fri3AlgDualBatchCommitForScenario(
            MakeColumns(), MakeSeed(0x66),
            unknown_scenario, 31);
    BOOST_CHECK(!invalid_scenario_proof.ok);
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerifyForScenario(
        duplicated_proof.proof, MakeSeed(0x64),
        unknown_scenario, &why));
    BOOST_CHECK_EQUAL(
        why, "dual: unknown commitment scenario");
}

BOOST_AUTO_TEST_CASE(fra3_dual_query_count_cost_probe_toy_and_medium)
{
    auto probe = [](const char* shape,
                    const std::vector<std::vector<rc::Fp3>>& columns,
                    const uint256& seed,
                    rc::Fri3AlgDualCommitmentScenario scenario) {
        const auto prove_begin =
            std::chrono::steady_clock::now();
        const auto c = rc::Fri3AlgDualBatchCommitForScenario(
            columns, seed, scenario, 23);
        const auto prove_us =
            std::chrono::duration_cast<
                std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                prove_begin)
                .count();
        BOOST_REQUIRE_MESSAGE(c.ok, c.note);
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::Fri3AlgDualBatchVerifyForScenario(
                c.proof, seed, scenario, &why), why);

        constexpr uint32_t REPEATS = 5;
        const auto begin = std::chrono::steady_clock::now();
        for (uint32_t i = 0; i < REPEATS; ++i) {
            BOOST_REQUIRE_MESSAGE(
                rc::Fri3AlgDualBatchVerifyForScenario(
                    c.proof, seed, scenario, &why), why);
        }
        const auto elapsed = std::chrono::duration_cast<
            std::chrono::microseconds>(
            std::chrono::steady_clock::now() - begin).count();
        BOOST_TEST_MESSAGE(
            "FRI3ALG_DUAL_COST shape=" << shape
            << " scenario="
            << (scenario ==
                        rc::Fri3AlgDualCommitmentScenario::
                            SharedMasterDerivedChildren
                    ? "shared"
                    : "duplicated")
            << " q_per_lane=" << rc::kRCFri3AlgDualQueriesPerLane
            << " proof_bytes=" << c.proof_bytes
            << " prove_us=" << prove_us
            << " verify_us_avg=" << (elapsed / REPEATS));
    };

    probe("toy", MakeColumns(), MakeSeed(0x61),
          rc::Fri3AlgDualCommitmentScenario::
              SharedMasterDerivedChildren);
    probe("medium_16x128", MakeMediumColumns(), MakeSeed(0x62),
          rc::Fri3AlgDualCommitmentScenario::
              SharedMasterDerivedChildren);
    probe("production_width_1092x2",
          MakeProductionWidthColumns(), MakeSeed(0x63),
          rc::Fri3AlgDualCommitmentScenario::
              SharedMasterDerivedChildren);
    probe("production_width_1092x2",
          MakeProductionWidthColumns(), MakeSeed(0x65),
          rc::Fri3AlgDualCommitmentScenario::
              FullyDuplicatedLaneCommitments);
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_production_width_cost_probe)
{
    const char* enabled =
        std::getenv("BTX_RC_DUAL_Q128_WIDTH_PROBE");
    if (enabled == nullptr || std::string(enabled) != "1") {
        BOOST_TEST_MESSAGE(
            "dual-Q128 production-width probe skipped "
            "(BTX_RC_DUAL_Q128_WIDTH_PROBE!=1)");
        return;
    }

    // Exact selected parallel normalized-root width.  The two-row coefficient
    // domain isolates width/query cost; this is not a production-depth claim.
    constexpr uint32_t WIDTH = 1092;
    std::vector<std::vector<rc::Fp3>> columns(
        WIDTH, std::vector<rc::Fp3>(2));
    for (uint32_t column = 0; column < WIDTH; ++column) {
        columns[column][0] =
            gf::FromSigned3(3 * column + 1);
        columns[column][1] =
            gf::FromSigned3(5 * column + 2);
    }
    const uint256 seed = MakeSeed(0x69);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto committed =
        rc::Fri3AlgDualBatchCommit(columns, seed, 29);
    const auto prove_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - prove_start)
            .count();
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);

    std::string why;
    constexpr uint32_t REPEATS = 3;
    const auto verify_start = std::chrono::steady_clock::now();
    for (uint32_t repeat = 0; repeat < REPEATS; ++repeat) {
        BOOST_REQUIRE_MESSAGE(
            rc::Fri3AlgDualBatchVerify(
                committed.proof, seed, &why),
            why);
    }
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start)
            .count() /
        REPEATS;
    BOOST_TEST_MESSAGE(
        "FRI3ALG_DUAL_PRODUCTION_WIDTH width=" << WIDTH
        << " n_coeffs=2 n_lde=32"
        << " q_per_lane=" << rc::kRCFri3AlgDualQueriesPerLane
        << " proof_bytes=" << committed.proof_bytes
        << " prove_us=" << prove_us
        << " verify_us_avg=" << verify_us
        << " budget_us=900000"
        << " production_depth_unmeasured=1");
    BOOST_CHECK_LT(verify_us, int64_t{900000});
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_production_depth_cost_probe)
{
    const char* enabled =
        std::getenv("BTX_RC_DUAL_Q128_DEPTH_PROBE");
    if (enabled == nullptr || std::string(enabled) != "1") {
        BOOST_TEST_MESSAGE(
            "dual-Q128 production-depth probe skipped "
            "(BTX_RC_DUAL_Q128_DEPTH_PROBE!=1)");
        return;
    }

    constexpr uint32_t ROWS = 1U << 16;
    std::vector<std::vector<rc::Fp3>> columns(
        1, std::vector<rc::Fp3>(ROWS));
    for (uint32_t row = 0; row < ROWS; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(row & 1U);
    }
    const uint256 seed = MakeSeed(0x6a);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto committed =
        rc::Fri3AlgDualBatchCommit(columns, seed, 31);
    const auto prove_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - prove_start)
            .count();
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);

    std::string why;
    const auto verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgDualBatchVerify(
            committed.proof, seed, &why),
        why);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start)
            .count();
    BOOST_TEST_MESSAGE(
        "FRI3ALG_DUAL_PRODUCTION_DEPTH width=1"
        << " n_coeffs=" << committed.proof.lane[0].n_coeffs
        << " n_lde=" << committed.proof.lane[0].row_commit.n_leaves
        << " folds="
        << committed.proof.lane[0].fold_challenges.size()
        << " q_per_lane=" << rc::kRCFri3AlgDualQueriesPerLane
        << " proof_bytes=" << committed.proof_bytes
        << " prove_us=" << prove_us
        << " verify_us=" << verify_us
        << " budget_us=900000"
        << " production_width_unmeasured=1");
}

BOOST_AUTO_TEST_CASE(fra3_dual_q128_combined_width_depth_cost_probe)
{
    const char* enabled =
        std::getenv("BTX_RC_DUAL_Q128_COMBINED_PROBE");
    if (enabled == nullptr || std::string(enabled) != "1") {
        BOOST_TEST_MESSAGE(
            "dual-Q128 combined width/depth probe skipped "
            "(BTX_RC_DUAL_Q128_COMBINED_PROBE!=1)");
        return;
    }

    // This is a genuine coupled width×depth execution through the selected
    // two-pass shared-master prover.  Width is the production normalized-root
    // width.  Depth is deliberately a resource-bounded 64 coefficients
    // (LDE=1024), not the production 2^16 coefficient domain; the result must
    // never be reported as a production end-to-end benchmark.
    constexpr uint32_t WIDTH = 1092;
    uint32_t coefficients = 64;
    if (const char* requested =
            std::getenv(
                "BTX_RC_DUAL_Q128_COMBINED_COEFFICIENTS")) {
        const unsigned long parsed =
            std::strtoul(requested, nullptr, 10);
        if (parsed >= 2 && parsed <= (1U << 16) &&
            (parsed & (parsed - 1)) == 0) {
            coefficients = static_cast<uint32_t>(parsed);
        }
    }
    std::vector<std::vector<rc::Fp3>> columns(
        WIDTH, std::vector<rc::Fp3>(coefficients));
    for (uint32_t column = 0; column < WIDTH; ++column) {
        for (uint32_t row = 0; row < coefficients; ++row) {
            columns[column][row] = gf::FromSigned3(
                static_cast<int64_t>(
                    17ULL * column + 29ULL * row +
                    ((column ^ row) & 7U)));
        }
    }
    const uint256 seed = MakeSeed(0x6b);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto committed =
        rc::Fri3AlgDualBatchCommitStreamingShared(
            columns, seed, 37);
    const auto prove_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - prove_start)
            .count();
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    BOOST_CHECK(committed.column_lde.empty());

    std::string why;
    const auto verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgDualBatchVerify(
            committed.proof, seed, &why),
        why);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start)
            .count();
    BOOST_TEST_MESSAGE(
        "FRI3ALG_DUAL_COMBINED width=" << WIDTH
        << " n_coeffs=" << coefficients
        << " n_lde="
        << committed.proof.lane[0].row_commit.n_leaves
        << " folds="
        << committed.proof.lane[0].fold_challenges.size()
        << " q_per_lane=" << rc::kRCFri3AlgDualQueriesPerLane
        << " proof_bytes=" << committed.proof_bytes
        << " prove_us=" << prove_us
        << " verify_us=" << verify_us
        << " production_width=1"
        << " production_depth=0");
    BOOST_CHECK_LT(verify_us, int64_t{900000});

    // Cross-axis mutation: a value opened at a deep row under the wide row
    // commitment must be rejected, exercising both dimensions together.
    auto tampered = committed.proof;
    BOOST_REQUIRE(!tampered.lane[0].queries.empty());
    BOOST_REQUIRE(
        !tampered.lane[0].queries[0].row.values.empty());
    tampered.lane[0].queries[0].row.values[WIDTH / 2].c0 =
        gf::Add(
            tampered.lane[0].queries[0].row.values[WIDTH / 2].c0,
            gf::FromU64(1));
    BOOST_CHECK(!rc::Fri3AlgDualBatchVerify(
        tampered, seed, &why));
}

// ============================================================================
// PR-89 Construction 2: enforced per-squeeze grinding tax.
// ============================================================================
BOOST_AUTO_TEST_CASE(pr89_grinding_tax_predicate_enforced)
{
    // Deterministic leading-zero-bit accounting.
    uint256 z; // all zero
    BOOST_CHECK_EQUAL(rc::Fri3AlgLeadingZeroBits(z), 256u);
    uint256 a = z;
    a.data()[0] = 0x01; // 0000_0001 => 7 leading zero bits
    BOOST_CHECK_EQUAL(rc::Fri3AlgLeadingZeroBits(a), 7u);
    uint256 b = z;
    b.data()[0] = 0x80; // 1000_0000 => 0 leading zero bits
    BOOST_CHECK_EQUAL(rc::Fri3AlgLeadingZeroBits(b), 0u);
    uint256 c = z;
    c.data()[1] = 0x40; // byte0 zero (8) + 0100_0000 => 8+1 = 9
    BOOST_CHECK_EQUAL(rc::Fri3AlgLeadingZeroBits(c), 9u);

    std::vector<unsigned char> input = {'p', 'r', '8', '9', 't', 'a', 'x'};
    const uint32_t g = 12; // small, so the prover grind is instant in-test

    // g==0 predicate is vacuously satisfied by any nonce.
    BOOST_CHECK(rc::Fri3AlgCheckSqueezeGrind(input, 0, 0));

    // Prover greps a nonce meeting the g-bit predicate; verifier accepts it.
    auto nonce = rc::Fri3AlgGrindSqueeze(input, g);
    BOOST_REQUIRE(nonce.has_value());
    BOOST_CHECK(rc::Fri3AlgCheckSqueezeGrind(input, *nonce, g));
    BOOST_CHECK(rc::Fri3AlgLeadingZeroBits(
                    rc::Fri3AlgSqueezeGrindDigest(input, *nonce)) >= g);

    // A nonce with < g leading zero bits is REJECTED by the verifier.
    uint64_t failing = 0;
    bool found_failing = false;
    for (uint64_t n = 0; n < 4096; ++n) {
        if (rc::Fri3AlgLeadingZeroBits(
                rc::Fri3AlgSqueezeGrindDigest(input, n)) < g) {
            failing = n;
            found_failing = true;
            break;
        }
    }
    BOOST_REQUIRE(found_failing);
    BOOST_CHECK(!rc::Fri3AlgCheckSqueezeGrind(input, failing, g));
}

// PR-89 Construction 2 DEFECT REGRESSION: the prover grind budget must be
// derived from g, not a flat constant.  The former default was 2^34 while the
// shipped kRCFri3AlgJointQGrindBits is 40, so an honest prover at the ADVERTISED
// g exhausted the range with probability 1 - (1 - 2^-40)^(2^34) = 98.4%.  The
// budget is now 2^(g + kGrindIterationSlackBits).
BOOST_AUTO_TEST_CASE(pr89_grind_budget_is_derived_from_g)
{
    const std::vector<unsigned char> input = {'b', 'u', 'd', 'g', 'e', 't'};

    // The advertised Pi_JQ target must be prover-feasible at all (this is the
    // property the old flat 2^34 default silently violated).
    BOOST_CHECK(rc::kRCFri3AlgJointQGrindBits <=
                rc::kRCFri3AlgMaxGrindableBits);

    // An explicitly SHORT budget must fail: 2^10 trials cannot meet a 20-bit
    // predicate (expected 2^20).  This is exactly the old defect's shape.
    BOOST_CHECK(!rc::Fri3AlgGrindSqueeze(input, 20, /*max_iters=*/uint64_t{1}
                                                    << 10)
                     .has_value());

    // With the auto-derived budget (2^30 at g=20) the same grind succeeds, and
    // the nonce it returns satisfies the verifier predicate.
    auto nonce = rc::Fri3AlgGrindSqueeze(input, 20);
    BOOST_REQUIRE(nonce.has_value());
    BOOST_CHECK(rc::Fri3AlgCheckSqueezeGrind(input, *nonce, 20));

    // Fail-fast on an ungrindable target.  Under the old code this spun for the
    // full flat budget; it must now return immediately.  A wall-clock bound is
    // the only way to observe "did not spin", so keep it generous but finite.
    const auto start = std::chrono::steady_clock::now();
    BOOST_CHECK(!rc::Fri3AlgGrindSqueeze(input, 200).has_value());
    const auto elapsed = std::chrono::steady_clock::now() - start;
    BOOST_CHECK(std::chrono::duration_cast<std::chrono::seconds>(elapsed)
                    .count() < 5);

    // The VERIFIER side is deliberately NOT narrowed by the prover-feasibility
    // bound: it must still evaluate any g <= 256 fail-closed.
    BOOST_CHECK(!rc::Fri3AlgCheckSqueezeGrind(input, 0, 200));
    BOOST_CHECK(!rc::Fri3AlgCheckSqueezeGrind(input, 0, 257));
}

// PR-89 Construction 2, field-native predicate: basic agreement with the
// trailing-zero definition, and the fail-closed edges.
BOOST_AUTO_TEST_CASE(pr89_algebraic_grind_predicate_basics)
{
    namespace gf = rc::gkr_field;
    BOOST_CHECK_EQUAL(rc::Fri3AlgTrailingZeroBitsFp(gf::FromU64(0)), 64u);
    BOOST_CHECK_EQUAL(rc::Fri3AlgTrailingZeroBitsFp(gf::FromU64(1)), 0u);
    BOOST_CHECK_EQUAL(rc::Fri3AlgTrailingZeroBitsFp(gf::FromU64(1u << 20)),
                      20u);
    BOOST_CHECK_EQUAL(rc::Fri3AlgTrailingZeroBitsFp(gf::FromU64(3u << 20)),
                      20u);

    // g == 0 is vacuously true — which is exactly why a taxed path must
    // static_assert its own nonzero floor rather than trust this predicate.
    BOOST_CHECK(rc::Fri3AlgCheckAlgebraicGrind(gf::FromU64(12345), 0));
    // Above the supported range the predicate is fail-CLOSED, never open.
    BOOST_CHECK(!rc::Fri3AlgCheckAlgebraicGrind(
        gf::FromU64(0), rc::kRCFri3AlgMaxAlgebraicGrindBits + 1));

    BOOST_CHECK(rc::Fri3AlgCheckAlgebraicGrind(gf::FromU64(uint64_t{1} << 20),
                                               20));
    BOOST_CHECK(!rc::Fri3AlgCheckAlgebraicGrind(
        gf::FromU64((uint64_t{1} << 20) - 1), 20));
}

// PR-89 Construction 2, THE VACUITY REGRESSION.
//
// This test exists to fail if anyone ever "optimises" the field-native grind
// predicate to the one-constraint multiplicative form  lane0 == 2^g * h.
// Over Fp that form is COMPLETELY VACUOUS because 2^g is a unit: a witness h
// exists for EVERY lane0, so the tax would enforce nothing while looking
// correct.  The first section below DEMONSTRATES that vacuity executably; the
// rest pins the real bit-decomposition + canonicity encoding, which rejects
// both a non-conforming value and the aliased B = x + p witness.
BOOST_AUTO_TEST_CASE(pr89_algebraic_grind_predicate_is_not_vacuous)
{
    namespace gf = rc::gkr_field;
    const uint32_t g = 20;

    // --- (a) the multiplicative form really is vacuous: pick a lane that does
    // NOT satisfy the tax and exhibit its witness h with 2^g * h == lane0.
    const gf::Fp bad_lane = gf::FromU64((uint64_t{1} << 20) - 1);
    BOOST_REQUIRE(!rc::Fri3AlgCheckAlgebraicGrind(bad_lane, g));
    const gf::Fp two_pow_g = gf::FromU64(uint64_t{1} << g);
    const gf::Fp h = gf::Mul(bad_lane, gf::Inv(two_pow_g));
    BOOST_CHECK(gf::Canonical(gf::Mul(two_pow_g, h)) ==
                gf::Canonical(bad_lane));
    // ^ If the predicate were encoded multiplicatively, THAT would satisfy it.

    // --- (b) the real encoding accepts a conforming value...
    const gf::Fp good_lane = gf::FromU64(uint64_t{7} << 20);
    BOOST_REQUIRE(rc::Fri3AlgCheckAlgebraicGrind(good_lane, g));
    const auto good = rc::BuildFri3AlgGrindPredicateAirV1(good_lane, g);
    BOOST_REQUIRE_MESSAGE(good.valid, good.note);
    BOOST_CHECK(good.booleanity_constrained);
    BOOST_CHECK(good.canonicity_constrained);
    BOOST_CHECK(good.tax_constrained);
    BOOST_CHECK_EQUAL(good.violations, 0u);

    // --- (c) ...and REJECTS the non-conforming value. This is the assertion
    // that the multiplicative form would break: there, violations would be 0.
    const auto bad = rc::BuildFri3AlgGrindPredicateAirV1(bad_lane, g);
    BOOST_REQUIRE_MESSAGE(bad.valid, bad.note);
    BOOST_CHECK_GT(bad.violations, 0u);

    // --- (d) canonicity is load-bearing, not decoration.  p = 1 (mod 2^20),
    // so x = 2^20 - 1 fails the tax while B = x + p has its low 20 bits ZERO
    // and is representable in 64 bits.  A prover supplying that aliased
    // decomposition satisfies every tax constraint; ONLY the canonicity
    // constraint stops it.
    const auto aliased = rc::BuildFri3AlgGrindPredicateAirV1(
        bad_lane, g, /*use_aliased_witness=*/true);
    BOOST_REQUIRE_MESSAGE(aliased.valid, aliased.note);
    BOOST_CHECK_GT(aliased.violations, 0u);

    // The shape itself, so a regression in column/constraint count is visible.
    BOOST_CHECK_EQUAL(good.n_rows, 2u);
    BOOST_CHECK_EQUAL(good.bit_columns, 64u);
    BOOST_CHECK_EQUAL(good.n_columns, 71u);
    BOOST_CHECK_EQUAL(good.n_constraints, 72u + g);
    BOOST_CHECK_EQUAL(good.max_alg_degree, 7u);
}

// PR-89 Construction 2, ALGEBRAIC taxed deciding squeeze (not activated).
// Covers the tax round-trip, domain separation, the sole-entropy-source
// property the credit depends on, and the u64-absorption injectivity trap.
BOOST_AUTO_TEST_CASE(pr89_algebraic_taxed_squeeze)
{
    namespace gf = rc::gkr_field;
    // The SHIPPED tax is g = 20, but a real g=20 Poseidon2 grind costs ~69 s
    // MEASURED (Permute is 30.7 us on this build, not the 0.3-1.0 us the
    // finish-plan microbenchmark reports). Grind at a small g in-test and
    // assert the shipped constant separately.
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgTaxedQGrindBits, 20u);
    const uint32_t g = 12; // fast in-test grind

    std::vector<gf::Fp> sigma_core;
    for (uint64_t i = 0; i < 12; ++i) sigma_core.push_back(gf::FromU64(i * 7 + 1));

    // --- deterministic, and domain-separated from the plain transcript hash.
    BOOST_CHECK(rc::Fri3AlgAlgebraicSqueeze(sigma_core, 5) ==
                rc::Fri3AlgAlgebraicSqueeze(sigma_core, 5));
    BOOST_CHECK(rc::Fri3AlgAlgebraicSqueeze(sigma_core, 5) !=
                rc::Fri3AlgAlgebraicTranscriptDigest(sigma_core, 0));

    // --- the honest prover meets the tax, and the verifier accepts it.
    const auto t0 = std::chrono::steady_clock::now();
    auto nonce = rc::Fri3AlgGrindAlgebraicSqueeze(sigma_core, g);
    const auto grind_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
    BOOST_REQUIRE(nonce.has_value());
    BOOST_TEST_MESSAGE("algebraic g=" << g << " grind took " << grind_ms
                                      << " ms");
    BOOST_CHECK(rc::Fri3AlgCheckAlgebraicSqueezeGrind(sigma_core, *nonce, g));

    // --- a nonce that does not meet the tax is REJECTED. Search a small range
    // for a concrete failing nonce; at g=20 essentially all of them fail.
    bool found_reject = false;
    for (uint64_t n = 0; n < 64 && !found_reject; ++n) {
        if (n == *nonce) continue;
        if (!rc::Fri3AlgCheckAlgebraicSqueezeGrind(sigma_core, n, g)) {
            found_reject = true;
        }
    }
    BOOST_CHECK(found_reject);

    // --- SOLE ENTROPY SOURCE. Every index is a function of sigma alone, so a
    // counterfactual sigma (what a regrind would produce) moves them. If this
    // failed, an adversary would pay the tax once and retarget for free.
    const uint32_t n_lde = 1u << 12;
    const auto sigma = rc::Fri3AlgAlgebraicSqueeze(sigma_core, *nonce);
    const auto sigma_prime = rc::Fri3AlgAlgebraicSqueeze(sigma_core, *nonce + 1);
    bool any_index_moved = false;
    for (uint32_t j = 0; j < 88; ++j) {
        const uint32_t idx = rc::Fri3AlgAlgebraicQueryIndex(sigma, j, n_lde);
        BOOST_REQUIRE_LT(idx, n_lde);
        // Deterministic in sigma: same inputs, same index, every time.
        BOOST_CHECK_EQUAL(idx,
                          rc::Fri3AlgAlgebraicQueryIndex(sigma, j, n_lde));
        if (rc::Fri3AlgAlgebraicQueryIndex(sigma_prime, j, n_lde) != idx) {
            any_index_moved = true;
        }
    }
    BOOST_CHECK(any_index_moved);

    // --- non-power-of-two moduli are refused rather than silently biased.
    BOOST_CHECK_EQUAL(rc::Fri3AlgAlgebraicQueryIndex(sigma, 0, 1000u), 0u);

    // --- INJECTIVITY TRAP: a uint64 must be absorbed as two 32-bit lanes.
    // Absorbing it as a single FromU64 lane is LOSSY (reduction mod p), so
    // nonces differing only above the reduction boundary would collide and the
    // tax could be replayed. These two differ by exactly p.
    const uint64_t a = 12345;
    const uint64_t b = a + gf::kP; // same residue mod p, different u64
    BOOST_CHECK(rc::Fri3AlgAlgebraicSqueeze(sigma_core, a) !=
                rc::Fri3AlgAlgebraicSqueeze(sigma_core, b));

    // --- the shipped tax is nonzero and prover-feasible (the g==0 trap).
    BOOST_CHECK(rc::kRCFri3AlgTaxedQGrindBits > 0u);
    BOOST_CHECK(!rc::Fri3AlgCheckAlgebraicSqueezeGrind(
        sigma_core, *nonce, rc::kRCFri3AlgMaxAlgebraicGrindBits + 1));
}

// ============================================================================
// PR-89 Construction 1: Pi_JQ joint query squeeze.
// ============================================================================
BOOST_AUTO_TEST_CASE(pr89_jointq_honest_verify_and_regrind_rejected)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x5a);
    const uint32_t g = 10; // fast in-test grind; ledger accounting uses g=40

    auto committed =
        rc::Fri3AlgJointQBatchCommit(columns, seed, /*pow_grind_nonce=*/17, g);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);

    // Honest dual proof verifies under the joint squeeze + enforced tax.
    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgJointQBatchVerify(committed.proof,
                                     committed.joint_query_grind_nonce, seed, g,
                                     &why),
        why);

    // Every lane's query indices ARE the joint-squeeze indices, for BOTH lanes.
    const uint32_t n_lde =
        committed.proof.lane[0].n_coeffs * committed.proof.lane[0].blowup;
    for (uint32_t lane = 0; lane < 2; ++lane) {
        const auto& qs = committed.proof.lane[lane].queries;
        for (uint32_t j = 0; j < qs.size(); ++j) {
            BOOST_CHECK_EQUAL(
                qs[j].index,
                rc::Fri3AlgJointQIndex(committed.joint_query_sigma, lane, j,
                                       n_lde));
        }
    }

    // Anti-regrind coupling: a counterfactual sigma_Q' (as if lane 1's terminal
    // transcript T_1 had been reground) changes lane-0's query indices. Under
    // the OLD per-lane squeeze lane-0 indices are drawn from lane 0's own
    // transcript and are invariant to T_1; the joint squeeze binds them.
    uint256 sigma_prime = committed.joint_query_sigma;
    sigma_prime.data()[0] ^= 0xff;
    bool lane0_index_changed = false;
    for (uint32_t j = 0; j < committed.proof.lane[0].queries.size(); ++j) {
        if (rc::Fri3AlgJointQIndex(sigma_prime, 0, j, n_lde) !=
            rc::Fri3AlgJointQIndex(committed.joint_query_sigma, 0, j, n_lde)) {
            lane0_index_changed = true;
            break;
        }
    }
    BOOST_CHECK(lane0_index_changed);

    // A proof whose queries follow the OLD per-lane squeeze (plain Q136) is
    // REJECTED by the joint verifier: its lane indices are not the joint ones.
    auto q136 = rc::Fri3AlgDualQ136BatchCommit(columns, seed, /*nonce=*/17);
    BOOST_REQUIRE(q136.ok);
    std::string why_old;
    BOOST_CHECK(!rc::Fri3AlgJointQBatchVerify(
        q136.proof, committed.joint_query_grind_nonce, seed, g, &why_old));

    // A wrong tax nonce yields a different sigma_Q (and generally fails the
    // enforced g-bit predicate) => rejected.
    std::string why_bad;
    BOOST_CHECK(!rc::Fri3AlgJointQBatchVerify(
        committed.proof, committed.joint_query_grind_nonce ^ 0x9e3779b9u, seed,
        g, &why_bad));
}

// PR-89 re-refutation (residual A.2): the enforced per-squeeze grinding tax must
// be genuinely wired into the VERIFY path, not only a standalone predicate. A
// proof whose nonce fails the g-leading-zero predicate MUST be rejected BY
// Fri3AlgJointQBatchVerify, with the tax-specific reason (isolating it from the
// index/binding mismatch that a wrong nonce also triggers later).
BOOST_AUTO_TEST_CASE(pr89_jointq_verify_rejects_subg_tax_nonce)
{
    const auto columns = MakeColumns();
    const uint256 seed = MakeSeed(0x77);
    const uint32_t g = 10; // fast in-test grind; ledger accounting uses g=40

    auto committed =
        rc::Fri3AlgJointQBatchCommit(columns, seed, /*pow_grind_nonce=*/17, g);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);

    // Honest nonce verifies (the tax gate is satisfied).
    std::string ok_why;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgJointQBatchVerify(committed.proof,
                                     committed.joint_query_grind_nonce, seed, g,
                                     &ok_why),
        ok_why);

    // (1) Same honest proof, but demand an impossibly high tax g' the committed
    // nonce cannot satisfy. Every other obligation still passes, so the ONLY
    // failing check is the enforced g-leading-zero predicate: the verifier is
    // the rejecter, with the tax-specific reason.
    std::string why_hi;
    BOOST_CHECK(!rc::Fri3AlgJointQBatchVerify(
        committed.proof, committed.joint_query_grind_nonce, seed,
        /*grind_bits=*/250, &why_hi));
    BOOST_CHECK_EQUAL(why_hi, "jointq enforced grinding tax not satisfied");

    // (2) A concrete sub-g nonce is caught at the tax gate (which runs before any
    // index/binding check). Random nonces almost never clear g=10 leading zeros,
    // so a search over a tiny range deterministically exhibits a tax rejection.
    bool found_subg_reject = false;
    for (uint64_t n = 0; n < 64 && !found_subg_reject; ++n) {
        if (n == committed.joint_query_grind_nonce) continue;
        std::string w;
        if (!rc::Fri3AlgJointQBatchVerify(committed.proof, n, seed, g, &w) &&
            w == "jointq enforced grinding tax not satisfied") {
            found_subg_reject = true;
        }
    }
    BOOST_CHECK(found_subg_reject);

    // (3) Ledger honesty: the single-lane Q192 path does NOT check this predicate,
    // so it earns NO +g credit — its bound is the proximity term minus the
    // unenforced-regrind deduction, distinct from the taxed +g the dual floor books.
    BOOST_CHECK(!rc::kRCFri3AlgSingleLaneEnforcesSqueezeGrind);
    BOOST_CHECK_EQUAL(rc::Fri3AlgEnforcedSqueezeGrindCreditBits(false, 40), 0);
    BOOST_CHECK_EQUAL(rc::Fri3AlgEnforcedSqueezeGrindCreditBits(true, 40), 40);
    BOOST_CHECK_EQUAL(rc::Fri3AlgProximityBoundBits(), 175);
    BOOST_CHECK_EQUAL(rc::Fri3AlgSoundnessBoundBits(),
                      rc::Fri3AlgProximityBoundBits() -
                          static_cast<int>(rc::kRCFri3AlgUnenforcedRegrindBudgetBits));
}

// PR-89 rung-5 cap-fix correctness proof. The column-at-a-time STREAMING
// row-Merkle commit must produce a BIT-IDENTICAL root to the all-columns-
// resident reference (dense) commit on the SAME data. The equivalence is
// W-AGNOSTIC: both paths take the same per-column LDE, hash each row with the
// same LeafHashRow primitive, and build the same Merkle tree in the same order;
// streaming only changes the memory SCHEDULE (one column resident at a time).
// Proving it at modest width therefore extends to the 384k-712k-column real
// recursion-node width, where the dense path is memory-infeasible (~303 GB at
// W=385k, n_lde=32768) and only the streaming path can run.
BOOST_AUTO_TEST_CASE(fra3_streaming_row_root_bit_identical_to_dense)
{
    for (uint32_t n_coeffs : {uint32_t{4}, uint32_t{16}, uint32_t{64}}) {
        std::vector<std::vector<rc::Fp3>> cols(777);
        for (size_t c = 0; c < cols.size(); ++c) {
            const size_t len = 1 + (c % static_cast<size_t>(n_coeffs));
            cols[c].resize(len);
            for (size_t j = 0; j < len; ++j) {
                cols[c][j] = gf::FromSigned3(
                    static_cast<int64_t>(11 * c + 5 * j + 2));
            }
        }
        const rc::Fri3AlgDigest dense =
            rc::Fri3AlgBatchRowRoot(cols, n_coeffs);
        const rc::Fri3AlgDigest stream =
            rc::Fri3AlgBatchRowRootStreaming(cols, n_coeffs);
        const uint256 dense_u = rc::Fri3AlgDigestToUint256(dense);
        const uint256 stream_u = rc::Fri3AlgDigestToUint256(stream);
        BOOST_REQUIRE_MESSAGE(
            !dense_u.IsNull(),
            "dense row root null at n_coeffs=" + std::to_string(n_coeffs));
        BOOST_CHECK_MESSAGE(
            dense_u == stream_u,
            "streaming row root must be bit-identical to dense at n_coeffs=" +
                std::to_string(n_coeffs) + " dense=" + dense_u.GetHex() +
                " stream=" + stream_u.GetHex());
    }
}

// PR-89 rung-5 wide-commit BASELINE (single-thread). Env-gated
// (BTX_TIME_WIDE_COMMIT=1) so it is a no-op in the normal suite. Commit cost is
// a function of SHAPE only (per-column LDE + row hashing), not witness values,
// so this synthetic set at the MEASURED real recursion-node shape
// (W=384984, n_coeffs=256 => n_lde=4096) reproduces the real internal-node
// streaming-commit wall-clock without the ~60-min parent-witness build.
BOOST_AUTO_TEST_CASE(fra3_wide_commit_realwidth_timing)
{
    if (std::getenv("BTX_TIME_WIDE_COMMIT") == nullptr) {
        BOOST_TEST_MESSAGE("skipped (set BTX_TIME_WIDE_COMMIT=1 to measure)");
        return;
    }
    const uint32_t W = 384984;
    const uint32_t n_coeffs = 256;  // measured parent_rows; n_lde = 256*16 = 4096
    std::vector<std::vector<rc::Fp3>> cols(W);
    for (uint32_t c = 0; c < W; ++c) {
        cols[c].resize(n_coeffs);
        for (uint32_t j = 0; j < n_coeffs; ++j) {
            cols[c][j] = gf::FromSigned3(
                static_cast<int64_t>(1315423911u * c + 2654435761u * j + 7u));
        }
    }
    const auto t0 = std::chrono::steady_clock::now();
    const rc::Fri3AlgDigest d = rc::Fri3AlgBatchRowRootStreaming(cols, n_coeffs);
    const auto t1 = std::chrono::steady_clock::now();
    const double ms =
        std::chrono::duration<double, std::milli>(t1 - t0).count();
    const uint256 root = rc::Fri3AlgDigestToUint256(d);
    BOOST_TEST_MESSAGE("WIDE_COMMIT_TIMING W=" << W << " n_coeffs=" << n_coeffs
                       << " n_lde=" << (n_coeffs * 16u)
                       << " streaming_commit_ms=" << ms
                       << " root=" << root.GetHex()
                       << " null=" << static_cast<int>(root.IsNull()));
    BOOST_CHECK(!root.IsNull());
}

// ===========================================================================
// PR-89 g4, TRANSCRIPT HALF (NOT ACTIVATED). The short-transcript lane
// absorbs domain-tagged Poseidon2 COMMITMENTS in place of the two
// W-proportional transcript bodies (the column_len loop and both full OOD
// evaluation vectors), so every Fiat-Shamir preimage becomes short and
// self-contained. These tests are the non-vacuity evidence for that claim.
// ===========================================================================

namespace {

std::vector<std::vector<rc::Fp3>> MakeShortFsColumns(uint32_t width,
                                                     uint32_t length)
{
    std::vector<std::vector<rc::Fp3>> columns(width);
    for (uint32_t c = 0; c < width; ++c) {
        columns[c].resize(length);
        for (uint32_t k = 0; k < length; ++k) {
            columns[c][k] = rc::Fp3{gf::FromU64(1 + 7ull * c + 11ull * k),
                                    gf::FromU64(3 + 5ull * c + 2ull * k),
                                    gf::FromU64(9 + 13ull * c + 17ull * k)};
        }
    }
    return columns;
}

/** First-occurrence prefix length of one challenge kind on one route. */
uint64_t PrefixFor(
    const std::vector<rc::Fri3AlgTranscriptChallengeCostV1>& first,
    const std::string& label)
{
    for (const auto& e : first) {
        if (e.label == label) return e.prefix_bytes;
    }
    return 0;
}

} // namespace

BOOST_AUTO_TEST_CASE(pr89_short_fs_lane_round_trip_and_version_separation)
{
    const uint256 seed = MakeSeed(0x5a);
    const auto columns = MakeShortFsColumns(6, 8);

    rc::Fri3AlgBatchCommitResult shortfs =
        rc::Fri3AlgShortFsBatchCommit(columns, seed, 0);
    BOOST_REQUIRE_MESSAGE(shortfs.ok, shortfs.note);
    BOOST_CHECK_EQUAL(shortfs.proof.version,
                      rc::kRCFri3AlgShortFsLaneProofVersion);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgShortFsLaneProofVersion, 7u);

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgShortFsBatchVerify(shortfs.proof, seed, &why), why);

    // The V3 lane is UNTOUCHED and still round-trips.  After ACTIVATION it is
    // no longer what Fri3AlgBatchCommit produces, so the A/B reaches it
    // through the explicit legacy entry point rather than silently losing its
    // producer.
    rc::Fri3AlgBatchCommitResult legacy =
        rc::Fri3AlgLegacyV3BatchCommit(columns, seed, 0);
    BOOST_REQUIRE_MESSAGE(legacy.ok, legacy.note);
    BOOST_CHECK_EQUAL(legacy.proof.version, rc::kRCFri3AlgBatchProofVersion);
    BOOST_CHECK(rc::Fri3AlgLegacyV3BatchVerify(legacy.proof, seed, &why));

    // Neither verifier accepts the other lane's proof: the version check fires
    // before any FS work, so the two layouts can never be confused.
    BOOST_CHECK(!rc::Fri3AlgLegacyV3BatchVerify(shortfs.proof, seed, &why));
    BOOST_CHECK(!rc::Fri3AlgShortFsBatchVerify(legacy.proof, seed, &why));

    // ACTIVATION, asserted rather than assumed: the DEFAULT Q192 producer and
    // verifier are now the P2-squeeze lane (short-FS absorbs + Poseidon2
    // squeezes).  Short-FS remains a named lane for A/B; ActiveConfig selects v8.
    BOOST_CHECK(rc::kRCFri3AlgShortFsActivatedV1);
    BOOST_CHECK(rc::kRCFri3AlgP2SqueezeActivatedV1);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgActiveBatchProofVersion,
                      rc::kRCFri3AlgP2SqueezeLaneProofVersion);
    rc::Fri3AlgBatchCommitResult active =
        rc::Fri3AlgBatchCommit(columns, seed, 0);
    BOOST_REQUIRE_MESSAGE(active.ok, active.note);
    BOOST_CHECK_EQUAL(active.proof.version,
                      rc::kRCFri3AlgP2SqueezeLaneProofVersion);
    BOOST_CHECK(rc::Fri3AlgBatchVerify(active.proof, seed, &why));
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(legacy.proof, seed, &why));
    BOOST_CHECK(!rc::Fri3AlgBatchVerify(shortfs.proof, seed, &why));

    // The two lanes agree on the STATEMENT and disagree only on the
    // transcript: same shape, same column lengths, different challenges.
    BOOST_CHECK_EQUAL(shortfs.proof.n_coeffs, legacy.proof.n_coeffs);
    BOOST_CHECK(shortfs.proof.column_len == legacy.proof.column_len);
    BOOST_CHECK(shortfs.proof.row_commit.root == legacy.proof.row_commit.root);
    BOOST_CHECK(!gf::Eq(shortfs.proof.lambda, legacy.proof.lambda));

    // The commitments are not constants: they move with their inputs.
    const rc::Fri3AlgDigest shape =
        rc::Fri3AlgShapeCommit(shortfs.proof.n_coeffs,
                               shortfs.proof.column_len);
    std::vector<uint32_t> moved = shortfs.proof.column_len;
    moved[0] = moved[0] == 1 ? 2 : moved[0] - 1;
    BOOST_CHECK(shape !=
                rc::Fri3AlgShapeCommit(shortfs.proof.n_coeffs, moved));
    BOOST_CHECK(shape !=
                rc::Fri3AlgShapeCommit(shortfs.proof.n_coeffs * 2,
                                       shortfs.proof.column_len));
}

BOOST_AUTO_TEST_CASE(pr89_p2_squeeze_lane_round_trip_and_version_separation)
{
    // Recommendation #1: short-FS absorbs + Poseidon2 squeezes as proof
    // version 8 — jointly activated with aq::kAirChallengeP2Activated.
    const uint256 seed = MakeSeed(0x5b);
    const auto columns = MakeShortFsColumns(4, 8);

    rc::Fri3AlgBatchCommitResult p2 =
        rc::Fri3AlgP2SqueezeBatchCommit(columns, seed, 0);
    BOOST_REQUIRE_MESSAGE(p2.ok, p2.note);
    BOOST_CHECK_EQUAL(p2.proof.version, rc::kRCFri3AlgP2SqueezeLaneProofVersion);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgP2SqueezeLaneProofVersion, 8u);
    BOOST_CHECK(rc::kRCFri3AlgP2SqueezeActivatedV1);
    BOOST_CHECK(rc::kRCFri3AlgActiveP2Squeeze);
    // ActiveConfig now selects the P2-squeeze lane.
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgActiveBatchProofVersion,
                      rc::kRCFri3AlgP2SqueezeLaneProofVersion);

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgP2SqueezeBatchVerify(p2.proof, seed, &why), why);

    // Cross-lane rejection: short-FS (v7) and P2-squeeze (v8) do not mix.
    rc::Fri3AlgBatchCommitResult shortfs =
        rc::Fri3AlgShortFsBatchCommit(columns, seed, 0);
    BOOST_REQUIRE(shortfs.ok);
    BOOST_CHECK(!rc::Fri3AlgP2SqueezeBatchVerify(shortfs.proof, seed, &why));
    BOOST_CHECK(!rc::Fri3AlgShortFsBatchVerify(p2.proof, seed, &why));

    // Same statement shape; challenges differ (SHA vs Poseidon2 squeeze).
    BOOST_CHECK_EQUAL(p2.proof.n_coeffs, shortfs.proof.n_coeffs);
    BOOST_CHECK(!gf::Eq(p2.proof.lambda, shortfs.proof.lambda));

    // Deterministic squeeze helper.
    std::vector<unsigned char> buf{1, 2, 3, 4, 5};
    const rc::Fp3 a =
        rc::Fri3AlgP2SqueezeChallengeFp3(buf, "fra3_lambda", 0);
    BOOST_CHECK(gf::Eq(a, rc::Fri3AlgP2SqueezeChallengeFp3(buf, "fra3_lambda", 0)));
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgP2SqueezeChallengeFp3(buf, "fra3_w", 0)));
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgP2SqueezeChallengeFp3(buf, "fra3_lambda", 1)));
}

// MEASURED, on the production transcript: the two W-proportional terms are
// gone, and the slope of the LEGACY route is exactly the documented 52*W.
BOOST_AUTO_TEST_CASE(pr89_short_fs_transcript_preimages_are_width_independent)
{
    constexpr uint32_t kNarrow = 8;
    constexpr uint32_t kWide = 64;
    const rc::Fri3AlgTranscriptReplayCostV1 narrow =
        rc::MeasureFri3AlgTranscriptReplayCostV1(kNarrow, 16);
    const rc::Fri3AlgTranscriptReplayCostV1 wide =
        rc::MeasureFri3AlgTranscriptReplayCostV1(kWide, 16);
    BOOST_REQUIRE_MESSAGE(narrow.valid, narrow.note);
    BOOST_REQUIRE_MESSAGE(wide.valid, wide.note);
    BOOST_REQUIRE_EQUAL(narrow.n_coeffs, wide.n_coeffs);

    // NON-VACUITY, asserted BEFORE any conclusion is read: the legacy route
    // must genuinely be width-proportional in this harness, or the comparison
    // below proves nothing.
    BOOST_REQUIRE_GT(PrefixFor(wide.legacy, "fra3_w"),
                     PrefixFor(narrow.legacy, "fra3_w"));

    const uint64_t dw = kWide - kNarrow;
    // Term (i) alone, at the FIRST challenge of all: 4 bytes per column.
    BOOST_CHECK_EQUAL(PrefixFor(wide.legacy, "fra3_lambda") -
                          PrefixFor(narrow.legacy, "fra3_lambda"),
                      4 * dw);
    // Terms (i) + (ii) together, from the DEEP weights onward: 52 bytes.
    for (const char* label : {"fra3_w", "fra3_fold", "fra3_query"}) {
        BOOST_CHECK_EQUAL(PrefixFor(wide.legacy, label) -
                              PrefixFor(narrow.legacy, label),
                          52 * dw);
    }
    // SHORT route: every challenge kind has a preimage of IDENTICAL length at
    // both widths. This is the whole claim.
    for (const char* label :
         {"fra3_lambda", "fra3_z", "fra3_w", "fra3_fold", "fra3_query"}) {
        BOOST_CHECK_EQUAL(PrefixFor(wide.short_fs, label),
                          PrefixFor(narrow.short_fs, label));
        BOOST_CHECK_GT(PrefixFor(wide.short_fs, label), 0u);
    }
    BOOST_CHECK(wide.short_fs_width_independent);
    BOOST_CHECK_LT(wide.short_fs_total_rows, wide.legacy_total_rows);

    for (const auto& e : wide.legacy) {
        BOOST_TEST_MESSAGE("SHORTFS_COST W=" << kWide << " route=legacy kind="
                           << e.label << " prefix_bytes=" << e.prefix_bytes
                           << " comps=" << e.compressions
                           << " rows=" << e.rows);
    }
    for (const auto& e : wide.short_fs) {
        BOOST_TEST_MESSAGE("SHORTFS_COST W=" << kWide << " route=short kind="
                           << e.label << " prefix_bytes=" << e.prefix_bytes
                           << " comps=" << e.compressions
                           << " rows=" << e.rows);
    }
    BOOST_TEST_MESSAGE("SHORTFS_COST_TOTAL W=" << kWide
                       << " legacy_total_rows=" << wide.legacy_total_rows
                       << " short_total_rows=" << wide.short_fs_total_rows
                       << " legacy_max_rows=" << wide.legacy_max_rows
                       << " short_max_rows=" << wide.short_fs_max_rows);

    // COMPUTED (not measured) extrapolation to the real child width, using the
    // slope just MEASURED above. The layout is exactly affine in W, which the
    // two exact delta checks above establish.
    const uint64_t kRealW = 384984;
    const uint64_t base = PrefixFor(wide.legacy, "fra3_query");
    const uint64_t real_bytes = base + 52 * (kRealW - kWide);
    uint64_t comps = (real_bytes + 9 + 63) / 64 + 1;
    uint64_t pow2 = 1;
    while (pow2 < comps) pow2 <<= 1;
    BOOST_TEST_MESSAGE("SHORTFS_COST_EXTRAPOLATED W=" << kRealW
                       << " legacy_prefix_bytes=" << real_bytes
                       << " legacy_comps=" << comps
                       << " legacy_rows=" << (pow2 * 1024)
                       << " short_prefix_bytes="
                       << PrefixFor(wide.short_fs, "fra3_query")
                       << " short_rows=" << wide.short_fs_max_rows);
    // Cross-check against the figure recorded in recursive_parent_air.h and
    // reproduced by fs_selection_air's SHA cost model.
    BOOST_CHECK_EQUAL(pow2 * 1024, 536870912ull);

    // The SHORT route's remaining length is dominated by the fold roots, which
    // scale with log2(n_coeffs) and NOT with W. Measure at the real parent
    // child shape's n_coeffs = 256 (MEASURED parent_rows, see the real-width
    // self-prove) so the reported per-kind figure needs no extrapolation on
    // that axis either. Width is small here BECAUSE the short route is
    // width-independent -- established above, not assumed.
    const rc::Fri3AlgTranscriptReplayCostV1 deep =
        rc::MeasureFri3AlgTranscriptReplayCostV1(8, 256);
    BOOST_REQUIRE_MESSAGE(deep.valid, deep.note);
    BOOST_CHECK_EQUAL(deep.n_coeffs, 256u);
    for (const auto& e : deep.short_fs) {
        BOOST_TEST_MESSAGE("SHORTFS_COST_REALSHAPE n_coeffs=256 route=short kind="
                           << e.label << " prefix_bytes=" << e.prefix_bytes
                           << " comps=" << e.compressions
                           << " rows=" << e.rows);
    }
    BOOST_TEST_MESSAGE("SHORTFS_COST_REALSHAPE n_coeffs=256"
                       << " short_total_rows=" << deep.short_fs_total_rows
                       << " short_max_rows=" << deep.short_fs_max_rows
                       << " challenges_drawn="
                       << (deep.short_fs_total_rows == 0 ? 0 : 1));
    // Deeper folding lengthens the SHORT transcript (more roots) but leaves it
    // W-independent; assert the direction so a regression that reintroduced a
    // W term would not hide behind this figure.
    BOOST_CHECK_GT(PrefixFor(deep.short_fs, "fra3_query"),
                   PrefixFor(wide.short_fs, "fra3_query"));
}

// The soundness claim, made non-vacuous.
BOOST_AUTO_TEST_CASE(pr89_short_fs_commitment_binds_what_verbatim_absorption_bound)
{
    const uint256 seed = MakeSeed(0x21);
    const auto columns = MakeShortFsColumns(6, 8);
    rc::Fri3AlgBatchCommitResult r =
        rc::Fri3AlgShortFsBatchCommit(columns, seed, 0);
    BOOST_REQUIRE_MESSAGE(r.ok, r.note);
    std::string why;
    BOOST_REQUIRE(rc::Fri3AlgShortFsBatchVerify(r.proof, seed, &why));

    // (a) One altered OOD claim cell is REJECTED. Under verbatim absorption
    //     this was caught because the byte changed; here it is caught because
    //     the commitment changed, hence w1/w2 moved.
    {
        rc::Fri3AlgBatchProof tampered = r.proof;
        tampered.evals_z1[2] =
            gf::Add(tampered.evals_z1[2], rc::Fp3::One());
        BOOST_CHECK(!rc::Fri3AlgShortFsBatchVerify(tampered, seed, &why));
        BOOST_CHECK_EQUAL(why, "deep weights mismatch");
    }
    {
        rc::Fri3AlgBatchProof tampered = r.proof;
        tampered.evals_z2.back() =
            gf::Add(tampered.evals_z2.back(), rc::Fp3::One());
        BOOST_CHECK(!rc::Fri3AlgShortFsBatchVerify(tampered, seed, &why));
    }

    // (b) THE POINT OF THE WHOLE DESIGN. The order-audit kernel produces a
    //     forged claim vector that leaves BOTH batched values v1,v2 fixed. Had
    //     the transcript absorbed v1,v2 instead of a commitment, that forgery
    //     would be transcript-invisible. It is not invisible to the
    //     commitment: the digest moves.
    {
        const uint32_t W =
            static_cast<uint32_t>(r.proof.column_len.size());
        std::vector<rc::Fp3> alpha(W);
        alpha[0] = rc::Fp3::One();
        for (uint32_t i = 1; i < W; ++i) {
            alpha[i] = gf::Mul(alpha[i - 1], r.proof.lambda);
        }
        const auto audit = rc::AuditFri3AlgAdaptiveEvaluationOrder(
            alpha, r.proof.column_len, r.proof.n_coeffs, r.proof.z1,
            r.proof.z2, r.proof.evals_z1, r.proof.evals_z2);
        // NON-VACUITY: the kernel must actually have been exhibited.
        BOOST_REQUIRE_MESSAGE(audit.self_consistent_legacy_kernel_exhibited,
                              audit.note);
        BOOST_REQUIRE(audit.z1_batched_value_unchanged);
        BOOST_REQUIRE(audit.z2_batched_value_unchanged);

        const rc::Fri3AlgDigest honest = rc::Fri3AlgOodEvalCommit(
            r.proof.z1, r.proof.z2, r.proof.evals_z1, r.proof.evals_z2);
        const rc::Fri3AlgDigest forged = rc::Fri3AlgOodEvalCommit(
            r.proof.z1, r.proof.z2, audit.forged_evals_z1,
            audit.forged_evals_z2);
        BOOST_CHECK(honest != forged);

        // And the forged vector is rejected end to end.
        rc::Fri3AlgBatchProof tampered = r.proof;
        tampered.evals_z1 = audit.forged_evals_z1;
        tampered.evals_z2 = audit.forged_evals_z2;
        BOOST_CHECK(!rc::Fri3AlgShortFsBatchVerify(tampered, seed, &why));
    }

    // (c) The shape commitment is equally live: a column_len edit is rejected
    //     at the FIRST challenge, not merely downstream.
    {
        rc::Fri3AlgBatchProof tampered = r.proof;
        BOOST_REQUIRE_GT(tampered.column_len[0], 1u);
        tampered.column_len[0] -= 1;
        BOOST_CHECK(!rc::Fri3AlgShortFsBatchVerify(tampered, seed, &why));
    }

    // (d) The commitment binds the OOD POINTS to the claims, not just the
    //     claims: reusing a claim vector under a different z is a different
    //     digest.
    {
        const rc::Fri3AlgDigest a = rc::Fri3AlgOodEvalCommit(
            r.proof.z1, r.proof.z2, r.proof.evals_z1, r.proof.evals_z2);
        const rc::Fri3AlgDigest b = rc::Fri3AlgOodEvalCommit(
            r.proof.z2, r.proof.z1, r.proof.evals_z1, r.proof.evals_z2);
        BOOST_CHECK(a != b);
    }
}

// Item 3: the algebraic Fp3 draw fri_ext3_alg.h did not export.
BOOST_AUTO_TEST_CASE(pr89_algebraic_fp3_draw_exists_and_needs_no_rejection)
{
    std::vector<gf::Fp> core;
    for (uint64_t i = 0; i < 20; ++i) core.push_back(gf::FromU64(i * 31 + 5));

    const rc::Fp3 a = rc::Fri3AlgAlgebraicChallengeFp3(
        core, rc::Fri3AlgAlgebraicDrawKind::Lambda, 0);
    // Deterministic.
    BOOST_CHECK(gf::Eq(a, rc::Fri3AlgAlgebraicChallengeFp3(
                              core, rc::Fri3AlgAlgebraicDrawKind::Lambda, 0)));
    // Separated by KIND at the same index...
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgAlgebraicChallengeFp3(
                               core, rc::Fri3AlgAlgebraicDrawKind::Ood, 0)));
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgAlgebraicChallengeFp3(
                               core, rc::Fri3AlgAlgebraicDrawKind::Weight, 0)));
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgAlgebraicChallengeFp3(
                               core, rc::Fri3AlgAlgebraicDrawKind::Fold, 0)));
    // ...and by INDEX at the same kind.
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgAlgebraicChallengeFp3(
                              core, rc::Fri3AlgAlgebraicDrawKind::Lambda, 1)));
    // ...and by CORE.
    std::vector<gf::Fp> moved = core;
    moved[7] = gf::Add(moved[7], 1);
    BOOST_CHECK(!gf::Eq(a, rc::Fri3AlgAlgebraicChallengeFp3(
                              moved, rc::Fri3AlgAlgebraicDrawKind::Lambda, 0)));

    // Every coordinate is a CANONICAL field element and no draw can fail --
    // there is no rejection sampler to exhaust, which is the structural
    // difference from the SHA route's eight-word / two-block schedule.
    static constexpr uint64_t kP = 0xFFFFFFFF00000001ull;
    uint32_t nonzero_c1 = 0;
    uint32_t nonzero_c2 = 0;
    for (uint32_t idx = 0; idx < 64; ++idx) {
        const rc::Fp3 d = rc::Fri3AlgAlgebraicChallengeFp3(
            core, rc::Fri3AlgAlgebraicDrawKind::Fold, idx);
        BOOST_REQUIRE_LT(static_cast<uint64_t>(d.c0), kP);
        BOOST_REQUIRE_LT(static_cast<uint64_t>(d.c1), kP);
        BOOST_REQUIRE_LT(static_cast<uint64_t>(d.c2), kP);
        if (d.c1 != 0) ++nonzero_c1;
        if (d.c2 != 0) ++nonzero_c2;
    }
    // Non-vacuity: all three coordinates are genuinely used, so this is an
    // Fp3 draw and not an Fp draw padded with zeros.
    BOOST_CHECK_EQUAL(nonzero_c1, 64u);
    BOOST_CHECK_EQUAL(nonzero_c2, 64u);
}

// Item 2: sigma_core -- previously undefined anywhere in the tree.
BOOST_AUTO_TEST_CASE(pr89_sigma_core_is_defined_and_width_independent)
{
    const uint256 seed = MakeSeed(0x33);
    rc::Fri3AlgBatchCommitResult narrow =
        rc::Fri3AlgShortFsBatchCommit(MakeShortFsColumns(4, 16), seed, 0);
    rc::Fri3AlgBatchCommitResult wide =
        rc::Fri3AlgShortFsBatchCommit(MakeShortFsColumns(48, 16), seed, 0);
    BOOST_REQUIRE_MESSAGE(narrow.ok, narrow.note);
    BOOST_REQUIRE_MESSAGE(wide.ok, wide.note);
    BOOST_REQUIRE_EQUAL(narrow.proof.n_coeffs, wide.proof.n_coeffs);

    const std::vector<gf::Fp> core_narrow =
        rc::Fri3AlgAlgebraicSigmaCore(seed, narrow.proof);
    const std::vector<gf::Fp> core_wide =
        rc::Fri3AlgAlgebraicSigmaCore(seed, wide.proof);
    // O(log n), not O(W): a 12x wider child yields the SAME sigma_core length.
    BOOST_CHECK_EQUAL(core_narrow.size(), core_wide.size());
    BOOST_CHECK_GT(core_narrow.size(), 0u);
    BOOST_TEST_MESSAGE("SIGMA_CORE lanes=" << core_wide.size()
                       << " n_coeffs=" << wide.proof.n_coeffs
                       << " W_narrow=4 W_wide=48");
    // ...and it still distinguishes the two children.
    BOOST_CHECK(core_narrow != core_wide);

    // It binds every part of the TERMINAL transcript: moving any one of them
    // moves sigma, hence moves every query index.
    const auto sigma_of = [&](const rc::Fri3AlgBatchProof& p) {
        return rc::Fri3AlgAlgebraicSqueeze(
            rc::Fri3AlgAlgebraicSigmaCore(seed, p), 0);
    };
    const rc::Fri3AlgDigest base = sigma_of(wide.proof);
    {
        rc::Fri3AlgBatchProof p = wide.proof;
        p.w1 = gf::Add(p.w1, rc::Fp3::One());
        BOOST_CHECK(sigma_of(p) != base);
    }
    {
        rc::Fri3AlgBatchProof p = wide.proof;
        p.final_value = gf::Add(p.final_value, rc::Fp3::One());
        BOOST_CHECK(sigma_of(p) != base);
    }
    {
        rc::Fri3AlgBatchProof p = wide.proof;
        p.fold_layers[0].root[0] = gf::Add(p.fold_layers[0].root[0], 1);
        BOOST_CHECK(sigma_of(p) != base);
    }
    {
        rc::Fri3AlgBatchProof p = wide.proof;
        p.fold_challenges.back() =
            gf::Add(p.fold_challenges.back(), rc::Fp3::One());
        BOOST_CHECK(sigma_of(p) != base);
    }
    {   // ...including the W-proportional bodies, through their commitments.
        rc::Fri3AlgBatchProof p = wide.proof;
        p.evals_z1[3] = gf::Add(p.evals_z1[3], rc::Fp3::One());
        BOOST_CHECK(sigma_of(p) != base);
    }
    {
        rc::Fri3AlgBatchProof p = wide.proof;
        p.column_len[1] = p.column_len[1] == 1 ? 2 : p.column_len[1] - 1;
        BOOST_CHECK(sigma_of(p) != base);
    }
    // A different SEED gives a different sigma_core even for the same proof
    // body -- the child is bound to its parent-supplied seed.
    BOOST_CHECK(rc::Fri3AlgAlgebraicSigmaCore(MakeSeed(0x34), wide.proof) !=
                core_wide);

    // End to end: grind the Construction-2 tax on a REAL sigma_core and derive
    // query indices from it. Small g so the test is fast; the shipped constant
    // is asserted separately in pr89_algebraic_taxed_squeeze.
    const uint32_t g = 10;
    const auto nonce = rc::Fri3AlgGrindAlgebraicSqueeze(core_wide, g);
    BOOST_REQUIRE(nonce.has_value());
    BOOST_CHECK(rc::Fri3AlgCheckAlgebraicSqueezeGrind(core_wide, *nonce, g));
    const rc::Fri3AlgDigest sigma =
        rc::Fri3AlgAlgebraicSqueeze(core_wide, *nonce);
    const uint32_t n_lde = wide.proof.n_coeffs * wide.proof.blowup;
    bool any_differs = false;
    for (uint32_t j = 0; j < 16; ++j) {
        const uint32_t index =
            rc::Fri3AlgAlgebraicQueryIndex(sigma, j, n_lde);
        BOOST_REQUIRE_LT(index, n_lde);
        if (index != rc::Fri3AlgAlgebraicQueryIndex(sigma, 0, n_lde)) {
            any_differs = true;
        }
    }
    BOOST_CHECK(any_differs);
}

BOOST_AUTO_TEST_SUITE_END()
