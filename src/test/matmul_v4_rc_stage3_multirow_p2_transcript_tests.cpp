// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_p2_transcript.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <set>

namespace matmul::v4::rc::stage3_multirow_p2_transcript {
namespace {

gf::Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fri3AlgDigest D(uint64_t base)
{
    return {
        gf::FromU64(base),
        gf::FromU64(base + 1),
        gf::FromU64(base + 2),
        gf::FromU64(base + 3)};
}

StatementV1 Statement()
{
    StatementV1 s;
    s.public_fs_seed =
        *uint256::FromHex(
            "0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef");
    s.pow_grind_nonce = 0;
    s.trace_rows = 512;
    s.trace_columns = 5;
    s.quotient_len = 1024;
    s.n_coeffs = 1024;
    s.blowup = 4;
    s.base_column_indices = {0, 1};
    s.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 2, 4096, D(10)},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 2, 3, 4096, D(20)},
        {Fri3AlgMultiRowGroupRole::Quotient, 5, 1, 4096, D(30)}}};
    s.column_len = {1024, 1000, 900, 800, 1024, 1024};
    for (uint32_t i = 0; i < s.column_len.size(); ++i) {
        s.evals_z1.push_back(U(100 + i));
        s.evals_z2.push_back(U(200 + i));
    }
    uint32_t leaves = 4096;
    for (uint32_t fold = 0; fold < 11; ++fold) {
        s.folds.push_back({leaves, D(1000 + 10 * fold)});
        leaves >>= 1;
    }
    s.final_value = U(9999);
    return s;
}

bool Different(const Fri3AlgDigest& a, const Fri3AlgDigest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) return true;
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_multirow_p2_transcript_tests)

BOOST_AUTO_TEST_CASE(
    host_and_constant_width_air_replay_exact_q192_k2_transcript)
{
    const auto statement = Statement();
    const auto receipt = DeriveV1(statement);
    BOOST_REQUIRE_MESSAGE(receipt.valid, receipt.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyReceiptV1(statement, receipt, &why), why);
    BOOST_CHECK_EQUAL(receipt.batching_coefficients.size(), 6U);
    BOOST_CHECK_EQUAL(receipt.fold_challenges.size(), 10U);
    BOOST_CHECK_LT(receipt.z1_selected, kOodCandidatesV1);
    BOOST_CHECK_LT(receipt.z2_selected, kOodCandidatesV1);
    std::set<uint32_t> queries;
    for (const auto& query : receipt.queries) {
        BOOST_CHECK_LT(query.selected_ordinal, kQueryCandidatesV1);
        BOOST_CHECK_LT(query.index, 4096U);
        queries.insert(query.index);
    }
    BOOST_CHECK_LE(queries.size(), kQueriesV1);
    BOOST_CHECK(receipt.q192_with_replacement);

    const auto product = BuildProductV1(statement);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(product.layout.n_columns, 503U);
    BOOST_CHECK_LE(product.max_constraint_degree, 2U);
    BOOST_CHECK(product.full_root_and_length_binding);
    BOOST_CHECK(product.full_ood_binding_before_batching);
    BOOST_CHECK(product.independent_batching_coefficients_host_derived);
    BOOST_CHECK(!product.independent_batching_consumer_air_constrained);
    BOOST_CHECK(product.k2_ood_selection_host_derived);
    BOOST_CHECK(!product.k2_ood_selection_air_constrained);
    BOOST_CHECK(product.q192_with_replacement_host_derived);
    BOOST_CHECK(product.q192_k2_first_valid_air_constrained);
    BOOST_CHECK(!product.q192_selected_index_consumer_air_constrained);
    BOOST_CHECK(product.canonical_u64_split);
    BOOST_CHECK(product.exact_host_poseidon_air_equivalence);
    BOOST_CHECK(product.preprocessed_event_tape_root_pinned);
    BOOST_CHECK(!product.preprocessed_row_group_root.IsNull());
    BOOST_CHECK(!product.proof_owned_sources_bound);
    BOOST_CHECK(!product.production_authority_ready);
    BOOST_CHECK_EQUAL(kLegacyMultiRowVersionV2, 2U);
    BOOST_CHECK_EQUAL(kProtocolVersionV1, 11U);
    const auto hooks = AssessBackendHooksV1();
    BOOST_CHECK(hooks.additive_version_and_domain);
    BOOST_CHECK(!hooks.commit_schedule_implemented);
    BOOST_CHECK(!hooks.verify_schedule_implemented);
    BOOST_CHECK(!hooks.unbiased_query_openings_implemented);
    BOOST_CHECK(!hooks.versioned_codec_implemented);
    BOOST_CHECK(!hooks.split_rap_dispatch_implemented);
    BOOST_CHECK(!hooks.receipt_cells_match_backend);
    BOOST_CHECK(!hooks.backend_executable);
    BOOST_TEST_MESSAGE(
        "multirow-p2 events=" << product.hash_events
        << " sponge_rows=" << product.real_sponge_rows
        << " trace_rows=" << product.trace_rows
        << " columns=" << product.layout.n_columns
        << " constraints=" << product.constraints);
}

BOOST_AUTO_TEST_CASE(
    incremental_backend_api_is_exactly_one_shot_equivalent)
{
    const auto statement = Statement();
    const auto one_shot = DeriveV1(statement);
    BOOST_REQUIRE_MESSAGE(one_shot.valid, one_shot.note);

    auto transcript =
        BeginIncrementalV1(BuildSkeletonV1(statement));
    BOOST_REQUIRE_MESSAGE(transcript.valid, transcript.note);
    BOOST_CHECK(
        transcript.stage == IncrementalStageV1::SkeletonBound);
    BOOST_CHECK_EQUAL(transcript.hash_events, 7U);
    BOOST_CHECK(!Different(
        transcript.stage_commitment,
        transcript.receipt.fri_seed));

    BOOST_REQUIRE_MESSAGE(
        BindEvaluationsV1(
            transcript, statement.evals_z1, statement.evals_z2),
        transcript.note);
    BOOST_CHECK(
        transcript.stage ==
        IncrementalStageV1::EvaluationsBound);
    BOOST_CHECK_EQUAL(
        transcript.hash_events,
        7U + statement.column_len.size() + 5U);
    BOOST_CHECK(!Different(
        transcript.stage_commitment, transcript.fold_state));

    uint32_t expected_events = transcript.hash_events;
    uint32_t betas = 0;
    for (uint32_t fold = 0; fold < statement.folds.size(); ++fold) {
        const auto step =
            AbsorbFoldV1(transcript, statement.folds[fold]);
        BOOST_REQUIRE_MESSAGE(step.valid, step.note);
        BOOST_CHECK_EQUAL(step.fold_index, fold);
        const bool terminal = fold + 1 == statement.folds.size();
        BOOST_CHECK_EQUAL(step.beta_derived, !terminal);
        expected_events += terminal ? 1U : 2U;
        BOOST_CHECK_EQUAL(transcript.hash_events, expected_events);
        if (!terminal) {
            BOOST_REQUIRE_LT(
                betas, one_shot.fold_challenges.size());
            BOOST_CHECK(gf::Eq(
                step.beta, one_shot.fold_challenges[betas]));
            ++betas;
        }
    }
    BOOST_CHECK(
        transcript.stage == IncrementalStageV1::FoldsComplete);
    BOOST_CHECK_EQUAL(betas, statement.folds.size() - 1);

    BOOST_REQUIRE_MESSAGE(
        FinalizeQueriesV1(transcript, statement.final_value),
        transcript.note);
    BOOST_CHECK(
        transcript.stage == IncrementalStageV1::Finalized);
    BOOST_CHECK(transcript.receipt.valid);
    BOOST_CHECK_EQUAL(
        transcript.hash_events,
        ExpectedHashEventsV1(
            static_cast<uint32_t>(statement.column_len.size()),
            static_cast<uint32_t>(statement.folds.size())));
    BOOST_CHECK_EQUAL(transcript.hash_events, 424U);
    BOOST_CHECK(!Different(
        transcript.stage_commitment,
        transcript.receipt.query_seed));
    std::string why;
    BOOST_CHECK_MESSAGE(
        VerifyReceiptV1(statement, transcript.receipt, &why), why);

    const auto product = BuildProductV1(statement);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.hash_events, transcript.hash_events);
}

BOOST_AUTO_TEST_CASE(
    incremental_stage_omission_and_reordering_fail_closed)
{
    const auto statement = Statement();
    {
        IncrementalTranscriptV1 empty;
        BOOST_CHECK(!BindEvaluationsV1(
            empty, statement.evals_z1, statement.evals_z2));
        BOOST_CHECK(empty.stage == IncrementalStageV1::Failed);
    }
    {
        auto transcript =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(transcript.valid);
        const auto early =
            AbsorbFoldV1(transcript, statement.folds.front());
        BOOST_CHECK(!early.valid);
        BOOST_CHECK(transcript.stage == IncrementalStageV1::Failed);
    }
    {
        auto transcript =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(transcript.valid);
        BOOST_CHECK(!FinalizeQueriesV1(
            transcript, statement.final_value));
        BOOST_CHECK(transcript.stage == IncrementalStageV1::Failed);
    }
    {
        auto transcript =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(BindEvaluationsV1(
            transcript, statement.evals_z1, statement.evals_z2));
        BOOST_CHECK(!BindEvaluationsV1(
            transcript, statement.evals_z1, statement.evals_z2));
        BOOST_CHECK(transcript.stage == IncrementalStageV1::Failed);
    }
    {
        auto transcript =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(BindEvaluationsV1(
            transcript, statement.evals_z1, statement.evals_z2));
        // The decreasing leaf count is an explicit stage-order tag.
        const auto reordered =
            AbsorbFoldV1(transcript, statement.folds[1]);
        BOOST_CHECK(!reordered.valid);
        BOOST_CHECK(transcript.stage == IncrementalStageV1::Failed);
    }
    {
        auto transcript =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(BindEvaluationsV1(
            transcript, statement.evals_z1, statement.evals_z2));
        for (uint32_t fold = 0;
             fold + 1 < statement.folds.size(); ++fold) {
            BOOST_REQUIRE(
                AbsorbFoldV1(
                    transcript, statement.folds[fold]).valid);
        }
        BOOST_CHECK(!FinalizeQueriesV1(
            transcript, statement.final_value));
        BOOST_CHECK(transcript.stage == IncrementalStageV1::Failed);
    }
    {
        auto transcript =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(BindEvaluationsV1(
            transcript, statement.evals_z1, statement.evals_z2));
        for (const auto& fold : statement.folds) {
            BOOST_REQUIRE(
                AbsorbFoldV1(transcript, fold).valid);
        }
        BOOST_CHECK(!AbsorbFoldV1(
            transcript, statement.folds.back()).valid);
        BOOST_CHECK(transcript.stage == IncrementalStageV1::Failed);
    }
}

BOOST_AUTO_TEST_CASE(
    incremental_root_eval_fold_terminal_and_nonce_mutations_bind)
{
    const auto statement = Statement();
    auto honest =
        BeginIncrementalV1(BuildSkeletonV1(statement));
    BOOST_REQUIRE(honest.valid);

    {
        auto changed = statement;
        changed.groups[1].root[2] = gf::Add(
            changed.groups[1].root[2], gf::FromU64(1));
        const auto mutated =
            BeginIncrementalV1(BuildSkeletonV1(changed));
        BOOST_REQUIRE(mutated.valid);
        BOOST_CHECK(Different(
            mutated.stage_commitment, honest.stage_commitment));
    }
    {
        auto changed = statement;
        changed.pow_grind_nonce = 1;
        const auto mutated =
            BeginIncrementalV1(BuildSkeletonV1(changed));
        BOOST_CHECK(!mutated.valid);
        BOOST_CHECK(mutated.stage == IncrementalStageV1::Failed);
    }

    BOOST_REQUIRE(BindEvaluationsV1(
        honest, statement.evals_z1, statement.evals_z2));
    {
        auto mutated =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        auto evals = statement.evals_z1;
        evals[3] = gf::Add(evals[3], U(1));
        BOOST_REQUIRE(BindEvaluationsV1(
            mutated, evals, statement.evals_z2));
        BOOST_CHECK(Different(
            mutated.stage_commitment, honest.stage_commitment));
        BOOST_CHECK(!gf::Eq(
            mutated.receipt.batching_coefficients[0],
            honest.receipt.batching_coefficients[0]));
    }
    {
        auto mutated =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        auto short_evals = statement.evals_z1;
        short_evals.pop_back();
        BOOST_CHECK(!BindEvaluationsV1(
            mutated, short_evals, statement.evals_z2));
        BOOST_CHECK(mutated.stage == IncrementalStageV1::Failed);
    }

    for (uint32_t fold = 0; fold < 3; ++fold) {
        BOOST_REQUIRE(
            AbsorbFoldV1(honest, statement.folds[fold]).valid);
    }
    {
        auto mutated =
            BeginIncrementalV1(BuildSkeletonV1(statement));
        BOOST_REQUIRE(BindEvaluationsV1(
            mutated, statement.evals_z1, statement.evals_z2));
        for (uint32_t fold = 0; fold < 3; ++fold) {
            BOOST_REQUIRE(
                AbsorbFoldV1(
                    mutated, statement.folds[fold]).valid);
        }
        auto changed_fold = statement.folds[3];
        changed_fold.root[1] = gf::Add(
            changed_fold.root[1], gf::FromU64(1));
        const auto changed_step =
            AbsorbFoldV1(mutated, changed_fold);
        const auto honest_step =
            AbsorbFoldV1(honest, statement.folds[3]);
        BOOST_REQUIRE(changed_step.valid);
        BOOST_REQUIRE(honest_step.valid);
        BOOST_CHECK(changed_step.beta_derived);
        BOOST_CHECK(!gf::Eq(
            changed_step.beta, honest_step.beta));
        BOOST_CHECK(Different(
            mutated.stage_commitment, honest.stage_commitment));
    }

    auto terminal_a =
        BeginIncrementalV1(BuildSkeletonV1(statement));
    auto terminal_b =
        BeginIncrementalV1(BuildSkeletonV1(statement));
    BOOST_REQUIRE(BindEvaluationsV1(
        terminal_a, statement.evals_z1, statement.evals_z2));
    BOOST_REQUIRE(BindEvaluationsV1(
        terminal_b, statement.evals_z1, statement.evals_z2));
    for (uint32_t fold = 0; fold < statement.folds.size(); ++fold) {
        auto a = statement.folds[fold];
        auto b = a;
        if (fold + 1 == statement.folds.size()) {
            b.root[0] = gf::Add(b.root[0], gf::FromU64(1));
        }
        const auto step_a = AbsorbFoldV1(terminal_a, a);
        const auto step_b = AbsorbFoldV1(terminal_b, b);
        BOOST_REQUIRE(step_a.valid);
        BOOST_REQUIRE(step_b.valid);
        if (fold + 1 == statement.folds.size()) {
            BOOST_CHECK(!step_a.beta_derived);
            BOOST_CHECK(!step_b.beta_derived);
        }
    }
    BOOST_REQUIRE(FinalizeQueriesV1(
        terminal_a, statement.final_value));
    BOOST_REQUIRE(FinalizeQueriesV1(
        terminal_b, statement.final_value));
    BOOST_CHECK(Different(
        terminal_a.receipt.query_seed,
        terminal_b.receipt.query_seed));

    auto terminal_value =
        BeginIncrementalV1(BuildSkeletonV1(statement));
    BOOST_REQUIRE(BindEvaluationsV1(
        terminal_value, statement.evals_z1, statement.evals_z2));
    for (const auto& fold : statement.folds) {
        BOOST_REQUIRE(
            AbsorbFoldV1(terminal_value, fold).valid);
    }
    BOOST_REQUIRE(FinalizeQueriesV1(
        terminal_value,
        gf::Add(statement.final_value, U(1))));
    BOOST_CHECK(Different(
        terminal_a.receipt.query_seed,
        terminal_value.receipt.query_seed));
}

BOOST_AUTO_TEST_CASE(
    with_replacement_distribution_and_exhaustion_theorem)
{
    // Goldilocks p = 1 mod 2^k for every supported k. Thus [0,p-2]
    // contains exactly (p-1)/2^k occurrences of every k-bit residue.
    // Rejecting only p-1 before masking removes the sole surplus zero.
    for (uint32_t k = 1; k <= 32; ++k) {
        const uint64_t modulus = uint64_t{1} << k;
        BOOST_CHECK_EQUAL(gf::kP % modulus, 1U);
        BOOST_CHECK_EQUAL((gf::kP - 1) % modulus, 0U);
    }
    // The first non-(p-1) candidate is exactly uniform on N. Queries are
    // independent and with replacement; duplicates remain in the standard
    // FRI proximity theorem. K=2 exhaustion is separately fail-closed.
    const double bits = QueryExhaustionBitsV1();
    BOOST_CHECK_GT(bits, 120.0);
    BOOST_CHECK_EQUAL(QueryExhaustionBitsV1(2048), 0.0);
    BOOST_CHECK_EQUAL(QueryExhaustionBitsV1(4095), 0.0);
    BOOST_TEST_MESSAGE(
        "Q192 fixed-window exhaustion security bits at N=4096: "
        << bits);

    std::array<Fri3AlgDigest, kQueryCandidatesV1> candidates{
        D(400), D(500)};
    candidates[0][0] = gf::FromU64(gf::kP - 1);
    const auto second = AuditQuerySelectionV1(candidates, 4096);
    BOOST_REQUIRE(second.valid);
    BOOST_CHECK(!second.candidate_valid[0]);
    BOOST_CHECK(second.candidate_valid[1]);
    BOOST_CHECK(!second.selected[0]);
    BOOST_CHECK(second.selected[1]);
    BOOST_CHECK_EQUAL(second.selected_ordinal, 1U);
    candidates[1][0] = gf::FromU64(gf::kP - 1);
    const auto exhausted = AuditQuerySelectionV1(candidates, 4096);
    BOOST_CHECK(!exhausted.valid);
    BOOST_CHECK_EQUAL(exhausted.constraint_violations, 1U);
}

BOOST_AUTO_TEST_CASE(
    roots_shape_evals_folds_and_nonce_are_bound_before_consumers)
{
    const auto statement = Statement();
    const auto honest = DeriveV1(statement);
    BOOST_REQUIRE(honest.valid);
    {
        auto changed = statement;
        changed.groups[0].root[0] =
            gf::Add(changed.groups[0].root[0], gf::FromU64(1));
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(!gf::Eq(receipt.air_lambda, honest.air_lambda));
        BOOST_CHECK(Different(receipt.fri_seed, honest.fri_seed));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        --changed.column_len[1];
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(Different(receipt.shape_commit, honest.shape_commit));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        changed.evals_z2[4] =
            gf::Add(changed.evals_z2[4], U(1));
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(Different(
            receipt.ood_eval_commit, honest.ood_eval_commit));
        BOOST_CHECK(!gf::Eq(
            receipt.batching_coefficients[0],
            honest.batching_coefficients[0]));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        changed.folds[3].root[2] =
            gf::Add(changed.folds[3].root[2], gf::FromU64(1));
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(!gf::Eq(
            receipt.fold_challenges[3],
            honest.fold_challenges[3]));
        BOOST_CHECK(Different(receipt.query_seed, honest.query_seed));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        changed.folds.back().root[0] =
            gf::Add(changed.folds.back().root[0], gf::FromU64(1));
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(Different(receipt.query_seed, honest.query_seed));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        // Split-RAP's current caller fixes nonce to zero. In particular a
        // nonce cannot be used to grind the constraint-composition lambda.
        changed.pow_grind_nonce = 1;
        const auto receipt = DeriveV1(changed);
        BOOST_CHECK(!receipt.valid);
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        changed.base_column_indices = {0, 2};
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(!gf::Eq(receipt.air_lambda, honest.air_lambda));
        BOOST_CHECK(Different(receipt.fri_seed, honest.fri_seed));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        changed.trace_rows = 256;
        const auto receipt = DeriveV1(changed);
        BOOST_REQUIRE(receipt.valid);
        BOOST_CHECK(!gf::Eq(receipt.air_lambda, honest.air_lambda));
        BOOST_CHECK(!VerifyReceiptV1(changed, honest));
    }
    {
        auto changed = statement;
        changed.quotient_len = 2048;
        BOOST_CHECK(!DeriveV1(changed).valid);
    }
}

BOOST_AUTO_TEST_CASE(
    version_confusion_and_transcript_cell_attacks_reject)
{
    const auto statement = Statement();
    const auto honest = DeriveV1(statement);
    BOOST_REQUIRE(honest.valid);
    {
        auto legacy = statement;
        legacy.protocol_version = kLegacyMultiRowVersionV2;
        const auto receipt = DeriveV1(legacy);
        BOOST_CHECK(!receipt.valid);
        BOOST_CHECK(!VerifyReceiptV1(legacy, honest));
    }
    {
        auto wrong_domain = statement;
        wrong_domain.protocol_domain ^=
            0x0100000000000000ULL;
        BOOST_CHECK(!DeriveV1(wrong_domain).valid);
        BOOST_CHECK(!VerifyReceiptV1(wrong_domain, honest));
    }
    {
        auto early = statement;
        early.folds.pop_back();
        BOOST_CHECK(!DeriveV1(early).valid);
    }
    {
        auto late = statement;
        late.folds.push_back({2, D(99999)});
        BOOST_CHECK(!DeriveV1(late).valid);
    }
    {
        auto wrong_terminal = statement;
        wrong_terminal.folds.back().n_leaves = 8;
        BOOST_CHECK(!DeriveV1(wrong_terminal).valid);
    }
    {
        auto forged = honest;
        forged.batching_coefficients[2] =
            gf::Add(forged.batching_coefficients[2], U(1));
        BOOST_CHECK(!VerifyReceiptV1(statement, forged));
    }
    {
        auto forged = honest;
        std::swap(forged.queries[0].index, forged.queries[1].index);
        BOOST_CHECK(!VerifyReceiptV1(statement, forged));
        const auto product = BuildProductV1(statement);
        BOOST_REQUIRE(product.valid);
        // The P2 candidates and first-valid selector are in this AIR, but
        // the selected index is not yet aliased into a FRI opening consumer.
        BOOST_CHECK(!product.q192_selected_index_consumer_air_constrained);
    }
    {
        auto forged = honest;
        forged.queries[0].candidate_digest[0][0] =
            gf::Add(
                forged.queries[0].candidate_digest[0][0],
                gf::FromU64(1));
        BOOST_CHECK(!VerifyReceiptV1(statement, forged));
    }
    {
        auto forged = honest;
        forged.fold_challenges.back() =
            gf::Add(forged.fold_challenges.back(), U(1));
        BOOST_CHECK(!VerifyReceiptV1(statement, forged));
    }
    {
        auto forged = honest;
        forged.fold_challenges.pop_back();
        BOOST_CHECK(!VerifyReceiptV1(statement, forged));
    }
}

BOOST_AUTO_TEST_CASE(
    air_witness_digest_and_event_tape_tampers_violate_constraints)
{
    const auto product = BuildProductV1(Statement());
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    {
        auto columns = product.columns;
        columns[
            product.layout.poseidon.perm.InputCol(0)][17] =
            gf::Add(
                columns[
                    product.layout.poseidon.perm.InputCol(0)][17],
                U(1));
        uint64_t violations = 0;
        std::vector<gf::Fp3> cur(product.cs.n_columns);
        std::vector<gf::Fp3> next(product.cs.n_columns);
        for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
            for (uint32_t col = 0; col < product.cs.n_columns; ++col) {
                cur[col] = columns[col][row];
                next[col] =
                    columns[col][(row + 1) % product.cs.n_rows];
            }
            for (const auto& constraint : product.cs.constraints) {
                bool applies =
                    constraint.kind == aq::AirKind::kEverywhere ||
                    (constraint.kind == aq::AirKind::kFirstRow && row == 0) ||
                    (constraint.kind == aq::AirKind::kLastRow &&
                     row + 1 == product.cs.n_rows) ||
                    (constraint.kind == aq::AirKind::kTransition &&
                     row + 1 < product.cs.n_rows);
                if (applies &&
                    !gf::IsZero(constraint.eval(cur, next))) {
                    ++violations;
                }
            }
        }
        BOOST_CHECK_GT(violations, 0U);
    }
    {
        auto columns = product.columns;
        const uint32_t row = product.real_sponge_rows - 1;
        columns[product.layout.DigestClaim(0)][row] =
            gf::Add(columns[product.layout.DigestClaim(0)][row], U(1));
        bool rejected = false;
        std::vector<gf::Fp3> cur(product.cs.n_columns);
        std::vector<gf::Fp3> next(product.cs.n_columns);
        for (uint32_t col = 0; col < product.cs.n_columns; ++col) {
            cur[col] = columns[col][row];
            next[col] = columns[col][row + 1];
        }
        for (const auto& constraint : product.cs.constraints) {
            if (constraint.kind == aq::AirKind::kEverywhere &&
                !gf::IsZero(constraint.eval(cur, next))) {
                rejected = true;
            }
        }
        BOOST_CHECK(rejected);
    }
    {
        auto columns = product.columns;
        uint32_t query_first = product.trace_rows;
        for (uint32_t row = 0; row < product.trace_rows; ++row) {
            if (gf::Eq(
                    columns[
                        product.layout.query_candidate_first][row],
                    gf::Fp3::One())) {
                query_first = row;
                break;
            }
        }
        BOOST_REQUIRE_LT(query_first, product.trace_rows - 1);
        columns[product.layout.candidate_selected][query_first] =
            gf::Sub(
                gf::Fp3::One(),
                columns[
                    product.layout.candidate_selected][query_first]);
        std::vector<gf::Fp3> cur(product.cs.n_columns);
        std::vector<gf::Fp3> next(product.cs.n_columns);
        for (uint32_t col = 0; col < product.cs.n_columns; ++col) {
            cur[col] = columns[col][query_first];
            next[col] = columns[col][query_first + 1];
        }
        bool rejected = false;
        for (const auto& constraint : product.cs.constraints) {
            if ((constraint.kind == aq::AirKind::kEverywhere ||
                 constraint.kind == aq::AirKind::kTransition) &&
                !gf::IsZero(constraint.eval(cur, next))) {
                rejected = true;
            }
        }
        BOOST_CHECK(rejected);
    }
}

BOOST_AUTO_TEST_CASE(
    optional_outer_splitrap_size_and_verify_measurement)
{
    if (std::getenv("BTX_RUN_STAGE3_MULTIROW_P2_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_MULTIROW_P2_PROOF=1 for outer proof "
            "measurement (outer envelope remains frozen MultiRow-V2)");
        return;
    }
    const auto product = BuildProductV1(Statement());
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto proved = aq::AirQuotientProveRowsSplitRap(
        product.cs, product.columns, product.preprocessed_columns,
        uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - prove_start).count();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    const auto verify_start = std::chrono::steady_clock::now();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proved.proof, product.preprocessed_columns,
            uint256::ONE, &why), why);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start).count();
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(proved.proof, wire);
    BOOST_REQUIRE_EQUAL(bytes, wire.size());
    BOOST_CHECK_LT(bytes, 16U * 1024U * 1024U);
    BOOST_TEST_MESSAGE(
        "multirow-p2 verifier AIR OUTER-V2 proof_bytes=" << bytes
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us
        << " rows=" << product.trace_rows
        << " columns=" << product.layout.n_columns);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_p2_transcript
