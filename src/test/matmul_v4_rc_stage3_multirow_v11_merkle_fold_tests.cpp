// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>

#include <algorithm>
#include <chrono>

namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold {
namespace {

using Digest = alg_hash::Digest;

struct Tree {
    std::vector<std::vector<Digest>> levels;
    Digest root{};

    [[nodiscard]] std::vector<Digest> Path(uint32_t index) const
    {
        std::vector<Digest> out;
        for (uint32_t level = 0; level + 1 < levels.size(); ++level) {
            out.push_back(levels[level][index ^ 1U]);
            index >>= 1;
        }
        return out;
    }
};

template <typename Leaf>
Tree BuildTree(uint32_t leaves, Leaf leaf)
{
    BOOST_REQUIRE(leaves >= 2);
    BOOST_REQUIRE((leaves & (leaves - 1)) == 0);
    Tree out;
    out.levels.emplace_back(leaves);
    for (uint32_t index = 0; index < leaves; ++index) {
        out.levels[0][index] = leaf(index);
    }
    uint32_t width = leaves;
    while (width > 1) {
        out.levels.emplace_back(width / 2);
        for (uint32_t index = 0; index < width / 2; ++index) {
            out.levels.back()[index] = alg_hash::Compress(
                out.levels[out.levels.size() - 2][2 * index],
                out.levels[out.levels.size() - 2][2 * index + 1]);
        }
        width >>= 1;
    }
    out.root = out.levels.back()[0];
    return out;
}

struct Fixture {
    abi::EnvelopeV1 envelope;
    backend::ProofV1 proof;
    abi::DecodedV1 decoded;
    tp::ReceiptV1 transcript;
    std::vector<uint32_t> words;
};

Fixture BuildFixture()
{
    constexpr uint32_t trace_rows = 256;
    constexpr uint32_t n_coeffs = 256;
    constexpr uint32_t blowup = kRCFriBlowup;
    constexpr uint32_t n_lde = n_coeffs * blowup;
    const Fp3 zero = Fp3::Zero();

    const Tree row_tree = BuildTree(
        n_lde,
        [&](uint32_t index) {
            return alg_hash::LeafHashRow({zero}, index);
        });
    std::vector<Tree> fold_trees;
    for (uint32_t width = n_lde;; width >>= 1) {
        fold_trees.push_back(BuildTree(
            width,
            [&](uint32_t index) {
                return alg_hash::LeafHash(zero, index);
            }));
        if (width == blowup) break;
    }

    Fixture fixture;
    auto& split = fixture.envelope.split;
    auto& batch = split.batch;
    for (uint32_t word = 0; word < fixture.envelope.public_fs_seed.size();
         ++word) {
        fixture.envelope.public_fs_seed[word] =
            0x11223300U + word;
    }
    fixture.envelope.trace_columns = 2;
    fixture.envelope.quotient_len = trace_rows;
    split.version = 1;
    split.trace_rows = trace_rows;
    split.base_column_indices = {0};
    batch.version = kRCFri3AlgMultiRowBatchProofVersion;
    batch.pow_grind_nonce = 0;
    batch.blowup = blowup;
    batch.n_coeffs = n_coeffs;
    batch.groups = {
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 1,
         {row_tree.root, n_lde}},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 1, 1,
         {row_tree.root, n_lde}},
        {Fri3AlgMultiRowGroupRole::Quotient, 2, 1,
         {row_tree.root, n_lde}}};
    batch.column_len = {trace_rows, trace_rows, trace_rows};
    batch.evals_z1.assign(3, zero);
    batch.evals_z2.assign(3, zero);
    for (uint32_t fold = 0; fold < fold_trees.size(); ++fold) {
        batch.fold_layers.push_back({
            fold_trees[fold].root, n_lde >> fold});
    }
    batch.final_value = zero;

    tp::StatementV1 statement;
    for (uint32_t word = 0; word < 8; ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            statement.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    fixture.envelope.public_fs_seed[word] >> (8 * byte));
        }
    }
    statement.trace_rows = trace_rows;
    statement.trace_columns = 2;
    statement.quotient_len = trace_rows;
    statement.n_coeffs = n_coeffs;
    statement.blowup = blowup;
    statement.base_column_indices = {0};
    statement.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 1,
         n_lde, row_tree.root},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 1, 1,
         n_lde, row_tree.root},
        {Fri3AlgMultiRowGroupRole::Quotient, 2, 1,
         n_lde, row_tree.root}}};
    statement.column_len = batch.column_len;
    statement.evals_z1 = batch.evals_z1;
    statement.evals_z2 = batch.evals_z2;
    for (uint32_t fold = 0; fold < fold_trees.size(); ++fold) {
        statement.folds.push_back(
            {n_lde >> fold, fold_trees[fold].root});
    }
    statement.final_value = zero;
    fixture.transcript = tp::DeriveV1(statement);
    BOOST_REQUIRE_MESSAGE(
        fixture.transcript.valid, fixture.transcript.note);
    split.air_constraint_lambda = fixture.transcript.air_lambda;
    batch.lambda = fixture.transcript.batching_coefficients[0];
    batch.z1 = fixture.transcript.z1;
    batch.z2 = fixture.transcript.z2;
    batch.w1 = fixture.transcript.w1;
    batch.w2 = fixture.transcript.w2;
    batch.fold_challenges = fixture.transcript.fold_challenges;

    batch.queries.resize(kProductionQueriesV1);
    split.next_trace_group_rows.resize(kProductionQueriesV1);
    for (uint32_t q = 0; q < kProductionQueriesV1; ++q) {
        auto& query = batch.queries[q];
        query.index = fixture.transcript.queries[q].index;
        query.group_rows.resize(3);
        for (uint32_t group = 0; group < 3; ++group) {
            query.group_rows[group].values = {zero};
            query.group_rows[group].siblings =
                row_tree.Path(query.index);
        }
        uint32_t index = query.index;
        query.steps.resize(batch.fold_challenges.size());
        for (uint32_t fold = 0;
             fold < batch.fold_challenges.size(); ++fold) {
            const uint32_t width = n_lde >> fold;
            const uint32_t half = width / 2;
            auto& step = query.steps[fold];
            step.even_index = index % half;
            step.odd_index = step.even_index + half;
            step.even = zero;
            step.odd = zero;
            step.even_siblings =
                fold_trees[fold].Path(step.even_index);
            step.odd_siblings =
                fold_trees[fold].Path(step.odd_index);
            index %= half;
        }
        const uint32_t next_index =
            (query.index + n_lde / trace_rows) % n_lde;
        split.next_trace_group_rows[q].resize(2);
        for (uint32_t group = 0; group < 2; ++group) {
            split.next_trace_group_rows[q][group].values = {zero};
            split.next_trace_group_rows[q][group].siblings =
                row_tree.Path(next_index);
        }
    }

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            fixture.envelope, fixture.words, nullptr, &why),
        why);
    auto decoded = abi::DecodeCanonicalV1(fixture.words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    fixture.decoded = std::move(*decoded);
    fixture.proof.envelope = fixture.envelope;
    return fixture;
}

const Fixture& Honest()
{
    static const Fixture fixture = BuildFixture();
    return fixture;
}

std::optional<abi::DecodedV1> Recode(const abi::EnvelopeV1& envelope)
{
    std::vector<uint32_t> words;
    std::string why;
    if (!abi::EncodeCanonicalV1(envelope, words, nullptr, &why)) {
        return std::nullopt;
    }
    return abi::DecodeCanonicalV1(words, &why);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_merkle_fold_tests)

BOOST_AUTO_TEST_CASE(
    all_q192_current_next_and_fold_paths_close)
{
    const auto& fixture = Honest();
    std::string backend_why;
    tp::ReceiptV1 backend_transcript;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(
            fixture.proof, &backend_transcript, &backend_why),
        backend_why);
    BOOST_REQUIRE(backend_transcript.valid);
    BOOST_CHECK_EQUAL(
        backend_transcript.queries[0].index,
        fixture.transcript.queries[0].index);
    const auto audit = AuditAllV1(
        fixture.proof, fixture.transcript);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.queries_checked, 192U);
    BOOST_CHECK_EQUAL(audit.current_paths_checked, 576U);
    BOOST_CHECK_EQUAL(audit.next_paths_checked, 384U);
    BOOST_CHECK_EQUAL(audit.fold_paths_checked, 3072U);
    BOOST_CHECK_EQUAL(audit.fold_equations_checked, 1536U);
    BOOST_CHECK(audit.current_group_paths_verified);
    BOOST_CHECK(audit.next_group_paths_verified);
    BOOST_CHECK(audit.fold_paths_verified);
    BOOST_CHECK(audit.fold_equations_verified);
    BOOST_CHECK(audit.terminal_value_verified);
    BOOST_CHECK(audit.exact_source_addresses);
    BOOST_CHECK(audit.full_q192_coverage);
    BOOST_CHECK(audit.duplicate_queries_preserved);
    BOOST_CHECK(audit.literal_parent_consumer_refs);
    BOOST_CHECK_GT(audit.duplicate_query_count, 0U);
    BOOST_CHECK_EQUAL(audit.parent_consumer_cells, 5952U);
    BOOST_CHECK_GT(audit.poseidon_permutations, 40000U);
    BOOST_TEST_MESSAGE(
        "V11 full native Merkle/fold audit permutations="
        << audit.poseidon_permutations
        << " source_cells=" << audit.source_cells_consumed);
}

BOOST_AUTO_TEST_CASE(
    sibling_path_root_current_next_and_index_mutations_reject)
{
    const auto& fixture = Honest();
    {
        auto forged = fixture.envelope;
        forged.split.batch.queries[0]
            .group_rows[0].siblings[0][0] =
            gf::Add(
                forged.split.batch.queries[0]
                    .group_rows[0].siblings[0][0],
                gf::FromU64(1));
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        std::swap(
            forged.split.batch.queries[0]
                .group_rows[0].siblings[0],
            forged.split.batch.queries[0]
                .group_rows[0].siblings[1]);
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.groups[0].row_commit.root[0] =
            gf::Add(
                forged.split.batch.groups[0].row_commit.root[0],
                gf::FromU64(1));
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.next_trace_group_rows[0][0].siblings =
            forged.split.batch.queries[0].group_rows[0].siblings;
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.queries[0].index ^=
            forged.split.batch.blowup;
        const auto decoded = Recode(forged);
        BOOST_CHECK(
            !decoded.has_value() ||
            !AuditAllV1(*decoded, fixture.transcript).valid);
    }
}

BOOST_AUTO_TEST_CASE(
    fold_side_beta_final_and_goldilocks_alias_mutations_reject)
{
    const auto& fixture = Honest();
    {
        auto forged = fixture.envelope;
        ++forged.split.batch.queries[0].steps[0].even_index;
        const auto decoded = Recode(forged);
        BOOST_CHECK(
            !decoded.has_value() ||
            !AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.fold_challenges[0] = gf::Add(
            forged.split.batch.fold_challenges[0],
            Fp3::One());
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.final_value = Fp3::One();
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto words = fixture.words;
        const auto address = abi::FindSourceAddressV1(
            fixture.decoded.sources,
            {abi::FieldKindV1::QueryStepEven, 0, 0, 0, 0, 0});
        BOOST_REQUIRE(address.has_value());
        words[abi::kFieldAbiHeaderWordsV1 + 2 * *address + 1] =
            static_cast<uint32_t>(gf::kP);
        words[abi::kFieldAbiHeaderWordsV1 + 2 * (*address + 1) + 1] =
            static_cast<uint32_t>(gf::kP >> 32);
        std::string why;
        BOOST_CHECK(!abi::DecodeCanonicalV1(words, &why).has_value());
        BOOST_CHECK(
            why.find("noncanonical") != std::string::npos ||
            why.find("decode") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(
    one_query_shard_is_constant_width_and_quadratic)
{
    const auto& fixture = Honest();
    const auto shard = BuildShardV1(
        fixture.proof, fixture.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);
    BOOST_CHECK_EQUAL(shard.hash_layout.n_columns, 500U);
    BOOST_CHECK_EQUAL(shard.fold_layout.n_columns, 16U);
    BOOST_CHECK_EQUAL(shard.hash_real_rows, 217U);
    BOOST_CHECK_EQUAL(shard.hash_trace_rows, 256U);
    BOOST_CHECK_EQUAL(shard.fold_real_rows, 8U);
    BOOST_CHECK_EQUAL(shard.fold_trace_rows, 8U);
    BOOST_CHECK_EQUAL(shard.hash_violations, 0U);
    BOOST_CHECK_EQUAL(shard.fold_violations, 0U);
    BOOST_CHECK_LE(shard.hash_max_degree, 2U);
    BOOST_CHECK_LE(shard.fold_max_degree, 2U);
    BOOST_CHECK(shard.proof_owned_pins_ood_bound);
    BOOST_CHECK(!shard.proof_owned_pins_root_pinned);
    BOOST_CHECK(shard.constant_width_schedule);
    BOOST_CHECK(shard.duplicate_queries_preserved);
    BOOST_CHECK(shard.literal_parent_consumer_refs);
    BOOST_CHECK_EQUAL(shard.parent_consumer_refs.size(), 31U);
    BOOST_CHECK(!shard.same_parent_decoder_aliases);
    BOOST_CHECK(!shard.deep_quotient_constrained);
    BOOST_CHECK(!shard.canonical_vm_constrained);
    BOOST_CHECK(!shard.recursive_authority_ready);

    auto forged_hash = shard.hash_columns;
    forged_hash[shard.hash_layout.poseidon.perm.InputCol(0)][0] =
        gf::Add(
            forged_hash[
                shard.hash_layout.poseidon.perm.InputCol(0)][0],
            Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(shard.hash_cs, forged_hash), 0U);
    auto forged_fold = shard.fold_columns;
    forged_fold[shard.fold_layout.folded][0] =
        gf::Add(forged_fold[shard.fold_layout.folded][0], Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(shard.fold_cs, forged_fold), 0U);
    auto forged_side = shard.fold_columns;
    forged_side[shard.fold_layout.side][0] = gf::Sub(
        Fp3::One(), forged_side[shard.fold_layout.side][0]);
    BOOST_CHECK_GT(
        RecountViolationsV1(shard.fold_cs, forged_side), 0U);
}

BOOST_AUTO_TEST_CASE(
    representative_shard_proofs_verify_and_substitution_rejects)
{
    const auto& fixture = Honest();
    const auto shard = BuildShardV1(
        fixture.proof, fixture.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);
    const uint256 seed = uint256::ONE;
    std::string why;

    const auto hash_prove_start = std::chrono::steady_clock::now();
    const auto hash_proved = aq::AirQuotientProveRows(
        shard.hash_cs, shard.hash_columns, seed);
    const auto hash_prove_end = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(hash_proved.ok, hash_proved.note);
    BOOST_REQUIRE(hash_proved.division_exact);
    const auto hash_verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            shard.hash_cs, hash_proved.proof, seed, &why),
        why);
    const auto hash_verify_end = std::chrono::steady_clock::now();

    AirQuotientProofAlg canonical;
    canonical.batch = hash_proved.proof.batch;
    canonical.next_openings = hash_proved.proof.next_openings;
    canonical.trace_commit = hash_proved.proof.trace_commit;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        SerializeAirQuotientProofAlg(canonical, bytes, &why), why);
    BOOST_TEST_MESSAGE(
        "V11_MERKLE_SHARD proof_bytes=" << bytes.size()
        << " prove_ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               hash_prove_end - hash_prove_start).count()
        << " verify_us="
        << std::chrono::duration_cast<std::chrono::microseconds>(
               hash_verify_end - hash_verify_start).count()
        << " rows=" << shard.hash_trace_rows
        << " cols=" << shard.hash_layout.n_columns
        << " constraints=" << shard.hash_constraints);

    // Proof-level child substitution: the same proof must not verify after
    // changing one root-pinned operation-table input.
    auto substituted_cs = shard.hash_cs;
    BOOST_REQUIRE(!substituted_cs.preprocessed.empty());
    substituted_cs.preprocessed[0].second[0] = gf::Add(
        substituted_cs.preprocessed[0].second[0], Fp3::One());
    BOOST_CHECK(!aq::AirQuotientVerifyRows(
        substituted_cs, hash_proved.proof, seed, &why));

    auto tampered = hash_proved.proof;
    BOOST_REQUIRE(!tampered.batch.queries.empty());
    BOOST_REQUIRE(
        !tampered.batch.queries[0].row.values.empty());
    tampered.batch.queries[0].row.values[0] = gf::Add(
        tampered.batch.queries[0].row.values[0], Fp3::One());
    BOOST_CHECK(!aq::AirQuotientVerifyRows(
        shard.hash_cs, tampered, seed, &why));

    const auto fold_proved = aq::AirQuotientProveRows(
        shard.fold_cs, shard.fold_columns, seed);
    BOOST_REQUIRE_MESSAGE(fold_proved.ok, fold_proved.note);
    BOOST_REQUIRE(fold_proved.division_exact);
    BOOST_CHECK(aq::AirQuotientVerifyRows(
        shard.fold_cs, fold_proved.proof, seed, &why));
}

BOOST_AUTO_TEST_CASE(readiness_is_explicitly_fail_closed)
{
    constexpr auto readiness = CurrentReadinessV1();
    static_assert(readiness.canonical_abi_consumption_executable);
    static_assert(readiness.all_current_next_paths_executable);
    static_assert(readiness.all_fold_paths_executable);
    static_assert(readiness.fp3_fold_equations_executable);
    static_assert(readiness.bounded_poseidon_operation_table_executable);
    static_assert(!readiness.same_parent_decoder_aliases_executable);
    static_assert(!readiness.deep_quotient_executable);
    static_assert(!readiness.canonical_vm_executable);
    static_assert(!readiness.recursive_authority_ready);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold
