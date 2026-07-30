// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_decoder_join.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <map>

namespace matmul::v4::rc::stage3_multirow_v11_decoder_join {
namespace {

using Digest = alg_hash::Digest;
namespace tp = stage3_multirow_p2_transcript;

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
    Tree out;
    out.levels.emplace_back(leaves);
    for (uint32_t index = 0; index < leaves; ++index) {
        out.levels[0][index] = leaf(index);
    }
    for (uint32_t width = leaves; width > 1; width >>= 1) {
        out.levels.emplace_back(width / 2);
        for (uint32_t index = 0; index < width / 2; ++index) {
            out.levels.back()[index] = alg_hash::Compress(
                out.levels[out.levels.size() - 2][2 * index],
                out.levels[out.levels.size() - 2][2 * index + 1]);
        }
    }
    out.root = out.levels.back()[0];
    return out;
}

struct Fixture {
    abi::EnvelopeV1 envelope;
    abi::DecodedV1 decoded;
    tp::StatementV1 statement;
    tp::ReceiptV1 transcript;
    tp::ProductV1 replay;
    stage3_multirow_p2_consumer_bridge::ProductV1 consumer;
    djp::ProductV1 parent;
    mf::ShardProductV1 shard;
    ProductV1 product;
    std::vector<uint32_t> words;
};

Fixture BuildFixture()
{
    constexpr uint32_t trace_rows = 256;
    constexpr uint32_t n_coeffs = 256;
    constexpr uint32_t blowup = kRCFriBlowup;
    constexpr uint32_t n_lde = n_coeffs * blowup;
    const gf::Fp3 zero = gf::Fp3::Zero();

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
    for (uint32_t word = 0;
         word < fixture.envelope.public_fs_seed.size(); ++word) {
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

    auto& statement = fixture.statement;
    for (uint32_t word = 0; word < 8; ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            statement.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    fixture.envelope.public_fs_seed[word] >> (8 * byte));
        }
    }
    statement.trace_rows = trace_rows;
    statement.trace_columns = fixture.envelope.trace_columns;
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
    batch.lambda = fixture.transcript.air_lambda;
    batch.z1 = fixture.transcript.z1;
    batch.z2 = fixture.transcript.z2;
    batch.w1 = fixture.transcript.w1;
    batch.w2 = fixture.transcript.w2;
    batch.fold_challenges = fixture.transcript.fold_challenges;

    batch.queries.resize(abi::kQueryCountV11);
    split.next_trace_group_rows.resize(abi::kQueryCountV11);
    for (uint32_t q = 0; q < abi::kQueryCountV11; ++q) {
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
    fixture.replay = tp::BuildProductV1(statement);
    BOOST_REQUIRE_MESSAGE(fixture.replay.valid, fixture.replay.note);
    fixture.consumer =
        stage3_multirow_p2_consumer_bridge::BuildProductV1(
            fixture.replay);
    BOOST_REQUIRE_MESSAGE(fixture.consumer.valid, fixture.consumer.note);
    std::vector<abi::ParentPublicCellV1> parent_public;
    uint32_t parent_column = 100;
    for (const auto& source : fixture.decoded.sources) {
        if (source.ownership == abi::OwnershipClassV1::PublicStatement) {
            parent_public.push_back({
                source.key, parent_column++, source.value});
        }
    }
    fixture.parent = djp::BuildProductV1(
        fixture.decoded, parent_public,
        fixture.replay, fixture.consumer);
    BOOST_REQUIRE_MESSAGE(fixture.parent.valid, fixture.parent.note);
    fixture.shard = mf::BuildShardV1(
        fixture.decoded, fixture.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(fixture.shard.valid, fixture.shard.note);
    fixture.product = BuildProductV1(
        fixture.decoded, fixture.parent, {fixture.shard});
    return fixture;
}

const Fixture& Honest()
{
    static const Fixture fixture = BuildFixture();
    return fixture;
}

std::pair<uint32_t, uint32_t> RowsForOccurrence(
    const ProductV1& product, uint32_t occurrence)
{
    uint32_t source = product.trace_rows;
    uint32_t consumer = product.trace_rows;
    for (uint32_t row = 0; row < product.real_rows; ++row) {
        if (gf::Canonical(
                product.columns[
                    product.layout.source_occurrence][row].c0) ==
            occurrence) {
            source = row;
        }
        if (gf::Canonical(
                product.columns[
                    product.layout.consumer_occurrence][row].c0) ==
            occurrence) {
            consumer = row;
        }
    }
    return {source, consumer};
}

void RebuildKnownChallengeBus(
    const ProductV1& product,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    const auto& l = product.layout;
    for (uint32_t lane = 0;
         lane < kDecoderJoinBusLanesV1; ++lane) {
        const auto compressed =
            [&](uint32_t row, bool source) {
                gf::Fp3 power = gf::Fp3::One();
                gf::Fp3 term = product.alpha[lane];
                const std::array<uint32_t, 4> tuple{
                    source ? l.source_kind : l.consumer_kind,
                    source ? l.source_occurrence : l.consumer_occurrence,
                    source ? l.source_address : l.consumer_address,
                    source ? l.source_value : l.consumer_claim};
                for (uint32_t column : tuple) {
                    power = gf::Mul(power, product.gamma[lane]);
                    term = gf::Add(
                        term, gf::Mul(power, columns[column][row]));
                }
                return term;
            };
        for (uint32_t row = 0; row < product.trace_rows; ++row) {
            if (gf::Eq(columns[l.active][row], gf::Fp3::One())) {
                columns[l.source_inverse[lane]][row] =
                    gf::Inv(compressed(row, true));
                columns[l.consumer_inverse[lane]][row] =
                    gf::Inv(compressed(row, false));
            } else {
                columns[l.source_inverse[lane]][row] = gf::Fp3::Zero();
                columns[l.consumer_inverse[lane]][row] = gf::Fp3::Zero();
            }
        }
        gf::Fp3 running = gf::Fp3::Zero();
        for (uint32_t row = 0; row < product.trace_rows; ++row) {
            columns[l.running[lane]][row] = running;
            running = gf::Add(
                running,
                gf::Sub(
                    columns[l.source_inverse[lane]][row],
                    columns[l.consumer_inverse[lane]][row]));
        }
    }
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_decoder_join_tests)

BOOST_AUTO_TEST_CASE(
    exact_same_parent_inventory_closes_with_dual_logup)
{
    const auto& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_TEST_MESSAGE(
        "V11 decoder join rows=" << product.trace_rows
        << " real=" << product.real_rows
        << " columns=" << product.cs.n_columns
        << " occurrences=" << product.source_occurrences.size()
        << " constraints=" << product.constraints
        << " note=" << product.note);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.canonical_abi);
    BOOST_CHECK(product.parent_replay_exactly_matches_decoded);
    BOOST_CHECK(product.parent_root_recomputed);
    BOOST_CHECK(product.child_roots_recomputed);
    BOOST_CHECK(product.exact_occurrence_inventory);
    BOOST_CHECK(product.all_logup_tuple_cells_precommitted);
    BOOST_CHECK(product.challenges_after_join_precommit);
    BOOST_CHECK(
        product.join_tuple_precommit_root ==
        product.preprocessed_row_group_root);
    BOOST_CHECK(product.dual_rational_identity_air_constrained);
    BOOST_CHECK(product.terminal_sums_zero);
    BOOST_CHECK(product.consumer_claims_equal_root_pinned_cells);
    BOOST_CHECK(product.ordered_preprocessed_root_pinned);
    BOOST_CHECK(product.canonical_u32_and_fp_pairs);
    BOOST_CHECK(product.duplicate_query_identity_preserved);
    BOOST_CHECK(product.same_parent_decoder_aliases_executable);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK_EQUAL(product.child_roots.size(), 3U);
    BOOST_CHECK_LE(product.max_constraint_degree, 2U);
    BOOST_CHECK(!product.preprocessed_row_group_root.IsNull());
}

BOOST_AUTO_TEST_CASE(
    claimed_expected_omission_duplication_reorder_and_alias_reject)
{
    const auto& product = Honest().product;
    BOOST_REQUIRE(product.valid);
    const auto [source0, consumer0] = RowsForOccurrence(product, 0);
    BOOST_REQUIRE_LT(source0, product.real_rows);
    BOOST_REQUIRE_LT(consumer0, product.real_rows);

    // Moving both the source and expected/claim together was the historical
    // free-expected attack.  Both expected tables are now R0-pinned.
    {
        auto forged = product.columns;
        forged[product.layout.source_value][source0] =
            gf::Add(
                forged[product.layout.source_value][source0],
                gf::Fp3::One());
        forged[product.layout.consumer_pin][consumer0] =
            gf::Add(
                forged[product.layout.consumer_pin][consumer0],
                gf::Fp3::One());
        forged[product.layout.consumer_claim][consumer0] =
            forged[product.layout.consumer_pin][consumer0];
        // Even when the malicious prover knows the old challenges and
        // consistently rebuilds every dependent LogUp column, the changed
        // source/consumer tuple has a different R0 precommit.
        RebuildKnownChallengeBus(product, forged);
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
    {
        auto forged = product.columns;
        forged[product.layout.active][source0] = gf::Fp3::Zero();
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
    {
        auto forged = product.columns;
        const auto [source1, consumer1] = RowsForOccurrence(product, 1);
        BOOST_REQUIRE_LT(consumer1, product.real_rows);
        for (uint32_t column : {
                 product.layout.consumer_kind,
                 product.layout.consumer_occurrence,
                 product.layout.consumer_address,
                 product.layout.consumer_pin,
                 product.layout.consumer_claim}) {
            forged[column][consumer1] = forged[column][consumer0];
        }
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
        (void)source1;
    }
    {
        auto forged = product.columns;
        const auto [source1, consumer1] = RowsForOccurrence(product, 1);
        BOOST_REQUIRE_LT(consumer1, product.real_rows);
        std::swap(
            forged[product.layout.consumer_pin][consumer0],
            forged[product.layout.consumer_pin][consumer1]);
        forged[product.layout.consumer_claim][consumer0] =
            forged[product.layout.consumer_pin][consumer0];
        forged[product.layout.consumer_claim][consumer1] =
            forged[product.layout.consumer_pin][consumer1];
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
        (void)source1;
    }
    {
        auto forged = product.columns;
        forged[product.layout.root_value][0] =
            gf::Add(
                forged[product.layout.root_value][0],
                gf::Fp3::One());
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
    {
        // p = 0xffffffff00000001.  Replacing a canonical field pair by p,
        // while changing both table sides, still changes fixed R0.
        auto forged = product.columns;
        uint32_t low_occurrence = product.real_rows;
        uint32_t high_occurrence = product.real_rows;
        for (uint32_t i = 0; i + 1 < product.source_occurrences.size(); ++i) {
            const auto& lo = product.source_occurrences[i];
            const auto& hi = product.source_occurrences[i + 1];
            if (lo.source_address + 1 == hi.source_address) {
                low_occurrence = lo.occurrence_id;
                high_occurrence = hi.occurrence_id;
                break;
            }
        }
        BOOST_REQUIRE_LT(low_occurrence, product.real_rows);
        const auto [sl, cl] = RowsForOccurrence(product, low_occurrence);
        const auto [sh, ch] = RowsForOccurrence(product, high_occurrence);
        forged[product.layout.source_value][sl] = gf::FromU64_3(1);
        forged[product.layout.source_value][sh] =
            gf::FromU64_3(0xffffffffU);
        forged[product.layout.consumer_pin][cl] = gf::FromU64_3(1);
        forged[product.layout.consumer_pin][ch] =
            gf::FromU64_3(0xffffffffU);
        forged[product.layout.consumer_claim][cl] =
            forged[product.layout.consumer_pin][cl];
        forged[product.layout.consumer_claim][ch] =
            forged[product.layout.consumer_pin][ch];
        BOOST_CHECK_GT(RecountViolationsV1(product, forged), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    duplicate_query_values_keep_distinct_occurrence_addresses)
{
    const auto& fixture = Honest();
    std::map<uint32_t, std::vector<uint32_t>> queries;
    for (uint32_t q = 0;
         q < fixture.decoded.envelope.split.batch.queries.size(); ++q) {
        queries[
            fixture.decoded.envelope.split.batch.queries[q].index]
            .push_back(q);
    }
    const auto duplicate = std::find_if(
        queries.begin(), queries.end(),
        [](const auto& item) { return item.second.size() > 1; });
    BOOST_REQUIRE(duplicate != queries.end());
    const uint32_t q0 = duplicate->second[0];
    const uint32_t q1 = duplicate->second[1];
    const auto a0 = abi::FindSourceAddressV1(
        fixture.decoded.sources,
        {abi::FieldKindV1::QueryIndex, q0, 0, 0, 0, 0});
    const auto a1 = abi::FindSourceAddressV1(
        fixture.decoded.sources,
        {abi::FieldKindV1::QueryIndex, q1, 0, 0, 0, 0});
    BOOST_REQUIRE(a0.has_value());
    BOOST_REQUIRE(a1.has_value());
    BOOST_CHECK_NE(*a0, *a1);
    BOOST_CHECK_EQUAL(
        fixture.decoded.sources[*a0].value,
        fixture.decoded.sources[*a1].value);
}

BOOST_AUTO_TEST_CASE(
    optional_proof_level_join_and_semantic_forgery_rejects)
{
    if (std::getenv("BTX_RUN_STAGE3_V11_DECODER_JOIN_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V11_DECODER_JOIN_PROOF=1 for "
            "full Split-RAP proof-level join attacks");
        return;
    }
    const auto& product = Honest().product;
    const uint256 seed = uint256::ONE;
    const auto proved = aq::AirQuotientProveRowsSplitRap(
        product.cs, product.columns,
        product.preprocessed_columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            product.cs, proved.proof,
            product.preprocessed_columns, seed, &why),
        why);

    // Proof-level child-root substitution.
    auto root_forgery = proved.proof;
    BOOST_REQUIRE(!root_forgery.batch.groups.empty());
    root_forgery.batch.groups[0].row_commit.root[0] = gf::Add(
        root_forgery.batch.groups[0].row_commit.root[0],
        gf::FromU64(1));
    BOOST_CHECK(!aq::AirQuotientVerifyRowsSplitRap(
        product.cs, root_forgery,
        product.preprocessed_columns, seed, &why));

    // A trace containing the simultaneous claimed+expected attack cannot
    // produce a verifying proof under the honest preprocessed root.
    auto forged_columns = product.columns;
    const auto [source, consumer] = RowsForOccurrence(product, 0);
    forged_columns[product.layout.source_value][source] =
        gf::Add(
            forged_columns[product.layout.source_value][source],
            gf::Fp3::One());
    forged_columns[product.layout.consumer_pin][consumer] =
        gf::Add(
            forged_columns[product.layout.consumer_pin][consumer],
            gf::Fp3::One());
    forged_columns[product.layout.consumer_claim][consumer] =
        forged_columns[product.layout.consumer_pin][consumer];
    const auto forged = aq::AirQuotientProveRowsSplitRap(
        product.cs, forged_columns,
        product.preprocessed_columns, seed);
    BOOST_CHECK(
        !forged.ok || !forged.division_exact ||
        !aq::AirQuotientVerifyRowsSplitRap(
            product.cs, forged.proof,
            product.preprocessed_columns, seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_decoder_join
