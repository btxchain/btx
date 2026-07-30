// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_parent_join.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <functional>

namespace matmul::v4::rc::stage3_multirow_v11_parent_join {
namespace {

using gf::Fp3;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fri3AlgDigest D(uint64_t base)
{
    return {
        gf::FromU64(base), gf::FromU64(base + 1),
        gf::FromU64(base + 2), gf::FromU64(base + 3)};
}

tp::StatementV1 Statement()
{
    tp::StatementV1 statement;
    statement.public_fs_seed =
        *uint256::FromHex(
            "1123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef");
    statement.trace_rows = 512;
    statement.trace_columns = 5;
    statement.quotient_len = 1024;
    statement.n_coeffs = 1024;
    statement.blowup = kRCFriBlowup;
    statement.base_column_indices = {0, 1};
    statement.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 2, 16384, D(10)},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 2, 3, 16384, D(20)},
        {Fri3AlgMultiRowGroupRole::Quotient, 5, 1, 16384, D(30)}}};
    statement.column_len = {512, 512, 512, 512, 512, 1024};
    for (uint32_t column = 0;
         column < statement.column_len.size(); ++column) {
        statement.evals_z1.push_back(U(100 + column));
        statement.evals_z2.push_back(U(200 + column));
    }
    uint32_t leaves = 16384;
    for (uint32_t fold = 0; fold < 11; ++fold) {
        statement.folds.push_back(
            {leaves, D(1000 + 10 * fold)});
        leaves >>= 1;
    }
    statement.final_value = U(9999);
    return statement;
}

Fri3AlgRowOpening Row(
    uint64_t value, uint32_t columns, uint32_t depth)
{
    Fri3AlgRowOpening out;
    for (uint32_t c = 0; c < columns; ++c) {
        out.values.push_back(U(value + 10 * c));
    }
    for (uint32_t i = 0; i < depth; ++i) {
        out.siblings.push_back(D(value + 100 + 10 * i));
    }
    return out;
}

abi::EnvelopeV1 Envelope(
    const tp::StatementV1& statement,
    const tp::ReceiptV1& receipt)
{
    abi::EnvelopeV1 out;
    for (uint32_t word = 0; word < 4; ++word) {
        const uint64_t value =
            statement.public_fs_seed.GetUint64(word);
        out.public_fs_seed[2 * word] =
            static_cast<uint32_t>(value);
        out.public_fs_seed[2 * word + 1] =
            static_cast<uint32_t>(value >> 32);
    }
    out.trace_columns = statement.trace_columns;
    out.quotient_len = statement.quotient_len;
    auto& split = out.split;
    split.version = 1;
    split.trace_rows = statement.trace_rows;
    split.base_column_indices =
        statement.base_column_indices;
    split.air_constraint_lambda = receipt.air_lambda;
    auto& batch = split.batch;
    batch.version = kRCFri3AlgMultiRowBatchProofVersion;
    batch.pow_grind_nonce = 0;
    batch.blowup = statement.blowup;
    batch.n_coeffs = statement.n_coeffs;
    for (const auto& group : statement.groups) {
        batch.groups.push_back({
            group.role, group.first_column, group.column_count,
            {group.root, group.n_leaves}});
    }
    batch.column_len = statement.column_len;
    batch.lambda = receipt.air_lambda;
    batch.z1 = receipt.z1;
    batch.z2 = receipt.z2;
    batch.evals_z1 = statement.evals_z1;
    batch.evals_z2 = statement.evals_z2;
    batch.w1 = receipt.w1;
    batch.w2 = receipt.w2;
    for (const auto& fold : statement.folds) {
        batch.fold_layers.push_back(
            {fold.root, fold.n_leaves});
    }
    batch.final_value = statement.final_value;
    batch.fold_challenges = receipt.fold_challenges;
    const uint32_t depth = 14;
    batch.queries.resize(abi::kQueryCountV11);
    split.next_trace_group_rows.resize(
        abi::kQueryCountV11);
    for (uint32_t q = 0;
         q < abi::kQueryCountV11; ++q) {
        auto& query = batch.queries[q];
        query.index = receipt.queries[q].index;
        query.group_rows = {
            Row(2000 + 100 * q, 2, depth),
            Row(3000 + 100 * q, 3, depth),
            Row(4000 + 100 * q, 1, depth)};
        uint32_t index = query.index;
        for (uint32_t fold = 0;
             fold < receipt.fold_challenges.size(); ++fold) {
            Fri3AlgFoldStep step;
            const uint32_t half =
                (statement.n_coeffs * statement.blowup >> fold) /
                2;
            step.even_index = index % half;
            step.odd_index = step.even_index + half;
            step.even = U(5000 + 100 * q + fold);
            step.odd = U(6000 + 100 * q + fold);
            for (uint32_t i = 0; i < depth - fold; ++i) {
                step.even_siblings.push_back(
                    D(7000 + 1000 * q + 20 * fold + i));
                step.odd_siblings.push_back(
                    D(8000 + 1000 * q + 20 * fold + i));
            }
            query.steps.push_back(std::move(step));
            index %= half;
        }
        split.next_trace_group_rows[q] = {
            Row(9000 + 100 * q, 2, depth),
            Row(10000 + 100 * q, 3, depth)};
    }
    return out;
}

struct Fixture {
    tp::ProductV1 replay;
    cb::ProductV1 consumer;
    abi::DecodedV1 decoded;
    std::vector<abi::ParentPublicCellV1> parent;
    ProductV1 product;
};

Fixture MakeFixture(
    const std::function<void(
        std::vector<abi::ParentPublicCellV1>&)>&
        mutate_parent = {})
{
    static const Fixture base = [] {
        Fixture out;
        out.replay = tp::BuildProductV1(Statement());
        BOOST_REQUIRE_MESSAGE(out.replay.valid, out.replay.note);
        out.consumer = cb::BuildProductV1(out.replay);
        BOOST_REQUIRE_MESSAGE(out.consumer.valid, out.consumer.note);
        std::vector<uint32_t> words;
        std::string why;
        const auto envelope =
            Envelope(out.replay.statement, out.replay.receipt);
        BOOST_REQUIRE_MESSAGE(
            abi::EncodeCanonicalV1(
                envelope, words, nullptr, &why),
            why);
        const auto decoded =
            abi::DecodeCanonicalV1(words, &why);
        BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
        out.decoded = *decoded;
        uint32_t parent_column = 100;
        for (const auto& source : out.decoded.sources) {
            if (source.ownership ==
                abi::OwnershipClassV1::PublicStatement) {
                out.parent.push_back({
                    source.key, parent_column++, source.value});
            }
        }
        out.product = BuildProductV1(
            out.decoded, out.parent,
            out.replay, out.consumer);
        return out;
    }();
    Fixture out = base;
    if (mutate_parent) {
        mutate_parent(out.parent);
        out.product = BuildProductV1(
            out.decoded, out.parent,
            out.replay, out.consumer);
    }
    return out;
}

std::pair<uint32_t, uint32_t> FirstPublicAbsorb(
    const ProductV1& product)
{
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        for (uint32_t lane = 0;
             lane < kPublicAbsorbSlotsV1; ++lane) {
            if (gf::Eq(
                    product.columns[
                        product.layout.public_absorb[lane].active][row],
                    Fp3::One())) {
                return {row, lane};
            }
        }
    }
    return {product.cs.n_rows, kPublicAbsorbSlotsV1};
}

std::vector<uint32_t> CandidateRows(const ProductV1& product)
{
    std::vector<uint32_t> rows;
    for (uint32_t row = 0; row < product.cs.n_rows; ++row) {
        if (gf::Eq(
                product.columns[
                    product.layout.replay.query_candidate_active][row],
                Fp3::One())) {
            rows.push_back(row);
        }
    }
    return rows;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_parent_join_tests)

BOOST_AUTO_TEST_CASE(
    actual_parent_air_closes_public_and_derived_cell_joins)
{
    const auto fixture = MakeFixture();
    const auto& product = fixture.product;
    BOOST_TEST_MESSAGE(
        "v11 parent join valid=" << product.valid
        << " rows=" << product.cs.n_rows
        << " columns=" << product.cs.n_columns
        << " constraints=" << product.constraints
        << " note=" << product.note);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.public_inventory_exact);
    BOOST_CHECK(product.public_parent_columns_root_pinned);
    BOOST_CHECK(product.public_claims_equal_parent_air_constrained);
    BOOST_CHECK(product.public_claims_equal_replay_air_constrained);
    BOOST_CHECK(
        product.derived_candidates_equal_replay_air_constrained);
    BOOST_CHECK(
        product.selected_ordinals_equal_replay_air_constrained);
    BOOST_CHECK(
        product.selected_query_indices_equal_proof_air_constrained);
    BOOST_CHECK(
        product.independent_coefficients_direct_replay_alias);
    BOOST_CHECK(
        product.canonical_u64_decomposition_air_constrained);
    BOOST_CHECK(product.exact_ordered_preprocessed_root);
    BOOST_CHECK(product.canonical_abi_claim_cells_air_joined);
    BOOST_CHECK(!product.backend_v11_proof_cells_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK_EQUAL(
        product.public_source_cells,
        fixture.decoded.public_statement_cells);
    BOOST_CHECK_EQUAL(
        product.derived_candidate_cells,
        abi::kQueryCountV11 *
            (abi::kQueryCandidatesV11 * 8 + 1));
    BOOST_CHECK_EQUAL(
        product.query_index_cells,
        abi::kQueryCountV11);
    BOOST_CHECK_EQUAL(
        product.coefficient_replay_rows.size(),
        fixture.replay.statement.column_len.size());
    // The PAD0 rows are independently domain-separated padding witnesses,
    // not additional transcript events. Counting all 478 terminal-marked
    // rows as the 424-event transcript caused the original inventory defect.
    BOOST_CHECK_EQUAL(product.replay_hash_events, 424U);
    BOOST_CHECK_EQUAL(product.replay_real_sponge_rows, 458U);
    BOOST_CHECK_EQUAL(product.replay_terminal_events, 424U);
    BOOST_CHECK_EQUAL(product.padding_terminal_rows, 54U);
    BOOST_CHECK_LE(product.max_constraint_degree, 2U);
    BOOST_CHECK(!product.preprocessed_row_group_root.IsNull());
}

BOOST_AUTO_TEST_CASE(
    simultaneous_claim_expected_and_replay_mutation_cannot_float)
{
    const auto fixture = MakeFixture();
    BOOST_REQUIRE(fixture.product.valid);
    auto forged = fixture.product.columns;
    const auto [row, lane] =
        FirstPublicAbsorb(fixture.product);
    BOOST_REQUIRE_LT(row, fixture.product.cs.n_rows);
    const auto slot =
        fixture.product.layout.public_absorb[lane];
    forged[slot.claim][row] =
        gf::Add(forged[slot.claim][row], Fp3::One());
    forged[slot.expected][row] =
        gf::Add(forged[slot.expected][row], Fp3::One());
    // The old free-expected defect accepted the first two mutations.
    // Mutating the replay source as well still changes fixed R0 and the
    // Poseidon execution, so no "move all aliases together" attack exists.
    forged[
        fixture.product.layout.replay.Absorb(lane)][row] =
        gf::Add(
            forged[
                fixture.product.layout.replay.Absorb(lane)][row],
            Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(fixture.product, forged), 0U);
}

BOOST_AUTO_TEST_CASE(
    public_root_shape_base_and_ali_substitution_reject)
{
    for (uint32_t ordinal = 0; ordinal < 4; ++ordinal) {
        const auto fixture = MakeFixture(
            [ordinal](auto& parent) {
                const std::array<abi::FieldKindV1, 4> kinds{
                    abi::FieldKindV1::PublicFsSeed,
                    abi::FieldKindV1::TraceRows,
                    abi::FieldKindV1::BaseColumnIndex,
                    abi::FieldKindV1::AirConstraintLambda};
                const auto found = std::find_if(
                    parent.begin(), parent.end(),
                    [&](const auto& cell) {
                        return cell.key.kind == kinds[ordinal];
                    });
                BOOST_REQUIRE(found != parent.end());
                found->value ^= 1;
            });
        BOOST_CHECK(!fixture.product.valid);
    }
}

BOOST_AUTO_TEST_CASE(
    omitted_duplicate_and_relabelled_addresses_reject)
{
    {
        const auto fixture = MakeFixture(
            [](auto& parent) { parent.pop_back(); });
        BOOST_CHECK(!fixture.product.valid);
    }
    {
        const auto fixture = MakeFixture(
            [](auto& parent) {
                BOOST_REQUIRE_GE(parent.size(), 2U);
                parent[1].parent_column =
                    parent[0].parent_column;
            });
        BOOST_CHECK(!fixture.product.valid);
    }
    {
        const auto fixture = MakeFixture();
        BOOST_REQUIRE(fixture.product.valid);
        auto forged = fixture.product.columns;
        const auto [row, lane] =
            FirstPublicAbsorb(fixture.product);
        const auto address =
            fixture.product.layout.public_absorb[lane]
                .source_address;
        forged[address][row] =
            gf::Add(forged[address][row], Fp3::One());
        // Addresses are metadata with no witness equation; only the fixed
        // ordered root stops this relabel.
        BOOST_CHECK_GT(
            RecountViolationsV1(fixture.product, forged), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    derived_candidate_query_and_coefficient_relabel_reject)
{
    const auto fixture = MakeFixture();
    BOOST_REQUIRE(fixture.product.valid);
    const auto rows = CandidateRows(fixture.product);
    BOOST_REQUIRE_GE(rows.size(), 4U);
    {
        auto forged = fixture.product.columns;
        const auto split =
            fixture.product.layout.candidate_digest[0];
        std::swap(
            forged[split.claim_lo][rows[0]],
            forged[split.claim_lo][rows[2]]);
        BOOST_CHECK_GT(
            RecountViolationsV1(fixture.product, forged), 0U);
    }
    {
        auto forged = fixture.product.columns;
        std::swap(
            forged[fixture.product.layout.query_index_claim][rows[0]],
            forged[fixture.product.layout.query_index_claim][rows[2]]);
        std::swap(
            forged[fixture.product.layout.query_index_claim][rows[1]],
            forged[fixture.product.layout.query_index_claim][rows[3]]);
        BOOST_CHECK_GT(
            RecountViolationsV1(fixture.product, forged), 0U);
    }
    {
        auto forged = fixture.product.columns;
        BOOST_REQUIRE_GE(
            fixture.product.coefficient_replay_rows.size(), 2U);
        const uint32_t row =
            fixture.product.coefficient_replay_rows[0];
        forged[fixture.product.layout.coefficient_label][row] =
            U(1);
        BOOST_CHECK_GT(
            RecountViolationsV1(fixture.product, forged), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    goldilocks_x_plus_p_decomposition_is_explicitly_rejected)
{
    const auto fixture = MakeFixture();
    BOOST_REQUIRE(fixture.product.valid);
    auto row = std::vector<Fp3>(
        fixture.product.cs.n_columns, Fp3::Zero());
    const auto split =
        fixture.product.layout.candidate_digest[0];
    constexpr uint64_t x = 5;
    const uint64_t alias = gf::kP + x;
    row[split.active] = Fp3::One();
    row[split.claim_lo] =
        U(static_cast<uint32_t>(alias));
    row[split.claim_hi] =
        U(static_cast<uint32_t>(alias >> 32));
    for (uint32_t bit = 0; bit < 64; ++bit) {
        row[split.Bit(bit)] =
            ((alias >> bit) & 1U) != 0
            ? Fp3::One() : Fp3::Zero();
    }
    bool high_and = true;
    for (uint32_t bit = 0; bit < 32; ++bit) {
        high_and =
            high_and && ((alias >> (32 + bit)) & 1U) != 0;
        row[split.HighAnd(bit)] =
            high_and ? Fp3::One() : Fp3::Zero();
    }
    row[split.low_nonzero] = Fp3::One();
    row[split.low_inverse] =
        gf::Inv(row[split.claim_lo]);
    uint32_t canonical_violations = 0;
    for (const auto& constraint :
         fixture.product.cs.constraints) {
        if (std::string{constraint.name} ==
                "stage3.v11_parent_join."
                "split_goldilocks_canonical" &&
            !gf::IsZero(constraint.eval(row, row))) {
            ++canonical_violations;
        }
    }
    BOOST_CHECK_GT(canonical_violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    optional_outer_proof_roundtrip_and_proof_level_tamper_reject)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_V11_PARENT_JOIN_PROOF") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_V11_PARENT_JOIN_PROOF=1 for "
            "the full parent-join Split-RAP proof measurement");
        return;
    }
    const auto fixture = MakeFixture();
    BOOST_REQUIRE_MESSAGE(
        fixture.product.valid, fixture.product.note);
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            fixture.product.cs,
            fixture.product.columns,
            fixture.product.preprocessed_columns,
            uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() -
            prove_start).count();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    const auto verify_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            fixture.product.cs, proved.proof,
            fixture.product.preprocessed_columns,
            uint256::ONE, &why),
        why);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() -
            verify_start).count();
    std::vector<unsigned char> wire;
    const size_t bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    BOOST_REQUIRE_EQUAL(bytes, wire.size());
    BOOST_REQUIRE_NE(bytes, 0U);

    auto forged = proved.proof;
    BOOST_REQUIRE_EQUAL(forged.batch.groups.size(), 3U);
    forged.batch.groups[0].row_commit.root[0] =
        gf::Add(
            forged.batch.groups[0].row_commit.root[0],
            gf::FromU64(1));
    why.clear();
    BOOST_CHECK_MESSAGE(
        !aq::AirQuotientVerifyRowsSplitRap(
            fixture.product.cs, forged,
            fixture.product.preprocessed_columns,
            uint256::ONE, &why),
        "proof-level root substitution unexpectedly accepted");
    BOOST_TEST_MESSAGE(
        "v11 parent-join outer-V2 proof_bytes=" << bytes
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us
        << " proof_level_root_tamper_rejected=1"
        << " rows=" << fixture.product.cs.n_rows
        << " columns=" << fixture.product.cs.n_columns);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_parent_join
