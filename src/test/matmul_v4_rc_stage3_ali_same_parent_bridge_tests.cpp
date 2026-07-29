// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_ali_same_parent_bridge.h>

#include <chrono>

namespace bridge =
    matmul::v4::rc::stage3_ali_same_parent_bridge;
namespace gf = matmul::v4::rc::gkr_field;
namespace aq = matmul::v4::rc::air_quotient;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_ali_same_parent_bridge_tests)

namespace {

uint256 Root(uint32_t value)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size();
         ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                (value + 29U * index) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

struct Fixture {
    bridge::CanonicalAliVmStatementV1 statement;
    bridge::AliSameParentRefsV1 refs;
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
};

bridge::CellPairV1 Install(
    Fixture& fixture,
    const gf::Fp3& value,
    uint32_t ordinal)
{
    const uint32_t producer =
        fixture.cs.n_columns++;
    const uint32_t consumer =
        fixture.cs.n_columns++;
    fixture.columns.resize(
        fixture.cs.n_columns,
        std::vector<gf::Fp3>(
            fixture.cs.n_rows,
            gf::Fp3::Zero()));
    const uint32_t producer_row =
        2 + ordinal % 11;
    const uint32_t consumer_row =
        32 + ordinal % 13;
    fixture.columns[producer][producer_row] =
        value;
    fixture.columns[consumer][consumer_row] =
        value;
    return {
        {producer, producer_row},
        {consumer, consumer_row}};
}

Fixture HonestFixture(uint32_t family_index = 5)
{
    Fixture fixture;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildCanonicalAliVmStatementV1(
            family_index,
            fixture.statement, &why),
        why);
    fixture.refs.family_index = family_index;
    fixture.cs.n_rows = 256;
    uint32_t ordinal = 0;
    for (uint32_t lane = 0;
         lane < bridge::kAliDigestLanesV1;
         ++lane) {
        fixture.refs.manifest_commitment[lane] =
            Install(
                fixture,
                gf::Fp3::FromFp(
                    fixture.statement
                        .manifest_commitment[lane]),
                ordinal++);
        fixture.refs.source_program_key[lane] =
            Install(
                fixture,
                gf::Fp3::FromFp(
                    fixture.statement
                        .source_program_key[lane]),
                ordinal++);
        fixture.refs.compiled_program_key[lane] =
            Install(
                fixture,
                gf::Fp3::FromFp(
                    fixture.statement
                        .compiled_program_key[lane]),
                ordinal++);
    }
    for (const auto& word : fixture.statement.words) {
        fixture.refs.words.push_back({
            word.kind, word.ordinal,
            Install(
                fixture,
                gf::Fp3::FromFp(
                    gf::FromU64(word.value)),
                ordinal++)});
    }
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_manifest_keys_degree_constraints_rows_and_cap_append)
{
    auto fixture = HonestFixture();
    const uint32_t original_columns =
        fixture.cs.n_columns;
    bridge::AppendResultV1 result;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::AppendAliSameParentBridgeV1(
            fixture.cs, fixture.columns,
            fixture.refs, result, &why),
        why);
    BOOST_CHECK(result.valid);
    BOOST_CHECK_EQUAL(
        result.manifest_commitment_equalities, 4U);
    BOOST_CHECK_EQUAL(result.source_key_equalities, 4U);
    BOOST_CHECK_EQUAL(result.compiled_key_equalities, 4U);
    BOOST_CHECK_EQUAL(
        result.statement_word_equalities,
        fixture.statement.words.size());
    BOOST_CHECK_EQUAL(
        result.equality_count,
        12U + fixture.statement.words.size());
    BOOST_CHECK_GT(result.degree_words_constrained, 0U);
    BOOST_CHECK_GT(
        result.constraint_count_words_constrained, 0U);
    BOOST_CHECK_GT(
        result.row_and_cap_words_constrained, 0U);
    BOOST_CHECK(
        result.exact_manifest_commitment_root_pinned);
    BOOST_CHECK(
        result.exact_source_and_compiled_keys_pinned);
    BOOST_CHECK(
        result.exact_word_order_and_values_pinned);
    BOOST_CHECK(result.literal_parent_refs_reused);
    BOOST_CHECK(result.cross_row_transport_constrained);
    BOOST_CHECK(
        result.only_position_selectors_preprocessed);
    BOOST_CHECK(!result.actual_values_preprocessed);
    BOOST_CHECK(
        !result.normalized_vm_cell_ownership_proved);
    BOOST_CHECK(
        !result.canonical_manifest_hash_replayed_in_parent);
    BOOST_CHECK(!result.recursively_consumed);
    BOOST_CHECK(!result.recursive_authority);
    BOOST_CHECK_GT(fixture.cs.n_columns, original_columns);
    BOOST_CHECK_EQUAL(
        bridge::CountViolationsV1(
            fixture.cs, fixture.columns),
        0U);

    const auto consumer =
        fixture.refs.words[13].
            cells.normalized_vm_consumer;
    fixture.columns[consumer.column][consumer.row] =
        gf::Add(
            fixture.columns[consumer.column][consumer.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        bridge::CountViolationsV1(
            fixture.cs, fixture.columns),
        0U);
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_duplicate_preprocessed_and_x_plus_p_reject)
{
    {
        auto fixture = HonestFixture();
        fixture.refs.words.pop_back();
        const uint32_t before = fixture.cs.n_columns;
        bridge::AppendResultV1 result;
        BOOST_CHECK(
            !bridge::AppendAliSameParentBridgeV1(
                fixture.cs, fixture.columns,
                fixture.refs, result));
        BOOST_CHECK_EQUAL(fixture.cs.n_columns, before);
    }
    {
        auto fixture = HonestFixture();
        std::swap(
            fixture.refs.words[2],
            fixture.refs.words[3]);
        bridge::AppendResultV1 result;
        BOOST_CHECK(
            !bridge::AppendAliSameParentBridgeV1(
                fixture.cs, fixture.columns,
                fixture.refs, result));
    }
    {
        auto fixture = HonestFixture();
        fixture.refs.words[7].cells =
            fixture.refs.words[6].cells;
        bridge::AppendResultV1 result;
        BOOST_CHECK(
            !bridge::AppendAliSameParentBridgeV1(
                fixture.cs, fixture.columns,
                fixture.refs, result));
    }
    {
        auto fixture = HonestFixture();
        const auto cell =
            fixture.refs.source_program_key[1].
                manifest_producer;
        fixture.cs.preprocessed.push_back({
            cell.column,
            fixture.columns[cell.column]});
        bridge::AppendResultV1 result;
        BOOST_CHECK(
            !bridge::AppendAliSameParentBridgeV1(
                fixture.cs, fixture.columns,
                fixture.refs, result));
    }
    {
        auto fixture = HonestFixture();
        size_t zero_word = 0;
        while (zero_word <
                   fixture.statement.words.size() &&
               fixture.statement.words[zero_word].value !=
                   0) {
            ++zero_word;
        }
        BOOST_REQUIRE_LT(
            zero_word,
            fixture.statement.words.size());
        const auto& cells =
            fixture.refs.words[zero_word].cells;
        fixture.columns[
            cells.manifest_producer.column]
            [cells.manifest_producer.row] =
            gf::Fp3{gf::kP, 0, 0};
        fixture.columns[
            cells.normalized_vm_consumer.column]
            [cells.normalized_vm_consumer.row] =
            gf::Fp3{gf::kP, 0, 0};
        bridge::AppendResultV1 result;
        BOOST_CHECK(
            !bridge::AppendAliSameParentBridgeV1(
                fixture.cs, fixture.columns,
                fixture.refs, result));
    }
}

BOOST_AUTO_TEST_CASE(
    compact_air_roundtrip_and_proof_level_tamper_reject)
{
    auto fixture = HonestFixture();
    bridge::AppendResultV1 result;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::AppendAliSameParentBridgeV1(
            fixture.cs, fixture.columns,
            fixture.refs, result, &why),
        why);
    const uint256 seed = Root(0xa11);
    const auto prove_begin =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRows(
            fixture.cs, fixture.columns, seed);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    const auto verify_begin =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            fixture.cs, proved.proof, seed, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();

    matmul::v4::rc::AirQuotientProofAlg canonical;
    canonical.batch = proved.proof.batch;
    canonical.next_openings =
        proved.proof.next_openings;
    canonical.trace_commit =
        proved.proof.trace_commit;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::SerializeAirQuotientProofAlg(
            canonical, bytes, &why),
        why);
    BOOST_TEST_MESSAGE(
        "ALI_SAME_PARENT_PROOF measured_bytes="
        << bytes.size()
        << " prove_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               prove_end - prove_begin).count()
        << " verify_us="
        << std::chrono::duration_cast<
               std::chrono::microseconds>(
               verify_end - verify_begin).count()
        << " rows=" << fixture.cs.n_rows
        << " cols=" << fixture.cs.n_columns
        << " equalities=" << result.equality_count);

    auto tampered = proved.proof;
    BOOST_REQUIRE(!tampered.batch.queries.empty());
    const uint32_t target =
        fixture.refs.words[9].
            cells.normalized_vm_consumer.column;
    BOOST_REQUIRE_GT(
        tampered.batch.queries[0].row.values.size(),
        target);
    tampered.batch.queries[0].row.values[target] =
        gf::Add(
            tampered.batch.queries[0].row.values[target],
            gf::Fp3::One());
    std::string reject_why;
    BOOST_CHECK_MESSAGE(
        !aq::AirQuotientVerifyRows(
            fixture.cs, tampered, seed, &reject_why),
        "ALI normalized VM statement-cell proof "
        "tamper accepted");
    BOOST_TEST_MESSAGE(
        "ALI_SAME_PARENT_PROOF_REJECT why=\""
        << reject_why << "\"");
}

BOOST_AUTO_TEST_SUITE_END()
