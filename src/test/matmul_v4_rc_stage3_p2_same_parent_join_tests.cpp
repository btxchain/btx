// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_p2_same_parent_join.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstring>

namespace join =
    matmul::v4::rc::stage3_p2_same_parent_join;
namespace p2binding =
    matmul::v4::rc::stage3_p2_transcript_binding;
namespace p2air =
    matmul::v4::rc::stage3_p2_transcript_air;
namespace airq =
    matmul::v4::rc::stage3_airq_p2_transcript;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_p2_same_parent_join_tests,
    BasicTestingSetup)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

std::vector<std::vector<gf::Fp3>> TinyColumns()
{
    return {{
        gf::FromSigned3(3),
        gf::FromSigned3(5)}};
}

uint32_t EventTerminal(
    const p2air::BuildResult& transcript,
    uint32_t ordinal)
{
    for (uint32_t row = 0;
         row < transcript.cs.n_rows; ++row) {
        const bool active = !gf::IsZero(
            transcript.columns[
                transcript.layout.active_col][row]);
        const uint32_t event =
            static_cast<uint32_t>(gf::Canonical(
                transcript.columns[
                    transcript.layout.event_ordinal_col][row]
                    .c0));
        if (active && event == ordinal &&
            !gf::IsZero(
                transcript.columns[
                    transcript.layout.terminal_col][row])) {
            return row;
        }
    }
    return transcript.cs.n_rows;
}

uint32_t AddColumn(
    aq::AirConstraintSystem<gf::Fp3>& cs,
    std::vector<std::vector<gf::Fp3>>& columns)
{
    const uint32_t out = cs.n_columns++;
    columns.push_back(
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
    return out;
}

join::BytesCellRefsV1 Slice(
    const join::BytesCellRefsV1& source,
    size_t offset,
    size_t length)
{
    join::BytesCellRefsV1 out;
    out.byte.insert(
        out.byte.end(),
        source.byte.begin() + offset,
        source.byte.begin() + offset + length);
    return out;
}

struct FriFixture {
    p2binding::BindingResult binding;
    p2air::BuildResult transcript;
    join::FriProofSourceRefsV1 sources;
    join::FriConsumerRefsV1 consumers;
};

FriFixture BuildFriFixture()
{
    FriFixture out;
    const uint256 seed = Seed(0x63);
    const auto committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            TinyColumns(), seed, 0);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    out.binding =
        p2binding::BuildProofOwnedTranscriptBindingV10(
            committed.proof, seed);
    BOOST_REQUIRE_MESSAGE(
        out.binding.valid, out.binding.note);
    out.transcript =
        p2air::BuildTranscriptAirV10(
            out.binding.statement);
    BOOST_REQUIRE_MESSAGE(
        out.transcript.valid, out.transcript.note);

    out.sources.prefix_schedule.resize(
        out.binding.prefix_schedule.size());
    for (size_t schedule = 1;
         schedule < out.binding.prefix_schedule.size();
         ++schedule) {
        const auto& bytes =
            out.binding.prefix_schedule[schedule].fs_prefix;
        BOOST_REQUIRE_LE(
            (bytes.size() + 3) / 4,
            out.transcript.cs.n_rows);
        std::array<uint32_t, 4> byte_columns{};
        for (uint32_t byte = 0; byte < 4; ++byte) {
            byte_columns[byte] = AddColumn(
                out.transcript.cs,
                out.transcript.columns);
        }
        auto& refs =
            out.sources.prefix_schedule[schedule].byte;
        refs.resize(bytes.size());
        for (size_t offset = 0;
             offset < bytes.size(); ++offset) {
            const uint32_t row =
                static_cast<uint32_t>(offset / 4);
            const uint32_t column =
                byte_columns[offset % 4];
            refs[offset] = {column, row};
            out.transcript.columns[column][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    bytes[offset]));
        }
    }

    const size_t domain = std::strlen(
        rc::kRCFri3AlgP2Q192K2DomainTagV10);
    const auto& initial =
        out.sources.prefix_schedule[1];
    out.sources.fs_seed =
        Slice(initial, domain, 32);
    out.sources.shape_commit =
        Slice(initial, domain + 56, 32);
    out.sources.row_commit_root =
        Slice(initial, domain + 88, 32);
    const auto& post_z =
        out.sources.prefix_schedule[3];
    out.sources.ood_eval_commit_root =
        Slice(post_z, post_z.byte.size() - 32, 32);

    const size_t fold_challenges =
        out.binding.prefix_schedule.size() - 5;
    out.sources.fold_roots.resize(
        fold_challenges + 1);
    for (size_t fold = 0;
         fold < out.sources.fold_roots.size();
         ++fold) {
        const size_t schedule =
            fold < fold_challenges
            ? 4 + fold
            : out.binding.prefix_schedule.size() - 1;
        const auto& prefix =
            out.sources.prefix_schedule[schedule];
        out.sources.fold_roots[fold] =
            Slice(
                prefix, prefix.byte.size() - 32, 32);
    }

    const uint32_t fp3_base[3] = {
        AddColumn(
            out.transcript.cs,
            out.transcript.columns),
        AddColumn(
            out.transcript.cs,
            out.transcript.columns),
        AddColumn(
            out.transcript.cs,
            out.transcript.columns)};
    const uint32_t query_column = AddColumn(
        out.transcript.cs, out.transcript.columns);
    out.consumers.events.resize(
        out.binding.consumer_manifest.entries.size());
    for (size_t event = 0;
         event < out.consumers.events.size();
         ++event) {
        const uint32_t row = EventTerminal(
            out.transcript,
            static_cast<uint32_t>(event));
        BOOST_REQUIRE_LT(row, out.transcript.cs.n_rows);
        const auto& manifest =
            out.binding.consumer_manifest.entries[event];
        if (manifest.width == 1) {
            out.consumers.events[event].query_index =
                {query_column, row};
            out.transcript.columns[query_column][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    manifest.index_value));
        } else {
            const gf::Fp coordinates[3] = {
                manifest.fp3_value.c0,
                manifest.fp3_value.c1,
                manifest.fp3_value.c2};
            for (uint32_t coord = 0;
                 coord < 3; ++coord) {
                out.consumers.events[event]
                    .fp3.coord[coord] =
                    {fp3_base[coord], row};
                out.transcript.columns[
                    fp3_base[coord]][row] =
                    gf::Fp3::FromFp(
                        coordinates[coord]);
            }
        }
    }
    return out;
}

join::EndpointV1 LinearWord(
    const std::array<join::CellRefV1, 4>& bytes)
{
    join::EndpointV1 out;
    out.kind =
        join::EndpointKindV1::LinearCombination;
    out.row = bytes[0].row;
    const uint32_t coefficient[4] = {
        1U, 1U << 8, 1U << 16, 1U << 24};
    for (uint32_t i = 0; i < 4; ++i) {
        out.linear_terms.push_back(
            {bytes[i], coefficient[i]});
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    all_v10_source_prefixes_and_consumers_map_exactly)
{
    FriFixture fixture = BuildFriFixture();
    join::JoinPlanV1 plan;
    std::vector<std::string> residuals;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::BuildFriV10JoinPlanV1(
            fixture.binding, fixture.transcript,
            fixture.sources, fixture.consumers,
            plan, residuals, &why),
        why);
    BOOST_CHECK(residuals.empty());
    BOOST_CHECK_GT(plan.fri_source_equalities, 0U);
    BOOST_CHECK_EQUAL(
        plan.fri_consumer_equalities,
        3U *
            (fixture.binding.consumer_manifest.entries.size() -
             rc::kRCFri3AlgNumQueries) +
            rc::kRCFri3AlgNumQueries);

    join::AppendResultV1 appended;
    BOOST_REQUIRE_MESSAGE(
        join::AppendSameParentJoinV1(
            fixture.transcript.cs,
            fixture.transcript.columns,
            plan, appended, &why),
        why);
    BOOST_CHECK(appended.valid);
    BOOST_CHECK(appended.column_refs_reused);
    BOOST_CHECK(
        appended.row_tagged_equalities_constrained);
    BOOST_CHECK(
        appended.cross_row_transport_constrained);
    BOOST_CHECK(
        appended.selectors_only_preprocessed);
    BOOST_CHECK(
        !appended.actual_values_preprocessed);
    BOOST_CHECK(
        appended.proof_owned_sources_equality_constrained);
    BOOST_CHECK(
        appended.verifier_consumers_equality_constrained);
    BOOST_CHECK(
        !appended.source_columns_proven_verifier_owned);
    BOOST_CHECK(
        !appended.consumer_columns_proven_verifier_owned);
    BOOST_CHECK(!appended.recursive_authority);
    BOOST_CHECK_EQUAL(
        join::CountViolations(
            fixture.transcript.cs,
            fixture.transcript.columns),
        0U);

    // Distinct semantic substitutions all hit an AIR equality, including
    // source bytes that straddle the V10 domain's non-u32-aligned boundary.
    auto attack = fixture.transcript.columns;
    const auto root =
        fixture.sources.row_commit_root.byte[0];
    attack[root.column][root.row] = gf::Add(
        attack[root.column][root.row],
        gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            fixture.transcript.cs, attack),
        0U);

    attack = fixture.transcript.columns;
    const auto proof_byte =
        fixture.sources.prefix_schedule[1].byte[
            std::strlen(
                rc::kRCFri3AlgP2Q192K2DomainTagV10) +
            32];
    attack[proof_byte.column][proof_byte.row] =
        gf::Add(
            attack[proof_byte.column][proof_byte.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            fixture.transcript.cs, attack),
        0U);

    attack = fixture.transcript.columns;
    const auto consumer =
        fixture.consumers.events[0].fp3.coord[0];
    attack[consumer.column][consumer.row] =
        gf::Add(
            attack[consumer.column][consumer.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            fixture.transcript.cs, attack),
        0U);

    attack = fixture.transcript.columns;
    const size_t query =
        fixture.consumers.events.size() - 1;
    const auto query_cell =
        fixture.consumers.events[query].query_index;
    attack[query_cell.column][query_cell.row] =
        gf::Add(
            attack[query_cell.column][query_cell.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            fixture.transcript.cs, attack),
        0U);
}

BOOST_AUTO_TEST_CASE(
    airq_seed_root_shape_and_lambda_use_same_parent_cells)
{
    airq::Statement statement;
    statement.fs_seed = Seed(0x81);
    statement.trace_commit = Seed(0x93);
    statement.n_rows = 16;
    statement.quotient_len = 64;
    statement.trace_width = 27;
    auto transcript =
        airq::BuildAirqLambdaTranscriptAir(statement);
    BOOST_REQUIRE_MESSAGE(
        transcript.valid, transcript.note);

    join::AirqProofSourceRefsV1 sources;
    join::AirqConsumerRefsV1 consumers;
    const auto add_value =
        [&](uint32_t value, uint32_t row) {
            const uint32_t column = AddColumn(
                transcript.cs, transcript.columns);
            transcript.columns[column][row] =
                gf::Fp3::FromFp(gf::FromU64(value));
            return join::CellRefV1{column, row};
        };
    for (uint32_t word = 0; word < 8; ++word) {
        sources.fs_seed.word[word] =
            add_value(
                transcript.source_map.seed_u32[word],
                word % transcript.cs.n_rows);
        sources.trace_commit_root.word[word] =
            add_value(
                transcript.source_map
                    .trace_commit_u32[word],
                (word + 1) % transcript.cs.n_rows);
    }
    for (uint32_t word = 0; word < 3; ++word) {
        sources.shape[word] =
            add_value(
                transcript.source_map.shape_u32[word],
                (word + 2) % transcript.cs.n_rows);
    }
    const gf::Fp lambda[3] = {
        transcript.native_lambda.c0,
        transcript.native_lambda.c1,
        transcript.native_lambda.c2};
    for (uint32_t coord = 0; coord < 3; ++coord) {
        consumers.lambda.coord[coord] =
            add_value(
                static_cast<uint32_t>(
                    gf::Canonical(lambda[coord])),
                coord);
        // AIRQ lambda coordinates are full Goldilocks values. Replace the
        // u32 helper's value with the exact field coordinate.
        transcript.columns[
            consumers.lambda.coord[coord].column]
            [consumers.lambda.coord[coord].row] =
            gf::Fp3::FromFp(lambda[coord]);
    }

    join::JoinPlanV1 plan;
    std::vector<std::string> residuals;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::BuildAirqJoinPlanV1(
            transcript, sources, consumers,
            plan, residuals, &why),
        why);
    BOOST_CHECK_EQUAL(
        plan.airq_source_equalities, 19U);
    BOOST_CHECK_EQUAL(
        plan.airq_consumer_equalities, 3U);
    BOOST_CHECK_EQUAL(plan.equalities.size(), 22U);
    BOOST_CHECK_EQUAL(
        std::count_if(
            plan.equalities.begin(),
            plan.equalities.end(),
            [](const join::EqualityV1& equality) {
                return equality.role ==
                    join::EqualityRoleV1::
                        AirqVerifierConsumer;
            }),
        3U);
    auto double_counted = plan;
    ++double_counted.airq_consumer_equalities;
    join::AppendResultV1 rejected_count;
    BOOST_CHECK(
        !join::AppendSameParentJoinV1(
            transcript.cs, transcript.columns,
            double_counted, rejected_count, &why));
    join::AppendResultV1 appended;
    BOOST_REQUIRE_MESSAGE(
        join::AppendSameParentJoinV1(
            transcript.cs, transcript.columns,
            plan, appended, &why),
        why);
    BOOST_CHECK_EQUAL(
        join::CountViolations(
            transcript.cs, transcript.columns),
        0U);

    auto attack = transcript.columns;
    const auto root =
        sources.trace_commit_root.word[3];
    attack[root.column][root.row] =
        gf::Add(
            attack[root.column][root.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            transcript.cs, attack),
        0U);

    attack = transcript.columns;
    const auto consumer =
        consumers.lambda.coord[2];
    attack[consumer.column][consumer.row] =
        gf::Add(
            attack[consumer.column][consumer.row],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        join::CountViolations(
            transcript.cs, attack),
        0U);
}

BOOST_AUTO_TEST_CASE(
    cross_row_packed_bytes_use_carry_safe_transport)
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 8;
    cs.n_columns = 5;
    std::vector<std::vector<gf::Fp3>> columns(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
    const uint32_t source_rows[4] = {0, 1, 1, 2};
    const uint32_t bytes[4] = {0x21, 0x43, 0x65, 0x87};
    uint32_t packed = 0;
    join::EndpointV1 source;
    source.kind = join::EndpointKindV1::LinearCombination;
    source.row = 6;
    for (uint32_t byte = 0; byte < 4; ++byte) {
        columns[byte][source_rows[byte]] =
            gf::Fp3::FromFp(gf::FromU64(bytes[byte]));
        const uint32_t coefficient =
            uint32_t{1} << (8 * byte);
        source.linear_terms.push_back({
            {byte, source_rows[byte]}, coefficient});
        packed |= bytes[byte] << (8 * byte);
    }
    columns[4][6] =
        gf::Fp3::FromFp(gf::FromU64(packed));
    join::EndpointV1 sink;
    sink.kind = join::EndpointKindV1::Cell;
    sink.cell = {4, 6};
    sink.row = 6;
    join::JoinPlanV1 plan;
    plan.equalities.push_back({
        join::EqualityRoleV1::FriProofSource,
        0, 0, source, sink});
    plan.fri_source_equalities = 1;

    join::AppendResultV1 appended;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::AppendSameParentJoinV1(
            cs, columns, plan, appended, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        appended.equality_layouts.size(), 1U);
    const auto& layout =
        appended.equality_layouts.front();
    BOOST_CHECK_EQUAL(
        layout.transport_carriers.size(), 4U);
    BOOST_CHECK_EQUAL(
        layout.transport_source_selectors.size(), 4U);
    BOOST_CHECK_EQUAL(
        layout.transport_carry_selectors.size(), 4U);
    BOOST_CHECK_EQUAL(
        join::CountViolations(cs, columns), 0U);

    auto attack = columns;
    attack[0][source_rows[0]] =
        gf::Add(attack[0][source_rows[0]], gf::Fp3::One());
    BOOST_CHECK_GT(join::CountViolations(cs, attack), 0U);

    attack = columns;
    const uint32_t carrier =
        layout.transport_carriers[0];
    attack[carrier][3] =
        gf::Add(attack[carrier][3], gf::Fp3::One());
    BOOST_CHECK_GT(join::CountViolations(cs, attack), 0U);

    attack = columns;
    attack[4][6] =
        gf::Add(attack[4][6], gf::Fp3::One());
    BOOST_CHECK_GT(join::CountViolations(cs, attack), 0U);
}

BOOST_AUTO_TEST_CASE(
    real_v10_parent_proof_rejects_combined_substitution)
{
    using Backend = aq::AirFriBackendAlg<gf::Fp3>;
    FriFixture fixture = BuildFriFixture();

    // Minimal canary: one interior row-root word, the proof lambda consumer,
    // and the final query consumer. The exhaustive mapping is tested above;
    // keeping this proof canary narrow avoids turning a wiring regression
    // test into a production-sized aggregation benchmark.
    join::JoinPlanV1 plan;
    const size_t root_start =
        std::strlen(
            rc::kRCFri3AlgP2Q192K2DomainTagV10) +
        88;
    const size_t aligned =
        (root_start + 3) & ~size_t{3};
    std::array<join::CellRefV1, 4> root_bytes{};
    for (uint32_t byte = 0; byte < 4; ++byte) {
        root_bytes[byte] =
            fixture.sources.prefix_schedule[1]
                .byte[aligned + byte];
    }
    join::EndpointV1 packed = LinearWord(root_bytes);
    const uint32_t word =
        static_cast<uint32_t>(aligned / 4);
    join::EndpointV1 message;
    message.kind = join::EndpointKindV1::Cell;
    message.cell = {
        fixture.transcript.layout.MessageCol(
            0, (3 + word) %
                   rc::alg_hash::kAlgHashRate),
        (3 + word) /
            rc::alg_hash::kAlgHashRate};
    message.row = message.cell.row;
    plan.equalities.push_back({
        join::EqualityRoleV1::FriProofSource,
        1, word, packed, message});
    plan.fri_source_equalities = 1;

    const uint32_t lambda_terminal =
        EventTerminal(fixture.transcript, 0);
    for (uint32_t coord = 0; coord < 3; ++coord) {
        join::EndpointV1 producer;
        producer.kind =
            join::EndpointKindV1::PoseidonOutput;
        producer.poseidon =
            fixture.transcript.layout.candidate[0];
        producer.output_lane = coord;
        producer.row = lambda_terminal;
        join::EndpointV1 consumer;
        consumer.kind = join::EndpointKindV1::Cell;
        consumer.cell =
            fixture.consumers.events[0]
                .fp3.coord[coord];
        consumer.row = consumer.cell.row;
        plan.equalities.push_back({
            join::EqualityRoleV1::FriVerifierConsumer,
            0, coord, producer, consumer});
        ++plan.fri_consumer_equalities;
    }
    const size_t query_event =
        fixture.consumers.events.size() - 1;
    const uint32_t query_terminal =
        EventTerminal(
            fixture.transcript,
            static_cast<uint32_t>(query_event));
    join::EndpointV1 query_producer;
    query_producer.kind =
        join::EndpointKindV1::Cell;
    query_producer.cell = {
        fixture.transcript.layout.query_index_col,
        query_terminal};
    query_producer.row = query_terminal;
    join::EndpointV1 query_consumer;
    query_consumer.kind =
        join::EndpointKindV1::Cell;
    query_consumer.cell =
        fixture.consumers.events[query_event]
            .query_index;
    query_consumer.row =
        query_consumer.cell.row;
    plan.equalities.push_back({
        join::EqualityRoleV1::FriVerifierConsumer,
        static_cast<uint32_t>(query_event), 0,
        query_producer, query_consumer});
    ++plan.fri_consumer_equalities;

    join::AppendResultV1 appended;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        join::AppendSameParentJoinV1(
            fixture.transcript.cs,
            fixture.transcript.columns,
            plan, appended, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        join::CountViolations(
            fixture.transcript.cs,
            fixture.transcript.columns),
        0U);
    const uint256 seed = Seed(0xa1);
    const auto honest =
        aq::AirQuotientProve<gf::Fp3, Backend>(
            fixture.transcript.cs,
            fixture.transcript.columns,
            seed, {});
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_REQUIRE(honest.division_exact);
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, Backend>(
            fixture.transcript.cs,
            honest.proof, seed, &why)),
        why);

    auto forged_columns =
        fixture.transcript.columns;
    forged_columns[root_bytes[0].column]
                  [root_bytes[0].row] =
        gf::Add(
            forged_columns[root_bytes[0].column]
                          [root_bytes[0].row],
            gf::Fp3::One());
    const auto lambda_consumer =
        fixture.consumers.events[0]
            .fp3.coord[0];
    forged_columns[lambda_consumer.column]
                  [lambda_consumer.row] =
        gf::Add(
            forged_columns[lambda_consumer.column]
                          [lambda_consumer.row],
            gf::Fp3::One());
    const auto query_cell =
        fixture.consumers.events[query_event]
            .query_index;
    forged_columns[query_cell.column][query_cell.row] =
        gf::Add(
            forged_columns[query_cell.column]
                          [query_cell.row],
            gf::Fp3::One());
    BOOST_REQUIRE_GT(
        join::CountViolations(
            fixture.transcript.cs,
            forged_columns),
        0U);
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProve<gf::Fp3, Backend>(
            fixture.transcript.cs,
            forged_columns, seed, adversarial);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            fixture.transcript.cs,
            forged.proof, seed, &why)));
}

BOOST_AUTO_TEST_CASE(
    missing_parent_exports_report_precise_residual)
{
    FriFixture fixture = BuildFriFixture();
    fixture.sources.prefix_schedule[1].byte.clear();
    join::JoinPlanV1 plan;
    std::vector<std::string> residuals;
    std::string why;
    BOOST_CHECK(
        !join::BuildFriV10JoinPlanV1(
            fixture.binding, fixture.transcript,
            fixture.sources, fixture.consumers,
            plan, residuals, &why));
    BOOST_REQUIRE(!residuals.empty());
    BOOST_CHECK(
        residuals.front().find(
            "fri_seed_byte_alias_missing") !=
            std::string::npos ||
        residuals.front().find(
            "fri_prefix") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
