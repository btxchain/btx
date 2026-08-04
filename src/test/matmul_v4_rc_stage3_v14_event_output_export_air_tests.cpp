// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_v14_event_output_export_air.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace exporter =
    matmul::v4::rc::stage3_v14_event_output_export_air;
namespace aq = matmul::v4::rc::air_quotient;
namespace bridge =
    matmul::v4::rc::stage3_safe_v12_recursive_bridge;
namespace gf = matmul::v4::rc::gkr_field;
namespace occurrence =
    matmul::v4::rc::stage3_v13_occurrence_manifest;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;

namespace {

tape::PublicShapeV1 ToyShape()
{
    tape::PublicShapeV1 shape;
    shape.trace_rows = 2;
    shape.trace_columns = 2;
    shape.quotient_len = 2;
    shape.n_coeffs = 2;
    shape.base_column_indices = {0};
    return shape;
}

uint256 Seed(uint8_t tag)
{
    uint256 seed;
    for (uint32_t i = 0; i < 32; ++i) {
        seed.data()[i] =
            static_cast<unsigned char>(tag + 13 * i);
    }
    return seed;
}

struct Fixture {
    tape::PublicShapeV1 shape;
    std::vector<bridge::TypedSafeEventProgramV13> program;
    std::vector<bridge::TypedSafeEventWitnessV13> witness;
    occurrence::ManifestV1 manifest;
    bridge::TypedSafeDirectParentProductV14 native_v14;
    exporter::InputV1 input;
    exporter::ProductV1 product;

    Fixture()
    {
        shape = ToyShape();
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            occurrence::BuildCanonicalTypedProgramV1(
                shape, program, &why),
            why);
        BOOST_REQUIRE_GT(program.size(), 192U);
        witness.resize(program.size());
        for (uint32_t event = 0;
             event < program.size(); ++event) {
            witness[event].message.resize(
                program[event].message.size());
            for (uint32_t ordinal = 0;
                 ordinal < program[event].message.size();
                 ++ordinal) {
                if (program[event].message[ordinal].binding ==
                    bridge::TypedSafeMessageBindingV13::
                        ProofOwned) {
                    witness[event].message[ordinal] =
                        gf::FromU64(
                            3 + uint64_t{event} * 131 +
                            uint64_t{ordinal} * 17);
                }
            }
        }
        BOOST_REQUIRE_MESSAGE(
            bridge::BuildTypedSafeDirectParentV14(
                program, witness, native_v14, &why),
            why);
        BOOST_REQUIRE(native_v14.valid);
        BOOST_REQUIRE_EQUAL(
            native_v14.event_output.size(),
            program.size());
        BOOST_REQUIRE_MESSAGE(
            occurrence::BuildCanonicalOccurrenceManifestV1(
                shape, program, manifest, &why),
            why);
        BOOST_REQUIRE(manifest.valid);
        input.manifest = manifest;
        input.event_output.resize(
            native_v14.event_output.size());
        for (uint32_t event = 0;
             event < native_v14.event_output.size();
             ++event) {
            for (uint32_t lane = 0; lane < 4; ++lane) {
                input.event_output[event][lane] =
                    gf::Canonical(
                        native_v14.event_output[event][lane]);
            }
        }
        product = exporter::BuildProductV1(input);
        BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    }
};

const Fixture& Honest()
{
    static const Fixture fixture;
    return fixture;
}

uint32_t Violations(
    const exporter::ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    return exporter::CountViolationsV1(
        product.cs, columns);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v14_event_output_export_air_tests)

BOOST_AUTO_TEST_CASE(
    inventory_collapses_consumers_and_delegates_special_outputs)
{
    const auto& fixture = Honest();
    const auto& inventory = fixture.product.inventory;
    BOOST_REQUIRE(inventory.complete);
    BOOST_CHECK(inventory.manifest_rebuilt);
    // Toy n_coeffs=2 has one fold. Direct verifier outputs are:
    // AirLambda 3 + FriSeed 4 + lambda/w1/w2 9 + fold 3 +
    // QuerySeed 4 = 23 unique lanes.
    BOOST_CHECK_EQUAL(inventory.exported.size(), 23U);
    BOOST_CHECK_EQUAL(fixture.product.active_rows, 23U);
    BOOST_CHECK_EQUAL(fixture.product.trace_rows, 32U);
    BOOST_CHECK_GT(
        inventory.duplicate_consumers_collapsed, 0U);
    BOOST_CHECK_EQUAL(
        inventory.prior_byte_occurrences,
        fixture.manifest
            .prior_event_output_byte_occurrences +
        fixture.manifest
            .outer_fri_seed_feedback_byte_occurrences);
    BOOST_CHECK_EQUAL(
        inventory.query_seed_field_occurrences,
        fixture.manifest
            .query_seed_feedback_field_occurrences);

    // Dedicated AIR boundaries are explicit and complete.
    BOOST_CHECK_EQUAL(
        inventory.delegated_ood_candidate_lanes, 12U);
    BOOST_CHECK_EQUAL(
        inventory.delegated_query_candidate_lanes, 192U);
    BOOST_CHECK_EQUAL(
        inventory.delegated_selected_ood_lanes, 6U);
    BOOST_CHECK_EQUAL(
        inventory.delegated_derived_hash_lanes, 8U);

    uint32_t fold_events = 0;
    for (uint32_t event = 0;
         event < fixture.program.size(); ++event) {
        if (fixture.program[event].kind ==
            bridge::TypedSafeChallengeKindV13::FoldBeta) {
            ++fold_events;
            for (uint8_t lane = 0; lane < 3; ++lane) {
                BOOST_CHECK(
                    fixture.product.cell_map.Find(
                        event, lane) != nullptr);
            }
        }
    }
    BOOST_CHECK_EQUAL(fold_events, 1U);
    BOOST_CHECK(!fixture.product.v14_output_equalities_executed);
    BOOST_CHECK(!fixture.product.recursively_consumed);
    BOOST_CHECK(!fixture.product.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    ordinary_exports_match_native_v14_outputs_and_le32_words)
{
    const auto& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_REQUIRE_EQUAL(
        product.cell_map.exports.size(),
        product.inventory.exported.size());
    BOOST_CHECK(product.input_cells_ordinary);
    BOOST_CHECK(product.word_cells_ordinary);
    BOOST_CHECK(product.canonical_goldilocks_constrained);
    BOOST_CHECK(product.le32_exports_constrained);
    BOOST_CHECK(product.event_lane_positions_constrained);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_LE(product.max_alg_degree, 7U);

    for (const auto& cell : product.cell_map.exports) {
        const uint64_t native =
            gf::Canonical(
                fixture.native_v14
                    .event_output[cell.event][cell.lane]);
        const auto& source =
            product.columns[cell.v14_output_lane.column]
                           [cell.v14_output_lane.row];
        BOOST_CHECK_EQUAL(
            gf::Canonical(source.c0), native);
        BOOST_CHECK_EQUAL(source.c1, 0U);
        BOOST_CHECK_EQUAL(source.c2, 0U);
        BOOST_CHECK_EQUAL(
            gf::Canonical(
                product.columns[cell.low_le32.column]
                               [cell.low_le32.row].c0),
            static_cast<uint32_t>(native));
        BOOST_CHECK_EQUAL(
            gf::Canonical(
                product.columns[cell.high_le32.column]
                               [cell.high_le32.row].c0),
            static_cast<uint32_t>(native >> 32));
        BOOST_CHECK_EQUAL(
            gf::Canonical(
                product.columns[cell.event_key.column]
                               [cell.event_key.row].c0),
            cell.event);
        BOOST_CHECK_EQUAL(
            gf::Canonical(
                product.columns[cell.lane_key.column]
                               [cell.lane_key.row].c0),
            cell.lane);
    }

    const exporter::LayoutV1 layout;
    for (const auto& [column, values] : product.cs.preprocessed) {
        BOOST_CHECK_GE(column, layout.active);
        BOOST_CHECK_LT(column, layout.dependent_zero);
        BOOST_REQUIRE_EQUAL(values.size(), product.trace_rows);
    }
}

BOOST_AUTO_TEST_CASE(
    aliases_transplants_and_event_lane_reordering_reject)
{
    const auto& honest = Honest();
    const auto& product = honest.product;
    BOOST_REQUIRE_GE(product.active_rows, 2U);

    auto output_transplant = product.columns;
    output_transplant[product.layout.lane_value][0] =
        gf::Add(
            output_transplant[
                product.layout.lane_value][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        Violations(product, output_transplant), 0U);

    auto low_word_transplant = product.columns;
    low_word_transplant[product.layout.low_word][0] =
        gf::Add(
            low_word_transplant[
                product.layout.low_word][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        Violations(product, low_word_transplant), 0U);

    auto high_word_transplant = product.columns;
    high_word_transplant[product.layout.high_word][0] =
        gf::Add(
            high_word_transplant[
                product.layout.high_word][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        Violations(product, high_word_transplant), 0U);

    // Move two complete ordinary exporter rows while leaving the verifier
    // positional columns in place. Canonical decomposition still holds, but
    // the event/lane key constraints reject the reorder.
    auto reordered = product.columns;
    for (uint32_t column = product.layout.lane_value;
         column <= product.layout.lane_key; ++column) {
        std::swap(reordered[column][0], reordered[column][1]);
    }
    BOOST_CHECK_GT(Violations(product, reordered), 0U);

    // x+p is identical in the field to x, but its 64-bit decomposition is
    // outside [0,p). Use a small x so x+p fits in uint64_t.
    auto aliased_input = honest.input;
    const auto& first = product.inventory.exported.front();
    const uint64_t small = 7;
    BOOST_REQUIRE((
        static_cast<unsigned __int128>(small) + gf::kP <
        static_cast<unsigned __int128>(
            std::numeric_limits<uint64_t>::max()) + 1));
    aliased_input.event_output[first.event][first.lane] =
        small + gf::kP;
    const auto aliased =
        exporter::BuildProductV1(aliased_input);
    BOOST_CHECK(!aliased.valid);
    BOOST_CHECK_GT(aliased.violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    unmodified_airquotient_accepts_and_proof_tampers_reject)
{
    using Backend = aq::AirFriBackendAlg<gf::Fp3>;
    const auto& product = Honest().product;
    const uint256 seed = Seed(0xa4);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, Backend>(
            product.cs, product.columns, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, Backend>(
            product.cs, proved.proof, seed, &why)),
        why);

    auto output_forged = proved.proof;
    BOOST_REQUIRE(!output_forged.batch.queries.empty());
    BOOST_REQUIRE_GT(
        output_forged.batch.queries[0].row.values.size(),
        product.layout.lane_value);
    output_forged.batch.queries[0]
        .row.values[product.layout.lane_value] =
        gf::Add(
            output_forged.batch.queries[0]
                .row.values[product.layout.lane_value],
            gf::Fp3::One());
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            product.cs, output_forged, seed, nullptr)));

    auto word_forged = proved.proof;
    word_forged.batch.queries[0]
        .row.values[product.layout.low_word] =
        gf::Add(
            word_forged.batch.queries[0]
                .row.values[product.layout.low_word],
            gf::Fp3::One());
    BOOST_CHECK(
        !(aq::AirQuotientVerify<gf::Fp3, Backend>(
            product.cs, word_forged, seed, nullptr)));
}

BOOST_AUTO_TEST_SUITE_END()
