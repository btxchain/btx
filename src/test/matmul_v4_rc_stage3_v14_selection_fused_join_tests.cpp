// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v14_selection_fused_join.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace fused =
    matmul::v4::rc::stage3_v14_selection_fused_join;
namespace aq = matmul::v4::rc::air_quotient;
namespace alg_hash = matmul::v4::rc::alg_hash;
namespace bridge =
    matmul::v4::rc::stage3_safe_v12_recursive_bridge;
namespace gf = matmul::v4::rc::gkr_field;
namespace occurrence =
    matmul::v4::rc::stage3_v13_occurrence_manifest;
namespace selection =
    matmul::v4::rc::stage3_v13_selection_query_air;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace rc = matmul::v4::rc;

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
            static_cast<unsigned char>(tag + 11 * i);
    }
    return seed;
}

selection::RawFp3V1 Raw(const alg_hash::Digest& digest)
{
    selection::RawFp3V1 out;
    for (uint32_t coordinate = 0; coordinate < 3; ++coordinate) {
        out.coordinate[coordinate] =
            gf::Canonical(digest[coordinate]);
    }
    return out;
}

gf::Fp3 Field(const selection::RawFp3V1& raw)
{
    return {
        gf::FromU64(raw.coordinate[0]),
        gf::FromU64(raw.coordinate[1]),
        gf::FromU64(raw.coordinate[2])};
}

struct Fixture {
    tape::PublicShapeV1 shape;
    std::vector<bridge::TypedSafeEventProgramV13> program;
    std::vector<bridge::TypedSafeEventWitnessV13> witness;
    occurrence::ManifestV1 manifest;
    bridge::TypedSafeDirectParentProductV14 v14;
    selection::InputV1 selection_input;
    selection::ProductV1 selected;
    fused::ProductV1 product;
    uint256 seed{Seed(0x71)};

    Fixture()
    {
        shape = ToyShape();
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            occurrence::BuildCanonicalTypedProgramV1(
                shape, program, &why),
            why);
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
                program, witness, v14, &why),
            why);
        BOOST_REQUIRE_MESSAGE(v14.valid, v14.note);
        BOOST_REQUIRE_MESSAGE(
            occurrence::BuildCanonicalOccurrenceManifestV1(
                shape, program, manifest, &why),
            why);
        BOOST_REQUIRE(manifest.valid);

        for (uint32_t pair = 0; pair < 2; ++pair) {
            for (uint32_t ordinal = 0;
                 ordinal < 2; ++ordinal) {
                const uint32_t candidate =
                    2 * pair + ordinal;
                const uint32_t event =
                    manifest.selectors[pair]
                        .candidate_events[ordinal];
                BOOST_REQUIRE_LT(
                    event, v14.event_output.size());
                selection_input.ood_candidate[candidate] =
                    Raw(v14.event_output[event]);
            }
        }
        const std::array<gf::Fp3, 2> z1_candidates{
            Field(selection_input.ood_candidate[0]),
            Field(selection_input.ood_candidate[1])};
        const std::array<gf::Fp3, 2> z2_candidates{
            Field(selection_input.ood_candidate[2]),
            Field(selection_input.ood_candidate[3])};
        uint32_t z1_ordinal = 0;
        uint32_t z2_ordinal = 0;
        gf::Fp3 z1{};
        gf::Fp3 z2{};
        BOOST_REQUIRE(
            rc::Fri3AlgSafeSelectOodK2V13(
                z1_candidates, nullptr,
                z1_ordinal, z1));
        BOOST_REQUIRE(
            rc::Fri3AlgSafeSelectOodK2V13(
                z2_candidates, &z1,
                z2_ordinal, z2));
        selection_input.proof_tape_z1 =
            selection_input.ood_candidate[z1_ordinal];
        selection_input.proof_tape_z2 =
            selection_input.ood_candidate[
                2 + z2_ordinal];

        selection_input.n_lde =
            shape.n_coeffs * rc::kRCFriBlowup;
        for (uint32_t event = 0;
             event < program.size(); ++event) {
            if (program[event].kind !=
                bridge::TypedSafeChallengeKindV13::
                    QueryCandidate) {
                continue;
            }
            const uint64_t lane0 =
                gf::Canonical(v14.event_output[event][0]);
            selection_input.query_digest_lane0.push_back(lane0);
            selection_input.proof_query_index.push_back(
                static_cast<uint32_t>(
                    lane0 &
                    uint64_t{
                        selection_input.n_lde - 1}));
        }
        BOOST_REQUIRE_EQUAL(
            selection_input.query_digest_lane0.size(),
            selection::kProductionQueriesV1);
        selected =
            selection::BuildProductV1(selection_input);
        BOOST_REQUIRE_MESSAGE(selected.valid, selected.note);
        BOOST_REQUIRE(selected.production_q192);
        product =
            fused::BuildProductV1(manifest, v14, selected);
        BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    }
};

const Fixture& Honest()
{
    static const Fixture fixture;
    return fixture;
}

uint32_t Violations(
    const fused::ProductV1& product,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    return fused::CountViolationsV1(
        product.cs, columns);
}

void AddOne(
    std::vector<std::vector<gf::Fp3>>& columns,
    uint32_t column,
    uint32_t row)
{
    columns[column][row] =
        gf::Add(columns[column][row], gf::Fp3::One());
}

void RequireForcedProofReject(
    const Fixture& fixture,
    std::vector<std::vector<gf::Fp3>> columns,
    const char* label)
{
    BOOST_REQUIRE_GT(
        Violations(fixture.product, columns), 0U);
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProveRows(
            fixture.product.cs, columns,
            fixture.seed, adversarial);
    BOOST_REQUIRE_MESSAGE(
        forged.ok, label << ": " << forged.note);
    BOOST_CHECK_MESSAGE(
        !forged.division_exact, label);

    fused::ProofV1 envelope;
    envelope.program_root =
        fixture.manifest.program_root;
    envelope.transcript_commitment =
        fixture.v14.transcript_commitment;
    envelope.proof = forged.proof;
    std::string why;
    BOOST_CHECK_MESSAGE(
        !fused::VerifyV1(
            fixture.manifest,
            fixture.v14.transcript_commitment,
            envelope, fixture.seed, &why),
        label << ": " << why);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v14_selection_fused_join_tests)

BOOST_AUTO_TEST_CASE(
    exact_v14_outputs_join_actual_selection_cells)
{
    const auto& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.v14_constraints_fused);
    BOOST_CHECK(product.selection_constraints_fused);
    BOOST_CHECK(product.ood_candidate_outputs_bound);
    BOOST_CHECK(product.query_candidate_outputs_bound);
    BOOST_CHECK(
        product.query_reduction_local_proof_tape_equality);
    BOOST_CHECK_EQUAL(product.schedule.ood_edges, 12U);
    BOOST_CHECK_EQUAL(
        product.schedule.query_edges,
        selection::kProductionQueriesV1);
    BOOST_CHECK_EQUAL(product.schedule.edges.size(), 204U);
    BOOST_CHECK(product.schedule.exact_manifest_rebuilt);
    BOOST_CHECK(product.schedule.ordinary_same_parent_cells);
    BOOST_CHECK(!product.actual_proof_tape_cells_bound);
    BOOST_CHECK(!product.selected_z_to_derived_hash_bound);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);

    for (const auto& edge : product.schedule.edges) {
        const auto& source =
            product.columns[edge.source_column]
                           [edge.source_row];
        const auto& destination =
            product.columns[
                product.layout.Selection(
                    edge.destination_column)]
                           [edge.destination_row];
        const auto& table =
            product.columns[product.layout.edge_value]
                           [edge.join_row];
        BOOST_CHECK(gf::Eq(source, destination));
        BOOST_CHECK(gf::Eq(source, table));
        BOOST_CHECK_EQUAL(
            gf::Canonical(
                product.columns[
                    product.layout.edge_multiplicity]
                               [edge.join_row].c0),
            1U);
    }
}

BOOST_AUTO_TEST_CASE(
    value_address_role_multiplicity_and_endpoint_attacks_reject)
{
    const auto& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_REQUIRE_GE(product.schedule.edges.size(), 2U);
    const auto& edge = product.schedule.edges[0];

    auto value = product.columns;
    AddOne(
        value, product.layout.edge_value,
        edge.join_row);
    BOOST_CHECK_GT(Violations(product, value), 0U);

    auto address = product.columns;
    AddOne(
        address, product.layout.edge_event,
        edge.join_row);
    BOOST_CHECK_GT(Violations(product, address), 0U);

    auto role = product.columns;
    AddOne(
        role, product.layout.edge_role,
        edge.join_row);
    BOOST_CHECK_GT(Violations(product, role), 0U);

    auto multiplicity = product.columns;
    multiplicity[product.layout.edge_multiplicity]
                [edge.join_row] = gf::Fp3::Zero();
    BOOST_CHECK_GT(Violations(product, multiplicity), 0U);

    auto source_transplant = product.columns;
    AddOne(
        source_transplant,
        edge.source_column, edge.source_row);
    BOOST_CHECK_GT(
        Violations(product, source_transplant), 0U);

    auto destination_transplant = product.columns;
    AddOne(
        destination_transplant,
        product.layout.Selection(
            edge.destination_column),
        edge.destination_row);
    BOOST_CHECK_GT(
        Violations(product, destination_transplant), 0U);

    // Cross an OOD edge with a Q192 edge. Even moving the value, role,
    // address, coordinate and multiplicity together cannot evade the
    // verifier-rebuilt row-tagged metadata or either endpoint equality.
    const auto& query_edge =
        product.schedule.edges[product.schedule.ood_edges];
    auto crossed = product.columns;
    for (const uint32_t column : {
             product.layout.edge_value,
             product.layout.edge_role,
             product.layout.edge_event,
             product.layout.edge_ordinal,
             product.layout.edge_coordinate,
             product.layout.edge_multiplicity,
         }) {
        crossed[column][edge.join_row] =
            crossed[column][query_edge.join_row];
    }
    BOOST_CHECK_GT(Violations(product, crossed), 0U);

    auto false_shape = fixture.selected;
    ++false_shape.trace_rows;
    const auto rejected =
        fused::BuildProductV1(
            fixture.manifest, fixture.v14,
            false_shape);
    BOOST_CHECK(!rejected.valid);
    BOOST_CHECK_EQUAL(
        rejected.note,
        "stage3:v14_selection_fused_join:"
        "component_shape");
}

BOOST_AUTO_TEST_CASE(
    proof_level_value_address_role_and_multiplicity_attacks_reject)
{
    const auto& fixture = Honest();
    fused::ProofV1 honest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fused::ProveV1(
            fixture.product, fixture.seed,
            honest, &why),
        why);
    BOOST_CHECK_MESSAGE(
        fused::VerifyV1(
            fixture.manifest,
            fixture.v14.transcript_commitment,
            honest, fixture.seed, &why),
        why);

    const auto& edge = fixture.product.schedule.edges[0];
    auto value = fixture.product.columns;
    AddOne(
        value, fixture.product.layout.edge_value,
        edge.join_row);
    RequireForcedProofReject(
        fixture, std::move(value), "value");

    auto address = fixture.product.columns;
    AddOne(
        address, fixture.product.layout.edge_event,
        edge.join_row);
    RequireForcedProofReject(
        fixture, std::move(address), "address");

    auto role = fixture.product.columns;
    AddOne(
        role, fixture.product.layout.edge_role,
        edge.join_row);
    RequireForcedProofReject(
        fixture, std::move(role), "role");

    auto multiplicity = fixture.product.columns;
    multiplicity[
        fixture.product.layout.edge_multiplicity]
        [edge.join_row] = gf::Fp3::Zero();
    RequireForcedProofReject(
        fixture, std::move(multiplicity),
        "multiplicity");
}

BOOST_AUTO_TEST_SUITE_END()
