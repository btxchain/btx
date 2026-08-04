// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v14_transcript_provenance_join.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace provenance =
    matmul::v4::rc::stage3_v14_transcript_provenance_join;
namespace aq = matmul::v4::rc::air_quotient;
namespace alg_hash = matmul::v4::rc::alg_hash;
namespace bridge =
    matmul::v4::rc::stage3_safe_v12_recursive_bridge;
namespace derived =
    matmul::v4::rc::stage3_v13_derived_hash_air;
namespace event_export =
    matmul::v4::rc::stage3_v14_event_output_export_air;
namespace fused =
    matmul::v4::rc::stage3_v14_selection_fused_join;
namespace gf = matmul::v4::rc::gkr_field;
namespace occurrence =
    matmul::v4::rc::stage3_v13_occurrence_manifest;
namespace selection =
    matmul::v4::rc::stage3_v13_selection_query_air;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v14_transcript_provenance_join_tests)

namespace {

uint256 Seed(uint32_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                (tag + 29 * index) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

selection::RawFp3V1 Raw(
    const alg_hash::Digest& digest)
{
    selection::RawFp3V1 out;
    for (uint32_t coordinate = 0;
         coordinate < 3; ++coordinate) {
        out.coordinate[coordinate] =
            gf::Canonical(digest[coordinate]);
    }
    return out;
}

gf::Fp3 Field(
    const selection::RawFp3V1& raw)
{
    return {
        gf::FromU64(raw.coordinate[0]),
        gf::FromU64(raw.coordinate[1]),
        gf::FromU64(raw.coordinate[2])};
}

struct Fixture {
    uint256 seed{Seed(0xa137)};
    tape::PublicShapeV1 shape{};
    bridge::NativeSplitRapMultiRowTypedSafeScheduleV2
        native;
    bridge::TypedSafeDirectParentProductV14 v14;
    occurrence::ManifestV1 manifest;
    selection::ProductV1 selected;
    fused::ProductV1 fused_product;
    derived::ProductV1 derived_product;
    event_export::ProductV1 export_product;
    provenance::ProductV1 product;

    Fixture()
    {
        constexpr uint32_t N = 8;
        std::vector<std::vector<gf::Fp3>> columns(
            4, std::vector<gf::Fp3>(
                   N, gf::Fp3::Zero()));
        for (uint32_t row = 0;
             row < N; ++row) {
            columns[0][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(
                        3 + 2 * row +
                        row * row));
            columns[1][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(
                        7 + 5 * row));
        }
        const auto make_cs =
            [](const gf::Fp3& challenge) {
                aq::AirConstraintSystem<gf::Fp3> cs;
                cs.n_rows = N;
                cs.n_columns = 4;
                aq::AirConstraint<gf::Fp3> relation;
                relation.name =
                    "test.provenance.relation";
                relation.kind =
                    aq::AirKind::kEverywhere;
                relation.alg_degree = 1;
                relation.eval =
                    [challenge](
                        const auto& cur,
                        const auto&) {
                        return gf::Sub(
                            cur[2],
                            gf::Add(
                                cur[0],
                                gf::Mul(
                                    challenge,
                                    cur[1])));
                    };
                cs.constraints.push_back(
                    std::move(relation));
                aq::AirConstraint<gf::Fp3> transition;
                transition.name =
                    "test.provenance.next";
                transition.kind =
                    aq::AirKind::kTransition;
                transition.alg_degree = 1;
                transition.eval =
                    [](const auto& cur,
                       const auto& next) {
                        return gf::Sub(
                            next[3],
                            gf::Add(
                                cur[3],
                                cur[2]));
                    };
                cs.constraints.push_back(
                    std::move(transition));
                return cs;
            };
        const std::vector<uint32_t>
            base_indices{0, 1};
        const auto shape_cs =
            make_cs(gf::Fp3::Zero());
        const auto r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                shape_cs, columns,
                base_indices);
        BOOST_REQUIRE_MESSAGE(
            r0.valid, r0.note);
        const uint256 relation_digest =
            aq::AirChallengeDigest(
                seed,
                "test.provenance.relation",
                {r0.base_row_commitment},
                {N, 4});
        const gf::Fp3 challenge =
            gf::FromChallengeBytes3(
                relation_digest.data());
        auto cs = make_cs(challenge);
        for (uint32_t row = 0;
             row < N; ++row) {
            columns[2][row] =
                gf::Add(
                    columns[0][row],
                    gf::Mul(
                        challenge,
                        columns[1][row]));
            if (row + 1 < N) {
                columns[3][row + 1] =
                    gf::Add(
                        columns[3][row],
                        columns[2][row]);
            }
        }
        cs.preprocessed.emplace_back(
            1, columns[1]);
        cs.preprocessed_pin_ood = true;
        cs.preprocessed_row_group_roots.push_back({
            .version = 1,
            .role =
                aq::AirPreprocessedRowGroupRole::kR0,
            .ordered_columns = base_indices,
            .root = r0.base_row_commitment,
        });
        const auto proved =
            aq::AirQuotientProveRowsSplitRapSafeV2(
                cs, columns, base_indices,
                seed, {}, &r0);
        BOOST_REQUIRE_MESSAGE(
            proved.ok, proved.note);

        std::string why;
        BOOST_REQUIRE_MESSAGE(
            bridge::
                BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
                    cs, proved.proof,
                    base_indices, seed,
                    native, &why),
            why);
        shape.trace_rows = cs.n_rows;
        shape.trace_columns = cs.n_columns;
        shape.quotient_len = cs.QuotientLen();
        shape.n_coeffs =
            proved.proof.batch.n_coeffs;
        shape.base_column_indices =
            base_indices;
        BOOST_REQUIRE_MESSAGE(
            occurrence::
                BuildCanonicalOccurrenceManifestV1(
                    shape, native.program,
                    manifest, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            bridge::BuildTypedSafeDirectParentV14(
                native.program, native.witness,
                v14, &why),
            why);

        selection::InputV1 input;
        for (uint32_t pair = 0;
             pair < 2; ++pair) {
            for (uint32_t ordinal = 0;
                 ordinal < 2; ++ordinal) {
                const uint32_t candidate =
                    2 * pair + ordinal;
                const uint32_t event =
                    manifest.selectors[pair]
                        .candidate_events[ordinal];
                input.ood_candidate[candidate] =
                    Raw(v14.event_output[event]);
            }
        }
        const std::array<gf::Fp3, 2>
            z1_candidates{{
                Field(input.ood_candidate[0]),
                Field(input.ood_candidate[1])}};
        const std::array<gf::Fp3, 2>
            z2_candidates{{
                Field(input.ood_candidate[2]),
                Field(input.ood_candidate[3])}};
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
        input.proof_tape_z1 =
            input.ood_candidate[z1_ordinal];
        input.proof_tape_z2 =
            input.ood_candidate[
                2 + z2_ordinal];
        input.n_lde =
            shape.n_coeffs * rc::kRCFriBlowup;
        for (uint32_t event = 0;
             event < native.program.size();
             ++event) {
            if (native.program[event].kind !=
                bridge::TypedSafeChallengeKindV13::
                    QueryCandidate) {
                continue;
            }
            const uint64_t lane0 =
                gf::Canonical(
                    v14.event_output[event][0]);
            input.query_digest_lane0.push_back(
                lane0);
            input.proof_query_index.push_back(
                static_cast<uint32_t>(
                    lane0 &
                    uint64_t{
                        input.n_lde - 1}));
        }
        selected =
            selection::BuildProductV1(input);
        BOOST_REQUIRE_MESSAGE(
            selected.valid, selected.note);
        fused_product =
            fused::BuildProductV1(
                manifest, v14, selected);
        BOOST_REQUIRE_MESSAGE(
            fused_product.valid,
            fused_product.note);

        derived::SelectedPointsV1 points;
        points.z1 = z1;
        points.z2 = z2;
        derived_product =
            derived::BuildProductV1(
                shape,
                native.canonical_v13_abi_words,
                points);
        BOOST_REQUIRE_MESSAGE(
            derived_product.valid,
            derived_product.note);

        event_export::InputV1 export_input;
        export_input.manifest = manifest;
        export_input.event_output.resize(
            v14.event_output.size());
        for (uint32_t event = 0;
             event < v14.event_output.size();
             ++event) {
            for (uint32_t lane = 0;
                 lane < 4; ++lane) {
                export_input.event_output[event][lane] =
                    gf::Canonical(
                        v14.event_output[event][lane]);
            }
        }
        export_product =
            event_export::BuildProductV1(
                export_input);
        BOOST_REQUIRE_MESSAGE(
            export_product.valid,
            export_product.note);
        product =
            provenance::BuildProductV1(
                manifest, fused_product,
                derived_product,
                export_product);
        BOOST_REQUIRE_MESSAGE(
            product.valid, product.note);
    }
};

Fixture& Honest()
{
    static Fixture fixture;
    return fixture;
}

void AddOne(
    std::vector<std::vector<gf::Fp3>>& columns,
    const provenance::CellRefV1& cell)
{
    columns[cell.column][cell.row] =
        gf::Add(
            columns[cell.column][cell.row],
            gf::Fp3::One());
}

void RequireProofReject(
    const Fixture& fixture,
    std::vector<std::vector<gf::Fp3>> columns,
    const char* label)
{
    BOOST_REQUIRE_GT(
        provenance::CountViolationsV1(
            fixture.product.cs, columns),
        0U);
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
    provenance::ProofV1 envelope;
    envelope.plan_root =
        fixture.product.plan.plan_root;
    envelope.program_root =
        fixture.manifest.program_root;
    envelope.transcript_commitment =
        fixture.fused_product
            .expected_transcript_commitment;
    envelope.derived_binding =
        fixture.derived_product.binding;
    envelope.proof = forged.proof;
    std::string why;
    BOOST_CHECK_MESSAGE(
        !provenance::VerifyV1(
            fixture.manifest,
            fixture.fused_product
                .expected_transcript_commitment,
            fixture.derived_product.binding,
            envelope, fixture.seed, &why),
        label << ": " << why);
}

void RequireWitnessReject(
    const Fixture& fixture,
    std::vector<std::vector<gf::Fp3>> columns,
    const char* label)
{
    BOOST_CHECK_MESSAGE(
        provenance::CountViolationsV1(
            fixture.product.cs, columns) > 0,
        label);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    all_prior_and_derived_occurrences_prove_and_attacks_reject)
{
    const Fixture& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(product.actual_v14_outputs_bound);
    BOOST_CHECK(product.selected_points_bound_to_derived);
    BOOST_CHECK(
        product.consumer_u32_decomposition_constrained);
    BOOST_CHECK(product.prior_output_occurrences_bound);
    BOOST_CHECK(product.derived_hash_occurrences_bound);
    BOOST_CHECK(product.exact_multiplicities_consumed);
    BOOST_CHECK(!product.canonical_abi_occurrences_bound);
    BOOST_CHECK(!product.protocol_constant_occurrences_bound);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_CHECK_EQUAL(
        product.plan.prior_occurrences,
        fixture.manifest
            .prior_event_output_byte_occurrences +
            fixture.manifest
                .outer_fri_seed_feedback_byte_occurrences);
    BOOST_CHECK_EQUAL(
        product.plan.derived_occurrences,
        fixture.manifest
            .derived_hash_byte_occurrences);
    BOOST_CHECK_EQUAL(
        product.plan.selected_field_edges, 6U);

    provenance::ProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        provenance::ProveV1(
            product, fixture.seed,
            proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        provenance::VerifyV1(
            fixture.manifest,
            fixture.fused_product
                .expected_transcript_commitment,
            fixture.derived_product.binding,
            proof, fixture.seed, &why),
        why);

    auto output = product.columns;
    AddOne(
        output,
        product.plan.field_edges.front()
            .destination);
    RequireProofReject(
        fixture, std::move(output),
        "V14-output-to-export");

    const auto selected_edge =
        std::find_if(
            product.plan.field_edges.begin(),
            product.plan.field_edges.end(),
            [](const auto& edge) {
                return edge.kind ==
                    provenance::FieldEdgeKindV1::
                        SelectionToDerivedSelectedPoint;
            });
    BOOST_REQUIRE(
        selected_edge !=
        product.plan.field_edges.end());
    auto selected = product.columns;
    AddOne(
        selected,
        selected_edge->destination);
    RequireWitnessReject(
        fixture, std::move(selected),
        "selected-to-derived");

    const auto derived_source =
        std::find_if(
            product.plan.byte_sources.begin(),
            product.plan.byte_sources.end(),
            [](const auto& source) {
                return source.kind ==
                    provenance::ByteSourceKindV1::
                        DerivedShapeCommit;
            });
    BOOST_REQUIRE(
        derived_source !=
        product.plan.byte_sources.end());
    auto digest = product.columns;
    AddOne(
        digest,
        derived_source->byte_cell);
    RequireWitnessReject(
        fixture, std::move(digest),
        "derived-digest-byte");

    const auto prior_source =
        std::find_if(
            product.plan.byte_sources.begin(),
            product.plan.byte_sources.end(),
            [](const auto& source) {
                return source.kind ==
                    provenance::ByteSourceKindV1::
                        PriorEventOutput;
            });
    BOOST_REQUIRE(
        prior_source !=
        product.plan.byte_sources.end());
    auto prior = product.columns;
    AddOne(
        prior,
        prior_source->bit_cell[0]);
    RequireWitnessReject(
        fixture, std::move(prior),
        "prior-output-byte");

    const auto consumer =
        product.plan.byte_consumers.front();
    const uint32_t lane =
        consumer.message_ordinal %
        provenance::kConsumerLanesV1;
    auto destination = product.columns;
    AddOne(
        destination,
        {product.plan.consumer_bit_base +
             lane *
                 provenance::kConsumerBitsPerLaneV1 +
             8 * consumer.byte_in_message_word,
         consumer.message.row});
    RequireWitnessReject(
        fixture, std::move(destination),
        "consumer-byte-transplant");

    BOOST_TEST_MESSAGE(
        "V14_PROVENANCE_JOIN rows="
        << product.cs.n_rows
        << " columns=" << product.cs.n_columns
        << " field_edges="
        << product.plan.field_edges.size()
        << " byte_sources="
        << product.plan.byte_sources.size()
        << " occurrences="
        << product.plan.byte_consumers.size());
}

BOOST_AUTO_TEST_SUITE_END()
