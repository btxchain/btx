// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_occurrence_manifest.h>

#include <algorithm>
#include <map>
#include <tuple>

namespace occurrence =
    matmul::v4::rc::stage3_v13_occurrence_manifest;
namespace bridge =
    matmul::v4::rc::stage3_safe_v12_recursive_bridge;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_occurrence_manifest_tests)

namespace {

uint256 TestSeed(uint32_t value)
{
    uint256 out;
    for (uint32_t index = 0; index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                (value + 29U * index) & 0xffU);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

tape::PublicShapeV1 ToyShape()
{
    tape::PublicShapeV1 out;
    out.trace_rows = 8;
    out.trace_columns = 4;
    out.quotient_len = 8;
    out.n_coeffs = 8;
    out.base_column_indices = {0, 1};
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    shape_rebuilds_exact_program_and_fail_closed_manifest)
{
    const auto shape = ToyShape();
    std::vector<bridge::TypedSafeEventProgramV13> program;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        occurrence::BuildCanonicalTypedProgramV1(
            shape, program, &why),
        why);
    BOOST_REQUIRE_GT(program.size(), 192U);
    BOOST_CHECK(
        program[0].kind ==
        bridge::TypedSafeChallengeKindV13::AirLambda);
    BOOST_CHECK(
        program[1].kind ==
        bridge::TypedSafeChallengeKindV13::FriSeed);
    BOOST_CHECK(
        program[2].kind ==
        bridge::TypedSafeChallengeKindV13::OodZ1);
    BOOST_CHECK(
        program[6].kind ==
        bridge::TypedSafeChallengeKindV13::
            BatchCoefficient);

    occurrence::ManifestV1 manifest;
    BOOST_REQUIRE_MESSAGE(
        occurrence::BuildCanonicalOccurrenceManifestV1(
            shape, program, manifest, &why),
        why);
    BOOST_CHECK(manifest.valid);
    BOOST_CHECK(manifest.proof_tape_schedule_regenerated);
    BOOST_CHECK(manifest.canonical_program_rebuilt_from_shape);
    BOOST_CHECK(manifest.public_program_exact_match);
    BOOST_CHECK(manifest.every_abi_address_resolved);
    BOOST_CHECK(
        manifest.every_consumer_destination_resolved);
    BOOST_CHECK(manifest.no_native_verify_or_replay);
    BOOST_CHECK_GT(
        manifest.outer_fri_seed_feedback_byte_occurrences,
        32U);
    BOOST_CHECK_EQUAL(
        manifest.outer_fri_seed_feedback_byte_occurrences %
            32U,
        0U);
    BOOST_CHECK_EQUAL(
        manifest.query_seed_feedback_field_occurrences,
        4U * rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_GT(
        manifest.canonical_abi_byte_occurrences, 0U);
    BOOST_CHECK_GT(
        manifest.prior_event_output_byte_occurrences, 0U);
    BOOST_CHECK_GT(
        manifest.derived_hash_byte_occurrences, 0U);
    BOOST_CHECK_GT(
        manifest.protocol_constant_byte_occurrences, 0U);
    const std::array<uint32_t, 2> z1_candidates{2, 3};
    const std::array<uint32_t, 2> z2_candidates{4, 5};
    BOOST_CHECK(
        manifest.selectors[0].candidate_events ==
        z1_candidates);
    BOOST_CHECK(
        manifest.selectors[1].candidate_events ==
        z2_candidates);
    BOOST_CHECK(
        manifest.selectors[0]
            .selected_ordinal_is_witness_dependent);
    BOOST_CHECK(
        manifest.selectors[0]
            .first_acceptable_air_required);
    BOOST_CHECK(!manifest.selected_ood_ordinal_public);
    BOOST_CHECK(!manifest.selector_air_executed);
    BOOST_CHECK(!manifest.derived_hash_air_executed);
    BOOST_CHECK(!manifest.consumer_equalities_executed);
    BOOST_CHECK(!manifest.recursively_consumed);
    BOOST_CHECK(!manifest.recursive_authority_ready);
    BOOST_CHECK(
        occurrence::ValidateCanonicalOccurrenceManifestV1(
            shape, program, manifest, &why));

    // Public program order, omission and binding are committed metadata,
    // never inferred from a proof witness.
    {
        auto changed = program;
        std::swap(changed[2], changed[3]);
        occurrence::ManifestV1 rejected;
        BOOST_CHECK(
            !occurrence::BuildCanonicalOccurrenceManifestV1(
                shape, changed, rejected, &why));
    }
    {
        auto changed = program;
        changed.erase(changed.begin() + 2);
        occurrence::ManifestV1 rejected;
        BOOST_CHECK(
            !occurrence::BuildCanonicalOccurrenceManifestV1(
                shape, changed, rejected, &why));
    }
    {
        auto changed = program;
        auto cell = std::find_if(
            changed[2].message.begin(),
            changed[2].message.end(),
            [](const auto& item) {
                return item.binding ==
                    bridge::TypedSafeMessageBindingV13::
                        ProofOwned;
            });
        BOOST_REQUIRE(cell != changed[2].message.end());
        cell->binding =
            bridge::TypedSafeMessageBindingV13::Constant;
        occurrence::ManifestV1 rejected;
        BOOST_CHECK(
            !occurrence::BuildCanonicalOccurrenceManifestV1(
                shape, changed, rejected, &why));
    }
    {
        // A source-byte/address transplant is rejected by exact
        // rebuild-and-compare, even if all event cells are unchanged.
        auto changed = manifest;
        const auto occurrence_it = std::find_if(
            changed.byte_occurrences.begin(),
            changed.byte_occurrences.end(),
            [](const auto& item) {
                return item.canonical_abi_source;
            });
        BOOST_REQUIRE(
            occurrence_it != changed.byte_occurrences.end());
        occurrence_it->abi_source_address ^= 1U;
        BOOST_CHECK(
            !occurrence::ValidateCanonicalOccurrenceManifestV1(
                shape, program, changed, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    native_honest_schedule_has_exact_manifest_parity)
{
    constexpr uint32_t N = 8;
    const uint256 seed = TestSeed(0x931);
    std::vector<std::vector<gf::Fp3>> columns(
        4, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    3 + 2 * row + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(
                gf::FromU64(7 + 5 * row));
    }
    const auto make_cs =
        [](const gf::Fp3& relation_challenge) {
            aq::AirConstraintSystem<gf::Fp3> cs;
            cs.n_rows = N;
            cs.n_columns = 4;
            aq::AirConstraint<gf::Fp3> relation;
            relation.name = "test.occurrence.relation";
            relation.kind = aq::AirKind::kEverywhere;
            relation.alg_degree = 1;
            relation.eval =
                [relation_challenge](
                    const auto& cur,
                    const auto&) {
                    return gf::Sub(
                        cur[2],
                        gf::Add(
                            cur[0],
                            gf::Mul(
                                relation_challenge,
                                cur[1])));
                };
            cs.constraints.push_back(
                std::move(relation));
            aq::AirConstraint<gf::Fp3> transition;
            transition.name = "test.occurrence.next";
            transition.kind = aq::AirKind::kTransition;
            transition.alg_degree = 1;
            transition.eval =
                [](const auto& cur,
                   const auto& next) {
                    return gf::Sub(
                        next[3],
                        gf::Add(cur[3], cur[2]));
                };
            cs.constraints.push_back(
                std::move(transition));
            return cs;
        };
    const std::vector<uint32_t> base_indices{0, 1};
    const auto shape_cs = make_cs(gf::Fp3::Zero());
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape_cs, columns, base_indices);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const uint256 relation_digest =
        aq::AirChallengeDigest(
            seed, "test.occurrence.relation",
            {r0.base_row_commitment}, {N, 4});
    const gf::Fp3 relation_challenge =
        gf::FromChallengeBytes3(
            relation_digest.data());
    auto cs = make_cs(relation_challenge);
    for (uint32_t row = 0; row < N; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(
                    relation_challenge,
                    columns[1][row]));
        if (row + 1 < N) {
            columns[3][row + 1] =
                gf::Add(
                    columns[3][row],
                    columns[2][row]);
        }
    }
    cs.preprocessed.emplace_back(1, columns[1]);
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
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    bridge::NativeSplitRapMultiRowTypedSafeScheduleV2
        native;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        bridge::BuildNativeSplitRapMultiRowTypedSafeScheduleV2(
            cs, proved.proof, base_indices,
            seed, native, &why),
        why);
    tape::PublicShapeV1 shape;
    shape.trace_rows = cs.n_rows;
    shape.trace_columns = cs.n_columns;
    shape.quotient_len = cs.QuotientLen();
    shape.n_coeffs = proved.proof.batch.n_coeffs;
    shape.base_column_indices = base_indices;

    occurrence::ManifestV1 manifest;
    BOOST_REQUIRE_MESSAGE(
        occurrence::BuildCanonicalOccurrenceManifestV1(
            shape, native.program, manifest, &why),
        why);
    BOOST_CHECK_EQUAL(
        manifest.canonical_program.size(),
        native.program.size());
    BOOST_CHECK_EQUAL(
        manifest.canonical_abi_byte_occurrences,
        native.child.canonical_abi_byte_occurrences);
    BOOST_CHECK_EQUAL(
        manifest.prior_event_output_byte_occurrences,
        native.child.prior_event_output_byte_occurrences);
    BOOST_CHECK_EQUAL(
        manifest.derived_hash_byte_occurrences,
        native.child.derived_hash_byte_occurrences);
    BOOST_CHECK_EQUAL(
        manifest.protocol_constant_byte_occurrences,
        native.child.protocol_constant_byte_occurrences);

    using Destination =
        std::tuple<uint32_t, uint32_t, uint8_t>;
    std::map<Destination, const occurrence::ByteOccurrenceV1*>
        by_destination;
    for (const auto& item : manifest.byte_occurrences) {
        BOOST_REQUIRE(
            by_destination.emplace(
                Destination{
                    item.consumer_event,
                    item.consumer_message_ordinal,
                    item.byte_in_message_word},
                &item).second);
    }
    for (const auto& word :
         native.child.transcript_word_bindings) {
        for (uint32_t byte = 0;
             byte < word.bytes_present; ++byte) {
            const auto found = by_destination.find({
                word.event + occurrence::kOuterEventCountV1,
                word.message_ordinal,
                static_cast<uint8_t>(byte)});
            BOOST_REQUIRE(
                found != by_destination.end());
            const auto& actual = *found->second;
            const auto& source = word.source_bytes[byte];
            if (source.canonical_abi_source) {
                BOOST_CHECK(actual.canonical_abi_source);
                BOOST_CHECK(actual.abi_key == source.abi_key);
                BOOST_CHECK_EQUAL(
                    actual.abi_source_address,
                    source.abi_source_address);
                BOOST_CHECK_EQUAL(
                    actual.byte_in_abi_word,
                    source.byte_in_abi_word);
            } else if (source.prior_event_output_source) {
                BOOST_CHECK(
                    actual.prior_event_output_source);
                const uint32_t producer =
                    source.producer_event +
                    occurrence::kOuterEventCountV1;
                BOOST_CHECK_GE(
                    producer, actual.source_event_begin);
                BOOST_CHECK_LE(
                    producer, actual.source_event_end);
                BOOST_CHECK_EQUAL(
                    actual.source_output_lane,
                    source.producer_output_lane);
                BOOST_CHECK_EQUAL(
                    actual.byte_in_output_lane,
                    source.byte_offset % 8);
            } else if (source.hash_relation_required) {
                BOOST_CHECK(actual.derived_hash_source);
            } else {
                BOOST_CHECK(
                    actual.source_kind ==
                    occurrence::ByteSourceKindV1::
                        ProtocolConstant);
            }
        }
    }
    BOOST_TEST_MESSAGE(
        "V13_OCCURRENCE_NATIVE_PARITY events="
        << manifest.canonical_program.size()
        << " bytes=" << manifest.byte_occurrences.size()
        << " abi=" <<
            manifest.canonical_abi_byte_occurrences
        << " prior=" <<
            manifest.prior_event_output_byte_occurrences
        << " derived=" <<
            manifest.derived_hash_byte_occurrences);
}

BOOST_AUTO_TEST_SUITE_END()
