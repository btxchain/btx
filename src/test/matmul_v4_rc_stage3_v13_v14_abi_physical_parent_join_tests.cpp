// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_v13_v14_abi_physical_parent_join.h>

#include <array>
#include <cstdlib>
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

namespace parent_join =
    matmul::v4::rc::stage3_v13_v14_abi_physical_parent_join;
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
namespace abi_join =
    matmul::v4::rc::stage3_v13_v14_abi_logup_join;
namespace prefix =
    matmul::v4::rc::stage3_v14_protocol_prefix_join;
namespace provenance =
    matmul::v4::rc::stage3_v14_transcript_provenance_join;
namespace proofabi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;
namespace selection =
    matmul::v4::rc::stage3_v13_selection_query_air;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_v14_abi_physical_parent_join_tests)

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

gf::Fp3 Field(const selection::RawFp3V1& raw)
{
    return {
        gf::FromU64(raw.coordinate[0]),
        gf::FromU64(raw.coordinate[1]),
        gf::FromU64(raw.coordinate[2])};
}

struct Fixture {
    uint256 seed{Seed(0xab11)};
    tape::PublicShapeV1 shape{};
    tape::PublicBindingV1 tape_binding{};
    bridge::NativeSplitRapMultiRowTypedSafeScheduleV2
        native;
    bridge::TypedSafeDirectParentProductV14 v14;
    occurrence::ManifestV1 manifest;
    tape::ProductV1 tape_product;
    selection::ProductV1 selected;
    fused::ProductV1 fused_product;
    derived::ProductV1 derived_product;
    event_export::ProductV1 export_product;
    provenance::ProductV1 provenance_product;
    prefix::ProductV1 prefix_product;
    parent_join::ProductV1 product;

    Fixture()
    {
        constexpr uint32_t N = 8;
        std::vector<std::vector<gf::Fp3>> columns(
            4, std::vector<gf::Fp3>(
                   N, gf::Fp3::Zero()));
        for (uint32_t row = 0; row < N; ++row) {
            columns[0][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(
                        3 + 2 * row +
                        row * row));
            columns[1][row] =
                gf::Fp3::FromFp(
                    gf::FromU64(7 + 5 * row));
        }
        const auto make_cs =
            [](const gf::Fp3& challenge) {
                aq::AirConstraintSystem<gf::Fp3> cs;
                cs.n_rows = N;
                cs.n_columns = 4;
                cs.constraints.push_back({
                    "test.physical_parent.relation",
                    aq::AirKind::kEverywhere, 1,
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
                    }});
                cs.constraints.push_back({
                    "test.physical_parent.next",
                    aq::AirKind::kTransition, 1,
                    [](const auto& cur,
                       const auto& next) {
                        return gf::Sub(
                            next[3],
                            gf::Add(
                                cur[3], cur[2]));
                    }});
                return cs;
            };
        const std::vector<uint32_t>
            base_indices{0, 1};
        const auto shape_cs =
            make_cs(gf::Fp3::Zero());
        const auto r0 =
            aq::AirQuotientBuildTwoEpochBaseRowSession(
                shape_cs, columns, base_indices);
        BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
        const uint256 relation_digest =
            aq::AirChallengeDigest(
                seed,
                "test.physical_parent.relation",
                {r0.base_row_commitment},
                {N, 4});
        const gf::Fp3 challenge =
            gf::FromChallengeBytes3(
                relation_digest.data());
        auto cs = make_cs(challenge);
        for (uint32_t row = 0; row < N; ++row) {
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
        BOOST_REQUIRE(
            !proved.proof.batch.column_len.empty());
        shape.quotient_len =
            proved.proof.batch.column_len.back();
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

        tape_binding.program_root = Seed(0x10);
        tape_binding.statement_root = Seed(0x20);
        tape_binding.public_fs_seed =
            native.outer.replay.fri_seed;
        tape_binding.proof_wire_root = Seed(0x30);
        tape_binding.tape_root =
            tape::ComputeTapeRootV1(
                shape, tape_binding,
                native.canonical_v13_abi_words,
                &why);
        BOOST_REQUIRE_MESSAGE(
            tape_binding.tape_root !=
                alg_hash::Digest{},
            why);
        const auto decoded =
            proofabi::DecodeCanonicalSafeV13(
                native.canonical_v13_abi_words,
                &why);
        BOOST_REQUIRE_MESSAGE(
            decoded.has_value(), why);
        const auto tape_schedule =
            tape::BuildScheduleV1(
                shape, tape_binding);
        BOOST_REQUIRE_MESSAGE(
            tape_schedule.valid,
            tape_schedule.note);
        BOOST_REQUIRE_EQUAL(
            decoded->sources.size(),
            tape_schedule.semantic_sources.size());
        for (uint32_t index = 0;
             index < decoded->sources.size();
             ++index) {
            const auto& record =
                tape_schedule.records[
                    tape::kPublicPrefixRecordsV1 +
                    tape::kHeaderRecordsV1 +
                    index];
            if (!record.fixed_value) continue;
            BOOST_REQUIRE_MESSAGE(
                decoded->sources[index].value ==
                    record.expected_value,
                "fixed tape source mismatch at address " <<
                    index << " kind=" <<
                    static_cast<uint32_t>(
                        record.key.kind) <<
                    " expected=" <<
                    record.expected_value <<
                    " actual=" <<
                    decoded->sources[index].value);
        }
        tape_product =
            tape::BuildProductV1(
                shape, tape_binding,
                native.canonical_v13_abi_words);
        BOOST_REQUIRE_MESSAGE(
            tape_product.valid,
            tape_product.note);

        selection::InputV1 input;
        for (uint32_t pair = 0; pair < 2; ++pair) {
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
        selected = selection::BuildProductV1(input);
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
        provenance_product =
            provenance::BuildProductV1(
                manifest, fused_product,
                derived_product,
                export_product);
        BOOST_REQUIRE_MESSAGE(
            provenance_product.valid,
            provenance_product.note);
        prefix_product =
            prefix::BuildProductV1(
                manifest, provenance_product);
        BOOST_REQUIRE_MESSAGE(
            prefix_product.valid,
            prefix_product.note);
        BOOST_REQUIRE_MESSAGE(
            parent_join::BuildProductV1(
                tape_product, prefix_product,
                manifest, seed, product, &why),
            why);
    }
};

Fixture& Honest()
{
    static Fixture fixture;
    return fixture;
}

bool FullActualProductEnabled()
{
    const char* enabled =
        std::getenv(
            "BTX_RUN_V13_V14_PHYSICAL_FULL");
    return enabled != nullptr &&
        std::string{enabled} == "1";
}

struct BoundedFixture {
    static constexpr uint32_t kRows = 16;

    uint256 seed{Seed(0x71)};
    abi_join::BoundedPhysicalCanaryStatementV1
        statement{};
    abi_join::PlanV1 plan;
    aq::AirConstraintSystem<gf::Fp3> resident_cs;
    std::vector<std::vector<gf::Fp3>>
        resident_columns;
    std::vector<uint32_t> base_indices;
    abi_join::ProductV1 product;
    uint32_t source_word{0x13579bdfU};

    BoundedFixture()
    {
        const tape::LayoutV1 tape_layout =
            tape::CanonicalLayoutV1();
        const bridge::TypedSafeDirectParentLayoutV14
            v14_layout;
        const uint32_t tape_offset = 0;
        const uint32_t v14_offset =
            tape_layout.End();

        resident_cs.n_rows = kRows;
        resident_cs.n_columns =
            v14_offset + v14_layout.end;
        resident_columns.assign(
            resident_cs.n_columns,
            std::vector<gf::Fp3>(
                kRows, gf::Fp3::Zero()));
        base_indices.resize(
            resident_cs.n_columns);
        std::iota(
            base_indices.begin(),
            base_indices.end(), 0U);

        std::string why;
        BOOST_REQUIRE_MESSAGE(
            abi_join::BuildBoundedPhysicalCanaryPlanV1(
                statement, kRows,
                tape_offset, v14_offset,
                plan, &why),
            why);
        BOOST_REQUIRE_EQUAL(
            plan.sources.size(), 1U);
        BOOST_REQUIRE_EQUAL(
            plan.consumers.size(), 1U);
        const auto& source = plan.sources.front();
        resident_columns[source.address.column]
                        [source.address.row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    statement.abi_address));
        resident_columns[source.value.column]
                        [source.value.row] =
            gf::Fp3::FromFp(
                gf::FromU64(source_word));
        for (uint32_t bit = 0; bit < 32; ++bit) {
            resident_columns[
                tape_layout.Bit(
                    (tape::kPublicPrefixRecordsV1 +
                     tape::kHeaderRecordsV1 +
                     statement.abi_address) %
                        tape::kRecordsPerRowV1,
                    bit)]
                [source.address.row] =
                    gf::Fp3::FromFp(
                        gf::FromU64(
                            (source_word >> bit) & 1U));
        }
        const uint32_t expected_byte =
            (source_word >>
             (8 * statement.byte_in_word)) &
            0xffU;
        resident_columns[
            v14_offset + v14_layout.Message(0)]
            [statement.consumer_row] =
                gf::Fp3::FromFp(
                    gf::FromU64(expected_byte));

        for (uint32_t bit = 0; bit < 32; ++bit) {
            const uint32_t bit_column =
                tape_layout.Bit(
                    (tape::kPublicPrefixRecordsV1 +
                     tape::kHeaderRecordsV1 +
                     statement.abi_address) %
                        tape::kRecordsPerRowV1,
                    bit);
            resident_cs.constraints.push_back({
                "test.bounded_physical.source_bit",
                aq::AirKind::kEverywhere, 2,
                [bit_column](
                    const auto& cur,
                    const auto&) {
                    return gf::Mul(
                        cur[bit_column],
                        gf::Sub(
                            cur[bit_column],
                            gf::Fp3::One()));
                }});
        }
        const uint32_t value_column =
            source.value.column;
        const uint32_t record_slot =
            (tape::kPublicPrefixRecordsV1 +
             tape::kHeaderRecordsV1 +
             statement.abi_address) %
            tape::kRecordsPerRowV1;
        resident_cs.constraints.push_back({
            "test.bounded_physical.source_value",
            aq::AirKind::kEverywhere, 1,
            [tape_layout, value_column,
             record_slot](
                const auto& cur,
                const auto&) {
                gf::Fp3 recomposed =
                    gf::Fp3::Zero();
                uint64_t weight = 1;
                for (uint32_t bit = 0;
                     bit < 32; ++bit) {
                    recomposed = gf::Add(
                        recomposed,
                        gf::Mul(
                            gf::Fp3::FromFp(
                                gf::FromU64(weight)),
                            cur[tape_layout.Bit(
                                record_slot, bit)]));
                    weight <<= 1;
                }
                return gf::Sub(
                    cur[value_column],
                    recomposed);
            }});

        BOOST_REQUIRE_MESSAGE(
            abi_join::BuildProductV1(
                plan, seed, resident_cs,
                resident_columns, base_indices,
                product, &why),
            why);
        BOOST_REQUIRE_EQUAL(
            product.violations, 0U);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(
    bounded_physical_join_proof_accepts_and_substitution_rejects)
{
    const BoundedFixture fixture;
    std::string why;
    abi_join::ProofV1 honest;
    BOOST_REQUIRE_MESSAGE(
        abi_join::ProveV1(
            fixture.product, fixture.seed,
            honest, &why),
        why);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeV2(
            fixture.product.cs,
            honest.proof,
            fixture.product
                .r0_base_column_indices,
            fixture.seed, &why),
        why);

    auto substituted =
        fixture.resident_columns;
    const auto& source =
        fixture.plan.sources.front();
    substituted[source.byte_bits[0].column]
               [source.byte_bits[0].row] =
        gf::Add(
            substituted[source.byte_bits[0].column]
                       [source.byte_bits[0].row],
            gf::Fp3::One());
    substituted[source.value.column]
               [source.value.row] =
        gf::Add(
            substituted[source.value.column]
                       [source.value.row],
            gf::Fp3::One());

    abi_join::ProductV1 forged_product;
    BOOST_CHECK(
        !abi_join::BuildProductV1(
            fixture.plan, fixture.seed,
            fixture.resident_cs, substituted,
            fixture.base_indices,
            forged_product, &why));
    BOOST_REQUIRE_GT(
        forged_product.violations, 0U);
    aq::AirProveOptions adversarial;
    adversarial.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            forged_product.cs,
            forged_product.columns,
            forged_product.r0_base_column_indices,
            fixture.seed, adversarial);
    BOOST_REQUIRE_MESSAGE(
        forged.ok, forged.note);
    BOOST_CHECK(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            forged_product.cs,
            forged.proof,
            forged_product
                .r0_base_column_indices,
            fixture.seed, &why));
}

BOOST_AUTO_TEST_CASE(
    actual_products_share_physical_cells_and_complete_r0)
{
    if (!FullActualProductEnabled()) return;
    const Fixture& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_CHECK(product.valid);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(
        product.actual_tape_verifier_resident);
    BOOST_CHECK(
        product.actual_v14_prefix_verifier_resident);
    BOOST_CHECK(
        product.actual_tape_cells_referenced);
    BOOST_CHECK(
        product.actual_v14_message_cells_referenced);
    BOOST_CHECK(product.no_host_copied_value_vector);
    BOOST_CHECK(
        product.complete_parent_r0_committed);
    BOOST_CHECK(
        product.dual_fp3_logup_constrained);
    BOOST_CHECK_EQUAL(
        product.plan
            .complete_r0_base_column_indices.size(),
        product.resident_parent_cs.n_columns);
    BOOST_CHECK_EQUAL(
        product.abi_product.layout.original_columns,
        product.resident_parent_cs.n_columns);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    coherent_tape_substitution_is_rejected_by_physical_logup)
{
    if (!FullActualProductEnabled()) return;
    const Fixture& fixture = Honest();
    BOOST_REQUIRE(
        !fixture.product.plan.abi_plan.sources.empty());
    const auto& source =
        fixture.product.plan.abi_plan.sources.front();
    std::vector<uint32_t> changed_words =
        fixture.native.canonical_v13_abi_words;
    BOOST_REQUIRE_LT(
        source.abi_address,
        changed_words.size());
    changed_words[source.abi_address] ^=
        uint32_t{1} <<
        (8 * source.byte_in_word);

    std::string why;
    auto changed_binding = fixture.tape_binding;
    changed_binding.tape_root =
        tape::ComputeTapeRootV1(
            fixture.shape, changed_binding,
            changed_words, &why);
    BOOST_REQUIRE_MESSAGE(
        changed_binding.tape_root !=
            alg_hash::Digest{},
        why);
    const auto changed_tape =
        tape::BuildProductV1(
            fixture.shape, changed_binding,
            changed_words);
    BOOST_REQUIRE_MESSAGE(
        changed_tape.valid,
        changed_tape.note);
    parent_join::ProductV1 forged;
    BOOST_CHECK(
        !parent_join::BuildProductV1(
            changed_tape,
            fixture.prefix_product,
            fixture.manifest,
            fixture.seed, forged, &why));
}

BOOST_AUTO_TEST_CASE(
    public_plan_transplant_is_rejected_before_proof)
{
    if (!FullActualProductEnabled()) return;
    const Fixture& fixture = Honest();
    parent_join::ProofV1 envelope;
    envelope.plan_root =
        fixture.product.plan.plan_root;
    envelope.abi_proof.plan_root =
        fixture.product.plan.abi_plan.plan_root;
    envelope.abi_proof.r0_row_root =
        fixture.product.abi_product.r0_session
            .base_row_commitment;

    auto changed_binding = fixture.tape_binding;
    changed_binding.statement_root = Seed(0xee);
    std::string why;
    BOOST_CHECK(
        !parent_join::VerifyV1(
            fixture.shape, changed_binding,
            fixture.manifest,
            fixture.prefix_product
                .transcript_commitment,
            fixture.prefix_product
                .derived_binding,
            fixture.seed, envelope, &why));
}

BOOST_AUTO_TEST_SUITE_END()
