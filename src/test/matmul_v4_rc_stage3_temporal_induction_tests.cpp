// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_temporal_induction.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace ti =
    matmul::v4::rc::stage3_temporal;
namespace aq =
    matmul::v4::rc::air_quotient;
namespace gf =
    matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_temporal_induction_tests)

namespace {

ti::TemporalRootU32V1 Root(uint32_t seed)
{
    ti::TemporalRootU32V1 root;
    for (uint32_t word = 0;
         word < ti::kTemporalRootWordsV1;
         ++word) {
        root.words[word] =
            seed * 0x101U + word * 0x10001U;
    }
    return root;
}

std::vector<ti::TemporalTransitionV1>
HonestTransitions()
{
    std::vector<ti::TemporalTransitionV1>
        transitions;
    for (uint32_t round = 0;
         round < 4;
         ++round) {
        transitions.push_back({
            round,
            Root(10 + round),
            Root(11 + round)});
    }
    return transitions;
}

ti::TemporalInductionManifestV1 HonestManifest()
{
    ti::TemporalInductionManifestV1 manifest;
    const auto transitions =
        HonestTransitions();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ti::BuildTemporalInductionManifestV1(
            4,
            Root(10),
            Root(14),
            transitions,
            manifest,
            &why),
        why);
    return manifest;
}

void Recommit(
    ti::TemporalInductionManifestV1& manifest)
{
    manifest.commitment =
        ti::ComputeTemporalInductionCommitmentV1(
            manifest);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    honest_chain_builds_and_appends_fail_closed)
{
    const auto manifest = HonestManifest();
    const auto air =
        ti::BuildTemporalInductionAirV1(
            manifest);
    BOOST_REQUIRE_MESSAGE(air.valid, air.note);
    BOOST_CHECK_EQUAL(air.cs.n_rows, 8U);
    BOOST_CHECK_EQUAL(
        air.cs.n_columns,
        ti::TemporalInductionLayoutV1::
            kColumns);
    BOOST_CHECK_EQUAL(
        air.cs.preprocessed.size(),
        ti::TemporalInductionLayoutV1::
            kSemanticFields);
    BOOST_CHECK(air.cs.preprocessed_pin_ood);
    BOOST_CHECK_EQUAL(air.violations, 0U);
    BOOST_CHECK(
        air.verifier_owned_preprocessed_rows);
    BOOST_CHECK(air.base_anchor_constrained);
    BOOST_CHECK(
        air.strict_round_increment_constrained);
    BOOST_CHECK(
        air.transition_continuity_constrained);
    BOOST_CHECK(air.final_anchor_constrained);
    BOOST_CHECK(air.active_padding_constrained);
    BOOST_CHECK(
        !air.direct_endpoint_aliases_installed);
    BOOST_CHECK(!air.recursively_consumed);

    aq::AirConstraintSystem<gf::Fp3> parent;
    parent.n_rows = manifest.n_rows;
    parent.n_columns = 1;
    std::vector<std::vector<gf::Fp3>>
        parent_columns(
            1,
            std::vector<gf::Fp3>(
                manifest.n_rows,
                gf::Fp3::Zero()));
    const auto attachment =
        ti::AppendTemporalInductionToParentV1(
            parent, parent_columns, manifest);
    BOOST_REQUIRE_MESSAGE(
        attachment.valid, attachment.note);
    BOOST_CHECK_EQUAL(attachment.layout.base, 1U);
    BOOST_CHECK_EQUAL(
        attachment.columns_added,
        ti::TemporalInductionLayoutV1::
            kColumns);
    BOOST_CHECK_GT(
        attachment.constraints_added, 0U);
    BOOST_CHECK_EQUAL(
        attachment.violations, 0U);
    BOOST_CHECK(
        !attachment.direct_endpoint_aliases_installed);
    BOOST_CHECK(!attachment.recursively_consumed);
}

BOOST_AUTO_TEST_CASE(
    manifest_rejects_omission_reorder_duplicate_and_foreign_splice)
{
    const auto honest = HonestManifest();
    std::string why;

    auto omission = honest;
    omission.transitions.erase(
        omission.transitions.begin() + 1);
    Recommit(omission);
    BOOST_CHECK(
        !ti::ValidateTemporalInductionManifestV1(
            omission, &why));

    auto reorder = honest;
    std::swap(
        reorder.transitions[1],
        reorder.transitions[2]);
    Recommit(reorder);
    BOOST_CHECK(
        !ti::ValidateTemporalInductionManifestV1(
            reorder, &why));

    auto duplicate = honest;
    duplicate.transitions[2].round = 1;
    Recommit(duplicate);
    BOOST_CHECK(
        !ti::ValidateTemporalInductionManifestV1(
            duplicate, &why));

    auto foreign = honest;
    foreign.transitions[2] = {
        2, Root(100), Root(101)};
    Recommit(foreign);
    BOOST_CHECK(
        !ti::ValidateTemporalInductionManifestV1(
            foreign, &why));
}

BOOST_AUTO_TEST_CASE(
    manifest_rejects_wrong_public_base_and_final_anchors)
{
    const auto honest = HonestManifest();
    std::string why;

    auto wrong_base = honest;
    wrong_base.base_root = Root(200);
    Recommit(wrong_base);
    BOOST_CHECK(
        !ti::ValidateTemporalInductionManifestV1(
            wrong_base, &why));

    auto wrong_final = honest;
    wrong_final.final_root = Root(201);
    Recommit(wrong_final);
    BOOST_CHECK(
        !ti::ValidateTemporalInductionManifestV1(
            wrong_final, &why));
}

BOOST_AUTO_TEST_CASE(
    air_rejects_row_and_padding_smuggling_attacks)
{
    const auto manifest = HonestManifest();
    const auto air =
        ti::BuildTemporalInductionAirV1(
            manifest);
    BOOST_REQUIRE(air.valid);

    auto duplicate_round = air.columns;
    duplicate_round[air.layout.Round()][2] =
        gf::Fp3::FromFp(1);
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, duplicate_round),
        0U);

    auto reordered = air.columns;
    for (uint32_t field = 0;
         field <
             ti::TemporalInductionLayoutV1::
                 kSemanticFields;
         ++field) {
        std::swap(
            reordered[
                air.layout.Witness(field)][1],
            reordered[
                air.layout.Witness(field)][2]);
    }
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, reordered),
        0U);

    auto foreign = air.columns;
    for (uint32_t word = 0;
         word < ti::kTemporalRootWordsV1;
         ++word) {
        foreign[air.layout.Input(word)][2] =
            gf::Fp3::FromFp(
                Root(100).words[word]);
        foreign[air.layout.Output(word)][2] =
            gf::Fp3::FromFp(
                Root(101).words[word]);
    }
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, foreign),
        0U);

    auto omitted = air.columns;
    omitted[air.layout.Active()][1] =
        gf::Fp3::Zero();
    omitted[air.layout.Padding()][1] =
        gf::Fp3::One();
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, omitted),
        0U);

    auto inactive_smuggle = air.columns;
    const uint32_t padding_row =
        manifest.expected_rounds;
    inactive_smuggle[
        air.layout.Round()][padding_row] =
        gf::Fp3::FromFp(99);
    inactive_smuggle[
        air.layout.Input(0)][padding_row] =
        gf::Fp3::FromFp(7);
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, inactive_smuggle),
        0U);

    auto wrong_base = air.columns;
    wrong_base[air.layout.Input(0)][0] =
        gf::Add(
            wrong_base[air.layout.Input(0)][0],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, wrong_base),
        0U);

    auto wrong_final = air.columns;
    wrong_final[air.layout.Output(0)]
               [manifest.expected_rounds - 1] =
        gf::Add(
            wrong_final[air.layout.Output(0)]
                       [manifest.expected_rounds - 1],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        ti::CountTemporalInductionViolationsV1(
            air.cs, wrong_final),
        0U);
}

BOOST_AUTO_TEST_CASE(
    root_loader_rejects_goldilocks_x_plus_p_alias)
{
    const uint256 transcript_root =
        uint256::FromHex(
            "ffeeddccbbaa99887766554433221100"
            "0123456789abcdeffedcba9876543210")
            .value();
    BOOST_CHECK(
        ti::DecodeTemporalRootU32V1(
            ti::EncodeTemporalRootU32V1(
                transcript_root)) ==
        transcript_root);

    std::array<gf::Fp3,
               ti::kTemporalRootWordsV1>
        lanes{};
    for (uint32_t word = 0;
         word < ti::kTemporalRootWordsV1;
         ++word) {
        lanes[word] =
            gf::Fp3::FromFp(word + 1);
    }
    ti::TemporalRootU32V1 decoded;
    std::string why;
    BOOST_REQUIRE(
        ti::DecodeCanonicalTemporalRootU32V1(
            lanes, decoded, &why));
    BOOST_CHECK_EQUAL(decoded.words[0], 1U);

    // Raw p+1 is algebraically the same field element as 1.  The canonical
    // loader rejects it before reduction, so it cannot name a second root.
    lanes[0] = gf::Fp3{gf::kP + 1, 0, 0};
    BOOST_CHECK(
        !ti::DecodeCanonicalTemporalRootU32V1(
            lanes, decoded, &why));
    BOOST_CHECK_EQUAL(
        why,
        "temporal:root_lane_not_canonical_u32");

    lanes[0] = gf::Fp3{1, 1, 0};
    BOOST_CHECK(
        !ti::DecodeCanonicalTemporalRootU32V1(
            lanes, decoded, &why));
}

BOOST_AUTO_TEST_CASE(
    proof_level_preprocessed_pin_rejects_coherent_foreign_chain)
{
    const auto manifest = HonestManifest();
    const auto air =
        ti::BuildTemporalInductionAirV1(
            manifest);
    BOOST_REQUIRE(air.valid);

    const uint256 seed =
        uint256::FromHex(
            "09f1a9f4239781540f623f31b7b505bd"
            "39331c6b8b48e1d9c800937d13fc97ca")
            .value();
    const auto honest =
        aq::AirQuotientProve<gf::Fp3>(
            air.cs, air.columns, seed);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_REQUIRE(honest.division_exact);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            air.cs, honest.proof, seed, &why),
        why);
    auto opening_tamper = honest.proof;
    BOOST_REQUIRE(
        !opening_tamper.next_openings.empty());
    BOOST_REQUIRE(
        !opening_tamper.next_openings[0].empty());
    opening_tamper.next_openings[0][0].leaf =
        gf::Add(
            opening_tamper.next_openings[0][0].leaf,
            gf::Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            air.cs,
            opening_tamper,
            seed,
            &why));

    // Change an internal state on both sides of the transition and in the
    // prover's expected mirror.  All algebraic chain equations still vanish:
    // only the verifier's immutable preprocessed row pin distinguishes it
    // from the canonical statement.
    auto foreign = air.columns;
    const gf::Fp3 delta = gf::Fp3::One();
    foreign[air.layout.Output(0)][0] =
        gf::Add(
            foreign[air.layout.Output(0)][0],
            delta);
    foreign[air.layout.Input(0)][1] =
        gf::Add(
            foreign[air.layout.Input(0)][1],
            delta);
    foreign[
        air.layout.Expected(
            ti::TemporalInductionLayoutV1::
                kOutputField)][0] =
        foreign[air.layout.Output(0)][0];
    foreign[
        air.layout.Expected(
            ti::TemporalInductionLayoutV1::
                kInputField)][1] =
        foreign[air.layout.Input(0)][1];
    BOOST_REQUIRE_EQUAL(
        ti::CountTemporalInductionViolationsV1(
            air.cs, foreign),
        0U);

    const auto forged =
        aq::AirQuotientProve<gf::Fp3>(
            air.cs, foreign, seed);
    bool accepted = false;
    if (forged.ok && forged.division_exact) {
        accepted =
            aq::AirQuotientVerify<gf::Fp3>(
                air.cs,
                forged.proof,
                seed,
                &why);
    }
    BOOST_CHECK_MESSAGE(
        !accepted,
        "coherent foreign temporal chain passed "
        "the verifier-owned preprocessed pin");
}

BOOST_AUTO_TEST_SUITE_END()
