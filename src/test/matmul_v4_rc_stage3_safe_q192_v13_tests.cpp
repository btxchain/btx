// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <algorithm>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_safe_q192_v13_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

std::vector<std::vector<gf::Fp3>> Columns()
{
    std::vector<std::vector<gf::Fp3>> out(2);
    for (uint32_t column = 0; column < out.size(); ++column) {
        out[column].resize(8);
        for (uint32_t row = 0; row < out[column].size(); ++row) {
            out[column][row] = gf::Fp3{
                gf::FromU64(1 + 19 * column + 7 * row),
                gf::FromU64(3 + 11 * column + 5 * row),
                gf::FromU64(9 + 13 * column + 17 * row)};
        }
    }
    return out;
}

bool Same(const gf::Fp3& a, const gf::Fp3& b)
{
    return gf::Eq(a, b);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    typed_safe_challenge_is_deterministic_injective_and_role_separated)
{
    const std::vector<unsigned char> transcript{
        0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff};
    gf::Fp3 lambda{};
    gf::Fp3 lambda_again{};
    gf::Fp3 lambda_next{};
    gf::Fp3 fold{};
    gf::Fp3 query0{};
    gf::Fp3 query0_direct{};
    gf::Fp3 query1{};
    gf::Fp3 rejected{};
    rc::Fri3AlgDigest query_seed{};
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "fra3_lambda", 0, lambda, &why),
        why);
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "fra3_lambda", 0, lambda_again, &why));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "fra3_lambda", 1, lambda_next, &why));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "fra3_fold", 0, fold, &why));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2QuerySeedV13(
            transcript, query_seed, &why));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2QueryCandidateV13(
            query_seed, 0, query0_direct, &why));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "fra3_query", 0, query0, &why));
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "fra3_query", 1, query1, &why));

    BOOST_CHECK(Same(lambda, lambda_again));
    BOOST_CHECK(!Same(lambda, lambda_next));
    BOOST_CHECK(!Same(lambda, fold));
    BOOST_CHECK(Same(query0, query0_direct));
    BOOST_CHECK(!Same(query0, query1));
    BOOST_CHECK(lambda.c0 < gf::kP);
    BOOST_CHECK(lambda.c1 < gf::kP);
    BOOST_CHECK(lambda.c2 < gf::kP);

    auto changed = transcript;
    changed.back() ^= 1;
    gf::Fp3 changed_draw{};
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            changed, "fra3_lambda", 0, changed_draw, &why));
    BOOST_CHECK(!Same(lambda, changed_draw));
    rc::Fri3AlgDigest changed_seed{};
    BOOST_REQUIRE(
        rc::Fri3AlgSafeQ192K2QuerySeedV13(
            changed, changed_seed, &why));
    BOOST_CHECK(query_seed != changed_seed);

    auto noncanonical_seed = query_seed;
    noncanonical_seed[0] = gf::kP;
    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2QueryCandidateV13(
            noncanonical_seed, 0, rejected, &why));
    BOOST_CHECK(
        why.find("noncanonical_query_seed") != std::string::npos);

    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2ChallengeFp3V13(
            transcript, "unknown", 0, rejected, &why));
    BOOST_CHECK(why.find("unknown_label") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    safe_q192_k2_roundtrip_is_version_isolated)
{
    const auto columns = Columns();
    const uint256 seed = Seed(0x51);
    const auto proved =
        rc::Fri3AlgSafeQ192K2V13BatchCommit(
            columns, seed, 7);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK_EQUAL(
        proved.proof.version,
        rc::kRCFri3AlgSafeQ192K2ProofVersionV13);
    BOOST_CHECK_EQUAL(
        proved.proof.queries.size(),
        rc::kRCFri3AlgNumQueries);

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgSafeQ192K2V13BatchVerify(
            proved.proof, seed, &why),
        why);
    BOOST_CHECK(
        !rc::Fri3AlgP2Q192K2V10BatchVerify(
            proved.proof, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgP2SqueezeBatchVerify(
            proved.proof, seed, &why));

    std::vector<unsigned char> bytes;
    const size_t encoded_size =
        rc::SerializeFri3AlgBatchProof(
            proved.proof, bytes);
    BOOST_REQUIRE_EQUAL(encoded_size, bytes.size());
    const auto decoded =
        rc::DeserializeFri3AlgSafeQ192K2V13BatchProof(
            bytes);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK_EQUAL(
        decoded->version,
        rc::kRCFri3AlgSafeQ192K2ProofVersionV13);
    BOOST_CHECK(
        !rc::DeserializeFri3AlgBatchProof(bytes).has_value());
}

BOOST_AUTO_TEST_CASE(
    safe_q192_replay_exports_every_native_consumer)
{
    const uint256 seed = Seed(0x53);
    const auto proved =
        rc::Fri3AlgSafeQ192K2V13BatchCommit(
            Columns(), seed, 11);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    rc::Fri3AlgSafeV13Replay replay;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::Fri3AlgSafeQ192K2V13BatchVerifyReplay(
            proved.proof, seed, replay, &why),
        why);
    BOOST_CHECK(replay.native_verified);
    BOOST_CHECK(replay.exact_event_order);
    BOOST_CHECK_EQUAL(replay.lambda_events, 1U);
    BOOST_CHECK_EQUAL(replay.ood_candidate_events, 4U);
    BOOST_CHECK_EQUAL(replay.deep_weight_events, 2U);
    BOOST_CHECK_EQUAL(
        replay.fold_events,
        proved.proof.fold_challenges.size());
    BOOST_CHECK_EQUAL(replay.query_seed_events, 1U);
    BOOST_CHECK_EQUAL(
        replay.query_candidate_events,
        rc::kRCFri3AlgNumQueries);
    BOOST_CHECK_EQUAL(
        replay.events.size(),
        size_t{1 + 4 + 2 + 3 + 1 +
               rc::kRCFri3AlgNumQueries});

    BOOST_REQUIRE(!replay.events.empty());
    BOOST_CHECK(
        replay.events.front().consumer ==
        rc::Fri3AlgSafeV13Consumer::FriLambda);
    BOOST_CHECK_EQUAL(
        replay.events.front().label,
        "fra3_lambda");
    BOOST_CHECK(
        !replay.events.front()
             .transcript_before_draw.empty());
    BOOST_CHECK(
        replay.events.front().safe_digest[3] <
        gf::kP);

    uint32_t selected_z1 = 0;
    uint32_t selected_z2 = 0;
    for (const auto& event : replay.events) {
        if (event.consumer ==
                rc::Fri3AlgSafeV13Consumer::OodZ1 &&
            event.selected) {
            ++selected_z1;
            BOOST_CHECK(event.acceptable);
            BOOST_CHECK(
                Same(
                    event.consumed_fp3,
                    proved.proof.z1));
        }
        if (event.consumer ==
                rc::Fri3AlgSafeV13Consumer::OodZ2 &&
            event.selected) {
            ++selected_z2;
            BOOST_CHECK(event.acceptable);
            BOOST_CHECK(
                Same(
                    event.consumed_fp3,
                    proved.proof.z2));
        }
    }
    BOOST_CHECK_EQUAL(selected_z1, 1U);
    BOOST_CHECK_EQUAL(selected_z2, 1U);

    const auto query_seed =
        std::find_if(
            replay.events.begin(),
            replay.events.end(),
            [](const auto& event) {
                return event.consumer ==
                    rc::Fri3AlgSafeV13Consumer::
                        QuerySeed;
            });
    BOOST_REQUIRE(query_seed != replay.events.end());
    BOOST_CHECK(
        query_seed->safe_digest ==
        replay.query_seed);
    const auto first_query =
        std::find_if(
            replay.events.begin(),
            replay.events.end(),
            [](const auto& event) {
                return event.consumer ==
                    rc::Fri3AlgSafeV13Consumer::
                        QueryIndex;
            });
    BOOST_REQUIRE(first_query != replay.events.end());
    BOOST_CHECK(
        first_query->transcript_before_draw.empty());
    BOOST_CHECK_EQUAL(
        first_query->consumed_index,
        proved.proof.queries.front().index);

    auto bad = proved.proof;
    bad.w1.c0 =
        gf::Add(bad.w1.c0, gf::FromU64(1));
    replay.native_verified = true;
    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2V13BatchVerifyReplay(
            bad, seed, replay, &why));
    BOOST_CHECK(!replay.native_verified);
    BOOST_CHECK(replay.events.empty());
}

BOOST_AUTO_TEST_CASE(
    safe_q192_fixed_k2_selector_is_first_acceptable)
{
    const gf::Fp3 invalid =
        gf::Fp3::FromFp(gf::FromU64(7));
    const gf::Fp3 valid_a{
        gf::FromU64(1),
        gf::FromU64(2),
        gf::FromU64(0)};
    const gf::Fp3 valid_b{
        gf::FromU64(3),
        gf::FromU64(0),
        gf::FromU64(4)};
    uint32_t ordinal = 99;
    gf::Fp3 selected{};

    std::array<gf::Fp3, 2> candidates{
        invalid, valid_a};
    BOOST_REQUIRE(
        rc::Fri3AlgSafeSelectOodK2V13(
            candidates, nullptr,
            ordinal, selected));
    BOOST_CHECK_EQUAL(ordinal, 1U);
    BOOST_CHECK(Same(selected, valid_a));

    candidates = {valid_a, valid_b};
    BOOST_REQUIRE(
        rc::Fri3AlgSafeSelectOodK2V13(
            candidates, nullptr,
            ordinal, selected));
    BOOST_CHECK_EQUAL(ordinal, 0U);
    BOOST_CHECK(Same(selected, valid_a));

    candidates = {valid_a, valid_b};
    BOOST_REQUIRE(
        rc::Fri3AlgSafeSelectOodK2V13(
            candidates, &valid_a,
            ordinal, selected));
    BOOST_CHECK_EQUAL(ordinal, 1U);
    BOOST_CHECK(Same(selected, valid_b));

    candidates = {invalid, invalid};
    BOOST_CHECK(
        !rc::Fri3AlgSafeSelectOodK2V13(
            candidates, nullptr,
            ordinal, selected));
}

BOOST_AUTO_TEST_CASE(
    safe_q192_k2_proof_transcript_and_opening_tamper_reject)
{
    const uint256 seed = Seed(0x61);
    const auto proved =
        rc::Fri3AlgSafeQ192K2V13BatchCommit(
            Columns(), seed, 9);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    std::string why;

    auto bad = proved.proof;
    bad.w1.c0 = gf::Add(bad.w1.c0, gf::FromU64(1));
    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2V13BatchVerify(
            bad, seed, &why));

    bad = proved.proof;
    BOOST_REQUIRE(!bad.queries.empty());
    bad.queries.front().index ^= 1U;
    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2V13BatchVerify(
            bad, seed, &why));

    bad = proved.proof;
    BOOST_REQUIRE(!bad.fold_layers.empty());
    bad.fold_layers.front().root[0] =
        gf::Add(
            bad.fold_layers.front().root[0],
            gf::FromU64(1));
    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2V13BatchVerify(
            bad, seed, &why));

    BOOST_CHECK(
        !rc::Fri3AlgSafeQ192K2V13BatchVerify(
            proved.proof, Seed(0x62), &why));
}

BOOST_AUTO_TEST_CASE(
    v13_is_additive_and_does_not_flip_active_or_authority_routes)
{
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgNumQueries, 192U);
    BOOST_CHECK(rc::kRCFri3AlgActiveP2Squeeze);
    BOOST_CHECK_EQUAL(
        rc::kRCFri3AlgActiveBatchProofVersion,
        rc::kRCFri3AlgP2SqueezeLaneProofVersion);
    BOOST_CHECK(!rc::kRCFri3AlgSafeQ192K2ActivatedV13);
}

BOOST_AUTO_TEST_SUITE_END()
