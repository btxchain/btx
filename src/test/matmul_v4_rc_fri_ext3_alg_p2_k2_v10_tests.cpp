// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <algorithm>
#include <vector>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_fri_ext3_alg_p2_k2_v10_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

std::vector<std::vector<rc::Fp3>> Columns()
{
    std::vector<std::vector<rc::Fp3>> out(4);
    for (uint32_t column = 0; column < out.size(); ++column) {
        out[column].resize(8 - (column & 1U));
        for (uint32_t row = 0; row < out[column].size(); ++row) {
            out[column][row] = rc::Fp3{
                gf::FromU64(1 + 7 * column + 11 * row),
                gf::FromU64(3 + 5 * column + 13 * row),
                gf::FromU64(9 + 17 * column + 19 * row)};
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    p2_q192_k2_v10_round_trip_and_canonical_codec)
{
    BOOST_CHECK_EQUAL(
        rc::kRCFri3AlgP2Q192K2ProofVersionV10, 10U);
    BOOST_CHECK_EQUAL(
        rc::kRCFri3AlgP2Q192K2OodCandidatesV10, 2U);
    BOOST_CHECK_EQUAL(rc::kRCFri3AlgNumQueries, 192U);
    BOOST_CHECK(!rc::kRCFri3AlgP2Q192K2ActivatedV10);

    const uint256 seed = Seed(0xa1);
    const auto committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    BOOST_CHECK_EQUAL(
        committed.proof.version,
        rc::kRCFri3AlgP2Q192K2ProofVersionV10);
    BOOST_CHECK_EQUAL(
        committed.proof.queries.size(),
        rc::kRCFri3AlgNumQueries);

    std::string why;
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgP2Q192K2V10BatchVerify(
            committed.proof, seed, &why),
        why);

    std::vector<unsigned char> encoded;
    const size_t encoded_size =
        rc::SerializeFri3AlgBatchProof(
            committed.proof, encoded);
    BOOST_REQUIRE_GT(encoded_size, 0U);
    BOOST_REQUIRE_EQUAL(encoded_size, encoded.size());
    const auto parsed =
        rc::DeserializeFri3AlgP2Q192K2V10BatchProof(
            encoded);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_CHECK_EQUAL(
        parsed->version,
        rc::kRCFri3AlgP2Q192K2ProofVersionV10);
    BOOST_CHECK_MESSAGE(
        rc::Fri3AlgP2Q192K2V10BatchVerify(
            *parsed, seed, &why),
        why);
    std::vector<unsigned char> reencoded;
    BOOST_CHECK_EQUAL(
        rc::SerializeFri3AlgBatchProof(
            *parsed, reencoded),
        encoded_size);
    BOOST_CHECK(encoded == reencoded);
    // The active V8 codec rejects V10 before allocating proof internals.
    BOOST_CHECK(
        !rc::DeserializeFri3AlgBatchProof(
            encoded).has_value());
}

BOOST_AUTO_TEST_CASE(
    v10_is_protocol_separated_from_active_p2_v8)
{
    const uint256 seed = Seed(0xa2);
    const auto columns = Columns();
    const auto v10 =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            columns, seed, 0);
    const auto v8 =
        rc::Fri3AlgP2SqueezeBatchCommit(
            columns, seed, 0);
    BOOST_REQUIRE_MESSAGE(v10.ok, v10.note);
    BOOST_REQUIRE_MESSAGE(v8.ok, v8.note);
    BOOST_CHECK_EQUAL(
        v10.proof.version,
        rc::kRCFri3AlgP2Q192K2ProofVersionV10);
    BOOST_CHECK_EQUAL(
        v8.proof.version,
        rc::kRCFri3AlgP2SqueezeLaneProofVersion);

    // Same polynomial statement and row commitment, distinct transcript
    // domain and OOD schedule.
    BOOST_CHECK_EQUAL(
        v10.proof.n_coeffs, v8.proof.n_coeffs);
    BOOST_CHECK(
        v10.proof.column_len == v8.proof.column_len);
    BOOST_CHECK(
        v10.proof.row_commit.root ==
        v8.proof.row_commit.root);
    BOOST_CHECK(!gf::Eq(v10.proof.lambda, v8.proof.lambda));

    std::string why;
    BOOST_CHECK(
        !rc::Fri3AlgP2SqueezeBatchVerify(
            v10.proof, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgP2Q192K2V10BatchVerify(
            v8.proof, seed, &why));
    BOOST_CHECK(
        !rc::Fri3AlgBatchVerify(
            v10.proof, seed, &why));

    // Merely relabelling a V10 proof as V8 cannot cross the domain boundary.
    auto relabelled = v10.proof;
    relabelled.version =
        rc::kRCFri3AlgP2SqueezeLaneProofVersion;
    BOOST_CHECK(
        !rc::Fri3AlgP2SqueezeBatchVerify(
            relabelled, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    v10_verifier_rejects_transcript_and_opening_tamper)
{
    const uint256 seed = Seed(0xa3);
    const auto committed =
        rc::Fri3AlgP2Q192K2V10BatchCommit(
            Columns(), seed, 0);
    BOOST_REQUIRE_MESSAGE(committed.ok, committed.note);
    std::string why;
    BOOST_REQUIRE(
        rc::Fri3AlgP2Q192K2V10BatchVerify(
            committed.proof, seed, &why));

    auto transcript = committed.proof;
    transcript.w1 =
        gf::Add(transcript.w1, rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgP2Q192K2V10BatchVerify(
            transcript, seed, &why));

    auto opening = committed.proof;
    BOOST_REQUIRE(!opening.queries.empty());
    BOOST_REQUIRE(!opening.queries[0].row.values.empty());
    opening.queries[0].row.values[0] =
        gf::Add(
            opening.queries[0].row.values[0],
            rc::Fp3::One());
    BOOST_CHECK(
        !rc::Fri3AlgP2Q192K2V10BatchVerify(
            opening, seed, &why));

    BOOST_CHECK(
        !rc::Fri3AlgP2Q192K2V10BatchVerify(
            committed.proof, Seed(0xa4), &why));
}

BOOST_AUTO_TEST_SUITE_END()
