// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokfp.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace {

modelnet::SwarmMatchFingerprintRequest MatchingIds()
{
    modelnet::SwarmMatchFingerprintRequest request;
    request.family_id = "family-a";
    request.tokenizer_id = "tok-a";
    request.architecture_id = "arch-a";
    request.quantization = "q4";
    request.other_tokenizer_id = "tok-a";
    request.other_architecture_id = "arch-a";
    request.other_quantization = "q4";
    request.family_member = false;
    return request;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_tokfp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tokenizer_is_fingerprint)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.tokenizer_id.clear();
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "FINGERPRINT");
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
}

BOOST_AUTO_TEST_CASE(empty_other_quantization_is_fingerprint)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.other_quantization.clear();
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "FINGERPRINT");
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
}

BOOST_AUTO_TEST_CASE(family_member_with_empty_id_is_fingerprint)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.family_member = true;
    request.architecture_id.clear();
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "FINGERPRINT");
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
}

BOOST_AUTO_TEST_CASE(family_name_does_not_invent_a_match)
{
    modelnet::SwarmMatchFingerprintRequest request;
    request.family_id = "family-a";
    request.family_member = true;
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "FINGERPRINT");
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
}

BOOST_AUTO_TEST_CASE(family_member_tokenizer_mismatch_is_not_compat)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.family_member = true;
    request.other_tokenizer_id = "tok-b";
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "FAMILY_NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "FAMILY_NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(tokenizer_mismatch_is_tokenizer)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.other_tokenizer_id = "tok-b";
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "TOKENIZER");
    BOOST_CHECK_EQUAL(err, "TOKENIZER");
}

BOOST_AUTO_TEST_CASE(architecture_mismatch_is_architecture)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.other_architecture_id = "arch-b";
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "ARCHITECTURE");
    BOOST_CHECK_EQUAL(err, "ARCHITECTURE");
}

BOOST_AUTO_TEST_CASE(quantization_mismatch_is_quantization)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.other_quantization = "q8";
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "QUANTIZATION");
    BOOST_CHECK_EQUAL(err, "QUANTIZATION");
}

BOOST_AUTO_TEST_CASE(equal_ids_are_match)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(result.compatible);
    BOOST_CHECK_EQUAL(result.code, "MATCH");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(family_member_exact_match_is_match)
{
    modelnet::SwarmMatchFingerprintRequest request = MatchingIds();
    request.family_member = true;
    request.family_id = "other-label";
    std::string err = "prior";
    const modelnet::SwarmMatchFingerprintResult result = modelnet::SwarmMatchFingerprint(request, err);
    BOOST_CHECK(result.compatible);
    BOOST_CHECK_EQUAL(result.code, "MATCH");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
