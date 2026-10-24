// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_enckv.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_enckv_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_kv)
{
    std::string err = "prior";
    modelnet::SwarmEncryptedKvRequest request;
    request.page_id = "";
    request.plaintext = true;
    request.same_trust_domain = true;
    request.seal_present = true;
    request.engine_present = true;
    const modelnet::SwarmEncryptedKvResult result = modelnet::SwarmAdmitEncryptedKv(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "KV");
    BOOST_CHECK_EQUAL(err, "KV");
}

BOOST_AUTO_TEST_CASE(plaintext_is_realm_sealed)
{
    std::string err = "prior";
    modelnet::SwarmEncryptedKvRequest request;
    request.page_id = "page";
    request.plaintext = true;
    request.same_trust_domain = true;
    request.seal_present = true;
    request.engine_present = true;
    const modelnet::SwarmEncryptedKvResult result = modelnet::SwarmAdmitEncryptedKv(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REALM_SEALED");
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
}

BOOST_AUTO_TEST_CASE(other_trust_domain_is_realm_sealed)
{
    std::string err = "prior";
    modelnet::SwarmEncryptedKvRequest request;
    request.page_id = "page";
    request.plaintext = false;
    request.same_trust_domain = false;
    request.seal_present = true;
    request.engine_present = true;
    const modelnet::SwarmEncryptedKvResult result = modelnet::SwarmAdmitEncryptedKv(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REALM_SEALED");
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
}

BOOST_AUTO_TEST_CASE(missing_seal_is_realm_sealed)
{
    std::string err = "prior";
    modelnet::SwarmEncryptedKvRequest request;
    request.page_id = "page";
    request.plaintext = false;
    request.same_trust_domain = true;
    request.seal_present = false;
    request.engine_present = true;
    const modelnet::SwarmEncryptedKvResult result = modelnet::SwarmAdmitEncryptedKv(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REALM_SEALED");
    BOOST_CHECK_EQUAL(err, "REALM_SEALED");
}

BOOST_AUTO_TEST_CASE(absent_engine_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmEncryptedKvRequest request;
    request.page_id = "page";
    request.plaintext = false;
    request.same_trust_domain = true;
    request.seal_present = true;
    request.engine_present = false;
    const modelnet::SwarmEncryptedKvResult result = modelnet::SwarmAdmitEncryptedKv(request, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(sealed_local_admits_without_moving_bytes)
{
    std::string err = "prior";
    modelnet::SwarmEncryptedKvRequest request;
    request.page_id = "page";
    request.plaintext = false;
    request.same_trust_domain = true;
    request.seal_present = true;
    request.engine_present = true;
    const modelnet::SwarmEncryptedKvResult result = modelnet::SwarmAdmitEncryptedKv(request, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "SEALED_LOCAL");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
