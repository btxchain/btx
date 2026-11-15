// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag09.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_flag09_tests, BasicTestingSetup)

static modelnet::SwarmFlag09 QualifiedReal()
{
    modelnet::SwarmFlag09 in;
    in.descendant_id = "desc-9";
    in.qualified = true;
    in.real_run = true;
    in.want_cert = false;
    in.want_realm = false;
    in.want_pass = false;
    return in;
}

static void ExpectNoPromotion(const modelnet::SwarmFlag09Result& result)
{
    BOOST_CHECK(!result.issued);
    BOOST_CHECK(!result.realm);
    BOOST_CHECK(!result.replay_admitted);
    BOOST_CHECK(!result.passed);
}

BOOST_AUTO_TEST_CASE(empty_descendant_id_is_descendant)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    in.descendant_id.clear();
    in.want_cert = true;
    in.want_realm = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "DESCENDANT");
    BOOST_CHECK_EQUAL(err, "DESCENDANT");
}

BOOST_AUTO_TEST_CASE(not_qualified_is_no_cert_even_if_want_cert)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    in.qualified = false;
    in.want_cert = true;
    in.want_realm = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "NO_CERT");
    BOOST_CHECK_EQUAL(err, "NO_CERT");
}

BOOST_AUTO_TEST_CASE(not_real_run_is_no_cert_even_if_want_cert)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    in.real_run = false;
    in.want_cert = true;
    in.want_realm = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "NO_CERT");
    BOOST_CHECK_EQUAL(err, "NO_CERT");
}

BOOST_AUTO_TEST_CASE(want_realm_is_not_realm)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    in.want_realm = true;
    in.want_cert = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "NOT_REALM");
    BOOST_CHECK_EQUAL(err, "NOT_REALM");
}

BOOST_AUTO_TEST_CASE(want_cert_is_held)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    in.want_cert = true;
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(want_pass_is_unqualified)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    in.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_CASE(qualified_real_descendant_is_noted)
{
    modelnet::SwarmFlag09 in = QualifiedReal();
    std::string err = "prior";
    const modelnet::SwarmFlag09Result result = modelnet::SwarmStageGraduate(in, err);
    ExpectNoPromotion(result);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
