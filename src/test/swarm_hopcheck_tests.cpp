// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_hopcheck.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_hopcheck_tests, BasicTestingSetup)

static modelnet::SwarmHopCheck DescribedHop()
{
    modelnet::SwarmHopCheck check;
    check.route_id = "route-1";
    check.preimage_len = 32;
    check.covers_outputs = true;
    check.overlapping_timeout = false;
    check.signer = true;
    check.hops = 2;
    return check;
}

BOOST_AUTO_TEST_CASE(empty_route_is_route)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.route_id.clear();
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, check.hops);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(preimage_len_31_is_preimage)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.preimage_len = 31;
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, check.hops);
    BOOST_CHECK_EQUAL(result.code, "PREIMAGE");
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
}

BOOST_AUTO_TEST_CASE(covers_outputs_false_is_outputs)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.covers_outputs = false;
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, check.hops);
    BOOST_CHECK_EQUAL(result.code, "OUTPUTS");
    BOOST_CHECK_EQUAL(err, "OUTPUTS");
}

BOOST_AUTO_TEST_CASE(overlapping_timeout_is_timeout)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.overlapping_timeout = true;
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, check.hops);
    BOOST_CHECK_EQUAL(result.code, "TIMEOUT");
    BOOST_CHECK_EQUAL(err, "TIMEOUT");
}

BOOST_AUTO_TEST_CASE(signer_false_is_signer)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.signer = false;
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, check.hops);
    BOOST_CHECK_EQUAL(result.code, "SIGNER");
    BOOST_CHECK_EQUAL(err, "SIGNER");
}

BOOST_AUTO_TEST_CASE(hops_one_is_hops)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.hops = 1;
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, check.hops);
    BOOST_CHECK_EQUAL(result.code, "HOPS");
    BOOST_CHECK_EQUAL(err, "HOPS");
}

BOOST_AUTO_TEST_CASE(well_formed_description_is_unqualified)
{
    modelnet::SwarmHopCheck check = DescribedHop();
    check.preimage_len = 32;
    check.covers_outputs = true;
    check.overlapping_timeout = false;
    check.signer = true;
    check.hops = 2;
    std::string err = "prior";
    const modelnet::SwarmHopCheckResult result = modelnet::SwarmCheckHopScript(check, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.hops, static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(result.code, "UNQUALIFIED");
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
}

BOOST_AUTO_TEST_SUITE_END()
