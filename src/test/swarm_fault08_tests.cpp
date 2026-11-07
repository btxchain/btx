// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault08.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault08_tests, BasicTestingSetup)

static modelnet::SwarmFault08 CompatiblePage()
{
    modelnet::SwarmFault08 in;
    in.page_id = "page-1";
    in.truncated = false;
    in.compatible = true;
    in.want_accept = false;
    return in;
}

static void ExpectNoAccept(const modelnet::SwarmFault08Result& result)
{
    BOOST_CHECK(!result.accepted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    in.page_id.clear();
    in.truncated = true;
    in.compatible = false;
    in.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(truncated_is_prefix_mismatch)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    in.truncated = true;
    in.compatible = true;
    in.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "PREFIX_MISMATCH");
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
}

BOOST_AUTO_TEST_CASE(incompatible_is_prefix_mismatch)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    in.truncated = false;
    in.compatible = false;
    in.want_accept = false;
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "PREFIX_MISMATCH");
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
}

BOOST_AUTO_TEST_CASE(truncated_with_want_accept_is_prefix_mismatch)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    in.truncated = true;
    in.compatible = true;
    in.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "PREFIX_MISMATCH");
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
}

BOOST_AUTO_TEST_CASE(incompatible_with_want_accept_is_prefix_mismatch)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    in.truncated = false;
    in.compatible = false;
    in.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "PREFIX_MISMATCH");
    ExpectNoAccept(result);
    BOOST_CHECK_EQUAL(err, "PREFIX_MISMATCH");
}

BOOST_AUTO_TEST_CASE(want_accept_is_held)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    in.truncated = false;
    in.compatible = true;
    in.want_accept = true;
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(compatible_page_is_noted)
{
    modelnet::SwarmFault08 in = CompatiblePage();
    std::string err = "prior";
    const modelnet::SwarmFault08Result result = modelnet::SwarmRecoverFault08(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    ExpectNoAccept(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
