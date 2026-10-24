// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault07.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault07_tests, BasicTestingSetup)

static modelnet::SwarmFault07 PresentPage()
{
    modelnet::SwarmFault07 in;
    in.page_id = "page-1";
    in.owner_present = true;
    in.durable = false;
    in.want_transfer = false;
    return in;
}

static void ExpectNoMove(const modelnet::SwarmFault07Result& result)
{
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.broadcast);
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmFault07 in = PresentPage();
    in.page_id.clear();
    in.owner_present = true;
    in.durable = true;
    in.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmFault07Result result = modelnet::SwarmRecoverFault07(in, err);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK(!result.recovered);
    ExpectNoMove(result);
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(missing_owner_is_incomplete)
{
    modelnet::SwarmFault07 in = PresentPage();
    in.owner_present = false;
    in.durable = true;
    in.want_transfer = true;
    std::string err = "prior";
    const modelnet::SwarmFault07Result result = modelnet::SwarmRecoverFault07(in, err);
    BOOST_CHECK_EQUAL(result.code, "INCOMPLETE");
    BOOST_CHECK(!result.recovered);
    ExpectNoMove(result);
    BOOST_CHECK_EQUAL(err, "INCOMPLETE");
}

BOOST_AUTO_TEST_CASE(want_transfer_is_held)
{
    modelnet::SwarmFault07 in = PresentPage();
    in.want_transfer = true;
    in.durable = true;
    std::string err = "prior";
    const modelnet::SwarmFault07Result result = modelnet::SwarmRecoverFault07(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.recovered);
    ExpectNoMove(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(durable_is_durable)
{
    modelnet::SwarmFault07 in = PresentPage();
    in.durable = true;
    std::string err = "prior";
    const modelnet::SwarmFault07Result result = modelnet::SwarmRecoverFault07(in, err);
    BOOST_CHECK_EQUAL(result.code, "DURABLE");
    BOOST_CHECK(result.recovered);
    ExpectNoMove(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmFault07 in = PresentPage();
    std::string err = "prior";
    const modelnet::SwarmFault07Result result = modelnet::SwarmRecoverFault07(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.recovered);
    ExpectNoMove(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
