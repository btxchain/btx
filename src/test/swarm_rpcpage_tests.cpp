// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rpcpage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_rpcpage_tests, BasicTestingSetup)

static modelnet::SwarmRpcPage NotedPage()
{
    modelnet::SwarmRpcPage page;
    page.page_id = "page-1";
    page.want_add = false;
    return page;
}

BOOST_AUTO_TEST_CASE(empty_page_is_page)
{
    modelnet::SwarmRpcPage page = NotedPage();
    page.page_id.clear();
    page.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmRpcPageResult result = modelnet::SwarmNoteRpcPage(page, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(want_add_is_held)
{
    modelnet::SwarmRpcPage page = NotedPage();
    page.want_add = true;
    std::string err = "prior";
    const modelnet::SwarmRpcPageResult result = modelnet::SwarmNoteRpcPage(page, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_add_false_is_noted)
{
    modelnet::SwarmRpcPage page = NotedPage();
    page.want_add = false;
    std::string err = "prior";
    const modelnet::SwarmRpcPageResult result = modelnet::SwarmNoteRpcPage(page, err);
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
