// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_prefixbook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_prefixbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_is_page)
{
    std::string err = "prior";
    modelnet::SwarmPrefixBook page;
    page.page_id = "";
    page.same_prefix = true;
    page.same_family = true;
    page.engine_present = true;
    page.want_share = true;
    const modelnet::SwarmPrefixBookResult result = modelnet::SwarmMatchPrefix(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(same_family_different_prefix_is_not_compat)
{
    std::string err = "prior";
    modelnet::SwarmPrefixBook page;
    page.page_id = "page";
    page.same_prefix = false;
    page.same_family = true;
    page.engine_present = true;
    page.want_share = false;
    const modelnet::SwarmPrefixBookResult result = modelnet::SwarmMatchPrefix(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(different_prefix_different_family_is_prefix)
{
    std::string err = "prior";
    modelnet::SwarmPrefixBook page;
    page.page_id = "page";
    page.same_prefix = false;
    page.same_family = false;
    page.engine_present = true;
    page.want_share = true;
    const modelnet::SwarmPrefixBookResult result = modelnet::SwarmMatchPrefix(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "PREFIX");
    BOOST_CHECK_EQUAL(err, "PREFIX");
}

BOOST_AUTO_TEST_CASE(engine_missing_same_prefix_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmPrefixBook page;
    page.page_id = "page";
    page.same_prefix = true;
    page.same_family = false;
    page.engine_present = false;
    page.want_share = true;
    const modelnet::SwarmPrefixBookResult result = modelnet::SwarmMatchPrefix(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK(!result.compatible);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_share_same_prefix_engine_present_is_held)
{
    std::string err = "prior";
    modelnet::SwarmPrefixBook page;
    page.page_id = "page";
    page.same_prefix = true;
    page.same_family = false;
    page.engine_present = true;
    page.want_share = true;
    const modelnet::SwarmPrefixBookResult result = modelnet::SwarmMatchPrefix(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK(result.compatible);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(same_prefix_without_share_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmPrefixBook page;
    page.page_id = "page";
    page.same_prefix = true;
    page.same_family = false;
    page.engine_present = true;
    page.want_share = false;
    const modelnet::SwarmPrefixBookResult result = modelnet::SwarmMatchPrefix(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK(result.compatible);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
