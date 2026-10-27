// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvadmit.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvadmit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_is_page)
{
    std::string err = "prior";
    modelnet::SwarmKvAdmit page;
    page.page_id = "";
    page.family_id = "family";
    page.same_prefix = true;
    page.engine_present = true;
    page.revoked = false;
    page.want_move = false;
    page.bytes = 64;
    const modelnet::SwarmKvAdmitResult result = modelnet::SwarmAdmitKvPage(page, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(revoked_is_revoked)
{
    std::string err = "prior";
    modelnet::SwarmKvAdmit page;
    page.page_id = "page";
    page.family_id = "family";
    page.same_prefix = true;
    page.engine_present = true;
    page.revoked = true;
    page.want_move = false;
    page.bytes = 64;
    const modelnet::SwarmKvAdmitResult result = modelnet::SwarmAdmitKvPage(page, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(different_prefix_is_prefix)
{
    std::string err = "prior";
    modelnet::SwarmKvAdmit page;
    page.page_id = "page";
    page.family_id = "family";
    page.same_prefix = false;
    page.engine_present = true;
    page.revoked = false;
    page.want_move = false;
    page.bytes = 64;
    const modelnet::SwarmKvAdmitResult result = modelnet::SwarmAdmitKvPage(page, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "PREFIX");
    BOOST_CHECK_EQUAL(err, "PREFIX");
}

BOOST_AUTO_TEST_CASE(engine_missing_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmKvAdmit page;
    page.page_id = "page";
    page.family_id = "family";
    page.same_prefix = true;
    page.engine_present = false;
    page.revoked = false;
    page.want_move = true;
    page.bytes = 64;
    const modelnet::SwarmKvAdmitResult result = modelnet::SwarmAdmitKvPage(page, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(want_move_is_held_and_admitted)
{
    std::string err = "prior";
    modelnet::SwarmKvAdmit page;
    page.page_id = "page";
    page.family_id = "family";
    page.same_prefix = true;
    page.engine_present = true;
    page.revoked = false;
    page.want_move = true;
    page.bytes = 64;
    const modelnet::SwarmKvAdmitResult result = modelnet::SwarmAdmitKvPage(page, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(without_want_move_is_noted_and_admitted)
{
    std::string err = "prior";
    modelnet::SwarmKvAdmit page;
    page.page_id = "page";
    page.family_id = "family";
    page.same_prefix = true;
    page.engine_present = true;
    page.revoked = false;
    page.want_move = false;
    page.bytes = 64;
    const modelnet::SwarmKvAdmitResult result = modelnet::SwarmAdmitKvPage(page, err);
    BOOST_CHECK(result.admitted);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
