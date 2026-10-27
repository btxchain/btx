// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_compatfam.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_compatfam_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id)
{
    std::string err = "prior";
    modelnet::SwarmCompatFam page;
    page.same_family = true;
    page.want_share = true;
    const modelnet::SwarmCompatFamResult result = modelnet::SwarmNoteCompatFam(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(same_family_without_want_share)
{
    std::string err = "prior";
    modelnet::SwarmCompatFam page;
    page.page_id = "page-1";
    page.same_family = true;
    page.want_share = false;
    const modelnet::SwarmCompatFamResult result = modelnet::SwarmNoteCompatFam(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOT_COMPAT");
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
}

BOOST_AUTO_TEST_CASE(want_share_without_same_family)
{
    std::string err = "prior";
    modelnet::SwarmCompatFam page;
    page.page_id = "page-1";
    page.same_family = false;
    page.want_share = true;
    const modelnet::SwarmCompatFamResult result = modelnet::SwarmNoteCompatFam(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note)
{
    std::string err = "prior";
    modelnet::SwarmCompatFam page;
    page.page_id = "page-1";
    page.same_family = false;
    page.want_share = false;
    const modelnet::SwarmCompatFamResult result = modelnet::SwarmNoteCompatFam(page, err);
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
