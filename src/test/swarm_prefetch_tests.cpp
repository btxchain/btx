// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_prefetch.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_prefetch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_is_page)
{
    modelnet::SwarmPrefetchRequest page;
    page.page_id.clear();
    page.want_prefetch = true;
    std::string err = "prior";
    const modelnet::SwarmPrefetchResult result = modelnet::SwarmNotePrefetch(page, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(want_prefetch_true_is_held)
{
    modelnet::SwarmPrefetchRequest page;
    page.page_id = "page-a";
    page.want_prefetch = true;
    std::string err = "prior";
    const modelnet::SwarmPrefetchResult result = modelnet::SwarmNotePrefetch(page, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_prefetch_false_is_noted)
{
    modelnet::SwarmPrefetchRequest page;
    page.page_id = "page-b";
    page.want_prefetch = false;
    std::string err = "prior";
    const modelnet::SwarmPrefetchResult result = modelnet::SwarmNotePrefetch(page, err);
    BOOST_CHECK(!result.moved);
    BOOST_CHECK_EQUAL(result.bytes_moved, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
