// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvpage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvpage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page)
{
    modelnet::SwarmKvPageRegistry kv;
    std::string err;
    BOOST_CHECK(!kv.Share("", "fam-a", "fam-b", true, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK(!kv.shared(""));
    BOOST_CHECK(!kv.bytes_moved());
}

BOOST_AUTO_TEST_CASE(same_family_not_compat)
{
    modelnet::SwarmKvPageRegistry kv;
    std::string err;
    BOOST_CHECK(!kv.Share("page-1", "fam", "fam", true, err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(!kv.shared("page-1"));
    BOOST_CHECK(!kv.bytes_moved());
}

BOOST_AUTO_TEST_CASE(compatible_false)
{
    modelnet::SwarmKvPageRegistry kv;
    std::string err;
    BOOST_CHECK(!kv.Share("page-1", "fam-a", "fam-b", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_COMPAT");
    BOOST_CHECK(!kv.shared("page-1"));
    BOOST_CHECK(!kv.bytes_moved());
}

BOOST_AUTO_TEST_CASE(share_then_replay)
{
    modelnet::SwarmKvPageRegistry kv;
    std::string err = "stale";
    BOOST_REQUIRE(kv.Share("page-1", "fam-a", "fam-b", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(kv.shared("page-1"));
    BOOST_CHECK(!kv.bytes_moved());

    BOOST_CHECK(!kv.Share("page-1", "fam-c", "fam-d", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(kv.shared("page-1"));
    BOOST_CHECK(!kv.bytes_moved());
}

BOOST_AUTO_TEST_SUITE_END()
