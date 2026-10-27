// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_profitshare.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_profitshare_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_share)
{
    modelnet::SwarmProfitShareRequest share;
    share.share_id.clear();
    share.want_share = false;
    std::string err;
    const modelnet::SwarmProfitShareRefusal result = modelnet::SwarmRefuseProfitShare(share, err);
    BOOST_CHECK_EQUAL(result.code, "SHARE");
    BOOST_CHECK_EQUAL(err, "SHARE");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_share_held)
{
    modelnet::SwarmProfitShareRequest share;
    share.share_id = "share-1";
    share.want_share = true;
    std::string err;
    const modelnet::SwarmProfitShareRefusal result = modelnet::SwarmRefuseProfitShare(share, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmProfitShareRequest share;
    share.share_id = "share-2";
    share.want_share = false;
    std::string err = "stale";
    const modelnet::SwarmProfitShareRefusal result = modelnet::SwarmRefuseProfitShare(share, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.shared);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
