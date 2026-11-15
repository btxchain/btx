// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_discover/nif_discover.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_discover_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(multicast_hint_is_not_authority)
{
    modelnet::NifDiscover discover;
    std::string err;
    BOOST_CHECK(discover.hint_only());
    BOOST_CHECK(!discover.authority());
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!discover.Hint("", true, true, err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!discover.hinted(""));

    BOOST_CHECK(discover.Hint("cast-peer", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(discover.hinted("cast-peer"));
    BOOST_CHECK(discover.peer_multicast("cast-peer"));
    BOOST_CHECK(discover.peer_authenticated("cast-peer"));
    BOOST_CHECK(discover.hint_only());
    BOOST_CHECK(!discover.authority());
    BOOST_CHECK(!discover.authority("cast-peer"));

    BOOST_CHECK(!discover.Connect("cast-peer", err));
    BOOST_CHECK_EQUAL(err, "HINT");
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!discover.Hint("cast-peer", false, false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(discover.peer_authenticated("cast-peer"));
    BOOST_CHECK(discover.peer_multicast("cast-peer"));
    BOOST_CHECK(discover.hint_only());
    BOOST_CHECK(!discover.authority());
    BOOST_CHECK(!discover.launched());
    BOOST_CHECK(!discover.gpu());
    BOOST_CHECK(!discover.broadcast());
    BOOST_CHECK_EQUAL(discover.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(unauthenticated_peer_is_auth)
{
    modelnet::NifDiscover discover;
    std::string err;
    BOOST_CHECK(!discover.Hint("open-peer", false, false, err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK(discover.hinted("open-peer"));
    BOOST_CHECK(!discover.peer_authenticated("open-peer"));
    BOOST_CHECK(!discover.authority());
    BOOST_CHECK(!discover.authority("open-peer"));
    BOOST_CHECK(discover.hint_only());
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(0));

    BOOST_CHECK(!discover.Hint("open-peer", false, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(!discover.peer_authenticated("open-peer"));
    BOOST_CHECK(!discover.authority());
    BOOST_CHECK(!discover.authority("open-peer"));

    BOOST_CHECK(!discover.Connect("open-peer", err));
    BOOST_CHECK_EQUAL(err, "AUTH");
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(discover.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(one_authenticated_local_peer_can_connect)
{
    modelnet::NifDiscover discover;
    std::string err;
    BOOST_CHECK(discover.Hint("id-a", false, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(discover.authority());
    BOOST_CHECK(discover.authority("id-a"));
    BOOST_CHECK(!discover.hint_only());
    BOOST_CHECK(discover.peer_authenticated("id-a"));
    BOOST_CHECK(!discover.peer_multicast("id-a"));
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(0));

    BOOST_CHECK(discover.Connect("id-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(1));
    BOOST_CHECK(discover.Connect("id-a", err));
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!discover.Connect("", err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK(!discover.Connect("missing-peer", err));
    BOOST_CHECK_EQUAL(err, "PEER");
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(1));
    BOOST_CHECK(!discover.launched());
    BOOST_CHECK(!discover.gpu());
    BOOST_CHECK(!discover.broadcast());
    BOOST_CHECK_EQUAL(discover.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(wan_is_no_route)
{
    modelnet::NifDiscover discover;
    std::string err;
    BOOST_CHECK(!discover.Wan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!discover.Scan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NOT_SCAN);
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(discover.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!discover.launched());
    BOOST_CHECK(!discover.gpu());
    BOOST_CHECK(!discover.broadcast());
    BOOST_CHECK_EQUAL(discover.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(hosts_stay_one)
{
    modelnet::NifDiscover discover;
    std::string err;
    BOOST_CHECK_EQUAL(discover.ranks(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(discover.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.physical_hosts(), static_cast<int64_t>(1));

    BOOST_CHECK(discover.Hint("id-a", false, true, err));
    BOOST_CHECK(discover.Hint("id-b", false, true, err));
    BOOST_CHECK_EQUAL(discover.ranks(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(discover.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(discover.authority("id-a"));
    BOOST_CHECK(discover.authority("id-b"));
    BOOST_CHECK(discover.Connect("id-a", err));
    BOOST_CHECK(discover.Connect("id-b", err));
    BOOST_CHECK_EQUAL(discover.connected(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(discover.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!discover.Wan(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_NO_ROUTE);
    BOOST_CHECK_EQUAL(discover.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(discover.ranks(), static_cast<int64_t>(2));
}

BOOST_AUTO_TEST_SUITE_END()
