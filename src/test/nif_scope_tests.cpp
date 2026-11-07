// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_scope/nif_scope.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nif_scope_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(local_copy_lan_exchange_wan_and_beacon)
{
    modelnet::NifScope scope;
    std::string err;
    const std::vector<unsigned char> payload{'p', 'i', 'n', 'g'};
    BOOST_CHECK(scope.SendLocal(payload, err));
    BOOST_CHECK(scope.received() == payload);
    BOOST_CHECK_EQUAL(scope.lan_packets(), static_cast<int64_t>(0));

    BOOST_CHECK(scope.SetPolicy(modelnet::NifPrivacy::LanOnly, err));
    BOOST_CHECK(scope.SendLocal(payload, err));
    BOOST_CHECK(scope.received() == payload);
    BOOST_CHECK_EQUAL(scope.lan_packets(), static_cast<int64_t>(1));

    BOOST_CHECK(!scope.SendWan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK(!scope.Scan("10.", err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK(scope.ObserveBeacon("hint", err));
    BOOST_CHECK(!scope.granted());
    BOOST_CHECK(!scope.connected());
    BOOST_CHECK(!scope.gpu());
    BOOST_CHECK_EQUAL(scope.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
