// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tenant.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_tenant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(a_cross_tenant_lookup_is_tenant_and_rotation_creates_no_key)
{
    std::string err;
    BOOST_CHECK(!modelnet::SwarmLookupTenant("", "cache", true, err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK(!modelnet::SwarmLookupTenant("tenant", "", true, err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK(!modelnet::SwarmLookupTenant("a", "b", true, err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK(!modelnet::SwarmLookupTenant("a", "a", false, err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_CHECK(!modelnet::SwarmLookupTenant("a", "b", false, err));
    BOOST_CHECK_EQUAL(err, "TENANT");
    BOOST_REQUIRE(modelnet::SwarmLookupTenant("a", "a", true, err));
    BOOST_CHECK(err.empty());

    bool rotated = true;
    BOOST_CHECK(!modelnet::SwarmRotateKeyEpoch(true, rotated, err));
    BOOST_CHECK(!rotated);
    BOOST_CHECK_EQUAL(err, "SHARED_REALM_KEY");
    rotated = true;
    BOOST_CHECK(!modelnet::SwarmRotateKeyEpoch(false, rotated, err));
    BOOST_CHECK(!rotated);
    BOOST_CHECK_EQUAL(err, "KEY_EPOCH");

    BOOST_CHECK(!modelnet::SwarmOpenPublicRendezvous(true, err));
    BOOST_CHECK_EQUAL(err, "NO_SOCKET");
    BOOST_CHECK(modelnet::SwarmOpenPublicRendezvous(false, err));
}

BOOST_AUTO_TEST_SUITE_END()
