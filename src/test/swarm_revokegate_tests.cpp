// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_revokegate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_revokegate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(revoked_member_is_revoked_and_plaintext_is_not_erased)
{
    std::string err;
    const modelnet::SwarmRevokeGateResult result = modelnet::SwarmReadAfterRevoke(true, false, true, true, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.plaintext_erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(previously_delivered_stays_with_delivered_kept)
{
    std::string err = "prior";
    const modelnet::SwarmRevokeGateResult result = modelnet::SwarmReadAfterRevoke(true, true, true, true, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.plaintext_erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "DELIVERED_KEPT");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(cross_tenant_is_tenant)
{
    std::string err;
    const modelnet::SwarmRevokeGateResult result = modelnet::SwarmReadAfterRevoke(false, false, false, true, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.plaintext_erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TENANT");
    BOOST_CHECK_EQUAL(err, "TENANT");
}

BOOST_AUTO_TEST_CASE(authorized_same_tenant_read_is_ok_and_bytes_stay)
{
    std::string err = "prior";
    const modelnet::SwarmRevokeGateResult result = modelnet::SwarmReadAfterRevoke(false, false, true, true, err);
    BOOST_CHECK(result.allowed);
    BOOST_CHECK(!result.plaintext_erased);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "OK");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
