// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING.

#include <modelnet/swarm_tenantlook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_tenantlook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_tenant_yields_tenant)
{
    std::string err = "prior";
    modelnet::SwarmTenantLook look;
    look.tenant_id.clear();
    look.caller_id = "a";
    look.revoked = false;
    look.want_read = false;
    const modelnet::SwarmTenantLookResult result = modelnet::SwarmLookupTenantAccess(look, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TENANT");
    BOOST_CHECK_EQUAL(err, "TENANT");
}

BOOST_AUTO_TEST_CASE(empty_caller_yields_caller)
{
    std::string err = "prior";
    modelnet::SwarmTenantLook look;
    look.tenant_id = "a";
    look.caller_id.clear();
    look.revoked = false;
    look.want_read = false;
    const modelnet::SwarmTenantLookResult result = modelnet::SwarmLookupTenantAccess(look, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "CALLER");
    BOOST_CHECK_EQUAL(err, "CALLER");
}

BOOST_AUTO_TEST_CASE(different_caller_yields_tenant)
{
    std::string err = "prior";
    modelnet::SwarmTenantLook look;
    look.tenant_id = "a";
    look.caller_id = "b";
    look.revoked = false;
    look.want_read = false;
    const modelnet::SwarmTenantLookResult result = modelnet::SwarmLookupTenantAccess(look, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TENANT");
    BOOST_CHECK_EQUAL(err, "TENANT");
}

BOOST_AUTO_TEST_CASE(revoked_equal_ids_yields_revoked)
{
    std::string err = "prior";
    modelnet::SwarmTenantLook look;
    look.tenant_id = "a";
    look.caller_id = "a";
    look.revoked = true;
    look.want_read = false;
    const modelnet::SwarmTenantLookResult result = modelnet::SwarmLookupTenantAccess(look, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "REVOKED");
    BOOST_CHECK_EQUAL(err, "REVOKED");
}

BOOST_AUTO_TEST_CASE(want_read_yields_held)
{
    std::string err = "prior";
    modelnet::SwarmTenantLook look;
    look.tenant_id = "a";
    look.caller_id = "a";
    look.revoked = false;
    look.want_read = true;
    const modelnet::SwarmTenantLookResult result = modelnet::SwarmLookupTenantAccess(look, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(equal_ids_yields_noted)
{
    std::string err = "prior";
    modelnet::SwarmTenantLook look;
    look.tenant_id = "a";
    look.caller_id = "a";
    look.revoked = false;
    look.want_read = false;
    const modelnet::SwarmTenantLookResult result = modelnet::SwarmLookupTenantAccess(look, err);
    BOOST_CHECK(!result.allowed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
