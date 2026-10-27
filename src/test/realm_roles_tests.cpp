// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_roles/realm_roles.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::RealmRoles& eng)
{
    std::string err;
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(realm_roles_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_or_unknown_role)
{
    modelnet::RealmRoles eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Seat("", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!eng.seated(""));
    BOOST_CHECK(!eng.live(""));
    BOOST_CHECK(!eng.Seat("", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!eng.Seat("mirror", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!eng.seated("mirror"));
    BOOST_CHECK(!eng.Seat("endpoint", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!eng.seated("endpoint"));
    BOOST_CHECK(!eng.Seat("endpoint-d", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!eng.seated("endpoint-d"));
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(-1));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.monetary_store());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(known_roles_stay_one_host)
{
    modelnet::RealmRoles eng;
    std::string err = "stale";
    const char* roles[] = {
        "ingress",
        "attestor",
        "controller",
        "mirror-a",
        "mirror-b",
        "endpoint-a",
        "endpoint-b",
        "endpoint-c",
    };
    for (const char* role : roles) {
        BOOST_CHECK(eng.Seat(role, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.seated(role));
        BOOST_CHECK(eng.live(role));
        BOOST_CHECK(eng.Seat(role, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(eng.seated(role));
        BOOST_CHECK(eng.live(role));
    }
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(sequence_zero_then_one)
{
    modelnet::RealmRoles eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Seat("ingress", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(-1));
    BOOST_CHECK(eng.Advance(static_cast<int64_t>(0), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Advance(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(gap_keeps_last_sequence)
{
    modelnet::RealmRoles eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(-1));
    BOOST_CHECK(eng.Advance(static_cast<int64_t>(0), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Advance(static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, "GAP");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Advance(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(hosts_rejects_two)
{
    modelnet::RealmRoles eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Seat("controller", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(6), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.live("controller"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.monetary_store());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(mirror_reports_after_ingress_stops)
{
    modelnet::RealmRoles eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Seat("ingress", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Seat("mirror-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Seat("mirror-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Advance(static_cast<int64_t>(0), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Advance(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));

    int64_t reported = static_cast<int64_t>(-7);
    BOOST_CHECK(!eng.Report("endpoint-a", reported, err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK_EQUAL(reported, static_cast<int64_t>(-7));

    BOOST_CHECK(eng.Stop("ingress", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.seated("ingress"));
    BOOST_CHECK(!eng.live("ingress"));
    BOOST_CHECK(eng.live("mirror-a"));
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Stop("ingress", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Stop("", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK(!eng.Stop("endpoint-c", err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));

    reported = static_cast<int64_t>(-7);
    BOOST_CHECK(!eng.Report("ingress", reported, err));
    BOOST_CHECK_EQUAL(err, "ROLE");
    BOOST_CHECK_EQUAL(reported, static_cast<int64_t>(-7));
    BOOST_CHECK(eng.Report("mirror-a", reported, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(reported, static_cast<int64_t>(1));
    BOOST_CHECK(eng.Report("mirror-b", reported, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(reported, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.sequence(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.monetary_store());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.monetary_store());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
