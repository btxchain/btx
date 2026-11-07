// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lan01/lan01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void FlagsStayFalse(const modelnet::Lan01& lan)
{
    BOOST_CHECK(!lan.passed());
    BOOST_CHECK(!lan.qualified());
    BOOST_CHECK(!lan.release_qualified());
    BOOST_CHECK(!lan.hardware_qualified());
    BOOST_CHECK(!lan.gpu_passed());
    BOOST_CHECK(!lan.windows_passed());
    BOOST_CHECK(!lan.advertised());
    BOOST_CHECK_EQUAL(lan.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(lan.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(lan01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(scenario_other_than_b_c_e_is_id)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("A", false, false, true, 5, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(!lan.Observe("", false, false, true, 5, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!lan.Observe("P2P-SCN-B", false, false, true, 5, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_CASE(scenario_b_manual_address_discovers_nothing)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("B", true, false, false, 4, err));
    BOOST_CHECK_EQUAL(err, "MANUAL");
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(!lan.Observe("B", true, false, false, 0, err));
    BOOST_CHECK_EQUAL(err, "MANUAL");
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_CASE(scenario_b_few_peers_is_unqualified)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("B", false, false, false, 1, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(!lan.Observe("B", false, true, true, 0, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_CASE(scenario_b_two_peers_discovers)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(lan.Observe("B", false, true, false, 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 2);
    FlagsStayFalse(lan);

    modelnet::Lan01 wider;
    BOOST_CHECK(wider.Observe("B", false, false, false, 3, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(wider.discovered());
    BOOST_CHECK_EQUAL(wider.peers_discovered(), 3);
    FlagsStayFalse(wider);
}

BOOST_AUTO_TEST_CASE(scenario_c_online_before_peer_count)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("C", false, true, false, 0, err));
    BOOST_CHECK_EQUAL(err, "ONLINE");
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(!lan.Observe("C", false, true, true, 4, err));
    BOOST_CHECK_EQUAL(err, "ONLINE");
    BOOST_CHECK(!lan.discovered());
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_CASE(scenario_c_offline_needs_two_peers)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("C", false, false, false, 1, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(lan.Observe("C", true, false, false, 2, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_CASE(scenario_e_bootstrap_present_is_refused)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("E", false, false, false, 0, err));
    BOOST_CHECK_EQUAL(err, "BOOTSTRAP");
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(!lan.Observe("E", false, true, false, 3, err));
    BOOST_CHECK_EQUAL(err, "BOOTSTRAP");
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_CASE(scenario_e_lost_bootstrap_needs_a_peer)
{
    modelnet::Lan01 lan;
    std::string err = "stale";
    BOOST_CHECK(!lan.Observe("E", false, false, true, 0, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);

    BOOST_CHECK(lan.Observe("E", false, true, true, 1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!lan.discovered());
    BOOST_CHECK_EQUAL(lan.peers_discovered(), 0);
    FlagsStayFalse(lan);
}

BOOST_AUTO_TEST_SUITE_END()
