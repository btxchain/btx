// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_payreg/swarm_payreg.h>
#include <pqkey.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmPayReg& reg)
{
    BOOST_CHECK(!reg.launched());
    BOOST_CHECK(!reg.gpu());
    BOOST_CHECK(!reg.broadcast());
    BOOST_CHECK(!reg.qualified());
    BOOST_CHECK(!reg.spendable());
    BOOST_CHECK(!reg.mainnet());
    BOOST_CHECK_EQUAL(reg.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(reg.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(reg.Mode(), "REGTEST_UNBROADCAST");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_payreg_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(same_outpoint_cannot_fund_two_pools)
{
    modelnet::SwarmPayReg reg;
    std::string err = "prior";
    BOOST_REQUIRE(reg.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(reg.holds_money("pool-a"));
    BOOST_CHECK(!reg.holds_money("pool-b"));

    BOOST_CHECK(!reg.Reserve("pool-a", "out-a", 0, err));
    BOOST_CHECK_EQUAL(err, "AMOUNT");
    BOOST_CHECK(reg.reserve_pool("out-a").empty());
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-a"), static_cast<int64_t>(0));

    BOOST_CHECK(!reg.Reserve("pool-a", "", 4, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-a"), static_cast<int64_t>(0));

    BOOST_REQUIRE(reg.Reserve("pool-a", "out-shared", 5, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(reg.reserve_pool("out-shared"), "pool-a");
    BOOST_CHECK_EQUAL(reg.reserve_atoms("out-shared"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-a"), static_cast<int64_t>(5));

    BOOST_REQUIRE(reg.Reserve("pool-b", "out-b", 9, err));
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-b"), static_cast<int64_t>(9));
    BOOST_CHECK_EQUAL(reg.reserve_pool("out-b"), "pool-b");

    BOOST_CHECK(!reg.Reserve("pool-b", "out-shared", 5, err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK_EQUAL(reg.reserve_pool("out-shared"), "pool-a");
    BOOST_CHECK_EQUAL(reg.reserve_atoms("out-shared"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-b"), static_cast<int64_t>(9));
    BOOST_CHECK(reg.holds_money("pool-a"));
    BOOST_CHECK(!reg.holds_money("pool-b"));
    BOOST_CHECK(!reg.spendable());
    ExpectQuiet(reg);

    BOOST_CHECK(!reg.Open("channel-2", "pool-c", "pool-d", err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK(reg.holds_money("pool-a"));
    BOOST_CHECK(!reg.holds_money("pool-c"));
    BOOST_CHECK_EQUAL(reg.reserve_pool("out-shared"), "pool-a");
    ExpectQuiet(reg);
}

BOOST_AUTO_TEST_CASE(route_atom_change_does_not_replace_terms)
{
    modelnet::SwarmPayReg reg;
    std::string err = "prior";
    BOOST_REQUIRE(reg.Open("channel-1", "pool-a", "pool-b", err));

    BOOST_REQUIRE(reg.Terms("route-1", 10, 160, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(reg.terms_stored("route-1"));
    BOOST_CHECK_EQUAL(reg.terms_atoms("route-1"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(reg.terms_timeout("route-1"), static_cast<int64_t>(160));

    BOOST_CHECK(!reg.Terms("route-1", 11, 160, err));
    BOOST_CHECK_EQUAL(err, "TERMS");
    BOOST_CHECK_EQUAL(reg.terms_atoms("route-1"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(reg.terms_timeout("route-1"), static_cast<int64_t>(160));

    BOOST_CHECK(!reg.Terms("route-1", 10, 161, err));
    BOOST_CHECK_EQUAL(err, "TERMS");
    BOOST_CHECK_EQUAL(reg.terms_atoms("route-1"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(reg.terms_timeout("route-1"), static_cast<int64_t>(160));

    BOOST_REQUIRE(reg.Terms("route-1", 10, 160, err));
    BOOST_CHECK_EQUAL(reg.terms_atoms("route-1"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(reg.terms_timeout("route-1"), static_cast<int64_t>(160));
    ExpectQuiet(reg);
}

BOOST_AUTO_TEST_CASE(fail_compute_keeps_the_claim)
{
    modelnet::SwarmPayReg reg;
    std::string err = "prior";
    BOOST_REQUIRE(reg.Claim("work-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(reg.claim_kept("work-1"));
    BOOST_CHECK(!reg.compute_failed());

    reg.FailCompute();
    BOOST_CHECK(reg.compute_failed());
    BOOST_CHECK(reg.claim_kept("work-1"));
    BOOST_CHECK(!reg.claim_kept("work-2"));
    ExpectQuiet(reg);
}

BOOST_AUTO_TEST_CASE(settle_is_unqualified)
{
    modelnet::SwarmPayReg reg;
    std::string err = "prior";
    BOOST_REQUIRE(reg.Open("channel-1", "pool-a", "pool-b", err));

    std::vector<unsigned char> hash(32, 0x22);
    std::vector<unsigned char> pubkey(MLDSA44_PUBKEY_SIZE, 0x11);
    BOOST_REQUIRE(reg.Build(hash, pubkey, 160, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!reg.claim_script().empty());
    BOOST_CHECK(!reg.refund_script().empty());

    BOOST_CHECK(!reg.Settle(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!reg.qualified());
    BOOST_CHECK(!reg.broadcast());
    BOOST_CHECK_EQUAL(reg.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(reg.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!reg.spendable());
    BOOST_CHECK_EQUAL(reg.Mode(), "REGTEST_UNBROADCAST");
    ExpectQuiet(reg);
}

BOOST_AUTO_TEST_CASE(credit_does_not_increase_the_funded_balance)
{
    modelnet::SwarmPayReg reg;
    std::string err = "prior";
    BOOST_REQUIRE(reg.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_REQUIRE(reg.Reserve("pool-a", "out-a", 7, err));

    BOOST_CHECK(!reg.Credit("pool-a", 100, err));
    BOOST_CHECK_EQUAL(err, "NOT_BACKING");
    BOOST_CHECK_EQUAL(reg.credit_note("pool-a"), static_cast<int64_t>(100));
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-a"), static_cast<int64_t>(7));
    BOOST_CHECK(reg.holds_money("pool-a"));

    BOOST_CHECK(!reg.Credit("pool-b", 40, err));
    BOOST_CHECK_EQUAL(err, "NOT_BACKING");
    BOOST_CHECK_EQUAL(reg.credit_note("pool-b"), static_cast<int64_t>(40));
    BOOST_CHECK_EQUAL(reg.funded_balance("pool-b"), static_cast<int64_t>(0));
    BOOST_CHECK(!reg.holds_money("pool-b"));
    BOOST_CHECK(!reg.spendable());
    BOOST_CHECK_EQUAL(reg.atoms_moved(), static_cast<int64_t>(0));
    ExpectQuiet(reg);
}

BOOST_AUTO_TEST_SUITE_END()
