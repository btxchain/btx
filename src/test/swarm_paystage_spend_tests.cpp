// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/paystage.h>
#include <modelnet/swarm_paystage/spend_policy.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_spend_tests, BasicTestingSetup)

namespace {

modelnet::SwarmPaySettle Pay(const std::string& id, bool research_key, bool scheduler)
{
    modelnet::SwarmPaySettle pay;
    pay.invoice_id = id;
    pay.beneficiary = "ben";
    pay.objective = "objective";
    pay.liquidity_id = id + "-liq";
    pay.atoms = 12;
    pay.preimage.assign(32, 0x70);
    pay.research_key = research_key;
    pay.scheduler = scheduler;
    return pay;
}

} // namespace

BOOST_AUTO_TEST_CASE(flags_refuse_before_atoms_move)
{
    BOOST_CHECK_EQUAL(modelnet::SwarmPayAutomaticSpend(), "0");
    BOOST_CHECK(!modelnet::SwarmPayBroadcast());
    BOOST_CHECK(!modelnet::SwarmPayMined());

    std::string err = "prior";
    BOOST_CHECK(!modelnet::SwarmPayAcceptSpend(true, false, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmPayAcceptSpend(false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_CHECK(!modelnet::SwarmPayAcceptSpend(true, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    err = "prior";
    BOOST_REQUIRE(modelnet::SwarmPayAcceptSpend(false, false, err));
    BOOST_CHECK(err.empty());

    modelnet::SwarmPayStage stage;
    err = "prior";
    BOOST_REQUIRE(stage.Credit("escrow", 3, "keep", err));
    BOOST_REQUIRE(stage.Open("channel-1", 9, err));

    err = "prior";
    BOOST_CHECK(!stage.Settle(Pay("sched", false, true), err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 3);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 9);
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());

    err = "prior";
    BOOST_CHECK(!stage.Settle(Pay("research", true, false), err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 9);

    err = "prior";
    BOOST_REQUIRE(stage.Settle(Pay("sched", false, false), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 12);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 3);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 9);
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());
    BOOST_CHECK(!stage.MultiHopQualified());
}

BOOST_AUTO_TEST_SUITE_END()
