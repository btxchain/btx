// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/paystage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_tests, BasicTestingSetup)

namespace {

modelnet::SwarmPaySettle Pay(const std::string& id, int64_t atoms, unsigned char fill, bool research_key, bool scheduler)
{
    modelnet::SwarmPaySettle pay;
    pay.invoice_id = id;
    pay.beneficiary = "ben";
    pay.objective = "objective";
    pay.liquidity_id = id + "-liq";
    pay.atoms = atoms;
    pay.preimage.assign(32, fill);
    pay.research_key = research_key;
    pay.scheduler = scheduler;
    return pay;
}

} // namespace

BOOST_AUTO_TEST_CASE(create_reveal_earns_and_leaves_other_buckets)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_CHECK(!stage.MultiHopQualified());
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);

    const modelnet::SwarmPaySettle pay = Pay("inv-1", 25, 0x11, false, false);
    BOOST_REQUIRE(stage.Settle(pay, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 25);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
    BOOST_CHECK(!stage.MultiHopQualified());

    modelnet::SwarmPaySettle again = pay;
    err = "prior";
    BOOST_CHECK(!stage.Settle(again, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 25);

    modelnet::SwarmPaySettle short_preimage = Pay("inv-short", 9, 0x22, false, false);
    short_preimage.preimage.assign(31, 0x22);
    err = "prior";
    BOOST_CHECK(!stage.Settle(short_preimage, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 25);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
}

BOOST_AUTO_TEST_CASE(short_debit_leaves_remaining)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), -1);
    BOOST_CHECK_EQUAL(stage.Remaining("other"), -1);

    BOOST_REQUIRE(stage.Open("channel-1", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 10);
    BOOST_CHECK_EQUAL(stage.Remaining("other"), -1);

    err = "prior";
    BOOST_CHECK(!stage.Debit(11, err));
    BOOST_CHECK_EQUAL(err, "SHORT");
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 10);
    BOOST_CHECK_EQUAL(stage.Remaining("other"), -1);

    err = "prior";
    BOOST_REQUIRE(stage.Debit(4, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 6);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
}

BOOST_AUTO_TEST_CASE(second_channel_is_not_opened)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Open("channel-1", 10, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(stage.Debit(3, err));
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 7);
    BOOST_CHECK_EQUAL(stage.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(stage.capacity(), 10);

    err = "prior";
    BOOST_CHECK(!stage.Open("channel-2", 20, err));
    BOOST_CHECK_EQUAL(err, "NOT_OPENED");
    BOOST_CHECK_EQUAL(stage.open_channel(), "channel-1");
    BOOST_CHECK_EQUAL(stage.capacity(), 10);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 7);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-2"), -1);
}

BOOST_AUTO_TEST_CASE(merge_is_refused_and_buckets_stay_apart)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Credit("escrow", 3, "memo-escrow", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(stage.Credit("collateral", 4, "memo-collateral", err));
    BOOST_REQUIRE(stage.Credit("fees", 1, "memo-fees", err));

    err = "prior";
    BOOST_CHECK(!stage.Credit("collateral", 3, "memo-escrow", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 3);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 4);

    err = "prior";
    BOOST_CHECK(!stage.Merge(err));
    BOOST_CHECK_EQUAL(err, "NOT_MERGED");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 3);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 4);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 1);
}

BOOST_AUTO_TEST_CASE(scheduler_and_research_key_are_not_signed)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    const modelnet::SwarmPaySettle scheduler = Pay("inv-sched", 8, 0x33, false, true);
    BOOST_CHECK(!stage.Settle(scheduler, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);

    err = "prior";
    const modelnet::SwarmPaySettle research = Pay("inv-research", 8, 0x34, true, false);
    BOOST_CHECK(!stage.Settle(research, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);

    err = "prior";
    const modelnet::SwarmPaySettle both = Pay("inv-both", 8, 0x35, true, true);
    BOOST_CHECK(!stage.Settle(both, err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);

    err = "prior";
    BOOST_REQUIRE(stage.Settle(Pay("inv-ok", 8, 0x36, false, false), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 8);
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());
}

BOOST_AUTO_TEST_CASE(automatic_spend_stays_zero)
{
    modelnet::SwarmPayStage stage;
    std::string err;
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());
    BOOST_CHECK(!stage.MultiHopQualified());

    BOOST_REQUIRE(stage.Settle(Pay("inv-auto", 2, 0x41, false, false), err));
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());
    BOOST_CHECK(!stage.MultiHopQualified());

    BOOST_CHECK(!stage.Settle(Pay("inv-auto-2", 2, 0x42, false, true), err));
    BOOST_CHECK_EQUAL(err, "NOT_SIGNED");
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());
}

BOOST_AUTO_TEST_SUITE_END()
