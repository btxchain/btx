// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_invoice.h>
#include <modelnet/swarm_paystage/paystage.h>
#include <modelnet/swarm_paystage/preimage.h>
#include <hash.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <limits>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_paystage_invoice_tests, BasicTestingSetup)

namespace {

modelnet::SwarmPaySettle Pay(const std::string& id, int64_t atoms, unsigned char fill)
{
    modelnet::SwarmPaySettle pay;
    pay.invoice_id = id;
    pay.beneficiary = "ben";
    pay.objective = "objective";
    pay.liquidity_id = id + "-liq";
    pay.atoms = atoms;
    pay.preimage.assign(32, fill);
    pay.research_key = false;
    pay.scheduler = false;
    return pay;
}

} // namespace

BOOST_AUTO_TEST_CASE(preimage_hash_matches_invoice_reveal)
{
    const std::vector<unsigned char> preimage(32, 0x5a);
    const uint256 single = modelnet::SwarmPayPreimageHash(preimage);
    const uint256 doubled = Hash(preimage);
    BOOST_CHECK(single != doubled);

    modelnet::SwarmInvoiceBook book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Open(err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(book.Create("inv", "ben", "objective", 3, single, err));
    BOOST_REQUIRE(book.Reserve("inv", "liq", err));
    BOOST_REQUIRE(book.Reveal("inv", preimage, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.MultiHopQualified());

    modelnet::SwarmInvoiceBook wrong;
    err = "prior";
    BOOST_REQUIRE(wrong.Open(err));
    BOOST_REQUIRE(wrong.Create("inv", "ben", "objective", 3, doubled, err));
    BOOST_REQUIRE(wrong.Reserve("inv", "liq", err));
    BOOST_CHECK(!wrong.Reveal("inv", preimage, err));
    BOOST_CHECK_EQUAL(err, "HASHLOCK");
    BOOST_CHECK(!wrong.MultiHopQualified());
}

BOOST_AUTO_TEST_CASE(settle_credits_earned_only)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Credit("escrow", 4, "already", err));
    BOOST_REQUIRE(stage.Open("channel-1", 100, err));
    BOOST_REQUIRE(stage.Debit(2, err));

    err = "prior";
    BOOST_REQUIRE(stage.Settle(Pay("inv-a", 15, 0x10), err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(stage.Settle(Pay("inv-b", 6, 0x11), err));
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 21);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 4);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
    BOOST_CHECK_EQUAL(stage.Remaining("channel-1"), 98);
    BOOST_CHECK(!stage.MultiHopQualified());
    BOOST_CHECK_EQUAL(stage.automatic_spend(), "0");
    BOOST_CHECK(!stage.Broadcast());
    BOOST_CHECK(!stage.mined());

    err = "prior";
    BOOST_CHECK(!stage.Settle(Pay("inv-a", 15, 0x10), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 21);
}

BOOST_AUTO_TEST_CASE(short_preimage_adds_nothing)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    modelnet::SwarmPaySettle empty = Pay("inv-empty", 5, 0x01);
    empty.preimage.clear();
    BOOST_CHECK(!stage.Settle(empty, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);

    modelnet::SwarmPaySettle long_preimage = Pay("inv-long", 5, 0x02);
    long_preimage.preimage.assign(33, 0x02);
    err = "prior";
    BOOST_CHECK(!stage.Settle(long_preimage, err));
    BOOST_CHECK_EQUAL(err, "PREIMAGE");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);

    err = "prior";
    BOOST_REQUIRE(stage.Settle(Pay("inv-after", 5, 0x03), err));
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 5);
}

BOOST_AUTO_TEST_CASE(invoice_fields_add_nothing)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    modelnet::SwarmPaySettle missing = Pay("", 5, 0x04);
    BOOST_CHECK(!stage.Settle(missing, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);

    modelnet::SwarmPaySettle no_atoms = Pay("inv-zero", 0, 0x05);
    err = "prior";
    BOOST_CHECK(!stage.Settle(no_atoms, err));
    BOOST_CHECK_EQUAL(err, "INVOICE");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);

    modelnet::SwarmPaySettle no_liquidity = Pay("inv-liq", 5, 0x06);
    no_liquidity.liquidity_id.clear();
    err = "prior";
    BOOST_CHECK(!stage.Settle(no_liquidity, err));
    BOOST_CHECK_EQUAL(err, "LIQUIDITY");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);

    err = "prior";
    BOOST_REQUIRE(stage.Settle(Pay("inv-liq", 5, 0x06), err));
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 5);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
}

BOOST_AUTO_TEST_CASE(settle_does_not_copy_a_memo_into_a_second_bucket)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Credit("escrow", 5, "inv-memo", err));
    BOOST_CHECK(!stage.Settle(Pay("inv-memo", 5, 0x45), err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 5);
    BOOST_CHECK_EQUAL(stage.Balance("earned"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
}

BOOST_AUTO_TEST_CASE(settle_overflow_leaves_earned)
{
    modelnet::SwarmPayStage stage;
    std::string err = "prior";
    BOOST_REQUIRE(stage.Credit("earned", std::numeric_limits<int64_t>::max(), "fill", err));
    BOOST_CHECK(!stage.Settle(Pay("inv-over", 1, 0x44), err));
    BOOST_CHECK_EQUAL(err, "ATOMS");
    BOOST_CHECK_EQUAL(stage.Balance("earned"), std::numeric_limits<int64_t>::max());
    BOOST_CHECK_EQUAL(stage.Balance("escrow"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("collateral"), 0);
    BOOST_CHECK_EQUAL(stage.Balance("fees"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
