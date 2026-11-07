// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dispute.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_dispute_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(open_records_an_unsettled_dispute)
{
    modelnet::SwarmDisputeBook book;
    std::string err;

    BOOST_CHECK(!book.OpenDispute("", "receipt-1", err));
    BOOST_CHECK_EQUAL(err, "DISPUTE");
    BOOST_CHECK(!book.OpenDispute("dispute-1", "", err));
    BOOST_CHECK_EQUAL(err, "DISPUTE");
    BOOST_CHECK(book.Find("dispute-1") == nullptr);

    BOOST_REQUIRE(book.OpenDispute("dispute-1", "receipt-1", err));
    BOOST_CHECK(err.empty());
    const modelnet::SwarmDispute* opened = book.Find("dispute-1");
    BOOST_REQUIRE(opened != nullptr);
    BOOST_CHECK_EQUAL(opened->dispute_id, "dispute-1");
    BOOST_CHECK_EQUAL(opened->receipt_id, "receipt-1");
    BOOST_CHECK(opened->state == modelnet::SwarmDisputeState::Open);
    BOOST_CHECK(!opened->settled);
    BOOST_CHECK(!opened->broadcast);
    BOOST_CHECK(opened->outpoint.empty());

    BOOST_CHECK(!book.OpenDispute("dispute-1", "receipt-2", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    opened = book.Find("dispute-1");
    BOOST_REQUIRE(opened != nullptr);
    BOOST_CHECK_EQUAL(opened->receipt_id, "receipt-1");
    BOOST_CHECK(opened->state == modelnet::SwarmDisputeState::Open);
    BOOST_CHECK(!opened->settled);
    BOOST_CHECK(!opened->broadcast);
    BOOST_CHECK(opened->outpoint.empty());
}

BOOST_AUTO_TEST_CASE(empty_evidence_stays_open)
{
    modelnet::SwarmDisputeBook book;
    std::string err;

    BOOST_CHECK(!book.AddEvidence("missing", "note", err));
    BOOST_CHECK_EQUAL(err, "DISPUTE");

    BOOST_REQUIRE(book.OpenDispute("dispute-1", "receipt-1", err));
    BOOST_CHECK(!book.AddEvidence("dispute-1", "", err));
    BOOST_CHECK_EQUAL(err, "DISPUTE");
    const modelnet::SwarmDispute* row = book.Find("dispute-1");
    BOOST_REQUIRE(row != nullptr);
    BOOST_CHECK(row->state == modelnet::SwarmDisputeState::Open);
    BOOST_CHECK(!row->settled);
    BOOST_CHECK(!row->broadcast);
    BOOST_CHECK(row->outpoint.empty());

    BOOST_REQUIRE(book.AddEvidence("dispute-1", "note", err));
    BOOST_CHECK(err.empty());
    row = book.Find("dispute-1");
    BOOST_REQUIRE(row != nullptr);
    BOOST_CHECK(row->state == modelnet::SwarmDisputeState::Evidence);

    BOOST_REQUIRE(book.AddEvidence("dispute-1", "another-note", err));
    BOOST_CHECK(err.empty());
    row = book.Find("dispute-1");
    BOOST_REQUIRE(row != nullptr);
    BOOST_CHECK(row->state == modelnet::SwarmDisputeState::Evidence);
    BOOST_CHECK(!row->settled);
    BOOST_CHECK(!row->broadcast);
    BOOST_CHECK(row->outpoint.empty());
}

BOOST_AUTO_TEST_CASE(accept_without_settlement)
{
    modelnet::SwarmDisputeBook book;
    std::string err;

    BOOST_REQUIRE(book.OpenDispute("dispute-1", "receipt-1", err));
    BOOST_CHECK(!book.Resolve("dispute-1", true, err));
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
    const modelnet::SwarmDispute* row = book.Find("dispute-1");
    BOOST_REQUIRE(row != nullptr);
    BOOST_CHECK(row->state == modelnet::SwarmDisputeState::Open);
    BOOST_CHECK(!row->settled);
    BOOST_CHECK(!row->broadcast);
    BOOST_CHECK(row->outpoint.empty());

    BOOST_REQUIRE(book.AddEvidence("dispute-1", "note", err));
    BOOST_REQUIRE(book.Resolve("dispute-1", true, err));
    BOOST_CHECK(err.empty());
    row = book.Find("dispute-1");
    BOOST_REQUIRE(row != nullptr);
    BOOST_CHECK(row->state == modelnet::SwarmDisputeState::Accepted);
    BOOST_CHECK(!row->settled);
    BOOST_CHECK(!row->broadcast);
    BOOST_CHECK(row->outpoint.empty());
}

BOOST_AUTO_TEST_CASE(refuse_stays_unsettled)
{
    modelnet::SwarmDisputeBook book;
    std::string err;

    BOOST_REQUIRE(book.OpenDispute("dispute-1", "receipt-1", err));
    BOOST_REQUIRE(book.AddEvidence("dispute-1", "note", err));
    BOOST_REQUIRE(book.Resolve("dispute-1", false, err));
    BOOST_CHECK(err.empty());
    const modelnet::SwarmDispute* row = book.Find("dispute-1");
    BOOST_REQUIRE(row != nullptr);
    BOOST_CHECK(row->state == modelnet::SwarmDisputeState::Refused);
    BOOST_CHECK(!row->settled);
    BOOST_CHECK(!row->broadcast);
    BOOST_CHECK(row->outpoint.empty());
}

BOOST_AUTO_TEST_CASE(resolve_again_is_replay)
{
    modelnet::SwarmDisputeBook book;
    std::string err;

    BOOST_REQUIRE(book.OpenDispute("dispute-1", "receipt-1", err));
    BOOST_REQUIRE(book.AddEvidence("dispute-1", "note", err));
    BOOST_REQUIRE(book.Resolve("dispute-1", true, err));
    BOOST_CHECK(!book.Resolve("dispute-1", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!book.Resolve("dispute-1", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    const modelnet::SwarmDispute* accepted = book.Find("dispute-1");
    BOOST_REQUIRE(accepted != nullptr);
    BOOST_CHECK(accepted->state == modelnet::SwarmDisputeState::Accepted);
    BOOST_CHECK(!accepted->settled);
    BOOST_CHECK(!accepted->broadcast);
    BOOST_CHECK(accepted->outpoint.empty());

    BOOST_REQUIRE(book.OpenDispute("dispute-2", "receipt-2", err));
    BOOST_REQUIRE(book.AddEvidence("dispute-2", "note", err));
    BOOST_REQUIRE(book.Resolve("dispute-2", false, err));
    BOOST_CHECK(!book.Resolve("dispute-2", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!book.Resolve("dispute-2", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    const modelnet::SwarmDispute* refused = book.Find("dispute-2");
    BOOST_REQUIRE(refused != nullptr);
    BOOST_CHECK(refused->state == modelnet::SwarmDisputeState::Refused);
    BOOST_CHECK(!refused->settled);
    BOOST_CHECK(!refused->broadcast);
    BOOST_CHECK(refused->outpoint.empty());
}

BOOST_AUTO_TEST_SUITE_END()
