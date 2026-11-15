// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evidence/swarm_evidence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmEvidence& evidence)
{
    BOOST_CHECK(!evidence.launched());
    BOOST_CHECK(!evidence.gpu());
    BOOST_CHECK(!evidence.broadcast());
    BOOST_CHECK_EQUAL(evidence.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(evidence.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_evidence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(private_share_and_unknown_id_are_not_visible)
{
    modelnet::SwarmEvidence evidence;
    std::string err = "prior";
    const std::vector<unsigned char> bytes{0x0a, 0x0b, 0x0c};

    BOOST_CHECK(!evidence.Store("", bytes, true, err));
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
    BOOST_CHECK(!evidence.stored(""));
    BOOST_CHECK(!evidence.shareable(""));

    BOOST_CHECK(!evidence.Store("item-empty", {}, false, err));
    BOOST_CHECK_EQUAL(err, "EVIDENCE");
    BOOST_CHECK(!evidence.stored("item-empty"));
    BOOST_CHECK(!evidence.shareable("item-empty"));

    BOOST_REQUIRE(evidence.Store("item-private", bytes, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(evidence.stored("item-private"));
    BOOST_CHECK(!evidence.shareable("item-private"));
    BOOST_CHECK(evidence.body("item-private") == bytes);

    std::string private_err = "prior";
    BOOST_CHECK(!evidence.Share("item-private", private_err));
    BOOST_CHECK_EQUAL(private_err, "NOT_VISIBLE");

    std::string unknown_err = "prior";
    BOOST_CHECK(!evidence.Share("item-missing", unknown_err));
    BOOST_CHECK_EQUAL(unknown_err, "NOT_VISIBLE");
    BOOST_CHECK_EQUAL(private_err, unknown_err);

    BOOST_CHECK(!evidence.Store("item-private", std::vector<unsigned char>{0x01}, false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!evidence.shareable("item-private"));
    BOOST_CHECK(evidence.body("item-private") == bytes);

    const std::vector<unsigned char> public_bytes{0x21, 0x22};
    BOOST_REQUIRE(evidence.Store("item-public", public_bytes, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(evidence.shareable("item-public"));
    BOOST_CHECK(!evidence.shareable("item-private"));
    BOOST_CHECK(!evidence.shareable("item-missing"));
    BOOST_REQUIRE(evidence.Share("item-public", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(evidence.body("item-public") == public_bytes);
    BOOST_CHECK_EQUAL(evidence.bytes_moved(), static_cast<int64_t>(0));
    ExpectQuiet(evidence);
}

BOOST_AUTO_TEST_CASE(summary_keeps_its_source_id)
{
    modelnet::SwarmEvidence evidence;
    std::string err = "prior";
    const std::vector<unsigned char> bytes{0x31, 0x32};
    BOOST_REQUIRE(evidence.Store("source-1", bytes, true, err));
    BOOST_REQUIRE(evidence.Store("source-2", std::vector<unsigned char>{0x33}, false, err));

    BOOST_CHECK(!evidence.Summarize("sum-1", "", "source-1", err));
    BOOST_CHECK_EQUAL(err, "SUMMARY");
    BOOST_CHECK(evidence.summary_source("sum-1").empty());

    BOOST_CHECK(!evidence.Summarize("sum-1", "short note", "", err));
    BOOST_CHECK_EQUAL(err, "SUMMARY");
    BOOST_CHECK(evidence.summary_source("sum-1").empty());

    BOOST_CHECK(!evidence.Summarize("", "short note", "source-1", err));
    BOOST_CHECK_EQUAL(err, "SUMMARY");

    BOOST_REQUIRE(evidence.Promise("replica-src", err));
    BOOST_CHECK(!evidence.Summarize("sum-1", "short note", "replica-src", err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK(evidence.summary_source("sum-1").empty());
    BOOST_CHECK(evidence.summary("sum-1").empty());

    BOOST_CHECK(!evidence.Summarize("sum-1", "short note", "missing-source", err));
    BOOST_CHECK_EQUAL(err, "SOURCE");
    BOOST_CHECK(evidence.summary_source("sum-1").empty());

    BOOST_REQUIRE(evidence.Summarize("sum-1", "short note", "source-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(evidence.summary("sum-1"), "short note");
    BOOST_CHECK_EQUAL(evidence.summary_source("sum-1"), "source-1");
    BOOST_CHECK(!evidence.shareable("sum-1"));
    BOOST_CHECK(!evidence.shareable("source-1"));

    BOOST_CHECK(!evidence.Summarize("sum-1", "other note", "source-2", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(evidence.summary("sum-1"), "short note");
    BOOST_CHECK_EQUAL(evidence.summary_source("sum-1"), "source-1");
    BOOST_CHECK_EQUAL(evidence.bytes_moved(), static_cast<int64_t>(0));
    ExpectQuiet(evidence);
}

BOOST_AUTO_TEST_CASE(inject_is_not_authority)
{
    modelnet::SwarmEvidence evidence;
    std::string err = "prior";
    const std::string text = "keep this note as data";

    BOOST_CHECK(!evidence.Inject("note-1", text, err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
    BOOST_CHECK(evidence.tainted("note-1"));
    BOOST_CHECK_EQUAL(evidence.tainted_bytes(), text.size());
    BOOST_CHECK(!evidence.launched());
    BOOST_CHECK(!evidence.stored("note-1"));
    BOOST_CHECK(!evidence.shareable("note-1"));
    BOOST_CHECK(!evidence.gpu());
    BOOST_CHECK(!evidence.broadcast());

    BOOST_CHECK(!evidence.Inject("note-1", text, err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
    BOOST_CHECK_EQUAL(evidence.tainted_bytes(), text.size() * 2);
    BOOST_CHECK(!evidence.launched());
    ExpectQuiet(evidence);
}

BOOST_AUTO_TEST_CASE(promise_then_retrieve_is_not_retrievable)
{
    modelnet::SwarmEvidence evidence;
    std::string err = "prior";

    BOOST_CHECK(!evidence.Promise("", err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!evidence.promised(""));

    BOOST_REQUIRE(evidence.Promise("replica-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(evidence.promised("replica-1"));
    BOOST_CHECK(!evidence.stored("replica-1"));
    BOOST_CHECK(evidence.body("replica-1").empty());

    BOOST_CHECK(!evidence.Retrieve("replica-1", err));
    BOOST_CHECK_EQUAL(err, "NOT_RETRIEVABLE");
    BOOST_CHECK_EQUAL(evidence.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(evidence.body("replica-1").empty());
    BOOST_CHECK(evidence.promised("replica-1"));

    const std::vector<unsigned char> bytes{0x41, 0x42, 0x43};
    BOOST_REQUIRE(evidence.Store("item-kept", bytes, true, err));
    BOOST_REQUIRE(evidence.Promise("item-kept", err));
    BOOST_CHECK(evidence.promised("item-kept"));
    BOOST_CHECK(!evidence.Retrieve("item-kept", err));
    BOOST_CHECK_EQUAL(err, "NOT_RETRIEVABLE");
    BOOST_CHECK(evidence.body("item-kept") == bytes);
    BOOST_CHECK_EQUAL(evidence.bytes_moved(), static_cast<int64_t>(0));
    ExpectQuiet(evidence);
}

BOOST_AUTO_TEST_CASE(automatic_spend_is_zero)
{
    modelnet::SwarmEvidence evidence;
    BOOST_CHECK_EQUAL(evidence.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(evidence.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!evidence.launched());
    BOOST_CHECK(!evidence.gpu());
    BOOST_CHECK(!evidence.broadcast());
    ExpectQuiet(evidence);
}

BOOST_AUTO_TEST_SUITE_END()
