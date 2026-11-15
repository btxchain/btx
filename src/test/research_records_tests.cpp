// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/research_records/research_records.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::ResearchRecords& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
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
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(research_records_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_fields_store_nothing)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Publish("", "body-a", "author-a", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, modelnet::RESEARCH_RECORDS_FIELD);
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored(""));
    BOOST_CHECK(eng.body("").empty());
    BOOST_CHECK_EQUAL(eng.sequence(""), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Publish("record-a", "", "author-a", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("record-a"));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.stored("record-a"));
    BOOST_CHECK(!eng.Publish("", "", "", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(sequence_below_one_stores_nothing)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, modelnet::RESEARCH_RECORDS_SEQUENCE);
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK(!eng.stored("record-a"));
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(-1), err));
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK(!eng.stored("record-a"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(publish_stores_body_and_sequence)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.stored("record-a"));
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_REQUIRE(eng.Publish("record-b", "body-b", "author-b", static_cast<int64_t>(4), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.body("record-b"), "body-b");
    BOOST_CHECK_EQUAL(eng.sequence("record-b"), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(eng.author("record-b"), "author-b");
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_CASE(same_body_and_sequence_is_replay)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(2), err));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-b", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(different_body_is_mismatch_and_keeps_the_first)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(3), err));
    BOOST_CHECK(!eng.Publish("record-a", "body-b", "author-a", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, modelnet::RESEARCH_RECORDS_MISMATCH);
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(3));
    BOOST_CHECK(!eng.Publish("record-a", "body-c", "author-c", static_cast<int64_t>(9), err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(3));
    BOOST_CHECK(!eng.Publish("record-a", "body-d", "author-a", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "MISMATCH");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(lower_sequence_is_rollback_and_keeps_the_first)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(5), err));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(4), err));
    BOOST_CHECK_EQUAL(err, modelnet::RESEARCH_RECORDS_ROLLBACK);
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-b", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(5));
    BOOST_CHECK(!eng.Publish("record-a", "", "author-a", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "SEQUENCE");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(higher_sequence_keeps_the_first_body_and_author)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(1), err));
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-b", static_cast<int64_t>(6), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(6));
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(6), err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(!eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "ROLLBACK");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(spend_release_vendor_and_gpu_leave_the_record)
{
    modelnet::ResearchRecords eng;
    std::string err = "stale";
    BOOST_REQUIRE(eng.Publish("record-a", "body-a", "author-a", static_cast<int64_t>(1), err));
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.body("record-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.sequence("record-a"), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.author("record-a"), "author-a");
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
