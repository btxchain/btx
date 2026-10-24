// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/cursor.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace {

const char* const kStages[] = {
    "acquire",
    "join",
    "coordinate",
    "accelerate",
    "experience",
    "train",
    "evolve",
    "evaluate",
    "graduate",
    "adopt",
    "pay",
    "recover",
    "repeat",
};

constexpr std::size_t kStageCount = sizeof(kStages) / sizeof(kStages[0]);

std::string EvidenceFor(const char* stage)
{
    return std::string("evidence-") + stage;
}

void ExpectDark(const modelnet::SwarmFlagshipCursor& cursor)
{
    BOOST_REQUIRE(!cursor.passed());
    BOOST_REQUIRE(!cursor.gpu_passed());
    BOOST_REQUIRE(!cursor.windows_passed());
    BOOST_REQUIRE(!cursor.pay_passed());
    BOOST_REQUIRE(!cursor.launched());
    BOOST_REQUIRE(!cursor.gpu());
    BOOST_REQUIRE(!cursor.broadcast());
    BOOST_REQUIRE(cursor.bytes_moved() == std::uint64_t{0});
    BOOST_REQUIRE(cursor.atoms_moved() == std::uint64_t{0});
    BOOST_REQUIRE_EQUAL(cursor.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_flagship_record_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fresh_cursor_points_at_acquire_and_stays_dark)
{
    const modelnet::SwarmFlagshipCursor cursor;
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE(cursor.evidence("acquire").empty());
    BOOST_REQUIRE(!cursor.recorded("repeat"));
    BOOST_REQUIRE(cursor.evidence("repeat").empty());
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(empty_evidence_is_evidence_and_stores_nothing)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("acquire", "", err));
    BOOST_REQUIRE_EQUAL(err, "EVIDENCE");
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE(cursor.evidence("acquire").empty());
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(unknown_stage_is_stage_and_stores_nothing)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("launch", "evidence-launch", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(!cursor.recorded("launch"));
    BOOST_REQUIRE(cursor.evidence("launch").empty());
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(unknown_stage_beats_empty_evidence)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Record("", "", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(!cursor.recorded(""));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(record_acquire_stores_evidence_and_advances)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    BOOST_REQUIRE(!cursor.recorded("join"));
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(records_all_thirteen_in_order_then_next_is_empty)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE_EQUAL(kStageCount, std::size_t{13});
    for (std::size_t i = 0; i < kStageCount; ++i) {
        BOOST_REQUIRE_EQUAL(cursor.next_stage(), kStages[i]);
        BOOST_REQUIRE(cursor.Record(kStages[i], EvidenceFor(kStages[i]), err));
        BOOST_REQUIRE(err.empty());
        BOOST_REQUIRE(cursor.recorded(kStages[i]));
        BOOST_REQUIRE_EQUAL(cursor.evidence(kStages[i]), EvidenceFor(kStages[i]));
        ExpectDark(cursor);
    }
    BOOST_REQUIRE(cursor.next_stage().empty());
    BOOST_REQUIRE(!cursor.passed());
}

BOOST_AUTO_TEST_CASE(unknown_inspectors_are_empty)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(!cursor.recorded("Acquire"));
    BOOST_REQUIRE(cursor.evidence("Acquire").empty());
    BOOST_REQUIRE(!cursor.recorded("gpu"));
    BOOST_REQUIRE(cursor.evidence("gpu").empty());
    BOOST_REQUIRE(cursor.recorded("acquire"));
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(blank_evidence_check_does_not_trim)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", " ", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), " ");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(same_evidence_text_may_be_used_on_two_stages)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "shared-id", err));
    BOOST_REQUIRE(cursor.Record("join", "shared-id", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "shared-id");
    BOOST_REQUIRE_EQUAL(cursor.evidence("join"), "shared-id");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "coordinate");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(passed_stays_false_after_every_record)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    for (std::size_t i = 0; i < kStageCount; ++i) {
        BOOST_REQUIRE(cursor.Record(kStages[i], EvidenceFor(kStages[i]), err));
        BOOST_REQUIRE(!cursor.passed());
        BOOST_REQUIRE(!cursor.gpu_passed());
        BOOST_REQUIRE(!cursor.windows_passed());
        BOOST_REQUIRE(!cursor.pay_passed());
    }
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_SUITE_END()
