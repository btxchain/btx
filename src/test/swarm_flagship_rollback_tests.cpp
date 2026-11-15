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

void RecordAll(modelnet::SwarmFlagshipCursor& cursor)
{
    std::string err = "prior";
    for (std::size_t i = 0; i < kStageCount; ++i) {
        BOOST_REQUIRE(cursor.Record(kStages[i], EvidenceFor(kStages[i]), err));
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_flagship_rollback_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_stage_is_stage_and_deletes_nothing)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(cursor.Record("coordinate", "evidence-coordinate", err));

    err = "prior";
    BOOST_REQUIRE(!cursor.Rollback("Evaluate", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE(cursor.recorded("join"));
    BOOST_REQUIRE(cursor.recorded("coordinate"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.evidence("join"), "evidence-join");
    BOOST_REQUIRE_EQUAL(cursor.evidence("coordinate"), "evidence-coordinate");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "accelerate");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(rollback_evaluate_keeps_acquire_through_evolve_and_clears_the_rest)
{
    modelnet::SwarmFlagshipCursor cursor;
    RecordAll(cursor);

    std::string err = "prior";
    BOOST_REQUIRE(cursor.Rollback("evaluate", err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE(cursor.recorded("join"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("join"), "evidence-join");
    BOOST_REQUIRE(cursor.recorded("coordinate"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("coordinate"), "evidence-coordinate");
    BOOST_REQUIRE(cursor.recorded("accelerate"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("accelerate"), "evidence-accelerate");
    BOOST_REQUIRE(cursor.recorded("experience"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("experience"), "evidence-experience");
    BOOST_REQUIRE(cursor.recorded("train"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("train"), "evidence-train");
    BOOST_REQUIRE(cursor.recorded("evolve"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("evolve"), "evidence-evolve");

    BOOST_REQUIRE(!cursor.recorded("evaluate"));
    BOOST_REQUIRE(cursor.evidence("evaluate").empty());
    BOOST_REQUIRE(!cursor.recorded("graduate"));
    BOOST_REQUIRE(cursor.evidence("graduate").empty());
    BOOST_REQUIRE(!cursor.recorded("adopt"));
    BOOST_REQUIRE(cursor.evidence("adopt").empty());
    BOOST_REQUIRE(!cursor.recorded("pay"));
    BOOST_REQUIRE(cursor.evidence("pay").empty());
    BOOST_REQUIRE(!cursor.recorded("recover"));
    BOOST_REQUIRE(cursor.evidence("recover").empty());
    BOOST_REQUIRE(!cursor.recorded("repeat"));
    BOOST_REQUIRE(cursor.evidence("repeat").empty());

    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "evaluate");
    BOOST_REQUIRE(!cursor.passed());
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(rollback_acquire_clears_every_stage)
{
    modelnet::SwarmFlagshipCursor cursor;
    RecordAll(cursor);

    std::string err = "prior";
    BOOST_REQUIRE(cursor.Rollback("acquire", err));
    BOOST_REQUIRE(err.empty());
    for (std::size_t i = 0; i < kStageCount; ++i) {
        BOOST_REQUIRE(!cursor.recorded(kStages[i]));
        BOOST_REQUIRE(cursor.evidence(kStages[i]).empty());
    }
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(rollback_repeat_clears_only_repeat)
{
    modelnet::SwarmFlagshipCursor cursor;
    RecordAll(cursor);

    std::string err = "prior";
    BOOST_REQUIRE(cursor.Rollback("repeat", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!cursor.recorded("repeat"));
    BOOST_REQUIRE(cursor.evidence("repeat").empty());
    BOOST_REQUIRE(cursor.recorded("recover"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("recover"), "evidence-recover");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "repeat");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(rollback_of_a_clear_stage_still_returns_true)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Rollback("evaluate", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "acquire");
    BOOST_REQUIRE(!cursor.recorded("acquire"));
    BOOST_REQUIRE(!cursor.recorded("evaluate"));
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(after_rollback_the_stage_can_be_recorded_again)
{
    modelnet::SwarmFlagshipCursor cursor;
    RecordAll(cursor);

    std::string err = "prior";
    BOOST_REQUIRE(cursor.Rollback("evaluate", err));
    BOOST_REQUIRE(cursor.Record("evaluate", "evidence-evaluate-again", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(cursor.recorded("evaluate"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("evaluate"), "evidence-evaluate-again");
    BOOST_REQUIRE(cursor.recorded("evolve"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("evolve"), "evidence-evolve");
    BOOST_REQUIRE(!cursor.recorded("graduate"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "graduate");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(rollback_join_keeps_acquire_and_clears_the_suffix)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(cursor.Record("coordinate", "evidence-coordinate", err));
    BOOST_REQUIRE(cursor.Rollback("join", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE(!cursor.recorded("join"));
    BOOST_REQUIRE(!cursor.recorded("coordinate"));
    BOOST_REQUIRE(!cursor.recorded("repeat"));
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_SUITE_END()
