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

BOOST_FIXTURE_TEST_SUITE(swarm_flagship_pass_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_train_before_any_record_is_not_passed)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Pass("train", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(!cursor.recorded("train"));
    BOOST_REQUIRE(!cursor.passed());
    BOOST_REQUIRE(!cursor.gpu_passed());
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(pass_train_after_record_is_not_passed_and_gpu_passed_stays_false)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(cursor.Record("join", "evidence-join", err));
    BOOST_REQUIRE(cursor.Record("coordinate", "evidence-coordinate", err));
    BOOST_REQUIRE(cursor.Record("accelerate", "evidence-accelerate", err));
    BOOST_REQUIRE(cursor.Record("experience", "evidence-experience", err));
    BOOST_REQUIRE(cursor.Record("train", "evidence-train", err));
    BOOST_REQUIRE(cursor.recorded("train"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("train"), "evidence-train");

    err = "prior";
    BOOST_REQUIRE(!cursor.Pass("train", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(!cursor.passed());
    BOOST_REQUIRE(!cursor.gpu_passed());
    BOOST_REQUIRE(!cursor.windows_passed());
    BOOST_REQUIRE(!cursor.pay_passed());
    BOOST_REQUIRE(cursor.recorded("train"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("train"), "evidence-train");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "evolve");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(every_listed_stage_is_not_passed)
{
    BOOST_REQUIRE_EQUAL(kStageCount, std::size_t{13});
    for (std::size_t i = 0; i < kStageCount; ++i) {
        modelnet::SwarmFlagshipCursor cursor;
        std::string err = "prior";
        BOOST_REQUIRE(!cursor.Pass(kStages[i], err));
        BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
        BOOST_REQUIRE(!cursor.recorded(kStages[i]));
        ExpectDark(cursor);
    }
}

BOOST_AUTO_TEST_CASE(unknown_stage_is_stage)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(!cursor.Pass("gpu", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(!cursor.Pass("", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(!cursor.Pass("windows", err));
    BOOST_REQUIRE_EQUAL(err, "STAGE");
    BOOST_REQUIRE(!cursor.gpu());
    BOOST_REQUIRE(!cursor.gpu_passed());
    BOOST_REQUIRE(!cursor.windows_passed());
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(pass_pay_does_not_set_pay_passed)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    for (std::size_t i = 0; i < kStageCount; ++i) {
        BOOST_REQUIRE(cursor.Record(kStages[i], EvidenceFor(kStages[i]), err));
        if (std::string{kStages[i]} == "pay") {
            break;
        }
    }
    BOOST_REQUIRE(cursor.recorded("pay"));

    err = "prior";
    BOOST_REQUIRE(!cursor.Pass("pay", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(!cursor.pay_passed());
    BOOST_REQUIRE(!cursor.passed());
    BOOST_REQUIRE_EQUAL(cursor.automatic_spend(), "0");
    BOOST_REQUIRE(cursor.recorded("pay"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("pay"), "evidence-pay");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(pass_does_not_clear_recorded_evidence)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    BOOST_REQUIRE(cursor.Record("acquire", "evidence-acquire", err));
    BOOST_REQUIRE(!cursor.Pass("acquire", err));
    BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
    BOOST_REQUIRE(cursor.recorded("acquire"));
    BOOST_REQUIRE_EQUAL(cursor.evidence("acquire"), "evidence-acquire");
    BOOST_REQUIRE_EQUAL(cursor.next_stage(), "join");
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_CASE(pass_after_every_stage_is_recorded_is_still_not_passed)
{
    modelnet::SwarmFlagshipCursor cursor;
    std::string err = "prior";

    for (std::size_t i = 0; i < kStageCount; ++i) {
        BOOST_REQUIRE(cursor.Record(kStages[i], EvidenceFor(kStages[i]), err));
    }
    BOOST_REQUIRE(cursor.next_stage().empty());

    for (std::size_t i = 0; i < kStageCount; ++i) {
        err = "prior";
        BOOST_REQUIRE(!cursor.Pass(kStages[i], err));
        BOOST_REQUIRE_EQUAL(err, "NOT_PASSED");
        BOOST_REQUIRE(cursor.recorded(kStages[i]));
        BOOST_REQUIRE_EQUAL(cursor.evidence(kStages[i]), EvidenceFor(kStages[i]));
    }
    ExpectDark(cursor);
}

BOOST_AUTO_TEST_SUITE_END()
