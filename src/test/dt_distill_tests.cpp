// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_distill/dt_distill.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_distill_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(self_score_stores_nothing_and_bound_reward_updates_once)
{
    modelnet::DtDistill distill;
    std::string err;

    BOOST_CHECK(!distill.qualified_v41());
    BOOST_CHECK(!distill.launched());
    BOOST_CHECK(!distill.gpu());
    BOOST_CHECK(!distill.broadcast());
    BOOST_CHECK_EQUAL(distill.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(distill.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(0));
    BOOST_CHECK(!distill.new_generation());

    BOOST_CHECK(!distill.Bind("", "student", err));
    BOOST_CHECK_EQUAL(err, "TEACHER");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DISTILL_TEACHER);
    BOOST_CHECK(!distill.bound(""));

    BOOST_CHECK(!distill.Bind("teacher", "", err));
    BOOST_CHECK_EQUAL(err, "STUDENT");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DISTILL_STUDENT);
    BOOST_CHECK(!distill.bound("teacher"));

    BOOST_CHECK(!distill.Bind("same", "same", err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DISTILL_SELF);
    BOOST_CHECK(!distill.bound("same"));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));

    // A student scoring itself stores nothing, before any teacher is bound.
    BOOST_CHECK(!distill.Score("student", "student", static_cast<int64_t>(4), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!distill.has_score("student", "student"));
    BOOST_CHECK_EQUAL(distill.reward_of("student", "student"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(!distill.Score("teacher", "student", static_cast<int64_t>(3), false, err));
    BOOST_CHECK_EQUAL(err, "TEACHER");
    BOOST_CHECK(!distill.has_score("teacher", "student"));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(0));

    BOOST_CHECK(!distill.Update(err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DISTILL_MISSING);
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!distill.new_generation());

    BOOST_CHECK(distill.Bind("teacher", "student", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(distill.bound("teacher"));
    BOOST_CHECK_EQUAL(distill.student_of("teacher"), "student");

    BOOST_CHECK(!distill.Bind("teacher", "other", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(distill.student_of("teacher"), "student");

    // self_scored true stores nothing, including for a bound pair.
    BOOST_CHECK(!distill.Score("teacher", "student", static_cast<int64_t>(9), true, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!distill.has_score("teacher", "student"));
    BOOST_CHECK_EQUAL(distill.reward_of("teacher", "student"), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!distill.new_generation());

    BOOST_CHECK(!distill.Score("teacher", "teacher", static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(!distill.has_score("teacher", "teacher"));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(0));

    BOOST_CHECK(!distill.Update(err));
    BOOST_CHECK_EQUAL(err, "MISSING");
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(distill.Score("teacher", "student", static_cast<int64_t>(3), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(distill.has_score("teacher", "student"));
    BOOST_CHECK_EQUAL(distill.reward_of("teacher", "student"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!distill.new_generation());

    BOOST_CHECK(!distill.Score("teacher", "student", static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(distill.reward_of("teacher", "student"), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(distill.stored_scores(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(0));

    BOOST_CHECK(distill.Update(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(3));
    BOOST_CHECK(distill.new_generation());
    BOOST_CHECK_EQUAL(distill.reward_of("teacher", "student"), static_cast<int64_t>(3));

    BOOST_CHECK(!distill.Update(err));
    BOOST_CHECK_EQUAL(err, "UNCHANGED");
    BOOST_CHECK_EQUAL(err, modelnet::DT_DISTILL_UNCHANGED);
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(3));
    BOOST_CHECK(distill.new_generation());

    BOOST_CHECK(!distill.GpuStep(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(distill.student_weight(), static_cast<int64_t>(3));
    BOOST_CHECK(distill.new_generation());
    BOOST_CHECK(!distill.qualified_v41());
    BOOST_CHECK(!distill.launched());
    BOOST_CHECK(!distill.gpu());
    BOOST_CHECK(!distill.broadcast());
    BOOST_CHECK_EQUAL(distill.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
