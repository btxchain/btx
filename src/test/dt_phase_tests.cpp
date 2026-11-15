// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_phase/dt_phase.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_phase_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(legal_walk_reaches_draining)
{
    modelnet::DtPhaseEngine engine;
    std::string err;
    const int64_t now = static_cast<int64_t>(0);
    const int64_t until = static_cast<int64_t>(1);

    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Discovered);
    BOOST_CHECK_EQUAL(engine.weight(), static_cast<int64_t>(0));

    const std::array<modelnet::DtPhase, 9> walk{{
        modelnet::DtPhase::Eligible,
        modelnet::DtPhase::Reserved,
        modelnet::DtPhase::Prepared,
        modelnet::DtPhase::Running,
        modelnet::DtPhase::Snapshotting,
        modelnet::DtPhase::CandidateCommitted,
        modelnet::DtPhase::Evaluating,
        modelnet::DtPhase::Waiting,
        modelnet::DtPhase::Draining,
    }};
    for (const modelnet::DtPhase next : walk) {
        BOOST_CHECK(engine.Advance(next, now, until, true, err));
        BOOST_CHECK(err.empty());
        BOOST_CHECK(engine.phase() == next);
    }
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Draining);
    BOOST_CHECK_EQUAL(engine.weight(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Draining, now, until, true, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Draining);

    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(skip_does_not_change_phase)
{
    modelnet::DtPhaseEngine engine;
    std::string err;
    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Prepared, static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Discovered);
    BOOST_CHECK_EQUAL(engine.weight(), static_cast<int64_t>(0));

    BOOST_CHECK(engine.Advance(modelnet::DtPhase::Eligible, static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Running, static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
}

BOOST_AUTO_TEST_CASE(authority_equal_is_expired)
{
    modelnet::DtPhaseEngine engine;
    std::string err;
    const int64_t until = static_cast<int64_t>(10);

    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Eligible, until, until, true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Discovered);
    BOOST_CHECK_EQUAL(engine.weight(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Eligible, static_cast<int64_t>(11), until, true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Discovered);

    BOOST_CHECK(engine.Advance(modelnet::DtPhase::Eligible, static_cast<int64_t>(9), until, true, err));
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Reserved, until, until, true, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
}

BOOST_AUTO_TEST_CASE(journal_false_leaves_phase)
{
    modelnet::DtPhaseEngine engine;
    std::string err;

    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Eligible, static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Discovered);

    BOOST_CHECK(engine.Advance(modelnet::DtPhase::Eligible, static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
    BOOST_CHECK(!engine.Advance(modelnet::DtPhase::Reserved, static_cast<int64_t>(0), static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
    BOOST_CHECK_EQUAL(engine.weight(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(gpu_step_is_engine_absent)
{
    modelnet::DtPhaseEngine engine;
    std::string err;
    BOOST_CHECK(engine.Advance(modelnet::DtPhase::Eligible, static_cast<int64_t>(0), static_cast<int64_t>(1), true, err));
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);

    BOOST_CHECK(!engine.GpuStep(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(engine.phase() == modelnet::DtPhase::Eligible);
    BOOST_CHECK_EQUAL(engine.weight(), static_cast<int64_t>(0));
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.broadcast());
}

BOOST_AUTO_TEST_CASE(revoked_and_failed_do_not_advance)
{
    modelnet::DtPhaseEngine running;
    std::string err;
    const int64_t now = static_cast<int64_t>(0);
    const int64_t until = static_cast<int64_t>(1);
    BOOST_CHECK(running.Advance(modelnet::DtPhase::Eligible, now, until, true, err));
    BOOST_CHECK(running.Advance(modelnet::DtPhase::Reserved, now, until, true, err));
    BOOST_CHECK(running.Advance(modelnet::DtPhase::Prepared, now, until, true, err));
    BOOST_CHECK(running.Advance(modelnet::DtPhase::Running, now, until, true, err));
    BOOST_CHECK(running.phase() == modelnet::DtPhase::Running);
    BOOST_CHECK(running.Fail(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(running.phase() == modelnet::DtPhase::Failed);
    BOOST_CHECK(!running.Advance(modelnet::DtPhase::Snapshotting, now, until, true, err));
    BOOST_CHECK_EQUAL(err, "FAILED");
    BOOST_CHECK(running.phase() == modelnet::DtPhase::Failed);
    BOOST_CHECK_EQUAL(running.weight(), static_cast<int64_t>(0));

    modelnet::DtPhaseEngine early;
    BOOST_CHECK(!early.Fail(err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(early.phase() == modelnet::DtPhase::Discovered);

    modelnet::DtPhaseEngine revoked;
    BOOST_CHECK(revoked.Revoke(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(revoked.phase() == modelnet::DtPhase::Revoked);
    BOOST_CHECK(!revoked.Advance(modelnet::DtPhase::Eligible, now, until, true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(revoked.phase() == modelnet::DtPhase::Revoked);

    modelnet::DtPhaseEngine unknown;
    BOOST_CHECK(unknown.Advance(modelnet::DtPhase::Eligible, now, until, true, err));
    BOOST_CHECK(unknown.Unknown(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(unknown.phase() == modelnet::DtPhase::OutcomeUnknown);
    BOOST_CHECK(!unknown.Advance(modelnet::DtPhase::Reserved, now, until, true, err));
    BOOST_CHECK_EQUAL(err, "ORDER");
    BOOST_CHECK(unknown.phase() == modelnet::DtPhase::OutcomeUnknown);
    BOOST_CHECK(!unknown.GpuStep(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(unknown.phase() == modelnet::DtPhase::OutcomeUnknown);
    BOOST_CHECK_EQUAL(unknown.weight(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
