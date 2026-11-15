// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/swarm_faultseq.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_faultseq_tests, BasicTestingSetup)

// Codes SwarmFaultJournal::Apply returns after Arm(earned, true, true, true).
static constexpr const char* kCode[20] = {
    "DURABLE",
    "LEASE_EXPIRED",
    "STALE_EPOCH",
    "CHECKPOINT",
    "DURABLE",
    "REPLAY",
    "INCOMPLETE",
    "INCOMPLETE",
    "PIECE",
    "GATE",
    "REGRESSION",
    "CONFLICT",
    "EARNED",
    "REFUND",
    "REORG",
    "COLLATERAL_REUSE",
    "REVOKED",
    "DATASET",
    "FAMILY_NOT_COMPAT",
    "DURABLE",
};

static constexpr bool kApplied[20] = {
    true,  false, false, false, true,
    true,  false, false, false, false,
    false, false, true,  false, false,
    false, false, false, false, true,
};

static void ExpectHeld(const modelnet::SwarmFaultSequence& seq)
{
    BOOST_CHECK_EQUAL(seq.earned_atoms(), int64_t{42});
    BOOST_CHECK_EQUAL(seq.armed_earned(), int64_t{42});
    BOOST_CHECK_EQUAL(seq.journal().earned_atoms(), int64_t{42});
    BOOST_CHECK_EQUAL(seq.bytes_moved(), int64_t{0});
    BOOST_CHECK(!seq.live_gpu_injection());
    BOOST_CHECK(!seq.mined());
    BOOST_CHECK(!seq.spent());
    BOOST_CHECK(!seq.broadcast());
}

BOOST_AUTO_TEST_CASE(earned_42_steps_all_twenty)
{
    modelnet::SwarmFaultSequence seq;
    BOOST_CHECK(!seq.ContinueWork());
    seq.Begin(42);
    ExpectHeld(seq);
    BOOST_CHECK(!seq.ContinueWork());
    BOOST_CHECK(!seq.refused());
    BOOST_CHECK(!seq.finished());

    std::string err;
    for (int fault = 1; fault <= 20; ++fault) {
        const modelnet::SwarmFaultSeqStep step = seq.Step(err);
        ExpectHeld(seq);
        BOOST_CHECK_EQUAL(seq.last_fault(), fault);
        BOOST_CHECK_EQUAL(seq.code(), kCode[fault - 1]);
        BOOST_CHECK_EQUAL(seq.journal().code(), kCode[fault - 1]);
        if (kApplied[fault - 1]) {
            BOOST_REQUIRE(step == modelnet::SwarmFaultSeqStep::Applied);
            // Fault 1 is the only success before a refusal. Later successes stay blocked until Restart.
            if (!seq.refused()) {
                BOOST_REQUIRE(seq.ContinueWork());
            } else {
                BOOST_REQUIRE(!seq.ContinueWork());
            }
        } else {
            BOOST_REQUIRE(step == modelnet::SwarmFaultSeqStep::Failed);
            BOOST_CHECK_EQUAL(err, kCode[fault - 1]);
            BOOST_REQUIRE(!seq.ContinueWork());
            BOOST_REQUIRE(!seq.ContinueWork());
        }
        if (fault == 12) {
            BOOST_CHECK(!seq.journal().report_accepted());
        }
        if (fault == 15) {
            BOOST_CHECK(seq.journal().frozen());
        }
        if (fault == 18) {
            BOOST_CHECK(!seq.journal().training());
        }
    }

    BOOST_REQUIRE(seq.finished());
    BOOST_CHECK(seq.refused());
    BOOST_CHECK_EQUAL(seq.codes().size(), 20U);
    for (const std::string& code : seq.codes()) {
        BOOST_CHECK_NE(code, "FAULT");
    }
    const std::string code_after_20 = seq.code();
    BOOST_REQUIRE(code_after_20 == "DURABLE");

    const modelnet::SwarmFaultSeqStep done = seq.Step(err);
    BOOST_REQUIRE(done == modelnet::SwarmFaultSeqStep::Done);
    BOOST_CHECK_EQUAL(err, "DONE");
    BOOST_CHECK_EQUAL(seq.code(), code_after_20);
    BOOST_CHECK_EQUAL(seq.journal().code(), code_after_20);
    BOOST_CHECK_EQUAL(seq.codes().size(), 20U);
    BOOST_CHECK_EQUAL(seq.last_fault(), 20);
    ExpectHeld(seq);
    BOOST_CHECK(!seq.ContinueWork());

    const modelnet::SwarmFaultSeqStep done_again = seq.Step(err);
    BOOST_REQUIRE(done_again == modelnet::SwarmFaultSeqStep::Done);
    BOOST_CHECK_EQUAL(err, "DONE");
    BOOST_CHECK_EQUAL(seq.codes().size(), 20U);
    ExpectHeld(seq);

    BOOST_REQUIRE(seq.Restart());
    BOOST_CHECK_EQUAL(seq.armed_earned(), int64_t{42});
    ExpectHeld(seq);
    BOOST_CHECK(seq.code().empty());
    BOOST_CHECK(!seq.refused());
    BOOST_CHECK(!seq.finished());
    BOOST_CHECK(!seq.ContinueWork());
    BOOST_CHECK_EQUAL(seq.next_fault(), 1);

    const modelnet::SwarmFaultSeqStep again = seq.Step(err);
    BOOST_REQUIRE(again == modelnet::SwarmFaultSeqStep::Applied);
    BOOST_CHECK_EQUAL(seq.code(), "DURABLE");
    BOOST_REQUIRE(seq.ContinueWork());
    ExpectHeld(seq);
}

BOOST_AUTO_TEST_CASE(restart_after_refusal_keeps_earned)
{
    modelnet::SwarmFaultSequence seq;
    seq.Begin(42);
    std::string err;

    const modelnet::SwarmFaultSeqStep first = seq.Step(err);
    BOOST_REQUIRE(first == modelnet::SwarmFaultSeqStep::Applied);
    BOOST_REQUIRE(seq.ContinueWork());
    BOOST_CHECK(!seq.Restart());
    BOOST_CHECK_EQUAL(seq.next_fault(), 2);
    BOOST_CHECK_EQUAL(seq.code(), "DURABLE");

    const modelnet::SwarmFaultSeqStep refused = seq.Step(err);
    BOOST_CHECK(refused == modelnet::SwarmFaultSeqStep::Failed);
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK_EQUAL(seq.code(), "LEASE_EXPIRED");
    BOOST_CHECK(!seq.ContinueWork());
    BOOST_CHECK(!seq.ContinueWork());
    ExpectHeld(seq);

    BOOST_REQUIRE(seq.Restart());
    BOOST_CHECK_EQUAL(seq.armed_earned(), int64_t{42});
    ExpectHeld(seq);
    BOOST_CHECK(!seq.refused());
    BOOST_CHECK(!seq.ContinueWork());
    BOOST_CHECK(seq.code().empty());

    const modelnet::SwarmFaultSeqStep restarted = seq.Step(err);
    BOOST_REQUIRE(restarted == modelnet::SwarmFaultSeqStep::Applied);
    BOOST_CHECK_EQUAL(seq.code(), "DURABLE");
    BOOST_REQUIRE(seq.ContinueWork());
    ExpectHeld(seq);
    BOOST_CHECK(!seq.mined());
    BOOST_CHECK(!seq.spent());
    BOOST_CHECK(!seq.broadcast());
    BOOST_CHECK(!seq.live_gpu_injection());
}

BOOST_AUTO_TEST_CASE(step_before_begin_does_not_apply)
{
    modelnet::SwarmFaultSequence seq;
    std::string err = "STALE";
    const modelnet::SwarmFaultSeqStep step = seq.Step(err);
    BOOST_CHECK(step == modelnet::SwarmFaultSeqStep::Failed);
    BOOST_CHECK_EQUAL(err, "BEGIN");
    BOOST_CHECK(!seq.begun());
    BOOST_CHECK(!seq.Restart());
    BOOST_CHECK(!seq.ContinueWork());
    BOOST_CHECK(seq.code().empty());
    BOOST_CHECK_EQUAL(seq.journal().code(), "");
    BOOST_CHECK_EQUAL(seq.earned_atoms(), int64_t{0});
    BOOST_CHECK_EQUAL(seq.bytes_moved(), int64_t{0});
}

BOOST_AUTO_TEST_SUITE_END()
