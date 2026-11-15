// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc01/acc01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_handoff/swarm_handoff.h>
#include <modelnet/swarm_planner/codes.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void Qualification(const modelnet::Acc01& eng)
{
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(acc01_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc01 eng;
    std::string err = "stale";
    Qualification(eng);
    BOOST_CHECK(eng.control_on());
    BOOST_CHECK_EQUAL(eng.monetary_balance(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.monetary_halted());
    BOOST_CHECK(!eng.worker_failed());

    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());

    // ASR-NAT-001
    BOOST_CHECK(eng.control_on());
    BOOST_CHECK(!eng.omitted());
    BOOST_CHECK_EQUAL(eng.omit_code(), "PRESENT");
    BOOST_CHECK(eng.omit_control(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.control_on());
    BOOST_CHECK(!eng.omitted());

    // ASR-NAT-002
    BOOST_CHECK_EQUAL(eng.balance_at_failure(), modelnet::Acc01::kMonetaryCredit);
    BOOST_CHECK_EQUAL(eng.monetary_balance(), modelnet::Acc01::kMonetaryCredit);
    BOOST_CHECK(!eng.monetary_halted());
    BOOST_CHECK(eng.worker_failed());
    BOOST_CHECK(eng.monetary_ok());
    BOOST_CHECK(!eng.validation_affected());
    BOOST_CHECK_EQUAL(eng.pinned_bytes(), modelnet::Acc01::kPinnedBytes);
    BOOST_CHECK(!eng.research_may_spend());
    BOOST_CHECK(!eng.economy_touches_consensus());
    BOOST_CHECK(eng.debit(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.monetary_balance(), modelnet::Acc01::kMonetaryCredit - static_cast<int64_t>(1));
    BOOST_CHECK(!eng.monetary_halted());
    BOOST_CHECK_EQUAL(eng.pinned_bytes(), modelnet::Acc01::kPinnedBytes);

    // ASR-NAT-003
    BOOST_CHECK(eng.shutdown_stopped());
    BOOST_CHECK_EQUAL(eng.shutdown_steps(), modelnet::Acc01::kShutdownBound);
    BOOST_CHECK_EQUAL(eng.unresolved_effects(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.outcome(), "OUTCOME_UNKNOWN");

    // ASR-NAT-004
    const std::vector<std::string> inherited = eng.inherited_resources(
        {"descriptor", "cpu", "token", "scratch"}, {"cpu", "scratch"});
    BOOST_CHECK_EQUAL(inherited.size(), 2U);
    BOOST_CHECK_EQUAL(inherited[0], "cpu");
    BOOST_CHECK_EQUAL(inherited[1], "scratch");
    BOOST_CHECK(eng.env_kept("HOME"));
    BOOST_CHECK(eng.env_kept("PATH"));
    BOOST_CHECK(!eng.env_kept("SECRET_TOKEN"));
    BOOST_CHECK(!eng.torrent_receives_secrets());

    // ASR-NAT-005
    BOOST_CHECK(eng.quiet_observer());
    BOOST_CHECK(!eng.quiet_seeder());
    BOOST_CHECK(!eng.quiet_evaluator());
    BOOST_CHECK(!eng.quiet_trainer());
    BOOST_CHECK_EQUAL(eng.quiet_workers(), 0);
    BOOST_CHECK_EQUAL(eng.quiet_budget_code(), "IDLE_OFF");
    BOOST_CHECK_EQUAL(eng.role_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(eng.busy_observer());
    BOOST_CHECK(eng.busy_seeder());
    BOOST_CHECK(eng.busy_evaluator());
    BOOST_CHECK(!eng.busy_trainer());
    BOOST_CHECK_EQUAL(eng.busy_workers(), 2);
    BOOST_CHECK_EQUAL(eng.busy_budget_code(), "ADMITTED");

    // ASR-NAT-006
    BOOST_CHECK(eng.migrated_host_off());
    BOOST_CHECK(!eng.open_host_off());
    BOOST_CHECK(!eng.migrated_relay());
    BOOST_CHECK(eng.open_relay());
    BOOST_CHECK(!eng.migrated_follow());
    BOOST_CHECK(eng.open_follow());
    BOOST_CHECK_EQUAL(eng.migrated_upload(), static_cast<std::uint64_t>(0));
    BOOST_CHECK(eng.open_upload() > eng.migrated_upload());
    BOOST_CHECK_EQUAL(eng.blocked_upload(), static_cast<std::uint64_t>(0));

    // ASR-GRF-001
    BOOST_CHECK_EQUAL(eng.native_total(), static_cast<int64_t>(4));
    BOOST_CHECK(eng.kind_contains("rec-1"));
    BOOST_CHECK(eng.kind_contains("dep-1"));
    BOOST_CHECK(eng.kind_contains("evi-1"));
    BOOST_CHECK(eng.kind_contains("rep-1"));
    const int64_t records = eng.count_view("record", err);
    const int64_t dependencies = eng.count_view("dependency", err);
    const int64_t evidence = eng.count_view("evidence", err);
    const int64_t replication = eng.count_view("replication", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(records, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(dependencies, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(evidence, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(replication, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(records + dependencies + evidence + replication, eng.native_total());
    BOOST_CHECK(!eng.add_kind("rec-1", "record", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK(eng.kind_contains("rec-1"));

    // ASR-GRF-002
    BOOST_CHECK(eng.cycle_has_link("c-a", "c-b"));
    BOOST_CHECK(!eng.link("c-b", "c-a", err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK(!eng.cycle_has_link("c-b", "c-a"));
    BOOST_CHECK(!eng.link("c-a", "c-a", err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK(!eng.cycle_has_link("c-a", "c-a"));
    BOOST_CHECK(eng.dispatch_cycles(err));
    BOOST_CHECK(err.empty());

    // ASR-GRF-003
    BOOST_CHECK(eng.dispatch_before_retract());
    BOOST_CHECK_EQUAL(eng.evidence_history(), "evidence");
    BOOST_CHECK(eng.kind_retracted());
    BOOST_CHECK(eng.kind_contains("evi-1"));
    BOOST_CHECK(eng.planner_evidence_admitted());
    BOOST_CHECK(eng.planner_retracted());
    BOOST_CHECK_EQUAL(eng.history_after(), eng.history_before() + static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.dependent_dispatch(), modelnet::kSwarmPlannerInvalid);

    // ASR-GRF-004
    const int64_t visible = eng.visible_count();
    BOOST_CHECK(!eng.search(modelnet::kSwarmPlannerResource, "shown", false, err));
    const std::string hidden = err;
    BOOST_CHECK(!eng.search(modelnet::kSwarmPlannerResource, "missing", false, err));
    BOOST_CHECK_EQUAL(hidden, modelnet::kSwarmPlannerNotVisible);
    BOOST_CHECK_EQUAL(err, hidden);
    BOOST_CHECK_EQUAL(eng.visible_count(), visible);
    BOOST_CHECK(eng.search(modelnet::kSwarmPlannerResource, "shown", true, err));
    BOOST_CHECK(err.empty());

    // ASR-GRF-005
    BOOST_CHECK_EQUAL(eng.replica_count(), static_cast<int64_t>(modelnet::Acc01::kReplicaBound));
    BOOST_CHECK(eng.replica_contains("rep-0"));
    BOOST_CHECK(!eng.replicate("foreign", "rep-x", err));
    BOOST_CHECK_EQUAL(err, "SCOPE");
    BOOST_CHECK(!eng.replica_contains("rep-x"));
    BOOST_CHECK(!eng.replicate("local", "rep-extra", err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK(!eng.replica_contains("rep-extra"));
    BOOST_CHECK_EQUAL(eng.replica_count(), static_cast<int64_t>(modelnet::Acc01::kReplicaBound));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    // ASR-PLN-001
    const int64_t plan_epoch = eng.epoch();
    const std::string plan_body = eng.body();
    const uint64_t outbox = eng.outbox_size();
    const uint64_t plan_cursor = eng.cursor();
    BOOST_CHECK_EQUAL(eng.session(), "session-2");
    BOOST_CHECK_EQUAL(plan_epoch, static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(plan_body, "authority-2");
    BOOST_CHECK(eng.replace_session("session-3", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.session(), "session-3");
    BOOST_CHECK_EQUAL(eng.epoch(), plan_epoch);
    BOOST_CHECK_EQUAL(eng.body(), plan_body);
    BOOST_CHECK_EQUAL(eng.outbox_size(), outbox);
    BOOST_CHECK_EQUAL(eng.cursor(), plan_cursor);

    // ASR-PLN-002
    BOOST_CHECK_EQUAL(eng.pending_before_commit(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(eng.cursor(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(eng.outbox_size(), static_cast<uint64_t>(2));
    BOOST_CHECK(eng.outbox_size() > eng.cursor());

    // ASR-PLN-003
    BOOST_CHECK(!eng.propose(static_cast<int64_t>(1), "stale-body", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmPlannerStale);
    BOOST_CHECK_EQUAL(eng.epoch(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.body(), "authority-2");

    // ASR-PLN-004
    BOOST_CHECK_EQUAL(eng.replan_count(), modelnet::Acc01::kReplanBound);
    BOOST_CHECK(!eng.replan({"extra"}, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(eng.replan_count(), modelnet::Acc01::kReplanBound);

    // ASR-PLN-005
    BOOST_CHECK(eng.quiescent());
    BOOST_CHECK_EQUAL(eng.steps(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.step(err));
    BOOST_CHECK_EQUAL(err, "QUIESCENT");
    BOOST_CHECK_EQUAL(eng.steps(), static_cast<int64_t>(1));

    // ASR-PLN-006
    BOOST_CHECK(eng.quorum_before());
    BOOST_CHECK(!eng.quorum_now());
    BOOST_CHECK(!eng.stranger_quorum());
    BOOST_CHECK_EQUAL(eng.policy_code(), "BTX035_POLICY");
    BOOST_CHECK_EQUAL(eng.threshold(), 2);

    // ASR-PLN-007
    BOOST_CHECK_EQUAL(eng.controller(), "controller-2");
    BOOST_CHECK_EQUAL(eng.controller_generation(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.channel_sequence(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.channel_body(), "hist-0");
    BOOST_CHECK_EQUAL(eng.committed_history().size(), 1U);
    BOOST_CHECK_EQUAL(eng.committed_history()[0], "hist-0");
    BOOST_CHECK_EQUAL(eng.rollback_code(), "BTX035_ROLLBACK");

    // ASR-EXE-001
    BOOST_CHECK_EQUAL(eng.attempt_of("intent-a"), 1);
    BOOST_CHECK_EQUAL(eng.attempt_of("intent-b"), 1);
    BOOST_CHECK_EQUAL(eng.payload_of("intent-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.payload_of("intent-b"), "body-b");
    BOOST_CHECK(!eng.intent("intent-a", "body-a", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffReplay);
    BOOST_CHECK_EQUAL(eng.attempt_of("intent-a"), 1);

    // ASR-EXE-002
    BOOST_CHECK(!eng.intent("intent-a", "body-changed", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffConflict);
    BOOST_CHECK_EQUAL(eng.payload_of("intent-a"), "body-a");
    BOOST_CHECK_EQUAL(eng.attempt_of("intent-a"), 1);

    // ASR-EXE-003
    BOOST_CHECK(eng.effect_ambiguous());
    BOOST_CHECK_EQUAL(eng.effects_before_second(), 1);
    BOOST_CHECK_EQUAL(eng.unknown_effects(), 1);
    BOOST_CHECK(eng.unknown_owner().empty());
    BOOST_CHECK(!eng.fence_unknown(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffAmbiguous);
    BOOST_CHECK_EQUAL(eng.unknown_effects(), 1);

    // ASR-EXE-004
    BOOST_CHECK_EQUAL(eng.owner_before_fence(), modelnet::kSwarmHandoffSource);
    BOOST_CHECK(eng.fenced_committed());
    BOOST_CHECK_EQUAL(eng.fenced_owner(), "holder-f");
    BOOST_CHECK_EQUAL(eng.fenced_effects(), 1);
    BOOST_CHECK(!eng.fence_committed(err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffReplay);
    BOOST_CHECK_EQUAL(eng.fenced_effects(), 1);
    BOOST_CHECK_EQUAL(eng.fenced_owner(), "holder-f");

    // ASR-EXE-005
    BOOST_CHECK(!eng.boundary_admitted());
    BOOST_CHECK_EQUAL(eng.boundary_code(), "LEASE_EXPIRED");
    BOOST_CHECK(eng.interior_admitted());
    BOOST_CHECK(eng.equality_rejected());
    BOOST_CHECK(eng.edge_live(static_cast<int64_t>(9)));
    BOOST_CHECK(!eng.edge_live(static_cast<int64_t>(10)));
    BOOST_CHECK_EQUAL(eng.begin_boundary_code(), modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(eng.edge_open());
    BOOST_CHECK(!eng.admit_cohort(static_cast<int64_t>(10), static_cast<int64_t>(10), true, err));
    BOOST_CHECK_EQUAL(err, "LEASE_EXPIRED");
    BOOST_CHECK(eng.admit_cohort(static_cast<int64_t>(9), static_cast<int64_t>(10), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.lease("holder-bound", static_cast<int64_t>(10), static_cast<int64_t>(10), err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(!eng.leased("holder-bound"));
    BOOST_CHECK(eng.lease("holder-bound", static_cast<int64_t>(10), static_cast<int64_t>(9), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.leased("holder-bound"));

    // ASR-EXE-006
    BOOST_CHECK(eng.compatible_open());
    BOOST_CHECK(eng.current_generation_admitted());
    BOOST_CHECK_EQUAL(eng.member_generation(), static_cast<int64_t>(2));
    BOOST_CHECK(!eng.admit_member(static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "SUPERSEDED");
    BOOST_CHECK(!eng.admit_member(static_cast<int64_t>(2), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REVOKED);
    BOOST_CHECK(eng.admit_cohort(static_cast<int64_t>(5), static_cast<int64_t>(10), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.quorum_now());
    BOOST_CHECK_EQUAL(eng.channel_body(), "hist-0");
    BOOST_CHECK_EQUAL(eng.committed_history().size(), 1U);

    err = "stale";
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    Qualification(eng);
    BOOST_CHECK_EQUAL(eng.monetary_balance(), modelnet::Acc01::kMonetaryCredit - static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.session(), "session-3");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
