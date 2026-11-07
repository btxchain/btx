// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc01/acc01.h>

#include <modelnet/economy.h>
#include <modelnet/graph_views/graph_views.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/pq_delegation.h>
#include <modelnet/profile.h>
#include <modelnet/source_policy.h>
#include <modelnet/swarm_cycle.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_notomit.h>
#include <modelnet/swarm_planner/codes.h>
#include <modelnet/swarm_runtime/supervisor.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

ProfilePolicy RestrictivePolicy()
{
    ProfilePolicy policy;
    policy.relay = false;
    policy.index = false;
    policy.host_mode = HostMode::OFF;
    policy.storage_arg = "auto";
    policy.auto_cap_bytes = 0;
    policy.upload_bps = 0;
    policy.follow_peers = false;
    policy.preserve_rare = false;
    policy.seed = "auto";
    return policy;
}

ProfilePolicy MigratedPolicy()
{
    return ResolveProfile(OperatorProfile::MIRROR, OverridesFromPolicy(RestrictivePolicy()));
}

ProfilePolicy OpenMirror()
{
    return ResolveProfile(OperatorProfile::MIRROR, ProfileOverrides{});
}

SwarmDevice QuietDevice()
{
    SwarmDevice device;
    device.idle_contribution = false;
    device.slots = 4;
    device.cpu_threads = 2;
    return device;
}

SwarmDevice BusyDevice()
{
    SwarmDevice device;
    device.idle_contribution = true;
    device.slots = 2;
    device.cpu_threads = 1;
    device.vram_bytes = 0;
    device.license_allows_training = false;
    return device;
}

bool Named(const std::vector<std::string>& rows, const std::string& name)
{
    const std::string prefix = name + "=";
    for (const std::string& row : rows) {
        if (row.compare(0, prefix.size(), prefix) == 0) return true;
    }
    return false;
}

std::vector<std::string> FilteredEnvironment()
{
    char home[] = "HOME=/acc01";
    char path[] = "PATH=/usr/bin";
    char secret[] = "SECRET_TOKEN=hidden";
    char* envp[] = {home, secret, path, nullptr};
    return modelnet::swarm::SanitizeEnvironment(envp);
}

} // namespace

bool Acc01::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (!Run(err)) return false;
    if (hosts() != static_cast<int64_t>(1) || bytes_moved() != static_cast<int64_t>(0) ||
        passed() || gpu_passed() || windows_passed() || release_qualified() || hardware_qualified() ||
        qualified() || gpu() || launched() || broadcast() || advertised() ||
        automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Acc01::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc01::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Acc01::Run(std::string& err)
{
    if (!omit_control(err)) return false;
    if (!fail_swarm(err)) return false;
    if (!shutdown_bounded(err)) return false;
    if (!quiet_observer() || quiet_seeder() || quiet_evaluator() || quiet_trainer() ||
        quiet_workers() != 0 || quiet_budget_code() != "IDLE_OFF" || role_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = "OBSERVER";
        return false;
    }
    if (!busy_observer() || !busy_seeder() || !busy_evaluator() || busy_trainer() ||
        busy_workers() != 2 || busy_budget_code() != "ADMITTED") {
        err = "OBSERVER";
        return false;
    }
    if (!migrated_host_off() || open_host_off() || migrated_relay() || !open_relay() ||
        migrated_follow() || !open_follow() || migrated_upload() != 0 || open_upload() == 0 ||
        blocked_upload() != 0) {
        err = "MIGRATE";
        return false;
    }
    const std::vector<std::string> inherited = inherited_resources(
        {"descriptor", "cpu", "token", "scratch"}, {"cpu", "scratch"});
    if (inherited.size() != 2 || inherited[0] != "cpu" || inherited[1] != "scratch" ||
        !env_kept("HOME") || !env_kept("PATH") || env_kept("SECRET_TOKEN") || torrent_receives_secrets()) {
        err = "INHERIT";
        return false;
    }
    if (!load_views(err)) return false;
    if (!prove_cycle(err)) return false;
    if (!prove_retract(err)) return false;
    if (!prove_search(err)) return false;
    if (!prove_wake(err)) return false;
    if (!propose(2, "authority-2", err)) return false;
    {
        std::string stale;
        if (propose(1, "stale-body", stale) || stale != kSwarmPlannerStale || epoch() != 2 || body() != "authority-2") {
            err = "STALE";
            return false;
        }
    }
    if (!replace_session("session-2", err)) return false;
    if (!step(err) || m_steps != static_cast<int64_t>(1)) {
        err = "STEP";
        return false;
    }
    if (!m_planner.Quiesce(err) || !quiescent()) return false;
    {
        std::vector<std::string> round;
        round.reserve(kReplanBound);
        for (std::size_t i = 0; i < kReplanBound; ++i) {
            round.push_back("round-" + std::to_string(i));
        }
        if (!replan(round, err) || replan_count() != kReplanBound) {
            err = "BOUND";
            return false;
        }
    }
    if (!prove_quorum(err)) return false;
    if (!prove_history(err)) return false;
    if (!prove_reconfigure(err)) return false;
    if (!prove_override(err)) return false;
    if (!prove_attempts(err)) return false;
    if (!prove_unknown(err)) return false;
    if (!prove_fence(err)) return false;
    if (!prove_boundary(err)) return false;
    if (!prove_replicas(err)) return false;
    if (research_may_spend() || economy_touches_consensus()) {
        err = "MONETARY";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::omit_control(std::string& err)
{
    SwarmNotOmit note;
    note.target_id = "control";
    note.default_build = true;
    note.want_omit = true;
    const SwarmNotOmitResult result = SwarmNoteNotOmit(note, err);
    m_omitted = result.omitted;
    m_omit_code = result.code;
    if (result.omitted || !m_control_on || result.code != "PRESENT") {
        if (err.empty()) err = "LIFECYCLE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::fail_swarm(std::string& err)
{
    if (m_swarm_failed) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_balance = kMonetaryCredit;
    if (!m_sched.Reserve(kPinnedBytes, err)) return false;
    if (!m_sched.FailWorker(err)) return false;
    m_balance_at_failure = m_balance;
    if (m_balance != kMonetaryCredit || m_halted || m_sched.physical_bytes() != kPinnedBytes ||
        !m_sched.worker_failed() || !m_sched.monetary_ok() || m_sched.validation_affected() ||
        research_may_spend() || economy_touches_consensus()) {
        err = "MONETARY";
        return false;
    }
    std::string spend;
    if (m_sched.Spend(spend) || spend != NIFDT_AUTOMATIC_SPEND) {
        err = "SPEND";
        return false;
    }
    m_swarm_failed = true;
    err.clear();
    return true;
}

bool Acc01::debit(int64_t amount, std::string& err)
{
    if (m_halted || amount < static_cast<int64_t>(1) || m_balance < amount) {
        err = "HALTED";
        return false;
    }
    m_balance -= amount;
    err.clear();
    return true;
}

bool Acc01::shutdown_bounded(std::string& err)
{
    if (m_stopped) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_shutdown_steps = 0;
    m_unresolved = 0;
    for (int64_t step = 0; step < kShutdownBound; ++step) {
        m_shutdown_steps = step + static_cast<int64_t>(1);
    }
    if (m_shutdown_steps != kShutdownBound) {
        err = "BOUND";
        return false;
    }
    m_unresolved = 1;
    m_outcome = "OUTCOME_UNKNOWN";
    m_stopped = true;
    err.clear();
    return true;
}

bool Acc01::load_views(std::string& err)
{
    const char* const ids[] = {"rec-1", "dep-1", "evi-1", "rep-1"};
    const char* const kinds[] = {"record", "dependency", "evidence", "replication"};
    for (int i = 0; i < 4; ++i) {
        if (!m_kinds.Add(ids[i], kinds[i], err)) return false;
    }
    m_native_total = m_kinds.Count();
    if (m_native_total != static_cast<int64_t>(4)) {
        err = "VIEW";
        return false;
    }
    if (m_kinds.Add("rec-1", "record", err) || err != NIFDT_REPLAY || !m_kinds.contains("rec-1")) {
        err = "REPLAY";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_cycle(std::string& err)
{
    if (!m_cycles.Add("c-a", "dependency", err)) return false;
    if (!m_cycles.Add("c-b", "dependency", err)) return false;
    if (!m_cycles.Link("c-a", "c-b", err)) return false;
    std::string cycle;
    std::string self;
    const bool back = m_cycles.Link("c-b", "c-a", cycle);
    const bool self_edge = m_cycles.Link("c-a", "c-a", self);
    if (back || self_edge) {
        err = "CYCLE";
        return false;
    }
    if (cycle != "CYCLE" || self != "CYCLE" || m_cycles.has_link("c-b", "c-a") || m_cycles.has_link("c-a", "c-a") ||
        !m_cycles.has_link("c-a", "c-b")) {
        err = "CYCLE";
        return false;
    }
    if (!m_cycles.Dispatch(err)) return false;
    err.clear();
    return true;
}

bool Acc01::prove_retract(std::string& err)
{
    if (m_kinds.History("evi-1") != "evidence" || !m_kinds.Retract("evi-1", err)) {
        err = "HISTORY";
        return false;
    }
    if (m_kinds.History("evi-1") != "evidence" || !m_kinds.retracted("evi-1") || !m_kinds.contains("evi-1")) {
        err = "HISTORY";
        return false;
    }
    if (!m_planner.Admit(kSwarmPlannerEvidence, "ev-src", err)) return false;
    if (!m_planner.Admit(kSwarmPlannerWorkView, "ev-src", err)) return false;
    if (!m_planner.Admit(kSwarmPlannerWorkView, "job-1", err)) return false;
    if (!m_planner.Depend("ev-src", "job-1", err)) return false;
    if (!m_planner.Finish("ev-src", err)) return false;
    if (!m_planner.Dispatch("job-1", err)) return false;
    m_dispatch_before_retract = true;
    m_history_before = m_planner.history_count();
    if (!m_planner.Retract("ev-src", err)) return false;
    m_history_after = m_planner.history_count();
    std::string dispatch_err;
    if (m_planner.Dispatch("job-1", dispatch_err) || dispatch_err != kSwarmPlannerInvalid) {
        err = "RETRACT";
        return false;
    }
    if (m_history_after != m_history_before + static_cast<int64_t>(1) ||
        !m_planner.admitted(kSwarmPlannerEvidence, "ev-src") || !m_planner.retracted("ev-src")) {
        err = "HISTORY";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_search(std::string& err)
{
    if (!m_planner.Admit(kSwarmPlannerResource, "shown", err)) return false;
    const int64_t before = m_planner.visible_count();
    std::string hidden;
    std::string absent;
    const bool hidden_hit = m_planner.Search(kSwarmPlannerResource, "shown", false, hidden);
    const bool absent_hit = m_planner.Search(kSwarmPlannerResource, "missing", false, absent);
    if (hidden_hit || absent_hit || hidden != kSwarmPlannerNotVisible || hidden != absent ||
        m_planner.visible_count() != before) {
        err = "FILTER";
        return false;
    }
    if (!m_planner.Search(kSwarmPlannerResource, "shown", true, err)) return false;
    err.clear();
    return true;
}

bool Acc01::prove_wake(std::string& err)
{
    if (!m_planner.Wake("wake-1", err)) return false;
    m_pending_before_commit = m_planner.outbox_size() - m_planner.cursor();
    if (m_pending_before_commit != static_cast<uint64_t>(1) || m_planner.cursor() != static_cast<uint64_t>(0)) {
        err = "CURSOR";
        return false;
    }
    if (m_planner.CommitCursor() != static_cast<uint64_t>(1)) {
        err = "CURSOR";
        return false;
    }
    if (!m_planner.Wake("wake-2", err)) return false;
    if (m_planner.outbox_size() != m_planner.cursor() + static_cast<uint64_t>(1)) {
        err = "CURSOR";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_quorum(std::string& err)
{
    if (!m_realm.SetPolicy("committee", 2, {"voter-a", "voter-b"}, err)) return false;
    m_quorum_before = m_realm.Quorum("committee", {"voter-a", "voter-b"});
    const bool stranger = m_realm.Quorum("committee", {"voter-a", "stranger"});
    std::string policy_err;
    const bool replaced = m_realm.SetPolicy("committee", 2, {"voter-a", "voter-b", "stranger"}, policy_err);
    m_policy_code = policy_err;
    if (replaced || !m_quorum_before || stranger || m_policy_code != "BTX035_POLICY" ||
        m_realm.Threshold("committee") != 2 || !m_realm.Quorum("committee", {"voter-a", "voter-b"})) {
        err = "QUORUM";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_history(std::string& err)
{
    if (!m_realm.PublishChannel("committee", static_cast<int64_t>(0), "hist-0", err)) return false;
    m_committed.push_back(m_realm.ChannelBody("committee"));
    if (m_committed.size() != 1 || m_committed[0] != "hist-0" || m_realm.ChannelSequence("committee") != static_cast<int64_t>(0)) {
        err = "HISTORY";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_reconfigure(std::string& err)
{
    const std::vector<std::string> prior = m_committed;
    const int64_t sequence = m_realm.ChannelSequence("committee");
    const std::string body = m_realm.ChannelBody("committee");
    m_controller = "controller-2";
    m_controller_generation += static_cast<int64_t>(1);
    std::string rollback;
    if (m_realm.PublishChannel("committee", static_cast<int64_t>(-1), "erased", rollback)) {
        err = "ROLLBACK";
        return false;
    }
    m_rollback_code = rollback;
    if (m_committed != prior || m_realm.ChannelSequence("committee") != sequence ||
        m_realm.ChannelBody("committee") != body || m_rollback_code != "BTX035_ROLLBACK" ||
        m_controller_generation != static_cast<int64_t>(2)) {
        err = "HISTORY";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_attempts(std::string& err)
{
    if (!m_attempts.Intent("intent-a", "body-a", err)) return false;
    std::string replay;
    if (m_attempts.Intent("intent-a", "body-a", replay) || replay != kSwarmHandoffReplay ||
        m_attempts.attempt("intent-a") != 1) {
        err = "ATTEMPT";
        return false;
    }
    if (!m_attempts.Intent("intent-b", "body-b", err)) return false;
    std::string conflict;
    if (m_attempts.Intent("intent-a", "body-changed", conflict) || conflict != kSwarmHandoffConflict ||
        m_attempts.payload("intent-a") != "body-a" || m_attempts.attempt("intent-a") != 1 ||
        m_attempts.attempt("intent-b") != 1 || m_attempts.payload("intent-b") != "body-b") {
        err = "CONFLICT";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_unknown(std::string& err)
{
    if (!m_unknown.Intent("ext-effect", "once", err)) return false;
    if (!m_unknown.Lease("holder-u", static_cast<int64_t>(20), static_cast<int64_t>(10), err)) return false;
    if (!m_unknown.Begin("ext-effect", "holder-u", static_cast<int64_t>(20), static_cast<int64_t>(10), err)) return false;
    if (m_unknown.Fence("ext-effect", false, err) || err != kSwarmHandoffAmbiguous) {
        err = "AMBIGUOUS";
        return false;
    }
    m_effects_before_second = m_unknown.effects();
    std::string again;
    if (m_unknown.Fence("ext-effect", false, again) || again != kSwarmHandoffAmbiguous ||
        m_effects_before_second != 1 || m_unknown.effects() != 1 || !m_unknown.ambiguous("ext-effect") ||
        !m_unknown.owner_of("ext-effect").empty()) {
        err = "AMBIGUOUS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_fence(std::string& err)
{
    std::string missing;
    if (m_fenced.Fence("effect-job", true, missing) || missing != kSwarmHandoffHandoff) {
        err = "FENCE";
        return false;
    }
    if (!m_fenced.Intent("effect-job", "apply", err)) return false;
    if (!m_fenced.Lease("holder-f", static_cast<int64_t>(30), static_cast<int64_t>(10), err)) return false;
    if (!m_fenced.Begin("effect-job", "holder-f", static_cast<int64_t>(30), static_cast<int64_t>(10), err)) return false;
    m_owner_before = m_fenced.owner();
    if (m_owner_before != kSwarmHandoffSource || m_fenced.committed("effect-job")) {
        err = "FENCE";
        return false;
    }
    if (!m_fenced.Fence("effect-job", true, err)) return false;
    if (!m_fenced.committed("effect-job") || m_fenced.owner() != "holder-f" || m_fenced.effects() != 1) {
        err = "FENCE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_boundary(std::string& err)
{
    m_boundary_admitted = SwarmAdmitCohortMember(static_cast<int64_t>(10), static_cast<int64_t>(10), true, true, m_boundary_code);
    std::string interior;
    m_interior_admitted = SwarmAdmitCohortMember(static_cast<int64_t>(9), static_cast<int64_t>(10), true, true, interior);
    if (m_boundary_admitted || m_boundary_code != "LEASE_EXPIRED" || !m_interior_admitted || !interior.empty()) {
        err = "LEASE";
        return false;
    }
    std::string equality;
    if (m_edge.Lease("holder-edge", static_cast<int64_t>(10), static_cast<int64_t>(10), equality) ||
        equality != kSwarmHandoffExpired || m_edge.leased("holder-edge")) {
        err = "LEASE";
        return false;
    }
    m_equality_rejected = true;
    if (!m_edge.Lease("holder-edge", static_cast<int64_t>(10), static_cast<int64_t>(9), err)) return false;
    if (!m_edge.live("holder-edge", static_cast<int64_t>(9)) || m_edge.live("holder-edge", static_cast<int64_t>(10))) {
        err = "LEASE";
        return false;
    }
    if (!m_edge.Intent("edge-job", "edge-body", err)) return false;
    if (m_edge.Begin("edge-job", "holder-edge", static_cast<int64_t>(10), static_cast<int64_t>(10), m_begin_boundary_code) ||
        m_begin_boundary_code != kSwarmHandoffExpired) {
        err = "LEASE";
        return false;
    }
    if (!m_edge.Begin("edge-job", "holder-edge", static_cast<int64_t>(10), static_cast<int64_t>(9), err) ||
        !m_edge.open("edge-job")) {
        err = "LEASE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_override(std::string& err)
{
    std::string inner;
    m_compatible_open = SwarmAdmitCohortMember(static_cast<int64_t>(5), static_cast<int64_t>(10), true, true, inner);
    if (!m_compatible_open || !inner.empty()) {
        err = "COMPATIBLE";
        return false;
    }
    if (!admit_open(m_member_generation, false, err)) return false;
    m_current_admitted = true;
    if (!m_realm.RevokeAttestor("committee", "voter-b", err)) return false;
    if (m_realm.Quorum("committee", {"voter-a", "voter-b"}) || m_realm.ChannelBody("committee") != "hist-0" ||
        m_committed.size() != 1) {
        err = "REVOKED";
        return false;
    }
    m_member_generation += static_cast<int64_t>(1);
    if (admit_open(m_member_generation - static_cast<int64_t>(1), false, m_supersede_code) ||
        m_supersede_code != "SUPERSEDED") {
        err = "SUPERSEDED";
        return false;
    }
    if (admit_open(m_member_generation, true, m_revoke_code) || m_revoke_code != NIFDT_REVOKED) {
        err = "REVOKED";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::prove_replicas(std::string& err)
{
    for (std::size_t i = 0; i < kReplicaBound; ++i) {
        if (!replicate("local", "rep-" + std::to_string(i), err)) return false;
    }
    if (replica_count() != static_cast<int64_t>(kReplicaBound) || hosts() != static_cast<int64_t>(1) ||
        bytes_moved() != static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::admit_open(int64_t generation, bool revoked, std::string& err) const
{
    std::string inner;
    if (!SwarmAdmitCohortMember(static_cast<int64_t>(5), static_cast<int64_t>(10), true, true, inner)) {
        err = inner;
        return false;
    }
    if (revoked) {
        err = NIFDT_REVOKED;
        return false;
    }
    if (generation != m_member_generation) {
        err = "SUPERSEDED";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::step(std::string& err)
{
    if (m_planner.quiescent()) {
        err = "QUIESCENT";
        return false;
    }
    m_steps += static_cast<int64_t>(1);
    err.clear();
    return true;
}

bool Acc01::search(const std::string& view, const std::string& id, bool allowed, std::string& err) const
{
    return m_planner.Search(view, id, allowed, err);
}

bool Acc01::propose(int64_t plan_epoch, const std::string& plan_body, std::string& err)
{
    return m_planner.Propose(plan_epoch, plan_body, err);
}

bool Acc01::replace_session(const std::string& session, std::string& err)
{
    if (session.empty()) {
        err = "SESSION";
        return false;
    }
    const int64_t plan_epoch = m_planner.epoch();
    const std::string plan_body = m_planner.body();
    const uint64_t outbox = m_planner.outbox_size();
    const uint64_t plan_cursor = m_planner.cursor();
    const int64_t history = m_planner.history_count();
    m_session = session;
    if (m_planner.epoch() != plan_epoch || m_planner.body() != plan_body || m_planner.outbox_size() != outbox ||
        m_planner.cursor() != plan_cursor || m_planner.history_count() != history) {
        err = "LOST";
        return false;
    }
    err.clear();
    return true;
}

bool Acc01::replan(const std::vector<std::string>& intents, std::string& err)
{
    if (intents.empty()) {
        err = "FIELD";
        return false;
    }
    if (intents.size() > kReplanBound || m_replans.size() + intents.size() > kReplanBound) {
        err = "BOUND";
        return false;
    }
    for (const std::string& id : intents) {
        if (id.empty()) {
            err = "FIELD";
            return false;
        }
    }
    for (const std::string& id : intents) {
        m_replans.push_back(id);
    }
    err.clear();
    return true;
}

bool Acc01::replicate(const std::string& scope, const std::string& id, std::string& err)
{
    if (id.empty()) {
        err = "FIELD";
        return false;
    }
    if (scope != "local") {
        err = "SCOPE";
        return false;
    }
    if (!m_replica_view) {
        if (!m_replicas.View("replication", err)) return false;
        m_replica_view = true;
    }
    if (m_replicas.Count() >= static_cast<int64_t>(kReplicaBound)) {
        err = "BOUND";
        return false;
    }
    return m_replicas.Add(id, "replication", err);
}

int64_t Acc01::count_view(const std::string& name, std::string& err)
{
    if (!m_kinds.View(name, err)) return static_cast<int64_t>(-1);
    err.clear();
    return m_kinds.Count();
}

bool Acc01::add_kind(const std::string& id, const std::string& kind, std::string& err)
{
    return m_kinds.Add(id, kind, err);
}

bool Acc01::link(const std::string& from, const std::string& to, std::string& err)
{
    return m_cycles.Link(from, to, err);
}

bool Acc01::dispatch_cycles(std::string& err) const
{
    return m_cycles.Dispatch(err);
}

std::string Acc01::dependent_dispatch() const
{
    std::string err;
    if (m_planner.Dispatch("job-1", err)) return std::string();
    return err;
}

bool Acc01::intent(const std::string& id, const std::string& payload, std::string& err)
{
    return m_attempts.Intent(id, payload, err);
}

bool Acc01::fence_unknown(std::string& err)
{
    return m_unknown.Fence("ext-effect", false, err);
}

bool Acc01::fence_committed(std::string& err)
{
    return m_fenced.Fence("effect-job", true, err);
}

bool Acc01::lease(const std::string& worker, int64_t until_ms, int64_t now_ms, std::string& err)
{
    return m_edge.Lease(worker, until_ms, now_ms, err);
}

bool Acc01::admit_cohort(int64_t now_ms, int64_t until_ms, bool compatible, std::string& err) const
{
    return SwarmAdmitCohortMember(now_ms, until_ms, compatible, compatible, err);
}

bool Acc01::admit_member(int64_t generation, bool revoked, std::string& err) const
{
    return admit_open(generation, revoked, err);
}

bool Acc01::quorum_now() const
{
    return m_realm.Quorum("committee", {"voter-a", "voter-b"});
}

bool Acc01::stranger_quorum() const
{
    return m_realm.Quorum("committee", {"voter-a", "stranger"});
}

bool Acc01::quiet_observer() const
{
    return SwarmEligibleRoles(QuietDevice()).observer;
}

bool Acc01::quiet_seeder() const
{
    return SwarmEligibleRoles(QuietDevice()).seeder;
}

bool Acc01::quiet_evaluator() const
{
    return SwarmEligibleRoles(QuietDevice()).evaluator;
}

bool Acc01::quiet_trainer() const
{
    return SwarmEligibleRoles(QuietDevice()).trainer;
}

int Acc01::quiet_workers() const
{
    return SwarmGovern(QuietDevice(), 4).active_workers;
}

std::string Acc01::quiet_budget_code() const
{
    return SwarmGovern(QuietDevice(), 4).code;
}

bool Acc01::busy_observer() const
{
    return SwarmEligibleRoles(BusyDevice()).observer;
}

bool Acc01::busy_seeder() const
{
    return SwarmEligibleRoles(BusyDevice()).seeder;
}

bool Acc01::busy_evaluator() const
{
    return SwarmEligibleRoles(BusyDevice()).evaluator;
}

bool Acc01::busy_trainer() const
{
    return SwarmEligibleRoles(BusyDevice()).trainer;
}

int Acc01::busy_workers() const
{
    return SwarmGovern(BusyDevice(), 4).active_workers;
}

std::string Acc01::busy_budget_code() const
{
    return SwarmGovern(BusyDevice(), 4).code;
}

std::string Acc01::role_spend() const
{
    return SwarmEligibleRoles(QuietDevice()).automatic_spend_atoms;
}

bool Acc01::migrated_host_off() const
{
    return MigratedPolicy().host_mode == HostMode::OFF;
}

bool Acc01::open_host_off() const
{
    return OpenMirror().host_mode == HostMode::OFF;
}

bool Acc01::migrated_relay() const
{
    return MigratedPolicy().relay;
}

bool Acc01::open_relay() const
{
    return OpenMirror().relay;
}

bool Acc01::migrated_follow() const
{
    return MigratedPolicy().follow_peers;
}

bool Acc01::open_follow() const
{
    return OpenMirror().follow_peers;
}

std::uint64_t Acc01::migrated_upload() const
{
    return MigratedPolicy().upload_bps;
}

std::uint64_t Acc01::open_upload() const
{
    return OpenMirror().upload_bps;
}

std::uint64_t Acc01::blocked_upload() const
{
    return EffectiveHostUploadBps(OpenMirror().upload_bps, static_cast<int64_t>(1000000), false);
}

bool Acc01::env_kept(const std::string& name) const
{
    return Named(FilteredEnvironment(), name);
}

bool Acc01::torrent_receives_secrets() const
{
    return TorrentWorkerReceivesS3Credentials();
}

std::vector<std::string> Acc01::inherited_resources(const std::vector<std::string>& requested,
                                                    const std::vector<std::string>& approved) const
{
    std::vector<std::string> kept;
    for (const std::string& name : approved) {
        for (const std::string& want : requested) {
            if (want == name) {
                kept.push_back(name);
                break;
            }
        }
    }
    return kept;
}

bool Acc01::research_may_spend() const
{
    return ResearchMaySpendWallet();
}

bool Acc01::economy_touches_consensus() const
{
    return EconomyTouchesMonetaryConsensus();
}

bool Acc01::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    static const char* const kJournal[] = {
        "CORE-001", "CORE-002", "CORE-003", "CORE-004", "CORE-005",
        "ARCH-001", "ARCH-002", "ARCH-003", "ARCH-004",
        "SEC-001", "SEC-002", "SEC-003", "SEC-004",
        "WIRE-001", "WIRE-002", "WIRE-003",
    };
    bool known = false;
    for (const char* row : kJournal) {
        if (id == row) {
            known = true;
            break;
        }
    }
    if (id.empty() || !known) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < 0) {
        err = "BOUND";
        return false;
    }
    if (aux > 100) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    static const char* const kAbsent[] = {
        "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer", "dualpipe", "fp8", "fp4",
    };
    for (const char* name : kAbsent) {
        if (text == name) {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "CORE-003" && text.find("consensus") != std::string::npos) {
        err = "CONSENSUS";
        return false;
    }
    if (id == "CORE-005" && text.find("claim") != std::string::npos) {
        err = "CLAIM";
        return false;
    }
    if (id == "ARCH-001" && text == "hardware") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "ARCH-002" && text == "assign") {
        err = "AUTHORITY";
        return false;
    }
    if (id == "ARCH-004" && text == "s1") {
        err = "PROFILE";
        return false;
    }
    if (id == "SEC-002" && text == "shell") {
        err = "QUARANTINE";
        return false;
    }
    if (id == "WIRE-001" && text.find("1.1.0") == std::string::npos) {
        err = "VERSION";
        return false;
    }
    if (id == "WIRE-003" && text == "oversize") {
        err = "LIMIT";
        return false;
    }
    const auto found = m_journal.find(id);
    if (found != m_journal.end()) {
        err = found->second == text ? NIFDT_REPLAY : "UNCHANGED";
        return false;
    }
    m_journal.emplace(id, text);
    err.clear();
    return true;
}

} // namespace modelnet
