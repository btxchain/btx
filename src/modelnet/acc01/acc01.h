// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC01_ACC01_H
#define BITCOIN_MODELNET_ACC01_ACC01_H

#include <modelnet/dt_schedlive/dt_schedlive.h>
#include <modelnet/graph_views/graph_views.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_channel.h>
#include <modelnet/swarm_handoff/swarm_handoff.h>
#include <modelnet/swarm_planner/swarm_planner.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Acc01. In-process behavior for the first 24 ASR/1 rows whose
 * final acceptance is unset: ASR-NAT-001 through ASR-NAT-006,
 * ASR-GRF-001 through ASR-GRF-005, ASR-PLN-001 through ASR-PLN-007,
 * and ASR-EXE-001 through ASR-EXE-006.
 *
 * Pass runs each row once and then latches. A later Pass clears err and
 * returns true without running the rows again. The qualification
 * accessors stay false. hosts() stays 1. Spend returns
 * NIFDT_AUTOMATIC_SPEND. Release returns NIFDT_UNQUALIFIED.
 * bytes_moved() stays 0. This class opens no socket and starts no process.
 */
class Acc01 {
public:
    static constexpr int64_t kShutdownBound{3};
    static constexpr int64_t kMonetaryCredit{7};
    static constexpr int64_t kPinnedBytes{10};
    static constexpr std::size_t kReplanBound{64};
    static constexpr std::size_t kReplicaBound{4};

    bool Pass(std::string& err);
    // Journal caller from Jrn01. Separate from the ASR/1 pass.
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool omit_control(std::string& err);
    bool debit(int64_t amount, std::string& err);
    bool step(std::string& err);
    bool search(const std::string& view, const std::string& id, bool allowed, std::string& err) const;
    bool propose(int64_t epoch, const std::string& body, std::string& err);
    bool replace_session(const std::string& session, std::string& err);
    bool replan(const std::vector<std::string>& intents, std::string& err);
    bool replicate(const std::string& scope, const std::string& id, std::string& err);
    int64_t count_view(const std::string& name, std::string& err);
    bool add_kind(const std::string& id, const std::string& kind, std::string& err);
    bool link(const std::string& from, const std::string& to, std::string& err);
    bool dispatch_cycles(std::string& err) const;
    bool intent(const std::string& id, const std::string& payload, std::string& err);
    bool fence_unknown(std::string& err);
    bool fence_committed(std::string& err);
    bool lease(const std::string& worker, int64_t until_ms, int64_t now_ms, std::string& err);
    bool admit_cohort(int64_t now_ms, int64_t until_ms, bool compatible, std::string& err) const;
    bool admit_member(int64_t generation, bool revoked, std::string& err) const;
    bool quiet_observer() const;
    bool quiet_seeder() const;
    bool quiet_evaluator() const;
    bool quiet_trainer() const;
    int quiet_workers() const;
    std::string quiet_budget_code() const;
    bool busy_observer() const;
    bool busy_seeder() const;
    bool busy_evaluator() const;
    bool busy_trainer() const;
    int busy_workers() const;
    std::string busy_budget_code() const;
    std::string role_spend() const;
    bool migrated_host_off() const;
    bool open_host_off() const;
    bool migrated_relay() const;
    bool open_relay() const;
    bool migrated_follow() const;
    bool open_follow() const;
    std::uint64_t migrated_upload() const;
    std::uint64_t open_upload() const;
    std::uint64_t blocked_upload() const;
    bool env_kept(const std::string& name) const;
    bool torrent_receives_secrets() const;
    std::vector<std::string> inherited_resources(const std::vector<std::string>& requested,
                                                 const std::vector<std::string>& approved) const;
    bool research_may_spend() const;
    bool economy_touches_consensus() const;

    bool control_on() const { return m_control_on; }
    bool omitted() const { return m_omitted; }
    const std::string& omit_code() const { return m_omit_code; }
    int64_t monetary_balance() const { return m_balance; }
    int64_t balance_at_failure() const { return m_balance_at_failure; }
    bool monetary_halted() const { return m_halted; }
    bool worker_failed() const { return m_sched.worker_failed(); }
    bool monetary_ok() const { return m_sched.monetary_ok(); }
    bool validation_affected() const { return m_sched.validation_affected(); }
    int64_t pinned_bytes() const { return m_sched.physical_bytes(); }
    bool shutdown_stopped() const { return m_stopped; }
    int64_t shutdown_steps() const { return m_shutdown_steps; }
    int64_t unresolved_effects() const { return m_unresolved; }
    const std::string& outcome() const { return m_outcome; }
    int64_t native_total() const { return m_native_total; }
    bool kind_contains(const std::string& id) const { return m_kinds.contains(id); }
    bool cycle_has_link(const std::string& from, const std::string& to) const { return m_cycles.has_link(from, to); }
    bool dispatch_before_retract() const { return m_dispatch_before_retract; }
    int64_t history_before() const { return m_history_before; }
    int64_t history_after() const { return m_history_after; }
    int64_t history_count() const { return m_planner.history_count(); }
    std::string evidence_history() const { return m_kinds.History("evi-1"); }
    bool kind_retracted() const { return m_kinds.retracted("evi-1"); }
    bool planner_retracted() const { return m_planner.retracted("ev-src"); }
    bool planner_evidence_admitted() const { return m_planner.admitted(kSwarmPlannerEvidence, "ev-src"); }
    std::string dependent_dispatch() const;
    int64_t visible_count() const { return m_planner.visible_count(); }
    int64_t replica_count() const { return m_replicas.Count(); }
    bool replica_contains(const std::string& id) const { return m_replicas.contains(id); }
    const std::string& session() const { return m_session; }
    int64_t epoch() const { return m_planner.epoch(); }
    std::string body() const { return m_planner.body(); }
    uint64_t outbox_size() const { return m_planner.outbox_size(); }
    uint64_t cursor() const { return m_planner.cursor(); }
    uint64_t pending_before_commit() const { return m_pending_before_commit; }
    std::size_t replan_count() const { return m_replans.size(); }
    bool quiescent() const { return m_planner.quiescent(); }
    int64_t steps() const { return m_steps; }
    bool quorum_before() const { return m_quorum_before; }
    bool quorum_now() const;
    bool stranger_quorum() const;
    int threshold() const { return m_realm.Threshold("committee"); }
    const std::string& policy_code() const { return m_policy_code; }
    int64_t channel_sequence() const { return m_realm.ChannelSequence("committee"); }
    std::string channel_body() const { return m_realm.ChannelBody("committee"); }
    const std::vector<std::string>& committed_history() const { return m_committed; }
    const std::string& controller() const { return m_controller; }
    int64_t controller_generation() const { return m_controller_generation; }
    const std::string& rollback_code() const { return m_rollback_code; }
    int attempt_of(const std::string& id) const { return m_attempts.attempt(id); }
    std::string payload_of(const std::string& id) const { return m_attempts.payload(id); }
    bool effect_ambiguous() const { return m_unknown.ambiguous("ext-effect"); }
    int unknown_effects() const { return m_unknown.effects(); }
    std::string unknown_owner() const { return m_unknown.owner_of("ext-effect"); }
    int effects_before_second() const { return m_effects_before_second; }
    const std::string& owner_before_fence() const { return m_owner_before; }
    std::string fenced_owner() const { return m_fenced.owner(); }
    bool fenced_committed() const { return m_fenced.committed("effect-job"); }
    int fenced_effects() const { return m_fenced.effects(); }
    const std::string& boundary_code() const { return m_boundary_code; }
    bool boundary_admitted() const { return m_boundary_admitted; }
    bool interior_admitted() const { return m_interior_admitted; }
    const std::string& begin_boundary_code() const { return m_begin_boundary_code; }
    bool equality_rejected() const { return m_equality_rejected; }
    bool edge_live(int64_t now_ms) const { return m_edge.live("holder-edge", now_ms); }
    bool edge_open() const { return m_edge.open("edge-job"); }
    bool leased(const std::string& worker) const { return m_edge.leased(worker); }
    int64_t member_generation() const { return m_member_generation; }
    bool current_generation_admitted() const { return m_current_admitted; }
    const std::string& supersede_code() const { return m_supersede_code; }
    const std::string& revoke_code() const { return m_revoke_code; }
    bool compatible_open() const { return m_compatible_open; }

    bool passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool qualified() const { return false; }
    bool gpu() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Run(std::string& err);
    bool fail_swarm(std::string& err);
    bool shutdown_bounded(std::string& err);
    bool load_views(std::string& err);
    bool prove_cycle(std::string& err);
    bool prove_retract(std::string& err);
    bool prove_search(std::string& err);
    bool prove_wake(std::string& err);
    bool prove_quorum(std::string& err);
    bool prove_history(std::string& err);
    bool prove_reconfigure(std::string& err);
    bool prove_attempts(std::string& err);
    bool prove_unknown(std::string& err);
    bool prove_fence(std::string& err);
    bool prove_boundary(std::string& err);
    bool prove_override(std::string& err);
    bool prove_replicas(std::string& err);
    bool admit_open(int64_t generation, bool revoked, std::string& err) const;

    bool m_done{false};
    bool m_control_on{true};
    bool m_omitted{true};
    std::string m_omit_code;
    int64_t m_balance{0};
    int64_t m_balance_at_failure{0};
    bool m_halted{false};
    bool m_swarm_failed{false};
    DtSchedLive m_sched;
    bool m_stopped{false};
    int64_t m_shutdown_steps{0};
    int64_t m_unresolved{0};
    std::string m_outcome;
    GraphViews m_kinds;
    int64_t m_native_total{0};
    GraphViews m_cycles;
    bool m_dispatch_before_retract{false};
    int64_t m_history_before{0};
    int64_t m_history_after{0};
    GraphViews m_replicas;
    bool m_replica_view{false};
    SwarmPlanner m_planner;
    std::string m_session;
    uint64_t m_pending_before_commit{0};
    std::vector<std::string> m_replans;
    int64_t m_steps{0};
    RealmRollout m_realm;
    bool m_quorum_before{false};
    std::string m_policy_code;
    std::vector<std::string> m_committed;
    std::string m_controller{"controller-1"};
    int64_t m_controller_generation{1};
    std::string m_rollback_code;
    SwarmHandoff m_attempts;
    SwarmHandoff m_unknown;
    int m_effects_before_second{0};
    SwarmHandoff m_fenced;
    std::string m_owner_before;
    SwarmHandoff m_edge;
    std::string m_boundary_code;
    bool m_boundary_admitted{true};
    bool m_interior_admitted{false};
    std::string m_begin_boundary_code;
    bool m_equality_rejected{false};
    int64_t m_member_generation{1};
    bool m_current_admitted{false};
    std::string m_supersede_code;
    std::string m_revoke_code;
    bool m_compatible_open{false};
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif
