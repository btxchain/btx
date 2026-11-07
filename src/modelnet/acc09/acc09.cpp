// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc09/acc09.h>

#include <modelnet/action_authority.h>
#include <modelnet/guard_machine.h>
#include <modelnet/lan_discovery.h>
#include <modelnet/qualification.h>
#include <modelnet/reachability.h>
#include <modelnet/swarm_engine.h>
#include <modelnet/swarm_evolution.h>
#include <modelnet/swarm_kvshare.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_survivor.h>

#include <string>
#include <vector>

namespace modelnet {
namespace {

bool Token(const std::string& text)
{
    if (text.empty()) return false;
    for (unsigned char c : text) {
        const bool digit = c >= '0' && c <= '9';
        const bool upper = c >= 'A' && c <= 'Z';
        const bool lower = c >= 'a' && c <= 'z';
        if (!digit && !upper && !lower && c != '-') return false;
    }
    return true;
}

bool QualifyReport(const SwarmCounts& counts, SwarmBound& bound, std::string& err)
{
    SwarmPolicy policy;
    policy.suite_id = "p2p-suite";
    policy.holdout_commitment = "holdout";
    policy.alpha_ppm = 50000;
    policy.max_trials = 1;
    policy.min_examples = 1;
    policy.min_gain_ppm = 0;
    SwarmReport report;
    report.suite_id = policy.suite_id;
    report.holdout_commitment = policy.holdout_commitment;
    report.counts = counts;
    report.reproducible = true;
    report.safety_regression = false;
    return SwarmQualify(report, policy, bound, err);
}

} // namespace

Acc09Community* Acc09::Find(const std::string& id)
{
    for (Acc09Community& community : m_communities) {
        if (community.id == id) return &community;
    }
    return nullptr;
}

bool Acc09::CreateLocalCommunity(const std::string& node_id, const std::string& name, const std::string& locator,
                                 Acc09Community& out, std::string& err)
{
    out = Acc09Community{};
    if (!Token(node_id)) {
        err = "NODE";
        return false;
    }
    if (!Token(name)) {
        err = "NAME";
        return false;
    }
    if (!locator.empty()) {
        err = "LOCATOR";
        return false;
    }
    const std::string id = "local/" + node_id + "/" + name;
    if (Acc09Community* existing = Find(id)) {
        if (existing->members.size() != 1 || existing->members[0] != node_id || !existing->local) {
            err = "MEMBER";
            return false;
        }
        out = *existing;
        err.clear();
        return true;
    }
    Acc09Community created;
    created.id = id;
    created.creator = node_id;
    created.name = name;
    created.local = true;
    created.members.push_back(node_id);
    m_communities.push_back(created);
    out = m_communities.back();
    err.clear();
    return true;
}

bool Acc09::CreateAndEvaluateDescendants(const std::string& community_id, Acc09Descendants& out, std::string& err)
{
    out = Acc09Descendants{};
    Acc09Community* community = Find(community_id);
    if (community == nullptr || !community->local || community->members.size() != 1) {
        err = "COMMUNITY";
        return false;
    }
    const std::string author = community->members[0];
    const std::string id_a = community_id + "#1";
    const std::string id_b = community_id + "#2";
    community->descendants.clear();
    community->descendants.push_back(id_a);
    community->descendants.push_back(id_b);
    out.ids = community->descendants;

    SwarmEvaluator self;
    self.evaluator = author;
    self.author = author;
    self.domain = "alpha";
    std::string self_err;
    out.self_rejected = !SwarmQuorum({self}, 1, 1, author, self_err) && self_err == "SELF_EVALUATION";

    SwarmEvaluator only;
    only.evaluator = "eval-a";
    only.author = author;
    only.domain = "alpha";
    std::string one_err;
    out.single_rejected = !SwarmQuorum({only}, 2, 2, author, one_err) && one_err == "QUORUM";

    SwarmEvaluator left_eval;
    left_eval.evaluator = "eval-a";
    left_eval.author = author;
    left_eval.domain = "alpha";
    SwarmEvaluator right_eval;
    right_eval.evaluator = "eval-b";
    right_eval.author = author;
    right_eval.domain = "beta";
    out.quorum = SwarmQuorum({left_eval, right_eval}, 2, 2, author, err);
    if (!out.self_rejected || !out.single_rejected || !out.quorum) {
        if (err.empty()) err = "QUORUM";
        return false;
    }

    SwarmCounts counts_a;
    counts_a.n01 = 100;
    SwarmCounts counts_b;
    counts_b.n00 = 20;
    counts_b.n01 = 80;
    SwarmBound bound_a;
    SwarmBound bound_b;
    std::string err_a;
    std::string err_b;
    const bool ok_a = QualifyReport(counts_a, bound_a, err_a);
    const bool ok_b = QualifyReport(counts_b, bound_b, err_b);
    out.qualified = (ok_a ? 1 : 0) + (ok_b ? 1 : 0);
    if (!ok_a || !ok_b || bound_a.delta_ppm <= bound_b.delta_ppm) {
        err = ok_a ? err_b : err_a;
        if (err.empty()) err = "QUALIFY";
        return false;
    }

    SwarmCandidate left;
    left.id = id_a;
    left.niche = "family";
    left.quality = bound_a.delta_ppm;
    left.novelty = 1;
    left.cost = 1;
    SwarmCandidate right;
    right.id = id_b;
    right.niche = "family";
    right.quality = bound_b.delta_ppm;
    right.novelty = 2;
    right.cost = 1;
    const std::vector<SwarmCandidate> frontier = SwarmPareto({left, right});
    out.frontier = static_cast<int>(frontier.size());
    if (out.frontier != 2) {
        err = "FRONTIER";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::StageActivateRollback(Acc09Generation& out, std::string& err)
{
    out = Acc09Generation{};
    SwarmChannel channel;
    channel.name = "native";
    channel.active = "generation-0";
    channel.state = "IDLE";
    std::string stage_err;
    const bool unsigned_stage = SwarmStage(channel, "generation-1", 1, false, stage_err);
    out.unsigned_stage_rejected = !unsigned_stage && stage_err == "STAGE" && channel.state == "IDLE" &&
                                  channel.sequence == 0 && channel.staged.empty() && channel.active == "generation-0";
    if (!out.unsigned_stage_rejected) {
        err = "STAGE";
        return false;
    }

    SwarmCounts counts;
    counts.n01 = 100;
    SwarmBound bound;
    out.qualified_report = QualifyReport(counts, bound, err);
    if (!out.qualified_report || release_qualified() || qualified()) {
        if (err.empty()) err = "QUALIFY";
        return false;
    }
    if (!SwarmStage(channel, "generation-1", 1, true, err)) return false;
    if (channel.state != "STAGED" || channel.staged != "generation-1") {
        err = "STAGE";
        return false;
    }
    if (!SwarmCanary(channel, 2, err)) return false;
    if (!SwarmActivate(channel, 3, err)) return false;
    if (channel.active != "generation-1" || channel.previous != "generation-0" || channel.state != "ACTIVE") {
        err = "ACTIVATE";
        return false;
    }
    if (!SwarmRollback(channel, 4, err)) return false;
    out.active = channel.active;
    out.previous = channel.previous;
    out.rolled_back = channel.active == "generation-0" && channel.previous == "generation-1" && channel.state == "ACTIVE";
    if (!out.rolled_back || release_qualified() || qualified()) {
        err = "ROLLBACK";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::OperateDefensiveCase(const std::string& team_id, const std::string& case_id, const std::string& locator,
                                 Acc09Case& out, std::string& err)
{
    out = Acc09Case{};
    if (team_id.empty() || case_id.empty()) {
        err = "AUTH";
        return false;
    }
    if (!locator.empty()) {
        err = "SERVICE";
        return false;
    }
    GuardTable table;
    GuardPermit permit;
    if (!table.Prepare("contain-case", case_id, 1, 1000000, permit, err)) return false;
    if (!table.Execute(permit.secret, 1000000, out.receipt, err)) return false;
    std::string replay_receipt;
    std::string replay_err;
    out.replay_rejected = !table.Execute(permit.secret, 1000000, replay_receipt, replay_err) &&
                          replay_err == "BTX035_REPLAY" && replay_receipt.empty();
    GuardPermit spend;
    std::string spend_err;
    out.spend_rejected = !table.Prepare("spend", case_id, 1, 1000000, spend, spend_err) &&
                         spend_err == "BTX035_SCOPE_DENIED";
    if (out.receipt.empty() || !out.replay_rejected || !out.spend_rejected) {
        err = "CASE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::RecoverCommitted(Acc09Recovery& out, std::string& err)
{
    out = Acc09Recovery{};
    {
        SwarmDurableLog empty_log;
        std::vector<std::string> empty_ids;
        bool continues = true;
        std::string empty_err;
        const bool read = empty_log.Read("survivor", 1, empty_ids, continues, empty_err);
        out.empty_continues = read && continues;
        if (read || out.empty_continues || empty_err != "EMPTY") {
            err = "EMPTY";
            return false;
        }
    }

    SwarmDurableLog log;
    std::string scratch = "uncommitted-scratch";
    {
        const std::string coordinator_id = "coordinator";
        if (!log.Commit(coordinator_id, 1, "c1", "committed-state", err)) return false;
        if (log.Commit(coordinator_id, 1, "c1", "other-body", err)) {
            err = "CONFLICT";
            return false;
        }
        if (err != "CONFLICT") {
            err = "CONFLICT";
            return false;
        }
        scratch.clear();
    }

    std::vector<std::string> ids;
    bool continues = false;
    if (!log.Read("survivor", 1, ids, continues, err)) return false;
    out.continued = continues;
    out.commitment_id = ids.size() == 1 ? ids[0] : std::string{};
    out.scratch_visible = false;
    for (const std::string& id : ids) {
        if (id == "uncommitted-scratch") out.scratch_visible = true;
    }
    if (!out.continued || out.commitment_id != "c1" || out.scratch_visible || !scratch.empty() || log.Count() != 1) {
        err = "RECOVER";
        return false;
    }
    bool stale_continues = true;
    std::vector<std::string> stale_ids;
    std::string stale_err;
    if (log.Read("survivor", 0, stale_ids, stale_continues, stale_err) || stale_continues || stale_err != "STALE") {
        err = "STALE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::ActivateDefaultLifecycle(const std::string& extra_flags, Acc09Lifecycle& out, std::string& err)
{
    out = Acc09Lifecycle{};
    if (!extra_flags.empty()) {
        err = "FLAG";
        return false;
    }
    SwarmGovernSnapshot snapshot;
    if (!SwarmLoadGoverned(fs::path{}, snapshot, err)) return false;
    out.observer = snapshot.roles.observer;
    out.trainer = snapshot.roles.trainer;
    out.evaluator = snapshot.roles.evaluator;
    out.workers = snapshot.budget.active_workers;
    out.spend = snapshot.roles.automatic_spend_atoms;
    out.code = snapshot.budget.code;
    if (!out.observer || out.trainer || out.evaluator || out.workers != 1 || out.spend != NIFDT_AUTOMATIC_SPEND ||
        out.code != "ADMITTED" || snapshot.device.vram_bytes != 0 || snapshot.budget.vram_bytes != 0 ||
        snapshot.device.cpu_threads != 0) {
        err = "LIFECYCLE";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::SupportCpuWithoutGpu(Acc09CpuPlatform& out, std::string& err)
{
    out = Acc09CpuPlatform{};
    SwarmDevice device;
    device.idle_contribution = true;
    device.slots = 1;
    device.cpu_threads = 2;
    device.vram_bytes = 0;
    device.license_allows_training = true;
    const SwarmRoles roles = SwarmEligibleRoles(device);
    const SwarmBudget budget = SwarmGovern(device, 1);
    out.observer = roles.observer;
    out.evaluator = roles.evaluator;
    out.trainer = roles.trainer;
    out.discovery_needs_public_address = LanDiscoveryRequiresPublicAddress();
    out.lan_observed = EndpointLooksLan(".local");
    out.wan_observed = EndpointLooksLan("remote");
    out.cpu_threads = budget.cpu_threads;
    out.vram_bytes = budget.vram_bytes;
    if (!out.observer || !out.evaluator || out.trainer || out.discovery_needs_public_address || !out.lan_observed ||
        out.wan_observed || out.cpu_threads != 2 || out.vram_bytes != 0 || roles.automatic_spend_atoms != NIFDT_AUTOMATIC_SPEND ||
        budget.code != "ADMITTED") {
        err = "CPU";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::RefuseMissingClaims(Acc09Claims& out, std::string& err)
{
    out = Acc09Claims{};
    SwarmDevice device;
    device.idle_contribution = true;
    device.slots = 1;
    device.cpu_threads = 0;
    device.vram_bytes = 0;
    const SwarmRoles roles = SwarmEligibleRoles(device);
    out.trainer = roles.trainer || roles.evaluator;

    const SwarmEngineStatus engine = SwarmProbeEngine("memory", fs::path{}, err);
    out.engine_present = engine.present;
    out.engine_advertised = engine.advertised || engine.qualified;

    QualReport report;
    const QualResult result = QualifyBytes("missing.bin", Span<const unsigned char>{}, report);
    out.model_verified = result == QualResult::STRUCTURE_VERIFIED || result == QualResult::PROFILE_VERIFIED ||
                         result == QualResult::RUNTIME_OBSERVED;

    out.research_may_spend = ResearchMaySpend();

    GuardTable table;
    std::string receipt;
    std::string auth_err;
    out.unauthorized_executed = table.Execute("absent", 1000000, receipt, auth_err) || !receipt.empty();

    ReachabilityTracker tracker;
    out.host_advertised = tracker.MayAdvertiseHost(true) || !tracker.BestCandidate().empty();
    out.network_known = tracker.State() != ReachabilityState::UNKNOWN;

    if (out.trainer || out.engine_present || out.engine_advertised || out.model_verified || out.research_may_spend ||
        out.unauthorized_executed || out.host_advertised || out.network_known || passed() || gpu_passed() ||
        hardware_qualified() || release_qualified() || windows_passed() || automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = "CLAIM";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::RefuseUnqualified(const std::string& id, std::string& err)
{
    const bool owned = id == "P2P-SCN-B" || id == "P2P-SCN-C" || id == "P2P-SCN-D" || id == "P2P-SCN-E" ||
                       id == "P2P-SCN-F" || id == "P2P-SCN-I" || id == "P2P-SCN-M";
    if (!owned || final_acceptance(id) != "UNQUALIFIED") {
        err = "ID";
        return false;
    }
    if (id == "P2P-SCN-D") {
        std::string host_err;
        if (Hosts(static_cast<int64_t>(3), host_err) || host_err != "HOSTS" || hosts() != static_cast<int64_t>(1)) {
            err = "HOSTS";
            return false;
        }
    }
    if (id == "P2P-SCN-I") {
        std::string gpu_err;
        if (Gpu(gpu_err) || gpu_err != NIFDT_ENGINE_ABSENT || gpu_passed() || gpu()) {
            err = "GPU";
            return false;
        }
    }
    if (id == "P2P-SCN-M") {
        if (ResearchMaySpend() || automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
            err = "SPEND";
            return false;
        }
    }
    if (recorded_peers() != 0 || bytes_moved() != static_cast<int64_t>(0) || hosts() != static_cast<int64_t>(1)) {
        err = "CLAIM";
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc09::NoteNeedsProcess(const std::string& id, Acc09ProcessNote& out, std::string& err)
{
    out = Acc09ProcessNote{};
    if (final_acceptance(id) != "DEFINED_NEEDS_PROCESS") {
        err = "ID";
        return false;
    }
    if (id == "P2P-SCN-G") {
        const SwarmEngineStatus engine = SwarmProbeEngine("memory", fs::path{}, err);
        out.engine_present = engine.present || engine.advertised || engine.qualified;
        out.inference_ran = false;
        out.shared = false;
        out.bytes_moved = false;
        if (out.engine_present || out.inference_ran || passed()) {
            err = "CLAIM";
            return false;
        }
        err = "NEEDS_PROCESS";
        return false;
    }
    if (id == "P2P-SCN-H") {
        SwarmKvShare share;
        share.page_id = "page-a";
        share.same_fingerprint = true;
        share.compatible = true;
        share.want_share = true;
        std::string note_err;
        const SwarmKvShareResult result = SwarmNoteKvShare(share, note_err);
        out.shared = result.shared;
        out.bytes_moved = result.bytes_moved;
        out.kv_code = result.code;
        out.inference_ran = false;
        out.engine_present = false;
        if (out.shared || out.bytes_moved || out.kv_code != "HELD" || bytes_moved() != static_cast<int64_t>(0)) {
            err = "KV";
            return false;
        }
        err = "NEEDS_PROCESS";
        return false;
    }
    if (id == "P2P-SCN-Q") {
        if (LanDiscoveryRequiresPublicAddress() || !EndpointLooksLan(".local")) {
            err = "DISCOVERY";
            return false;
        }
        GuardTable table;
        GuardPermit permit;
        std::string guard_err;
        if (!table.Prepare("review-case", "case-q", 1, 1000000, permit, guard_err)) {
            err = guard_err.empty() ? "GUARD" : guard_err;
            return false;
        }
        std::string receipt;
        if (!table.Execute(permit.secret, 1000000, receipt, guard_err) || receipt.empty()) {
            err = guard_err.empty() ? "GUARD" : guard_err;
            return false;
        }
        const std::vector<SwarmPeer> chosen = SwarmNeighbors({});
        out.discovery_without_cloud = true;
        out.guard_without_cloud = true;
        out.peers_chosen = static_cast<int>(chosen.size());
        out.inference_ran = false;
        out.engine_present = false;
        out.shared = false;
        out.bytes_moved = false;
        if (out.peers_chosen != 0 || out.inference_ran) {
            err = "CLAIM";
            return false;
        }
        err = "NEEDS_PROCESS";
        return false;
    }
    err = "ID";
    return false;
}

bool Acc09::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    Acc09Lifecycle flagged;
    if (ActivateDefaultLifecycle("extra-flag", flagged, err) || err != "FLAG" || flagged.observer || flagged.workers != 0) {
        return false;
    }
    Acc09Lifecycle lifecycle;
    if (!ActivateDefaultLifecycle("", lifecycle, err) || !lifecycle.observer || lifecycle.trainer || lifecycle.spend != NIFDT_AUTOMATIC_SPEND) {
        return false;
    }
    Acc09CpuPlatform cpu;
    if (!SupportCpuWithoutGpu(cpu, err) || cpu.trainer || cpu.discovery_needs_public_address || !cpu.evaluator) {
        return false;
    }
    Acc09Claims claims;
    if (!RefuseMissingClaims(claims, err) || claims.trainer || claims.model_verified || claims.research_may_spend ||
        claims.host_advertised) {
        return false;
    }

    Acc09Community community;
    if (!CreateLocalCommunity("node-a", "family", "", community, err) || !community.local || community.members.size() != 1) {
        return false;
    }
    Acc09Community remote;
    if (CreateLocalCommunity("node-a", "family", "remote-locator", remote, err) || err != "LOCATOR" || !remote.id.empty()) {
        return false;
    }
    if (community_count() != 1) {
        err = "COMMUNITY";
        return false;
    }
    Acc09Community again;
    if (!CreateLocalCommunity("node-a", "family", "", again, err) || again.id != community.id || again.members.size() != 1) {
        return false;
    }
    Acc09Descendants descendants;
    if (!CreateAndEvaluateDescendants(community.id, descendants, err) || descendants.ids.size() != 2 || !descendants.self_rejected ||
        !descendants.quorum || descendants.qualified != 2 || descendants.frontier != 2) {
        return false;
    }
    Acc09Generation generation;
    if (!StageActivateRollback(generation, err) || !generation.rolled_back || generation.active != "generation-0" ||
        release_qualified()) {
        return false;
    }
    Acc09Case hosted;
    if (OperateDefensiveCase("team-a", "case-a", "hosted-service", hosted, err) || err != "SERVICE" || !hosted.receipt.empty()) {
        return false;
    }
    Acc09Case local_case;
    if (!OperateDefensiveCase("team-a", "case-a", "", local_case, err) || local_case.receipt.empty() || !local_case.replay_rejected) {
        return false;
    }
    Acc09Recovery recovery;
    if (!RecoverCommitted(recovery, err) || !recovery.continued || recovery.commitment_id != "c1" || recovery.scratch_visible ||
        recovery.empty_continues) {
        return false;
    }

    const char* unqualified[] = {"P2P-SCN-B", "P2P-SCN-C", "P2P-SCN-D", "P2P-SCN-E", "P2P-SCN-F", "P2P-SCN-I", "P2P-SCN-M"};
    for (const char* id : unqualified) {
        if (RefuseUnqualified(id, err) || err != NIFDT_UNQUALIFIED) return false;
    }
    const char* needs[] = {"P2P-SCN-G", "P2P-SCN-H", "P2P-SCN-Q"};
    for (const char* id : needs) {
        Acc09ProcessNote note;
        if (NoteNeedsProcess(id, note, err) || err != "NEEDS_PROCESS") return false;
        if (id == std::string("P2P-SCN-H") && (note.shared || note.bytes_moved || note.kv_code != "HELD")) return false;
        if (id == std::string("P2P-SCN-G") && (note.inference_ran || note.engine_present)) return false;
        if (id == std::string("P2P-SCN-Q") &&
            (!note.discovery_without_cloud || !note.guard_without_cloud || note.inference_ran || note.peers_chosen != 0)) {
            return false;
        }
    }

    if (passed() || gpu_passed() || windows_passed() || release_qualified() || hardware_qualified() || qualified()) return false;
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1)) return false;
    if (bytes_moved() != static_cast<int64_t>(0) || recorded_peers() != 0) return false;
    if (automatic_spend() != NIFDT_AUTOMATIC_SPEND) return false;
    if (Spend(err) || err != NIFDT_AUTOMATIC_SPEND) return false;
    if (Hosts(static_cast<int64_t>(2), err) || err != "HOSTS" || hosts() != static_cast<int64_t>(1)) return false;
    if (!Hosts(static_cast<int64_t>(1), err) || !err.empty()) return false;
    if (Release(err) || err != NIFDT_UNQUALIFIED || release_qualified()) return false;
    if (Vendor(err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (Gpu(err) || err != NIFDT_ENGINE_ABSENT || gpu()) return false;
    if (final_acceptance("P2P-SCN-A") != "CLOSED_IN_PROCESS") return false;
    if (final_acceptance("P2P-SCN-R") != "CLOSED_IN_PROCESS") return false;
    if (final_acceptance("P2P-SCN-I") != "UNQUALIFIED") return false;
    if (final_acceptance("P2P-SCN-G") != "DEFINED_NEEDS_PROCESS") return false;
    if (native_status("P2P-SCN-A") != "NOT_RUN_NATIVE") return false;

    m_done = true;
    err.clear();
    return true;
}

bool Acc09::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc09::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc09::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc09::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc09::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

std::string Acc09::final_acceptance(const std::string& id) const
{
    if (id == "P2P-SCN-A" || id == "P2P-SCN-J" || id == "P2P-SCN-K" || id == "P2P-SCN-L" || id == "P2P-SCN-N" ||
        id == "P2P-SCN-O" || id == "P2P-SCN-P" || id == "P2P-SCN-R") {
        return "CLOSED_IN_PROCESS";
    }
    if (id == "P2P-SCN-G" || id == "P2P-SCN-H" || id == "P2P-SCN-Q") {
        return "DEFINED_NEEDS_PROCESS";
    }
    if (id == "P2P-SCN-B" || id == "P2P-SCN-C" || id == "P2P-SCN-D" || id == "P2P-SCN-E" || id == "P2P-SCN-F" ||
        id == "P2P-SCN-I" || id == "P2P-SCN-M") {
        return "UNQUALIFIED";
    }
    return {};
}

std::string Acc09::evidence(const std::string& id) const
{
    if (id == "P2P-SCN-A") {
        return "CreateLocalCommunity derives one local community for one node, keeps a single member, and refuses a remote locator.";
    }
    if (id == "P2P-SCN-B") {
        return "Two LAN nodes are absent, so discovery without supplied addresses was not claimed.";
    }
    if (id == "P2P-SCN-C") {
        return "A LAN swarm with no internet path was not present, so continuation was not claimed.";
    }
    if (id == "P2P-SCN-D") {
        return "Joining three nodes would change the host count. hosts() stays 1 and no join was claimed.";
    }
    if (id == "P2P-SCN-E") {
        return "An established swarm and a bootstrap contact were not present, so survival was not claimed.";
    }
    if (id == "P2P-SCN-F") {
        return "Coordination among multiple nodes was not run, and no central scheduler was contacted.";
    }
    if (id == "P2P-SCN-G") {
        return "A supported local model was not executed. No provider key is read. The row stays defined and unrun.";
    }
    if (id == "P2P-SCN-H") {
        return "SwarmNoteKvShare leaves the page unshared and moves no bytes. A real exchange was not run.";
    }
    if (id == "P2P-SCN-I") {
        return "A second GPU is absent. Distributed training was not claimed.";
    }
    if (id == "P2P-SCN-J") {
        return "The local community derives two descendants. SwarmQuorum rejects the author and accepts two evaluators. SwarmQualify scores each report.";
    }
    if (id == "P2P-SCN-K") {
        return "SwarmQualify accepts the report. SwarmStage, SwarmCanary, SwarmActivate, and SwarmRollback restore the previous generation. release_qualified() stays false.";
    }
    if (id == "P2P-SCN-L") {
        return "GuardTable prepares and executes one local case permit. A hosted locator is refused before a permit is issued. A second execute is a replay.";
    }
    if (id == "P2P-SCN-M") {
        return "Isolated regtest settlement was not started. ResearchMaySpend() is false and spend stays 0.";
    }
    if (id == "P2P-SCN-N") {
        return "The coordinator scope ends after SwarmDurableLog::Commit. A survivor Read returns that commitment and drops uncommitted scratch.";
    }
    if (id == "P2P-SCN-O") {
        return "SwarmLoadGoverned on an empty model directory admits the stock lifecycle: observer on, trainer off, spend 0, and no extra flag.";
    }
    if (id == "P2P-SCN-P") {
        return "With no VRAM, SwarmEligibleRoles keeps observer and CPU evaluation and refuses training. LAN discovery does not require a public address.";
    }
    if (id == "P2P-SCN-Q") {
        return "Discovery and a local guard step still run with no cloud provider. Local inference was not executed, so the sentence is not closed.";
    }
    if (id == "P2P-SCN-R") {
        return "Missing hardware, model bytes, funding, authorization, and a network path leave trainer, advertisement, spend, execution, and host advertisement false.";
    }
    return {};
}

std::string Acc09::native_status(const std::string& id) const
{
    if (final_acceptance(id).empty()) return {};
    return "NOT_RUN_NATIVE";
}

} // namespace modelnet
