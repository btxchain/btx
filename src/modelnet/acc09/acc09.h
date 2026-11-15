// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC09_ACC09_H
#define BITCOIN_MODELNET_ACC09_ACC09_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** One locally created community. Membership is the record, not a boolean. */
struct Acc09Community {
    std::string id;
    std::string creator;
    std::string name;
    bool local{false};
    std::vector<std::string> members;
    std::vector<std::string> descendants;
};

/** Independent evaluation of descendants created from one local community. */
struct Acc09Descendants {
    std::vector<std::string> ids;
    bool self_rejected{false};
    bool single_rejected{false};
    bool quorum{false};
    int qualified{0};
    int frontier{0};
};

/** Native generation channel after stage, canary, activate, and rollback. */
struct Acc09Generation {
    bool unsigned_stage_rejected{false};
    bool qualified_report{false};
    bool rolled_back{false};
    std::string active;
    std::string previous;
};

/** One local defensive case. A non-empty locator is a hosted service. */
struct Acc09Case {
    std::string receipt;
    bool replay_rejected{false};
    bool spend_rejected{false};
};

/** Survivor read of a commitment after the coordinator scope has ended. */
struct Acc09Recovery {
    std::string commitment_id;
    bool continued{false};
    bool scratch_visible{false};
    bool empty_continues{true};
};

/** Stock lifecycle from an empty model directory and no extra flag. */
struct Acc09Lifecycle {
    bool observer{false};
    bool trainer{false};
    bool evaluator{false};
    int workers{0};
    std::string spend;
    std::string code;
};

/** Observer, discovery, and CPU eligibility with no VRAM. */
struct Acc09CpuPlatform {
    bool observer{false};
    bool evaluator{false};
    bool trainer{false};
    bool discovery_needs_public_address{true};
    bool lan_observed{false};
    bool wan_observed{true};
    int cpu_threads{0};
    int64_t vram_bytes{-1};
};

/** Claims inspected while hardware, bytes, funding, authority, or a path is absent. */
struct Acc09Claims {
    bool trainer{true};
    bool engine_present{true};
    bool engine_advertised{true};
    bool model_verified{true};
    bool research_may_spend{true};
    bool unauthorized_executed{true};
    bool host_advertised{true};
    bool network_known{true};
};

/**
 * Observation for a sentence that still needs a process.
 * Defaults are the claimed side, so a missed call stays visible.
 */
struct Acc09ProcessNote {
    bool shared{true};
    bool bytes_moved{true};
    bool inference_ran{true};
    bool engine_present{true};
    bool discovery_without_cloud{false};
    bool guard_without_cloud{false};
    int peers_chosen{-1};
    std::string kv_code;
};

/**
 * Acc09. P2P-SCN-A through P2P-SCN-R.
 *
 * CreateLocalCommunity builds one local community for one node.
 * CreateAndEvaluateDescendants derives two descendants and calls
 * SwarmQuorum, SwarmQualify, and SwarmPareto.
 * StageActivateRollback calls SwarmQualify, then SwarmStage,
 * SwarmCanary, SwarmActivate, and SwarmRollback.
 * OperateDefensiveCase calls GuardTable. A locator is refused first.
 * RecoverCommitted commits through SwarmDurableLog, ends the
 * coordinator scope, and reads as a survivor.
 * ActivateDefaultLifecycle calls SwarmLoadGoverned on an empty
 * directory. A non-empty extra flag is refused.
 * SupportCpuWithoutGpu calls SwarmEligibleRoles, SwarmGovern, and
 * the LAN discovery predicates with no VRAM.
 * RefuseMissingClaims calls SwarmEligibleRoles, SwarmProbeEngine,
 * QualifyBytes, ResearchMaySpend, GuardTable::Execute, and
 * ReachabilityTracker.
 *
 * RefuseUnqualified covers B, C, D, E, F, I, and M. Those sentences
 * need another host, a second GPU, or isolated regtest settlement.
 * NoteNeedsProcess covers G, H, and Q. G and the inference half of Q
 * are not executed. H calls SwarmNoteKvShare, which does not share.
 *
 * Pass runs each of those calls once and latches. A later Pass returns
 * true and does not call them again.
 * hosts() stays 1. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 * passed(), gpu_passed(), windows_passed(), release_qualified(), and
 * hardware_qualified() stay false. qualified() stays false.
 * Spend returns NIFDT_AUTOMATIC_SPEND. Release returns NIFDT_UNQUALIFIED.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * bytes_moved() stays 0. recorded_peers() stays 0.
 */
class Acc09 {
public:
    bool Pass(std::string& err);
    bool CreateLocalCommunity(const std::string& node_id, const std::string& name, const std::string& locator,
                              Acc09Community& out, std::string& err);
    bool CreateAndEvaluateDescendants(const std::string& community_id, Acc09Descendants& out, std::string& err);
    bool StageActivateRollback(Acc09Generation& out, std::string& err);
    bool OperateDefensiveCase(const std::string& team_id, const std::string& case_id, const std::string& locator,
                              Acc09Case& out, std::string& err);
    bool RecoverCommitted(Acc09Recovery& out, std::string& err);
    bool ActivateDefaultLifecycle(const std::string& extra_flags, Acc09Lifecycle& out, std::string& err);
    bool SupportCpuWithoutGpu(Acc09CpuPlatform& out, std::string& err);
    bool RefuseMissingClaims(Acc09Claims& out, std::string& err);
    bool RefuseUnqualified(const std::string& id, std::string& err);
    bool NoteNeedsProcess(const std::string& id, Acc09ProcessNote& out, std::string& err);

    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    std::string final_acceptance(const std::string& id) const;
    std::string evidence(const std::string& id) const;
    std::string native_status(const std::string& id) const;
    int community_count() const { return static_cast<int>(m_communities.size()); }
    int recorded_peers() const { return 0; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    Acc09Community* Find(const std::string& id);
    std::vector<Acc09Community> m_communities;
    bool m_done{false};
};

} // namespace modelnet

#endif
