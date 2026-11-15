// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC07_ACC07_H
#define BITCOIN_MODELNET_ACC07_ACC07_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_defbudget/swarm_defbudget.h>
#include <modelnet/swarm_payreg/swarm_payreg.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** One milestone weight. cap is that contract's award ceiling. */
struct Acc07Weight {
    std::string contract;
    int64_t weight{0};
    int64_t cap{0};
};

/**
 * Exact payment-mode disclosure.
 * enforceable and spendable stay false. oracle_trust names the trust
 * that remains; it is not a settlement proof.
 */
struct Acc07Disclosure {
    std::string mode;
    bool enforceable{false};
    std::string oracle_trust;
    bool spendable{false};
};

/**
 * Acc07. In-process enforcement for DS-MODEL-001 through DS-MODEL-006,
 * DS-LEARN-001 through DS-LEARN-006, DS-POOL-001 through DS-POOL-006,
 * and DS-PAY-001 through DS-PAY-006.
 *
 * Tenant KV, public-context reuse, checkpoint closure, generation pin,
 * placement order, capability withdrawal, holdout partitions, provenance,
 * joint utility and harm, competing descendants, separated budgets,
 * unique collateral, atom reconciliation, work-or-readiness pay,
 * milestone rounding, abuse refusal, payment disclosure, credit versus
 * backing, prefunded emergency cover, and earned-claim retention are
 * decided by the methods below.
 *
 * IssueLearningRelease, QualifyNativeFunding, and ProvePaymentPaths
 * return NIFDT_UNQUALIFIED. SecondResearchCycle calls
 * SwarmGenerationEngine::Continue and does not execute a second cycle.
 * passed(), gpu_passed(), windows_passed(), qualified(),
 * release_qualified(), and hardware_qualified() stay false.
 * hosts() and physical_hosts() stay 1. automatic_spend() stays
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * This class opens no file, socket, or process.
 */
class Acc07 {
public:
    bool PutIncidentKv(const std::string& tenant, int64_t epoch, const std::string& key, const std::string& value,
                       bool authorized, std::string& err);
    bool ReadIncidentKv(const std::string& tenant, int64_t epoch, const std::string& caller, const std::string& key,
                        std::string& value, std::string& err);

    bool ApprovePublic(const std::string& id, const std::string& author, const std::string& approver,
                       const std::string& body, const std::string& origin_case, std::string& err);
    bool ReusePublic(const std::string& id, const std::string& dest_case, std::string& err);

    bool MeasureCache(const std::vector<unsigned char>& src, std::vector<unsigned char>& dst, int64_t& measured,
                      std::string& err);
    bool CompleteCheckpoint(const std::vector<unsigned char>& weights, const std::vector<unsigned char>& adam_m,
                            const std::vector<unsigned char>& adam_v, std::string& err);

    bool OpenIncident(const std::string& incident, const std::string& generation, std::string& err);
    bool SwapGeneration(const std::string& incident, const std::string& generation, std::string& err);
    bool CloseIncident(const std::string& incident, std::string& err);

    bool RestrictPlacement(const std::string& location, const std::string& processor, std::string& err);
    bool Place(const std::string& location, const std::string& processor, std::string& err);

    bool GrantCapability(std::string& err);
    bool PoisonCache(const std::string& sample, std::string& err);
    bool FailRuntimeQualification(std::string& err);
    bool UseCapability(std::string& err);

    bool IssueLearningRelease(std::string& err);
    bool AssignHoldout(const std::string& sample, const std::string& axis, const std::string& lineage, std::string& err);
    bool PreserveCase(const std::string& kind, const std::string& provenance, const std::string& license, std::string& err);
    bool JointDecision(bool utility_ok, bool harm_ok, bool refusal_only, std::string& err);
    bool TrainCompeting(std::string& err);
    bool EvaluateDescendant(const std::string& evaluator, bool author_is_evaluator, std::string& err);
    bool SecondResearchCycle(std::string& err);

    bool FundPool(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err);
    bool JoinPool(const std::string& pool, const std::string& member, std::string& err);
    bool EarnWork(const std::string& pool, const std::string& work_id, const std::string& receipt, const std::string& member,
                  int64_t atoms, std::string& err);
    bool PayMilestone(const std::string& pool, const std::string& work_id, int64_t requested, int64_t cap, std::string& err);
    bool SetPayer(const std::string& payer, std::string& err);
    bool SelfDeal(const std::string& member, std::string& err);
    bool RaiseForUrgent(const std::string& pool, std::string& err);
    bool ReconcileAtoms(int64_t confirmed, int64_t fee, int64_t settled, int64_t earned_unpaid, int64_t reserved_new,
                        std::string& err);
    bool AllocateMilestones(int64_t pool, const std::vector<Acc07Weight>& rows, std::vector<int64_t>& paid,
                            int64_t& unallocated, std::string& err);

    bool DisclosePayment(Acc07Disclosure& out, std::string& err);
    bool QualifyNativeFunding(std::string& err);
    bool ProvePaymentPaths(std::string& err);
    bool ReserveBacking(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err);
    bool NoteCredit(const std::string& pool, int64_t atoms, std::string& err);
    bool RouteTerms(const std::string& route, int64_t atoms, int64_t timeout, std::string& err);
    bool PromiseEmergency(int64_t atoms, std::string& err);
    bool NotePending(const std::string& work_id, std::string& err);
    bool KeepClaim(const std::string& work_id, std::string& err);
    void FailCompute();
    bool Reorganize(std::string& err);

    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    std::string generation_of(const std::string& incident) const;
    bool incident_active(const std::string& incident) const;
    bool holdouts_separated() const;
    std::string provenance_of(const std::string& kind) const;
    std::string license_of(const std::string& kind) const;
    bool joint_accepted() const { return m_joint; }
    const std::string& parent_hash() const { return m_parent_hash; }
    const std::string& left_hash() const { return m_left_hash; }
    const std::string& right_hash() const { return m_right_hash; }
    int research_cycle() const { return m_cycle; }
    int64_t pool_balance(const std::string& pool) const;
    bool member_of(const std::string& pool, const std::string& member) const;
    bool earned(const std::string& work_id) const;
    int64_t earned_atoms(const std::string& pool) const;
    int64_t earned_count() const;
    int64_t available() const { return m_available; }
    int64_t funded_backing(const std::string& pool) const;
    int64_t credit_note(const std::string& pool) const;
    int64_t route_atoms(const std::string& route) const;
    int64_t emergency_atoms() const { return m_emergency; }
    bool pending(const std::string& work_id) const;
    bool claim_kept(const std::string& work_id) const;
    bool compute_failed() const;
    int64_t transfer_measured() const { return m_measured; }
    const std::vector<unsigned char>& checkpoint_weights() const { return m_checkpoint; }
    bool checkpoint_exact() const { return m_checkpoint_exact; }
    bool capability_granted() const { return m_capability && !m_withdrawn; }
    std::string classification() const;

    // Journal caller from Jrn07. Separate from the DS/1 pass.
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);
    bool stored(const std::string& id) const;
    std::string text(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct KvRow {
        std::string tenant;
        int64_t epoch{0};
        std::string key;
        std::string value;
    };
    struct CtxRow {
        std::string id;
        std::string author;
        std::string approver;
        std::string body;
        std::string origin;
    };
    struct PinRow {
        std::string generation;
        bool active{false};
    };
    struct CaseRow {
        std::string kind;
        std::string provenance;
        std::string license;
    };

    bool EnsurePay(std::string& err);
    const KvRow* FindKv(const std::string& tenant, const std::string& key) const;

    std::vector<KvRow> m_kv;
    std::vector<CtxRow> m_ctx;
    std::map<std::string, PinRow> m_pins;
    std::string m_location;
    std::string m_processor;
    bool m_restricted{false};
    bool m_capability{false};
    bool m_withdrawn{false};
    std::map<std::string, std::string> m_sample_axis;
    std::map<std::string, std::string> m_lineage_axis;
    int m_axis_time{0};
    int m_axis_campaign{0};
    int m_axis_tenant{0};
    int m_axis_lineage{0};
    std::vector<CaseRow> m_cases;
    bool m_joint{false};
    std::string m_parent_hash;
    std::string m_left_hash;
    std::string m_right_hash;
    int m_cycle{0};
    SwarmDefBudget m_budget;
    SwarmPayReg m_pay;
    bool m_pay_open{false};
    int64_t m_available{0};
    int64_t m_emergency{0};
    int64_t m_measured{0};
    std::vector<unsigned char> m_checkpoint;
    bool m_checkpoint_exact{false};
    std::set<std::string> m_pending;
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif
