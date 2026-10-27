// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC06_ACC06_H
#define BITCOIN_MODELNET_ACC06_ACC06_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_defense/swarm_defense.h>
#include <modelnet/swarm_defwork/swarm_defwork.h>
#include <modelnet/swarm_planner/swarm_planner.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Acceptance 06 for DS-PLAN-001 through DS-STD-006.
 *
 * Hypotheses, dependencies, retracted evidence, independent dispatch, and
 * dependent invalidation go through SwarmPlanner. D0-D4 effects, present
 * human approval, exact asset and blast checks, idempotent receipts,
 * unknown effects, canary rollback, and out-of-scope retaliation go
 * through SwarmDefWork. Embargo, sanitization, cross-case search, and
 * training consent go through SwarmDefense.
 *
 * Workload signals, plan bounds, backpressure, local procedures, TLP 2.0
 * recipient and purpose checks, versioned retractions, STIX external-id
 * mapping, collection paging, raw-event lineage, per-backend rule checks,
 * event parsing, and the typed import subset are enforced here.
 *
 * passed(), gpu_passed(), windows_passed(), qualified(),
 * release_qualified(), and hardware_qualified() stay false. hosts() stays
 * 1. Spend returns NIFDT_AUTOMATIC_SPEND. This class opens no file,
 * socket, or process.
 */
class Acc06 {
public:
    static constexpr int64_t kPlanBound = 8;
    static constexpr int64_t kSyncLimit = 100;
    static constexpr std::size_t kEveMax = 1024;

    Acc06();

    bool AdmitWork(const std::string& id, std::string& err);
    bool AdmitEvidence(const std::string& id, std::string& err);
    bool Depend(const std::string& before, const std::string& after, std::string& err);
    bool Dispatch(const std::string& id, std::string& err) const;
    bool Finish(const std::string& id, std::string& err);
    bool RetractEvidence(const std::string& id, std::string& err);

    bool hypothesis_persisted(const std::string& id) const;
    bool evidence_persisted(const std::string& id) const;
    bool evidence_retracted(const std::string& id) const;
    int64_t plan_history() const;

    bool DefineSignal(const std::string& workload, const std::string& signal, std::string& err);
    bool RecordSignal(const std::string& workload, const std::string& signal, int64_t amount, std::string& err);
    int64_t progress_of(const std::string& workload) const;
    std::string signal_of(const std::string& workload) const;

    bool AdmitPlan(const std::string& plan_id, int64_t cost, std::string& err);
    bool SetBackpressure(bool saturated, std::string& err);
    bool plan_held(const std::string& plan_id) const;
    int64_t committed_plan_cost() const;
    bool saturated() const;

    bool KeepProcedure(const std::string& id, const std::string& body, std::string& err);
    bool ReplaceProcedure(const std::string& id, const std::string& body, std::string& err);
    bool LoseQuorum(std::string& err);
    bool LoseRuntime(std::string& err);
    std::string procedure_of(const std::string& id) const;
    bool quorum_present() const;
    bool runtime_present() const;

    bool ProposeEffect(const std::string& case_id, const std::string& action_id, const std::string& level,
                       const std::string& asset, int64_t blast, std::string& err);
    bool ApprovePresent(const std::string& case_id, const std::string& action_id, bool human, std::string& err);
    bool ExecuteExact(const std::string& case_id, const std::string& action_id, const std::string& asset,
                      int64_t blast, std::string& err);
    bool ReconcileUnknown(const std::string& action_id, std::string& err);
    bool CheckCanary(const std::string& action_id, bool canary_ok, std::string& err);
    bool RefuseRetaliation(const std::string& target, std::string& err);

    bool proposed(const std::string& action_id) const;
    bool approved(const std::string& action_id) const;
    bool has_receipt(const std::string& action_id) const;
    int64_t receipt_count() const;
    bool rolled_back(const std::string& action_id) const;
    bool ambiguous(const std::string& action_id) const;
    std::string asset_of(const std::string& action_id) const;
    int64_t blast_of(const std::string& action_id) const;

    bool OpenCase(const std::string& customer, const std::string& case_id, const std::string& asset,
                  const std::string& policy_gen, int64_t until_ms, int64_t now_ms, std::string& err);
    bool KeepEvidence(const std::string& case_id, const std::string& evidence_id,
                      const std::vector<unsigned char>& bytes, std::string& err);
    bool PublishShare(const std::string& case_id, const std::string& artifact_id, bool embargo_expired,
                      bool sanitized, bool validated, std::string& err);
    bool SearchEvidence(const std::string& case_id, const std::string& evidence_id, std::string& err);
    bool GrantTraining(const std::string& case_id, std::string& err);
    bool published(const std::string& artifact_id) const;
    bool training_allowed(const std::string& case_id) const;
    const std::vector<unsigned char>& evidence_body(const std::string& evidence_id) const;

    bool AuthorizeShare(const std::string& originator, const std::string& recipient, const std::string& purpose,
                        const std::string& marking, const std::vector<std::string>& allowed,
                        const std::string& stated_purpose, const std::string& originator_org,
                        const std::string& recipient_org, bool public_release, std::string& err);
    bool share_authorized(const std::string& originator, const std::string& recipient, const std::string& purpose,
                          const std::string& marking) const;
    int64_t share_count() const;

    bool PutArtifact(const std::string& id, const std::string& body, std::string& err);
    bool DisseminateRetraction(const std::string& id, int64_t version, const std::string& reason, std::string& err);
    std::string artifact_body(const std::string& id) const;
    int64_t artifact_version(const std::string& id) const;
    bool artifact_retracted(const std::string& id) const;
    int64_t retraction_notices() const;

    bool MapExternalId(const std::string& object_id, const std::string& version, const std::string& source,
                       const std::string& external_id, std::string& err);
    std::string object_for_external(const std::string& source, const std::string& external_id) const;
    std::string stix_version(const std::string& object_id) const;

    bool OpenCollection(const std::string& id, bool can_read, bool can_write, std::string& err);
    bool AddToCollection(const std::string& id, const std::string& object_id, std::string& err);
    bool SyncCollection(const std::string& id, int64_t limit, std::vector<std::string>& page, bool& more,
                        std::string& err);
    int64_t collection_size(const std::string& id) const;

    bool PreserveOcsf(const std::string& event_id, const std::string& mapping_version, const std::string& raw,
                      std::string& err);
    std::string ocsf_raw(const std::string& event_id) const;
    bool ocsf_has_version(const std::string& event_id, const std::string& mapping_version) const;

    bool ValidateRule(const std::string& rule_id, const std::string& detection, std::string& err);
    bool rule_validated(const std::string& rule_id) const;
    int64_t advertised_backends() const;
    bool AdvertiseBackend(const std::string& name, std::string& err);

    bool ParseEve(const std::string& event_id, const std::string& body, std::string& err);
    std::string eve_body(const std::string& event_id) const;

    bool ImportTyped(const std::string& command_type, std::string& err);
    bool cacao_imported(const std::string& command_type) const;

    bool Release(std::string& err) const;
    bool Spend(std::string& err) const;

    bool passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);

private:
    struct SignalDef {
        std::string signal;
        int64_t progress{0};
    };
    struct PlanRow {
        int64_t cost{0};
    };
    struct Procedure {
        std::string body;
    };
    struct ShareAuth {
        std::string originator;
        std::string recipient;
        std::string purpose;
        std::string marking;
    };
    struct Artifact {
        std::string body;
        int64_t version{1};
        bool retracted{false};
    };
    struct Notice {
        std::string id;
        int64_t version{0};
        std::string reason;
    };
    struct StixRow {
        std::string object_id;
        std::string version;
        std::string source;
        std::string external_id;
    };
    struct Collection {
        bool can_read{false};
        bool can_write{false};
        std::vector<std::string> objects;
        std::size_t cursor{0};
    };
    struct OcsfRow {
        std::string raw;
        std::vector<std::string> versions;
    };
    struct Backend {
        std::string name;
        std::string token;
    };
    struct EveRow {
        std::string body;
    };

    SwarmPlanner m_planner;
    SwarmDefWork m_work;
    SwarmDefense m_defense;
    std::map<std::string, SignalDef> m_signals;
    std::map<std::string, PlanRow> m_plans;
    int64_t m_plan_cost{0};
    bool m_saturated{false};
    std::map<std::string, Procedure> m_procedures;
    bool m_quorum{true};
    bool m_runtime{true};
    std::vector<ShareAuth> m_shares;
    std::map<std::string, Artifact> m_artifacts;
    std::vector<Notice> m_notices;
    std::vector<StixRow> m_stix;
    std::map<std::string, Collection> m_collections;
    std::map<std::string, OcsfRow> m_ocsf;
    std::vector<Backend> m_backends;
    std::set<std::string> m_rules;
    std::map<std::string, EveRow> m_eve;
    std::set<std::string> m_cacao;
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif
