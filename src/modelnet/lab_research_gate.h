// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_RESEARCH_GATE_H
#define BITCOIN_MODELNET_LAB_RESEARCH_GATE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** ART-001. Immutable dependency identity. An origin URL is only a hint. */
enum class LockSlot {
    SOURCE,
    DATA,
    TOKENIZER,
    BASE_MODEL,
    RUNTIME,
    BUILD,
    EVALUATION,
};

const char* LockSlotName(LockSlot slot);

class DependencyLock {
public:
    void Set(LockSlot slot, std::string content_id, std::string origin_url, bool required);
    std::string ContentId(LockSlot slot) const;
    std::string OriginUrl(LockSlot slot) const;

    /**
     * Walk lookup_order. The first required slot whose content id is missing
     * or not 96 lowercase hex fails BTX035_ARTIFACT and is named in missing_slot.
     * Does not fetch origin_url or any network.
     */
    bool Resolve(const std::vector<LockSlot>& lookup_order, std::string& missing_slot, std::string& err) const;

private:
    struct Entry {
        LockSlot slot{LockSlot::SOURCE};
        std::string content_id;
        std::string origin_url;
        bool required{true};
    };
    const Entry* Find(LockSlot slot) const;
    std::vector<Entry> entries_;
};

/**
 * ART-002. Public redistribution needs a non-empty rights evidence id and
 * operator_policy_allows. Otherwise BTX035_SCOPE_DENIED. private_reproducibility
 * does not grant public redistribution.
 */
bool PublicRedistribution(const std::string& rights_evidence_id, bool operator_policy_allows,
                          bool private_reproducibility, bool& public_allowed, std::string& err);

/** ART-003. Local retention pin. Garbage collection is generation-fenced. */
enum class RetentionRole {
    RELEASE,
    ROLLBACK_TARGET,
    OFFLINE_BUNDLE,
};

class RetentionStore {
public:
    bool Track(const std::string& id, uint64_t generation, std::string& err);
    bool Pin(const std::string& id, RetentionRole role, uint64_t pin_generation, std::string& err);
    std::vector<std::string> CollectGarbage(uint64_t sweep_generation);
    bool Contains(const std::string& id) const;
    bool IsPinned(const std::string& id) const;
    bool PinRole(const std::string& id, RetentionRole& role) const;

private:
    struct Object {
        std::string id;
        uint64_t generation{0};
        bool pinned{false};
        uint64_t pin_generation{0};
        RetentionRole role{RetentionRole::RELEASE};
    };
    Object* Find(const std::string& id);
    const Object* Find(const std::string& id) const;
    std::vector<Object> objects_;
};

/**
 * VER-001. Writes stay under output_root. Absolute paths and ".." fail
 * BTX035_PATH_UNSAFE. Read-only input ids cannot be write targets.
 * Resume without a committed checkpoint id reports NOT_RESUMABLE.
 */
class TrainingAdapter {
public:
    explicit TrainingAdapter(std::string output_root);

    bool AddReadOnlyInput(const std::string& content_id, std::string& err);
    bool InputIsReadOnly(const std::string& content_id) const;
    const std::vector<std::string>& ReadOnlyInputs() const { return inputs_; }

    bool Write(const std::string& path, const std::string& bytes, std::string& err);
    /** 96 lowercase hex SHA-384 of the bytes accepted by Write, in order. */
    std::string ResultManifestId() const;

    bool CommitCheckpoint(const std::string& checkpoint_id, std::string& err);
    bool Resume(const std::string& checkpoint_id, std::string& err);
    const std::string& Status() const { return status_; }

private:
    bool TargetsInput(const std::string& path) const;

    std::string root_;
    std::vector<std::string> inputs_;
    std::string written_;
    std::vector<std::string> checkpoints_;
    std::string status_;
};

/**
 * VER-004. Freeze the evaluation contract before Compare. Development ids and
 * holdout ids must be disjoint. A negative result stays queryable after a
 * positive summary is stored.
 */
class EvaluationGate {
public:
    bool FreezeEvaluation(const std::string& contract_id, std::string& err);
    const std::string& FrozenContract() const { return frozen_; }

    bool SetDevelopmentHoldout(const std::vector<std::string>& development_ids,
                               const std::vector<std::string>& holdout_ids, std::string& err);
    const std::vector<std::string>& DevelopmentIds() const { return development_; }
    const std::vector<std::string>& HoldoutIds() const { return holdout_; }

    bool Compare(const std::string& candidate_evaluator_id, std::string& err) const;

    void AddResult(const std::string& run_id, bool negative);
    void StorePositiveSummary(const std::string& summary);
    bool ResultQueryable(const std::string& run_id) const;
    bool NegativeResultQueryable(const std::string& run_id) const;
    const std::string& Summary() const { return summary_; }

private:
    std::string frozen_;
    std::vector<std::string> development_;
    std::vector<std::string> holdout_;
    std::vector<std::string> result_ids_;
    std::vector<std::string> negative_ids_;
    std::string summary_;
};

/** RSI-001. Relation kind is not authority. */
enum class RelationKind {
    PRODUCED_BY,
    ENDORSED_BY,
    ADOPTED_BY,
};

enum class SignerRole {
    PRODUCER,
    ENDORSER,
    ADOPTER,
};

const char* RelationKindName(RelationKind kind);

/** Succeeds only for ADOPTED_BY signed by ADOPTER. Otherwise BTX035_SCOPE_DENIED. */
bool PublishAdoptionReceipt(RelationKind kind, SignerRole signer, std::string& err);

struct ResearchPrincipal {
    std::string research_key;
    std::string wallet;
    bool maintainer{false};
};

/** A fork does not receive the parent's research key, wallet, or maintainer bit. */
ResearchPrincipal ForkPrincipal(const ResearchPrincipal& parent);

/**
 * RSI-002. Order is closure, staged generation, regression, then the active
 * pointer. Skipping regression fails BTX035_REGRESSION and does not swap.
 * The previous generation stays readable.
 */
class LocalAdoption {
public:
    explicit LocalAdoption(std::string previous_generation);

    bool Adopt(bool closure_verified, bool generation_staged, bool regression_ok,
               const std::string& next_generation, std::string& err);
    const std::string& Active() const { return active_; }
    bool Readable(const std::string& generation) const;

private:
    std::string active_;
    std::vector<std::string> readable_;
};

/**
 * RSI-003. Qualification needs generation N research, an admitted N+1 adopted
 * by a different runtime, and an N+2 candidate produced by N+1.
 * A model-file id alone fails BTX035_LINEAGE.
 */
struct LineageClaim {
    std::string generation_n_research_id;
    std::string generation_n1_id;
    bool generation_n1_admitted{false};
    std::string adopted_by_runtime_id;
    std::string producer_runtime_id;
    std::string generation_n2_candidate_id;
    std::string model_file_id;
};

bool QualifyLineage(const LineageClaim& claim, std::string& err);

/**
 * INC-001. A valid signature records the reporter, not the truth of the report.
 * Quarantine is a separate local policy call.
 */
struct IncidentReport {
    std::vector<std::string> affected_ids;
    std::string severity;
    std::string confidence;
    std::vector<std::string> evidence_ids;
    std::string scope;
    bool signature_valid{false};
    bool truth{false};
};

class IncidentStore {
public:
    bool File(IncidentReport& report, std::string& err);
    bool Lookup(const std::string& affected_id, IncidentReport& out, std::string& err) const;
    bool Quarantine(const std::string& id, std::string& err);
    bool IsQuarantined(const std::string& id) const;

private:
    std::vector<IncidentReport> reports_;
    std::vector<std::string> quarantined_;
};

/** INC-002. Operational runbook. Unknown names fail BTX035_NOT_FOUND. */
struct RunbookPlan {
    std::string detection;
    std::string containment;
    std::string recovery;
};

bool Runbook(const std::string& name, RunbookPlan& plan, std::string& err);

/**
 * REV-005. Shipped PUBLIC_STRICT template: full replay required, no verifier
 * authority, unpinned. PinVerifier records a local owner pin only.
 */
struct StrictTemplate {
    bool full_replay_required{false};
    std::vector<std::string> verifier_ids;
    bool pinned{false};
};

StrictTemplate PublicStrictTemplate();

class LocalVerifierPins {
public:
    bool PinVerifier(const std::string& verifier_id, std::string& err);
    bool IsPinned(const std::string& verifier_id) const;
    StrictTemplate Template() const;

private:
    std::vector<std::string> pins_;
};

/**
 * REV-009. Closed action set: source.snapshot, git.ref_update, research.run,
 * model.activate, research.publish. Any other name, including realm.promote
 * and runtime.pause, fails BTX035_ACTION. parameters_ref must be 96 lowercase hex.
 */
bool AcceptActionIntent(const std::string& action, const std::string& parameters_ref, std::string& err);

/**
 * REV-010. A workflow name is not a training profile. The profile commits to
 * serialization, kernel, init, data order, checkpoint, and runtime.
 */
bool NamedWorkflowIsProfile(const std::string& workflow_name);

struct TrainingProfile {
    std::string serialization;
    std::string kernel;
    std::string init;
    std::string data_order;
    std::string checkpoint;
    std::string runtime;
};

bool AcceptTrainingProfile(const TrainingProfile& profile, std::string& err);

/**
 * REV-011. PUBLIC_STRICT and REALM_STRICT require full replay.
 * PRIVATE_OWNER_APPROVED is not a mode and fails BTX035_SCOPE_DENIED.
 */
bool FullReplayRequired(const std::string& mode, std::string& err);

/**
 * REV-015. Bound comparison. A summary score does not drop a negative run id.
 * Incomplete bindings fail BTX035_EVAL.
 */
struct ComparisonResult {
    std::string baseline;
    std::string candidate;
    std::string spec;
    std::vector<std::string> paired_run_ids;
    std::vector<std::string> negative_run_ids;
    std::string direction;
    uint64_t trials{0};
    uint64_t holdout_epoch{0};
    std::string procedure;
    std::string summary_score;

    void AddPairedRun(const std::string& id, bool negative);
    void SetSummaryScore(const std::string& score);
    bool HasNegativeRun(const std::string& id) const;
    bool Bind(std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_RESEARCH_GATE_H
