// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_research_gate.h>

#include <crypto/sha384.h>
#include <modelnet/types.h>

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

bool IsContentId(std::string_view hex)
{
    if (hex.size() != 96) return false;
    for (unsigned char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

std::string Sha384Hex(const std::string& bytes)
{
    CSHA384 hasher;
    if (!bytes.empty()) {
        hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    }
    Digest48 digest;
    hasher.Finalize(digest.data.data());
    return digest.Hex();
}

bool PathEscapes(const std::string& path)
{
    if (path.empty() || path.find('\0') != std::string::npos) return true;
    if (path[0] == '/' || path[0] == '\\') return true;
    if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':') return true;
    std::string segment;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == '/' || path[i] == '\\') {
            if (segment == "..") return true;
            segment.clear();
        } else {
            segment.push_back(path[i]);
        }
    }
    return false;
}

bool SegmentEquals(const std::string& path, const std::string& id)
{
    if (path == id) return true;
    std::string segment;
    for (size_t i = 0; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == '/' || path[i] == '\\') {
            if (segment == id) return true;
            segment.clear();
        } else {
            segment.push_back(path[i]);
        }
    }
    return false;
}

bool IncidentFieldsPresent(const IncidentReport& report)
{
    if (report.affected_ids.empty() || report.severity.empty() || report.confidence.empty() || report.scope.empty()) {
        return false;
    }
    for (const std::string& id : report.affected_ids) {
        if (id.empty()) return false;
    }
    for (const std::string& id : report.evidence_ids) {
        if (id.empty()) return false;
    }
    return true;
}

struct RunbookEntry {
    const char* name;
    const char* detection;
    const char* containment;
    const char* recovery;
};

const RunbookEntry RUNBOOKS[] = {
    {"key_compromise",
     "Unexpected use of a research signing key outside its recorded grant.",
     "Revoke that key and refuse new signatures from it.",
     "Install a successor key through the existing recovery threshold and re-evaluate the exposure window."},
    {"leaked_data",
     "Private source or dataset bytes appearing in a public cache or advertisement.",
     "Withdraw the public advertisement and keep the leaked bytes as evidence.",
     "Serve the material again only inside the private realm to authorized auditors."},
    {"malicious_weights",
     "Weight behavior that diverges from the frozen evaluation contract.",
     "Quarantine the weight content id and block new activations of it.",
     "Activate the last pinned release after an independent reproduction of the failure."},
    {"attestor_disagreement",
     "Two attestors publishing conflicting statements for one transition.",
     "Leave admission pending and retain both conflicting statements.",
     "Accept a later decision only after a fresh independent replay."},
    {"stale_policy",
     "An activation attempt bound to a policy epoch that is no longer current.",
     "Deny new activations that still name the expired policy.",
     "Pin the owner's current policy and evaluate the closure again."},
    {"corrupt_journal",
     "A journal page whose stored bytes do not match its recorded digest.",
     "Stop further appends and preserve the corrupt page unchanged.",
     "Rebuild from the last intact checkpoint while keeping the corrupt page as evidence."},
    {"disconnected_wan",
     "Loss of realm connectivity during transfer or rollout.",
     "Stay on the last admitted generation and do not fetch replacement bytes.",
     "Continue from retained local replicas once connectivity is back."},
    {"partial_rollout",
     "Only part of the frozen device ring has reached the new generation.",
     "Pause new permits and keep the previous generation readable.",
     "Complete or reverse the ring under the frozen health specification."},
    {"unknown_effect",
     "An action whose receipt was lost or whose effect remains unknown.",
     "Do not replay the uncertain effect and keep the original intent.",
     "Close the action from an external observation or an owner compensating step."},
    {"guard_failure",
     "The guard cannot enforce the active grant or stops answering.",
     "Pause protected actions and retain the guard failure record.",
     "Resume only after the owner restores a reviewed guard build."},
};

static_assert(sizeof(RUNBOOKS) / sizeof(RUNBOOKS[0]) == 10, "ten incident runbooks");

} // namespace

const char* LockSlotName(LockSlot slot)
{
    switch (slot) {
    case LockSlot::SOURCE: return "source";
    case LockSlot::DATA: return "data";
    case LockSlot::TOKENIZER: return "tokenizer";
    case LockSlot::BASE_MODEL: return "base_model";
    case LockSlot::RUNTIME: return "runtime";
    case LockSlot::BUILD: return "build";
    case LockSlot::EVALUATION: return "evaluation";
    }
    return "";
}

const DependencyLock::Entry* DependencyLock::Find(LockSlot slot) const
{
    for (const Entry& entry : entries_) {
        if (entry.slot == slot) return &entry;
    }
    return nullptr;
}

void DependencyLock::Set(LockSlot slot, std::string content_id, std::string origin_url, bool required)
{
    for (Entry& entry : entries_) {
        if (entry.slot != slot) continue;
        entry.content_id = std::move(content_id);
        entry.origin_url = std::move(origin_url);
        entry.required = required;
        return;
    }
    entries_.push_back(Entry{slot, std::move(content_id), std::move(origin_url), required});
}

std::string DependencyLock::ContentId(LockSlot slot) const
{
    const Entry* entry = Find(slot);
    return entry == nullptr ? std::string() : entry->content_id;
}

std::string DependencyLock::OriginUrl(LockSlot slot) const
{
    const Entry* entry = Find(slot);
    return entry == nullptr ? std::string() : entry->origin_url;
}

bool DependencyLock::Resolve(const std::vector<LockSlot>& lookup_order, std::string& missing_slot, std::string& err) const
{
    // Origin URLs are hints. They are not read here and nothing is fetched.
    missing_slot.clear();
    for (LockSlot slot : lookup_order) {
        const Entry* entry = Find(slot);
        if (entry == nullptr) {
            missing_slot = LockSlotName(slot);
            return Fail(err, "BTX035_ARTIFACT");
        }
        if (!entry->required) continue;
        if (!IsContentId(entry->content_id)) {
            missing_slot = LockSlotName(slot);
            return Fail(err, "BTX035_ARTIFACT");
        }
    }
    err.clear();
    return true;
}

bool PublicRedistribution(const std::string& rights_evidence_id, bool operator_policy_allows,
                          bool private_reproducibility, bool& public_allowed, std::string& err)
{
    public_allowed = false;
    if (private_reproducibility) {
        // Observed so it cannot be mistaken for a missing parameter. It does not grant public.
        public_allowed = false;
    }
    if (rights_evidence_id.empty() || !operator_policy_allows) {
        return Fail(err, "BTX035_SCOPE_DENIED");
    }
    public_allowed = true;
    err.clear();
    return true;
}

RetentionStore::Object* RetentionStore::Find(const std::string& id)
{
    for (Object& obj : objects_) {
        if (obj.id == id) return &obj;
    }
    return nullptr;
}

const RetentionStore::Object* RetentionStore::Find(const std::string& id) const
{
    for (const Object& obj : objects_) {
        if (obj.id == id) return &obj;
    }
    return nullptr;
}

bool RetentionStore::Track(const std::string& id, uint64_t generation, std::string& err)
{
    if (id.empty()) return Fail(err, "BTX035_ARTIFACT");
    if (Find(id) != nullptr) return Fail(err, "BTX035_ARTIFACT");
    Object obj;
    obj.id = id;
    obj.generation = generation;
    objects_.push_back(std::move(obj));
    err.clear();
    return true;
}

bool RetentionStore::Pin(const std::string& id, RetentionRole role, uint64_t pin_generation, std::string& err)
{
    if (id.empty()) return Fail(err, "BTX035_ARTIFACT");
    if (Object* found = Find(id)) {
        if (!found->pinned || pin_generation > found->pin_generation) {
            found->pin_generation = pin_generation;
        }
        found->pinned = true;
        found->role = role;
        err.clear();
        return true;
    }
    Object created;
    created.id = id;
    created.generation = pin_generation;
    created.pinned = true;
    created.pin_generation = pin_generation;
    created.role = role;
    objects_.push_back(std::move(created));
    err.clear();
    return true;
}

std::vector<std::string> RetentionStore::CollectGarbage(uint64_t sweep_generation)
{
    std::vector<std::string> deleted;
    std::vector<Object> keep;
    keep.reserve(objects_.size());
    for (const Object& obj : objects_) {
        // A pin at generation N+1 is invisible to a sweep of generation N.
        const bool newer_pin = obj.pinned && obj.pin_generation > sweep_generation;
        const bool newer_object = obj.generation > sweep_generation;
        const bool retained_pin = obj.pinned && (obj.role == RetentionRole::RELEASE ||
                                                 obj.role == RetentionRole::ROLLBACK_TARGET ||
                                                 obj.role == RetentionRole::OFFLINE_BUNDLE);
        if (retained_pin || newer_pin || newer_object) {
            keep.push_back(obj);
        } else {
            deleted.push_back(obj.id);
        }
    }
    objects_.swap(keep);
    return deleted;
}

bool RetentionStore::Contains(const std::string& id) const
{
    return Find(id) != nullptr;
}

bool RetentionStore::IsPinned(const std::string& id) const
{
    const Object* obj = Find(id);
    return obj != nullptr && obj->pinned;
}

bool RetentionStore::PinRole(const std::string& id, RetentionRole& role) const
{
    const Object* obj = Find(id);
    if (obj == nullptr || !obj->pinned) return false;
    role = obj->role;
    return true;
}

TrainingAdapter::TrainingAdapter(std::string output_root)
    : root_(std::move(output_root)), status_("NOT_RESUMABLE")
{
}

bool TrainingAdapter::AddReadOnlyInput(const std::string& content_id, std::string& err)
{
    if (!IsContentId(content_id)) return Fail(err, "BTX035_ARTIFACT");
    if (std::find(inputs_.begin(), inputs_.end(), content_id) == inputs_.end()) {
        inputs_.push_back(content_id);
    }
    err.clear();
    return true;
}

bool TrainingAdapter::InputIsReadOnly(const std::string& content_id) const
{
    return std::find(inputs_.begin(), inputs_.end(), content_id) != inputs_.end();
}

bool TrainingAdapter::TargetsInput(const std::string& path) const
{
    for (const std::string& id : inputs_) {
        if (SegmentEquals(path, id)) return true;
    }
    return false;
}

bool TrainingAdapter::Write(const std::string& path, const std::string& bytes, std::string& err)
{
    if (root_.empty() || PathEscapes(path) || TargetsInput(path)) {
        return Fail(err, "BTX035_PATH_UNSAFE");
    }
    written_.append(bytes);
    err.clear();
    return true;
}

std::string TrainingAdapter::ResultManifestId() const
{
    return Sha384Hex(written_);
}

bool TrainingAdapter::CommitCheckpoint(const std::string& checkpoint_id, std::string& err)
{
    if (checkpoint_id.empty()) return Fail(err, "BTX035_NOT_FOUND");
    if (std::find(checkpoints_.begin(), checkpoints_.end(), checkpoint_id) == checkpoints_.end()) {
        checkpoints_.push_back(checkpoint_id);
    }
    err.clear();
    return true;
}

bool TrainingAdapter::Resume(const std::string& checkpoint_id, std::string& err)
{
    if (checkpoint_id.empty()) {
        status_ = "NOT_RESUMABLE";
        err.clear();
        return false;
    }
    if (std::find(checkpoints_.begin(), checkpoints_.end(), checkpoint_id) == checkpoints_.end()) {
        status_ = "NOT_RESUMABLE";
        return Fail(err, "BTX035_NOT_FOUND");
    }
    status_ = "RESUMED";
    err.clear();
    return true;
}

bool EvaluationGate::FreezeEvaluation(const std::string& contract_id, std::string& err)
{
    if (contract_id.empty()) return Fail(err, "BTX035_EVAL");
    frozen_ = contract_id;
    err.clear();
    return true;
}

bool EvaluationGate::SetDevelopmentHoldout(const std::vector<std::string>& development_ids,
                                           const std::vector<std::string>& holdout_ids, std::string& err)
{
    for (const std::string& development : development_ids) {
        if (std::find(holdout_ids.begin(), holdout_ids.end(), development) != holdout_ids.end()) {
            return Fail(err, "BTX035_EVAL");
        }
    }
    development_ = development_ids;
    holdout_ = holdout_ids;
    err.clear();
    return true;
}

bool EvaluationGate::Compare(const std::string& candidate_evaluator_id, std::string& err) const
{
    if (frozen_.empty() || candidate_evaluator_id != frozen_) {
        return Fail(err, "BTX035_EVAL");
    }
    err.clear();
    return true;
}

void EvaluationGate::AddResult(const std::string& run_id, bool negative)
{
    result_ids_.push_back(run_id);
    if (negative) negative_ids_.push_back(run_id);
}

void EvaluationGate::StorePositiveSummary(const std::string& summary)
{
    summary_ = summary;
}

bool EvaluationGate::ResultQueryable(const std::string& run_id) const
{
    return std::find(result_ids_.begin(), result_ids_.end(), run_id) != result_ids_.end();
}

bool EvaluationGate::NegativeResultQueryable(const std::string& run_id) const
{
    return std::find(negative_ids_.begin(), negative_ids_.end(), run_id) != negative_ids_.end();
}

const char* RelationKindName(RelationKind kind)
{
    switch (kind) {
    case RelationKind::PRODUCED_BY: return "PRODUCED_BY";
    case RelationKind::ENDORSED_BY: return "ENDORSED_BY";
    case RelationKind::ADOPTED_BY: return "ADOPTED_BY";
    }
    return "";
}

bool PublishAdoptionReceipt(RelationKind kind, SignerRole signer, std::string& err)
{
    if (kind == RelationKind::ADOPTED_BY && signer == SignerRole::ADOPTER) {
        err.clear();
        return true;
    }
    return Fail(err, "BTX035_SCOPE_DENIED");
}

ResearchPrincipal ForkPrincipal(const ResearchPrincipal& parent)
{
    ResearchPrincipal forked;
    if (!parent.research_key.empty() || !parent.wallet.empty() || parent.maintainer) {
        forked.research_key.clear();
        forked.wallet.clear();
        forked.maintainer = false;
    }
    return forked;
}

LocalAdoption::LocalAdoption(std::string previous_generation)
    : active_(std::move(previous_generation))
{
    if (!active_.empty()) readable_.push_back(active_);
}

bool LocalAdoption::Adopt(bool closure_verified, bool generation_staged, bool regression_ok,
                          const std::string& next_generation, std::string& err)
{
    if (!closure_verified) return Fail(err, "BTX035_SCOPE_DENIED");
    if (!generation_staged || next_generation.empty()) return Fail(err, "BTX035_SCOPE_DENIED");
    if (!regression_ok) return Fail(err, "BTX035_REGRESSION");
    active_ = next_generation;
    if (std::find(readable_.begin(), readable_.end(), next_generation) == readable_.end()) {
        readable_.push_back(next_generation);
    }
    err.clear();
    return true;
}

bool LocalAdoption::Readable(const std::string& generation) const
{
    return std::find(readable_.begin(), readable_.end(), generation) != readable_.end();
}

bool QualifyLineage(const LineageClaim& claim, std::string& err)
{
    const bool lineage_present = !claim.generation_n_research_id.empty() || !claim.generation_n1_id.empty() ||
                                 claim.generation_n1_admitted || !claim.adopted_by_runtime_id.empty() ||
                                 !claim.producer_runtime_id.empty() || !claim.generation_n2_candidate_id.empty();
    if (!lineage_present || !IsContentId(claim.generation_n_research_id) || !claim.generation_n1_admitted ||
        !IsContentId(claim.generation_n1_id) || !IsContentId(claim.adopted_by_runtime_id) ||
        !IsContentId(claim.producer_runtime_id) || claim.adopted_by_runtime_id == claim.producer_runtime_id ||
        !IsContentId(claim.generation_n2_candidate_id) ||
        claim.generation_n_research_id == claim.generation_n1_id ||
        claim.generation_n1_id == claim.generation_n2_candidate_id ||
        claim.generation_n_research_id == claim.generation_n2_candidate_id) {
        return Fail(err, "BTX035_LINEAGE");
    }
    err.clear();
    return true;
}

bool IncidentStore::File(IncidentReport& report, std::string& err)
{
    if (!IncidentFieldsPresent(report)) return Fail(err, "BTX035_NOT_FOUND");
    report.truth = false;
    reports_.push_back(report);
    err.clear();
    return true;
}

bool IncidentStore::Lookup(const std::string& affected_id, IncidentReport& out, std::string& err) const
{
    for (const IncidentReport& report : reports_) {
        if (std::find(report.affected_ids.begin(), report.affected_ids.end(), affected_id) == report.affected_ids.end()) {
            continue;
        }
        out = report;
        err.clear();
        return true;
    }
    return Fail(err, "BTX035_NOT_FOUND");
}

bool IncidentStore::Quarantine(const std::string& id, std::string& err)
{
    IncidentReport stored;
    if (!Lookup(id, stored, err)) return Fail(err, "BTX035_NOT_FOUND");
    if (std::find(quarantined_.begin(), quarantined_.end(), id) == quarantined_.end()) {
        quarantined_.push_back(id);
    }
    err.clear();
    return true;
}

bool IncidentStore::IsQuarantined(const std::string& id) const
{
    return std::find(quarantined_.begin(), quarantined_.end(), id) != quarantined_.end();
}

bool Runbook(const std::string& name, RunbookPlan& plan, std::string& err)
{
    for (const RunbookEntry& book : RUNBOOKS) {
        if (name != book.name) continue;
        plan.detection = book.detection;
        plan.containment = book.containment;
        plan.recovery = book.recovery;
        err.clear();
        return true;
    }
    plan = RunbookPlan{};
    return Fail(err, "BTX035_NOT_FOUND");
}

StrictTemplate PublicStrictTemplate()
{
    StrictTemplate templ;
    templ.full_replay_required = true;
    templ.verifier_ids.clear();
    templ.pinned = false;
    return templ;
}

bool LocalVerifierPins::PinVerifier(const std::string& verifier_id, std::string& err)
{
    if (verifier_id.empty()) return Fail(err, "BTX035_SCOPE_DENIED");
    if (std::find(pins_.begin(), pins_.end(), verifier_id) == pins_.end()) {
        pins_.push_back(verifier_id);
    }
    err.clear();
    return true;
}

bool LocalVerifierPins::IsPinned(const std::string& verifier_id) const
{
    return std::find(pins_.begin(), pins_.end(), verifier_id) != pins_.end();
}

StrictTemplate LocalVerifierPins::Template() const
{
    return PublicStrictTemplate();
}

bool AcceptActionIntent(const std::string& action, const std::string& parameters_ref, std::string& err)
{
    static constexpr std::string_view kActions[] = {
        "source.snapshot",
        "git.ref_update",
        "research.run",
        "model.activate",
        "research.publish",
        "realm.promote",
        "runtime.pause",
    };
    bool known = false;
    for (std::string_view name : kActions) {
        if (action == name) known = true;
    }
    if (!known || !IsContentId(parameters_ref)) return Fail(err, "BTX035_ACTION");
    err.clear();
    return true;
}

bool NamedWorkflowIsProfile(const std::string& workflow_name)
{
    (void)workflow_name;
    return false;
}

bool AcceptTrainingProfile(const TrainingProfile& profile, std::string& err)
{
    if (profile.serialization.empty() || profile.kernel.empty() || profile.init.empty() ||
        profile.data_order.empty() || profile.checkpoint.empty() || profile.runtime.empty()) {
        return Fail(err, "BTX035_PROFILE");
    }
    err.clear();
    return true;
}

bool FullReplayRequired(const std::string& mode, std::string& err)
{
    if (mode == "PUBLIC_STRICT" || mode == "REALM_STRICT") {
        err.clear();
        return true;
    }
    return Fail(err, "BTX035_SCOPE_DENIED");
}

void ComparisonResult::AddPairedRun(const std::string& id, bool negative)
{
    paired_run_ids.push_back(id);
    if (negative) negative_run_ids.push_back(id);
}

void ComparisonResult::SetSummaryScore(const std::string& score)
{
    summary_score = score;
}

bool ComparisonResult::HasNegativeRun(const std::string& id) const
{
    return std::find(negative_run_ids.begin(), negative_run_ids.end(), id) != negative_run_ids.end();
}

bool ComparisonResult::Bind(std::string& err) const
{
    if (!IsContentId(baseline) || !IsContentId(candidate) || !IsContentId(spec) || paired_run_ids.empty() ||
        (direction != "LOWER" && direction != "HIGHER") || procedure.empty()) {
        return Fail(err, "BTX035_EVAL");
    }
    for (const std::string& id : paired_run_ids) {
        if (!IsContentId(id)) return Fail(err, "BTX035_EVAL");
    }
    for (const std::string& id : negative_run_ids) {
        if (!IsContentId(id)) return Fail(err, "BTX035_EVAL");
        if (std::find(paired_run_ids.begin(), paired_run_ids.end(), id) == paired_run_ids.end()) {
            return Fail(err, "BTX035_EVAL");
        }
    }
    err.clear();
    return true;
}

} // namespace modelnet
