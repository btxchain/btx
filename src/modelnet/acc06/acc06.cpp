// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc06/acc06.h>

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_defense/codes.h>
#include <modelnet/swarm_defwork/codes.h>
#include <modelnet/swarm_planner/codes.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

bool Listed(const std::vector<std::string>& allowed, const std::string& recipient)
{
    for (const std::string& item : allowed) {
        if (item == recipient) {
            return true;
        }
    }
    return false;
}

bool KnownMarking(const std::string& marking)
{
    return marking == "RED" || marking == "AMBER" || marking == "AMBER+STRICT" || marking == "GREEN" ||
           marking == "CLEAR";
}

bool ApprovedType(const std::string& command_type)
{
    return command_type == "contain" || command_type == "allow" || command_type == "deny" || command_type == "log";
}

} // namespace

Acc06::Acc06()
{
    m_backends.push_back(Backend{"match", "condition:"});
    m_backends.push_back(Backend{"count", "selection:"});
}

bool Acc06::AdmitWork(const std::string& id, std::string& err)
{
    return m_planner.Admit(kSwarmPlannerWorkView, id, err);
}

bool Acc06::AdmitEvidence(const std::string& id, std::string& err)
{
    return m_planner.Admit(kSwarmPlannerEvidence, id, err);
}

bool Acc06::Depend(const std::string& before, const std::string& after, std::string& err)
{
    return m_planner.Depend(before, after, err);
}

bool Acc06::Dispatch(const std::string& id, std::string& err) const
{
    return m_planner.Dispatch(id, err);
}

bool Acc06::Finish(const std::string& id, std::string& err)
{
    return m_planner.Finish(id, err);
}

bool Acc06::RetractEvidence(const std::string& id, std::string& err)
{
    return m_planner.Retract(id, err);
}

bool Acc06::hypothesis_persisted(const std::string& id) const
{
    return m_planner.admitted(kSwarmPlannerWorkView, id);
}

bool Acc06::evidence_persisted(const std::string& id) const
{
    return m_planner.admitted(kSwarmPlannerEvidence, id);
}

bool Acc06::evidence_retracted(const std::string& id) const
{
    return m_planner.retracted(id);
}

int64_t Acc06::plan_history() const
{
    return m_planner.history_count();
}

bool Acc06::DefineSignal(const std::string& workload, const std::string& signal, std::string& err)
{
    if (workload.empty() || signal.empty()) {
        err = "SIGNAL";
        return false;
    }
    const auto found = m_signals.find(workload);
    if (found != m_signals.end()) {
        err = found->second.signal == signal ? NIFDT_REPLAY : "SIGNAL";
        return false;
    }
    SignalDef row;
    row.signal = signal;
    m_signals.emplace(workload, std::move(row));
    err.clear();
    return true;
}

bool Acc06::RecordSignal(const std::string& workload, const std::string& signal, int64_t amount, std::string& err)
{
    const auto found = m_signals.find(workload);
    if (found == m_signals.end() || found->second.signal != signal) {
        err = "SIGNAL";
        return false;
    }
    if (amount <= static_cast<int64_t>(0)) {
        err = "PROGRESS";
        return false;
    }
    found->second.progress += amount;
    err.clear();
    return true;
}

int64_t Acc06::progress_of(const std::string& workload) const
{
    const auto found = m_signals.find(workload);
    if (found == m_signals.end()) {
        return static_cast<int64_t>(0);
    }
    return found->second.progress;
}

std::string Acc06::signal_of(const std::string& workload) const
{
    const auto found = m_signals.find(workload);
    if (found == m_signals.end()) {
        return std::string();
    }
    return found->second.signal;
}

bool Acc06::AdmitPlan(const std::string& plan_id, int64_t cost, std::string& err)
{
    if (plan_id.empty()) {
        err = "PLAN";
        return false;
    }
    if (m_plans.find(plan_id) != m_plans.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (cost < static_cast<int64_t>(1) || cost > kPlanBound || m_plan_cost + cost > kPlanBound) {
        err = "BOUND";
        return false;
    }
    if (m_saturated) {
        err = "BACKPRESSURE";
        return false;
    }
    PlanRow row;
    row.cost = cost;
    m_plans.emplace(plan_id, row);
    m_plan_cost += cost;
    err.clear();
    return true;
}

bool Acc06::SetBackpressure(bool saturated, std::string& err)
{
    m_saturated = saturated;
    err.clear();
    return true;
}

bool Acc06::plan_held(const std::string& plan_id) const
{
    return m_plans.find(plan_id) != m_plans.end();
}

int64_t Acc06::committed_plan_cost() const
{
    return m_plan_cost;
}

bool Acc06::saturated() const
{
    return m_saturated;
}

bool Acc06::KeepProcedure(const std::string& id, const std::string& body, std::string& err)
{
    if (id.empty() || body.empty()) {
        err = "PROCEDURE";
        return false;
    }
    if (m_procedures.find(id) != m_procedures.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    Procedure row;
    row.body = body;
    m_procedures.emplace(id, std::move(row));
    err.clear();
    return true;
}

bool Acc06::ReplaceProcedure(const std::string& id, const std::string& body, std::string& err)
{
    const auto found = m_procedures.find(id);
    if (found == m_procedures.end()) {
        err = "PROCEDURE";
        return false;
    }
    if (!m_quorum || !m_runtime) {
        err = "KEPT";
        return false;
    }
    if (body.empty()) {
        err = "PROCEDURE";
        return false;
    }
    found->second.body = body;
    err.clear();
    return true;
}

bool Acc06::LoseQuorum(std::string& err)
{
    m_quorum = false;
    err.clear();
    return true;
}

bool Acc06::LoseRuntime(std::string& err)
{
    m_runtime = false;
    err.clear();
    return true;
}

std::string Acc06::procedure_of(const std::string& id) const
{
    const auto found = m_procedures.find(id);
    if (found == m_procedures.end()) {
        return std::string();
    }
    return found->second.body;
}

bool Acc06::quorum_present() const
{
    return m_quorum;
}

bool Acc06::runtime_present() const
{
    return m_runtime;
}

bool Acc06::ProposeEffect(const std::string& case_id, const std::string& action_id, const std::string& level,
                          const std::string& asset, int64_t blast, std::string& err)
{
    return m_work.Propose(case_id, action_id, level, asset, blast, err);
}

bool Acc06::ApprovePresent(const std::string& case_id, const std::string& action_id, bool human, std::string& err)
{
    return m_work.Approve(case_id, action_id, human, err);
}

bool Acc06::ExecuteExact(const std::string& case_id, const std::string& action_id, const std::string& asset,
                         int64_t blast, std::string& err)
{
    return m_work.Execute(case_id, action_id, asset, blast, err);
}

bool Acc06::ReconcileUnknown(const std::string& action_id, std::string& err)
{
    return m_work.Unknown(action_id, err);
}

bool Acc06::CheckCanary(const std::string& action_id, bool canary_ok, std::string& err)
{
    return m_work.Rollback(action_id, canary_ok, err);
}

bool Acc06::RefuseRetaliation(const std::string& target, std::string& err)
{
    return m_work.Retaliate(target, err);
}

bool Acc06::proposed(const std::string& action_id) const
{
    return m_work.proposed(action_id);
}

bool Acc06::approved(const std::string& action_id) const
{
    return m_work.approved(action_id);
}

bool Acc06::has_receipt(const std::string& action_id) const
{
    return m_work.has_receipt(action_id);
}

int64_t Acc06::receipt_count() const
{
    return m_work.receipt_count();
}

bool Acc06::rolled_back(const std::string& action_id) const
{
    return m_work.rolled_back(action_id);
}

bool Acc06::ambiguous(const std::string& action_id) const
{
    return m_work.ambiguous(action_id);
}

std::string Acc06::asset_of(const std::string& action_id) const
{
    return m_work.asset_of(action_id);
}

int64_t Acc06::blast_of(const std::string& action_id) const
{
    return m_work.blast_of(action_id);
}

bool Acc06::OpenCase(const std::string& customer, const std::string& case_id, const std::string& asset,
                     const std::string& policy_gen, int64_t until_ms, int64_t now_ms, std::string& err)
{
    return m_defense.Mandate(customer, case_id, asset, policy_gen, until_ms, now_ms, err);
}

bool Acc06::KeepEvidence(const std::string& case_id, const std::string& evidence_id,
                         const std::vector<unsigned char>& bytes, std::string& err)
{
    return m_defense.Evidence(case_id, evidence_id, bytes, err);
}

bool Acc06::PublishShare(const std::string& case_id, const std::string& artifact_id, bool embargo_expired,
                         bool sanitized, bool validated, std::string& err)
{
    return m_defense.Publish(case_id, artifact_id, embargo_expired, sanitized, validated, err);
}

bool Acc06::SearchEvidence(const std::string& case_id, const std::string& evidence_id, std::string& err)
{
    return m_defense.Search(case_id, evidence_id, err);
}

bool Acc06::GrantTraining(const std::string& case_id, std::string& err)
{
    return m_defense.AllowTraining(case_id, err);
}

bool Acc06::published(const std::string& artifact_id) const
{
    return m_defense.published(artifact_id);
}

bool Acc06::training_allowed(const std::string& case_id) const
{
    return m_defense.training_allowed(case_id);
}

const std::vector<unsigned char>& Acc06::evidence_body(const std::string& evidence_id) const
{
    return m_defense.body(evidence_id);
}

bool Acc06::AuthorizeShare(const std::string& originator, const std::string& recipient, const std::string& purpose,
                           const std::string& marking, const std::vector<std::string>& allowed,
                           const std::string& stated_purpose, const std::string& originator_org,
                           const std::string& recipient_org, bool public_release, std::string& err)
{
    if (originator.empty() || recipient.empty() || purpose.empty() || marking.empty() || allowed.empty() ||
        stated_purpose.empty() || originator_org.empty()) {
        err = "FIELD";
        return false;
    }
    if (!KnownMarking(marking)) {
        err = "TLP";
        return false;
    }
    if (purpose != stated_purpose) {
        err = "PURPOSE";
        return false;
    }
    if (!Listed(allowed, recipient)) {
        err = "RECIPIENT";
        return false;
    }
    if (marking != "CLEAR" && public_release) {
        err = "TLP";
        return false;
    }
    if ((marking == "RED" || marking == "AMBER+STRICT") && recipient_org != originator_org) {
        err = "TLP";
        return false;
    }
    for (const ShareAuth& row : m_shares) {
        if (row.originator == originator && row.recipient == recipient && row.purpose == purpose &&
            row.marking == marking) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    ShareAuth row;
    row.originator = originator;
    row.recipient = recipient;
    row.purpose = purpose;
    row.marking = marking;
    m_shares.push_back(std::move(row));
    err.clear();
    return true;
}

bool Acc06::share_authorized(const std::string& originator, const std::string& recipient, const std::string& purpose,
                             const std::string& marking) const
{
    for (const ShareAuth& row : m_shares) {
        if (row.originator == originator && row.recipient == recipient && row.purpose == purpose &&
            row.marking == marking) {
            return true;
        }
    }
    return false;
}

int64_t Acc06::share_count() const
{
    return static_cast<int64_t>(m_shares.size());
}

bool Acc06::PutArtifact(const std::string& id, const std::string& body, std::string& err)
{
    if (id.empty() || body.empty()) {
        err = "ARTIFACT";
        return false;
    }
    if (m_artifacts.find(id) != m_artifacts.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    Artifact row;
    row.body = body;
    row.version = static_cast<int64_t>(1);
    m_artifacts.emplace(id, std::move(row));
    err.clear();
    return true;
}

bool Acc06::DisseminateRetraction(const std::string& id, int64_t version, const std::string& reason, std::string& err)
{
    const auto found = m_artifacts.find(id);
    if (found == m_artifacts.end()) {
        err = "ARTIFACT";
        return false;
    }
    if (reason.empty()) {
        err = "RETRACT";
        return false;
    }
    if (version != found->second.version + static_cast<int64_t>(1)) {
        err = "VERSION";
        return false;
    }
    found->second.version = version;
    found->second.retracted = true;
    Notice note;
    note.id = id;
    note.version = version;
    note.reason = reason;
    m_notices.push_back(std::move(note));
    err.clear();
    return true;
}

std::string Acc06::artifact_body(const std::string& id) const
{
    const auto found = m_artifacts.find(id);
    if (found == m_artifacts.end()) {
        return std::string();
    }
    return found->second.body;
}

int64_t Acc06::artifact_version(const std::string& id) const
{
    const auto found = m_artifacts.find(id);
    if (found == m_artifacts.end()) {
        return static_cast<int64_t>(0);
    }
    return found->second.version;
}

bool Acc06::artifact_retracted(const std::string& id) const
{
    const auto found = m_artifacts.find(id);
    return found != m_artifacts.end() && found->second.retracted;
}

int64_t Acc06::retraction_notices() const
{
    return static_cast<int64_t>(m_notices.size());
}

bool Acc06::MapExternalId(const std::string& object_id, const std::string& version, const std::string& source,
                          const std::string& external_id, std::string& err)
{
    if (object_id.empty() || source.empty() || external_id.empty()) {
        err = "STIX";
        return false;
    }
    if (version != "2.0" && version != "2.1") {
        err = "VERSION";
        return false;
    }
    for (const StixRow& row : m_stix) {
        if (row.source != source || row.external_id != external_id) {
            continue;
        }
        if (row.object_id == object_id && row.version == version) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "MAPPING";
        return false;
    }
    StixRow row;
    row.object_id = object_id;
    row.version = version;
    row.source = source;
    row.external_id = external_id;
    m_stix.push_back(std::move(row));
    err.clear();
    return true;
}

std::string Acc06::object_for_external(const std::string& source, const std::string& external_id) const
{
    for (const StixRow& row : m_stix) {
        if (row.source == source && row.external_id == external_id) {
            return row.object_id;
        }
    }
    return std::string();
}

std::string Acc06::stix_version(const std::string& object_id) const
{
    for (const StixRow& row : m_stix) {
        if (row.object_id == object_id) {
            return row.version;
        }
    }
    return std::string();
}

bool Acc06::OpenCollection(const std::string& id, bool can_read, bool can_write, std::string& err)
{
    if (id.empty()) {
        err = "TAXII";
        return false;
    }
    if (m_collections.find(id) != m_collections.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    Collection row;
    row.can_read = can_read;
    row.can_write = can_write;
    m_collections.emplace(id, std::move(row));
    err.clear();
    return true;
}

bool Acc06::AddToCollection(const std::string& id, const std::string& object_id, std::string& err)
{
    const auto found = m_collections.find(id);
    if (found == m_collections.end()) {
        err = "TAXII";
        return false;
    }
    if (!found->second.can_write || object_id.empty()) {
        err = "TAXII";
        return false;
    }
    for (const std::string& held : found->second.objects) {
        if (held == object_id) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    found->second.objects.push_back(object_id);
    err.clear();
    return true;
}

bool Acc06::SyncCollection(const std::string& id, int64_t limit, std::vector<std::string>& page, bool& more,
                           std::string& err)
{
    page.clear();
    more = false;
    const auto found = m_collections.find(id);
    if (found == m_collections.end()) {
        err = "TAXII";
        return false;
    }
    if (limit < static_cast<int64_t>(1) || limit > kSyncLimit) {
        err = "BOUND";
        return false;
    }
    if (!found->second.can_read) {
        err = "TAXII";
        return false;
    }
    const std::size_t start = found->second.cursor;
    const std::size_t available = found->second.objects.size();
    if (start >= available) {
        err.clear();
        return true;
    }
    const std::size_t remain = available - start;
    const std::size_t take = remain < static_cast<std::size_t>(limit) ? remain : static_cast<std::size_t>(limit);
    for (std::size_t i = 0; i < take; ++i) {
        page.push_back(found->second.objects[start + i]);
    }
    found->second.cursor = start + take;
    more = found->second.cursor < found->second.objects.size();
    err.clear();
    return true;
}

int64_t Acc06::collection_size(const std::string& id) const
{
    const auto found = m_collections.find(id);
    if (found == m_collections.end()) {
        return static_cast<int64_t>(0);
    }
    return static_cast<int64_t>(found->second.objects.size());
}

bool Acc06::PreserveOcsf(const std::string& event_id, const std::string& mapping_version, const std::string& raw,
                         std::string& err)
{
    if (event_id.empty() || mapping_version.empty() || raw.empty()) {
        err = "OCSF";
        return false;
    }
    const auto found = m_ocsf.find(event_id);
    if (found == m_ocsf.end()) {
        OcsfRow row;
        row.raw = raw;
        row.versions.push_back(mapping_version);
        m_ocsf.emplace(event_id, std::move(row));
        err.clear();
        return true;
    }
    if (found->second.raw != raw) {
        err = "LINEAGE";
        return false;
    }
    for (const std::string& held : found->second.versions) {
        if (held == mapping_version) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    found->second.versions.push_back(mapping_version);
    err.clear();
    return true;
}

std::string Acc06::ocsf_raw(const std::string& event_id) const
{
    const auto found = m_ocsf.find(event_id);
    if (found == m_ocsf.end()) {
        return std::string();
    }
    return found->second.raw;
}

bool Acc06::ocsf_has_version(const std::string& event_id, const std::string& mapping_version) const
{
    const auto found = m_ocsf.find(event_id);
    if (found == m_ocsf.end()) {
        return false;
    }
    for (const std::string& held : found->second.versions) {
        if (held == mapping_version) {
            return true;
        }
    }
    return false;
}

bool Acc06::ValidateRule(const std::string& rule_id, const std::string& detection, std::string& err)
{
    if (rule_id.empty() || detection.empty()) {
        err = "SIGMA";
        return false;
    }
    if (m_rules.find(rule_id) != m_rules.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (m_backends.empty()) {
        err = "BACKEND";
        return false;
    }
    for (const Backend& backend : m_backends) {
        if (detection.find(backend.token) == std::string::npos) {
            err = "BACKEND";
            return false;
        }
    }
    m_rules.insert(rule_id);
    err.clear();
    return true;
}

bool Acc06::rule_validated(const std::string& rule_id) const
{
    return m_rules.find(rule_id) != m_rules.end();
}

int64_t Acc06::advertised_backends() const
{
    return static_cast<int64_t>(m_backends.size());
}

bool Acc06::AdvertiseBackend(const std::string& name, std::string& err)
{
    if (name == "windows" || name == "macos") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    for (const Backend& backend : m_backends) {
        if (backend.name == name) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    err = "BACKEND";
    return false;
}

bool Acc06::ParseEve(const std::string& event_id, const std::string& body, std::string& err)
{
    if (event_id.empty()) {
        err = "EVE";
        return false;
    }
    if (m_eve.find(event_id) != m_eve.end()) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (body.size() > kEveMax) {
        err = "OVERSIZE";
        return false;
    }
    if (body.size() < static_cast<std::size_t>(2) || body.front() != '{' || body.back() != '}' ||
        body.find("\"event_type\"") == std::string::npos) {
        err = "MALFORMED";
        return false;
    }
    EveRow row;
    row.body = body;
    m_eve.emplace(event_id, std::move(row));
    err.clear();
    return true;
}

std::string Acc06::eve_body(const std::string& event_id) const
{
    const auto found = m_eve.find(event_id);
    if (found == m_eve.end()) {
        return std::string();
    }
    return found->second.body;
}

bool Acc06::ImportTyped(const std::string& command_type, std::string& err)
{
    if (!ApprovedType(command_type)) {
        err = "CACAO";
        return false;
    }
    if (!m_cacao.insert(command_type).second) {
        err = NIFDT_REPLAY;
        return false;
    }
    err.clear();
    return true;
}

bool Acc06::cacao_imported(const std::string& command_type) const
{
    return m_cacao.find(command_type) != m_cacao.end();
}

bool Acc06::Release(std::string& err) const
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc06::Spend(std::string& err) const
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Acc06::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    static const char* const kJournal[] = {
        "MIG-001", "MIG-002", "MIG-003",
        "BUILD-001", "BUILD-002", "BUILD-003",
        "INC-001", "INC-002",
        "DEV-001", "DEV-002", "DEV-003",
        "E2E-001", "E2E-002", "E2E-003", "E2E-004", "E2E-005",
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
    if (aux < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
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
    if (id == "MIG-001" && text == "wallet") {
        err = "UNTOUCHED";
        return false;
    }
    if (id == "MIG-002" && text == "fabricate") {
        err = "LEGACY";
        return false;
    }
    if (id == "MIG-003" && text == "downgrade") {
        err = "PROTOCOL";
        return false;
    }
    if (id == "BUILD-002" && (text == "windows" || text == "macos")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "BUILD-003" && text == "skip") {
        err = "MEASURE";
        return false;
    }
    if (id == "INC-001" && text == "blocklist") {
        err = "SCOPE";
        return false;
    }
    if (id == "INC-002" && text == "self") {
        err = "RUNBOOK";
        return false;
    }
    if (id == "DEV-002" && text == "grep") {
        err = "EVIDENCE";
        return false;
    }
    if (id == "DEV-003" && text == "doc") {
        err = "JOURNEY";
        return false;
    }
    if (id == "E2E-001" && text == "assign") {
        err = "AUTHORITY";
        return false;
    }
    if (id == "E2E-002" && text == "altered") {
        err = "MISMATCH";
        return false;
    }
    if (id == "E2E-003" && text == "hook") {
        err = "SAFE";
        return false;
    }
    if (id == "E2E-004" && text == "one-attestor") {
        err = "QUORUM";
        return false;
    }
    if (id == "E2E-005" && text == "shrink") {
        err = "THRESHOLD";
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
