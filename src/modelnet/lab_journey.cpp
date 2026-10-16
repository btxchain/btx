// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_journey.h>

#include <modelnet/crypto.h>
#include <modelnet/pq_delegation.h>
#include <modelnet/training_evidence.h>
#include <span.h>

#include <cctype>
#include <set>
#include <string>
#include <utility>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

Digest48 IdDigest(const std::string& label)
{
    return DomainHash("BTX/035/LabJourney/v1", Span<const unsigned char>{UCharCast(label.data()), label.size()});
}

bool RequestsWalletSpend(const std::string& prompt)
{
    std::string lower;
    lower.reserve(prompt.size());
    for (unsigned char c : prompt) {
        lower.push_back(static_cast<char>(std::tolower(c)));
    }
    return lower.find("wallet") != std::string::npos && lower.find("spend") != std::string::npos;
}

} // namespace

LabJourney::RootRow* LabJourney::FindMutable(const std::string& root_id)
{
    const auto it = m_roots.find(root_id);
    if (it == m_roots.end()) return nullptr;
    return &it->second;
}

bool LabJourney::WalletSpendAllowed() const
{
    return ResearchMaySpend() || ResearchMaySpendWallet();
}

bool LabJourney::HasWalletFlag(const std::string& root_id) const
{
    const auto it = m_roots.find(root_id);
    if (it == m_roots.end()) return false;
    return it->second.wallet;
}

bool LabJourney::CreateResearchRoot(bool wallet_flag, std::string& root_id, std::string& err)
{
    root_id.clear();
    if (wallet_flag || WalletSpendAllowed()) return Fail(err, "BTX035_SCOPE_DENIED");
    root_id = "research-root-" + std::to_string(m_roots.size() + 1);
    RootRow row;
    row.wallet = false;
    m_roots.emplace(root_id, std::move(row));
    err.clear();
    return true;
}

bool LabJourney::OfferObjective(const std::string& objective_id, std::string& err)
{
    Digest48 topic;
    if (!TopicId(objective_id, topic, err)) return false;
    m_offered.insert(objective_id);
    err.clear();
    return true;
}

bool LabJourney::DiscoverObjective(const std::string& objective_id, std::string& err)
{
    if (m_offered.count(objective_id) == 0) return Fail(err, "BTX035_NOT_FOUND");
    Digest48 topic;
    if (!TopicId(objective_id, topic, err)) return false;
    m_discovered.insert(objective_id);
    err.clear();
    return true;
}

bool LabJourney::SelectObjective(const std::string& root_id, const std::string& objective_id, std::string& err)
{
    RootRow* root = FindMutable(root_id);
    if (root == nullptr) return Fail(err, "BTX035_NOT_FOUND");
    if (m_discovered.count(objective_id) == 0) return Fail(err, "BTX035_NOT_FOUND");
    root->objective = objective_id;
    err.clear();
    return true;
}

bool LabJourney::RecordSourceSnapshot(const std::string& root_id, const std::string& snapshot_id, std::string& err)
{
    RootRow* root = FindMutable(root_id);
    if (root == nullptr || root->objective.empty()) return Fail(err, "BTX035_NOT_FOUND");
    if (snapshot_id.empty()) return Fail(err, "BTX035_SCHEMA");
    root->snapshot_id = snapshot_id;
    err.clear();
    return true;
}

bool LabJourney::RecordData(const std::string& root_id, const std::string& data_id, std::string& err)
{
    RootRow* root = FindMutable(root_id);
    if (root == nullptr || root->snapshot_id.empty()) return Fail(err, "BTX035_NOT_FOUND");
    if (data_id.empty()) return Fail(err, "BTX035_SCHEMA");
    root->data_id = data_id;
    err.clear();
    return true;
}

bool LabJourney::OpenWorkspaceGeneration(const std::string& root_id, uint64_t& generation, std::string& err)
{
    generation = 0;
    RootRow* root = FindMutable(root_id);
    if (root == nullptr || root->snapshot_id.empty() || root->data_id.empty()) return Fail(err, "BTX035_NOT_FOUND");
    if (!root->workspace_open) {
        if (!m_workspace.OpenTree(root_id, err)) return false;
        root->workspace_open = true;
    }
    root->generation = m_workspace.Generation(root_id);
    generation = root->generation;
    if (generation == 0) return Fail(err, "BTX035_GENERATION");
    err.clear();
    return true;
}

bool LabJourney::PublishContribution(const std::string& root_id, const std::string& contribution_id, std::string& err)
{
    RootRow* root = FindMutable(root_id);
    if (root == nullptr || !root->workspace_open || root->objective.empty()) return Fail(err, "BTX035_NOT_FOUND");
    if (contribution_id.empty()) return Fail(err, "BTX035_SCHEMA");
    Digest48 topic;
    if (!TopicId(root->objective, topic, err)) return false;
    const Digest48 contribution = IdDigest("contribution:" + contribution_id);
    const Digest48 author = IdDigest("author:" + root_id);
    if (!m_research.Publish(topic, contribution, author, false, "contribution", err)) return false;
    root->contribution_id = contribution_id;
    m_contribution_author[contribution_id] = root_id;
    m_contribution_topic[contribution_id] = topic;
    m_contribution_digest[contribution_id] = contribution;
    err.clear();
    return true;
}

bool LabJourney::RemoveAuthor(const std::string& root_id, std::string& err)
{
    if (FindMutable(root_id) == nullptr) return Fail(err, "BTX035_NOT_FOUND");
    m_research.ContinueWithout(IdDigest("author:" + root_id));
    m_removed_authors.insert(root_id);
    err.clear();
    return true;
}

bool LabJourney::FindContribution(const std::string& contribution_id) const
{
    const auto topic = m_contribution_topic.find(contribution_id);
    const auto id = m_contribution_digest.find(contribution_id);
    if (topic == m_contribution_topic.end() || id == m_contribution_digest.end()) return false;
    ResearchContribution row;
    return m_research.Find(topic->second, id->second, row);
}

bool LabJourney::AuthorPresent(const std::string& root_id) const
{
    return m_research.HasPeer(IdDigest("author:" + root_id));
}

bool LabJourney::ContinueParticipant(const std::string& participant_id, const std::string& contribution_id, std::string& err)
{
    if (participant_id.empty()) return Fail(err, "BTX035_NOT_FOUND");
    const auto author = m_contribution_author.find(contribution_id);
    if (author == m_contribution_author.end() || m_removed_authors.count(author->second) == 0) return Fail(err, "BTX035_NOT_FOUND");
    if (!FindContribution(contribution_id)) return Fail(err, "BTX035_NOT_FOUND");
    m_continued[participant_id] = contribution_id;
    err.clear();
    return true;
}

bool LabJourney::SelectedObjective(const std::string& root_id, std::string& objective_id) const
{
    const auto it = m_roots.find(root_id);
    if (it == m_roots.end() || it->second.objective.empty()) return false;
    objective_id = it->second.objective;
    return true;
}

bool LabJourney::SourceSnapshot(const std::string& root_id, std::string& snapshot_id) const
{
    const auto it = m_roots.find(root_id);
    if (it == m_roots.end() || it->second.snapshot_id.empty()) return false;
    snapshot_id = it->second.snapshot_id;
    return true;
}

bool LabJourney::DataId(const std::string& root_id, std::string& data_id) const
{
    const auto it = m_roots.find(root_id);
    if (it == m_roots.end() || it->second.data_id.empty()) return false;
    data_id = it->second.data_id;
    return true;
}

bool LabJourney::Continued(const std::string& participant_id, std::string& contribution_id) const
{
    const auto it = m_continued.find(participant_id);
    if (it == m_continued.end()) return false;
    contribution_id = it->second;
    return true;
}

bool LabJourney::RecordFixtureTransitions(std::string& err)
{
    const FixtureResult result = RunReferenceFixture(FrozenReferenceProfile());
    if (!result.ok || result.steps.size() != FIXTURE_STEP_COUNT || result.intervals.size() != FIXTURE_STEP_COUNT) {
        m_fixture_recorded = false;
        err = result.code.empty() ? "BTX035_EVIDENCE_INCOMPLETE" : result.code;
        return false;
    }
    m_fixture = result;
    m_checkpoint = "fixture-checkpoint";
    m_fixture_recorded = true;
    err.clear();
    return true;
}

uint64_t LabJourney::FixtureSteps() const
{
    return m_fixture_recorded ? static_cast<uint64_t>(m_fixture.steps.size()) : 0;
}

bool LabJourney::FixtureStep(uint64_t index, uint64_t& start_inclusive, uint64_t& end_exclusive) const
{
    if (!m_fixture_recorded || index >= m_fixture.intervals.size()) return false;
    start_inclusive = m_fixture.intervals[index].start_inclusive;
    end_exclusive = m_fixture.intervals[index].end_exclusive;
    return true;
}

bool LabJourney::FixtureCovers() const
{
    if (!m_fixture_recorded) return false;
    return FullReplayCoverage(FIXTURE_STEP_COUNT, m_fixture.start_state, m_fixture.final_state, m_fixture.intervals);
}

std::string LabJourney::FixtureDataCursor() const
{
    return m_fixture_recorded ? REFERENCE_DATA_CURSOR : std::string();
}

std::string LabJourney::FixtureOptimizer() const
{
    return m_fixture_recorded ? REFERENCE_OPTIMIZER : std::string();
}

std::string LabJourney::FixtureCheckpoint() const
{
    return m_fixture_recorded ? m_checkpoint : std::string();
}

bool LabJourney::AcceptFixtureBinding(const std::string& data_cursor, const std::string& optimizer, const std::string& checkpoint,
                                      std::string& err) const
{
    if (!m_fixture_recorded || m_fixture.intervals.empty()) return Fail(err, "BTX035_EVIDENCE_INCOMPLETE");
    if (checkpoint != m_checkpoint) return Fail(err, "BTX035_ID_MISMATCH");
    Interval probe = m_fixture.intervals.front();
    probe.profile = REFERENCE_PROFILE_NAME;
    probe.rng = REFERENCE_RNG;
    probe.optimizer = optimizer;
    probe.data_cursor = data_cursor;
    return AcceptInterval(probe, REFERENCE_RNG, REFERENCE_OPTIMIZER, REFERENCE_DATA_CURSOR, err);
}

AdmissionResult LabJourney::AdmitFixture(const std::vector<std::string>& independent_roots) const
{
    if (!m_fixture_recorded) {
        AdmissionResult denied;
        denied.code = "BTX035_EVIDENCE_INCOMPLETE";
        return denied;
    }
    std::vector<Interval> covered;
    std::vector<std::string> roots;
    for (const std::string& root : independent_roots) {
        if (root.empty()) continue;
        roots.push_back(root);
        for (Interval interval : m_fixture.intervals) {
            interval.ancestry = root;
            interval.publisher_only = false;
            covered.push_back(std::move(interval));
        }
    }
    return Admit(Assurance::PUBLIC_STRICT, true, covered, FIXTURE_STEP_COUNT, FIXTURE_START_STATE, FIXTURE_FINAL_STATE, roots, false);
}

bool LabJourney::MarkOriginsDown(std::string& err)
{
    m_origins_down = true;
    err.clear();
    return true;
}

bool LabJourney::RetainReplica(const std::string& replica_id, std::string& err)
{
    if (replica_id.empty()) return Fail(err, "BTX035_NOT_FOUND");
    m_replicas.insert(replica_id);
    err.clear();
    return true;
}

bool LabJourney::Reconstruct(const std::vector<std::string>& replica_ids, std::string& replica_id, std::string& err)
{
    replica_id.clear();
    if (!m_origins_down) return Fail(err, "BTX035_CONFLICT");
    if (replica_ids.empty() || m_replicas.empty()) return Fail(err, "BTX035_NOT_FOUND");
    for (const std::string& id : replica_ids) {
        if (m_replicas.count(id) != 0) {
            replica_id = id;
            err.clear();
            return true;
        }
    }
    return Fail(err, "BTX035_NOT_FOUND");
}

bool LabJourney::AcceptHook(const std::string& hook, std::string& err) const
{
    (void)hook;
    return Fail(err, "BTX035_SCOPE_DENIED");
}

bool LabJourney::AcceptSpendPrompt(const std::string& prompt, std::string& err)
{
    if (!RequestsWalletSpend(prompt)) {
        err.clear();
        return true;
    }
    ActionPermit permit;
    permit.permit_id = "prompt-wallet-spend";
    permit.grant_id = "grant-prompt";
    permit.generation = 1;
    permit.effect = "wallet-spend";
    permit.not_after_ms = 10;
    permit.parameter_fingerprint = "fp";
    return m_gate.Issue(permit, err);
}

bool LabJourney::MarkKeyStolen(const std::string& key_id, std::string& err)
{
    if (key_id.empty()) return Fail(err, "BTX035_SCHEMA");
    m_stolen_keys.insert(key_id);
    err.clear();
    return true;
}

bool LabJourney::AcceptOwner(const std::string& owner_id, const std::string& key_id, std::string& err) const
{
    if (owner_id.empty() || key_id.empty()) return Fail(err, "BTX035_SCOPE_DENIED");
    if (m_stolen_keys.count(key_id) != 0 || m_stolen_keys.count(owner_id) != 0) return Fail(err, "BTX035_IDENTITY_REVOKED");
    if (owner_id != key_id) return Fail(err, "BTX035_SCOPE_DENIED");
    err.clear();
    return true;
}

bool LabJourney::NotePublicAdmitted(const std::string& model_id, std::string& err)
{
    if (model_id.empty()) return Fail(err, "BTX035_ADMISSION_REQUIRED");
    m_admitted.insert(model_id);
    err.clear();
    return true;
}

bool LabJourney::Promote(const std::string& model_id, const std::string& destination_policy_id,
                         const std::vector<std::string>& pinned_attestation_ids, std::string& err)
{
    if (m_admitted.count(model_id) == 0) return Fail(err, "BTX035_ADMISSION_REQUIRED");
    if (destination_policy_id.empty()) return Fail(err, "BTX035_POLICY");
    std::set<std::string> pins;
    for (const std::string& id : pinned_attestation_ids) {
        if (!id.empty()) pins.insert(id);
    }
    if (pins.size() < static_cast<size_t>(kPromotionThreshold)) return Fail(err, "BTX035_QUORUM_NOT_MET");
    const std::vector<std::string> pin_list(pins.begin(), pins.end());
    if (!m_rollout.SetPolicy(destination_policy_id, kPromotionThreshold, pin_list, err)) return false;
    if (m_rollout.Threshold(destination_policy_id) != kPromotionThreshold) return Fail(err, "BTX035_THRESHOLD");
    m_promoted_model = model_id;
    err.clear();
    return true;
}

bool LabJourney::Promoted(const std::string& model_id) const
{
    return !model_id.empty() && model_id == m_promoted_model;
}

bool LabJourney::Distribute(const std::string& realm, int64_t sequence, const std::string& body, std::string& err)
{
    if (m_paused) return Fail(err, "BTX035_PAUSED");
    return m_rollout.PublishChannel(realm, sequence, body, err);
}

int64_t LabJourney::Sequence(const std::string& realm) const
{
    return m_rollout.ChannelSequence(realm);
}

bool LabJourney::PinAttestors(const std::string& realm, int threshold, const std::vector<std::string>& pinned_ids, std::string& err)
{
    return m_rollout.SetPolicy(realm, threshold, pinned_ids, err);
}

bool LabJourney::RevokeAttestor(const std::string& realm, const std::string& attestor_id, std::string& err)
{
    const int before = m_rollout.Threshold(realm);
    if (!m_rollout.RevokeAttestor(realm, attestor_id, err)) return false;
    if (m_rollout.Threshold(realm) != before) return Fail(err, "BTX035_THRESHOLD");
    err.clear();
    return true;
}

int LabJourney::Threshold(const std::string& realm) const
{
    return m_rollout.Threshold(realm);
}

bool LabJourney::Quorum(const std::string& realm, const std::vector<std::string>& signer_ids) const
{
    return m_rollout.Quorum(realm, signer_ids);
}

bool LabJourney::AcceptRealm(const std::string& realm, const std::string& claimed_realm, std::string& err)
{
    return m_rollout.Attest(realm, "attestor", claimed_realm, err);
}

bool LabJourney::AcceptPiece(const std::string& expected_hash, const std::string& actual_hash, std::string& err) const
{
    if (expected_hash.empty() || expected_hash != actual_hash) return Fail(err, "BTX035_BYTE_HASH_MISMATCH");
    err.clear();
    return true;
}

bool LabJourney::ExportPrivateToPublic(const std::string& private_body, std::string& err) const
{
    (void)private_body;
    return Fail(err, "BTX035_REALM_EXPORT_DENIED");
}

std::string LabJourney::PublicExport() const
{
    return {};
}

bool LabJourney::AcceptDependency(const std::string& dependency_id, bool present, std::string& err) const
{
    if (dependency_id.empty() || !present) return Fail(err, "BTX035_DEPENDENCY_MISSING");
    err.clear();
    return true;
}

bool LabJourney::ReportEndpoint(const std::string& endpoint, bool offline, const std::string& reported, std::string& err)
{
    if (endpoint.empty()) return Fail(err, "BTX035_OBSERVE");
    if (offline && reported == "HEALTHY") return Fail(err, "BTX035_HEALTH");
    return m_rollout.Observe(endpoint, reported, err);
}

int LabJourney::HealthyCount() const
{
    return m_rollout.FleetStatus().healthy;
}

void LabJourney::Pause()
{
    m_paused = true;
    m_gate.Pause();
}

bool LabJourney::Paused() const
{
    return m_paused;
}

bool LabJourney::Advance(const std::string& realm, std::string& err)
{
    if (m_paused) return Fail(err, "BTX035_PAUSED");
    return m_rollout.AdvanceRing(realm, m_policy_hash, m_policy_hash, 0, err);
}

int64_t LabJourney::Ring(const std::string& realm) const
{
    return m_rollout.RingGeneration(realm);
}

bool LabJourney::RecordOfflineBundle(const std::string& bundle_id, const std::string& closure_id, std::string& err)
{
    if (bundle_id.empty() || closure_id.empty()) return Fail(err, "BTX035_BUNDLE");
    m_bundles[bundle_id] = closure_id;
    err.clear();
    return true;
}

bool LabJourney::RemoveIngress(std::string& err)
{
    m_ingress = false;
    err.clear();
    return true;
}

bool LabJourney::IngressPresent() const
{
    return m_ingress;
}

bool LabJourney::ResolveClosure(const std::string& bundle_id, std::string& closure_id, std::string& err) const
{
    closure_id.clear();
    const auto it = m_bundles.find(bundle_id);
    if (it == m_bundles.end()) return Fail(err, "BTX035_NOT_FOUND");
    closure_id = it->second;
    err.clear();
    return true;
}

bool LabJourney::ActivatePolicy(const std::string& policy_id, bool expired, std::string& err)
{
    if (policy_id.empty()) return Fail(err, "BTX035_POLICY");
    if (expired) return Fail(err, "BTX035_EXPIRED");
    m_active_policy = policy_id;
    err.clear();
    return true;
}

bool LabJourney::PolicyActive(const std::string& policy_id) const
{
    return !policy_id.empty() && policy_id == m_active_policy;
}

bool LabJourney::RestoreOlderBackup(const std::string& realm, int64_t backup_sequence, std::string& err)
{
    const int64_t current = m_rollout.ChannelSequence(realm);
    if (current < 0 || backup_sequence >= current) return Fail(err, "BTX035_ROLLBACK");
    const int64_t before = current;
    if (m_rollout.RestoreBackup(backup_sequence, current, err)) return Fail(err, "BTX035_ROLLBACK");
    if (m_rollout.ChannelSequence(realm) != before) return Fail(err, "BTX035_ROLLBACK");
    if (err != "BTX035_ROLLBACK") return Fail(err, "BTX035_ROLLBACK");
    return false;
}

} // namespace modelnet
