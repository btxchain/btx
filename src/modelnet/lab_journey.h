// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_JOURNEY_H
#define BITCOIN_MODELNET_LAB_JOURNEY_H

#include <modelnet/action_authority.h>
#include <modelnet/model_admission.h>
#include <modelnet/realm_channel.h>
#include <modelnet/research_graph.h>
#include <modelnet/training_profile.h>
#include <modelnet/workspace_journal.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * In-process journey harness. It keeps research, fixture, replica, promotion,
 * and offline-bundle state in this process. It does not open a socket, spend
 * a wallet, or mine.
 *
 * The four-step run is the reference fixture from training_profile. It is a
 * fixed byte loop, not a production model.
 */
class LabJourney {
public:
    LabJourney() = default;

    /** Research roots never carry a wallet flag. */
    bool WalletSpendAllowed() const;
    bool HasWalletFlag(const std::string& root_id) const;

    /**
     * E2E-001. wallet_flag must be false. A true flag fails BTX035_SCOPE_DENIED
     * and does not store a root.
     */
    bool CreateResearchRoot(bool wallet_flag, std::string& root_id, std::string& err);
    bool OfferObjective(const std::string& objective_id, std::string& err);
    bool DiscoverObjective(const std::string& objective_id, std::string& err);
    bool SelectObjective(const std::string& root_id, const std::string& objective_id, std::string& err);
    bool RecordSourceSnapshot(const std::string& root_id, const std::string& snapshot_id, std::string& err);
    bool RecordData(const std::string& root_id, const std::string& data_id, std::string& err);
    bool OpenWorkspaceGeneration(const std::string& root_id, uint64_t& generation, std::string& err);
    bool PublishContribution(const std::string& root_id, const std::string& contribution_id, std::string& err);
    /** Drops the author from the peer set and leaves the contribution stored. */
    bool RemoveAuthor(const std::string& root_id, std::string& err);
    bool FindContribution(const std::string& contribution_id) const;
    bool AuthorPresent(const std::string& root_id) const;
    /** Second participant continues only after the contribution's author was removed. */
    bool ContinueParticipant(const std::string& participant_id, const std::string& contribution_id, std::string& err);

    bool SelectedObjective(const std::string& root_id, std::string& objective_id) const;
    bool SourceSnapshot(const std::string& root_id, std::string& snapshot_id) const;
    bool DataId(const std::string& root_id, std::string& data_id) const;
    bool Continued(const std::string& participant_id, std::string& contribution_id) const;

    /**
     * E2E-002 fixture. Records the four reference transitions.
     * An altered data cursor or optimizer fails BTX035_RNG.
     * An altered checkpoint fails BTX035_ID_MISMATCH.
     * AdmitFixture with fewer than two distinct roots fails BTX035_REPLAY.
     */
    bool RecordFixtureTransitions(std::string& err);
    uint64_t FixtureSteps() const;
    bool FixtureStep(uint64_t index, uint64_t& start_inclusive, uint64_t& end_exclusive) const;
    bool FixtureCovers() const;
    std::string FixtureDataCursor() const;
    std::string FixtureOptimizer() const;
    std::string FixtureCheckpoint() const;
    bool AcceptFixtureBinding(const std::string& data_cursor, const std::string& optimizer, const std::string& checkpoint,
                              std::string& err) const;
    AdmissionResult AdmitFixture(const std::vector<std::string>& independent_roots) const;

    /**
     * E2E-003. Reconstruction reads retained replica ids after origins are down.
     * An empty retained set or an empty request fails BTX035_NOT_FOUND.
     * A hook string fails BTX035_SCOPE_DENIED.
     * A prompt that requests wallet spend fails BTX035_PERMIT.
     * A stolen key id used as owner fails BTX035_IDENTITY_REVOKED.
     */
    bool MarkOriginsDown(std::string& err);
    bool RetainReplica(const std::string& replica_id, std::string& err);
    bool Reconstruct(const std::vector<std::string>& replica_ids, std::string& replica_id, std::string& err);
    bool AcceptHook(const std::string& hook, std::string& err) const;
    bool AcceptSpendPrompt(const std::string& prompt, std::string& err);
    bool MarkKeyStolen(const std::string& key_id, std::string& err);
    bool AcceptOwner(const std::string& owner_id, const std::string& key_id, std::string& err) const;

    /**
     * E2E-004. Promotion of a public admitted model id requires a destination
     * policy id and at least two pinned attestation ids. The required threshold
     * is 2. A missing policy fails BTX035_POLICY. Fewer pins fail
     * BTX035_QUORUM_NOT_MET. An id that was not admitted fails
     * BTX035_ADMISSION_REQUIRED. Distribute accepts a channel sequence that
     * increases. An older sequence fails BTX035_ROLLBACK.
     */
    static constexpr int kPromotionThreshold = 2;
    bool NotePublicAdmitted(const std::string& model_id, std::string& err);
    bool Promote(const std::string& model_id, const std::string& destination_policy_id,
                 const std::vector<std::string>& pinned_attestation_ids, std::string& err);
    bool Promoted(const std::string& model_id) const;
    bool Distribute(const std::string& realm, int64_t sequence, const std::string& body, std::string& err);
    int64_t Sequence(const std::string& realm) const;

    /**
     * E2E-005. RevokeAttestor leaves the stored threshold unchanged.
     * Old channel sequence: BTX035_ROLLBACK.
     * Wrong realm: BTX035_REALM.
     * Tampered piece: BTX035_BYTE_HASH_MISMATCH.
     * Private-to-public export: BTX035_REALM_EXPORT_DENIED.
     * Missing dependency: BTX035_DEPENDENCY_MISSING.
     * Offline endpoint reported HEALTHY: BTX035_HEALTH.
     * Pause makes Advance and later Distribute fail BTX035_PAUSED.
     */
    bool PinAttestors(const std::string& realm, int threshold, const std::vector<std::string>& pinned_ids, std::string& err);
    bool RevokeAttestor(const std::string& realm, const std::string& attestor_id, std::string& err);
    int Threshold(const std::string& realm) const;
    bool Quorum(const std::string& realm, const std::vector<std::string>& signer_ids) const;
    bool AcceptRealm(const std::string& realm, const std::string& claimed_realm, std::string& err);
    bool AcceptPiece(const std::string& expected_hash, const std::string& actual_hash, std::string& err) const;
    bool ExportPrivateToPublic(const std::string& private_body, std::string& err) const;
    std::string PublicExport() const;
    bool AcceptDependency(const std::string& dependency_id, bool present, std::string& err) const;
    bool ReportEndpoint(const std::string& endpoint, bool offline, const std::string& reported, std::string& err);
    int HealthyCount() const;
    void Pause();
    bool Paused() const;
    bool Advance(const std::string& realm, std::string& err);
    int64_t Ring(const std::string& realm) const;

    /**
     * E2E-006. An offline bundle recorded before ingress removal still resolves
     * its last closure. An expired policy fails BTX035_EXPIRED and does not
     * become active. An older backup fails BTX035_ROLLBACK and leaves the
     * channel sequence unchanged.
     */
    bool RecordOfflineBundle(const std::string& bundle_id, const std::string& closure_id, std::string& err);
    bool RemoveIngress(std::string& err);
    bool IngressPresent() const;
    bool ResolveClosure(const std::string& bundle_id, std::string& closure_id, std::string& err) const;
    bool ActivatePolicy(const std::string& policy_id, bool expired, std::string& err);
    bool PolicyActive(const std::string& policy_id) const;
    bool RestoreOlderBackup(const std::string& realm, int64_t backup_sequence, std::string& err);

private:
    struct RootRow {
        bool wallet{false};
        std::string objective;
        std::string snapshot_id;
        std::string data_id;
        bool workspace_open{false};
        uint64_t generation{0};
        std::string contribution_id;
    };

    ResearchBook m_research;
    WorkspaceBook m_workspace;
    RealmRollout m_rollout;
    ActionGate m_gate;

    std::map<std::string, RootRow> m_roots;
    std::set<std::string> m_offered;
    std::set<std::string> m_discovered;
    std::set<std::string> m_removed_authors;
    std::map<std::string, std::string> m_contribution_author;
    std::map<std::string, Digest48> m_contribution_topic;
    std::map<std::string, Digest48> m_contribution_digest;
    std::map<std::string, std::string> m_continued;

    FixtureResult m_fixture;
    bool m_fixture_recorded{false};
    std::string m_checkpoint;

    bool m_origins_down{false};
    std::set<std::string> m_replicas;
    std::set<std::string> m_stolen_keys;

    std::set<std::string> m_admitted;
    std::string m_promoted_model;

    bool m_paused{false};
    std::string m_policy_hash{"lab-journey-policy"};

    std::map<std::string, std::string> m_bundles;
    bool m_ingress{true};
    std::string m_active_policy;

    RootRow* FindMutable(const std::string& root_id);
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_JOURNEY_H
