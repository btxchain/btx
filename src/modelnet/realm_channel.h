// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_REALM_CHANNEL_H
#define BITCOIN_MODELNET_REALM_CHANNEL_H

#include <cstdint>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** Counts of endpoints actually passed to Observe. Omitted endpoints are absent. */
struct FleetCounts {
    int healthy{0};
    int unhealthy{0};
    int unknown{0};
};

/** Model-side realm channel and rollout.
 *  Local trust choice only. This object does not link a monetary attestor store,
 *  validation flag, BanMan, or AddrMan.
 */
class RealmRollout {
public:
    /** Store pinned ids and a fixed threshold. threshold < 1 fails BTX035_THRESHOLD.
     *  A later call cannot change the stored threshold.
     */
    bool SetPolicy(const std::string& realm, int threshold, const std::vector<std::string>& pinned_ids, std::string& err);

    /** Add id to the revoked set. Does not change the stored threshold. */
    bool RevokeAttestor(const std::string& realm, const std::string& id, std::string& err);

    /** True only when unique pinned, non-revoked signer ids are >= the original threshold. */
    bool Quorum(const std::string& realm, const std::vector<std::string>& signer_ids) const;

    /** Stored threshold, or 0 when this realm has no policy. */
    int Threshold(const std::string& realm) const;

    /** claimed_realm must equal realm. A mismatch fails BTX035_REALM. */
    bool Attest(const std::string& realm, const std::string& signer, const std::string& claimed_realm, std::string& err);

    /** First sequence is 0. After that the next sequence is exactly last+1.
     *  Lower fails BTX035_ROLLBACK, equal fails BTX035_STALE, a gap fails BTX035_GAP.
     */
    bool PublishChannel(const std::string& realm, int64_t sequence, const std::string& body_hash, std::string& err);

    /** Accepted channel sequence, or -1 when this realm has not accepted one. */
    int64_t ChannelSequence(const std::string& realm) const;

    /** Body hash of the accepted channel update, or empty when none is accepted. */
    std::string ChannelBody(const std::string& realm) const;

    /** Accept only HEALTHY, UNHEALTHY, or UNKNOWN. Any other string fails BTX035_OBSERVE.
     *  An endpoint that was not passed in is not created. UNKNOWN endpoints are kept.
     */
    bool Observe(const std::string& endpoint, const std::string& state, std::string& err);

    /** Count each observed endpoint once, by its latest accepted state. */
    FleetCounts FleetStatus() const;

    /** Advance one ring generation when the policy hashes match and unhealthy == 0.
     *  Differing hashes fail BTX035_POLICY. unhealthy != 0 fails BTX035_HEALTH.
     */
    bool AdvanceRing(const std::string& realm,
                     const std::string& frozen_policy_hash,
                     const std::string& current_policy_hash,
                     int unhealthy,
                     std::string& err);

    /** Ring generations successfully advanced for realm. Starts at 0. */
    int64_t RingGeneration(const std::string& realm) const;

    /** Record an offline bundle. Does not advance the ring or the channel sequence. */
    bool ActivateOffline(int64_t bundle_generation, int64_t channel_sequence, std::string& err);

    int64_t OfflineBundleGeneration() const;
    int64_t OfflineChannelSequence() const;
    bool OfflineRecorded() const;

    /** Always fails BTX035_OFFLINE. Offline activation cannot advance the ring. */
    bool AdvanceRingFromOffline(std::string& err) const;

    /** One realm or channel key as reloaded from the lab directory. */
    struct SavedRealm {
        std::string key;
        bool policy{false};
        int threshold{0};
        std::vector<std::string> pins;
        std::vector<std::string> revoked;
        bool has_channel{false};
        int64_t sequence{-1};
        std::string body;
    };

    /** Copy policy, revocation, and channel sequence. Does not include secrets. */
    std::vector<SavedRealm> SavedRealms() const;

    /** Install a previously saved realm. A bad threshold or empty key fails closed. */
    bool RestoreRealm(const SavedRealm& saved, std::string& err);

    std::vector<std::pair<std::string, std::string>> SavedFleet() const;
    std::vector<std::pair<std::string, std::string>> SavedEndpoints() const;

    /** Staged generation names in the order they were first staged. */
    std::vector<std::string> StagedGenerations() const;

    /** Reinstall staged names, then the active and previous pointers. */
    bool RestoreGenerations(const std::vector<std::string>& ordered, const std::string& active, const std::string& previous, std::string& err);

    /** Write a deterministic text bundle for realm. The first line is BTX035-OFFLINE-1,
     *  then realm, threshold, pinned ids, revoked ids, channel sequence and body hash.
     *  A realm with no policy fails BTX035_REALM. An unwritable path fails BTX035_BUNDLE.
     *  Does not advance the ring or the channel sequence.
     */
    bool WriteOfflineBundle(const std::filesystem::path& path, const std::string& realm, std::string& err) const;

    /** Reload policy, revocation and channel fields from a bundle into this object.
     *  expected_realm must equal the realm in the file; a mismatch fails BTX035_REALM.
     *  A truncated or malformed file fails BTX035_BUNDLE. Ring generation is unchanged.
     */
    bool ReadOfflineBundle(const std::filesystem::path& path, const std::string& expected_realm, std::string& err);

    /** backup_sequence < current_sequence fails BTX035_ROLLBACK and keeps the current sequence. */
    bool RestoreBackup(int64_t backup_sequence, int64_t current_sequence, std::string& err);

    /** Sequence preserved by RestoreBackup, or 0 before any restore call. */
    int64_t CurrentSequence() const;

    /** Record the two promotion authorities. Approval is a separate step. */
    bool RecordPromotion(const std::string& source_exporter, const std::string& destination_approver, std::string& err);

    /** Fails BTX035_AUTHORITY when the recorded authorities are equal or either is empty. */
    bool ApprovePromotion(std::string& err) const;

    std::string SourceExporter() const;
    std::string DestinationApprover() const;

    /** Deployment lifecycle, separate from Observe's HEALTHY/UNHEALTHY/UNKNOWN fleet states.
     *  Accepted states are exactly DISCOVERED, FETCHING, STAGED, VERIFIED, CANARY, ACTIVE,
     *  PAUSED, FAILED, ROLLED_BACK, and UNKNOWN. Any other string fails BTX035_OBSERVE.
     */
    bool ObserveEndpoint(const std::string& endpoint, const std::string& state, std::string& err);

    /** Latest accepted deployment state, or empty when this endpoint has none. */
    std::string EndpointState(const std::string& endpoint) const;

    /** May set FETCHING or STAGED only. VERIFIED and ACTIVE are rejected with BTX035_OBSERVE
     *  and the stored state is left unchanged.
     */
    bool MarkTransportComplete(const std::string& endpoint, const std::string& state, std::string& err);

    /** Separate from transport completion. Sets VERIFIED. */
    bool MarkVerified(const std::string& endpoint, std::string& err);

    /** Sets ACTIVE only from VERIFIED or CANARY. Any other state fails BTX035_HEALTH. */
    bool MarkActive(const std::string& endpoint, std::string& err);

    /** Record an immutable generation directory name. path is created only when non-empty;
     *  the name itself is not created on disk. A later stage of the same name keeps the
     *  original order.
     */
    bool StageGeneration(const std::string& directory_name, const std::filesystem::path& path, std::string& err);

    /** Swap the active pointer only when admission_ok and abi_ok are both true.
     *  Activating an older staged generation fails BTX035_ROLLBACK and leaves the pointer.
     *  Readers already bound to the previous generation stay there.
     */
    bool ActivateGeneration(const std::string& directory_name, bool admission_ok, bool abi_ok, std::string& err);

    bool GenerationStaged(const std::string& directory_name) const;
    std::string ActiveGeneration() const;
    std::string PreviousGeneration() const;

    /** Bind reader to an already staged generation. Activation does not move readers. */
    bool RetainReader(const std::string& reader, const std::string& directory_name, std::string& err);

    /** Readers still bound to directory_name, in sorted order. */
    std::vector<std::string> ReadersOf(const std::string& directory_name) const;

    /** Install a whole-store snapshot at its own channel sequence.
     *  A sequence lower than the accepted channel fails BTX035_ROLLBACK and leaves the
     *  channel sequence and body unchanged. The stored sequence becomes the snapshot
     *  sequence exactly; this does not invent a later one.
     */
    bool ReplaceLocalSnapshot(const std::string& realm, int64_t snapshot_sequence, const std::string& body_hash, std::string& err);

    /** Freeze the sorted unique device ids. The returned root is SHA-384 over the UTF-8
     *  lines of those ids joined by a newline and no trailing newline. A different set
     *  after freeze fails BTX035_POLICY and leaves StatusRoot unchanged.
     */
    std::string FreezeTargetSet(const std::vector<std::string>& device_ids, std::string& err);

    /** Frozen target root, or empty before a successful freeze. */
    std::string StatusRoot() const;

    /** After freeze, an id outside the frozen set is late enrollment and does not change StatusRoot. */
    bool AddDevice(const std::string& device_id, std::string& err);

    std::vector<std::string> LateEnrollment() const;
    bool FrozenTarget(const std::string& device_id) const;

    /** Declared archive bytes above this fail BTX035_LIMIT_EXCEEDED before the body is read. */
    static constexpr uint64_t kPortableArchiveBudget = 32ull * 1024ull * 1024ull;

    /** Sorted uncompressed POSIX ustar of regular files and directories only, plus a
     *  top-level "manifest" file whose lines are the relative payload paths.
     *  Absolute paths, "..", symlinks, and non-file/non-directory nodes fail
     *  BTX035_PATH_UNSAFE and the destination is not opened.
     */
    bool WritePortableArchive(const std::filesystem::path& directory, const std::filesystem::path& destination, std::string& err) const;

    /** Read a portable archive. Rejects the same unsafe entries with BTX035_PATH_UNSAFE.
     *  On failure relative_paths is empty. On success it is the manifest's relative paths.
     */
    bool ReadPortableArchive(const std::filesystem::path& archive, std::vector<std::string>& relative_paths, std::string& err) const;

private:
    struct RealmState {
        bool policy_set{false};
        int threshold{0};
        std::set<std::string> pinned;
        std::set<std::string> revoked;
        bool has_channel{false};
        int64_t channel_sequence{0};
        std::string body_hash;
    };

    std::map<std::string, RealmState> m_realms;
    std::map<std::string, std::string> m_observed;
    std::map<std::string, int64_t> m_ring;

    bool m_offline{false};
    int64_t m_offline_bundle{0};
    int64_t m_offline_channel{0};

    bool m_has_sequence{false};
    int64_t m_current_sequence{0};

    std::string m_source_exporter;
    std::string m_destination_approver;

    std::map<std::string, std::string> m_endpoint_state;

    struct GenerationState {
        int64_t order{0};
    };
    std::map<std::string, GenerationState> m_generations;
    int64_t m_next_generation_order{0};
    std::string m_active_generation;
    std::string m_previous_generation;
    std::map<std::string, std::set<std::string>> m_generation_readers;

    bool m_targets_frozen{false};
    std::set<std::string> m_frozen_targets;
    std::string m_status_root;
    std::set<std::string> m_late_enrollment;
};

/** Model-plane fetch budget. Global, per-site, and per-device byte caps.
 *  This object does not link BanMan, AddrMan, or monetary validation.
 */
class BandwidthBudget {
public:
    bool SetCaps(uint64_t global_bytes, uint64_t per_site_bytes, uint64_t per_device_bytes, std::string& err);
    bool SetDeploymentPaused(bool paused, std::string& err);
    bool WindowPaused() const;

    /** Admit bytes only when the deployment window is open and every cap still holds.
     *  A paused window fails BTX035_PAUSED. A cap that would be exceeded fails
     *  BTX035_LIMIT_EXCEEDED and admits nothing.
     */
    bool AdmitFetch(const std::string& site, const std::string& device, uint64_t bytes, std::string& err);

    uint64_t AdmittedGlobal() const;
    uint64_t AdmittedSite(const std::string& site) const;
    uint64_t AdmittedDevice(const std::string& device) const;

private:
    bool m_caps_set{false};
    bool m_paused{false};
    uint64_t m_global_cap{0};
    uint64_t m_site_cap{0};
    uint64_t m_device_cap{0};
    uint64_t m_global{0};
    std::map<std::string, uint64_t> m_site;
    std::map<std::string, uint64_t> m_device;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_REALM_CHANNEL_H
