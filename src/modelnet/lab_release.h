// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_RELEASE_H
#define BITCOIN_MODELNET_LAB_RELEASE_H

#include <span.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

/** Announcement and query caps from NET-003. */
inline constexpr size_t kMaxAnnouncementRecords = 32;
inline constexpr size_t kMaxAnnouncementTopics = 16;
inline constexpr int kMaxAnnouncementHops = 4;
inline constexpr int64_t kAnnouncementValidityMs = 600000;
inline constexpr int kQueryFanoutDefault = 4;
inline constexpr int kQueryFanoutMax = 8;

/**
 * BuildManifest binds six 96-lowercase-hex ids.
 * Money amounts are not part of this record.
 *
 * ManifestBindingDigest is SHA-384 of those six ids concatenated with no
 * separator, in this order: source_snapshot_id, dependency_lock_id,
 * environment_id, recipe_id, output_digest, test_digest.
 */
struct BuildManifest {
    std::string source_snapshot_id;
    std::string dependency_lock_id;
    std::string environment_id;
    std::string recipe_id;
    std::string output_digest;
    std::string test_digest;
    bool origin_account_ok{false};
    bool pq_attestation_ok{false};
    bool release_authority_ok{false};
    bool anti_rollback_ok{false};
    bool compatibility_ok{false};
};

/** Lowercase hex SHA-384 of the six ids concatenated. See BuildManifest. */
std::string ManifestBindingDigest(const BuildManifest& manifest);

/**
 * True when output_digest and test_digest both equal ManifestBindingDigest.
 * The preimage contains both fields, so this is a SHA-384 fixed point.
 */
bool DigestFieldsMatchBinding(const BuildManifest& manifest);

/**
 * Fails BTX035_BUILD when any of the six ids is empty or not 96 lowercase hex.
 * Fails BTX035_BUILD when origin_account_ok is the only true flag and the
 * digest fields do not match ManifestBindingDigest.
 */
bool VerifyManifest(const BuildManifest& manifest, std::string& err);

/** False when VerifyManifest fails. Installation is not allowed otherwise. */
bool InstallAllowed(const BuildManifest& manifest, std::string& err);

enum class PlatformStatus {
    TESTABLE,
    BLOCKED,
    PASS,
};

struct PlatformEntry {
    std::string name;
    PlatformStatus status;
};

/**
 * Linux and macOS are TESTABLE. Windows is BLOCKED.
 * There is no Windows runner here. This never returns PASS for windows.
 */
std::vector<PlatformEntry> PlatformMatrix();

struct MeasurementReport {
    std::string snapshot_id;
    int64_t cold_ms{0};
    int64_t warm_ms{0};
    uint64_t bytes_downloaded{0};
    double rehydration{0};
    int64_t journal_ms{0};
    double verify_per_s{0};
    int64_t rebuild_ms{0};
    int64_t rollout_ms{0};
};

/** Fails BTX035_BUILD when the two reports claim different snapshot ids. */
bool RequireSameSnapshot(const MeasurementReport& left, const MeasurementReport& right, std::string& err);

/**
 * Migration inventory. Money amount, balance, wallet, and chainstate fields are absent.
 * money_mutation true fails BTX035_SCOPE_DENIED.
 */
struct MigrationPlan {
    std::string commit_id;
    std::string dirty_diff_digest;
    std::string untracked_hash;
    std::vector<std::string> binary_ids;
    std::string config_id;
    std::string storage_root_name;
    bool money_mutation{false};
};

bool AcceptMigrationPlan(const MigrationPlan& plan, std::string& err);

/**
 * Cutover stops model-plane writers only after backup_recorded is true.
 * monetary_stop is never set true. After success, money_unchanged is true.
 */
struct CutoverState {
    bool backup_recorded{false};
    bool stop_writers{false};
    bool money_unchanged{false};
    bool monetary_stop{false};
};

/** Requires backup_recorded before stop_writers. Does not set monetary_stop. */
bool BackupThenCutover(CutoverState& state, std::string& err);

/** True when money_unchanged is set, which a successful cutover does. */
bool VerifyAfterCutover(const CutoverState& state);

struct AttestorStatement {
    std::string attestor_id;
    std::string promotion_id;
    std::string destination_realm;
    std::string policy_id;
    std::string closure_root;
};

/**
 * Model-side attestation store. Separate from any monetary type.
 * Stores realm, policy epoch, revocation ids, and attestation ids.
 * TouchesMonetaryConsensus() is false. Revocation does not lower the threshold.
 */
class ModelAttestationStore {
public:
    void SetRealm(const std::string& realm);
    std::string Realm() const;
    void SetPolicyEpoch(uint64_t epoch);
    uint64_t PolicyEpoch() const;
    void SetThreshold(int threshold);
    int Threshold() const;
    void AddRevocation(const std::string& id);
    bool Revoked(const std::string& id) const;
    void AddAttestation(const std::string& id);
    bool HasAttestation(const std::string& id) const;

    /** Always false. This store does not touch monetary consensus. */
    bool TouchesMonetaryConsensus() const;

    /**
     * Every remaining eligible attestor must agree on
     * (promotion_id, destination_realm, policy_id, closure_root).
     * One disagreement fails BTX035_ATTEST.
     * A missing eligible attestor fails BTX035_THRESHOLD.
     * Revoked ids leave the eligible set. The required count stays Threshold().
     * If remaining eligible < Threshold(), fail BTX035_THRESHOLD.
     */
    bool ApprovePromotion(const std::string& promotion_id, const std::string& destination_realm,
                          const std::string& policy_id, const std::string& closure_root,
                          const std::vector<std::string>& eligible_ids,
                          const std::vector<AttestorStatement>& statements, std::string& err) const;

private:
    std::string m_realm;
    uint64_t m_policy_epoch{0};
    int m_threshold{0};
    std::set<std::string> m_revoked;
    std::set<std::string> m_attestations;
};

/** Delegated trust still checks signatures. Always true. */
bool DelegatedTrustStillChecksSignatures();

/** Always false, with err BTX035_SIGNATURE. Delegation does not skip a signature. */
bool SkipSignatureBecauseDelegated(std::string& err);

/**
 * Requires a promotion manifest id, a source export authorization id, and a
 * different destination approver id. Equal approvers fail BTX035_AUTHORITY.
 */
bool CrossRealmImport(const std::string& promotion_manifest_id, const std::string& source_export_authorization_id,
                      const std::string& destination_approver_id, std::string& err);

/**
 * Realm id is lowercase hex SHA-384 of the ASCII string "BTX/035/Realm/v1",
 * a NUL byte, then network_id, founder_key_id, and nonce concatenated.
 * Nonce must be 64 lowercase hex (32 bytes). On failure id is left unchanged
 * and err is BTX035_REALM.
 */
bool RealmId(const std::string& network_id, const std::string& founder_key_id, const std::string& nonce,
             std::string& id, std::string& err);

/** Ingress key ids. public_acquisition and private_promotion must differ. */
struct Ingress {
    std::string public_acquisition;
    std::string private_promotion;
};

/** Equal or empty key ids fail BTX035_AUTHORITY. */
bool AcceptIngress(const Ingress& ingress, std::string& err);

/** Ingress keys are not wallet keys. Always false. */
bool SharesKeyWithWallet();

/**
 * Direct edges only. Trust is not transitive.
 * The pair (public_publisher, model) is never stored: public trust does not
 * imply model trust. Any other pair is false until AddEdge records it.
 */
class TrustGraph {
public:
    /** Refuses public_publisher -> model. Other pairs are recorded. */
    bool AddEdge(const std::string& from, const std::string& to);
    bool TrustTransitive(const std::string& from, const std::string& to) const;

private:
    std::set<std::pair<std::string, std::string>> m_edges;
};

struct PathRead {
    std::string path;
    std::vector<unsigned char> bytes;
    std::string err;
};

/** Names only. Byte payloads are not part of the listing. */
class PinnedTree {
public:
    void AddName(const std::string& name);
    const std::vector<std::string>& Names() const;
    void PutBytes(const std::string& path, const std::vector<unsigned char>& bytes);

private:
    friend std::vector<PathRead> ReadMissing(const PinnedTree& tree, const std::vector<std::string>& paths);

    std::vector<std::string> m_names;
    std::map<std::string, std::vector<unsigned char>> m_bytes;
};

/**
 * A missing path yields BTX035_MISSING and empty bytes.
 * A sibling path that is present still returns its bytes. One miss does not block the other.
 */
std::vector<PathRead> ReadMissing(const PinnedTree& tree, const std::vector<std::string>& paths);

/** True when the final path segment is dependency.manifest. */
bool IsDependencyManifest(const std::string& path);

/** Dependency manifests first, then other files. Order within each group is preserved. */
std::vector<std::string> PrefetchOrder(const std::vector<std::string>& paths);

/**
 * True when protected_profile and (events >= 1024 or elapsed_ms >= 1000).
 * A non-protected profile returns false at those thresholds.
 */
bool JournalCheckpointDue(uint64_t events, int64_t elapsed_ms, bool protected_profile);

/** "protected" or "ordinary". A non-protected profile is not labeled protected. */
const char* ProfileLabel(bool protected_profile);

/** A consequential git ref with an empty signature fails BTX035_SIGNATURE. */
bool AcceptConsequentialGitRef(const std::string& signature, std::string& err);

/** All three must be non-empty. An empty field fails BTX035_MISSING. */
bool WorkerStart(const std::string& head, const std::string& diff_hash, const std::string& untracked_hash,
                 std::string& err);

/** Fetched external research prompts are untrusted. Always false. */
bool ExternalPromptTrusted();

/**
 * native symbol, call path, unit test, and integration test must all be non-empty.
 * A test name starting with "grep" fails BTX035_TEST. Empty names fail BTX035_TEST.
 */
bool SliceComplete(const std::string& native_symbol, const std::string& call_path, const std::string& unit_test,
                   const std::string& integration_test, std::string& err);

/**
 * Fails BTX035_CLAIM when text contains "release qualified" and any assurance
 * dimension is false.
 */
bool ReleaseClaim(const std::string& text, Span<const bool> assurance, std::string& err);

/**
 * Fails BTX035_LIMIT_EXCEEDED when record ids, topics, hops, validity, or
 * query fanout exceed the NET-003 caps. The caps themselves are accepted.
 */
bool CheckAnnouncement(size_t record_ids, size_t topics, int hops, int64_t validity_ms, int query_fanout,
                       std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_RELEASE_H
