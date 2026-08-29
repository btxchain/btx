// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_TRUSTED_EXACT_REPLAY_ATTESTATION_H
#define BTX_MATMUL_TRUSTED_EXACT_REPLAY_ATTESTATION_H

#include <key.h>
#include <matmul/trusted_utxo_snapshot_attestation.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string_view>
#include <vector>

namespace matmul::trusted {

/**
 * Operator-trust sidecar for a successful MatMul v4 Profile 1 ExactReplay.
 *
 * These statements are not consensus proofs, do not change a block's hash or
 * validity, and are not CheckBlock / header objects. A pinned M-of-N set
 * (`-matmultrustedpubkey`) remains sufficient authority for CPU archives.
 * When open attestors are enabled, additional GPUs may speak; they count as
 * authority only after local admission on a hash that already has pin quorum.
 * The chain identifier MUST be that chain's genesis hash.
 */
struct ExactReplayStatement {
    static constexpr uint8_t CURRENT_VERSION{2};
    static constexpr uint8_t MATMUL_V4{4};
    static constexpr uint8_t PROFILE_1{1};

    uint8_t version{CURRENT_VERSION};
    uint256 chain_id{};
    uint256 block_hash{};
    int32_t block_height{-1};
    uint8_t matmul_major{MATMUL_V4};
    uint8_t profile{PROFILE_1};
    uint256 replay_authority_context{};

    SERIALIZE_METHODS(ExactReplayStatement, obj)
    {
        READWRITE(obj.version,
                  obj.chain_id,
                  obj.block_hash,
                  obj.block_height,
                  obj.matmul_major,
                  obj.profile);
        if (obj.version >= 2) {
            READWRITE(obj.replay_authority_context);
        } else {
            SER_READ(obj, obj.replay_authority_context.SetNull());
        }
    }

    friend bool operator==(const ExactReplayStatement&,
                           const ExactReplayStatement&) = default;
};

struct ExactReplayAttestation {
    ExactReplayStatement statement{};
    CPubKey signer{};
    std::vector<unsigned char> signature{};

    SERIALIZE_METHODS(ExactReplayAttestation, obj)
    {
        READWRITE(obj.statement, obj.signer, obj.signature);
    }

    friend bool operator==(const ExactReplayAttestation&,
                           const ExactReplayAttestation&) = default;
};

/** Double-SHA256 of a domain separator and the canonical V2 statement. */
[[nodiscard]] uint256 StatementHash(const ExactReplayStatement& statement);

/** Create a canonical compressed-secp256k1 ECDSA attestation. */
[[nodiscard]] std::optional<ExactReplayAttestation> SignStatement(
    const ExactReplayStatement& statement, const CKey& signer);

/**
 * Watchtower refutation: the signer asserts ExactReplay *failed* for this
 * statement. Same statement fields as a success attestation; different
 * domain. Not a consensus object. A pin-member refutation blocks open
 * quorum on that hash; pin quorum is unchanged (1-of-N pin still wins).
 */
struct ExactReplayRefutation {
    ExactReplayStatement statement{};
    CPubKey signer{};
    std::vector<unsigned char> signature{};

    SERIALIZE_METHODS(ExactReplayRefutation, obj)
    {
        READWRITE(obj.statement, obj.signer, obj.signature);
    }

    friend bool operator==(const ExactReplayRefutation&,
                           const ExactReplayRefutation&) = default;
};

[[nodiscard]] uint256 RefutationHash(const ExactReplayStatement& statement);

[[nodiscard]] std::optional<ExactReplayRefutation> SignRefutation(
    const ExactReplayStatement& statement, const CKey& signer);

/** Compiled (height, hash, log_root) pin. Not wired into chainparams until a
 *  log root is stable; same moral status as assumeutxo. */
struct CompiledAttestationLogPin {
    int32_t height{-1};
    uint256 block_hash{};
    uint256 log_root{};
    uint64_t tree_size{0};
};

struct AttestationLogHead {
    uint64_t tree_size{0};
    uint256 root{};
};

struct AttestationLogProof {
    uint64_t index{0};
    uint256 leaf{};
    uint256 root{};
    std::vector<uint256> branch{};
};

[[nodiscard]] uint256 ComputeAttestationLogRoot(
    const std::vector<uint256>& leaves);
[[nodiscard]] std::vector<uint256> ComputeAttestationLogBranch(
    const std::vector<uint256>& leaves, uint64_t index);
[[nodiscard]] bool VerifyAttestationLogInclusion(const AttestationLogProof& proof);

enum class VerifyResult : uint8_t {
    Valid,
    UnsupportedVersion,
    WrongChain,
    WrongBlock,
    WrongHeight,
    WrongMatMulContext,
    WrongReplayAuthorityContext,
    InvalidSigner,
    UntrustedSigner,
    InvalidSignature,
};

[[nodiscard]] std::string_view VerifyResultName(VerifyResult result);

/**
 * Verify every signed and contextual field against locally known block data.
 *
 * Requiring expected_hash and expected_height prevents an otherwise valid
 * signer from causing a store to associate an attestation with the wrong
 * block-index entry. trusted_signers must contain fully-valid compressed keys.
 */
[[nodiscard]] VerifyResult VerifyAttestation(
    const ExactReplayAttestation& attestation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_hash,
    int32_t expected_height,
    const std::set<CPubKey>& trusted_signers);

/**
 * Cryptographic and contextual checks only. Does not consult membership.
 * A valid-unpinned statement is a rumor until the local pin admits it.
 */
[[nodiscard]] VerifyResult VerifyAttestationCrypto(
    const ExactReplayAttestation& attestation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_hash,
    int32_t expected_height);

[[nodiscard]] VerifyResult VerifyRefutationCrypto(
    const ExactReplayRefutation& refutation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_hash,
    int32_t expected_height);

/** Open-quorum default: max(pin M, 2) so one newly-admitted key cannot
 *  replace the pin. Pass 0 in StoreConfig.open_threshold to use this. */
[[nodiscard]] constexpr size_t DefaultOpenThreshold(size_t pin_threshold)
{
    return pin_threshold > 2 ? pin_threshold : 2;
}

/** Directory / refute / log caps. 0 in StoreConfig uses these. */
inline constexpr size_t DEFAULT_MAX_ADMITTED_OPEN{256};
inline constexpr size_t DEFAULT_MAX_OPEN_SIGNED_HEIGHTS{4096};
inline constexpr size_t DEFAULT_MAX_OPEN_SIGNED_ENTRIES{4096};
inline constexpr size_t DEFAULT_MAX_OPEN_SIGNERS_PER_HEIGHT{256};
inline constexpr size_t DEFAULT_MAX_FROZEN_OPEN{4096};
inline constexpr size_t DEFAULT_MAX_REFUTATIONS{4096};
inline constexpr size_t DEFAULT_MAX_LOG_LEAVES{8192};
inline constexpr size_t DEFAULT_MAX_WINDOW_CHALLENGES{16};
/** Runtime + config blocklist cap. Emergency lists stay tiny. */
inline constexpr size_t DEFAULT_MAX_BLOCKED_SIGNERS{256};

/**
 * True when at least `threshold` pin members remain unblocked.
 * Constructor and runtime AddBlocklistedSigner refuse states that would
 * make this false (fail-closed: a CPU archive never starts or runs with
 * an M it cannot actually reach).
 */
[[nodiscard]] inline bool PinQuorumIsReachable(
    size_t unblocked_pin_members, size_t threshold) noexcept
{
    return threshold > 0 && unblocked_pin_members >= threshold;
}

struct StoreConfig {
    uint256 chain_id{};
    uint256 replay_authority_context{};
    std::vector<CPubKey> trusted_signers{};
    size_t threshold{1};
    size_t max_blocks{4096};
    size_t max_attestations{16384};
    std::chrono::milliseconds ttl{std::chrono::hours{24}};
    std::optional<CKey> local_signer{};
    /** When true, valid-unpinned statements are heard and keys that co-sign
     *  a pin-quorum hash are listed as admitted. They do not enter HasQuorum.
     *  Default false keeps unit tests closed. */
    bool open_attestors{false};
    /** Distinct pinned-or-admitted votes for the directory open-quorum
     *  signal. 0 = DefaultOpenThreshold. Not MatMul authority. */
    size_t open_threshold{0};
    size_t max_heard_attestations{4096};
    /** 0 = DEFAULT_MAX_ADMITTED_OPEN. Extra co-signers stay Heard. */
    size_t max_admitted_open{0};
    /** 0 = DEFAULT_MAX_OPEN_SIGNED_HEIGHTS. Oldest heights pruned. */
    size_t max_open_signed_heights{0};
    /** 0 = DEFAULT_MAX_OPEN_SIGNED_ENTRIES. Total (height,signer) pairs. */
    size_t max_open_signed_entries{0};
    /** 0 = DEFAULT_MAX_OPEN_SIGNERS_PER_HEIGHT. Tip-height Sybil cap. */
    size_t max_open_signers_per_height{0};
    /** 0 = DEFAULT_MAX_FROZEN_OPEN. Oldest frozen keys evicted. */
    size_t max_frozen_open{0};
    /** 0 = DEFAULT_MAX_REFUTATIONS. Oldest (height,hash) buckets pruned. */
    size_t max_refutations{0};
    /** 0 = DEFAULT_MAX_LOG_LEAVES. Oldest leaves dropped. */
    size_t max_log_leaves{0};
    /** 0 = DEFAULT_MAX_WINDOW_CHALLENGES. Oldest challenges dropped. */
    size_t max_window_challenges{0};
    /**
     * Config-forced attestation key blocklist. Overlap with trusted_signers
     * is legal and is the point: a still-listed pin member becomes inert.
     * Runtime RPC adds are stored separately and persist across restart.
     */
    std::vector<CPubKey> blocklist{};
};

enum class AddResult : uint8_t {
    Accepted,
    Duplicate,
    Capacity,
    UnsupportedVersion,
    WrongChain,
    WrongBlock,
    WrongHeight,
    WrongMatMulContext,
    WrongReplayAuthorityContext,
    InvalidSigner,
    UntrustedSigner,
    InvalidSignature,
    NoLocalSigner,
    /** Local signer already attested a different hash at this height. */
    HeightOccupied,
    /** Cryptographically valid, stored as directory, not authority. */
    Heard,
    /** Open key previously equivocated (same height, two hashes). */
    FrozenSigner,
    /** First observed open-key equivocation; key is now frozen. */
    Equivocation,
    /** Signer is on the operator attestation blocklist. */
    BlocklistedSigner,
};

[[nodiscard]] std::string_view AddResultName(AddResult result);

enum class BlocklistResult : uint8_t {
    Blocked,
    Duplicate,
    WouldDisablePinQuorum,
    LocalSigner,
    Invalid,
    Capacity,
};

[[nodiscard]] std::string_view BlocklistResultName(BlocklistResult result);

enum class WaitResult : uint8_t {
    Quorum,
    Timeout,
    Cancelled,
};

[[nodiscard]] std::string_view WaitResultName(WaitResult result);

struct StoreStats {
    uint64_t accepted{0};
    uint64_t duplicates{0};
    uint64_t rejected{0};
    uint64_t capacity_rejections{0};
    uint64_t evicted_blocks{0};
    uint64_t expired_blocks{0};
    uint64_t quorum_transitions{0};
    uint64_t waits{0};
    uint64_t wait_quorums{0};
    uint64_t wait_timeouts{0};
    uint64_t wait_cancellations{0};
    uint64_t heard{0};
    uint64_t equivocations{0};
    size_t stored_blocks{0};
    size_t stored_attestations{0};
    size_t blocks_with_quorum{0};
    size_t heard_attestations{0};
    size_t admitted_open{0};
    size_t frozen_open{0};
    size_t open_signed_heights{0};
    size_t open_signed_entries{0};
    size_t refutation_buckets{0};
    size_t log_leaves{0};
    size_t window_challenges{0};
};

/**
 * Thread-safe, bounded, in-memory trusted-attestation store.
 *
 * The store deliberately does not persist trust verdicts or alter consensus.
 * Its caller decides whether an operator-configured mirror may use quorum as a
 * substitute for local ExactReplay. Each bucket is keyed by both height and
 * hash, and each configured signer contributes at most one vote.
 *
 * HasQuorum is PinQuorum only (M-of-N of `-matmultrustedpubkey`). That is
 * the sole SkipExactReplay / signed-frontier / trusted-mirror authority.
 * Open attestors may speak and be listed after co-signing a pin-quorum
 * hash; they must not become MatMul PoW for CPU archives or consensus+pin
 * miners. Stolen open keys therefore cannot mint fake work for those nodes.
 */
class AttestationStore
{
public:
    explicit AttestationStore(StoreConfig config);

    AttestationStore(const AttestationStore&) = delete;
    AttestationStore& operator=(const AttestationStore&) = delete;

    [[nodiscard]] AddResult Add(const ExactReplayAttestation& attestation,
                                const uint256& expected_hash,
                                int32_t expected_height);

    /**
     * Sign with the optional configured local key, validate/store the result,
     * and optionally return it for P2P publication or RPC inspection.
     */
    [[nodiscard]] AddResult SignLocal(
        const uint256& block_hash,
        int32_t block_height,
        ExactReplayAttestation* produced = nullptr);

    /**
     * This node's own validated BlockDisconnected. If this process SignLocal'd
     * `disconnected_hash` at `height`, release that mint slot so the node can
     * re-mint the hash it now follows. Also drops open-directory entries for
     * that (height, hash) so a reorg is not treated as open-key equivocation.
     *
     * Call only from this process's chainstate (DisconnectTip /
     * BlockDisconnected). Inbound P2P / Add() of a competing hash must never
     * call this: that is the stolen-WIF jam the mint guard exists to stop.
     */
    bool NotifyActiveChainBlockDisconnected(int32_t height,
                                            const uint256& disconnected_hash);

    /**
     * Inverse of disconnect: the hash is on the active chain again, so its
     * pin quorum may occupy the mint slot once more.
     */
    void NotifyActiveChainBlockConnected(int32_t height,
                                         const uint256& connected_hash);

    /**
     * Operator recovery: erase local mint slots in [from_height, to_height]
     * inclusive, and the open-directory rows for those heights. Does not
     * delete stored attestations, does not accept a competing hash, and does
     * not skip the other_quorum stolen-WIF guard. Returns the number of mint
     * slots removed.
     */
    size_t ClearLocalMintSlots(int32_t from_height, int32_t to_height);

    /** Hash this process SignLocal'd at height, if the mint slot is held. */
    [[nodiscard]] std::optional<uint256> LocalMintedHash(int32_t height) const;

    /** Heights in [from_height, to_height] that currently hold a mint slot. */
    [[nodiscard]] std::vector<int32_t> LocalMintedHeights(
        int32_t from_height, int32_t to_height) const;

    /** True after NotifyActiveChainBlockDisconnected until the hash reconnects. */
    [[nodiscard]] bool IsOffActiveChain(int32_t height,
                                        const uint256& block_hash) const;

    /**
     * Sign an attested-fast-forward UTXO snapshot statement with the optional
     * local key. Does not store the signature; callers assemble manifests.
     */
    [[nodiscard]] std::optional<UtxoSnapshotSignature> SignUtxoSnapshot(
        const UtxoSnapshotStatement& statement) const;

    [[nodiscard]] bool HasQuorum(const uint256& block_hash,
                                 int32_t block_height) const;

    /**
     * Directory signal only. Never SkipExactReplay, never signed-frontier.
     * True when open attestors are enabled and enough pinned-or-admitted
     * unfrozen keys signed this hash, unless a pin member refuted it.
     */
    [[nodiscard]] bool HasOpenQuorum(const uint256& block_hash,
                                     int32_t block_height) const;

    /**
     * Evaluate pin quorum from a caller-supplied set (durable miss path).
     * Only cryptographically valid pin votes count.
     */
    [[nodiscard]] bool HasQuorumFromAttestations(
        const std::vector<ExactReplayAttestation>& attestations,
        const uint256& block_hash,
        int32_t block_height) const;

    [[nodiscard]] AddResult AddRefutation(
        const ExactReplayRefutation& refutation,
        const uint256& expected_hash,
        int32_t expected_height);

    /** Return all valid unique-signer attestations currently held. */
    [[nodiscard]] std::vector<ExactReplayAttestation> GetAttestations(
        const uint256& block_hash, int32_t block_height) const;

    /**
     * Snapshot every retained attestation (for durable archive flush).
     * Order is height/hash ascending; callers may rewrite a bounded disk file.
     */
    [[nodiscard]] std::vector<ExactReplayAttestation> ExportAll() const;

    /**
     * When true, wall-clock TTL pruning is disabled. Capacity eviction still
     * applies. Used when a durable datadir archive backs the store so a
     * restart cannot silently drop recent authority signatures.
     */
    void SetDurableRetention(bool durable);

    /**
     * Wait for quorum, cancellation, or timeout.
     *
     * cancel_requested is polled at a bounded interval even when no producer
     * notifies the store. A Quorum result can optionally return the exact
     * attestation set that satisfied the wait.
     */
    [[nodiscard]] WaitResult WaitForQuorum(
        const uint256& block_hash,
        int32_t block_height,
        std::chrono::milliseconds timeout,
        const std::function<bool()>& cancel_requested = {},
        std::vector<ExactReplayAttestation>* quorum = nullptr);

    void Erase(const uint256& block_hash, int32_t block_height);
    void PruneExpired();

    [[nodiscard]] StoreStats GetStats() const;
    [[nodiscard]] const uint256& ChainId() const { return m_config.chain_id; }
    [[nodiscard]] const uint256& ReplayAuthorityContext() const
    {
        return m_config.replay_authority_context;
    }
    [[nodiscard]] size_t Threshold() const { return m_config.threshold; }
    [[nodiscard]] size_t MaxBlocks() const { return m_config.max_blocks; }
    [[nodiscard]] size_t MaxAttestations() const
    {
        return m_config.max_attestations;
    }
    [[nodiscard]] size_t MaxHeardAttestations() const
    {
        return m_config.max_heard_attestations;
    }
    [[nodiscard]] size_t MaxAdmittedOpen() const
    {
        return m_config.max_admitted_open;
    }
    [[nodiscard]] size_t MaxOpenSignedHeights() const
    {
        return m_config.max_open_signed_heights;
    }
    [[nodiscard]] size_t MaxOpenSignedEntries() const
    {
        return m_config.max_open_signed_entries;
    }
    [[nodiscard]] size_t MaxFrozenOpen() const { return m_config.max_frozen_open; }
    [[nodiscard]] size_t MaxRefutations() const
    {
        return m_config.max_refutations;
    }
    [[nodiscard]] size_t MaxLogLeaves() const { return m_config.max_log_leaves; }
    [[nodiscard]] size_t MaxWindowChallenges() const
    {
        return m_config.max_window_challenges;
    }
    [[nodiscard]] const std::set<CPubKey>& TrustedSigners() const
    {
        return m_trusted_signers;
    }
    [[nodiscard]] std::optional<CPubKey> LocalSignerPubKey() const;
    [[nodiscard]] bool OpenAttestorsEnabled() const
    {
        return m_config.open_attestors;
    }
    [[nodiscard]] size_t OpenSignedHeightCount() const;
    [[nodiscard]] size_t OpenSignedEntryCount() const;
    [[nodiscard]] size_t OpenThreshold() const
    {
        return m_config.open_threshold;
    }
    [[nodiscard]] size_t MaxVotesPerBlock() const;
    [[nodiscard]] bool IsPinnedSigner(const CPubKey& pubkey) const;
    [[nodiscard]] bool IsAdmittedOpenSigner(const CPubKey& pubkey) const;
    [[nodiscard]] bool IsFrozenOpenSigner(const CPubKey& pubkey) const;
    [[nodiscard]] bool IsAuthoritySigner(const CPubKey& pubkey) const;
    [[nodiscard]] bool IsBlocked(const CPubKey& pubkey) const;
    [[nodiscard]] std::set<CPubKey> BlockedSigners() const;
    [[nodiscard]] std::set<CPubKey> ConfigBlockedSigners() const;
    [[nodiscard]] std::set<CPubKey> RuntimeBlockedSigners() const;
    [[nodiscard]] size_t UnblockedPinMembers() const;
    [[nodiscard]] bool PinQuorumReachable() const;
    /**
     * Manual emergency excision. Never auto-populated. Refuses without
     * applying when the add would leave fewer than M unblocked pin members,
     * or when the key is this process's local signer. No runtime remove:
     * unblocking a runtime add requires editing the persisted record.
     */
    [[nodiscard]] BlocklistResult AddBlocklistedSigner(const CPubKey& pubkey);
    /** Merge persisted runtime blocks. Returns false if a key would
     *  disable pin quorum, block the local signer, or overflow the cap. */
    [[nodiscard]] bool RestoreRuntimeBlocked(std::set<CPubKey> blocked);
    [[nodiscard]] std::set<CPubKey> AdmittedOpenSigners() const;
    [[nodiscard]] std::set<CPubKey> FrozenOpenSigners() const;
    [[nodiscard]] std::vector<ExactReplayAttestation> GetHeard(
        const uint256& block_hash, int32_t block_height) const;
    [[nodiscard]] std::vector<ExactReplayAttestation> ExportHeard() const;
    [[nodiscard]] std::vector<ExactReplayRefutation> GetRefutations(
        const uint256& block_hash, int32_t block_height) const;
    [[nodiscard]] AttestationLogHead LogHead() const;
    [[nodiscard]] std::optional<AttestationLogProof> LogInclusionProof(
        const uint256& statement_hash) const;
    void RestoreOpenAttestors(std::set<CPubKey> admitted,
                              std::set<CPubKey> frozen);
    void AdmitOpenSigner(const CPubKey& pubkey);

    struct WindowReplayChallenge {
        int32_t height{-1};
        uint256 block_hash{};
    };
    void ChallengeWindowReplay(int32_t height, const uint256& block_hash);
    [[nodiscard]] std::vector<WindowReplayChallenge> WindowReplayChallenges() const;
    [[nodiscard]] bool WindowReplayAnswered(const CPubKey& pubkey) const;

private:
    using Clock = std::chrono::steady_clock;

    struct BlockKey {
        int32_t height{-1};
        uint256 hash{};

        friend bool operator<(const BlockKey& a, const BlockKey& b)
        {
            return a.height < b.height ||
                   (a.height == b.height && a.hash < b.hash);
        }
    };

    struct Bucket {
        Clock::time_point updated{};
        std::map<CPubKey, ExactReplayAttestation> attestations{};
        bool quorum_counted{false};
    };

    [[nodiscard]] static AddResult ToAddResult(VerifyResult result);
    [[nodiscard]] size_t PinVotesLocked(const Bucket& bucket) const;
    [[nodiscard]] size_t AuthorityVotesLocked(const Bucket& bucket) const;
    [[nodiscard]] bool PinQuorumLocked(const Bucket& bucket) const;
    [[nodiscard]] bool OpenQuorumLocked(const BlockKey& key,
                                        const Bucket& bucket) const;
    [[nodiscard]] bool HasQuorumLocked(const BlockKey& key,
                                       const Bucket& bucket) const;
    [[nodiscard]] bool WouldReachQuorumLocked(const BlockKey& key,
                                              const CPubKey& signer) const;
    [[nodiscard]] bool IsBlockedLocked(const CPubKey& pubkey) const;
    [[nodiscard]] size_t UnblockedPinMembersLocked() const;
    void DropHeardLocked(const CPubKey& pubkey);
    void AdmitOpenLocked(const CPubKey& pubkey);
    void FreezeOpenLocked(const CPubKey& pubkey);
    void AdmitHeardOnHashLocked(const BlockKey& key, Clock::time_point now);
    [[nodiscard]] AddResult StoreHeardLocked(
        const ExactReplayAttestation& attestation, Clock::time_point now);
    void AppendLogLeafLocked(const uint256& leaf);
    void PruneExpiredLocked(Clock::time_point now);
    void PruneExpiredDirectoryLocked(Clock::time_point now);
    void PruneOpenDirectoryLocked();
    [[nodiscard]] size_t OpenSignedEntryCountLocked() const;
    void RefreshPinRefutedLocked(const BlockKey& key);
    void CapRefutationsLocked();
    void CapFrozenOpenLocked();
    void CapOffActiveChainLocked();
    void ReleaseOpenSignedMatchingHashLocked(int32_t height,
                                             const uint256& block_hash);
    [[nodiscard]] bool OccupyingCompetingQuorumLocked(
        int32_t block_height, const uint256& block_hash) const;
    /**
     * Make room for one additional signature.
     *
     * A partial bucket may never evict completed authority. When the completed
     * buckets fill the configured capacity, one partial bucket may be staged
     * beyond the base limits (at most threshold - 1 signatures). Only the
     * signature that completes that staged bucket may replace the oldest
     * completed quorum.
     */
    [[nodiscard]] bool MakeRoomLocked(
        const BlockKey& incoming, bool incoming_reaches_quorum);
    void EraseLocked(std::map<BlockKey, Bucket>::iterator it, bool expired);
    [[nodiscard]] size_t QuorumBlockCountLocked() const;
    [[nodiscard]] std::vector<ExactReplayAttestation> GetAttestationsLocked(
        const BlockKey& key) const;

    struct HeardKey {
        int32_t height{-1};
        uint256 hash{};
        CPubKey signer{};

        friend bool operator<(const HeardKey& a, const HeardKey& b)
        {
            if (a.height != b.height) return a.height < b.height;
            if (a.hash != b.hash) return a.hash < b.hash;
            return a.signer < b.signer;
        }
    };

    StoreConfig m_config;
    std::set<CPubKey> m_trusted_signers;
    std::set<CPubKey> m_blocked_config;

    mutable std::mutex m_mutex;
    std::set<CPubKey> m_blocked;
    std::condition_variable m_changed;
    std::map<BlockKey, Bucket> m_buckets;
    std::map<HeardKey, ExactReplayAttestation> m_heard;
    std::map<HeardKey, Clock::time_point> m_heard_updated;
    std::set<CPubKey> m_admitted_open;
    std::set<CPubKey> m_frozen_open;
    std::deque<CPubKey> m_frozen_open_order;
    std::map<int32_t, std::map<CPubKey, uint256>> m_open_signed_at_height;
    std::map<int32_t, Clock::time_point> m_open_signed_updated;
    std::map<BlockKey, std::map<CPubKey, ExactReplayRefutation>> m_refutations;
    std::map<BlockKey, Clock::time_point> m_refutation_updated;
    std::set<BlockKey> m_pin_refuted;
    std::vector<uint256> m_log_leaves;
    std::vector<WindowReplayChallenge> m_window_challenges;
    size_t m_attestation_count{0};
    StoreStats m_stats;
    bool m_durable_retention{false};
    /** Heights this process SignLocal'd. Relayed copies of local_pk do not count. */
    std::map<int32_t, uint256> m_local_minted_hash_by_height;
    /**
     * Hashes this node's own validated reorg disconnected. other_quorum skips
     * these so a legitimate chain switch can re-mint; inbound MMATTEST cannot
     * insert here.
     */
    std::set<BlockKey> m_off_active_chain;
};

} // namespace matmul::trusted

#endif // BTX_MATMUL_TRUSTED_EXACT_REPLAY_ATTESTATION_H
