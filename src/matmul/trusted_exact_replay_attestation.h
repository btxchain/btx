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
 * validity, and are meaningful only to nodes explicitly configured to trust an
 * M-of-N signer set. The chain identifier MUST be that chain's genesis hash.
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

struct StoreConfig {
    uint256 chain_id{};
    uint256 replay_authority_context{};
    std::vector<CPubKey> trusted_signers{};
    size_t threshold{1};
    size_t max_blocks{4096};
    size_t max_attestations{16384};
    std::chrono::milliseconds ttl{std::chrono::hours{24}};
    std::optional<CKey> local_signer{};
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
};

[[nodiscard]] std::string_view AddResultName(AddResult result);

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
    size_t stored_blocks{0};
    size_t stored_attestations{0};
    size_t blocks_with_quorum{0};
};

/**
 * Thread-safe, bounded, in-memory trusted-attestation store.
 *
 * The store deliberately does not persist trust verdicts or alter consensus.
 * Its caller decides whether an operator-configured mirror may use quorum as a
 * substitute for local ExactReplay. Each bucket is keyed by both height and
 * hash, and each configured signer contributes at most one vote.
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
     * Sign an attested-fast-forward UTXO snapshot statement with the optional
     * local key. Does not store the signature; callers assemble manifests.
     */
    [[nodiscard]] std::optional<UtxoSnapshotSignature> SignUtxoSnapshot(
        const UtxoSnapshotStatement& statement) const;

    [[nodiscard]] bool HasQuorum(const uint256& block_hash,
                                 int32_t block_height) const;

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
    [[nodiscard]] const std::set<CPubKey>& TrustedSigners() const
    {
        return m_trusted_signers;
    }
    [[nodiscard]] std::optional<CPubKey> LocalSignerPubKey() const;

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
    void PruneExpiredLocked(Clock::time_point now);
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

    StoreConfig m_config;
    std::set<CPubKey> m_trusted_signers;

    mutable std::mutex m_mutex;
    std::condition_variable m_changed;
    std::map<BlockKey, Bucket> m_buckets;
    size_t m_attestation_count{0};
    StoreStats m_stats;
    bool m_durable_retention{false};
};

} // namespace matmul::trusted

#endif // BTX_MATMUL_TRUSTED_EXACT_REPLAY_ATTESTATION_H
