// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_TRUSTED_UTXO_SNAPSHOT_ATTESTATION_H
#define BTX_MATMUL_TRUSTED_UTXO_SNAPSHOT_ATTESTATION_H

#include <key.h>
#include <pubkey.h>
#include <serialize.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <set>
#include <string_view>
#include <vector>

namespace matmul::trusted {

/**
 * Operator-trust binding for a UTXO-set snapshot used by attested fast-forward.
 *
 * This is not a consensus proof and is meaningful only to nodes that already
 * configure matmulvalidation=trusted with an M-of-N signer set. The chain
 * identifier MUST be that chain's genesis hash. hash_serialized is the
 * hash_serialized_3 UTXO commitment; shielded_state_commitment is the same
 * pin dumptxoutset emits for AssumeutxoData.
 */
struct UtxoSnapshotStatement {
    static constexpr uint8_t CURRENT_VERSION{1};

    uint8_t version{CURRENT_VERSION};
    uint256 chain_id{};
    uint256 block_hash{};
    int32_t block_height{-1};
    uint256 hash_serialized{};
    uint64_t coins_count{0};
    uint64_t m_chain_tx_count{0};
    uint256 shielded_state_commitment{};
    uint256 replay_authority_context{};

    SERIALIZE_METHODS(UtxoSnapshotStatement, obj)
    {
        READWRITE(obj.version,
                  obj.chain_id,
                  obj.block_hash,
                  obj.block_height,
                  obj.hash_serialized,
                  obj.coins_count,
                  obj.m_chain_tx_count,
                  obj.shielded_state_commitment,
                  obj.replay_authority_context);
    }

    friend bool operator==(const UtxoSnapshotStatement&,
                           const UtxoSnapshotStatement&) = default;
};

struct UtxoSnapshotSignature {
    CPubKey signer{};
    std::vector<unsigned char> signature{};

    SERIALIZE_METHODS(UtxoSnapshotSignature, obj)
    {
        READWRITE(obj.signer, obj.signature);
    }

    friend bool operator==(const UtxoSnapshotSignature&,
                           const UtxoSnapshotSignature&) = default;
};

/**
 * File/RPC payload: one statement plus M unique-signer signatures over it.
 * P2P distribution is intentionally out of scope for v1; this structure is the
 * hook a future GETUTXOATTEST/UTXOATTEST path would reuse.
 */
struct UtxoSnapshotManifest {
    UtxoSnapshotStatement statement{};
    std::vector<UtxoSnapshotSignature> signatures{};

    SERIALIZE_METHODS(UtxoSnapshotManifest, obj)
    {
        READWRITE(obj.statement, obj.signatures);
    }

    friend bool operator==(const UtxoSnapshotManifest&,
                           const UtxoSnapshotManifest&) = default;
};

/** Double-SHA256 of a domain separator and the canonical statement. */
[[nodiscard]] uint256 UtxoSnapshotStatementHash(
    const UtxoSnapshotStatement& statement);

[[nodiscard]] std::optional<UtxoSnapshotSignature> SignUtxoSnapshotStatement(
    const UtxoSnapshotStatement& statement, const CKey& signer);

enum class UtxoSnapshotVerifyResult : uint8_t {
    Valid,
    UnsupportedVersion,
    WrongChain,
    WrongBlock,
    WrongHeight,
    WrongHashSerialized,
    WrongCoinsCount,
    WrongChainTxCount,
    MissingShieldedCommitment,
    WrongShieldedCommitment,
    WrongReplayAuthorityContext,
    InvalidSigner,
    UntrustedSigner,
    InvalidSignature,
    DuplicateSigner,
    ThresholdNotMet,
    EmptyManifest,
};

[[nodiscard]] std::string_view UtxoSnapshotVerifyResultName(
    UtxoSnapshotVerifyResult result);

/**
 * Verify one signature against expected statement fields and the configured
 * trusted signer set. Does not enforce threshold by itself.
 */
[[nodiscard]] UtxoSnapshotVerifyResult VerifyUtxoSnapshotSignature(
    const UtxoSnapshotStatement& statement,
    const UtxoSnapshotSignature& attestation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_block_hash,
    int32_t expected_height,
    const uint256& expected_hash_serialized,
    uint64_t expected_coins_count,
    uint64_t expected_chain_tx_count,
    const uint256& expected_shielded_state_commitment,
    const std::set<CPubKey>& trusted_signers);

/**
 * Fail-closed quorum check: every signature must verify, signers must be
 * unique and trusted, and the distinct-signer count must meet threshold.
 * expected_* fields must match the statement (and later the loaded snapshot).
 */
[[nodiscard]] UtxoSnapshotVerifyResult VerifyUtxoSnapshotManifest(
    const UtxoSnapshotManifest& manifest,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_block_hash,
    int32_t expected_height,
    const uint256& expected_hash_serialized,
    uint64_t expected_coins_count,
    uint64_t expected_chain_tx_count,
    const uint256& expected_shielded_state_commitment,
    const std::set<CPubKey>& trusted_signers,
    size_t threshold);

/**
 * Verify the manifest against its own statement fields (no external hash yet).
 * Used when checking signature quorum before opening the coins file.
 */
[[nodiscard]] UtxoSnapshotVerifyResult VerifyUtxoSnapshotManifestSelfConsistent(
    const UtxoSnapshotManifest& manifest,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const std::set<CPubKey>& trusted_signers,
    size_t threshold);

} // namespace matmul::trusted

#endif // BTX_MATMUL_TRUSTED_UTXO_SNAPSHOT_ATTESTATION_H
