// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/trusted_utxo_snapshot_attestation.h>

#include <hash.h>

#include <limits>
#include <string>

namespace matmul::trusted {
namespace {

constexpr char HASH_DOMAIN[] = "BTX_TRUSTED_UTXO_SNAPSHOT_ATTESTATION_V2";
constexpr uint64_t MAX_SIGNED_SNAPSHOT_FILE_SIZE{512ULL << 30};
constexpr uint32_t MIN_SIGNED_SNAPSHOT_CHUNK_SIZE{64U << 10};
constexpr uint32_t MAX_SIGNED_SNAPSHOT_CHUNK_SIZE{4U << 20};

bool IsCanonicalSigner(const CPubKey& pubkey)
{
    return pubkey.IsCompressed() && pubkey.IsFullyValid();
}

// Strict DER without a script sighash byte. Same gate as ExactReplay
// attestations so sidecar signatures stay canonical across trust surfaces.
bool IsStrictDERSignature(const std::vector<unsigned char>& signature)
{
    if (signature.size() < 8 || signature.size() > CPubKey::SIGNATURE_SIZE) {
        return false;
    }
    if (signature[0] != 0x30 ||
        signature[1] != signature.size() - 2 ||
        signature[2] != 0x02) {
        return false;
    }
    const size_t len_r{signature[3]};
    if (len_r == 0 || 5 + len_r >= signature.size()) return false;
    if (signature[4] & 0x80) return false;
    if (len_r > 1 && signature[4] == 0 &&
        !(signature[5] & 0x80)) {
        return false;
    }
    const size_t s_tag{4 + len_r};
    if (signature[s_tag] != 0x02) return false;
    const size_t len_s{signature[s_tag + 1]};
    const size_t s_value{s_tag + 2};
    if (len_s == 0 || s_value + len_s != signature.size()) return false;
    if (signature[s_value] & 0x80) return false;
    if (len_s > 1 && signature[s_value] == 0 &&
        !(signature[s_value + 1] & 0x80)) {
        return false;
    }
    return len_r + len_s + 6 == signature.size();
}

UtxoSnapshotVerifyResult VerifyStatementFields(
    const UtxoSnapshotStatement& statement,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_block_hash,
    int32_t expected_height,
    const uint256& expected_hash_serialized,
    uint64_t expected_coins_count,
    uint64_t expected_chain_tx_count,
    const uint256& expected_shielded_state_commitment)
{
    if (statement.version != UtxoSnapshotStatement::CURRENT_VERSION) {
        return UtxoSnapshotVerifyResult::UnsupportedVersion;
    }
    if (statement.chain_id != expected_chain_id) {
        return UtxoSnapshotVerifyResult::WrongChain;
    }
    if (statement.block_hash != expected_block_hash) {
        return UtxoSnapshotVerifyResult::WrongBlock;
    }
    if (statement.block_height < 0 ||
        statement.block_height != expected_height) {
        return UtxoSnapshotVerifyResult::WrongHeight;
    }
    if (statement.hash_serialized != expected_hash_serialized) {
        return UtxoSnapshotVerifyResult::WrongHashSerialized;
    }
    if (statement.coins_count != expected_coins_count) {
        return UtxoSnapshotVerifyResult::WrongCoinsCount;
    }
    if (statement.m_chain_tx_count != expected_chain_tx_count) {
        return UtxoSnapshotVerifyResult::WrongChainTxCount;
    }
    if (expected_shielded_state_commitment.IsNull() ||
        statement.shielded_state_commitment.IsNull()) {
        return UtxoSnapshotVerifyResult::MissingShieldedCommitment;
    }
    if (statement.shielded_state_commitment !=
        expected_shielded_state_commitment) {
        return UtxoSnapshotVerifyResult::WrongShieldedCommitment;
    }
    if (statement.replay_authority_context !=
        expected_replay_authority_context) {
        return UtxoSnapshotVerifyResult::WrongReplayAuthorityContext;
    }
    if (statement.snapshot_file_size == 0 ||
        statement.snapshot_file_size > MAX_SIGNED_SNAPSHOT_FILE_SIZE ||
        statement.snapshot_file_hash.IsNull() ||
        statement.snapshot_chunk_size < MIN_SIGNED_SNAPSHOT_CHUNK_SIZE ||
        statement.snapshot_chunk_size > MAX_SIGNED_SNAPSHOT_CHUNK_SIZE) {
        return UtxoSnapshotVerifyResult::InvalidSnapshotGeometry;
    }
    const uint64_t expected_chunks{
        1 + ((statement.snapshot_file_size - 1) /
             statement.snapshot_chunk_size)};
    if (expected_chunks > std::numeric_limits<uint32_t>::max() ||
        statement.snapshot_chunk_count != expected_chunks) {
        return UtxoSnapshotVerifyResult::InvalidSnapshotGeometry;
    }
    return UtxoSnapshotVerifyResult::Valid;
}

} // namespace

uint256 UtxoSnapshotStatementHash(const UtxoSnapshotStatement& statement)
{
    HashWriter hasher;
    hasher << std::string{HASH_DOMAIN};
    hasher << statement;
    return hasher.GetHash();
}

std::optional<UtxoSnapshotSignature> SignUtxoSnapshotStatement(
    const UtxoSnapshotStatement& statement, const CKey& signer)
{
    if (!signer.IsValid() || !signer.IsCompressed()) return std::nullopt;
    const CPubKey pubkey{signer.GetPubKey()};
    if (!IsCanonicalSigner(pubkey)) return std::nullopt;

    UtxoSnapshotSignature attestation;
    attestation.signer = pubkey;
    if (!signer.Sign(UtxoSnapshotStatementHash(statement),
                     attestation.signature)) {
        return std::nullopt;
    }
    return attestation;
}

UtxoSnapshotVerifyResult VerifyUtxoSnapshotSignature(
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
    const std::set<CPubKey>& trusted_signers)
{
    const UtxoSnapshotVerifyResult fields{VerifyStatementFields(
        statement, expected_chain_id, expected_replay_authority_context,
        expected_block_hash, expected_height, expected_hash_serialized,
        expected_coins_count, expected_chain_tx_count,
        expected_shielded_state_commitment)};
    if (fields != UtxoSnapshotVerifyResult::Valid) return fields;

    if (!IsCanonicalSigner(attestation.signer)) {
        return UtxoSnapshotVerifyResult::InvalidSigner;
    }
    if (trusted_signers.count(attestation.signer) == 0) {
        return UtxoSnapshotVerifyResult::UntrustedSigner;
    }
    if (!IsStrictDERSignature(attestation.signature) ||
        !CPubKey::CheckLowS(attestation.signature) ||
        !attestation.signer.Verify(UtxoSnapshotStatementHash(statement),
                                   attestation.signature)) {
        return UtxoSnapshotVerifyResult::InvalidSignature;
    }
    return UtxoSnapshotVerifyResult::Valid;
}

UtxoSnapshotVerifyResult VerifyUtxoSnapshotManifest(
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
    size_t threshold)
{
    if (manifest.signatures.empty()) {
        return UtxoSnapshotVerifyResult::EmptyManifest;
    }
    if (threshold == 0 || threshold > trusted_signers.size()) {
        return UtxoSnapshotVerifyResult::ThresholdNotMet;
    }

    const UtxoSnapshotVerifyResult fields{VerifyStatementFields(
        manifest.statement, expected_chain_id,
        expected_replay_authority_context, expected_block_hash,
        expected_height, expected_hash_serialized, expected_coins_count,
        expected_chain_tx_count, expected_shielded_state_commitment)};
    if (fields != UtxoSnapshotVerifyResult::Valid) return fields;

    std::set<CPubKey> seen;
    for (const auto& attestation : manifest.signatures) {
        const UtxoSnapshotVerifyResult verified{VerifyUtxoSnapshotSignature(
            manifest.statement, attestation, expected_chain_id,
            expected_replay_authority_context, expected_block_hash,
            expected_height, expected_hash_serialized, expected_coins_count,
            expected_chain_tx_count, expected_shielded_state_commitment,
            trusted_signers)};
        if (verified != UtxoSnapshotVerifyResult::Valid) return verified;
        if (!seen.insert(attestation.signer).second) {
            return UtxoSnapshotVerifyResult::DuplicateSigner;
        }
    }
    if (seen.size() < threshold) {
        return UtxoSnapshotVerifyResult::ThresholdNotMet;
    }
    return UtxoSnapshotVerifyResult::Valid;
}

UtxoSnapshotVerifyResult VerifyUtxoSnapshotManifestSelfConsistent(
    const UtxoSnapshotManifest& manifest,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const std::set<CPubKey>& trusted_signers,
    size_t threshold)
{
    return VerifyUtxoSnapshotManifest(
        manifest, expected_chain_id, expected_replay_authority_context,
        manifest.statement.block_hash, manifest.statement.block_height,
        manifest.statement.hash_serialized, manifest.statement.coins_count,
        manifest.statement.m_chain_tx_count,
        manifest.statement.shielded_state_commitment, trusted_signers,
        threshold);
}

std::string_view UtxoSnapshotVerifyResultName(
    UtxoSnapshotVerifyResult result)
{
    switch (result) {
    case UtxoSnapshotVerifyResult::Valid: return "valid";
    case UtxoSnapshotVerifyResult::UnsupportedVersion:
        return "unsupported-version";
    case UtxoSnapshotVerifyResult::WrongChain: return "wrong-chain";
    case UtxoSnapshotVerifyResult::WrongBlock: return "wrong-block";
    case UtxoSnapshotVerifyResult::WrongHeight: return "wrong-height";
    case UtxoSnapshotVerifyResult::WrongHashSerialized:
        return "wrong-hash-serialized";
    case UtxoSnapshotVerifyResult::WrongCoinsCount: return "wrong-coins-count";
    case UtxoSnapshotVerifyResult::WrongChainTxCount:
        return "wrong-chain-tx-count";
    case UtxoSnapshotVerifyResult::MissingShieldedCommitment:
        return "missing-shielded-commitment";
    case UtxoSnapshotVerifyResult::WrongShieldedCommitment:
        return "wrong-shielded-commitment";
    case UtxoSnapshotVerifyResult::WrongReplayAuthorityContext:
        return "wrong-replay-authority-context";
    case UtxoSnapshotVerifyResult::InvalidSnapshotGeometry:
        return "invalid-snapshot-geometry";
    case UtxoSnapshotVerifyResult::InvalidSigner: return "invalid-signer";
    case UtxoSnapshotVerifyResult::UntrustedSigner: return "untrusted-signer";
    case UtxoSnapshotVerifyResult::InvalidSignature: return "invalid-signature";
    case UtxoSnapshotVerifyResult::DuplicateSigner: return "duplicate-signer";
    case UtxoSnapshotVerifyResult::ThresholdNotMet: return "threshold-not-met";
    case UtxoSnapshotVerifyResult::EmptyManifest: return "empty-manifest";
    }
    return "unknown";
}

} // namespace matmul::trusted
