// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/trusted_exact_replay_attestation.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace matmul::trusted {
namespace {

constexpr char HASH_DOMAIN[] = "BTX_TRUSTED_EXACT_REPLAY_ATTESTATION_V2";
constexpr auto WAIT_POLL_INTERVAL = std::chrono::milliseconds{25};

bool IsCanonicalSigner(const CPubKey& pubkey)
{
    return pubkey.IsCompressed() && pubkey.IsFullyValid();
}

// Strict DER without a script sighash byte. CPubKey::Verify deliberately uses
// Bitcoin's historical lax DER parser, so sidecar signatures need this
// independent canonical-encoding gate before verification.
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

} // namespace

uint256 StatementHash(const ExactReplayStatement& statement)
{
    HashWriter hasher;
    hasher << std::string{HASH_DOMAIN};
    hasher << statement;
    return hasher.GetHash();
}

std::optional<ExactReplayAttestation> SignStatement(
    const ExactReplayStatement& statement, const CKey& signer)
{
    if (!signer.IsValid() || !signer.IsCompressed()) return std::nullopt;
    const CPubKey pubkey{signer.GetPubKey()};
    if (!IsCanonicalSigner(pubkey)) return std::nullopt;

    ExactReplayAttestation attestation;
    attestation.statement = statement;
    attestation.signer = pubkey;
    if (!signer.Sign(StatementHash(statement), attestation.signature)) {
        return std::nullopt;
    }
    return attestation;
}

VerifyResult VerifyAttestation(
    const ExactReplayAttestation& attestation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_hash,
    int32_t expected_height,
    const std::set<CPubKey>& trusted_signers)
{
    const auto& statement{attestation.statement};
    if (statement.version != ExactReplayStatement::CURRENT_VERSION) {
        return VerifyResult::UnsupportedVersion;
    }
    if (statement.chain_id != expected_chain_id) return VerifyResult::WrongChain;
    if (statement.block_hash != expected_hash) return VerifyResult::WrongBlock;
    if (statement.block_height < 0 ||
        statement.block_height != expected_height) {
        return VerifyResult::WrongHeight;
    }
    if (statement.matmul_major != ExactReplayStatement::MATMUL_V4 ||
        statement.profile != ExactReplayStatement::PROFILE_1) {
        return VerifyResult::WrongMatMulContext;
    }
    if (statement.replay_authority_context !=
        expected_replay_authority_context) {
        return VerifyResult::WrongReplayAuthorityContext;
    }
    if (!IsCanonicalSigner(attestation.signer)) {
        return VerifyResult::InvalidSigner;
    }
    if (trusted_signers.count(attestation.signer) == 0) {
        return VerifyResult::UntrustedSigner;
    }
    if (!IsStrictDERSignature(attestation.signature) ||
        !CPubKey::CheckLowS(attestation.signature) ||
        !attestation.signer.Verify(StatementHash(statement),
                                   attestation.signature)) {
        return VerifyResult::InvalidSignature;
    }
    return VerifyResult::Valid;
}

std::string_view VerifyResultName(VerifyResult result)
{
    switch (result) {
    case VerifyResult::Valid: return "valid";
    case VerifyResult::UnsupportedVersion: return "unsupported-version";
    case VerifyResult::WrongChain: return "wrong-chain";
    case VerifyResult::WrongBlock: return "wrong-block";
    case VerifyResult::WrongHeight: return "wrong-height";
    case VerifyResult::WrongMatMulContext: return "wrong-matmul-context";
    case VerifyResult::WrongReplayAuthorityContext:
        return "wrong-replay-authority-context";
    case VerifyResult::InvalidSigner: return "invalid-signer";
    case VerifyResult::UntrustedSigner: return "untrusted-signer";
    case VerifyResult::InvalidSignature: return "invalid-signature";
    }
    return "unknown";
}

std::string_view AddResultName(AddResult result)
{
    switch (result) {
    case AddResult::Accepted: return "accepted";
    case AddResult::Duplicate: return "duplicate";
    case AddResult::Capacity: return "capacity";
    case AddResult::UnsupportedVersion: return "unsupported-version";
    case AddResult::WrongChain: return "wrong-chain";
    case AddResult::WrongBlock: return "wrong-block";
    case AddResult::WrongHeight: return "wrong-height";
    case AddResult::WrongMatMulContext: return "wrong-matmul-context";
    case AddResult::WrongReplayAuthorityContext:
        return "wrong-replay-authority-context";
    case AddResult::InvalidSigner: return "invalid-signer";
    case AddResult::UntrustedSigner: return "untrusted-signer";
    case AddResult::InvalidSignature: return "invalid-signature";
    case AddResult::NoLocalSigner: return "no-local-signer";
    case AddResult::HeightOccupied: return "height-occupied";
    }
    return "unknown";
}

std::string_view WaitResultName(WaitResult result)
{
    switch (result) {
    case WaitResult::Quorum: return "quorum";
    case WaitResult::Timeout: return "timeout";
    case WaitResult::Cancelled: return "cancelled";
    }
    return "unknown";
}

AttestationStore::AttestationStore(StoreConfig config)
    : m_config{std::move(config)}
{
    if (m_config.chain_id.IsNull()) {
        throw std::invalid_argument{
            "trusted ExactReplay chain identifier must be non-null"};
    }
    if (m_config.replay_authority_context.IsNull()) {
        throw std::invalid_argument{
            "trusted ExactReplay replay authority context must be non-null"};
    }
    if (m_config.trusted_signers.empty()) {
        throw std::invalid_argument{
            "trusted ExactReplay signer set must not be empty"};
    }
    for (const auto& signer : m_config.trusted_signers) {
        if (!IsCanonicalSigner(signer)) {
            throw std::invalid_argument{
                "trusted ExactReplay signers must be valid compressed keys"};
        }
        if (!m_trusted_signers.insert(signer).second) {
            throw std::invalid_argument{
                "trusted ExactReplay signer set contains a duplicate"};
        }
    }
    if (m_config.threshold == 0 ||
        m_config.threshold > m_trusted_signers.size()) {
        throw std::invalid_argument{
            "trusted ExactReplay threshold must be between one and N"};
    }
    if (m_config.max_blocks == 0 ||
        m_config.max_attestations < m_config.threshold) {
        throw std::invalid_argument{
            "trusted ExactReplay store capacity is below quorum capacity"};
    }
    if (m_config.max_blocks == std::numeric_limits<size_t>::max() ||
        m_config.threshold - 1 >
            std::numeric_limits<size_t>::max() -
                m_config.max_attestations) {
        throw std::invalid_argument{
            "trusted ExactReplay store staging capacity overflows"};
    }
    if (m_config.ttl <= std::chrono::milliseconds::zero()) {
        throw std::invalid_argument{
            "trusted ExactReplay store TTL must be positive"};
    }
    if (m_config.local_signer.has_value()) {
        const auto& key{*m_config.local_signer};
        if (!key.IsValid() || !key.IsCompressed() ||
            m_trusted_signers.count(key.GetPubKey()) == 0) {
            throw std::invalid_argument{
                "local ExactReplay signer must be a configured compressed key"};
        }
    }
}

AddResult AttestationStore::ToAddResult(VerifyResult result)
{
    switch (result) {
    case VerifyResult::Valid: return AddResult::Accepted;
    case VerifyResult::UnsupportedVersion:
        return AddResult::UnsupportedVersion;
    case VerifyResult::WrongChain: return AddResult::WrongChain;
    case VerifyResult::WrongBlock: return AddResult::WrongBlock;
    case VerifyResult::WrongHeight: return AddResult::WrongHeight;
    case VerifyResult::WrongMatMulContext:
        return AddResult::WrongMatMulContext;
    case VerifyResult::WrongReplayAuthorityContext:
        return AddResult::WrongReplayAuthorityContext;
    case VerifyResult::InvalidSigner: return AddResult::InvalidSigner;
    case VerifyResult::UntrustedSigner: return AddResult::UntrustedSigner;
    case VerifyResult::InvalidSignature: return AddResult::InvalidSignature;
    }
    return AddResult::InvalidSignature;
}

AddResult AttestationStore::Add(
    const ExactReplayAttestation& attestation,
    const uint256& expected_hash,
    int32_t expected_height)
{
    const VerifyResult verified{VerifyAttestation(
        attestation, m_config.chain_id, m_config.replay_authority_context,
        expected_hash, expected_height, m_trusted_signers)};
    if (verified != VerifyResult::Valid) {
        std::lock_guard lock{m_mutex};
        ++m_stats.rejected;
        return ToAddResult(verified);
    }

    const BlockKey key{expected_height, expected_hash};
    const auto now{Clock::now()};
    {
        std::lock_guard lock{m_mutex};
        PruneExpiredLocked(now);
        const auto existing_bucket{m_buckets.find(key)};
        if (existing_bucket != m_buckets.end() &&
            existing_bucket->second.attestations.count(attestation.signer) !=
                0) {
            ++m_stats.duplicates;
            return AddResult::Duplicate;
        }
        // Add() stores signatures that already exist (P2P, disk, historical
        // dual-attest). Refusing a local-key second hash here would brick
        // recovery from a past dual-sign already on the network. Minting a
        // new local signature is SignLocal / SignAuthoritative.
        const size_t existing_signatures{
            existing_bucket == m_buckets.end()
                ? 0
                : existing_bucket->second.attestations.size()};
        const bool incoming_reaches_quorum{
            existing_signatures < m_config.threshold &&
            existing_signatures + 1 >= m_config.threshold};
        if (!MakeRoomLocked(key, incoming_reaches_quorum)) {
            ++m_stats.rejected;
            ++m_stats.capacity_rejections;
            return AddResult::Capacity;
        }

        auto [bucket_it, inserted]{
            m_buckets.try_emplace(key, Bucket{now, {}, false})};
        Bucket& bucket{bucket_it->second};
        bucket.updated = now;
        bucket.attestations.emplace(attestation.signer, attestation);
        ++m_attestation_count;
        ++m_stats.accepted;
        if (!bucket.quorum_counted &&
            bucket.attestations.size() >= m_config.threshold) {
            bucket.quorum_counted = true;
            ++m_stats.quorum_transitions;
        }
        (void)inserted;
    }
    m_changed.notify_all();
    return AddResult::Accepted;
}

AddResult AttestationStore::SignLocal(
    const uint256& block_hash,
    int32_t block_height,
    ExactReplayAttestation* produced)
{
    if (!m_config.local_signer.has_value()) {
        std::lock_guard lock{m_mutex};
        ++m_stats.rejected;
        return AddResult::NoLocalSigner;
    }
    {
        std::lock_guard lock{m_mutex};
        const CPubKey local_pk{m_config.local_signer->GetPubKey()};
        for (auto it = m_buckets.lower_bound(BlockKey{block_height, uint256{}});
             it != m_buckets.end() && it->first.height == block_height; ++it) {
            if (it->first.hash == block_hash) continue;
            const bool local_signed{
                it->second.attestations.count(local_pk) != 0};
            const bool other_quorum{
                it->second.attestations.size() >= m_config.threshold};
            if (local_signed || other_quorum) {
                ++m_stats.rejected;
                return AddResult::HeightOccupied;
            }
        }
    }
    ExactReplayStatement statement;
    statement.chain_id = m_config.chain_id;
    statement.block_hash = block_hash;
    statement.block_height = block_height;
    statement.replay_authority_context =
        m_config.replay_authority_context;
    auto attestation{SignStatement(statement, *m_config.local_signer)};
    if (!attestation.has_value()) {
        std::lock_guard lock{m_mutex};
        ++m_stats.rejected;
        return AddResult::InvalidSigner;
    }
    const AddResult result{Add(*attestation, block_hash, block_height)};
    if (produced != nullptr &&
        (result == AddResult::Accepted || result == AddResult::Duplicate)) {
        *produced = std::move(*attestation);
    }
    return result;
}

std::optional<UtxoSnapshotSignature> AttestationStore::SignUtxoSnapshot(
    const UtxoSnapshotStatement& statement) const
{
    if (!m_config.local_signer.has_value()) return std::nullopt;
    if (statement.chain_id != m_config.chain_id) return std::nullopt;
    if (statement.replay_authority_context !=
        m_config.replay_authority_context) {
        return std::nullopt;
    }
    return SignUtxoSnapshotStatement(statement, *m_config.local_signer);
}

bool AttestationStore::HasQuorum(const uint256& block_hash,
                                  int32_t block_height) const
{
    std::lock_guard lock{m_mutex};
    const auto it{m_buckets.find(BlockKey{block_height, block_hash})};
    return it != m_buckets.end() &&
           it->second.attestations.size() >= m_config.threshold;
}

std::vector<ExactReplayAttestation> AttestationStore::GetAttestationsLocked(
    const BlockKey& key) const
{
    std::vector<ExactReplayAttestation> out;
    const auto bucket{m_buckets.find(key)};
    if (bucket == m_buckets.end()) return out;
    out.reserve(bucket->second.attestations.size());
    for (const auto& [signer, attestation] :
         bucket->second.attestations) {
        (void)signer;
        out.push_back(attestation);
    }
    return out;
}

std::vector<ExactReplayAttestation> AttestationStore::GetAttestations(
    const uint256& block_hash, int32_t block_height) const
{
    std::lock_guard lock{m_mutex};
    return GetAttestationsLocked(BlockKey{block_height, block_hash});
}

std::vector<ExactReplayAttestation> AttestationStore::ExportAll() const
{
    std::lock_guard lock{m_mutex};
    std::vector<ExactReplayAttestation> out;
    out.reserve(m_attestation_count);
    for (const auto& [key, bucket] : m_buckets) {
        (void)key;
        for (const auto& [signer, attestation] : bucket.attestations) {
            (void)signer;
            out.push_back(attestation);
        }
    }
    return out;
}

void AttestationStore::SetDurableRetention(bool durable)
{
    std::lock_guard lock{m_mutex};
    m_durable_retention = durable;
}

WaitResult AttestationStore::WaitForQuorum(
    const uint256& block_hash,
    int32_t block_height,
    std::chrono::milliseconds timeout,
    const std::function<bool()>& cancel_requested,
    std::vector<ExactReplayAttestation>* quorum)
{
    const BlockKey key{block_height, block_hash};
    const auto deadline{Clock::now() + std::max(timeout,
                                                std::chrono::milliseconds{0})};
    std::unique_lock lock{m_mutex};
    ++m_stats.waits;
    while (true) {
        PruneExpiredLocked(Clock::now());
        const auto bucket{m_buckets.find(key)};
        if (bucket != m_buckets.end() &&
            bucket->second.attestations.size() >= m_config.threshold) {
            if (quorum != nullptr) *quorum = GetAttestationsLocked(key);
            ++m_stats.wait_quorums;
            return WaitResult::Quorum;
        }
        if (cancel_requested && cancel_requested()) {
            ++m_stats.wait_cancellations;
            return WaitResult::Cancelled;
        }
        const auto now{Clock::now()};
        if (now >= deadline) {
            ++m_stats.wait_timeouts;
            return WaitResult::Timeout;
        }
        m_changed.wait_until(lock, std::min(deadline,
                                            now + WAIT_POLL_INTERVAL));
    }
}

void AttestationStore::EraseLocked(
    std::map<BlockKey, Bucket>::iterator it, bool expired)
{
    m_attestation_count -= it->second.attestations.size();
    if (expired) {
        ++m_stats.expired_blocks;
    } else {
        ++m_stats.evicted_blocks;
    }
    m_buckets.erase(it);
}

void AttestationStore::PruneExpiredLocked(Clock::time_point now)
{
    if (m_durable_retention) return;
    for (auto it = m_buckets.begin(); it != m_buckets.end();) {
        if (now - it->second.updated < m_config.ttl) {
            ++it;
            continue;
        }
        auto expired{it++};
        EraseLocked(expired, true);
    }
}

bool AttestationStore::MakeRoomLocked(
    const BlockKey& incoming, bool incoming_reaches_quorum)
{
    const auto would_exceed_base_capacity = [this, &incoming] {
        const bool is_new_block{m_buckets.count(incoming) == 0};
        return m_buckets.size() + (is_new_block ? 1 : 0) >
                   m_config.max_blocks ||
               m_attestation_count + 1 > m_config.max_attestations;
    };

    while (would_exceed_base_capacity()) {
        // Partial buckets are best-effort. Evict them oldest-first before
        // considering the durable completed-quorum set.
        auto oldest_partial{m_buckets.end()};
        for (auto it = m_buckets.begin(); it != m_buckets.end(); ++it) {
            if (!(it->first < incoming) && !(incoming < it->first)) continue;
            if (it->second.attestations.size() >=
                m_config.threshold) {
                continue;
            }
            if (oldest_partial == m_buckets.end() ||
                it->second.updated < oldest_partial->second.updated) {
                oldest_partial = it;
            }
        }
        if (oldest_partial != m_buckets.end()) {
            EraseLocked(oldest_partial, false);
            continue;
        }

        if (incoming_reaches_quorum) {
            // A new completed quorum must be able to advance a long-running
            // mirror after max_blocks sequential blocks. Replacement is
            // permitted only on the vote that completes the incoming quorum;
            // minority votes can never remove completed authority.
            auto oldest_quorum{m_buckets.end()};
            for (auto it = m_buckets.begin(); it != m_buckets.end(); ++it) {
                if (!(it->first < incoming) && !(incoming < it->first)) {
                    continue;
                }
                if (it->second.attestations.size() <
                    m_config.threshold) {
                    continue;
                }
                if (oldest_quorum == m_buckets.end() ||
                    it->second.updated < oldest_quorum->second.updated) {
                    oldest_quorum = it;
                }
            }
            if (oldest_quorum == m_buckets.end()) return false;
            EraseLocked(oldest_quorum, false);
            continue;
        }

        // If completed quorums consume the base capacity, retain one bounded
        // partial candidate so it can collect the remaining votes. A different
        // partial arrival will replace this bucket above. The final vote must
        // return the store to the configured base limits by evicting the
        // oldest completed quorum.
        const bool incoming_exists{m_buckets.count(incoming) != 0};
        const size_t incoming_signatures{
            incoming_exists
                ? m_buckets.find(incoming)->second.attestations.size()
                : 0};
        const size_t partial_blocks{
            static_cast<size_t>(std::count_if(
                m_buckets.begin(), m_buckets.end(),
                [this](const auto& entry) {
                    return entry.second.attestations.size() <
                           m_config.threshold;
                })) +
            (incoming_exists ? 0 : 1)};
        const size_t staged_signatures{
            incoming_signatures + 1};
        const size_t attestation_staging_limit{
            m_config.max_attestations + m_config.threshold - 1};
        if (partial_blocks == 1 &&
            staged_signatures < m_config.threshold &&
            m_buckets.size() + (incoming_exists ? 0 : 1) <=
                m_config.max_blocks + 1 &&
            m_attestation_count + 1 <= attestation_staging_limit) {
            return true;
        }
        return false;
    }
    return true;
}

void AttestationStore::Erase(const uint256& block_hash, int32_t block_height)
{
    {
        std::lock_guard lock{m_mutex};
        const auto it{m_buckets.find(BlockKey{block_height, block_hash})};
        if (it == m_buckets.end()) return;
        m_attestation_count -= it->second.attestations.size();
        m_buckets.erase(it);
    }
    m_changed.notify_all();
}

void AttestationStore::PruneExpired()
{
    {
        std::lock_guard lock{m_mutex};
        PruneExpiredLocked(Clock::now());
    }
    m_changed.notify_all();
}

size_t AttestationStore::QuorumBlockCountLocked() const
{
    return std::count_if(
        m_buckets.begin(), m_buckets.end(),
        [this](const auto& entry) {
            return entry.second.attestations.size() >= m_config.threshold;
        });
}

StoreStats AttestationStore::GetStats() const
{
    std::lock_guard lock{m_mutex};
    StoreStats stats{m_stats};
    stats.stored_blocks = m_buckets.size();
    stats.stored_attestations = m_attestation_count;
    stats.blocks_with_quorum = QuorumBlockCountLocked();
    return stats;
}

std::optional<CPubKey> AttestationStore::LocalSignerPubKey() const
{
    if (!m_config.local_signer.has_value()) return std::nullopt;
    return m_config.local_signer->GetPubKey();
}

} // namespace matmul::trusted
