// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/trusted_exact_replay_attestation.h>

#include <hash.h>

#include <algorithm>
#include <limits>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace matmul::trusted {
namespace {

constexpr char HASH_DOMAIN[] = "BTX_TRUSTED_EXACT_REPLAY_ATTESTATION_V2";
constexpr char REFUTATION_DOMAIN[] = "BTX_TRUSTED_EXACT_REPLAY_REFUTATION_V1";
constexpr char LOG_NODE_DOMAIN[] = "BTX_MMATTEST_LOG_NODE_V1";
constexpr auto WAIT_POLL_INTERVAL = std::chrono::milliseconds{25};
constexpr size_t MAX_OPEN_VOTES_PER_BLOCK{256};

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

VerifyResult VerifyStatementFields(const ExactReplayStatement& statement,
                                   const uint256& expected_chain_id,
                                   const uint256& expected_replay_authority_context,
                                   const uint256& expected_hash,
                                   int32_t expected_height)
{
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
    return VerifyResult::Valid;
}

bool SignatureValid(const CPubKey& signer,
                    const uint256& hash,
                    const std::vector<unsigned char>& signature)
{
    return IsStrictDERSignature(signature) &&
           CPubKey::CheckLowS(signature) &&
           signer.Verify(hash, signature);
}

uint256 LogNodeHash(const uint256& left, const uint256& right)
{
    HashWriter hasher;
    hasher << std::string{LOG_NODE_DOMAIN} << left << right;
    return hasher.GetHash();
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

uint256 RefutationHash(const ExactReplayStatement& statement)
{
    HashWriter hasher;
    hasher << std::string{REFUTATION_DOMAIN};
    hasher << statement;
    return hasher.GetHash();
}

std::optional<ExactReplayRefutation> SignRefutation(
    const ExactReplayStatement& statement, const CKey& signer)
{
    if (!signer.IsValid() || !signer.IsCompressed()) return std::nullopt;
    const CPubKey pubkey{signer.GetPubKey()};
    if (!IsCanonicalSigner(pubkey)) return std::nullopt;

    ExactReplayRefutation refutation;
    refutation.statement = statement;
    refutation.signer = pubkey;
    if (!signer.Sign(RefutationHash(statement), refutation.signature)) {
        return std::nullopt;
    }
    return refutation;
}

uint256 ComputeAttestationLogRoot(const std::vector<uint256>& leaves)
{
    if (leaves.empty()) return uint256{};
    std::vector<uint256> level{leaves};
    while (level.size() > 1) {
        if (level.size() % 2 != 0) level.emplace_back();
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(LogNodeHash(level[i], level[i + 1]));
        }
        level = std::move(next);
    }
    return level.front();
}

std::vector<uint256> ComputeAttestationLogBranch(
    const std::vector<uint256>& leaves, uint64_t index)
{
    std::vector<uint256> branch;
    if (leaves.empty() || index >= leaves.size()) return branch;
    std::vector<uint256> level{leaves};
    size_t pos{static_cast<size_t>(index)};
    while (level.size() > 1) {
        if (level.size() % 2 != 0) level.emplace_back();
        const size_t sibling{pos ^ 1U};
        branch.push_back(level[sibling]);
        std::vector<uint256> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(LogNodeHash(level[i], level[i + 1]));
        }
        level = std::move(next);
        pos /= 2;
    }
    return branch;
}

bool VerifyAttestationLogInclusion(const AttestationLogProof& proof)
{
    if (proof.branch.empty() && proof.leaf != proof.root) {
        return proof.leaf == proof.root && !proof.leaf.IsNull();
    }
    uint256 hash{proof.leaf};
    uint64_t pos{proof.index};
    for (const auto& sibling : proof.branch) {
        if ((pos & 1U) == 0) {
            hash = LogNodeHash(hash, sibling);
        } else {
            hash = LogNodeHash(sibling, hash);
        }
        pos /= 2;
    }
    return hash == proof.root && !proof.root.IsNull();
}

VerifyResult VerifyAttestationCrypto(
    const ExactReplayAttestation& attestation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_hash,
    int32_t expected_height)
{
    const auto fields{VerifyStatementFields(
        attestation.statement, expected_chain_id,
        expected_replay_authority_context, expected_hash, expected_height)};
    if (fields != VerifyResult::Valid) return fields;
    if (!IsCanonicalSigner(attestation.signer)) {
        return VerifyResult::InvalidSigner;
    }
    if (!SignatureValid(attestation.signer, StatementHash(attestation.statement),
                        attestation.signature)) {
        return VerifyResult::InvalidSignature;
    }
    return VerifyResult::Valid;
}

VerifyResult VerifyRefutationCrypto(
    const ExactReplayRefutation& refutation,
    const uint256& expected_chain_id,
    const uint256& expected_replay_authority_context,
    const uint256& expected_hash,
    int32_t expected_height)
{
    const auto fields{VerifyStatementFields(
        refutation.statement, expected_chain_id,
        expected_replay_authority_context, expected_hash, expected_height)};
    if (fields != VerifyResult::Valid) return fields;
    if (!IsCanonicalSigner(refutation.signer)) {
        return VerifyResult::InvalidSigner;
    }
    if (!SignatureValid(refutation.signer, RefutationHash(refutation.statement),
                        refutation.signature)) {
        return VerifyResult::InvalidSignature;
    }
    return VerifyResult::Valid;
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
    const auto fields{VerifyStatementFields(
        statement, expected_chain_id, expected_replay_authority_context,
        expected_hash, expected_height)};
    if (fields != VerifyResult::Valid) return fields;
    if (!IsCanonicalSigner(attestation.signer)) {
        return VerifyResult::InvalidSigner;
    }
    if (trusted_signers.count(attestation.signer) == 0) {
        return VerifyResult::UntrustedSigner;
    }
    if (!SignatureValid(attestation.signer, StatementHash(statement),
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
    case AddResult::Heard: return "heard";
    case AddResult::FrozenSigner: return "frozen-signer";
    case AddResult::Equivocation: return "equivocation";
    case AddResult::BlocklistedSigner: return "blocklisted-signer";
    }
    return "unknown";
}

std::string_view BlocklistResultName(BlocklistResult result)
{
    switch (result) {
    case BlocklistResult::Blocked: return "blocked";
    case BlocklistResult::Duplicate: return "duplicate";
    case BlocklistResult::WouldDisablePinQuorum:
        return "would-disable-pin-quorum";
    case BlocklistResult::LocalSigner: return "local-signer";
    case BlocklistResult::Invalid: return "invalid";
    case BlocklistResult::Capacity: return "capacity";
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
    if (m_config.blocklist.size() > DEFAULT_MAX_BLOCKED_SIGNERS) {
        throw std::invalid_argument{
            "attestation blocklist exceeds the maximum number of keys"};
    }
    for (const auto& blocked : m_config.blocklist) {
        if (!IsCanonicalSigner(blocked)) {
            throw std::invalid_argument{
                "attestation blocklist entries must be valid compressed keys"};
        }
        if (!m_blocked_config.insert(blocked).second ||
            !m_blocked.insert(blocked).second) {
            throw std::invalid_argument{
                "attestation blocklist contains a duplicate"};
        }
    }
    if (!PinQuorumIsReachable(UnblockedPinMembersLocked(),
                              m_config.threshold)) {
        throw std::invalid_argument{
            "attestation blocklist leaves fewer than M unblocked trusted signers"};
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
        if (!key.IsValid() || !key.IsCompressed()) {
            throw std::invalid_argument{
                "local ExactReplay signer must be a valid compressed key"};
        }
        if (m_trusted_signers.count(key.GetPubKey()) == 0 &&
            !m_config.open_attestors) {
            throw std::invalid_argument{
                "local ExactReplay signer must be a configured compressed key"};
        }
        if (m_blocked.count(key.GetPubKey()) != 0) {
            throw std::invalid_argument{
                "local ExactReplay signer must not be on the attestation blocklist"};
        }
    }
    if (m_config.open_attestors) {
        if (m_config.open_threshold == 0) {
            m_config.open_threshold = DefaultOpenThreshold(m_config.threshold);
        }
        if (m_config.open_threshold < 1) {
            throw std::invalid_argument{
                "open ExactReplay threshold must be at least one"};
        }
        if (m_config.max_heard_attestations == 0) {
            throw std::invalid_argument{
                "open ExactReplay heard-store capacity must be positive"};
        }
    } else {
        m_config.open_threshold = 0;
    }
    if (m_config.max_admitted_open == 0) {
        m_config.max_admitted_open = DEFAULT_MAX_ADMITTED_OPEN;
    }
    if (m_config.max_open_signed_heights == 0) {
        m_config.max_open_signed_heights = DEFAULT_MAX_OPEN_SIGNED_HEIGHTS;
    }
    if (m_config.max_open_signed_entries == 0) {
        m_config.max_open_signed_entries = DEFAULT_MAX_OPEN_SIGNED_ENTRIES;
    }
    if (m_config.max_open_signers_per_height == 0) {
        m_config.max_open_signers_per_height =
            DEFAULT_MAX_OPEN_SIGNERS_PER_HEIGHT;
    }
    if (m_config.max_frozen_open == 0) {
        m_config.max_frozen_open = DEFAULT_MAX_FROZEN_OPEN;
    }
    if (m_config.max_refutations == 0) {
        m_config.max_refutations = DEFAULT_MAX_REFUTATIONS;
    }
    if (m_config.max_log_leaves == 0) {
        m_config.max_log_leaves = DEFAULT_MAX_LOG_LEAVES;
    }
    if (m_config.max_window_challenges == 0) {
        m_config.max_window_challenges = DEFAULT_MAX_WINDOW_CHALLENGES;
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

size_t AttestationStore::PinVotesLocked(const Bucket& bucket) const
{
    size_t votes{0};
    for (const auto& [pubkey, attestation] : bucket.attestations) {
        (void)attestation;
        if (m_trusted_signers.count(pubkey) != 0 &&
            !IsBlockedLocked(pubkey)) {
            ++votes;
        }
    }
    return votes;
}

size_t AttestationStore::AuthorityVotesLocked(const Bucket& bucket) const
{
    size_t votes{0};
    for (const auto& [pubkey, attestation] : bucket.attestations) {
        (void)attestation;
        if (m_frozen_open.count(pubkey) != 0) continue;
        if (IsBlockedLocked(pubkey)) continue;
        if (m_trusted_signers.count(pubkey) != 0 ||
            m_admitted_open.count(pubkey) != 0) {
            ++votes;
        }
    }
    return votes;
}

bool AttestationStore::PinQuorumLocked(const Bucket& bucket) const
{
    return PinVotesLocked(bucket) >= m_config.threshold;
}

bool AttestationStore::OpenQuorumLocked(const BlockKey& key,
                                        const Bucket& bucket) const
{
    if (!m_config.open_attestors) return false;
    if (m_pin_refuted.count(key) != 0) return false;
    return AuthorityVotesLocked(bucket) >= m_config.open_threshold;
}

bool AttestationStore::HasQuorumLocked(const BlockKey& key,
                                       const Bucket& bucket) const
{
    (void)key;
    return PinQuorumLocked(bucket);
}

bool AttestationStore::WouldReachQuorumLocked(const BlockKey& key,
                                              const CPubKey& signer) const
{
    if (m_trusted_signers.count(signer) == 0) return false;
    if (IsBlockedLocked(signer)) return false;
    const auto it{m_buckets.find(key)};
    const bool already{
        it != m_buckets.end() && HasQuorumLocked(key, it->second)};
    if (already) return false;
    const size_t pin{
        (it == m_buckets.end() ? 0 : PinVotesLocked(it->second)) + 1};
    return pin >= m_config.threshold;
}

bool AttestationStore::IsBlockedLocked(const CPubKey& pubkey) const
{
    return m_blocked.count(pubkey) != 0;
}

size_t AttestationStore::UnblockedPinMembersLocked() const
{
    size_t unblocked{0};
    for (const auto& signer : m_trusted_signers) {
        if (!IsBlockedLocked(signer)) ++unblocked;
    }
    return unblocked;
}

void AttestationStore::DropHeardLocked(const CPubKey& pubkey)
{
    for (auto it = m_heard.begin(); it != m_heard.end();) {
        if (it->first.signer == pubkey) {
            m_heard_updated.erase(it->first);
            it = m_heard.erase(it);
        } else {
            ++it;
        }
    }
}

void AttestationStore::AdmitOpenLocked(const CPubKey& pubkey)
{
    if (m_trusted_signers.count(pubkey) != 0) return;
    if (m_frozen_open.count(pubkey) != 0) return;
    if (IsBlockedLocked(pubkey)) return;
    if (!IsCanonicalSigner(pubkey)) return;
    if (m_admitted_open.count(pubkey) != 0) return;
    if (m_admitted_open.size() >= m_config.max_admitted_open) return;
    m_admitted_open.insert(pubkey);
}

void AttestationStore::FreezeOpenLocked(const CPubKey& pubkey)
{
    if (m_trusted_signers.count(pubkey) != 0) return;
    if (m_frozen_open.insert(pubkey).second) {
        m_frozen_open_order.push_back(pubkey);
        CapFrozenOpenLocked();
    }
    m_admitted_open.erase(pubkey);
    for (auto it = m_open_signed_at_height.begin();
         it != m_open_signed_at_height.end();) {
        it->second.erase(pubkey);
        if (it->second.empty()) {
            m_open_signed_updated.erase(it->first);
            it = m_open_signed_at_height.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = m_buckets.begin(); it != m_buckets.end();) {
        auto att_it{it->second.attestations.find(pubkey)};
        if (att_it == it->second.attestations.end()) {
            ++it;
            continue;
        }
        it->second.attestations.erase(att_it);
        if (m_attestation_count > 0) --m_attestation_count;
        if (it->second.attestations.empty()) {
            it = m_buckets.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = m_heard.begin(); it != m_heard.end();) {
        if (it->first.signer == pubkey) {
            m_heard_updated.erase(it->first);
            it = m_heard.erase(it);
        } else {
            ++it;
        }
    }
}

void AttestationStore::AdmitHeardOnHashLocked(const BlockKey& key,
                                              Clock::time_point now)
{
    (void)now;
    for (const auto& [heard_key, attestation] : m_heard) {
        (void)attestation;
        if (heard_key.height != key.height || heard_key.hash != key.hash) {
            continue;
        }
        AdmitOpenLocked(heard_key.signer);
    }
}

AddResult AttestationStore::StoreHeardLocked(
    const ExactReplayAttestation& attestation, Clock::time_point now)
{
    const HeardKey heard_key{attestation.statement.block_height,
                             attestation.statement.block_hash,
                             attestation.signer};
    if (m_heard.count(heard_key) != 0) {
        // Already directory. Duplicate is reserved for pin-bucket
        // re-relays so it cannot promote the signed frontier.
        return AddResult::Heard;
    }
    while (m_heard.size() >= m_config.max_heard_attestations &&
           !m_heard.empty()) {
        auto oldest{m_heard_updated.begin()};
        for (auto it = m_heard_updated.begin(); it != m_heard_updated.end();
             ++it) {
            if (it->second < oldest->second) oldest = it;
        }
        m_heard.erase(oldest->first);
        m_heard_updated.erase(oldest);
    }
    m_heard.emplace(heard_key, attestation);
    m_heard_updated.emplace(heard_key, now);
    ++m_stats.heard;
    return AddResult::Heard;
}

void AttestationStore::AppendLogLeafLocked(const uint256& leaf)
{
    m_log_leaves.push_back(leaf);
    while (m_log_leaves.size() > m_config.max_log_leaves) {
        m_log_leaves.erase(m_log_leaves.begin());
    }
}

void AttestationStore::PruneOpenDirectoryLocked()
{
    while (m_open_signed_at_height.size() > m_config.max_open_signed_heights &&
           !m_open_signed_at_height.empty()) {
        m_open_signed_updated.erase(m_open_signed_at_height.begin()->first);
        m_open_signed_at_height.erase(m_open_signed_at_height.begin());
    }
    while (OpenSignedEntryCountLocked() > m_config.max_open_signed_entries &&
           !m_open_signed_at_height.empty()) {
        m_open_signed_updated.erase(m_open_signed_at_height.begin()->first);
        m_open_signed_at_height.erase(m_open_signed_at_height.begin());
    }
}

size_t AttestationStore::OpenSignedEntryCountLocked() const
{
    size_t n{0};
    for (const auto& [height, signers] : m_open_signed_at_height) {
        n += signers.size();
    }
    return n;
}

size_t AttestationStore::OpenSignedHeightCount() const
{
    std::lock_guard lock{m_mutex};
    return m_open_signed_at_height.size();
}

size_t AttestationStore::OpenSignedEntryCount() const
{
    std::lock_guard lock{m_mutex};
    return OpenSignedEntryCountLocked();
}

void AttestationStore::RefreshPinRefutedLocked(const BlockKey& key)
{
    const auto it{m_refutations.find(key)};
    if (it == m_refutations.end()) {
        m_pin_refuted.erase(key);
        return;
    }
    size_t pin_votes{0};
    for (const auto& [pubkey, refutation] : it->second) {
        (void)refutation;
        if (m_trusted_signers.count(pubkey) != 0 &&
            !IsBlockedLocked(pubkey)) {
            ++pin_votes;
        }
    }
    if (pin_votes >= m_config.threshold) {
        m_pin_refuted.insert(key);
    } else {
        m_pin_refuted.erase(key);
    }
}

void AttestationStore::CapRefutationsLocked()
{
    while (m_refutations.size() > m_config.max_refutations &&
           !m_refutations.empty()) {
        auto oldest{m_refutations.begin()};
        const BlockKey dropped{oldest->first};
        m_refutations.erase(oldest);
        m_refutation_updated.erase(dropped);
        m_pin_refuted.erase(dropped);
    }
}

void AttestationStore::CapFrozenOpenLocked()
{
    while (m_frozen_open.size() > m_config.max_frozen_open &&
           !m_frozen_open_order.empty()) {
        const CPubKey oldest{m_frozen_open_order.front()};
        m_frozen_open_order.pop_front();
        m_frozen_open.erase(oldest);
    }
}

AddResult AttestationStore::Add(
    const ExactReplayAttestation& attestation,
    const uint256& expected_hash,
    int32_t expected_height)
{
    const VerifyResult crypto{VerifyAttestationCrypto(
        attestation, m_config.chain_id, m_config.replay_authority_context,
        expected_hash, expected_height)};
    if (crypto != VerifyResult::Valid) {
        std::lock_guard lock{m_mutex};
        ++m_stats.rejected;
        return ToAddResult(crypto);
    }

    const BlockKey key{expected_height, expected_hash};
    const auto now{Clock::now()};
    AddResult result{AddResult::Accepted};
    {
        std::lock_guard lock{m_mutex};
        PruneExpiredLocked(now);

        if (IsBlockedLocked(attestation.signer)) {
            ++m_stats.rejected;
            return AddResult::BlocklistedSigner;
        }

        const bool pinned{m_trusted_signers.count(attestation.signer) != 0};

        if (!pinned) {
            if (!m_config.open_attestors) {
                ++m_stats.rejected;
                return AddResult::UntrustedSigner;
            }
            if (m_frozen_open.count(attestation.signer) != 0) {
                ++m_stats.rejected;
                return AddResult::FrozenSigner;
            }
            auto height_it{m_open_signed_at_height.find(expected_height)};
            if (height_it != m_open_signed_at_height.end()) {
                auto& signed_at{height_it->second};
                const auto existing_hash{signed_at.find(attestation.signer)};
                if (existing_hash != signed_at.end() &&
                    existing_hash->second != expected_hash) {
                    FreezeOpenLocked(attestation.signer);
                    ++m_stats.equivocations;
                    ++m_stats.rejected;
                    return AddResult::Equivocation;
                }
                if (existing_hash != signed_at.end() ||
                    signed_at.size() < m_config.max_open_signers_per_height) {
                    signed_at[attestation.signer] = expected_hash;
                    m_open_signed_updated[expected_height] = now;
                }
            } else if (m_config.max_open_signers_per_height > 0) {
                m_open_signed_at_height[expected_height][attestation.signer] =
                    expected_hash;
                m_open_signed_updated[expected_height] = now;
            }
            PruneOpenDirectoryLocked();

            const auto existing_bucket{m_buckets.find(key)};
            const bool pin_quorum_already{
                existing_bucket != m_buckets.end() &&
                PinQuorumLocked(existing_bucket->second)};
            if (pin_quorum_already) {
                AdmitOpenLocked(attestation.signer);
            }
            result = StoreHeardLocked(attestation, now);
            return result;
        }

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
        const bool incoming_reaches_quorum{
            WouldReachQuorumLocked(key, attestation.signer)};
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
        AppendLogLeafLocked(StatementHash(attestation.statement));
        if (pinned && PinQuorumLocked(bucket)) {
            AdmitHeardOnHashLocked(key, now);
        }
        auto after{m_buckets.find(key)};
        if (after != m_buckets.end() && !after->second.quorum_counted &&
            HasQuorumLocked(key, after->second)) {
            after->second.quorum_counted = true;
            ++m_stats.quorum_transitions;
        }
        (void)inserted;
        result = AddResult::Accepted;
    }
    m_changed.notify_all();
    return result;
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
        if (IsBlockedLocked(local_pk)) {
            ++m_stats.rejected;
            return AddResult::BlocklistedSigner;
        }
        const auto minted{m_local_minted_hash_by_height.find(block_height)};
        const bool minted_other_hash{
            minted != m_local_minted_hash_by_height.end() &&
            minted->second != block_hash};
        // Relayed copies of this node's pubkey (stolen-WIF MMATTEST) must
        // not occupy the mint slot. Only a competing *on-chain quorum* or a
        // hash this process already SignLocal'd refuses. Otherwise one stolen
        // pin key jams the honest attestor and freezes every M=2 mirror.
        // A hash this node itself disconnected no longer occupies: that is a
        // local validated reorg, not an inbound competing attestation.
        if (minted_other_hash ||
            OccupyingCompetingQuorumLocked(block_height, block_hash)) {
            ++m_stats.rejected;
            return AddResult::HeightOccupied;
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
    if (result == AddResult::Accepted || result == AddResult::Duplicate) {
        std::lock_guard lock{m_mutex};
        m_local_minted_hash_by_height.emplace(block_height, block_hash);
    }
    if (produced != nullptr &&
        (result == AddResult::Accepted || result == AddResult::Duplicate ||
         result == AddResult::Heard)) {
        *produced = std::move(*attestation);
    }
    return result;
}

void AttestationStore::CapOffActiveChainLocked()
{
    while (m_off_active_chain.size() > m_config.max_blocks &&
           !m_off_active_chain.empty()) {
        m_off_active_chain.erase(m_off_active_chain.begin());
    }
}

void AttestationStore::ReleaseOpenSignedMatchingHashLocked(
    int32_t height, const uint256& block_hash)
{
    auto height_it{m_open_signed_at_height.find(height)};
    if (height_it == m_open_signed_at_height.end()) return;
    auto& signers{height_it->second};
    for (auto it = signers.begin(); it != signers.end();) {
        if (it->second == block_hash) {
            it = signers.erase(it);
        } else {
            ++it;
        }
    }
    if (signers.empty()) {
        m_open_signed_at_height.erase(height_it);
        m_open_signed_updated.erase(height);
    }
}

bool AttestationStore::OccupyingCompetingQuorumLocked(
    int32_t block_height, const uint256& block_hash) const
{
    for (auto it = m_buckets.lower_bound(BlockKey{block_height, uint256{}});
         it != m_buckets.end() && it->first.height == block_height; ++it) {
        if (it->first.hash == block_hash) continue;
        if (m_off_active_chain.count(it->first) != 0) continue;
        if (HasQuorumLocked(it->first, it->second)) return true;
    }
    return false;
}

bool AttestationStore::NotifyActiveChainBlockDisconnected(
    int32_t height, const uint256& disconnected_hash)
{
    if (height < 0 || disconnected_hash.IsNull()) return false;
    std::lock_guard lock{m_mutex};
    m_off_active_chain.insert(BlockKey{height, disconnected_hash});
    CapOffActiveChainLocked();
    ReleaseOpenSignedMatchingHashLocked(height, disconnected_hash);
    const auto minted{m_local_minted_hash_by_height.find(height)};
    if (minted == m_local_minted_hash_by_height.end() ||
        minted->second != disconnected_hash) {
        return false;
    }
    m_local_minted_hash_by_height.erase(minted);
    return true;
}

void AttestationStore::NotifyActiveChainBlockConnected(
    int32_t height, const uint256& connected_hash)
{
    if (height < 0 || connected_hash.IsNull()) return;
    std::lock_guard lock{m_mutex};
    m_off_active_chain.erase(BlockKey{height, connected_hash});
}

size_t AttestationStore::ClearLocalMintSlots(int32_t from_height,
                                             int32_t to_height)
{
    if (from_height > to_height) return 0;
    std::lock_guard lock{m_mutex};
    size_t cleared{0};
    auto it{m_local_minted_hash_by_height.lower_bound(from_height)};
    while (it != m_local_minted_hash_by_height.end() &&
           it->first <= to_height) {
        m_open_signed_at_height.erase(it->first);
        m_open_signed_updated.erase(it->first);
        it = m_local_minted_hash_by_height.erase(it);
        ++cleared;
    }
    // Heights that only had open-directory rows (no local mint) still need
    // a consistent wipe so an operator can recover an open attestor too.
    auto open_it{m_open_signed_at_height.lower_bound(from_height)};
    while (open_it != m_open_signed_at_height.end() &&
           open_it->first <= to_height) {
        m_open_signed_updated.erase(open_it->first);
        open_it = m_open_signed_at_height.erase(open_it);
    }
    return cleared;
}

std::optional<uint256> AttestationStore::LocalMintedHash(int32_t height) const
{
    std::lock_guard lock{m_mutex};
    const auto it{m_local_minted_hash_by_height.find(height)};
    if (it == m_local_minted_hash_by_height.end() || it->second.IsNull()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<int32_t> AttestationStore::LocalMintedHeights(
    int32_t from_height, int32_t to_height) const
{
    std::vector<int32_t> out;
    if (from_height > to_height) return out;
    std::lock_guard lock{m_mutex};
    auto it{m_local_minted_hash_by_height.lower_bound(from_height)};
    while (it != m_local_minted_hash_by_height.end() &&
           it->first <= to_height) {
        out.push_back(it->first);
        ++it;
    }
    return out;
}

bool AttestationStore::IsOffActiveChain(int32_t height,
                                        const uint256& block_hash) const
{
    if (height < 0 || block_hash.IsNull()) return false;
    std::lock_guard lock{m_mutex};
    return m_off_active_chain.count(BlockKey{height, block_hash}) != 0;
}

std::optional<UtxoSnapshotSignature> AttestationStore::SignUtxoSnapshot(
    const UtxoSnapshotStatement& statement) const
{
    if (!m_config.local_signer.has_value()) return std::nullopt;
    {
        std::lock_guard lock{m_mutex};
        if (IsBlockedLocked(m_config.local_signer->GetPubKey())) {
            return std::nullopt;
        }
    }
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
    return it != m_buckets.end() && HasQuorumLocked(it->first, it->second);
}

bool AttestationStore::HasOpenQuorum(const uint256& block_hash,
                                     int32_t block_height) const
{
    std::lock_guard lock{m_mutex};
    if (!m_config.open_attestors) return false;
    const BlockKey key{block_height, block_hash};
    if (m_pin_refuted.count(key) != 0) return false;
    std::set<CPubKey> votes;
    const auto it{m_buckets.find(key)};
    if (it != m_buckets.end()) {
        for (const auto& [pubkey, attestation] : it->second.attestations) {
            (void)attestation;
            if (m_frozen_open.count(pubkey) != 0) continue;
            if (IsBlockedLocked(pubkey)) continue;
            if (m_trusted_signers.count(pubkey) != 0 ||
                m_admitted_open.count(pubkey) != 0) {
                votes.insert(pubkey);
            }
        }
    }
    for (const auto& [heard_key, attestation] : m_heard) {
        (void)attestation;
        if (heard_key.height != block_height || heard_key.hash != block_hash) {
            continue;
        }
        if (m_frozen_open.count(heard_key.signer) != 0) continue;
        if (IsBlockedLocked(heard_key.signer)) continue;
        if (m_admitted_open.count(heard_key.signer) != 0) {
            votes.insert(heard_key.signer);
        }
    }
    return votes.size() >= m_config.open_threshold;
}

bool AttestationStore::HasQuorumFromAttestations(
    const std::vector<ExactReplayAttestation>& attestations,
    const uint256& block_hash,
    int32_t block_height) const
{
    std::set<CPubKey> pin_votes;
    {
        std::lock_guard lock{m_mutex};
        for (const auto& attestation : attestations) {
            if (VerifyAttestationCrypto(
                    attestation, m_config.chain_id,
                    m_config.replay_authority_context, block_hash,
                    block_height) != VerifyResult::Valid) {
                continue;
            }
            if (m_trusted_signers.count(attestation.signer) != 0 &&
                !IsBlockedLocked(attestation.signer)) {
                pin_votes.insert(attestation.signer);
            }
        }
    }
    return pin_votes.size() >= m_config.threshold;
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
            HasQuorumLocked(key, bucket->second)) {
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
    if (!m_durable_retention) {
        for (auto it = m_buckets.begin(); it != m_buckets.end();) {
            if (now - it->second.updated < m_config.ttl) {
                ++it;
                continue;
            }
            auto expired{it++};
            EraseLocked(expired, true);
        }
    }
    // Open-directory maps are a mem/disk DoS surface, not authority. TTL
    // them even when pin buckets are durable.
    PruneExpiredDirectoryLocked(now);
}

void AttestationStore::PruneExpiredDirectoryLocked(Clock::time_point now)
{
    for (auto it = m_heard_updated.begin(); it != m_heard_updated.end();) {
        if (now - it->second < m_config.ttl) {
            ++it;
            continue;
        }
        m_heard.erase(it->first);
        it = m_heard_updated.erase(it);
    }
    for (auto it = m_open_signed_updated.begin();
         it != m_open_signed_updated.end();) {
        if (now - it->second < m_config.ttl) {
            ++it;
            continue;
        }
        m_open_signed_at_height.erase(it->first);
        it = m_open_signed_updated.erase(it);
    }
    for (auto it = m_refutation_updated.begin();
         it != m_refutation_updated.end();) {
        if (now - it->second < m_config.ttl) {
            ++it;
            continue;
        }
        const BlockKey key{it->first};
        m_refutations.erase(key);
        m_pin_refuted.erase(key);
        it = m_refutation_updated.erase(it);
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
            if (HasQuorumLocked(it->first, it->second)) {
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
                if (it->second.attestations.size() == 0) continue;
                if (!HasQuorumLocked(it->first, it->second)) {
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
                    return !HasQuorumLocked(entry.first, entry.second);
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
            return HasQuorumLocked(entry.first, entry.second);
        });
}

StoreStats AttestationStore::GetStats() const
{
    std::lock_guard lock{m_mutex};
    StoreStats stats{m_stats};
    stats.stored_blocks = m_buckets.size();
    stats.stored_attestations = m_attestation_count;
    stats.blocks_with_quorum = QuorumBlockCountLocked();
    stats.heard_attestations = m_heard.size();
    stats.admitted_open = m_admitted_open.size();
    stats.frozen_open = m_frozen_open.size();
    stats.open_signed_heights = m_open_signed_at_height.size();
    stats.open_signed_entries = OpenSignedEntryCountLocked();
    stats.refutation_buckets = m_refutations.size();
    stats.log_leaves = m_log_leaves.size();
    stats.window_challenges = m_window_challenges.size();
    return stats;
}

std::optional<CPubKey> AttestationStore::LocalSignerPubKey() const
{
    if (!m_config.local_signer.has_value()) return std::nullopt;
    return m_config.local_signer->GetPubKey();
}

size_t AttestationStore::MaxVotesPerBlock() const
{
    if (!m_config.open_attestors) return m_trusted_signers.size();
    return m_trusted_signers.size() + MAX_OPEN_VOTES_PER_BLOCK;
}

bool AttestationStore::IsPinnedSigner(const CPubKey& pubkey) const
{
    return m_trusted_signers.count(pubkey) != 0;
}

bool AttestationStore::IsAdmittedOpenSigner(const CPubKey& pubkey) const
{
    std::lock_guard lock{m_mutex};
    return m_admitted_open.count(pubkey) != 0;
}

bool AttestationStore::IsFrozenOpenSigner(const CPubKey& pubkey) const
{
    std::lock_guard lock{m_mutex};
    return m_frozen_open.count(pubkey) != 0;
}

bool AttestationStore::IsAuthoritySigner(const CPubKey& pubkey) const
{
    std::lock_guard lock{m_mutex};
    return m_trusted_signers.count(pubkey) != 0 && !IsBlockedLocked(pubkey);
}

bool AttestationStore::IsBlocked(const CPubKey& pubkey) const
{
    std::lock_guard lock{m_mutex};
    return IsBlockedLocked(pubkey);
}

std::set<CPubKey> AttestationStore::BlockedSigners() const
{
    std::lock_guard lock{m_mutex};
    return m_blocked;
}

std::set<CPubKey> AttestationStore::ConfigBlockedSigners() const
{
    std::lock_guard lock{m_mutex};
    return m_blocked_config;
}

std::set<CPubKey> AttestationStore::RuntimeBlockedSigners() const
{
    std::lock_guard lock{m_mutex};
    std::set<CPubKey> runtime;
    for (const auto& pubkey : m_blocked) {
        if (m_blocked_config.count(pubkey) == 0) runtime.insert(pubkey);
    }
    return runtime;
}

size_t AttestationStore::UnblockedPinMembers() const
{
    std::lock_guard lock{m_mutex};
    return UnblockedPinMembersLocked();
}

bool AttestationStore::PinQuorumReachable() const
{
    std::lock_guard lock{m_mutex};
    return PinQuorumIsReachable(UnblockedPinMembersLocked(),
                                m_config.threshold);
}

BlocklistResult AttestationStore::AddBlocklistedSigner(const CPubKey& pubkey)
{
    if (!IsCanonicalSigner(pubkey)) return BlocklistResult::Invalid;
    {
        std::lock_guard lock{m_mutex};
        if (m_config.local_signer.has_value() &&
            m_config.local_signer->GetPubKey() == pubkey) {
            return BlocklistResult::LocalSigner;
        }
        if (IsBlockedLocked(pubkey)) return BlocklistResult::Duplicate;
        if (m_blocked.size() >= DEFAULT_MAX_BLOCKED_SIGNERS) {
            return BlocklistResult::Capacity;
        }
        if (m_trusted_signers.count(pubkey) != 0) {
            const size_t unblocked_after{UnblockedPinMembersLocked() - 1};
            if (!PinQuorumIsReachable(unblocked_after, m_config.threshold)) {
                return BlocklistResult::WouldDisablePinQuorum;
            }
        }
        m_blocked.insert(pubkey);
        m_admitted_open.erase(pubkey);
        DropHeardLocked(pubkey);
    }
    m_changed.notify_all();
    return BlocklistResult::Blocked;
}

bool AttestationStore::RestoreRuntimeBlocked(std::set<CPubKey> blocked)
{
    for (const auto& pubkey : blocked) {
        if (!IsCanonicalSigner(pubkey)) continue;
        const BlocklistResult result{AddBlocklistedSigner(pubkey)};
        if (result == BlocklistResult::WouldDisablePinQuorum ||
            result == BlocklistResult::LocalSigner ||
            result == BlocklistResult::Capacity) {
            return false;
        }
    }
    return true;
}

std::set<CPubKey> AttestationStore::AdmittedOpenSigners() const
{
    std::lock_guard lock{m_mutex};
    return m_admitted_open;
}

std::set<CPubKey> AttestationStore::FrozenOpenSigners() const
{
    std::lock_guard lock{m_mutex};
    return m_frozen_open;
}

std::vector<ExactReplayAttestation> AttestationStore::GetHeard(
    const uint256& block_hash, int32_t block_height) const
{
    std::lock_guard lock{m_mutex};
    std::vector<ExactReplayAttestation> out;
    for (const auto& [key, attestation] : m_heard) {
        if (key.height == block_height && key.hash == block_hash) {
            out.push_back(attestation);
        }
    }
    return out;
}

std::vector<ExactReplayAttestation> AttestationStore::ExportHeard() const
{
    std::lock_guard lock{m_mutex};
    std::vector<ExactReplayAttestation> out;
    out.reserve(m_heard.size());
    for (const auto& [key, attestation] : m_heard) {
        (void)key;
        out.push_back(attestation);
    }
    return out;
}

std::vector<ExactReplayRefutation> AttestationStore::GetRefutations(
    const uint256& block_hash, int32_t block_height) const
{
    std::lock_guard lock{m_mutex};
    std::vector<ExactReplayRefutation> out;
    const auto it{m_refutations.find(BlockKey{block_height, block_hash})};
    if (it == m_refutations.end()) return out;
    out.reserve(it->second.size());
    for (const auto& [signer, refutation] : it->second) {
        (void)signer;
        out.push_back(refutation);
    }
    return out;
}

AttestationLogHead AttestationStore::LogHead() const
{
    std::lock_guard lock{m_mutex};
    AttestationLogHead head;
    head.tree_size = m_log_leaves.size();
    head.root = ComputeAttestationLogRoot(m_log_leaves);
    return head;
}

std::optional<AttestationLogProof> AttestationStore::LogInclusionProof(
    const uint256& statement_hash) const
{
    std::lock_guard lock{m_mutex};
    for (size_t i = 0; i < m_log_leaves.size(); ++i) {
        if (m_log_leaves[i] != statement_hash) continue;
        AttestationLogProof proof;
        proof.index = i;
        proof.leaf = statement_hash;
        proof.branch = ComputeAttestationLogBranch(m_log_leaves, i);
        proof.root = ComputeAttestationLogRoot(m_log_leaves);
        return proof;
    }
    return std::nullopt;
}

void AttestationStore::RestoreOpenAttestors(std::set<CPubKey> admitted,
                                            std::set<CPubKey> frozen)
{
    std::lock_guard lock{m_mutex};
    m_frozen_open.clear();
    m_frozen_open_order.clear();
    for (const auto& pubkey : frozen) {
        if (m_frozen_open.insert(pubkey).second) {
            m_frozen_open_order.push_back(pubkey);
        }
    }
    CapFrozenOpenLocked();
    m_admitted_open.clear();
    for (const auto& pubkey : admitted) {
        AdmitOpenLocked(pubkey);
    }
    for (const auto& pubkey : m_frozen_open) {
        m_admitted_open.erase(pubkey);
    }
}

void AttestationStore::AdmitOpenSigner(const CPubKey& pubkey)
{
    std::lock_guard lock{m_mutex};
    AdmitOpenLocked(pubkey);
}

void AttestationStore::ChallengeWindowReplay(int32_t height,
                                             const uint256& block_hash)
{
    std::lock_guard lock{m_mutex};
    for (const auto& existing : m_window_challenges) {
        if (existing.height == height && existing.block_hash == block_hash) {
            return;
        }
    }
    m_window_challenges.push_back(WindowReplayChallenge{height, block_hash});
    while (m_window_challenges.size() > m_config.max_window_challenges) {
        m_window_challenges.erase(m_window_challenges.begin());
    }
}

std::vector<AttestationStore::WindowReplayChallenge>
AttestationStore::WindowReplayChallenges() const
{
    std::lock_guard lock{m_mutex};
    return m_window_challenges;
}

bool AttestationStore::WindowReplayAnswered(const CPubKey& pubkey) const
{
    std::lock_guard lock{m_mutex};
    if (m_window_challenges.empty()) return true;
    for (const auto& challenge : m_window_challenges) {
        const auto bucket{
            m_buckets.find(BlockKey{challenge.height, challenge.block_hash})};
        if (bucket != m_buckets.end() &&
            bucket->second.attestations.count(pubkey) != 0) {
            continue;
        }
        bool heard{false};
        for (const auto& [key, attestation] : m_heard) {
            (void)attestation;
            if (key.height == challenge.height &&
                key.hash == challenge.block_hash && key.signer == pubkey) {
                heard = true;
                break;
            }
        }
        if (!heard) return false;
    }
    return true;
}

AddResult AttestationStore::AddRefutation(
    const ExactReplayRefutation& refutation,
    const uint256& expected_hash,
    int32_t expected_height)
{
    const VerifyResult crypto{VerifyRefutationCrypto(
        refutation, m_config.chain_id, m_config.replay_authority_context,
        expected_hash, expected_height)};
    if (crypto != VerifyResult::Valid) {
        std::lock_guard lock{m_mutex};
        ++m_stats.rejected;
        return ToAddResult(crypto);
    }
    {
        std::lock_guard lock{m_mutex};
        // Directory TTL even on a refute-only flood; pin buckets are not
        // this path's DoS surface (Add() / PruneExpired handle those).
        PruneExpiredDirectoryLocked(Clock::now());
        if (IsBlockedLocked(refutation.signer)) {
            ++m_stats.rejected;
            return AddResult::BlocklistedSigner;
        }
        const bool pinned{m_trusted_signers.count(refutation.signer) != 0};
        if (!pinned) {
            if (!m_config.open_attestors ||
                m_admitted_open.count(refutation.signer) == 0 ||
                m_frozen_open.count(refutation.signer) != 0) {
                ++m_stats.rejected;
                return AddResult::UntrustedSigner;
            }
        }
        const BlockKey key{expected_height, expected_hash};
        auto& bucket{m_refutations[key]};
        if (bucket.count(refutation.signer) != 0) {
            ++m_stats.duplicates;
            return AddResult::Duplicate;
        }
        bucket.emplace(refutation.signer, refutation);
        m_refutation_updated[key] = Clock::now();
        RefreshPinRefutedLocked(key);
        CapRefutationsLocked();
        ++m_stats.accepted;
    }
    m_changed.notify_all();
    return AddResult::Accepted;
}

} // namespace matmul::trusted
