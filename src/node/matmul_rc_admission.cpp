// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/matmul_rc_admission.h>

#include <arith_uint256.h>
#include <crypto/common.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <pow.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace node {
namespace {
constexpr char ADMISSION_DOMAIN[] = "BTX_RC_ADMIT_P2_V1";
constexpr uint32_t ADMISSION_NBITS_DISCOUNT{48};
constexpr uint32_t ADMISSION_MIN_WORK_BITS{12};
constexpr uint32_t ADMISSION_MAX_WORK_BITS{20};

arith_uint256 TargetForWorkBits(uint32_t bits)
{
    arith_uint256 target{1};
    target <<= 256 - bits;
    target -= 1;
    return target;
}
}

uint256 RCAdmissionTicketHash(const RCAdmissionTicket& ticket)
{
    using namespace matmul::v4::rc;
    std::vector<unsigned char> preimage;
    preimage.insert(
        preimage.end(), ADMISSION_DOMAIN,
        ADMISSION_DOMAIN + sizeof(ADMISSION_DOMAIN) - 1);
    preimage.insert(
        preimage.end(), ticket.block_hash.begin(), ticket.block_hash.end());
    std::array<unsigned char, 8> nonce_bytes{};
    WriteLE64(nonce_bytes.data(), ticket.nonce);
    preimage.insert(preimage.end(), nonce_bytes.begin(), nonce_bytes.end());

    // Seven-byte limbs are injective into Goldilocks (each < 2^56 < p).
    std::vector<alg_hash::Fp> lanes;
    lanes.reserve((preimage.size() + 6) / 7 + 1);
    lanes.push_back(gkr_field::FromU64(preimage.size()));
    for (size_t offset = 0; offset < preimage.size(); offset += 7) {
        uint64_t limb{0};
        const size_t count{std::min<size_t>(7, preimage.size() - offset)};
        for (size_t i = 0; i < count; ++i) {
            limb |= static_cast<uint64_t>(preimage[offset + i]) << (8 * i);
        }
        lanes.push_back(gkr_field::FromU64(limb));
    }
    const alg_hash::Digest digest{alg_hash::SpongeHashFp(lanes)};
    uint256 out;
    for (size_t i = 0; i < digest.size(); ++i) {
        WriteLE64(out.data() + i * 8, gkr_field::Canonical(digest[i]));
    }
    return out;
}

std::optional<arith_uint256> DeriveRCAdmissionTarget(
    uint32_t nBits, const uint256& pow_limit)
{
    const auto block_target{DeriveTarget(nBits, pow_limit)};
    if (!block_target) return std::nullopt;
    arith_uint256 raw{*block_target};
    if ((raw >> (256 - ADMISSION_NBITS_DISCOUNT)) != arith_uint256{0}) {
        raw = UintToArith256(pow_limit);
    } else {
        raw <<= ADMISSION_NBITS_DISCOUNT;
    }
    const arith_uint256 hardest{TargetForWorkBits(ADMISSION_MAX_WORK_BITS)};
    const arith_uint256 easiest{TargetForWorkBits(ADMISSION_MIN_WORK_BITS)};
    return std::clamp(raw, hardest, easiest);
}

bool CheckRCAdmissionTicket(const RCAdmissionTicket& ticket,
                            const CBlockHeader& header,
                            const uint256& pow_limit)
{
    if (ticket.block_hash != header.GetHash()) return false;
    const auto target{DeriveRCAdmissionTarget(header.nBits, pow_limit)};
    return target.has_value() &&
           UintToArith256(RCAdmissionTicketHash(ticket)) <= *target;
}

bool GrindRCAdmissionTicket(const CBlockHeader& header,
                            const uint256& pow_limit,
                            RCAdmissionTicket& ticket,
                            uint64_t& max_tries)
{
    ticket.block_hash = header.GetHash();
    while (max_tries > 0) {
        if (CheckRCAdmissionTicket(ticket, header, pow_limit)) {
            return true;
        }
        if (ticket.nonce == std::numeric_limits<uint64_t>::max()) return false;
        ++ticket.nonce;
        --max_tries;
    }
    return CheckRCAdmissionTicket(ticket, header, pow_limit);
}

RCAdmissionStore::RCAdmissionStore() : RCAdmissionStore(Config{}) {}

RCAdmissionStore::RCAdmissionStore(Config config) : m_config{config}
{
    m_config.max_entries = std::max<size_t>(1, m_config.max_entries);
    m_config.max_entries_per_netgroup =
        std::max<size_t>(1, m_config.max_entries_per_netgroup);
    m_config.max_validated_candidates_per_hash =
        std::max<size_t>(1, m_config.max_validated_candidates_per_hash);
    m_config.max_unknown_entries =
        std::max<size_t>(1, m_config.max_unknown_entries);
    m_config.max_unknown_entries_per_netgroup =
        std::max<size_t>(1, m_config.max_unknown_entries_per_netgroup);
    m_config.max_unknown_candidates_per_hash =
        std::max<size_t>(1, m_config.max_unknown_candidates_per_hash);
    m_config.max_unknown_submissions_per_netgroup =
        std::max<size_t>(1, m_config.max_unknown_submissions_per_netgroup);
}

RCDeferredBodyCooldowns::RCDeferredBodyCooldowns()
    : RCDeferredBodyCooldowns(Config{})
{
}

RCDeferredBodyCooldowns::RCDeferredBodyCooldowns(Config config)
    : m_config{config}
{
    m_config.max_entries = std::max<size_t>(1, m_config.max_entries);
    m_config.cooldown = std::max(std::chrono::seconds{1}, m_config.cooldown);
}

bool RCDeferredBodyCooldowns::Mark(
    const uint256& block_hash,
    int64_t peer_id,
    std::chrono::steady_clock::time_point now)
{
    const auto key{std::make_pair(block_hash, peer_id)};
    const auto existing{m_deadlines.find(key)};
    if (existing != m_deadlines.end()) {
        if (now < existing->second) {
            // Deliberately do not refresh. Otherwise one source can keep a
            // hash globally suppressed by redelivering a ticketless body just
            // before every deadline. This hot duplicate path is O(log n).
            return false;
        }
        m_deadlines.erase(existing);
    }
    if (m_deadlines.size() >= m_config.max_entries) {
        const auto oldest{std::min_element(
            m_deadlines.begin(), m_deadlines.end(),
            [](const auto& lhs, const auto& rhs) {
                return lhs.second < rhs.second;
            })};
        if (oldest != m_deadlines.end()) m_deadlines.erase(oldest);
    }
    m_deadlines.emplace(key, now + m_config.cooldown);
    return true;
}

bool RCDeferredBodyCooldowns::Contains(
    const uint256& block_hash,
    int64_t peer_id,
    std::chrono::steady_clock::time_point now)
{
    const auto it{m_deadlines.find(std::make_pair(block_hash, peer_id))};
    if (it == m_deadlines.end()) return false;
    // FindNextBlocks calls this once per candidate. Scanning the entire store
    // on every negative lookup would turn download selection into
    // O(candidates * cooldowns) work after a ticketless-body flood. Expire only
    // the queried key here; Mark()/Size() retain global pruning, and capacity
    // eviction still chooses the oldest deadline.
    if (now >= it->second) {
        m_deadlines.erase(it);
        return false;
    }
    return true;
}

void RCDeferredBodyCooldowns::Erase(const uint256& block_hash)
{
    // Erase across all peers: admission succeeded or validation reached a
    // terminal verdict for this block, so no source needs holding off.
    for (auto it{m_deadlines.lower_bound(std::make_pair(block_hash, std::numeric_limits<int64_t>::min()))};
         it != m_deadlines.end() && it->first.first == block_hash;) {
        it = m_deadlines.erase(it);
    }
}

void RCDeferredBodyCooldowns::Clear()
{
    m_deadlines.clear();
}

size_t RCDeferredBodyCooldowns::Size(
    std::chrono::steady_clock::time_point now)
{
    Prune(now);
    return m_deadlines.size();
}

void RCDeferredBodyCooldowns::Prune(
    std::chrono::steady_clock::time_point now)
{
    for (auto it{m_deadlines.begin()}; it != m_deadlines.end();) {
        if (now >= it->second) {
            it = m_deadlines.erase(it);
        } else {
            ++it;
        }
    }
}

RCAdmissionStore::RememberResult RCAdmissionStore::Remember(
    const RCAdmissionTicket& ticket,
    uint64_t keyed_netgroup,
    std::chrono::steady_clock::time_point now)
{
    Prune(now);
    const EntryKey key{ticket.block_hash, keyed_netgroup};
    // Check process-wide/per-hash capacity before creating per-netgroup rate
    // state. Otherwise a Sybil could grow the rate-history map without bound
    // merely by submitting while quarantine is already full, or by targeting
    // a hash whose candidate fan-in is full.
    if (m_unknown_entries.size() >= m_config.max_unknown_entries) {
        return RememberResult::GlobalQuota;
    }
    if (UnknownCandidatesForHash(ticket.block_hash) >=
            m_config.max_unknown_candidates_per_hash &&
        m_unknown_entries.count(key) == 0) {
        return RememberResult::HashQuota;
    }
    auto& submissions{m_unknown_submission_history[keyed_netgroup]};
    if (submissions.size() >=
        m_config.max_unknown_submissions_per_netgroup) {
        return RememberResult::RateLimited;
    }
    submissions.push_back(now);
    if (m_unknown_entries.count(key) != 0) {
        return RememberResult::Duplicate;
    }
    if (UnknownNetgroupSize(keyed_netgroup) >=
        m_config.max_unknown_entries_per_netgroup) {
        return RememberResult::NetgroupQuota;
    }
    m_unknown_entries.emplace(key, Entry{ticket, now});
    ++m_unknown_netgroup_counts[keyed_netgroup];
    ++m_unknown_hash_counts[ticket.block_hash];
    return RememberResult::Stored;
}

RCAdmissionStore::RememberResult RCAdmissionStore::RememberKnown(
    const RCAdmissionTicket& ticket,
    const CBlockHeader& header,
    uint64_t keyed_netgroup,
    const uint256& pow_limit,
    std::chrono::steady_clock::time_point now)
{
    Prune(now);
    const EntryKey key{header.GetHash(), keyed_netgroup};
    if (ticket.block_hash != header.GetHash() ||
        !CheckRCAdmissionTicket(ticket, header, pow_limit)) {
        return RememberResult::Invalid;
    }
    if (m_validated_entries.count(key) != 0) {
        return RememberResult::Duplicate;
    }
    if (ValidatedCandidatesForHash(header.GetHash()) >=
        m_config.max_validated_candidates_per_hash) {
        return RememberResult::HashQuota;
    }
    if (m_validated_entries.size() >= m_config.max_entries) {
        return RememberResult::GlobalQuota;
    }
    if (NetgroupSize(keyed_netgroup) >=
        m_config.max_entries_per_netgroup) {
        return RememberResult::NetgroupQuota;
    }

    // A now-authenticated sidecar supersedes only the quarantine candidate
    // from its own netgroup. Candidates planted by other groups remain unable
    // to spend this entry and unable to prevent it from being stored.
    const auto unknown{m_unknown_entries.find(key)};
    if (unknown != m_unknown_entries.end()) EraseUnknownIterator(unknown);
    m_validated_entries.emplace(key, Entry{ticket, now});
    ++m_validated_netgroup_counts[keyed_netgroup];
    ++m_validated_hash_counts[header.GetHash()];
    return RememberResult::Stored;
}

bool RCAdmissionStore::Consume(const CBlockHeader& header,
                               uint64_t keyed_netgroup,
                               const uint256& pow_limit,
                               std::chrono::steady_clock::time_point now,
                               RCAdmissionTicket* accepted_ticket)
{
    Prune(now);
    const EntryKey key{header.GetHash(), keyed_netgroup};

    const auto validated{m_validated_entries.find(key)};
    if (validated != m_validated_entries.end()) {
        if (accepted_ticket != nullptr) {
            *accepted_ticket = validated->second.ticket;
        }
        EraseValidatedIterator(validated);
        return true;
    }

    const auto unknown{m_unknown_entries.find(key)};
    if (unknown == m_unknown_entries.end()) return false;
    const bool valid{
        CheckRCAdmissionTicket(unknown->second.ticket, header, pow_limit)};
    if (valid && accepted_ticket != nullptr) {
        *accepted_ticket = unknown->second.ticket;
    }
    // Valid or invalid: one cryptographic attempt per source-bound sidecar.
    // Candidates belonging to other groups are deliberately untouched.
    EraseUnknownIterator(unknown);
    return valid;
}

bool RCAdmissionStore::RestoreConsumed(
    const RCAdmissionTicket& ticket,
    const CBlockHeader& header,
    uint64_t keyed_netgroup,
    const uint256& pow_limit,
    std::chrono::steady_clock::time_point now)
{
    Prune(now);
    const uint256 hash{header.GetHash()};
    const EntryKey key{hash, keyed_netgroup};
    if (ticket.block_hash != hash ||
        !CheckRCAdmissionTicket(ticket, header, pow_limit)) {
        return false;
    }
    if (m_validated_entries.count(key) != 0) return true;

    // Consume() created room for this paid attempt. If another candidate used
    // that room before the caller could roll back, reclaim it deterministically
    // without ever exceeding a configured bound. Prefer the oldest entry in
    // the specific conflicting dimension, then the oldest global entry.
    const auto erase_oldest_matching = [&](const auto& predicate) {
        auto victim{m_validated_entries.end()};
        for (auto it{m_validated_entries.begin()};
             it != m_validated_entries.end(); ++it) {
            if (!predicate(it->first)) continue;
            if (victim == m_validated_entries.end() ||
                it->second.received < victim->second.received ||
                (it->second.received == victim->second.received &&
                 it->first < victim->first)) {
                victim = it;
            }
        }
        if (victim == m_validated_entries.end()) return false;
        EraseValidatedIterator(victim);
        return true;
    };

    while (ValidatedCandidatesForHash(hash) >=
           m_config.max_validated_candidates_per_hash) {
        if (!erase_oldest_matching(
                [&](const EntryKey& candidate) {
                    return candidate.first == hash;
                })) {
            return false;
        }
    }
    while (NetgroupSize(keyed_netgroup) >=
           m_config.max_entries_per_netgroup) {
        if (!erase_oldest_matching(
                [&](const EntryKey& candidate) {
                    return candidate.second == keyed_netgroup;
                })) {
            return false;
        }
    }
    while (m_validated_entries.size() >= m_config.max_entries) {
        if (!erase_oldest_matching([](const EntryKey&) { return true; })) {
            return false;
        }
    }

    m_validated_entries.emplace(key, Entry{ticket, now});
    ++m_validated_netgroup_counts[keyed_netgroup];
    ++m_validated_hash_counts[hash];
    return true;
}

void RCAdmissionStore::Erase(const uint256& block_hash)
{
    for (auto it = m_validated_entries.lower_bound({block_hash, 0});
         it != m_validated_entries.end() && it->first.first == block_hash;) {
        auto erase{it++};
        EraseValidatedIterator(erase);
    }
    for (auto it = m_unknown_entries.lower_bound({block_hash, 0});
         it != m_unknown_entries.end() && it->first.first == block_hash;) {
        auto erase{it++};
        EraseUnknownIterator(erase);
    }
}

void RCAdmissionStore::Prune(std::chrono::steady_clock::time_point now)
{
    for (auto it = m_validated_entries.begin();
         it != m_validated_entries.end();) {
        if (now - it->second.received <= m_config.ttl) {
            ++it;
            continue;
        }
        auto stale{it++};
        EraseValidatedIterator(stale);
    }
    for (auto it = m_unknown_entries.begin();
         it != m_unknown_entries.end();) {
        if (now - it->second.received <= m_config.ttl) {
            ++it;
            continue;
        }
        auto stale{it++};
        EraseUnknownIterator(stale);
    }
    PruneSubmissionHistory(now);
}

size_t RCAdmissionStore::NetgroupSize(uint64_t keyed_netgroup) const
{
    const auto it{m_validated_netgroup_counts.find(keyed_netgroup)};
    return it == m_validated_netgroup_counts.end() ? 0 : it->second;
}

size_t RCAdmissionStore::ValidatedCandidatesForHash(
    const uint256& block_hash) const
{
    const auto it{m_validated_hash_counts.find(block_hash)};
    return it == m_validated_hash_counts.end() ? 0 : it->second;
}

size_t RCAdmissionStore::UnknownNetgroupSize(uint64_t keyed_netgroup) const
{
    const auto it{m_unknown_netgroup_counts.find(keyed_netgroup)};
    return it == m_unknown_netgroup_counts.end() ? 0 : it->second;
}

size_t RCAdmissionStore::UnknownCandidatesForHash(
    const uint256& block_hash) const
{
    const auto it{m_unknown_hash_counts.find(block_hash)};
    return it == m_unknown_hash_counts.end() ? 0 : it->second;
}

void RCAdmissionStore::EraseValidatedIterator(
    std::map<EntryKey, Entry>::iterator it)
{
    const uint256 hash{it->first.first};
    const uint64_t group{it->first.second};
    m_validated_entries.erase(it);
    const auto count_it{m_validated_netgroup_counts.find(group)};
    if (count_it != m_validated_netgroup_counts.end()) {
        if (count_it->second <= 1) {
            m_validated_netgroup_counts.erase(count_it);
        } else {
            --count_it->second;
        }
    }
    const auto hash_count{m_validated_hash_counts.find(hash)};
    if (hash_count != m_validated_hash_counts.end()) {
        if (hash_count->second <= 1) {
            m_validated_hash_counts.erase(hash_count);
        } else {
            --hash_count->second;
        }
    }
}

void RCAdmissionStore::EraseUnknownIterator(
    std::map<EntryKey, Entry>::iterator it)
{
    const uint256 hash{it->first.first};
    const uint64_t group{it->first.second};
    m_unknown_entries.erase(it);

    const auto group_count{m_unknown_netgroup_counts.find(group)};
    if (group_count != m_unknown_netgroup_counts.end()) {
        if (group_count->second <= 1) {
            m_unknown_netgroup_counts.erase(group_count);
        } else {
            --group_count->second;
        }
    }
    const auto hash_count{m_unknown_hash_counts.find(hash)};
    if (hash_count != m_unknown_hash_counts.end()) {
        if (hash_count->second <= 1) {
            m_unknown_hash_counts.erase(hash_count);
        } else {
            --hash_count->second;
        }
    }
}

void RCAdmissionStore::PruneSubmissionHistory(
    std::chrono::steady_clock::time_point now)
{
    for (auto it = m_unknown_submission_history.begin();
         it != m_unknown_submission_history.end();) {
        auto& times{it->second};
        times.erase(
            std::remove_if(
                times.begin(), times.end(),
                [&](const auto submitted) {
                    return now - submitted >
                           m_config.unknown_submission_window;
                }),
            times.end());
        if (times.empty()) {
            it = m_unknown_submission_history.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace node
