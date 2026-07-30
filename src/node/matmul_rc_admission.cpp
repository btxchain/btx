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
}

RCAdmissionStore::RememberResult RCAdmissionStore::Remember(
    const RCAdmissionTicket& ticket,
    uint64_t keyed_netgroup,
    std::chrono::steady_clock::time_point now)
{
    Prune(now);
    if (m_entries.count(ticket.block_hash) != 0) {
        return RememberResult::Duplicate;
    }
    if (m_entries.size() >= m_config.max_entries) {
        return RememberResult::GlobalQuota;
    }
    if (NetgroupSize(keyed_netgroup) >= m_config.max_entries_per_netgroup) {
        return RememberResult::NetgroupQuota;
    }
    m_entries.emplace(ticket.block_hash,
                      Entry{ticket, keyed_netgroup, now});
    ++m_netgroup_counts[keyed_netgroup];
    return RememberResult::Stored;
}

bool RCAdmissionStore::Consume(const CBlockHeader& header,
                               uint64_t keyed_netgroup,
                               const uint256& pow_limit,
                               std::chrono::steady_clock::time_point now,
                               RCAdmissionTicket* accepted_ticket)
{
    Prune(now);
    const auto it{m_entries.find(header.GetHash())};
    if (it == m_entries.end()) return false;
    // A ticket cannot be planted through one netgroup and spent through
    // another. Trusted/manual callers bypass this store at the caller.
    if (it->second.keyed_netgroup != keyed_netgroup) return false;
    const bool valid{
        CheckRCAdmissionTicket(it->second.ticket, header, pow_limit)};
    if (valid && accepted_ticket != nullptr) {
        *accepted_ticket = it->second.ticket;
    }
    EraseIterator(it); // valid or invalid: one cryptographic attempt per sidecar
    return valid;
}

void RCAdmissionStore::Erase(const uint256& block_hash)
{
    const auto it{m_entries.find(block_hash)};
    if (it != m_entries.end()) EraseIterator(it);
}

void RCAdmissionStore::Prune(std::chrono::steady_clock::time_point now)
{
    for (auto it = m_entries.begin(); it != m_entries.end();) {
        if (now - it->second.received <= m_config.ttl) {
            ++it;
            continue;
        }
        auto stale{it++};
        EraseIterator(stale);
    }
}

size_t RCAdmissionStore::NetgroupSize(uint64_t keyed_netgroup) const
{
    const auto it{m_netgroup_counts.find(keyed_netgroup)};
    return it == m_netgroup_counts.end() ? 0 : it->second;
}

void RCAdmissionStore::EraseIterator(std::map<uint256, Entry>::iterator it)
{
    const uint64_t group{it->second.keyed_netgroup};
    m_entries.erase(it);
    const auto count_it{m_netgroup_counts.find(group)};
    if (count_it == m_netgroup_counts.end()) return;
    if (count_it->second <= 1) {
        m_netgroup_counts.erase(count_it);
    } else {
        --count_it->second;
    }
}

} // namespace node
