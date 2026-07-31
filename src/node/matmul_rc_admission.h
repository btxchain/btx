// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_NODE_MATMUL_RC_ADMISSION_H
#define BTX_NODE_MATMUL_RC_ADMISSION_H

#include <arith_uint256.h>
#include <primitives/block.h>
#include <serialize.h>
#include <uint256.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <vector>

namespace node {

/**
 * P2P-only admission ticket for an expensive RC ExactReplay attempt.
 *
 * This object is deliberately not part of CBlockHeader or CBlock. It therefore
 * adds no blockchain bytes and cannot change the consensus block hash. The
 * ticket is a policy throttle; successful ExactReplay remains the only
 * authority and unauthenticated header work receives no fork-choice credit.
 */
struct RCAdmissionTicket {
    uint256 block_hash{};
    uint64_t nonce{0};

    SERIALIZE_METHODS(RCAdmissionTicket, obj)
    {
        READWRITE(obj.block_hash, obj.nonce);
    }
};

/**
 * Poseidon2-GL12("BTX_RC_ADMIT_P2_V1" || block_hash || nonce_le64).
 *
 * The four canonical Goldilocks output lanes are encoded LE64 as a uint256.
 * This deliberately avoids renting Bitcoin SHA ASICs for verifier admission.
 */
[[nodiscard]] uint256 RCAdmissionTicketHash(const RCAdmissionTicket& ticket);

/**
 * Frozen V1 policy target:
 *
 *   raw = DecodeCompact(nBits) << 48
 *   target = clamp(raw, target_for_20_bits, target_for_12_bits)
 *
 * Thus admission retains proportionality to claimed work in an explicit
 * eight-bit window, while an honest ticket is bounded to 2^12..2^20 expected
 * Poseidon2 permutations. ExactReplay and delayed chainwork—not this throttle—
 * remain the security authority.
 */
[[nodiscard]] std::optional<arith_uint256> DeriveRCAdmissionTarget(
    uint32_t nBits, const uint256& pow_limit);

[[nodiscard]] bool CheckRCAdmissionTicket(const RCAdmissionTicket& ticket,
                                          const CBlockHeader& header,
                                          const uint256& pow_limit);

/** Mine a ticket without changing the block/header. max_tries is decremented. */
[[nodiscard]] bool GrindRCAdmissionTicket(const CBlockHeader& header,
                                          const uint256& pow_limit,
                                          RCAdmissionTicket& ticket,
                                          uint64_t& max_tries);

/**
 * Bounded, per-netgroup sidecar store and admission budget.
 *
 * Unknown-header tickets enter a deliberately small quarantine. They neither
 * consume the independently bounded validated-ticket capacity nor monopolize a
 * block hash: candidates are keyed by (block_hash, keyed_netgroup), with a
 * small per-hash fan-in bound. Once the header is known, RememberKnown()
 * authenticates before allocating validated capacity. Consume() may also
 * authenticate the matching quarantined candidate when a header arrives after
 * its sidecar.
 *
 * Tickets remain bound to their source netgroup and are single-use locally.
 * An invalid candidate from one netgroup is never consulted or erased while
 * another netgroup consumes its own candidate, preventing cross-netgroup
 * spending without allowing a planted candidate to censor the hash.
 */
class RCAdmissionStore
{
public:
    struct Config {
        /** Cryptographically validated, known-header entries. */
        size_t max_entries{256};
        size_t max_entries_per_netgroup{4};
        /** Unverified, unknown-header quarantine (separate capacity). */
        size_t max_unknown_entries{32};
        size_t max_unknown_entries_per_netgroup{2};
        size_t max_unknown_candidates_per_hash{2};
        /** Reconnect-resistant unknown-ticket submission rate per netgroup. */
        size_t max_unknown_submissions_per_netgroup{8};
        std::chrono::seconds unknown_submission_window{60};
        std::chrono::seconds ttl{180};
    };

    enum class RememberResult : uint8_t {
        Stored,
        Duplicate,
        Invalid,
        GlobalQuota,
        NetgroupQuota,
        HashQuota,
        RateLimited,
    };

    RCAdmissionStore();
    explicit RCAdmissionStore(Config config);

    [[nodiscard]] RememberResult Remember(const RCAdmissionTicket& ticket,
                                          uint64_t keyed_netgroup,
                                          std::chrono::steady_clock::time_point now);

    /**
     * Authenticate a ticket for a known header before storing it. A validated
     * ticket replaces a quarantined candidate for the same hash/netgroup, but
     * an invalid duplicate can never displace a validated ticket.
     */
    [[nodiscard]] RememberResult RememberKnown(
        const RCAdmissionTicket& ticket,
        const CBlockHeader& header,
        uint64_t keyed_netgroup,
        const uint256& pow_limit,
        std::chrono::steady_clock::time_point now);

    [[nodiscard]] bool Consume(const CBlockHeader& header,
                               uint64_t keyed_netgroup,
                               const uint256& pow_limit,
                               std::chrono::steady_clock::time_point now,
                               RCAdmissionTicket* accepted_ticket = nullptr);

    void Erase(const uint256& block_hash);
    void Prune(std::chrono::steady_clock::time_point now);
    [[nodiscard]] size_t Size() const
    {
        return m_validated_entries.size() + m_unknown_entries.size();
    }
    [[nodiscard]] size_t ValidatedSize() const
    {
        return m_validated_entries.size();
    }
    [[nodiscard]] size_t UnknownSize() const { return m_unknown_entries.size(); }
    [[nodiscard]] size_t NetgroupSize(uint64_t keyed_netgroup) const;
    [[nodiscard]] size_t UnknownNetgroupSize(uint64_t keyed_netgroup) const;
    [[nodiscard]] size_t UnknownCandidatesForHash(
        const uint256& block_hash) const;

private:
    using EntryKey = std::pair<uint256, uint64_t>;

    struct Entry {
        RCAdmissionTicket ticket;
        std::chrono::steady_clock::time_point received{};
    };

    void EraseValidatedIterator(std::map<EntryKey, Entry>::iterator it);
    void EraseUnknownIterator(std::map<EntryKey, Entry>::iterator it);
    void PruneSubmissionHistory(std::chrono::steady_clock::time_point now);

    Config m_config;
    std::map<EntryKey, Entry> m_validated_entries;
    std::map<EntryKey, Entry> m_unknown_entries;
    std::map<uint64_t, size_t> m_validated_netgroup_counts;
    std::map<uint64_t, size_t> m_unknown_netgroup_counts;
    std::map<uint256, size_t> m_unknown_hash_counts;
    std::map<uint64_t, std::vector<std::chrono::steady_clock::time_point>>
        m_unknown_submission_history;
};

} // namespace node

#endif // BTX_NODE_MATMUL_RC_ADMISSION_H
