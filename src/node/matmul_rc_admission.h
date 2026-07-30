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
 * Remember() is intentionally cheap and does not need a header. Consume()
 * performs the cryptographic check once the matching contextual header is
 * known. A valid ticket is single-use locally so replaying it cannot repeatedly
 * buy verifier slots. Netgroup quotas prevent a large peer fan-out in one
 * address group from filling the sidecar store.
 */
class RCAdmissionStore
{
public:
    struct Config {
        size_t max_entries{256};
        size_t max_entries_per_netgroup{4};
        std::chrono::seconds ttl{180};
    };

    enum class RememberResult : uint8_t {
        Stored,
        Duplicate,
        GlobalQuota,
        NetgroupQuota,
    };

    RCAdmissionStore();
    explicit RCAdmissionStore(Config config);

    [[nodiscard]] RememberResult Remember(const RCAdmissionTicket& ticket,
                                          uint64_t keyed_netgroup,
                                          std::chrono::steady_clock::time_point now);

    [[nodiscard]] bool Consume(const CBlockHeader& header,
                               uint64_t keyed_netgroup,
                               const uint256& pow_limit,
                               std::chrono::steady_clock::time_point now,
                               RCAdmissionTicket* accepted_ticket = nullptr);

    void Erase(const uint256& block_hash);
    void Prune(std::chrono::steady_clock::time_point now);
    [[nodiscard]] size_t Size() const { return m_entries.size(); }
    [[nodiscard]] size_t NetgroupSize(uint64_t keyed_netgroup) const;

private:
    struct Entry {
        RCAdmissionTicket ticket;
        uint64_t keyed_netgroup{0};
        std::chrono::steady_clock::time_point received{};
    };

    void EraseIterator(std::map<uint256, Entry>::iterator it);

    Config m_config;
    std::map<uint256, Entry> m_entries;
    std::map<uint64_t, size_t> m_netgroup_counts;
};

} // namespace node

#endif // BTX_NODE_MATMUL_RC_ADMISSION_H
