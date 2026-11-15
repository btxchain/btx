// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_ISLAND_NIF_ISLAND_H
#define BITCOIN_MODELNET_NIF_ISLAND_NIF_ISLAND_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One physical host. Membership stores the measured rtt_us of qualified hardware.
 *
 * Admit: an empty member is MEMBER. qualified_hardware false is HARDWARE and
 * stores nothing. A second Admit of the same member is NIFDT_REPLAY and keeps
 * the first rtt_us. The stored rtt is the measured argument.
 *
 * Place assigns prefill or decode to an admitted member. An unknown member is
 * MEMBER. Prefill and decode may name different members. Place opens no socket.
 *
 * Push adds bytes to that member's queue. The cap is 8. The byte past the cap
 * is BACKPRESSURE and leaves queued() unchanged.
 *
 * Collective: rtt_us above 1000 returns false with NIFDT_NO_ROUTE and records
 * nothing. rtt_us at or below 1000 on an admitted member records one local
 * collective. gpu() stays false.
 *
 * launched(), broadcast(), and gpu() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND. physical_hosts() is 1.
 */
class NifIsland {
public:
    bool Admit(const std::string& member, int64_t rtt_us, bool qualified_hardware, std::string& err);
    bool Place(const std::string& member, const std::string& phase, std::string& err);
    bool Push(const std::string& member, int64_t bytes, std::string& err);
    bool Collective(const std::string& member, int64_t rtt_us, std::string& err);

    bool admitted(const std::string& member) const;
    int64_t rtt_us(const std::string& member) const;
    int64_t member_count() const { return static_cast<int64_t>(m_members.size()); }
    int64_t queued() const;
    int64_t queued(const std::string& member) const;
    std::string placed(const std::string& phase) const;
    int64_t local_collectives() const { return m_local_collectives; }
    int64_t last_local_rtt_us() const { return m_last_local_rtt_us; }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    bool socket_opened() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    bool gpu() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Member {
        std::string name;
        int64_t rtt_us{0};
        int64_t queued{0};
    };

    Member* Find(const std::string& member);
    const Member* Find(const std::string& member) const;

    static constexpr int64_t kQueueCap = 8;

    std::vector<Member> m_members;
    std::string m_prefill;
    std::string m_decode;
    int64_t m_local_collectives{0};
    int64_t m_last_local_rtt_us{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_ISLAND_NIF_ISLAND_H
