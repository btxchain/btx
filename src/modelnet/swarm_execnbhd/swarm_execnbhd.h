// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_H

#include <modelnet/swarm_execnbhd/identity.h>
#include <modelnet/swarm_execnbhd/limits.h>
#include <modelnet/swarm_execnbhd/offer.h>
#include <modelnet/swarm_execnbhd/quiet.h>
#include <modelnet/swarm_execnbhd/seating.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process execution neighborhood.
 *
 * Offer stores an authorized, compatible peer. Seat places the lowest-RTT
 * admitted peers into the nearby set, up to kSwarmExecNbhdNearbyCap, and
 * then up to kSwarmExecNbhdRemoteCap peers whose trust domain is absent
 * from that nearby set. Ties break by ascending peer id, bytewise.
 *
 * Peer ids and trust-domain ids are opaque strings. This plane does not
 * open a socket, connect, discover by DNS, or move bytes. connected(),
 * socket_opened(), launched(), gpu(), and broadcast() stay false.
 * bytes_moved() stays 0. automatic_spend() stays "0". atoms_moved() stays 0.
 * No method on this class assigns a live value to those gauges.
 *
 * Refusal paths return false and set err to the code. Accepted paths
 * return true and clear err. Seat with fewer than the caps still returns
 * true and seats what qualifies. Seat replaces the previous seating.
 */
class SwarmExecNeighborhood {
public:
    /**
     * Store one peer. First match wins: empty peer is PEER, rtt_ms below 0
     * is RTT, empty trust_domain is DOMAIN, authorized false is
     * NOT_AUTHORIZED, compatible false is NOT_COMPAT. A second offer of
     * the same peer id is REPLAY and keeps the first record, including
     * its original rtt and domain. Otherwise the peer is stored.
     * Offering does not seat anyone.
     */
    bool Offer(const std::string& peer, int64_t rtt_ms, const std::string& trust_domain, bool authorized,
               bool compatible, std::string& err);

    /**
     * Replace the seating from the stored admitted peers.
     * Nearby is the lowest rtt_ms, then ascending peer id, up to the
     * nearby cap. Remote is taken from the peers that were not seated
     * nearby whose trust domain is not already present in the nearby set,
     * up to the remote cap, same order. A later new domain stays unseated
     * once the remote cap is full. A peer whose domain is already in the
     * nearby set cannot fill a remote slot. This does not connect.
     */
    bool Seat(std::string& err);

    /**
     * Empty peer is PEER. Any other peer is NOT_CONNECTED.
     * The peer is not stored and not seated by this call.
     * connected() stays false.
     */
    bool Fallback(const std::string& peer, std::string& err);

    /**
     * Unknown or unseated peer is NOT_SEATED. Two seated peers in
     * different trust domains are NOT_COMPAT and do not share a page.
     * Two seated peers in the same trust domain return true.
     * bytes_moved() stays 0 either way. Same-domain seating is not a
     * byte transfer.
     */
    bool ShareKv(const std::string& left_peer, const std::string& right_peer, std::string& err);

    /**
     * Empty id is NEIGHBORHOOD and stores nothing. A non-empty id is
     * stored. The same id again is REPLAY. A different id is HELD and
     * keeps the first.
     */
    bool Identity(const std::string& neighborhood_id, std::string& err);

    int64_t offered_count() const;
    int64_t nearby_count() const;
    int64_t remote_count() const;
    bool seated(const std::string& peer) const;
    bool nearby(const std::string& peer) const;
    bool remote(const std::string& peer) const;
    /** Domain stored by Offer. Empty when the peer was not stored. */
    std::string domain_of(const std::string& peer) const;
    std::string identity() const;

    bool connected() const;
    bool socket_opened() const;
    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    int64_t bytes_moved() const;
    std::string automatic_spend() const;
    int64_t atoms_moved() const;

private:
    SwarmExecNbhdOfferBook m_offers;
    SwarmExecNbhdSeating m_seating;
    SwarmExecNbhdIdentity m_identity;
    SwarmExecNbhdQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_H
