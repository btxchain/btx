// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HASHLOCK_H
#define BITCOIN_MODELNET_SWARM_HASHLOCK_H

#include <modelnet/swarm_hashlock/offer.h>
#include <modelnet/swarm_hashlock/policy.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Hashlock claim plane.
 * Offer stores a 32-byte payment hash under an id. Claim marks that
 * offer claimed when the preimage is 32 bytes and one SHA-256 of it
 * equals the stored hash. A second matching claim does not claim twice.
 * A hashlock is not a qualified route. Nothing is broadcast.
 * bytes_moved() and atoms_moved() stay 0.
 */
class SwarmHashlock {
public:
    /**
     * Empty id is INVOICE and stores nothing.
     * payment_hash size != 32 is PREIMAGE and stores nothing.
     * Duplicate id is REPLAY and keeps the first hash.
     */
    bool Offer(const std::string& id, const std::vector<unsigned char>& payment_hash, std::string& err);

    /**
     * Unknown id is INVOICE.
     * preimage.size() != 32 is PREIMAGE and stores nothing.
     * A digest mismatch is HASHLOCK and nothing is marked claimed.
     * A match sets claimed once. The same preimage again is REPLAY.
     */
    bool Claim(const std::string& id, const std::vector<unsigned char>& preimage, std::string& err);

    bool offered(const std::string& id) const;
    bool claimed(const std::string& id) const;
    int claims(const std::string& id) const;
    bool stored_hash(const std::string& id, std::vector<unsigned char>& out) const;

    bool qualified() const { return m_policy.qualified(); }
    bool broadcast() const { return m_policy.broadcast(); }
    int64_t bytes_moved() const { return m_policy.bytes_moved(); }
    int64_t atoms_moved() const { return m_policy.atoms_moved(); }

private:
    SwarmHashlockOfferBook m_offers;
    SwarmHashlockPolicy m_policy;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HASHLOCK_H
