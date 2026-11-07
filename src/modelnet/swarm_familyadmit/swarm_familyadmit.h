// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAMILYADMIT_H
#define BITCOIN_MODELNET_SWARM_FAMILYADMIT_H

#include <modelnet/swarm_familyadmit/link.h>
#include <modelnet/swarm_familyadmit/quiet.h>
#include <modelnet/swarm_familyadmit/roster.h>
#include <modelnet/swarm_familyadmit/seeds.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Family-admission plane.
 * A peer that advertises compatibility without a matching family id is
 * not admitted. Discovery does not connect. bytes_moved() stays 0.
 *
 * Admit stores a peer only when peer and family are non-empty,
 * claims_compatible is true, and advertised_family equals family.
 * Empty peer or family is FAMILY and stores nothing. claims_compatible
 * true with a different advertised family is FALSE_COMPAT and stores
 * nothing. claims_compatible false is NOT_ADMITTED and stores nothing
 * even when the family strings match. A duplicate peer is REPLAY and
 * keeps the first family.
 *
 * admitted(peer) is true only after a successful Admit. connected(peer)
 * is always false. dns_seeds() is empty. AddSeed returns HELD and the
 * list stays empty. launched() stays false.
 */
class SwarmFamilyAdmit {
public:
    bool Admit(const std::string& peer,
               const std::string& family,
               const std::string& advertised_family,
               bool claims_compatible,
               std::string& err);
    bool AddSeed(const std::string& seed, std::string& err);

    bool admitted(const std::string& peer) const;
    std::string family_of(const std::string& peer) const;
    std::size_t admitted_count() const;
    bool connected(const std::string& peer) const;
    const std::vector<std::string>& dns_seeds() const;
    int64_t bytes_moved() const;
    bool launched() const;

private:
    SwarmFamilyAdmitRoster m_roster;
    SwarmFamilyAdmitLink m_link;
    SwarmFamilyAdmitSeeds m_seeds;
    SwarmFamilyAdmitQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAMILYADMIT_H
