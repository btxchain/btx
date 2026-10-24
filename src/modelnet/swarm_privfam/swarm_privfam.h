// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PRIVFAM_H
#define BITCOIN_MODELNET_SWARM_PRIVFAM_H

#include <modelnet/swarm_privfam/link.h>
#include <modelnet/swarm_privfam/quiet.h>
#include <modelnet/swarm_privfam/roster.h>
#include <modelnet/swarm_privfam/seeds.h>
#include <modelnet/swarm_privfam/shelf.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Private-family plane.
 * A private family is not published. DNS seeds stay empty. Nothing connects.
 *
 * Offer stores a family only when family is non-empty and private_flag
 * is true. An empty family is FAMILY and stores nothing. private_flag
 * false is PUBLIC and stores nothing. A second Offer of a stored family
 * is REPLAY and keeps the first privacy flag. A successful Offer returns
 * true and clears err.
 *
 * Publish of a stored private family is NOT_PUBLISHED and published()
 * stays false. Publish of an unknown family is FAMILY. Publish of an
 * empty family is FAMILY.
 *
 * AddSeed returns HELD. dns_seeds() stays empty. connected() stays false.
 * bytes_moved() stays 0. launched() stays false.
 */
class SwarmPrivFamily {
public:
    bool Offer(const std::string& family, bool private_flag, std::string& err);
    bool Publish(const std::string& family, std::string& err);
    bool AddSeed(const std::string& host, std::string& err);

    bool offered(const std::string& family) const;
    bool is_private(const std::string& family) const;
    std::size_t offered_count() const;
    bool published() const;
    bool published(const std::string& family) const;
    const std::vector<std::string>& dns_seeds() const;
    bool connected() const;
    bool connected(const std::string& family) const;
    int64_t bytes_moved() const;
    bool launched() const;

private:
    SwarmPrivFamRoster m_roster;
    SwarmPrivFamShelf m_shelf;
    SwarmPrivFamLink m_link;
    SwarmPrivFamSeeds m_seeds;
    SwarmPrivFamQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PRIVFAM_H
