// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REMEDY_BOOK_H
#define BITCOIN_MODELNET_SWARM_REMEDY_BOOK_H

#include <modelnet/swarm_paymesh.h>
#include <modelnet/swarm_remedy/open.h>
#include <modelnet/swarm_remedy/supersede.h>

#include <string>

namespace modelnet {

/**
 * One stored revocation, plus the prior retained after a successful supersede.
 * A second Open is REPLAY and leaves the first.
 * A stale Supersede leaves the stored revocation in place.
 * secret_released() is the prior flag when a prior exists, otherwise the
 * current flag. Open stores a revocation whose flag is false.
 */
class SwarmRemedyBook {
public:
    bool Open(int sequence, unsigned char fill, std::string& err);
    bool Supersede(int sequence, unsigned char fill, std::string& err);

    bool opened() const { return m_opened; }
    bool has_prior() const { return m_has_prior; }
    int sequence() const { return m_current.sequence; }
    bool secret_released() const;
    const SwarmRevocation& current() const { return m_current; }
    const SwarmRevocation& prior() const { return m_prior; }

private:
    SwarmRemedyOpen m_open;
    SwarmRemedySupersede m_supersede;
    SwarmRevocation m_current;
    SwarmRevocation m_prior;
    bool m_opened{false};
    bool m_has_prior{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REMEDY_BOOK_H
