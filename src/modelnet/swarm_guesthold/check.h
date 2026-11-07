// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_CHECK_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_CHECK_H

#include <modelnet/swarm_guesthold/book.h>

#include <string>

namespace modelnet {

/**
 * Records one guest-agent check and leaves it unpassed.
 * An empty name is GUEST and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is NOT_PASSED.
 * A second Check of the same name is REPLAY and leaves the first check.
 * Those checks run in that order. Nothing passes, nothing logs in,
 * and no bytes move.
 */
class SwarmGuestHoldCheck {
public:
    bool Apply(SwarmGuestHoldBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_CHECK_H
