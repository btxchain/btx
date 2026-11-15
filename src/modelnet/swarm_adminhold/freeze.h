// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_FREEZE_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_FREEZE_H

#include <modelnet/swarm_adminhold/book.h>

#include <string>

namespace modelnet {

/**
 * An admin move of a stored refund field.
 * An unknown channel is CHANNEL. A known channel is HELD.
 * The book is taken by const reference, so the opened height and key stay.
 */
class SwarmAdminHoldFreeze {
public:
    bool refuse(const SwarmAdminHoldBook& book, const std::string& channel, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_FREEZE_H
