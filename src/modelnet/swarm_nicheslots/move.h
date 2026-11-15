// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_MOVE_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_MOVE_H

#include <modelnet/swarm_nicheslots/table.h>

#include <string>

namespace modelnet {

/**
 * Assignment across niches is refused.
 * The table is taken by const reference so neither remaining can change.
 * The result is always NOT_MERGED.
 */
bool SwarmNicheSlotsMove(const SwarmNicheSlotsTable& table, const std::string& task, const std::string& from,
                         const std::string& to, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_MOVE_H
