// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_OPEN_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_OPEN_H

#include <modelnet/swarm_nicheslots/table.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Open one niche on its own row.
 * A name other than general, coding, or research is NICHE and stores nothing.
 * When the niche is already open, the call is REPLAY and the first slot
 * count stays, including when the new count is below 1.
 * A first open with slots below 1 is SLOTS and stores nothing.
 */
bool SwarmNicheSlotsOpen(SwarmNicheSlotsTable& table, const std::string& niche, int64_t slots, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_OPEN_H
