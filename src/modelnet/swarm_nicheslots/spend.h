// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NICHESLOTS_SPEND_H
#define BITCOIN_MODELNET_SWARM_NICHESLOTS_SPEND_H

#include <modelnet/swarm_nicheslots/table.h>

#include <string>

namespace modelnet {

/**
 * Spend one task against one niche.
 * An unknown name, or a known name that was not opened, is NICHE and
 * stores nothing. An empty task is TASK and stores nothing. A task
 * already recorded in this niche is REPLAY and does not decrement.
 * A new task when remaining is 0 is EXHAUSTED and stores nothing.
 * Otherwise only this niche's remaining drops by one and the task is
 * appended there. Other niches are not read for the update.
 */
bool SwarmNicheSlotsSpend(SwarmNicheSlotsTable& table, const std::string& niche, const std::string& task,
                          std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NICHESLOTS_SPEND_H
