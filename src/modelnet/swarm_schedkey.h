// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SCHEDKEY_H
#define BTX_MODELNET_SWARM_SCHEDKEY_H

#include <string>

namespace modelnet {

/**
 * A local note that a scheduler was named, and whether that note asked
 * for a spend key. The scheduler never receives a spend key. This note
 * does not sign and does not broadcast.
 */
struct SwarmSchedKey {
    std::string scheduler_id;
    bool want_spend_key{false};
};

/**
 * Outcome of noting a scheduler key request. spend_armed stays false on
 * every path. The scheduler never receives a spend key.
 */
struct SwarmSchedKeyResult {
    std::string code;
    bool spend_armed{false};
};

/**
 * Note a scheduler key request without arming a spend key.
 * Order, first match wins: an empty scheduler_id is KEY.
 * want_spend_key is NO_KEY. Otherwise the note is NOTED and err is
 * clear. spend_armed stays false on every path. The scheduler never
 * receives a spend key. This note does not sign and does not broadcast.
 */
SwarmSchedKeyResult SwarmNoteSchedKey(const SwarmSchedKey& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SCHEDKEY_H
