// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDUP_H
#define BTX_MODELNET_SWARM_NOTDUP_H

#include <string>

namespace modelnet {

/**
 * A local note about one work receipt. want_accept asks this note to treat
 * a duplicate work receipt after reconnect as this live case.
 *
 * A duplicate work receipt after reconnect is not this live case.
 * accepted stays false on every path.
 */
struct SwarmNotDup {
    std::string receipt_id;
    bool want_accept{false};
};

/**
 * Outcome of noting a duplicate-receipt request. accepted stays false on
 * every path: a duplicate work receipt after reconnect is not this live case.
 */
struct SwarmNotDupResult {
    std::string code;
    bool accepted{false};
};

/**
 * Note a duplicate-receipt request without treating it as this live case.
 * Order, first match wins: an empty receipt_id is RECEIPT. want_accept is
 * NOT_LIVE. Otherwise the note is NOTED and err is clear.
 * accepted stays false on every path.
 */
SwarmNotDupResult SwarmNoteNotDup(const SwarmNotDup& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDUP_H
