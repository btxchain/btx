// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDISPUTE_H
#define BTX_MODELNET_SWARM_NOTDISPUTE_H

#include <string>

namespace modelnet {

/**
 * A local note about one receipt. want_settle asks this note to settle.
 *
 * This note stores no txid, does not mine, and does not broadcast.
 * settled and broadcast stay false on every path.
 */
struct SwarmNotDispute {
    std::string receipt_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a dispute request. settled and broadcast stay false
 * on every path: this note stores no txid, does not mine, and does not
 * broadcast.
 */
struct SwarmNotDisputeResult {
    std::string code;
    bool settled{false};
    bool broadcast{false};
};

/**
 * Note a dispute request without storing a txid, mining, or broadcasting.
 * Order, first match wins: an empty receipt_id is RECEIPT. want_settle is
 * NOT_SETTLED. Otherwise the note is NOTED and err is clear.
 * settled and broadcast stay false on every path. This note stores no
 * txid, does not mine, and does not broadcast.
 */
SwarmNotDisputeResult SwarmNoteNotDispute(const SwarmNotDispute& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDISPUTE_H
