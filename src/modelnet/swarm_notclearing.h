// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCLEARING_H
#define BTX_MODELNET_SWARM_NOTCLEARING_H

#include <string>

namespace modelnet {

/**
 * A local note about one clearing batch. want_settle asks this note to
 * settle the batch.
 *
 * This note does not settle a clearing batch or broadcast. settled and
 * broadcast stay false on every path. l1_txs stays 0 on every path.
 */
struct SwarmNotClearing {
    std::string batch_id;
    bool want_settle{false};
};

/**
 * Outcome of noting a clearing request. settled and broadcast stay false
 * on every path. l1_txs stays 0: this note does not settle a clearing
 * batch or broadcast.
 */
struct SwarmNotClearingResult {
    std::string code;
    bool settled{false};
    bool broadcast{false};
    int l1_txs{0};
};

/**
 * Note a clearing request without settling a clearing batch or
 * broadcasting.
 * Order, first match wins: an empty batch_id is BATCH. want_settle is
 * NOT_SETTLED. Otherwise the note is NOTED and err is clear.
 * settled and broadcast stay false on every path. l1_txs stays 0 on
 * every path.
 */
SwarmNotClearingResult SwarmNoteNotClearing(const SwarmNotClearing& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCLEARING_H
