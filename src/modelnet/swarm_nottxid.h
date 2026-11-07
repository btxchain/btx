// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTXID_H
#define BTX_MODELNET_SWARM_NOTTXID_H

#include <string>

namespace modelnet {

/**
 * A local note about one payment. want_store asks this note to store a
 * broadcast txid.
 *
 * This note stores no broadcast txid.
 * stored and broadcast stay false on every path.
 */
struct SwarmNotTxid {
    std::string payment_id;
    bool want_store{false};
};

/**
 * Outcome of noting a payment. stored and broadcast stay false on every
 * path: this note stores no broadcast txid.
 */
struct SwarmNotTxidResult {
    std::string code;
    bool stored{false};
    bool broadcast{false};
};

/**
 * Note a payment without storing a broadcast txid.
 * Order, first match wins: an empty payment_id is PAYMENT. want_store is
 * NOT_STORED. Otherwise the note is NOTED and err is clear.
 * stored and broadcast stay false on every path. This note stores no
 * broadcast txid.
 */
SwarmNotTxidResult SwarmNoteNotTxid(const SwarmNotTxid& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTXID_H
