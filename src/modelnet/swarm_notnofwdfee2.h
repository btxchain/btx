// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFWDFEE2_H
#define BTX_MODELNET_SWARM_NOTNOFWDFEE2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one edge. forwarder records that this edge is a
 * forwarder. want_charge asks this note to charge a fee.
 *
 * A forwarder fee is not charged. charged stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoFwdFee2 {
    std::string edge_id;
    bool forwarder{false};
    bool want_charge{false};
};

/**
 * Outcome of noting an edge. charged stays false and atoms stays 0 on
 * every path. A forwarder fee is not charged.
 */
struct SwarmNotNoFwdFee2Result {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note an edge without charging a forwarder fee. Order, first match wins:
 * an empty edge_id is EDGE. forwarder is NOT_CHARGED even when want_charge
 * is false. want_charge is HELD. Otherwise the note is NOTED and err is
 * cleared. charged stays false and atoms stays 0 on every path. A
 * forwarder fee is not charged.
 */
SwarmNotNoFwdFee2Result SwarmNoteNotNoFwdFee2(const SwarmNotNoFwdFee2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFWDFEE2_H
