// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFORWARD2_H
#define BTX_MODELNET_SWARM_NOTNOFORWARD2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one hop. forwarder records that this hop is a
 * forwarder. want_charge asks this note to charge a fee.
 *
 * A forwarder fee is not charged. charged stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoForward2 {
    std::string hop_id;
    bool forwarder{false};
    bool want_charge{false};
};

/**
 * Outcome of noting a hop. charged stays false and atoms stays 0 on
 * every path. A forwarder fee is not charged.
 */
struct SwarmNotNoForward2Result {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a hop without charging a forwarder fee. Order, first match wins:
 * an empty hop_id is HOP. forwarder is NOT_CHARGED even when want_charge
 * is false. want_charge is HELD. Otherwise the note is NOTED and err is
 * cleared. charged stays false and atoms stays 0 on every path. A
 * forwarder fee is not charged.
 */
SwarmNotNoForward2Result SwarmNoteNotNoForward2(const SwarmNotNoForward2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFORWARD2_H
