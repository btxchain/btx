// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFEE2_H
#define BTX_MODELNET_SWARM_NOTNOFEE2_H

#include <string>
#include <cstdint>

namespace modelnet {

/**
 * A local note about one edge. want_charge asks this note to charge a
 * forwarder fee from base, amount, and ppm.
 *
 * The formula base + (amount*ppm+999999)/1000000 is not applied. A
 * forwarder fee is not charged. charged stays false and atoms stays 0
 * on every path.
 */
struct SwarmNotNoFee2 {
    std::string edge_id;
    bool want_charge{false};
    int64_t base{0};
    int64_t amount{0};
    int64_t ppm{0};
};

/**
 * Outcome of noting a forwarder fee. charged stays false and atoms stays
 * 0: a forwarder fee is not charged.
 */
struct SwarmNotNoFee2Result {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a forwarder fee without charging it.
 * Order, first match wins: an empty edge_id is EDGE. want_charge is
 * NOT_CHARGED even when base, amount, and ppm are positive. The formula
 * base + (amount*ppm+999999)/1000000 is not applied. Otherwise the note
 * is NOTED and err is cleared.
 * charged stays false and atoms stays 0 on every path. A forwarder fee
 * is not charged.
 */
SwarmNotNoFee2Result SwarmNoteNotNoFee2(const SwarmNotNoFee2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFEE2_H
