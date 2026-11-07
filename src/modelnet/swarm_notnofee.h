// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFEE_H
#define BTX_MODELNET_SWARM_NOTNOFEE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one hop. want_charge asks this note to charge a
 * forwarder fee.
 *
 * A forwarder-fee note charges nothing. charged stays false and atoms
 * stays 0 on every path.
 */
struct SwarmNotNoFee {
    std::string hop_id;
    bool want_charge{false};
};

/**
 * Outcome of noting a forwarder fee. charged stays false and atoms stays
 * 0: a forwarder-fee note charges nothing.
 */
struct SwarmNotNoFeeResult {
    std::string code;
    bool charged{false};
    int64_t atoms{0};
};

/**
 * Note a forwarder fee without charging it.
 * Order, first match wins: an empty hop_id is HOP. want_charge is
 * NOT_CHARGED. Otherwise the note is NOTED and err is clear.
 * charged stays false and atoms stays 0 on every path. A forwarder-fee
 * note charges nothing.
 */
SwarmNotNoFeeResult SwarmNoteNotNoFee(const SwarmNotNoFee& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFEE_H
