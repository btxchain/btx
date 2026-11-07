// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOADVERT2_H
#define BTX_MODELNET_SWARM_NOTNOADVERT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one sample. caller_rate is a caller-supplied token
 * rate. want_advertise asks this note to advertise the sample.
 *
 * advertised stays false on every path. A caller-supplied token rate is
 * not an advertisement.
 */
struct SwarmNotNoAdvert2 {
    std::string sample_id;
    bool caller_rate{false};
    bool want_advertise{false};
};

/**
 * Outcome of noting a sample. advertised stays false on every path. A
 * caller-supplied token rate is not an advertisement.
 */
struct SwarmNotNoAdvert2Result {
    std::string code;
    bool advertised{false};
};

/**
 * Note a sample without advertising it. Order, first match wins: an
 * empty sample_id is SAMPLE. caller_rate is NOT_ADVERTISED even when
 * want_advertise is false. want_advertise is HELD. Otherwise the note
 * is NOTED and err is clear. advertised stays false on every path. A
 * caller-supplied token rate is not an advertisement.
 */
SwarmNotNoAdvert2Result SwarmNoteNotNoAdvert2(const SwarmNotNoAdvert2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOADVERT2_H
