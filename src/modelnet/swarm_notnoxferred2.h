// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOXFERRED2_H
#define BTX_MODELNET_SWARM_NOTNOXFERRED2_H

#include <string>

namespace modelnet {

/**
 * A local note that a unit might publish a transferred-byte count.
 * want_publish asks this note to publish one.
 *
 * A unit note publishes no transferred-byte count. published stays false
 * and bytes stays 0 on every path.
 */
struct SwarmNotNoXferred2 {
    std::string sample_id;
    bool want_publish{false};
};

/**
 * Outcome of noting that no transferred-byte count is published. published
 * stays false and bytes stays 0 on every path.
 */
struct SwarmNotNoXferred2Result {
    std::string code;
    bool published{false};
    int bytes{0};
};

/**
 * Note that a unit note publishes no transferred-byte count.
 * Order, first match wins: an empty sample_id is SAMPLE. want_publish is
 * UNMEASURED. Otherwise the note is NOTED and err is cleared.
 * published stays false and bytes stays 0 on every path.
 * A unit note publishes no transferred-byte count.
 */
SwarmNotNoXferred2Result SwarmNoteNotNoXferred2(const SwarmNotNoXferred2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOXFERRED2_H
