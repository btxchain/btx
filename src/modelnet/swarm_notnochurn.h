// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCHURN_H
#define BTX_MODELNET_SWARM_NOTNOCHURN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one worker. gone marks the worker as departed.
 * want_pay asks this note to pay that worker.
 *
 * A departed worker is not paid by this note. paid stays false and
 * atoms stays 0 on every path.
 */
struct SwarmNotNoChurn {
    std::string worker_id;
    bool gone{false};
    bool want_pay{false};
};

/**
 * Outcome of noting a worker. paid stays false and atoms stays 0 on
 * every path. A departed worker is not paid by this note.
 */
struct SwarmNotNoChurnResult {
    std::string code;
    bool paid{false};
    int64_t atoms{0};
};

/**
 * Note a worker without paying a departed worker.
 * Order, first match wins: an empty worker_id is WORKER. gone is HELD,
 * even when want_pay is false. want_pay is HELD. Otherwise the note is
 * NOTED and err is clear. paid stays false and atoms stays 0 on every
 * path. A departed worker is not paid by this note.
 */
SwarmNotNoChurnResult SwarmNoteNotNoChurn(const SwarmNotNoChurn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCHURN_H
