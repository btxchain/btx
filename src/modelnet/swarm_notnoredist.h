// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOREDIST_H
#define BTX_MODELNET_SWARM_NOTNOREDIST_H

#include <string>

namespace modelnet {

/**
 * A local note about one download license. want_redistribute asks this
 * note to grant redistribution.
 *
 * A download license is not a redistribution grant and moves no bytes.
 * redistributed and bytes_moved stay false on every path.
 */
struct SwarmNotNoRedist {
    std::string license_id;
    bool want_redistribute{false};
};

/**
 * Outcome of noting a download license. redistributed and bytes_moved
 * stay false on every path. A download license is not a redistribution
 * grant and moves no bytes.
 */
struct SwarmNotNoRedistResult {
    std::string code;
    bool redistributed{false};
    bool bytes_moved{false};
};

/**
 * Note a download license without granting redistribution.
 * Order, first match wins: an empty license_id is LICENSE.
 * want_redistribute is NOT_GRANT. Otherwise the note is NOTED and err
 * is cleared. redistributed and bytes_moved stay false on every path.
 * A download license is not a redistribution grant and moves no bytes.
 */
SwarmNotNoRedistResult SwarmNoteNotNoRedist(const SwarmNotNoRedist& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOREDIST_H
