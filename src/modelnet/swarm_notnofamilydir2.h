// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFAMILYDIR2_H
#define BTX_MODELNET_SWARM_NOTNOFAMILYDIR2_H

#include <string>

namespace modelnet {

/**
 * A local note about one family directory. directory_id names the directory.
 * want_publish asks this note to publish an address.
 *
 * A global family directory publishes no address. published stays false
 * on every path.
 */
struct SwarmNotNoFamilyDir2 {
    std::string directory_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a family directory. published stays false on every path.
 * A global family directory publishes no address.
 */
struct SwarmNotNoFamilyDir2Result {
    std::string code;
    bool published{false};
};

/**
 * Note a family directory without publishing an address.
 * Order, first match wins: an empty directory_id is DIRECTORY. want_publish
 * is HELD. Otherwise the note is NOTED and err is cleared.
 * published stays false on every path.
 * A global family directory publishes no address.
 */
SwarmNotNoFamilyDir2Result SwarmNoteNotNoFamilyDir2(const SwarmNotNoFamilyDir2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFAMILYDIR2_H
