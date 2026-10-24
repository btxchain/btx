// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAMILYDIR_H
#define BTX_MODELNET_SWARM_FAMILYDIR_H

#include <string>

namespace modelnet {

/**
 * A local family-directory record. family_id names the family.
 * want_publish asks this record to publish a family directory.
 *
 * A family directory publish request is held and publishes nothing.
 * published stays false on every path. No hostname, IP, or key path
 * is used.
 */
struct SwarmFamilyDir {
    std::string family_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a family directory. published stays false on every
 * path. A family directory publish request is held and publishes nothing.
 */
struct SwarmFamilyDirResult {
    std::string code;
    bool published{false};
};

/**
 * Note a family directory without publishing it.
 * Order, first match wins: an empty family_id is FAMILY. want_publish
 * is HELD. Otherwise the note is NOTED and err is clear.
 * published stays false on every path. A family directory publish
 * request is held and publishes nothing.
 */
SwarmFamilyDirResult SwarmNoteFamilyDir(const SwarmFamilyDir& family, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAMILYDIR_H
