// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFAMILYDIR_H
#define BTX_MODELNET_SWARM_NOTFAMILYDIR_H

#include <string>

namespace modelnet {

/**
 * A local note about one family. want_publish asks this note to publish
 * a global family directory.
 *
 * This note does not publish a global family directory. published and
 * global_dir stay false on every path.
 */
struct SwarmNotFamilyDir {
    std::string family_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a family-directory request. published and global_dir
 * stay false on every path. This note does not publish a global family
 * directory.
 */
struct SwarmNotFamilyDirResult {
    std::string code;
    bool published{false};
    bool global_dir{false};
};

/**
 * Note a family-directory request without publishing a global family directory.
 * Order, first match wins: an empty family_id is FAMILY. want_publish is
 * NOT_PUBLISHED. Otherwise the note is NOTED and err is clear.
 * published and global_dir stay false on every path. This note does not
 * publish a global family directory.
 */
SwarmNotFamilyDirResult SwarmNoteNotFamilyDir(const SwarmNotFamilyDir& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFAMILYDIR_H
