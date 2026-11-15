// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTPACKAGE_H
#define BTX_MODELNET_SWARM_NOTPACKAGE_H

#include <string>

namespace modelnet {

/**
 * A local note about one target. want_omit asks this note to omit the
 * swarm lifecycle from the default package.
 *
 * The default package must not silently omit the swarm lifecycle.
 * omitted and packaged stay false on every path.
 */
struct SwarmNotPackage {
    std::string target_id;
    bool want_omit{false};
};

/**
 * Outcome of noting a package request. omitted and packaged stay false
 * on every path. The default package must not silently omit the swarm
 * lifecycle.
 */
struct SwarmNotPackageResult {
    std::string code;
    bool omitted{false};
    bool packaged{false};
};

/**
 * Note a package request without omitting the swarm lifecycle.
 * Order, first match wins: an empty target_id is TARGET.
 * want_omit is PRESENT. Otherwise the note is NOTED and err is clear.
 * omitted and packaged stay false on every path.
 * The default package must not silently omit the swarm lifecycle.
 */
SwarmNotPackageResult SwarmNoteNotPackage(const SwarmNotPackage& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTPACKAGE_H
