// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINSTALL_H
#define BTX_MODELNET_SWARM_NOTNOINSTALL_H

#include <string>

namespace modelnet {

/**
 * A local note that a package might be installed.
 * want_install asks this note to install one.
 *
 * This note installs nothing and moves no bytes. installed and
 * bytes_moved stay false on every path.
 */
struct SwarmNotNoInstall {
    std::string package_id;
    bool want_install{false};
};

/**
 * Outcome of noting that nothing is installed. installed and bytes_moved
 * stay false on every path: this note installs nothing and moves no
 * bytes.
 */
struct SwarmNotNoInstallResult {
    std::string code;
    bool installed{false};
    bool bytes_moved{false};
};

/**
 * Note that nothing is installed and no bytes are moved.
 * Order, first match wins: an empty package_id is PACKAGE. want_install is
 * NOT_INSTALLED. Otherwise the note is NOTED and err is cleared.
 * installed and bytes_moved stay false on every path. This note installs
 * nothing and moves no bytes.
 */
SwarmNotNoInstallResult SwarmNoteNotNoInstall(const SwarmNotNoInstall& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINSTALL_H
