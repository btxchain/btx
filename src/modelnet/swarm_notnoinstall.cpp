// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoinstall.h>

#include <string>

namespace modelnet {

SwarmNotNoInstallResult SwarmNoteNotNoInstall(const SwarmNotNoInstall& note, std::string& err)
{
    // This note installs nothing and moves no bytes.
    SwarmNotNoInstallResult result;
    result.installed = false;
    result.bytes_moved = false;
    if (note.package_id.empty()) {
        result.code = "PACKAGE";
        result.installed = false;
        result.bytes_moved = false;
        err = "PACKAGE";
        return result;
    }
    if (note.want_install) {
        result.code = "NOT_INSTALLED";
        result.installed = false;
        result.bytes_moved = false;
        err = "NOT_INSTALLED";
        return result;
    }
    result.code = "NOTED";
    result.installed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
