// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoreplace.h>

#include <string>

namespace modelnet {

SwarmNotNoReplaceResult SwarmNoteNotNoReplace(const SwarmNotNoReplace& note, std::string& err)
{
    SwarmNotNoReplaceResult result;
    result.installed = false;
    result.bytes_moved = false;
    // Permanent coordinator loss does not install a replacement.
    if (note.coord_id.empty()) {
        result.code = "COORD";
        result.installed = false;
        result.bytes_moved = false;
        err = "COORD";
        return result;
    }
    // A permanently lost coordinator is NOT_INSTALLED even when want_install is false.
    if (note.gone) {
        result.code = "NOT_INSTALLED";
        result.installed = false;
        result.bytes_moved = false;
        err = "NOT_INSTALLED";
        return result;
    }
    // This note installs no replacement.
    if (note.want_install) {
        result.code = "HELD";
        result.installed = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.installed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
