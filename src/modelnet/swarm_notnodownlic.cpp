// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodownlic.h>

#include <string>

namespace modelnet {

SwarmNotNoDownLicResult SwarmNoteNotNoDownLic(const SwarmNotNoDownLic& note, std::string& err)
{
    SwarmNotNoDownLicResult result;
    result.trained = false;
    result.bytes_moved = false;
    // A download license is not a training grant and moves no bytes.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.trained = false;
        result.bytes_moved = false;
        err = "LICENSE";
        return result;
    }
    if (note.download_only) {
        result.code = "NOT_GRANT";
        result.trained = false;
        result.bytes_moved = false;
        err = "NOT_GRANT";
        return result;
    }
    if (note.want_train) {
        result.code = "NOT_GRANT";
        result.trained = false;
        result.bytes_moved = false;
        err = "NOT_GRANT";
        return result;
    }
    result.code = "NOTED";
    result.trained = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
