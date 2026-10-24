// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnodownlicgrant2.h>

#include <string>

namespace modelnet {

SwarmNotNoDownLicGrant2Result SwarmNoteNotNoDownLicGrant2(const SwarmNotNoDownLicGrant2& note, std::string& err)
{
    SwarmNotNoDownLicGrant2Result result;
    result.granted = false;
    // A download license is not a training grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.granted = false;
        err = "LICENSE";
        return result;
    }
    if (note.download) {
        result.code = "NOT_GRANTED";
        result.granted = false;
        err = "NOT_GRANTED";
        return result;
    }
    if (note.want_train) {
        result.code = "HELD";
        result.granted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    err.clear();
    return result;
}

} // namespace modelnet
