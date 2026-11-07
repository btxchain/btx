// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoquality.h>

namespace modelnet {

SwarmNotNoQualityResult SwarmNoteNotNoQuality(const SwarmNotNoQuality& note, std::string& err)
{
    SwarmNotNoQualityResult result;
    result.promoted = false;
    result.admitted = false;
    // A quality graduation is not a realm promotion and admits nothing to ExactReplay.
    if (note.candidate_id.empty()) {
        result.code = "CANDIDATE";
        result.promoted = false;
        result.admitted = false;
        err = "CANDIDATE";
        return result;
    }
    if (note.want_promote) {
        result.code = "NOT_REALM";
        result.promoted = false;
        result.admitted = false;
        err = "NOT_REALM";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
