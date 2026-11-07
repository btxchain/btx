// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoheadhide.h>

#include <string>

namespace modelnet {

SwarmNotNoHeadHideResult SwarmNoteNotNoHeadHide(const SwarmNotNoHeadHide& note, std::string& err)
{
    SwarmNotNoHeadHideResult result;
    result.hidden = false;
    result.trained = false;
    // Several heads stay visible. Hiding one does not train.
    if (note.head_id.empty()) {
        result.code = "HEAD";
        result.hidden = false;
        result.trained = false;
        err = "HEAD";
        return result;
    }
    if (note.want_hide) {
        result.code = "VISIBLE";
        result.hidden = false;
        result.trained = false;
        err = "VISIBLE";
        return result;
    }
    result.code = "NOTED";
    result.hidden = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
