// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrepeat.h>

#include <string>

namespace modelnet {

SwarmNotRepeatResult SwarmNoteNotRepeat(const SwarmNotRepeat& note, std::string& err)
{
    SwarmNotRepeatResult result;
    result.repeated = false;
    // A second research cycle has not used a graduated model as its parent.
    if (note.parent_id.empty()) {
        result.code = "PARENT";
        result.repeated = false;
        err = "PARENT";
        return result;
    }
    if (note.want_repeat) {
        result.code = "NOT_REPEATED";
        result.repeated = false;
        err = "NOT_REPEATED";
        return result;
    }
    result.code = "NOTED";
    result.repeated = false;
    err.clear();
    return result;
}

} // namespace modelnet
