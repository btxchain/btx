// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowrongdig.h>

#include <string>

namespace modelnet {

SwarmNotNoWrongDigResult SwarmNoteNotNoWrongDig(const SwarmNotNoWrongDig& note, std::string& err)
{
    SwarmNotNoWrongDigResult result;
    result.streamed = false;
    result.activated = false;
    // A wrong-digest child streams nothing and does not activate.
    if (note.child_id.empty()) {
        result.code = "CHILD";
        result.streamed = false;
        result.activated = false;
        err = "CHILD";
        return result;
    }
    if (note.wrong_digest) {
        result.code = "NOT_STREAMED";
        result.streamed = false;
        result.activated = false;
        err = "NOT_STREAMED";
        return result;
    }
    if (note.want_stream) {
        result.code = "HELD";
        result.streamed = false;
        result.activated = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.streamed = false;
    result.activated = false;
    err.clear();
    return result;
}

} // namespace modelnet
