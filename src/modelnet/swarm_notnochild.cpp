// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochild.h>

#include <string>

namespace modelnet {

SwarmNotNoChildResult SwarmNoteNotNoChild(const SwarmNotNoChild& note, std::string& err)
{
    SwarmNotNoChildResult result;
    result.streamed = false;
    result.activated = false;
    // A missing, truncated, reordered, wrong-digest, or wrong-length child
    // streams nothing and activates nothing. A manifest root is not proof
    // of its children.
    if (note.manifest_id.empty()) {
        result.code = "MANIFEST";
        result.streamed = false;
        result.activated = false;
        err = "MANIFEST";
        return result;
    }
    if (!note.child_matches) {
        result.code = "INCOMPLETE";
        result.streamed = false;
        result.activated = false;
        err = "INCOMPLETE";
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
