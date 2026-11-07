// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notgradleak.h>

#include <string>

namespace modelnet {

SwarmNotGradLeakResult SwarmNoteNotGradLeak(const SwarmNotGradLeak& note, std::string& err)
{
    SwarmNotGradLeakResult result;
    result.published = false;
    result.bytes_moved = false;
    // This note does not publish a gradient or move bytes.
    if (note.gradient_id.empty()) {
        result.code = "GRADIENT";
        result.published = false;
        result.bytes_moved = false;
        err = "GRADIENT";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
