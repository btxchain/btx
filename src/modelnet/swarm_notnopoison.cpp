// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopoison.h>

namespace modelnet {

SwarmNotNoPoisonResult SwarmNoteNotNoPoison(const SwarmNotNoPoison& note, std::string& err)
{
    SwarmNotNoPoisonResult result;
    result.published = false;
    result.trained = false;
    // A poisoned sample is frozen, published nowhere, and trains nothing.
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.trained = false;
        err = "SAMPLE";
        return result;
    }
    if (note.poisoned) {
        result.code = "FROZEN";
        result.published = false;
        result.trained = false;
        err = "FROZEN";
        return result;
    }
    if (note.want_publish) {
        result.code = "FROZEN";
        result.published = false;
        result.trained = false;
        err = "FROZEN";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
