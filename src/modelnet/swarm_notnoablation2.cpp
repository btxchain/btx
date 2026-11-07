// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoablation2.h>

#include <string>

namespace modelnet {

SwarmNotNoAblation2Result SwarmNoteNotNoAblation2(const SwarmNotNoAblation2& note, std::string& err)
{
    SwarmNotNoAblation2Result result;
    result.published = false;
    // An ablation has not run and this note publishes no multiplier.
    if (note.study_id.empty()) {
        result.code = "STUDY";
        result.published = false;
        err = "STUDY";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    err.clear();
    return result;
}

} // namespace modelnet
