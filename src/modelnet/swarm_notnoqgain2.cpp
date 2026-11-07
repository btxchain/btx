// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoqgain2.h>

namespace modelnet {

SwarmNotNoQgain2Result SwarmNoteNotNoQgain2(const SwarmNotNoQgain2& note, std::string& err)
{
    SwarmNotNoQgain2Result result;
    result.gained = false;
    if (note.step_id.empty()) {
        result.code = "STEP";
        result.gained = false;
        err = "STEP";
        return result;
    }
    // One GPU step is not a quality gain.
    if (note.one_step) {
        result.code = "NOT_GAIN";
        result.gained = false;
        err = "NOT_GAIN";
        return result;
    }
    if (note.want_claim) {
        result.code = "HELD";
        result.gained = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.gained = false;
    err.clear();
    return result;
}

} // namespace modelnet
