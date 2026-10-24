// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOQGAIN2_H
#define BTX_MODELNET_SWARM_NOTNOQGAIN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one GPU step. want_claim asks this note to record a
 * quality gain.
 *
 * One GPU step is not a quality gain. gained stays false on every path.
 */
struct SwarmNotNoQgain2 {
    std::string step_id;
    bool one_step{false};
    bool want_claim{false};
};

/**
 * Outcome of noting one GPU step. gained stays false on every path.
 * One GPU step is not a quality gain.
 */
struct SwarmNotNoQgain2Result {
    std::string code;
    bool gained{false};
};

/**
 * Note one GPU step without recording a quality gain.
 * Order, first match wins: an empty step_id is STEP. one_step is NOT_GAIN
 * even when want_claim is false. want_claim is HELD. Otherwise the note is
 * NOTED and err is cleared. gained stays false on every path. One GPU step
 * is not a quality gain.
 */
SwarmNotNoQgain2Result SwarmNoteNotNoQgain2(const SwarmNotNoQgain2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOQGAIN2_H
