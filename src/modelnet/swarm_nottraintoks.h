// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTTRAINTOKS_H
#define BTX_MODELNET_SWARM_NOTTRAINTOKS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one job. want_publish asks this note to publish a
 * training token rate.
 *
 * One SGD step is not a training token rate. published stays false and
 * tokens_per_sec stays 0 on every path.
 */
struct SwarmNotTrainToks {
    std::string job_id;
    bool want_publish{false};
};

/**
 * Outcome of noting a training-token request. published stays false and
 * tokens_per_sec stays 0 on every path: one SGD step is not a training
 * token rate.
 */
struct SwarmNotTrainToksResult {
    std::string code;
    bool published{false};
    int64_t tokens_per_sec{0};
};

/**
 * Note a job without publishing a training token rate. Order, first match
 * wins: an empty job_id is JOB. want_publish is UNMEASURED. Otherwise the
 * note is NOTED and err is clear. published stays false and tokens_per_sec
 * stays 0 on every path. One SGD step is not a training token rate.
 */
SwarmNotTrainToksResult SwarmNoteNotTrainToks(const SwarmNotTrainToks& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTTRAINTOKS_H
