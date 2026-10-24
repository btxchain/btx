// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SCALEEXEC_H
#define BTX_MODELNET_SWARM_SCALEEXEC_H

#include <string>

namespace modelnet {

/**
 * A timescale record is not execution. Medium and long execution need a
 * training runtime this function does not have. executed, trained, and
 * bytes_moved stay false: this does not train and does not treat a record
 * as a checkpoint.
 */
struct SwarmScaleExecResult {
    bool executed{false};
    bool trained{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Order: an empty or unknown scale is TIMESCALE. A missing record is
 * NOT_FOUND. Medium and long are TRAIN_ABSENT. Immediate and short are
 * RECORD_ONLY and clear err. This does not train and does not treat a
 * record as a checkpoint.
 */
SwarmScaleExecResult SwarmExecuteTimescale(const std::string& scale, bool record_present, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SCALEEXEC_H
