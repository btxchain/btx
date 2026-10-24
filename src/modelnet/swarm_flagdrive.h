// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAGDRIVE_H
#define BTX_MODELNET_SWARM_FLAGDRIVE_H

#include <string>

namespace modelnet {

/** Local 13-stage flagship cursor. It does not train, spend, broadcast, mine, or move bytes. */
enum class SwarmFlagStage {
    Acquire = 0,
    Join,
    Coordinate,
    Accelerate,
    Experience,
    Train,
    Evolve,
    Evaluate,
    Graduate,
    Adopt,
    Pay,
    Recover,
    Repeat
};

struct SwarmFlagDrive {
    std::string lineage_id;
    SwarmFlagStage stage{SwarmFlagStage::Acquire};
    bool hardware_seen{false};
    bool want_pass{false};
};

struct SwarmFlagDriveResult {
    std::string code;
    SwarmFlagStage stage{SwarmFlagStage::Acquire};
    bool passed{false};
    bool advanced{false};
};

/**
 * Advance one local flagship stage.
 * The flagship cursor can advance a local stage and cannot pass a hardware demonstration.
 * Order, first match wins: an empty lineage_id is LINEAGE at Acquire.
 * hardware_seen false is UNQUALIFIED and leaves the stage unchanged, even when want_pass is false.
 * want_pass is HELD and leaves the stage unchanged.
 * Repeat is NOTED and stays Repeat.
 * Otherwise the note is NOTED, err is clear, and the stage becomes the next enumerator.
 * passed stays false on every path.
 */
SwarmFlagDriveResult SwarmAdvanceFlagship(const SwarmFlagDrive& drive, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAGDRIVE_H
