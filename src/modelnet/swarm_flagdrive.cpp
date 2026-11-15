// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagdrive.h>

#include <string>

namespace modelnet {

SwarmFlagDriveResult SwarmAdvanceFlagship(const SwarmFlagDrive& drive, std::string& err)
{
    // The flagship cursor can advance a local stage and cannot pass a hardware demonstration.
    SwarmFlagDriveResult result;
    result.passed = false;
    result.advanced = false;
    result.stage = drive.stage;
    if (drive.lineage_id.empty()) {
        result.code = "LINEAGE";
        result.stage = SwarmFlagStage::Acquire;
        result.passed = false;
        result.advanced = false;
        err = "LINEAGE";
        return result;
    }
    if (!drive.hardware_seen) {
        result.code = "UNQUALIFIED";
        result.stage = drive.stage;
        result.passed = false;
        result.advanced = false;
        err = "UNQUALIFIED";
        return result;
    }
    if (drive.want_pass) {
        result.code = "HELD";
        result.stage = drive.stage;
        result.passed = false;
        result.advanced = false;
        err = "HELD";
        return result;
    }
    if (drive.stage == SwarmFlagStage::Repeat) {
        result.code = "NOTED";
        result.stage = SwarmFlagStage::Repeat;
        result.passed = false;
        result.advanced = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.stage = static_cast<SwarmFlagStage>(static_cast<int>(drive.stage) + 1);
    result.passed = false;
    result.advanced = true;
    err.clear();
    return result;
}

} // namespace modelnet
