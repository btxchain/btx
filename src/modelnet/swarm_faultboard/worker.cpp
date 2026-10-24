// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/worker.h>

#include <modelnet/swarm_faultboard/codes.h>

#include <string>

namespace modelnet {

bool SwarmFaultGpuCrash(const SwarmFaultCheckpoint& checkpoint, const SwarmFaultQuiet& quiet, std::string& err)
{
    const std::string id = checkpoint.id();
    const bool present = checkpoint.kept();
    const bool gpu_ran = quiet.gpu();
    const bool saved = quiet.saved();
    const bool launched = quiet.launched();
    (void)id;
    (void)present;
    (void)gpu_ran;
    (void)saved;
    (void)launched;
    err = kSwarmFaultSaveHeld;
    return false;
}

bool SwarmFaultWorkerDisconnect(const SwarmFaultResultBook& results, const std::string& task, std::string& err)
{
    const bool present = results.contains(task);
    if (present) {
        const std::string receipt = results.receipt_for(task);
        (void)receipt;
    }
    err = kSwarmFaultDisconnected;
    return false;
}

bool SwarmFaultDuplicateReceipt(const SwarmFaultResultBook& results, const std::string& task, const std::string& receipt, std::string& err)
{
    if (!results.contains(task)) {
        err = kSwarmFaultTask;
        return false;
    }
    if (results.receipt_for(task) == receipt) {
        err = kSwarmFaultReplay;
        return false;
    }
    err = kSwarmFaultConflict;
    return false;
}

} // namespace modelnet
