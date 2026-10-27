// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_WORKER_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_WORKER_H

#include <modelnet/swarm_faultboard/checkpoint.h>
#include <modelnet/swarm_faultboard/quiet.h>
#include <modelnet/swarm_faultboard/result.h>

#include <string>

namespace modelnet {

/**
 * Checkpoint publication crash, worker disconnect, and duplicate receipt.
 * A stored result is not deleted. gpu() is not raised. saved() stays false.
 */
bool SwarmFaultGpuCrash(const SwarmFaultCheckpoint& checkpoint, const SwarmFaultQuiet& quiet, std::string& err);
bool SwarmFaultWorkerDisconnect(const SwarmFaultResultBook& results, const std::string& task, std::string& err);
bool SwarmFaultDuplicateReceipt(const SwarmFaultResultBook& results, const std::string& task, const std::string& receipt, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_WORKER_H
