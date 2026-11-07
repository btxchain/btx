// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/recover.h>

#include <utility>

#include <modelnet/swarm_engineflag.h>
#include <modelnet/swarm_exactstall.h>
#include <modelnet/swarm_fault01.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {

void SwarmEvolveRecover::SetCoordinator(std::string coordinator_id)
{
    m_coordinator_id = std::move(coordinator_id);
}

bool SwarmEvolveRecover::Recover(int64_t earned_atoms, bool checkpoint_present, const std::string& work_id, std::string& err)
{
    SwarmRecoverySnapshot in;
    in.pending_jobs = 0;
    in.earned_atoms = earned_atoms;
    in.channel_sequence = 0;
    in.checkpoint_present = checkpoint_present;
    in.payment_plane_present = true;
    in.execution_plane_present = true;
    in.frozen = false;
    SwarmRecoverySnapshot out;
    if (!SwarmCoordinatorLost(in, out, err)) return false;
    if (out.earned_atoms != earned_atoms || SwarmWorkerDisconnected(earned_atoms) != earned_atoms) {
        err = "EARNED";
        return false;
    }

    if (!m_coordinator_id.empty()) {
        SwarmFault01 fault;
        fault.coord_id = m_coordinator_id;
        fault.work_id = work_id.empty() ? std::string("generation") : work_id;
        fault.pending = false;
        fault.durable = true;
        fault.payment_claim = true;
        fault.want_commit = false;
        fault.want_reassign = false;
        std::string fault_err;
        const SwarmFault01Result recovered = SwarmRecoverFault01(fault, fault_err);
        if (!recovered.recovered || recovered.bytes_moved || recovered.broadcast || recovered.committed ||
            !recovered.payment_preserved) {
            err = fault_err.empty() ? recovered.code : fault_err;
            return false;
        }
    }

    SwarmExactStall stall;
    stall.chain_id = work_id.empty() ? std::string("integer") : work_id;
    stall.want_mine = false;
    std::string mine_err;
    const SwarmExactStallResult mine = SwarmHoldExactMine(stall, mine_err);
    if (mine.mined || mine.blocks != 0) {
        err = mine_err.empty() ? mine.code : mine_err;
        return false;
    }

    SwarmEngineFlag flag;
    flag.engine_id = "integer-trainer";
    flag.engine_flag = false;
    flag.want_move = false;
    std::string flag_err;
    const SwarmEngineFlagResult moved = SwarmNoteEngineFlag(flag, flag_err);
    if (moved.moved || moved.bytes_moved != 0) {
        err = flag_err.empty() ? moved.code : flag_err;
        return false;
    }

    m_coordinator_id.clear();
    m_bytes_moved = moved.bytes_moved;
    m_mined = mine.mined;
    err.clear();
    return true;
}

} // namespace modelnet
