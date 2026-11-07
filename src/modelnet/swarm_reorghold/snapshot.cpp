// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/snapshot.h>

namespace modelnet {

bool ReorgHoldReorgMatches(int64_t earned, int channel_sequence, SwarmRecoverySnapshot& out)
{
    SwarmRecoverySnapshot in;
    in.pending_jobs = 0;
    in.earned_atoms = earned;
    in.channel_sequence = channel_sequence;
    in.checkpoint_present = false;
    in.payment_plane_present = false;
    in.execution_plane_present = false;
    in.frozen = false;
    out = SwarmReorgExit(in);
    return out.frozen && out.earned_atoms == in.earned_atoms && out.pending_jobs == in.pending_jobs &&
           out.channel_sequence == in.channel_sequence && out.checkpoint_present == in.checkpoint_present &&
           out.payment_plane_present == in.payment_plane_present &&
           out.execution_plane_present == in.execution_plane_present;
}

} // namespace modelnet
