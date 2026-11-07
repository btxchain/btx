// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTSEQ_RESTART_H
#define BTX_MODELNET_SWARM_FAULTSEQ_RESTART_H

namespace modelnet {

/** Restart is allowed after fault 20 has been applied, or after a refusal. */
bool SwarmFaultSeqCanRestart(bool took_last, bool refused);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTSEQ_RESTART_H
