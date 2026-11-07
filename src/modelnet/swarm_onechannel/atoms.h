// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ONECHANNEL_ATOMS_H
#define BITCOIN_MODELNET_SWARM_ONECHANNEL_ATOMS_H

#include <cstdint>

namespace modelnet {

/**
 * Keep an atom balance at zero.
 * A zero balance is returned unchanged. Any other value is returned as zero.
 * Funding and quoting call this so they do not move atoms.
 */
int64_t SwarmOneChannelKeepAtoms(int64_t atoms);

/** Funding does not move atoms. */
bool SwarmOneChannelFundingMovesAtoms();

/** Quoting does not move atoms and does not spend. */
bool SwarmOneChannelQuotingMovesAtoms();

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ONECHANNEL_ATOMS_H
