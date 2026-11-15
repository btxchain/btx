// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_REORGHOLD_ATOMS_H
#define BITCOIN_MODELNET_SWARM_REORGHOLD_ATOMS_H

#include <cstdint>

namespace modelnet {

/**
 * Add earned atoms into a plane counter.
 * A negative addend is refused. A sum that does not fit in int64_t is refused.
 * On refusal, out is left unchanged.
 */
bool ReorgHoldAddAtoms(int64_t total, int64_t add, int64_t& out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_REORGHOLD_ATOMS_H
