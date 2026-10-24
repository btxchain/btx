// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DUPRECEIPT_ATOMS_H
#define BITCOIN_MODELNET_SWARM_DUPRECEIPT_ATOMS_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Atoms a first Pay may add.
 * atoms below 1 is ATOMS. A sum that would pass int64 max does not fit.
 * Neither path adds atoms.
 */
class SwarmDupAtoms {
public:
    bool accept(int64_t atoms, std::string& err) const;
    bool fits(int64_t have, int64_t atoms) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DUPRECEIPT_ATOMS_H
