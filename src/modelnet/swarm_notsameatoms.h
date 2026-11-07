// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSAMEATOMS_H
#define BTX_MODELNET_SWARM_NOTSAMEATOMS_H

#include <string>

namespace modelnet {

/**
 * A local note about one atom. escrow and collateral ask this note to
 * treat the same atoms as both escrow and collateral.
 *
 * The same atoms are never both escrow and collateral. both stays false
 * on every path.
 */
struct SwarmNotSameAtoms {
    std::string atom_id;
    bool escrow{false};
    bool collateral{false};
};

/**
 * Outcome of noting atoms. both stays false on every path: the same
 * atoms are never both escrow and collateral.
 */
struct SwarmNotSameAtomsResult {
    std::string code;
    bool both{false};
};

/**
 * Note atoms without treating the same atoms as both escrow and collateral.
 * Order, first match wins: an empty atom_id is ATOMS.
 * escrow and collateral both true is REUSE.
 * Otherwise the note is NOTED and err is clear.
 * both stays false on every path. The same atoms are never both escrow
 * and collateral.
 */
SwarmNotSameAtomsResult SwarmNoteNotSameAtoms(const SwarmNotSameAtoms& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSAMEATOMS_H
