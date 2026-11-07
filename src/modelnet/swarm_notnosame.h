// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSAME_H
#define BTX_MODELNET_SWARM_NOTNOSAME_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one atom. escrow and collateral ask this note to
 * treat the same atoms as both escrow and collateral.
 *
 * The same atoms are never both escrow and collateral. counted_twice
 * stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoSame {
    std::string atom_id;
    bool escrow{false};
    bool collateral{false};
};

/**
 * Outcome of noting atoms. counted_twice stays false and atoms stays 0
 * on every path: the same atoms are never both escrow and collateral.
 */
struct SwarmNotNoSameResult {
    std::string code;
    bool counted_twice{false};
    int64_t atoms{0};
};

/**
 * Note atoms without treating the same atoms as both escrow and collateral.
 * Order, first match wins: an empty atom_id is ATOM.
 * escrow and collateral both true is SAME_ATOMS.
 * Otherwise the note is NOTED and err is clear.
 * counted_twice stays false and atoms stays 0 on every path. The same
 * atoms are never both escrow and collateral.
 */
SwarmNotNoSameResult SwarmNoteNotNoSame(const SwarmNotNoSame& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSAME_H
