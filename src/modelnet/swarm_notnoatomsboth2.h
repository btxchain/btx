// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOATOMSBOTH2_H
#define BTX_MODELNET_SWARM_NOTNOATOMSBOTH2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one atom. both_roles marks the atoms as already
 * used as both escrow and collateral. want_book asks this note to book it.
 *
 * The same atoms are never both escrow and collateral.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoAtomsBoth2 {
    std::string atom_id;
    bool both_roles{false};
    bool want_book{false};
};

/**
 * Outcome of noting an atom. booked stays false and atoms stays 0 on
 * every path: the same atoms are never both escrow and collateral.
 */
struct SwarmNotNoAtomsBoth2Result {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note an atom without treating the same atoms as both escrow and collateral.
 * Order, first match wins: an empty atom_id is ATOMS.
 * If both_roles is true, the note is HELD even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. The same atoms are
 * never both escrow and collateral.
 */
SwarmNotNoAtomsBoth2Result SwarmNoteNotNoAtomsBoth2(const SwarmNotNoAtomsBoth2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOATOMSBOTH2_H
