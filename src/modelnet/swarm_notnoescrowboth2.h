// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOESCROWBOTH2_H
#define BTX_MODELNET_SWARM_NOTNOESCROWBOTH2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one ledger. same_atoms marks the atoms as already
 * used as both escrow and collateral. want_book asks this note to book it.
 *
 * The same atoms are never both escrow and collateral.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoEscrowBoth2 {
    std::string ledger_id;
    bool same_atoms{false};
    bool want_book{false};
};

/**
 * Outcome of noting a ledger. booked stays false and atoms stays 0 on
 * every path: the same atoms are never both escrow and collateral.
 */
struct SwarmNotNoEscrowBoth2Result {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note a ledger without treating the same atoms as both escrow and collateral.
 * Order, first match wins: an empty ledger_id is LEDGER.
 * If same_atoms is true, the note is NOT_BOTH even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. The same atoms are
 * never both escrow and collateral.
 */
SwarmNotNoEscrowBoth2Result SwarmNoteNotNoEscrowBoth2(const SwarmNotNoEscrowBoth2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOESCROWBOTH2_H
