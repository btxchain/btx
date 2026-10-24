// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOLLAT_H
#define BTX_MODELNET_SWARM_NOTNOCOLLAT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one collateral. reused marks the collateral as
 * already used. want_book asks this note to book it.
 *
 * Reused collateral is not booked again.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoCollat {
    std::string book_id;
    bool reused{false};
    bool want_book{false};
};

/**
 * Outcome of noting collateral. booked stays false and atoms stays 0 on
 * every path: reused collateral is not booked again.
 */
struct SwarmNotNoCollatResult {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note collateral without booking it again.
 * Order, first match wins: an empty book_id is BOOK.
 * If reused is true, the note is NOT_BOOKED even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. Reused collateral
 * is not booked again.
 */
SwarmNotNoCollatResult SwarmNoteNotNoCollat(const SwarmNotNoCollat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOLLAT_H
