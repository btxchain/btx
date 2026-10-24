// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNO6720_H
#define BTX_MODELNET_SWARM_NOTNO6720_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about block spacing. spacing_id names the spacing. blocks
 * is the block count. want_guarantee asks this note to treat the count
 * as a wall-clock guarantee.
 *
 * 6720 blocks is not a 604800-second wall-clock guarantee. guaranteed
 * stays false, and applied_seconds stays 0, on every path.
 */
struct SwarmNotNo6720 {
    std::string spacing_id;
    int64_t blocks{0};
    bool want_guarantee{false};
};

/**
 * Outcome of noting block spacing. guaranteed stays false, and
 * applied_seconds stays 0, on every path. 6720 blocks is not a
 * 604800-second wall-clock guarantee.
 */
struct SwarmNotNo6720Result {
    std::string code;
    bool guaranteed{false};
    int64_t applied_seconds{0};
};

/**
 * Note block spacing without treating it as a 604800-second wall-clock
 * guarantee. Order, first match wins: an empty spacing_id is SPACING. A
 * blocks value that is not exactly 6720 is NOT_GUARANTEE, even when
 * want_guarantee is false. want_guarantee is NOT_GUARANTEE. Otherwise the
 * note is NOTED and err is clear. 6720 blocks is not a 604800-second
 * wall-clock guarantee. guaranteed stays false, and applied_seconds stays
 * 0, on every path.
 */
SwarmNotNo6720Result SwarmNoteNotNo6720(const SwarmNotNo6720& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNO6720_H
