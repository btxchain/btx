// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT08_H
#define BTX_MODELNET_SWARM_FAULT08_H

#include <string>

namespace modelnet {

/**
 * Live fault 8: a transferred cache is truncated or incompatible.
 * Local classification only. accepted, bytes_moved, committed, and
 * broadcast stay false on every path.
 */
struct SwarmFault08 {
    std::string page_id;
    bool truncated{false};
    bool compatible{false};
    bool want_accept{false};
};

/**
 * Outcome of a local truncated or incompatible cache note.
 * accepted, bytes_moved, committed, and broadcast stay false on every path.
 */
struct SwarmFault08Result {
    std::string code;
    bool accepted{false};
    bool bytes_moved{false};
    bool committed{false};
    bool broadcast{false};
};

/**
 * Classify a transferred cache that may be truncated or incompatible.
 * Order, first match wins:
 * 1. An empty page_id is PAGE. Every result bool stays false and err is PAGE.
 * 2. truncated, or not compatible, is PREFIX_MISMATCH. accepted and
 *    bytes_moved stay false. err is PREFIX_MISMATCH. Truncated wins even
 *    if want_accept is set.
 * 3. want_accept is HELD. accepted and bytes_moved stay false. err is cleared.
 * 4. Otherwise NOTED. accepted and bytes_moved stay false. err is cleared.
 * accepted, bytes_moved, committed, and broadcast stay false on every path.
 * This does not accept the cache, move bytes, commit, or broadcast.
 */
SwarmFault08Result SwarmRecoverFault08(const SwarmFault08& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT08_H
