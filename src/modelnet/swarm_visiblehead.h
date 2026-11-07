// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_VISIBLEHEAD_H
#define BTX_MODELNET_SWARM_VISIBLEHEAD_H

#include <string>

namespace modelnet {

/**
 * A local note about one head's visibility. An ungraduated head is not
 * public. A public request is not a public advertisement. No socket is
 * opened. No hostnames or IPs are recorded.
 */
struct SwarmHeadVisibility {
    std::string head_id;
    bool graduated{false};
    bool public_requested{false};
};

/**
 * Outcome of noting head visibility. visible is always false: a note is
 * not a public advertisement.
 */
struct SwarmHeadVisibilityResult {
    bool visible{false};
    std::string code;
};

/**
 * Note whether a head may be treated as public.
 * Order, first match wins: an empty head_id is HEAD. A head that has not
 * graduated is PRIVATE, including when public_requested is also true. A
 * public request is HELD and err is cleared. Otherwise the note is NOTED
 * and err is clear. visible stays false on every path. This records a
 * local note. It does not advertise the head, does not open a socket,
 * and does not record a hostname or IP.
 */
SwarmHeadVisibilityResult SwarmNoteHeadVisibility(const SwarmHeadVisibility& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_VISIBLEHEAD_H
