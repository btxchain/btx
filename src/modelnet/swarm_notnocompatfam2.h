// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOMPATFAM2_H
#define BTX_MODELNET_SWARM_NOTNOCOMPATFAM2_H

#include <string>

namespace modelnet {

/**
 * A local note about one family. family_id names the family.
 * membership records family membership. want_share asks this note to
 * share a KV page.
 *
 * Family membership is not KV-page compatibility and shares nothing.
 * shared stays false on every path.
 */
struct SwarmNotNoCompatFam2 {
    std::string family_id;
    bool membership{false};
    bool want_share{false};
};

/**
 * Outcome of noting a family. shared stays false on every path.
 * Family membership does not share KV pages.
 */
struct SwarmNotNoCompatFam2Result {
    std::string code;
    bool shared{false};
};

/**
 * Note a family without sharing a KV page.
 * Order, first match wins: an empty family_id is FAMILY. membership
 * true is NOT_COMPAT, even when want_share is false. want_share is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * shared stays false on every path.
 * Family membership does not share KV pages.
 */
SwarmNotNoCompatFam2Result SwarmNoteNotNoCompatFam2(const SwarmNotNoCompatFam2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOMPATFAM2_H
