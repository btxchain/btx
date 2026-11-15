// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOHF_H
#define BTX_MODELNET_SWARM_NOTNOHF_H

#include <string>

namespace modelnet {

/**
 * A local note about one origin. want_authority asks this note for
 * lineage authority.
 *
 * A Hugging Face import is not lineage authority. authority and
 * published stay false on every path.
 */
struct SwarmNotNoHf {
    std::string origin_id;
    bool want_authority{false};
};

/**
 * Outcome of noting an origin. authority and published stay false on
 * every path. A Hugging Face import is not lineage authority.
 */
struct SwarmNotNoHfResult {
    std::string code;
    bool authority{false};
    bool published{false};
};

/**
 * Note an origin without granting lineage authority.
 * Order, first match wins: an empty origin_id is ORIGIN. want_authority
 * is NOT_AUTHORITY. Otherwise the note is NOTED and err is cleared.
 * authority and published stay false on every path.
 * A Hugging Face import is not lineage authority.
 */
SwarmNotNoHfResult SwarmNoteNotNoHf(const SwarmNotNoHf& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOHF_H
