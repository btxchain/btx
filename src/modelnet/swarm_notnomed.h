// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOMED_H
#define BTX_MODELNET_SWARM_NOTNOMED_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one context. tokens is a context length.
 * want_promote asks this note to promote a realm.
 *
 * A context length is not a realm promotion.
 * promoted and admitted stay false on every path.
 */
struct SwarmNotNoMed {
    std::string context_id;
    int64_t tokens{0};
    bool want_promote{false};
};

/**
 * Outcome of noting a context. promoted and admitted stay false on every
 * path: a context length is not a realm promotion.
 */
struct SwarmNotNoMedResult {
    std::string code;
    bool promoted{false};
    bool admitted{false};
};

/**
 * Note a context without promoting a realm or admitting it.
 * Order, first match wins: an empty context_id is CONTEXT. tokens that
 * are not exactly 0 are NOT_PROMOTED even when want_promote is false.
 * want_promote is NOT_PROMOTED. Otherwise the note is NOTED and err is
 * cleared. promoted and admitted stay false on every path. A context
 * length is not a realm promotion.
 */
SwarmNotNoMedResult SwarmNoteNotNoMed(const SwarmNotNoMed& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOMED_H
