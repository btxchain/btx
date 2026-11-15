// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROMPT2_H
#define BTX_MODELNET_SWARM_NOTNOPROMPT2_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_enable asks this note to enable a
 * private prompt.
 *
 * Private prompts stay off. enabled stays false on every path.
 */
struct SwarmNotNoPrompt2 {
    std::string node_id;
    bool want_enable{false};
};

/**
 * Outcome of noting a prompt. enabled stays false on every path.
 * Private prompts stay off.
 */
struct SwarmNotNoPrompt2Result {
    std::string code;
    bool enabled{false};
};

/**
 * Note a prompt without enabling it.
 * Order, first match wins: an empty node_id is NODE. want_enable is
 * HELD. Otherwise the note is NOTED and err is cleared. enabled stays
 * false on every path. Private prompts stay off.
 */
SwarmNotNoPrompt2Result SwarmNoteNotNoPrompt2(const SwarmNotNoPrompt2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROMPT2_H
