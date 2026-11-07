// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PROPOSER_H
#define BTX_MODELNET_SWARM_PROPOSER_H

#include <string>

namespace modelnet {

struct SwarmProposer {
    std::string idea_id;
    bool want_propose{false};
};

struct SwarmProposerResult {
    std::string code;
    bool proposed{false};
};

/**
 * An experiment propose request is held and proposes nothing.
 * Order: an empty idea_id is IDEA. want_propose true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 */
SwarmProposerResult SwarmNoteProposer(const SwarmProposer& idea, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PROPOSER_H
