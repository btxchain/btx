// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PRIVATE_H
#define BTX_MODELNET_SWARM_PRIVATE_H

#include <string>

namespace modelnet {

/**
 * A private-prompt note. node_id names the note. operator_allows marks
 * an operator allowance. want_private asks this note to accept a
 * private prompt.
 *
 * This note does not store anything and does not send anything.
 * accepted stays false on every path. No hostnames or IPs are used.
 */
struct SwarmPrivatePrompt {
    std::string node_id;
    bool operator_allows{false};
    bool want_private{false};
};

/**
 * Outcome of noting a private prompt. accepted stays false: this note
 * does not accept a private prompt. Nothing is stored and nothing is
 * sent.
 */
struct SwarmPrivatePromptResult {
    bool accepted{false};
    std::string code;
};

/**
 * Note a private prompt. Order, first match wins: an empty node_id is
 * PROMPT. want_private without operator_allows is PRIVATE: a private
 * prompt stays off without an operator allowance. want_private is HELD
 * and err is cleared: an operator allowance still does not make this
 * note accept a private prompt. Otherwise the note is NOTED and err is
 * cleared. accepted stays false on every path. Nothing is stored and
 * nothing is sent. No hostnames or IPs are used.
 */
SwarmPrivatePromptResult SwarmNotePrivatePrompt(const SwarmPrivatePrompt& prompt, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PRIVATE_H
