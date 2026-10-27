// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_PROMPT_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_PROMPT_H

#include <modelnet/swarm_tokgate/book.h>

#include <string>

namespace modelnet {

/**
 * Store one public prompt on an open session.
 * An unknown session is SESSION. A private prompt is PRIVATE_DATA and stores
 * nothing. An empty public prompt is PROMPT and stores nothing.
 * The first public prompt is stored once. The same public prompt again is
 * REPLAY. A different public prompt is HELD and keeps the first.
 * On success err is cleared and the result is true.
 * The stored prompt is not generated text. text() stays empty.
 */
bool SwarmTokenGatePromptApply(SwarmTokenGateBook& book,
                               const std::string& session,
                               const std::string& text,
                               bool is_private,
                               std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_PROMPT_H
