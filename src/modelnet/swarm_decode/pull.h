// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_PULL_H
#define BITCOIN_MODELNET_SWARM_DECODE_PULL_H

#include <modelnet/swarm_decode/book.h>
#include <modelnet/swarm_decode/output.h>

#include <string>

namespace modelnet {

/**
 * Pull one byte, or refuse.
 * An unknown session is SESSION.
 * A session with no stored prompt is PROMPT.
 * vllm, sglang, and lmcache return ENGINE_ABSENT and do not change text() or tokens().
 * memory appends prompt[tokens()] and increments tokens() by 1.
 * memory returns DONE once tokens() is already at the prompt size or at 8.
 * tokens() counts bytes already appended to text(), and the next memory byte
 * is taken from that index in the session prompt.
 */
bool SwarmDecodePullApply(const SwarmDecodeBook& book,
                          SwarmDecodeOutput& output,
                          const std::string& session,
                          std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_PULL_H
