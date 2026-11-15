// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_MEMORY_H
#define BITCOIN_MODELNET_SWARM_DECODE_MEMORY_H

#include <modelnet/swarm_decode/output.h>

#include <string>

namespace modelnet {

/**
 * Append the next byte of the stored public prompt.
 * The byte is prompt[tokens()] from the caller. Nothing else is written.
 * On success tokens() increases by 1 and the call returns true.
 * When tokens() is already at the prompt size, or already at 8, the call
 * returns false with DONE and leaves text() and tokens() unchanged.
 * An empty prompt returns false with PROMPT and appends nothing.
 */
bool SwarmDecodeMemoryPull(const std::string& prompt, SwarmDecodeOutput& output, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_MEMORY_H
