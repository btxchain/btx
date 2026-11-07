// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_CURSOR_H
#define BITCOIN_MODELNET_SWARM_DECODE_CURSOR_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Where the next memory byte sits in the stored prompt.
 * Next means prompt[tokens] is still inside the prompt and tokens is below 8.
 * Done means the prompt is exhausted or 8 bytes were already appended.
 * Empty means there is no prompt to read.
 */
enum class SwarmDecodeCursorKind {
    Next,
    Done,
    Empty,
};

/**
 * Classify the next memory read.
 * An empty prompt is Empty.
 * tokens below 0, tokens at the prompt size, or tokens at 8 is Done.
 * Otherwise the next byte is prompt[tokens].
 */
SwarmDecodeCursorKind SwarmDecodeClassifyCursor(const std::string& prompt, int64_t tokens);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_CURSOR_H
