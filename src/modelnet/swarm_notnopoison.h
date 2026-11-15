// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPOISON_H
#define BTX_MODELNET_SWARM_NOTNOPOISON_H

#include <string>

namespace modelnet {

/**
 * A local note about a sample. sample_id names the sample.
 * poisoned marks a poisoned sample. want_publish asks this note to
 * publish it.
 *
 * A poisoned sample is frozen, published nowhere, and trains nothing.
 * published and trained stay false on every path.
 */
struct SwarmNotNoPoison {
    std::string sample_id;
    bool poisoned{false};
    bool want_publish{false};
};

/**
 * Outcome of noting a sample. published and trained stay false on every
 * path. A poisoned sample is frozen, published nowhere, and trains nothing.
 */
struct SwarmNotNoPoisonResult {
    std::string code;
    bool published{false};
    bool trained{false};
};

/**
 * Note a sample without publishing or training it.
 * Order, first match wins: an empty sample_id is SAMPLE. poisoned is
 * FROZEN even when want_publish is false. want_publish is FROZEN.
 * Otherwise the note is NOTED and err is cleared.
 * published and trained stay false on every path. A poisoned sample is
 * frozen, published nowhere, and trains nothing.
 */
SwarmNotNoPoisonResult SwarmNoteNotNoPoison(const SwarmNotNoPoison& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPOISON_H
