// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_TEXT_SLOT_H
#define BTX_MODELNET_SWARM_INFER_TEXT_SLOT_H

#include <string>

namespace modelnet {

/**
 * One text slot for one session.
 * Empty text is TEXT and stores nothing.
 * The first non-empty text is STORED.
 * The same text again is REPLAY.
 * A different text is CONFLICT and the first text stays.
 */
struct SwarmInferTextSlot {
    bool occupied{false};
    std::string value;
};

/**
 * Admit text into the slot.
 * On STORED, err is cleared. On TEXT, REPLAY, and CONFLICT, err is that code.
 * CONFLICT and REPLAY leave value unchanged. TEXT leaves the slot unchanged.
 */
std::string SwarmInferStoreText(SwarmInferTextSlot& slot, const std::string& text, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_TEXT_SLOT_H
