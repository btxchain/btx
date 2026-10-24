// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/text_slot.h>

#include <modelnet/swarm_infer/codes.h>

#include <string>

namespace modelnet {

std::string SwarmInferStoreText(SwarmInferTextSlot& slot, const std::string& text, std::string& err)
{
    if (text.empty()) {
        err = SwarmInferCode::text;
        return SwarmInferCode::text;
    }
    if (!slot.occupied) {
        slot.occupied = true;
        slot.value = text;
        err.clear();
        return SwarmInferCode::stored;
    }
    if (slot.value == text) {
        err = SwarmInferCode::replay;
        return SwarmInferCode::replay;
    }
    err = SwarmInferCode::conflict;
    return SwarmInferCode::conflict;
}

} // namespace modelnet
