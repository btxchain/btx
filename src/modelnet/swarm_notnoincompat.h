// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOINCOMPAT_H
#define BTX_MODELNET_SWARM_NOTNOINCOMPAT_H

#include <string>

namespace modelnet {

/**
 * A local note about one tensor. compatible is false when the tensors
 * cannot share a KV page. want_share asks this note to share that page.
 *
 * Incompatible tensors do not share KV pages and this note moves no bytes.
 * shared and bytes_moved stay false on every path.
 */
struct SwarmNotNoIncompat {
    std::string tensor_id;
    bool compatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting an incompatible tensor. shared and bytes_moved stay
 * false on every path: incompatible tensors do not share KV pages and this
 * note moves no bytes.
 */
struct SwarmNotNoIncompatResult {
    std::string code;
    bool shared{false};
    bool bytes_moved{false};
};

/**
 * Note a tensor without sharing a KV page.
 * Order, first match wins: an empty tensor_id is TENSOR. compatible false
 * is NOT_SHARED even when want_share is false. want_share is NOT_SHARED.
 * Otherwise the note is NOTED and err is clear.
 * shared and bytes_moved stay false on every path. Incompatible tensors do
 * not share KV pages and this note moves no bytes.
 */
SwarmNotNoIncompatResult SwarmNoteNotNoIncompat(const SwarmNotNoIncompat& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOINCOMPAT_H
