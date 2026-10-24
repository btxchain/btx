// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVSHARE_H
#define BTX_MODELNET_SWARM_KVSHARE_H

#include <string>

namespace modelnet {

/**
 * A local note about one KV page. page_id names the page.
 * same_fingerprint and compatible mark a matching tensor. want_share
 * asks this note to share the page.
 *
 * This note does not share a KV page and does not copy a tensor. shared
 * and bytes_moved stay false on every path. No hostnames or IPs are used.
 */
struct SwarmKvShare {
    std::string page_id;
    bool same_fingerprint{false};
    bool compatible{false};
    bool want_share{false};
};

/**
 * Outcome of noting a KV page. shared and bytes_moved stay false: this
 * note does not share a page and does not move bytes. No tensor is copied.
 */
struct SwarmKvShareResult {
    bool shared{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Note a KV page without sharing it.
 * Order, first match wins:
 * an empty page_id is KV. shared and bytes_moved stay false and err is KV.
 * !same_fingerprint or !compatible is INCOMPATIBLE. shared and bytes_moved
 * stay false and err is INCOMPATIBLE. This wins even when want_share is
 * true. Incompatible tensors do not share a KV page.
 * want_share is HELD. shared and bytes_moved stay false and err is
 * cleared. A matching page still moves no bytes in this note.
 * Otherwise the note is NOTED. shared and bytes_moved stay false and err
 * is cleared.
 * shared and bytes_moved stay false. No tensor is copied. No hostnames
 * or IPs are used.
 */
SwarmKvShareResult SwarmNoteKvShare(const SwarmKvShare& share, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVSHARE_H
