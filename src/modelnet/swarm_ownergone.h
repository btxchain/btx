// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_OWNERGONE_H
#define BTX_MODELNET_SWARM_OWNERGONE_H

#include <string>

namespace modelnet {

/**
 * A local note about one cache page and its owner. Noting a page does
 * not transfer a tensor and does not open a socket.
 */
struct SwarmCacheOwnerRequest {
    std::string page_id;
    std::string owner_id;
    bool owner_present{false};
    bool transfer_requested{false};
};

/**
 * A local cache-owner note. bytes_moved stays false: a note is not a
 * tensor transfer and not a socket.
 */
struct SwarmCacheOwnerResult {
    bool noted{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * Order, first match wins: an empty page_id or owner_id is CACHE. An
 * owner who is not present is OWNER_ABSENT, including when
 * transfer_requested is also true. A transfer request is ENGINE_ABSENT.
 * Otherwise the note is NOTED and err is clear. bytes_moved stays false
 * on every path. This records a local note. It does not transfer a
 * tensor and does not open a socket. No hostnames or addresses are used.
 */
SwarmCacheOwnerResult SwarmNoteCacheOwner(const SwarmCacheOwnerRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_OWNERGONE_H
