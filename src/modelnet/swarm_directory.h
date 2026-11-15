// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DIRECTORY_H
#define BTX_MODELNET_SWARM_DIRECTORY_H

#include <string>

namespace modelnet {

/**
 * A request to list one family. NAT traversal and a global family
 * directory are not provided. Discovery stays a local catalog record.
 */
struct SwarmDirectoryRequest {
    std::string family_id;
    bool want_public_directory{false};
    bool want_nat_traversal{false};
    bool want_socket{false};
};

/**
 * A local catalog answer. socket_opened and nat_opened stay false:
 * this function does not open a socket.
 */
struct SwarmDirectoryResult {
    bool listed{false};
    bool socket_opened{false};
    bool nat_opened{false};
    std::string code;
};

/**
 * Order: an empty family_id is DIRECTORY. A request that wants a socket
 * is NO_SOCKET. A request that wants NAT traversal is NAT_ABSENT. A
 * request that wants a public directory is DIRECTORY_PRIVATE. Otherwise
 * the family is listed as LOCAL_CATALOG and err is clear. socket_opened
 * and nat_opened stay false. This function does not open a socket.
 */
SwarmDirectoryResult SwarmListFamily(const SwarmDirectoryRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DIRECTORY_H
