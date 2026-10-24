// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_directory.h>

namespace modelnet {

SwarmDirectoryResult SwarmListFamily(const SwarmDirectoryRequest& request, std::string& err)
{
    SwarmDirectoryResult result;
    result.socket_opened = false;
    result.nat_opened = false;
    if (request.family_id.empty()) {
        result.listed = false;
        result.code = "DIRECTORY";
        err = "DIRECTORY";
        return result;
    }
    if (request.want_socket) {
        result.listed = false;
        result.code = "NO_SOCKET";
        err = "NO_SOCKET";
        return result;
    }
    if (request.want_nat_traversal) {
        result.listed = false;
        result.code = "NAT_ABSENT";
        err = "NAT_ABSENT";
        return result;
    }
    if (request.want_public_directory) {
        result.listed = false;
        result.code = "DIRECTORY_PRIVATE";
        err = "DIRECTORY_PRIVATE";
        return result;
    }
    result.listed = true;
    result.code = "LOCAL_CATALOG";
    err.clear();
    return result;
}

} // namespace modelnet
