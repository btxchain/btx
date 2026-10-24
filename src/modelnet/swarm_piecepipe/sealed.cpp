// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/sealed.h>

#include <modelnet/swarm_piecepipe/codes.h>

#include <string>
#include <vector>

namespace modelnet {

bool SwarmPiecePipeAcceptSealed(SwarmPiecePipeStore& store, const std::string& id, const std::vector<unsigned char>& body, bool ciphertext, bool is_private, std::string& err)
{
    // Private wins when both flags are set. The body is not inspected.
    if (is_private) {
        err = kSwarmPiecePipePrivateData;
        return false;
    }
    if (ciphertext) {
        err = kSwarmPiecePipeRealmSealed;
        return false;
    }
    return store.Accept(id, body, err);
}

} // namespace modelnet
