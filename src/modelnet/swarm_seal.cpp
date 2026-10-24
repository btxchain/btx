// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_seal.h>

namespace modelnet {

SwarmSealResult SwarmAcceptSealedPiece(const SwarmSealedPiece& piece, std::string& err)
{
    SwarmSealResult result;
    if (piece.piece_id.empty() || piece.realm_id.empty()) {
        err = "PIECE";
        result.code = "PIECE";
        return result;
    }
    if (piece.ciphertext) {
        err = "REALM_SEALED";
        result.code = "REALM_SEALED";
        return result;
    }
    if (piece.private_record) {
        err = "PRIVATE_DATA";
        result.code = "PRIVATE_DATA";
        return result;
    }
    result.stored = true;
    err.clear();
    return result;
}

bool SwarmPublishDiscovery(bool private_family, bool contains_prompt, bool contains_work_detail, bool contains_data_grant, std::string& err)
{
    if (private_family || contains_prompt || contains_work_detail || contains_data_grant) {
        err = "PRIVATE_DATA";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
