// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/gate.h>

#include <modelnet/swarm_dedup/codes.h>

#include <string>

namespace modelnet {

bool SwarmPieceDedupAllowAnnounce(const std::string& peer, const std::string& piece_id, bool is_private, std::string& err)
{
    if (peer.empty()) {
        err = kSwarmPieceDedupPeer;
        return false;
    }
    if (piece_id.empty()) {
        err = kSwarmPieceDedupPiece;
        return false;
    }
    if (is_private) {
        err = kSwarmPieceDedupPrivateData;
        return false;
    }
    return true;
}

bool SwarmPieceDedupAllowDigest(const std::string& piece_id, const std::string& digest_hex, std::string& err)
{
    if (piece_id.empty()) {
        err = kSwarmPieceDedupPiece;
        return false;
    }
    if (digest_hex.empty()) {
        err = kSwarmPieceDedupDigest;
        return false;
    }
    if (digest_hex != piece_id) {
        err = kSwarmPieceDedupConflict;
        return false;
    }
    return true;
}

bool SwarmPieceDedupAllowPull(const std::string& requester, const std::string& piece_id, std::string& err)
{
    if (piece_id.empty()) {
        err = kSwarmPieceDedupPiece;
        return false;
    }
    if (requester.empty()) {
        err = kSwarmPieceDedupPeer;
        return false;
    }
    return true;
}

} // namespace modelnet
