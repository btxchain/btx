// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PIECE_H
#define BTX_MODELNET_SWARM_PIECE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** SHA-384 of the raw bytes. The id must equal that digest. */
std::string SwarmPieceDigest(const std::vector<unsigned char>& bytes);

/**
 * Accept a content-addressed piece. A body over 32 MiB is refused.
 * A digest mismatch is refused. This does not decrypt, transfer, or broadcast.
 */
bool SwarmAcceptPiece(const std::string& piece_id, const std::vector<unsigned char>& bytes, std::string& err);

} // namespace modelnet

#endif
