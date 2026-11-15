// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piece.h>

#include <modelnet/swarm_codec.h>
#include <crypto/sha384.h>
#include <util/strencodings.h>

namespace modelnet {

std::string SwarmPieceDigest(const std::vector<unsigned char>& bytes)
{
    CSHA384 hasher;
    if (!bytes.empty()) hasher.Write(bytes.data(), bytes.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(Span<const unsigned char>(out, CSHA384::OUTPUT_SIZE));
}

bool SwarmAcceptPiece(const std::string& piece_id, const std::vector<unsigned char>& bytes, std::string& err)
{
    constexpr std::size_t kMax = 32U * 1024U * 1024U;
    if (bytes.empty()) {
        err = "PIECE";
        return false;
    }
    if (bytes.size() > kMax) {
        err = "PIECE_LIMIT";
        return false;
    }
    if (!SwarmFixedId(piece_id)) {
        err = "PIECE_ID";
        return false;
    }
    if (SwarmPieceDigest(bytes) != piece_id) {
        err = "PIECE_DIGEST";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
