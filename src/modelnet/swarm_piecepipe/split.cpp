// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/split.h>

#include <modelnet/swarm_piecepipe/codes.h>
#include <modelnet/swarm_piecepipe/digest.h>
#include <modelnet/swarm_piecepipe/limits.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmPiecePipeSplit(SwarmPiecePipeStore& store, SwarmPiecePipeManifestBook& manifests, const std::vector<unsigned char>& body, std::string& err)
{
    if (body.empty()) {
        err = kSwarmPiecePipePiece;
        return false;
    }
    if (body.size() > kSwarmPiecePipeBodyLimit) {
        err = kSwarmPiecePipePieceLimit;
        return false;
    }

    std::vector<std::string> ids;
    std::vector<std::vector<unsigned char>> slices;
    std::size_t offset = 0;
    while (offset < body.size()) {
        const std::size_t n = std::min(kSwarmPiecePipePieceBytes, body.size() - offset);
        std::vector<unsigned char> part(body.data() + offset, body.data() + offset + n);
        ids.push_back(SwarmPiecePipeDigest(part.data(), part.size()));
        slices.push_back(std::move(part));
        offset += n;
    }

    // The artifact id covers the original body. A single slice therefore
    // shares that id. A longer body does not, apart from a hash collision.
    const std::string artifact = SwarmPiecePipeDigest(body);

    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (store.contains(ids[i]) && !store.same(ids[i], slices[i])) {
            err = kSwarmPiecePipeConflict;
            return false;
        }
    }
    if (!manifests.Put(artifact, ids, err)) {
        return false;
    }
    for (std::size_t i = 0; i < ids.size(); ++i) {
        if (store.contains(ids[i])) {
            continue;
        }
        store.InsertNew(ids[i], std::move(slices[i]));
    }
    err.clear();
    return true;
}

} // namespace modelnet
