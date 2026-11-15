// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_MANIFEST_H
#define BTX_MODELNET_SWARM_MANIFEST_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

static constexpr std::size_t SWARM_PIECE_BYTES = 4 * 1024 * 1024;

struct SwarmPieceRef {
    std::string id;
    std::size_t offset{0};
    std::size_t length{0};
    bool verified{false};
};

struct SwarmArtifactManifest {
    std::string artifact_id;
    std::uint64_t length{0};
    std::vector<SwarmPieceRef> pieces;
    bool usable{false};
};

/**
 * Split a body into pieces of at most 4 MiB. Each piece id is the SHA-384 of
 * that slice. The manifest is usable only when every piece verifies and the
 * lengths sum to the body. An empty body is PIECE. A body over 32 MiB is
 * PIECE_LIMIT. This does not write a file, decrypt, or broadcast.
 */
bool SwarmSplitManifest(const std::vector<unsigned char>& body, SwarmArtifactManifest& manifest, std::string& err);

/**
 * A piece whose id is in already_verified_ids stays verified. A piece whose
 * id is absent becomes unverified. Usable is true only when every piece is
 * verified. No pieces, or any unverified piece, is MANIFEST.
 */
bool SwarmResumeManifest(SwarmArtifactManifest& manifest, const std::vector<std::string>& already_verified_ids, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_MANIFEST_H
