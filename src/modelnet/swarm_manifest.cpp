// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_manifest.h>

#include <modelnet/swarm_piece.h>

#include <algorithm>
#include <cstddef>

namespace modelnet {
namespace {

constexpr std::size_t kBodyMax = 32U * 1024U * 1024U;

} // namespace

bool SwarmSplitManifest(const std::vector<unsigned char>& body, SwarmArtifactManifest& manifest, std::string& err)
{
    manifest = SwarmArtifactManifest{};
    if (body.empty()) {
        err = "PIECE";
        return false;
    }
    if (body.size() > kBodyMax) {
        err = "PIECE_LIMIT";
        return false;
    }
    manifest.artifact_id = SwarmPieceDigest(body);
    manifest.length = body.size();
    std::size_t offset = 0;
    while (offset < body.size()) {
        const std::size_t length = std::min(SWARM_PIECE_BYTES, body.size() - offset);
        std::vector<unsigned char> slice(body.begin() + static_cast<std::ptrdiff_t>(offset),
                                          body.begin() + static_cast<std::ptrdiff_t>(offset + length));
        SwarmPieceRef piece;
        piece.id = SwarmPieceDigest(slice);
        piece.offset = offset;
        piece.length = length;
        piece.verified = true;
        manifest.pieces.push_back(std::move(piece));
        offset += length;
    }
    std::uint64_t sum = 0;
    for (const SwarmPieceRef& piece : manifest.pieces) {
        if (!piece.verified || piece.id.empty()) {
            manifest.usable = false;
            err = "MANIFEST";
            return false;
        }
        sum += piece.length;
    }
    manifest.usable = sum == manifest.length && !manifest.pieces.empty();
    if (!manifest.usable) {
        err = "MANIFEST";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmResumeManifest(SwarmArtifactManifest& manifest, const std::vector<std::string>& already_verified_ids, std::string& err)
{
    if (manifest.pieces.empty()) {
        manifest.usable = false;
        err = "MANIFEST";
        return false;
    }
    bool all = true;
    for (SwarmPieceRef& piece : manifest.pieces) {
        const bool known = std::find(already_verified_ids.begin(), already_verified_ids.end(), piece.id) != already_verified_ids.end();
        piece.verified = known;
        if (!known) all = false;
    }
    manifest.usable = all;
    if (!all) {
        err = "MANIFEST";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
