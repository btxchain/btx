// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PARTIAL_H
#define BTX_MODELNET_SWARM_PARTIAL_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one artifact's piece count. Streaming a checkpoint
 * and publishing an artifact are not provided.
 */
struct SwarmPartialArtifact {
    std::string artifact_id;
    int64_t expected_pieces{0};
    int64_t received_pieces{0};
    bool digest_ok{false};
};

/**
 * A local partial-artifact note. complete stays false: a full piece
 * count with a matching digest is still not a streamed checkpoint
 * and not a published artifact.
 */
struct SwarmPartialResult {
    bool complete{false};
    std::string code;
};

/**
 * Order, first match wins: an empty artifact_id, expected_pieces
 * below 1, or received_pieces below 0 is ARTIFACT. A short count
 * (received_pieces below expected_pieces) is PARTIAL, including when
 * digest_ok is true. A long count (received_pieces above
 * expected_pieces) is PARTIAL. A matching count whose digest is not
 * ok is DIGEST. Otherwise the note is HELD and err is clear. complete
 * stays false on every path. This records a local note. It does not
 * stream a checkpoint and does not publish an artifact. No files are
 * written. No hostnames or IPs are used.
 */
SwarmPartialResult SwarmNotePartialArtifact(const SwarmPartialArtifact& artifact, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PARTIAL_H
