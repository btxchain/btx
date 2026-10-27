// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_partial.h>

#include <cstdint>

namespace modelnet {

SwarmPartialResult SwarmNotePartialArtifact(const SwarmPartialArtifact& artifact, std::string& err)
{
    SwarmPartialResult result;
    result.complete = false;
    if (artifact.artifact_id.empty() || artifact.expected_pieces < 1 || artifact.received_pieces < 0) {
        result.code = "ARTIFACT";
        err = "ARTIFACT";
        return result;
    }
    if (artifact.received_pieces < artifact.expected_pieces) {
        result.code = "PARTIAL";
        err = "PARTIAL";
        return result;
    }
    if (artifact.received_pieces > artifact.expected_pieces) {
        result.code = "PARTIAL";
        err = "PARTIAL";
        return result;
    }
    if (!artifact.digest_ok) {
        result.code = "DIGEST";
        err = "DIGEST";
        return result;
    }
    result.complete = false;
    result.code = "HELD";
    err.clear();
    return result;
}

} // namespace modelnet
