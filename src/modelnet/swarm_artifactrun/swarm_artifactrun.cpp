// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_artifactrun/swarm_artifactrun.h>

#include <modelnet/swarm_piecepipe/codes.h>
#include <modelnet/swarm_piecepipe/limits.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

static_assert(kSwarmPiecePipePieceBytes == 4194304, "artifact pieces are at most 4194304 bytes");

bool SwarmArtifactRun::AcceptBody(const std::string& id, const std::vector<unsigned char>& body,
                                  const std::string& digest_hex, std::string& err)
{
    // Accept rejects an empty body as PIECE before it compares digests.
    // The pipeline hashes. This class does not.
    const std::string& offered = digest_hex.empty() ? id : digest_hex;
    return m_pipe.Accept(offered, body, err);
}

bool SwarmArtifactRun::SplitBody(const std::vector<unsigned char>& body, std::string& err)
{
    // The reference is forwarded. No member keeps a second full copy.
    return m_pipe.Split(body, err);
}

bool SwarmArtifactRun::Close(const std::string& id, std::string& err)
{
    if (!m_pipe.Resume(id, err)) {
        return false;
    }
    m_closed.insert(id);
    err.clear();
    return true;
}

bool SwarmArtifactRun::Complete(const std::string& id, std::string& err)
{
    if (!closed(id)) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmArtifactRun::Generation(const std::string& id, const std::vector<unsigned char>& bytes, std::string& err)
{
    if (!closed(id)) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    if (bytes.empty()) {
        err = kSwarmPiecePipePiece;
        return false;
    }
    const auto found = m_generations.find(id);
    if (found != m_generations.end()) {
        if (found->second == bytes) {
            err = kSwarmPiecePipeReplay;
            return false;
        }
        err = kSwarmPiecePipeConflict;
        return false;
    }
    m_generations.emplace(id, bytes);
    err.clear();
    return true;
}

bool SwarmArtifactRun::Load(const std::string& id, std::string& err)
{
    if (!closed(id)) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    const auto found = m_generations.find(id);
    if (found == m_generations.end() || found->second.empty()) {
        err = kSwarmPiecePipeManifest;
        return false;
    }
    m_loaded = true;
    err.clear();
    return true;
}

bool SwarmArtifactRun::closed() const
{
    return !m_closed.empty();
}

bool SwarmArtifactRun::closed(const std::string& id) const
{
    return m_closed.find(id) != m_closed.end();
}

bool SwarmArtifactRun::loaded() const
{
    return m_loaded;
}

std::vector<unsigned char> SwarmArtifactRun::generation_bytes(const std::string& id) const
{
    const auto found = m_generations.find(id);
    if (found == m_generations.end()) {
        return {};
    }
    return found->second;
}

std::int64_t SwarmArtifactRun::bytes_moved() const
{
    return kSwarmArtifactRunBytesMoved;
}

bool SwarmArtifactRun::launched() const
{
    return kSwarmArtifactRunLaunched;
}

bool SwarmArtifactRun::gpu() const
{
    return kSwarmArtifactRunGpu;
}

bool SwarmArtifactRun::broadcast() const
{
    return kSwarmArtifactRunBroadcast;
}

std::string SwarmArtifactRun::automatic_spend() const
{
    return std::string{kSwarmArtifactRunAutomaticSpend};
}

} // namespace modelnet
