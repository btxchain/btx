// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecepipe/swarm_piecepipe.h>

#include <modelnet/swarm_piecepipe/drop.h>
#include <modelnet/swarm_piecepipe/limits.h>
#include <modelnet/swarm_piecepipe/resume.h>
#include <modelnet/swarm_piecepipe/sealed.h>
#include <modelnet/swarm_piecepipe/split.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

static_assert(kSwarmPiecePipePieceBytes == 4194304, "piece size limit is 4194304 bytes");
static_assert(kSwarmPiecePipeBodyLimit == 33554432, "body size limit is 33554432 bytes");

bool SwarmPiecePipe::Accept(const std::string& id, const std::vector<unsigned char>& body, std::string& err)
{
    return m_store.Accept(id, body, err);
}

bool SwarmPiecePipe::Split(const std::vector<unsigned char>& body, std::string& err)
{
    return SwarmPiecePipeSplit(m_store, m_manifests, body, err);
}

bool SwarmPiecePipe::Resume(const std::string& artifact, std::string& err)
{
    return SwarmPiecePipeResume(m_manifests, m_store, artifact, err);
}

bool SwarmPiecePipe::Drop(const std::string& id, std::string& err)
{
    return SwarmPiecePipeDrop(m_store, m_manifests, id, err);
}

bool SwarmPiecePipe::AcceptSealed(const std::string& id, const std::vector<unsigned char>& body, bool ciphertext, bool is_private, std::string& err)
{
    return SwarmPiecePipeAcceptSealed(m_store, id, body, ciphertext, is_private, err);
}

std::size_t SwarmPiecePipe::PieceCount() const
{
    return m_store.count();
}

std::size_t SwarmPiecePipe::ManifestCount() const
{
    return m_manifests.count();
}

bool SwarmPiecePipe::usable(const std::string& artifact) const
{
    return SwarmPiecePipeUsable(m_manifests, m_store, artifact);
}

std::vector<std::string> SwarmPiecePipe::SliceIds(const std::string& artifact) const
{
    return m_manifests.slice_ids(artifact);
}

bool SwarmPiecePipe::HasPiece(const std::string& id) const
{
    return m_store.contains(id);
}

std::int64_t SwarmPiecePipe::bytes_moved() const
{
    return 0;
}

bool SwarmPiecePipe::decrypted() const
{
    return false;
}

bool SwarmPiecePipe::broadcast() const
{
    return false;
}

bool SwarmPiecePipe::launched() const
{
    return false;
}

bool SwarmPiecePipe::gpu() const
{
    return false;
}

} // namespace modelnet
