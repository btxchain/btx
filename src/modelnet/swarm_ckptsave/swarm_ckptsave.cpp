// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/swarm_ckptsave.h>

#include <modelnet/swarm_ckptsave/keep.h>
#include <modelnet/swarm_ckptsave/limits.h>
#include <modelnet/swarm_ckptsave/request.h>

namespace modelnet {

bool SwarmCheckpointSave::Request(const std::string& name, std::string& err)
{
    return SwarmCkptSaveRequest{}.Apply(m_book, name, err);
}

bool SwarmCheckpointSave::requested(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmCheckpointSave::stored_name(const std::string& name) const
{
    return SwarmCkptSaveKeep{}.first(m_book, name);
}

std::size_t SwarmCheckpointSave::request_count() const
{
    return m_book.size();
}

bool SwarmCheckpointSave::saved() const
{
    if (m_book.saved()) return true;
    return m_stay.saved();
}

int64_t SwarmCheckpointSave::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmCkptSaveBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmCheckpointSave::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmCheckpointSave::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
