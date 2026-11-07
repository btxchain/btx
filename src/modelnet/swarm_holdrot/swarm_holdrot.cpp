// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/swarm_holdrot.h>

#include <modelnet/swarm_holdrot/keep.h>
#include <modelnet/swarm_holdrot/limits.h>
#include <modelnet/swarm_holdrot/request.h>

namespace modelnet {

bool SwarmHoldoutRotate::Rotate(const std::string& holdout, std::string& err)
{
    return SwarmHoldoutRotateRequest{}.Apply(m_book, holdout, err);
}

bool SwarmHoldoutRotate::held(const std::string& holdout) const
{
    return m_book.contains(holdout);
}

std::string SwarmHoldoutRotate::stored_holdout(const std::string& holdout) const
{
    return SwarmHoldoutRotateKeep{}.first(m_book, holdout);
}

std::size_t SwarmHoldoutRotate::holdout_count() const
{
    return m_book.size();
}

bool SwarmHoldoutRotate::rotated() const
{
    if (m_book.rotated()) return true;
    return m_stay.rotated();
}

int64_t SwarmHoldoutRotate::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmHoldoutRotateBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmHoldoutRotate::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmHoldoutRotate::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
