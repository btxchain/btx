// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_launchprof/swarm_launchprofile.h>

#include <modelnet/swarm_launchprof/keep.h>
#include <modelnet/swarm_launchprof/limits.h>
#include <modelnet/swarm_launchprof/request.h>

#include <string>

namespace modelnet {

bool SwarmLaunchProfile::Rename(const std::string& name, std::string& err)
{
    return SwarmLaunchProfileRequest{}.Apply(m_book, name, err);
}

std::string SwarmLaunchProfile::profile() const
{
    return std::string{kSwarmLaunchProfileName};
}

bool SwarmLaunchProfile::stored(const std::string& name) const
{
    return m_book.contains(name);
}

std::string SwarmLaunchProfile::stored_name(const std::string& name) const
{
    return SwarmLaunchProfileKeep{}.first(m_book, name);
}

std::size_t SwarmLaunchProfile::rename_count() const
{
    return m_book.size();
}

bool SwarmLaunchProfile::renamed() const
{
    if (m_book.renamed()) return true;
    return m_stay.renamed();
}

int64_t SwarmLaunchProfile::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmLaunchProfileBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmLaunchProfile::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmLaunchProfile::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
