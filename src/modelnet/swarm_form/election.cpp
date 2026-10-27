// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/election.h>

#include <modelnet/swarm_form/atomic.h>
#include <modelnet/swarm_form/codec.h>

#include <system_error>

namespace modelnet {

bool SwarmFormElection::Save(const fs::path& swarm_dir, std::string& err)
{
    if (m_epoch < 1) {
        err = "SCHEMA";
        return false;
    }
    if (!SwarmFormWrite(swarm_dir / kElectionFile, EncodeElection(m_leader, m_epoch), err)) return false;
    m_dir = swarm_dir;
    m_loaded = true;
    return true;
}

bool SwarmFormElection::Load(const fs::path& swarm_dir, std::string& err)
{
    m_loaded = false;
    m_leader.clear();
    m_epoch = 1;
    m_dir = swarm_dir;
    const fs::path file = swarm_dir / kElectionFile;
    std::error_code ec;
    const fs::file_status status = fs::symlink_status(file, ec);
    if (!ec && fs::is_symlink(status)) {
        err = "SYMLINK";
        return false;
    }
    if (!fs::exists(file)) {
        m_loaded = true;
        err.clear();
        return true;
    }
    std::string raw;
    if (!SwarmFormRead(file, raw, err)) return false;
    std::string leader;
    uint64_t epoch = 1;
    if (!DecodeElection(raw, leader, epoch, err)) return false;
    m_leader = std::move(leader);
    m_epoch = epoch;
    m_loaded = true;
    return true;
}

bool SwarmFormElection::Claim(const fs::path& swarm_dir, const SwarmFormMembership& members, const std::string& candidate, uint64_t epoch, std::string& err)
{
    if (!m_loaded || m_dir != swarm_dir) {
        if (!Load(swarm_dir, err)) return false;
    }
    if (candidate.empty()) {
        err = "LEADER";
        return false;
    }
    if (!members.admitted(candidate)) {
        err = "NOT_ADMITTED";
        return false;
    }
    if (epoch < m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    if (!m_leader.empty() && epoch == m_epoch && candidate != m_leader) {
        err = "EPOCH";
        return false;
    }
    if (candidate == m_leader && epoch == m_epoch) {
        err.clear();
        return true;
    }
    const std::string previous_leader = m_leader;
    const uint64_t previous_epoch = m_epoch;
    m_leader = candidate;
    m_epoch = epoch;
    if (!Save(swarm_dir, err)) {
        m_leader = previous_leader;
        m_epoch = previous_epoch;
        return false;
    }
    return true;
}

} // namespace modelnet
