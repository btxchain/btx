// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/swarm_leasework.h>

#include <modelnet/swarm_leasework/bump.h>
#include <modelnet/swarm_leasework/claim.h>
#include <modelnet/swarm_leasework/commit.h>
#include <modelnet/swarm_leasework/grant.h>

namespace modelnet {

bool SwarmLeaseWork::Grant(const std::string& task, const std::string& worker, int64_t now_ms, int64_t until_ms,
                           std::string& err)
{
    return LeaseWorkGrant(m_book, m_epoch, task, worker, now_ms, until_ms, err);
}

void SwarmLeaseWork::BumpEpoch()
{
    LeaseWorkBump(m_epoch, m_leader);
}

bool SwarmLeaseWork::ClaimLeader(const std::string& worker, std::string& err)
{
    return LeaseWorkClaim(m_book, m_leader, worker, err);
}

bool SwarmLeaseWork::Commit(const std::string& task, int64_t epoch, const std::string& result_hash, std::string& err)
{
    return LeaseWorkCommit(m_book, m_epoch, m_leader, task, epoch, result_hash, err);
}

int64_t SwarmLeaseWork::epoch() const
{
    return m_epoch.current();
}

std::string SwarmLeaseWork::leader() const
{
    return m_leader.worker();
}

bool SwarmLeaseWork::commit_right() const
{
    return m_leader.right();
}

bool SwarmLeaseWork::has(const std::string& task) const
{
    return m_book.contains(task);
}

std::string SwarmLeaseWork::worker(const std::string& task) const
{
    return m_book.worker(task);
}

int64_t SwarmLeaseWork::grant_epoch(const std::string& task) const
{
    return m_book.grant_epoch(task);
}

int64_t SwarmLeaseWork::until_ms(const std::string& task) const
{
    return m_book.until_ms(task);
}

bool SwarmLeaseWork::committed(const std::string& task) const
{
    return m_book.committed(task);
}

std::string SwarmLeaseWork::result_hash(const std::string& task) const
{
    return m_book.result_hash(task);
}

bool SwarmLeaseWork::live(const std::string& worker) const
{
    return m_book.worker_live(worker);
}

std::size_t SwarmLeaseWork::grants() const
{
    return m_book.size();
}

int64_t SwarmLeaseWork::bytes_moved() const
{
    return m_silence.bytes_moved();
}

bool SwarmLeaseWork::launched() const
{
    return m_silence.launched();
}

bool SwarmLeaseWork::broadcast() const
{
    return m_silence.broadcast();
}

} // namespace modelnet
