// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cohortbook.h>

#include <modelnet/swarm_cycle.h>

#include <fstream>
#include <system_error>

namespace modelnet {
namespace {

bool WriteAtomic(const fs::path& final_path, const std::string& body, std::string& err)
{
    const fs::path tmp = fs::u8path(final_path.utf8string() + ".tmp");
    {
        std::ofstream file(tmp, std::ios::trunc);
        if (!file) {
            err = "WRITE";
            return false;
        }
        file << body;
        if (!file) {
            err = "WRITE";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "RENAME";
        return false;
    }
    err.clear();
    return true;
}

} // namespace

bool SwarmCohortBook::Open(int64_t epoch, std::string& err)
{
    if (m_open) {
        err = "REOPEN";
        return false;
    }
    if (epoch < 0) {
        err = "EPOCH";
        return false;
    }
    m_open = true;
    m_epoch = epoch;
    m_leases.clear();
    err.clear();
    return true;
}

bool SwarmCohortBook::Grant(const std::string& member_id, const std::string& lease_id, int64_t until_ms, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    if (member_id.empty() || lease_id.empty() || until_ms <= 0) {
        err = "LEASE";
        return false;
    }
    for (Lease& lease : m_leases) {
        if (lease.lease_id == lease_id) {
            err = "REPLAY";
            return false;
        }
        if (lease.member_id == member_id && !lease.superseded) lease.superseded = true;
    }
    Lease lease;
    lease.member_id = member_id;
    lease.lease_id = lease_id;
    lease.until_ms = until_ms;
    m_leases.push_back(lease);
    err.clear();
    return true;
}

bool SwarmCohortBook::Revoke(const std::string& lease_id, std::string& err)
{
    for (Lease& lease : m_leases) {
        if (lease.lease_id == lease_id && !lease.superseded) {
            lease.revoked = true;
            err.clear();
            return true;
        }
    }
    err = "LEASE";
    return false;
}

bool SwarmCohortBook::SetEpoch(int64_t epoch, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    if (epoch < m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    m_epoch = epoch;
    err.clear();
    return true;
}

bool SwarmCohortBook::Admit(int64_t now_ms, int64_t leader_epoch, const std::string& member_id, const std::string& lease_id,
                            bool checkpoint_match, bool recipe_match, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    if (leader_epoch != m_epoch) {
        err = "STALE_EPOCH";
        return false;
    }
    Lease* found = nullptr;
    for (Lease& lease : m_leases) {
        if (lease.lease_id == lease_id && lease.member_id == member_id) found = &lease;
    }
    if (found == nullptr) {
        err = "LEASE";
        return false;
    }
    if (found->revoked) {
        err = "REVOKED";
        return false;
    }
    if (found->superseded) {
        err = "SUPERSEDED";
        return false;
    }
    if (!SwarmAdmitCohortMember(now_ms, found->until_ms, checkpoint_match, recipe_match, err)) return false;
    found->admitted = true;
    err.clear();
    return true;
}

int SwarmCohortBook::Admitted() const
{
    int count = 0;
    for (const Lease& lease : m_leases) {
        if (lease.admitted && !lease.revoked && !lease.superseded) ++count;
    }
    return count;
}

bool SwarmCohortBook::Persist(const fs::path& modeldir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    fs::path dir = modeldir / "swarm";
    fs::create_directories(dir);
    if (!fs::exists(dir)) {
        err = "SWARM_DIR";
        return false;
    }
    std::string body = "epoch " + std::to_string(m_epoch) + "\n";
    for (const Lease& lease : m_leases) {
        body += "lease " + lease.member_id + " " + lease.lease_id + " " + std::to_string(lease.until_ms) + " " +
                (lease.revoked ? "1" : "0") + " " + (lease.superseded ? "1" : "0") + " " + (lease.admitted ? "1" : "0") + "\n";
    }
    return WriteAtomic(dir / "cohort-leases.txt", body, err);
}

bool SwarmCohortBook::Load(const fs::path& modeldir, std::string& err)
{
    const fs::path path = modeldir / "swarm" / "cohort-leases.txt";
    std::ifstream in(path);
    if (!in) {
        err = "READ";
        return false;
    }
    m_leases.clear();
    std::string tag;
    if (!(in >> tag >> m_epoch) || tag != "epoch") {
        err = "READ";
        return false;
    }
    while (in >> tag) {
        if (tag != "lease") {
            err = "READ";
            return false;
        }
        Lease lease;
        int revoked = 0;
        int superseded = 0;
        int admitted = 0;
        if (!(in >> lease.member_id >> lease.lease_id >> lease.until_ms >> revoked >> superseded >> admitted)) {
            err = "READ";
            return false;
        }
        lease.revoked = revoked != 0;
        lease.superseded = superseded != 0;
        lease.admitted = admitted != 0;
        m_leases.push_back(lease);
    }
    m_open = true;
    err.clear();
    return true;
}

} // namespace modelnet
