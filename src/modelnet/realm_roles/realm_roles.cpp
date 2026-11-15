// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/realm_roles/realm_roles.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownRole(const std::string& role)
{
    static const char* const kRoles[] = {
        "ingress",
        "attestor",
        "controller",
        "mirror-a",
        "mirror-b",
        "endpoint-a",
        "endpoint-b",
        "endpoint-c",
    };
    for (const char* row : kRoles) {
        if (role == row) return true;
    }
    return false;
}

bool Contains(const std::vector<std::string>& rows, const std::string& role)
{
    for (const std::string& row : rows) {
        if (row == role) return true;
    }
    return false;
}

} // namespace

bool RealmRoles::seated(const std::string& role) const
{
    return Contains(m_seated, role);
}

bool RealmRoles::live(const std::string& role) const
{
    return Contains(m_live, role);
}

int64_t RealmRoles::sequence() const
{
    if (!m_has_sequence) return static_cast<int64_t>(-1);
    return m_sequence;
}

bool RealmRoles::Seat(const std::string& role, std::string& err)
{
    if (role.empty() || !KnownRole(role)) {
        err = "ROLE";
        return false;
    }
    if (!seated(role)) {
        m_seated.push_back(role);
    }
    if (!live(role)) {
        m_live.push_back(role);
    }
    err.clear();
    return true;
}

bool RealmRoles::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool RealmRoles::Advance(int64_t sequence, std::string& err)
{
    if (!m_has_sequence) {
        if (sequence < static_cast<int64_t>(0)) {
            err = "ROLLBACK";
            return false;
        }
        if (sequence != static_cast<int64_t>(0)) {
            err = "GAP";
            return false;
        }
        m_sequence = sequence;
        m_has_sequence = true;
        err.clear();
        return true;
    }
    if (sequence < m_sequence) {
        err = "ROLLBACK";
        return false;
    }
    if (sequence == m_sequence) {
        err = "STALE";
        return false;
    }
    if (sequence != m_sequence + static_cast<int64_t>(1)) {
        err = "GAP";
        return false;
    }
    m_sequence = sequence;
    err.clear();
    return true;
}

bool RealmRoles::Stop(const std::string& role, std::string& err)
{
    if (!live(role)) {
        err = "ROLE";
        return false;
    }
    std::vector<std::string> kept;
    kept.reserve(m_live.size());
    for (const std::string& row : m_live) {
        if (row != role) kept.push_back(row);
    }
    m_live.swap(kept);
    err.clear();
    return true;
}

bool RealmRoles::Report(const std::string& role, int64_t& sequence, std::string& err) const
{
    if (!live(role)) {
        err = "ROLE";
        return false;
    }
    if (!m_has_sequence) {
        err = "GAP";
        return false;
    }
    sequence = m_sequence;
    err.clear();
    return true;
}

bool RealmRoles::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool RealmRoles::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool RealmRoles::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool RealmRoles::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
