// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp40/grp40.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    static constexpr const char* kIds[] = {
        "DS-STD-006",
        "DS-MODEL-001",
        "DS-MODEL-002",
        "DS-MODEL-003",
        "DS-MODEL-004",
        "DS-MODEL-005",
        "DS-MODEL-006",
        "DS-LEARN-001",
        "DS-LEARN-002",
        "DS-LEARN-003",
        "DS-LEARN-004",
        "DS-LEARN-005",
        "DS-LEARN-006",
        "DS-POOL-001",
        "DS-POOL-002",
        "DS-POOL-003",
        "DS-POOL-004",
        "DS-POOL-005",
        "DS-POOL-006",
        "DS-PAY-001",
    };
    for (const char* row : kIds) {
        if (id == row) {
            return true;
        }
    }
    return false;
}

bool UnqualifiedId(const std::string& id)
{
    return id == "DS-PAY-001" || id == "DS-LEARN-006";
}

} // namespace

bool Grp40::stored(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

std::string Grp40::text(const std::string& id) const
{
    const auto found = m_rows.find(id);
    if (found == m_rows.end()) {
        return {};
    }
    return found->second;
}

int64_t Grp40::count() const
{
    return static_cast<int64_t>(m_rows.size());
}

bool Grp40::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id.empty() || !KnownId(id)) {
        err = GRP40_ID;
        return false;
    }
    if (text.empty()) {
        err = GRP40_FIELD;
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = GRP40_BOUND;
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = GRP40_CAP;
        return false;
    }
    if (!flag) {
        err = GRP40_ABSENT;
        return false;
    }
    if (!NifDtEngineLinked(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (UnqualifiedId(id)) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    const auto found = m_rows.find(id);
    if (found != m_rows.end()) {
        if (found->second == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = GRP40_UNCHANGED;
        return false;
    }
    m_rows.emplace(id, text);
    err.clear();
    return true;
}

bool Grp40::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = GRP40_HOSTS;
        return false;
    }
    err.clear();
    return true;
}

bool Grp40::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp40::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp40::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp40::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
