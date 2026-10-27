// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp38/grp38.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    static constexpr const char* kIds[] = {
        "DS-HIRE-002",
        "DS-HIRE-003",
        "DS-HIRE-004",
        "DS-HIRE-005",
        "DS-HIRE-006",
        "DS-AUTH-001",
        "DS-AUTH-002",
        "DS-AUTH-003",
        "DS-AUTH-004",
        "DS-AUTH-005",
        "DS-AUTH-006",
        "DS-DATA-001",
        "DS-DATA-002",
        "DS-DATA-003",
        "DS-DATA-004",
        "DS-DATA-005",
        "DS-DATA-006",
        "DS-PLAN-001",
        "DS-PLAN-002",
        "DS-PLAN-003",
    };
    for (const char* row : kIds) {
        if (id == row) return true;
    }
    return false;
}

bool ContainsPrivate(const std::string& text)
{
    return text.find("private") != std::string::npos;
}

} // namespace

bool Grp38::stored(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

std::string Grp38::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return std::string();
    return it->second.text;
}

int64_t Grp38::aux_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return static_cast<int64_t>(0);
    return it->second.aux;
}

bool Grp38::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id.empty() || !KnownId(id)) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    if (!NifDtEngineLinked(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (ContainsPrivate(text)) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "DS-AUTH-003" && aux <= static_cast<int64_t>(0)) {
        err = "EXPIRED";
        return false;
    }
    const auto it = m_rows.find(id);
    if (it != m_rows.end()) {
        if (it->second.text == text) {
            err = NIFDT_REPLAY;
        } else {
            err = "UNCHANGED";
        }
        return false;
    }
    m_rows.emplace(id, Row{text, aux});
    err.clear();
    return true;
}

bool Grp38::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp38::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp38::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp38::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp38::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
