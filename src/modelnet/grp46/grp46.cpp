// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp46/grp46.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "NIF-QA-004", "NIF-QA-005", "NIF-QA-006",
        "NIF-GOV-001", "NIF-GOV-002", "NIF-GOV-003", "NIF-GOV-004",
        "DT-EVD-001", "DT-EVD-002", "DT-EVD-003", "DT-EVD-004",
        "DT-EVD-005", "DT-EVD-006", "DT-EVD-007", "DT-EVD-008",
        "DT-NAT-001", "DT-NAT-002", "DT-NAT-003", "DT-NAT-005",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool RemoteName(const std::string& text)
{
    if (text == "fp8") return true;
    return !NifDtEngineLinked(text);
}

} // namespace

int64_t Grp46::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp46::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

std::string Grp46::classification(const std::string&) const
{
    return "COMPONENT";
}

bool Grp46::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp46::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp46::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp46::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp46::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp46::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (!Known(id)) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = id == "DT-NAT-003" ? "EXPIRED" : "BOUND";
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
    if (RemoteName(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "NIF-GOV-004") {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (id == "DT-NAT-003" && aux <= static_cast<int64_t>(0)) {
        err = "EXPIRED";
        return false;
    }
    const auto it = m_rows.find(id);
    if (it != m_rows.end()) {
        if (it->second == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.emplace(id, text);
    err.clear();
    return true;
}

} // namespace modelnet
