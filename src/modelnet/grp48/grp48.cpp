// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp48/grp48.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "DT-OPT-002", "DT-OPT-003", "DT-OPT-005", "DT-OPT-006", "DT-OPT-007", "DT-OPT-008",
        "DT-DAT-001", "DT-DAT-002", "DT-DAT-003", "DT-DAT-004",
        "DT-DAT-005", "DT-DAT-006", "DT-DAT-007", "DT-DAT-008",
        "DT-RLP-001", "DT-RLP-002", "DT-RLP-003", "DT-RLP-004", "DT-RLP-005",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool UnqualifiedId(const std::string& id)
{
    return id == "DT-OPT-005" || id == "DT-OPT-006";
}

bool NonFinite(const std::string& text)
{
    return text.find("nan") != std::string::npos || text.find("inf") != std::string::npos;
}

} // namespace

int64_t Grp48::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp48::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

bool Grp48::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp48::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp48::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp48::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp48::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp48::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id.empty() || !Known(id)) {
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
    if (text == "fp8" || text == "fp4") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (NonFinite(text)) {
        err = "FINITE";
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
