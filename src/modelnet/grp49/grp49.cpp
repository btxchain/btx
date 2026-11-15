// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp49/grp49.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "DT-RLP-006", "DT-RLP-007", "DT-RLP-008",
        "DT-CKP-001", "DT-CKP-003", "DT-CKP-004", "DT-CKP-005", "DT-CKP-006", "DT-CKP-007", "DT-CKP-008",
        "DT-WAN-001", "DT-WAN-002", "DT-WAN-003", "DT-WAN-004", "DT-WAN-005", "DT-WAN-006", "DT-WAN-008",
        "DT-SEC-001", "DT-SEC-002",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool RemoteName(const std::string& text)
{
    return !NifDtEngineLinked(text);
}

} // namespace

int64_t Grp49::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp49::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

bool Grp49::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp49::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp49::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp49::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp49::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp49::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (!flag && id != "DT-RLP-006") {
        err = "ABSENT";
        return false;
    }
    if (RemoteName(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("pickle") != std::string::npos) {
        err = "CODE";
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "DT-CKP-004") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-WAN-001") {
        err = NIFDT_NO_ROUTE;
        return false;
    }
    if (id == "DT-RLP-006" && !flag) {
        err = "ROUTE";
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
