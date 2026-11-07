// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp44/grp44.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "NIF-PROF-005",
        "NIF-EXEC-002", "NIF-EXEC-003", "NIF-EXEC-004", "NIF-EXEC-006",
        "NIF-KV-001", "NIF-KV-002", "NIF-KV-003", "NIF-KV-004",
        "NIF-KV-005", "NIF-KV-006", "NIF-KV-007", "NIF-KV-008",
        "NIF-LAN-001", "NIF-LAN-002", "NIF-LAN-006", "NIF-LAN-007", "NIF-LAN-008",
        "NIF-ISL-001", "NIF-ISL-002",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool KvTransferAbsent(const std::string& id)
{
    return id == "NIF-KV-004" || id == "NIF-KV-007";
}

} // namespace

int64_t Grp44::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp44::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

std::string Grp44::classification(const std::string&) const
{
    return "COMPONENT";
}

bool Grp44::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp44::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp44::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp44::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp44::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (KvTransferAbsent(id)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "NIF-LAN-001" && aux != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (id == "NIF-LAN-002") {
        err = "HINT";
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
