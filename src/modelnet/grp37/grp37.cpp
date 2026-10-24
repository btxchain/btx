// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp37/grp37.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "ASR-SEC-001",
        "ASR-SEC-002",
        "ASR-REC-001",
        "ASR-REC-002",
        "ASR-OBS-001",
        "ASR-MIG-001",
        "ASR-MIG-002",
        "ASR-ACC-001",
        "ASR-ACC-002",
        "ASR-PUB-001",
        "ASR-PUB-002",
        "ASR-PUB-003",
        "ASR-PUB-004",
        "DS-NAT-001",
        "DS-NAT-002",
        "DS-NAT-003",
        "DS-NAT-004",
        "DS-NAT-005",
        "DS-NAT-006",
        "DS-HIRE-001",
    };
    for (const char* row : kIds) {
        if (id == row) return true;
    }
    return false;
}

} // namespace

bool Grp37::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

int64_t Grp37::aux_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on) return static_cast<int64_t>(0);
    return it->second.aux;
}

std::string Grp37::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on) return std::string();
    return it->second.text;
}

bool Grp37::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp37::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp37::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp37::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp37::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp37::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (id == "ASR-ACC-002" && (text == "gpu" || text == "windows")) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    const auto it = m_rows.find(id);
    if (it != m_rows.end() && it->second.on) {
        if (id == "ASR-MIG-001" && aux > it->second.aux) {
            err = "UPGRADE";
            return false;
        }
        if (text != it->second.text) {
            err = "UNCHANGED";
            return false;
        }
        err = NIFDT_REPLAY;
        return false;
    }
    Row& row = m_rows[id];
    row.on = true;
    row.aux = aux;
    row.text = text;
    err.clear();
    return true;
}

} // namespace modelnet
