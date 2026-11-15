// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp43/grp43.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    return id == "P2P-SCN-L" || id == "P2P-SCN-M" || id == "P2P-SCN-N" ||
           id == "P2P-SCN-O" || id == "P2P-SCN-P" || id == "P2P-SCN-Q" ||
           id == "P2P-SCN-R" || id == "NIF-NAT-001" || id == "NIF-NAT-004" ||
           id == "NIF-NAT-006" || id == "NIF-FORK-001" || id == "NIF-FORK-002" ||
           id == "NIF-FORK-003" || id == "NIF-FORK-004" || id == "NIF-FORK-005" ||
           id == "NIF-FORK-006" || id == "NIF-PROF-001" || id == "NIF-PROF-002" ||
           id == "NIF-PROF-003" || id == "NIF-PROF-004";
}

bool IsP2p(const std::string& id)
{
    return id.rfind("P2P-", 0) == 0;
}

bool RemoteName(const std::string& text)
{
    if (!NifDtEngineLinked(text)) return true;
    static const char* const kRemote[] = {
        "deepinfer", "vllm", "sglang", "lmcache", "deepep", "deepgemm",
        "dualpipe", "dualpipev", "nixl", "mooncake", "rdma",
    };
    for (const char* name : kRemote) {
        if (text.find(name) != std::string::npos) return true;
    }
    return false;
}

} // namespace

bool Grp43::recorded(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

int64_t Grp43::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return static_cast<int64_t>(0);
    return it->second.aux;
}

std::string Grp43::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return std::string();
    return it->second.text;
}

std::string Grp43::classification(const std::string& id) const
{
    if (IsP2p(id)) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp43::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp43::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp43::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp43::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp43::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (RemoteName(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (IsP2p(id) && aux != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (id == "P2P-SCN-M") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "NIF-FORK-004" || id == "NIF-FORK-005") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    const auto it = m_rows.find(id);
    if (it != m_rows.end()) {
        if (it->second.text != text) {
            err = "UNCHANGED";
            return false;
        }
        err = NIFDT_REPLAY;
        return false;
    }
    Row row;
    row.aux = aux;
    row.text = text;
    m_rows.emplace(id, row);
    err.clear();
    return true;
}

} // namespace modelnet
