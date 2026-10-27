// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp42/grp42.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    static const char* const kIds[] = {
        "DS-REC-004", "DS-REC-005", "DS-REC-006",
        "DS-DEL-001", "DS-DEL-002", "DS-DEL-003",
        "DS-DEL-004", "DS-DEL-005", "DS-DEL-006",
        "P2P-SCN-A", "P2P-SCN-B", "P2P-SCN-C", "P2P-SCN-D",
        "P2P-SCN-E", "P2P-SCN-F", "P2P-SCN-G", "P2P-SCN-H",
        "P2P-SCN-I", "P2P-SCN-J", "P2P-SCN-K",
    };
    for (const char* known : kIds) {
        if (id == known) return true;
    }
    return false;
}

bool IsP2P(const std::string& id)
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

int64_t Grp42::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp42::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

std::string Grp42::classification(const std::string& id) const
{
    if (IsP2P(id)) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    return "COMPONENT";
}

bool Grp42::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp42::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp42::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp42::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp42::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (RemoteName(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (IsP2P(id) && aux != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (id == "P2P-SCN-I") {
        err = NIFDT_ENGINE_ABSENT;
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
