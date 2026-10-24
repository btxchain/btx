// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp34/grp34.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Known(const std::string& id)
{
    static const char* kIds[] = {
        "ASR-EXE-003", "ASR-EXE-004", "ASR-EXE-005", "ASR-EXE-006", "ASR-EXE-007",
        "ASR-NET-001", "ASR-NET-002", "ASR-NET-003", "ASR-NET-004", "ASR-NET-005",
        "ASR-HND-001", "ASR-HND-002", "ASR-HND-003", "ASR-HND-004",
        "ASR-PRG-001", "ASR-PRG-002", "ASR-PRG-003", "ASR-PRG-004",
        "ASR-EVD-001", "ASR-EVD-002",
    };
    for (const char* s : kIds) {
        if (id == s) return true;
    }
    return false;
}

bool EngineName(const std::string& text)
{
    static const char* kNames[] = {
        "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer", "dualpipe", "fp8",
    };
    for (const char* s : kNames) {
        if (text == s) return true;
    }
    return false;
}

} // namespace

int64_t Grp34::stored(const std::string& id) const
{
    return m_rows.find(id) == m_rows.end() ? static_cast<int64_t>(0) : static_cast<int64_t>(1);
}

std::string Grp34::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it == m_rows.end() ? std::string() : it->second;
}

std::string Grp34::classification(const std::string&) const
{
    return "COMPONENT";
}

bool Grp34::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp34::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp34::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp34::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp34::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp34::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (EngineName(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
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
