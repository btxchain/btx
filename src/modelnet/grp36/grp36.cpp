// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp36/grp36.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    static const char* kIds[] = {
        "ASR-TRN-003",
        "ASR-TRN-004",
        "ASR-TRN-005",
        "ASR-EVO-001",
        "ASR-EVO-002",
        "ASR-EVO-003",
        "ASR-EVO-004",
        "ASR-VAL-001",
        "ASR-VAL-002",
        "ASR-VAL-003",
        "ASR-VAL-004",
        "ASR-VAL-005",
        "ASR-PAY-001",
        "ASR-PAY-002",
        "ASR-PAY-003",
        "ASR-PAY-004",
        "ASR-PRT-001",
        "ASR-PRT-002",
        "ASR-RES-001",
        "ASR-RES-002",
    };
    for (const char* row : kIds) {
        if (id == row) return true;
    }
    return false;
}

bool EngineAbsent(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" || text == "nixl" ||
           text == "mooncake" || text == "rdma" || text == "deepinfer" || text == "dualpipe" ||
           text == "fp8";
}

} // namespace

bool Grp36::stored(const std::string& id) const
{
    return m_rows.find(id) != m_rows.end();
}

std::string Grp36::text(const std::string& id) const
{
    const auto found = m_rows.find(id);
    if (found == m_rows.end()) return {};
    return found->second;
}

bool Grp36::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (EngineAbsent(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    const auto found = m_rows.find(id);
    if (found != m_rows.end()) {
        if (found->second == text) {
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

bool Grp36::Settle(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp36::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp36::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp36::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp36::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp36::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
