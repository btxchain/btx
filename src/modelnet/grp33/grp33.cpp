// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp33/grp33.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    return id == "ASR-NAT-001" || id == "ASR-NAT-002" || id == "ASR-NAT-003" ||
           id == "ASR-NAT-004" || id == "ASR-NAT-005" || id == "ASR-NAT-006" ||
           id == "ASR-GRF-001" || id == "ASR-GRF-002" || id == "ASR-GRF-003" ||
           id == "ASR-GRF-004" || id == "ASR-GRF-005" || id == "ASR-PLN-001" ||
           id == "ASR-PLN-002" || id == "ASR-PLN-003" || id == "ASR-PLN-004" ||
           id == "ASR-PLN-005" || id == "ASR-PLN-006" || id == "ASR-PLN-007" ||
           id == "ASR-EXE-001" || id == "ASR-EXE-002";
}

bool EngineAbsent(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8";
}

} // namespace

bool Grp33::Has(const std::string& id) const
{
    const auto it = m_rows.find(id);
    return it != m_rows.end() && it->second.on;
}

void Grp33::Put(const std::string& id, int64_t n, const std::string& text)
{
    Row& row = m_rows[id];
    row.on = true;
    row.n = n;
    row.s = text;
}

int64_t Grp33::stored(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on) return static_cast<int64_t>(0);
    return it->second.n;
}

std::string Grp33::text_of(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end() || !it->second.on) return std::string();
    return it->second.s;
}

std::string Grp33::classification(const std::string& id) const
{
    if (id.rfind("P2P-", 0) == 0) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    if (KnownId(id)) return "COMPONENT";
    return std::string();
}

bool Grp33::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp33::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp33::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp33::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp33::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp33::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (Has(id)) {
        if (text_of(id) == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    Put(id, aux, text);
    err.clear();
    return true;
}

} // namespace modelnet
