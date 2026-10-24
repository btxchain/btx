// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nt02/nt02.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "NT-EXEC-001",
    "NT-EXEC-002",
    "NT-EXEC-003",
    "NT-EXEC-004",
    "NT-EXEC-005",
    "NT-EXEC-006",
    "NT-KV-001",
    "NT-KV-002",
    "NT-KV-003",
    "NT-KV-004",
    "NT-KV-005",
    "NT-KV-006",
    "NT-KV-007",
    "NT-KV-008",
    "NT-LAN-001",
    "NT-LAN-002",
    "NT-LAN-003",
    "NT-LAN-004",
};

const char* const kExactEngine[] = {
    "vllm",
    "sglang",
    "lmcache",
    "nixl",
    "mooncake",
    "rdma",
    "deepinfer",
    "dualpipe",
    "fp8",
    "fp4",
};

bool Known(const std::string& id)
{
    for (const char* row : kKnown) {
        if (id == row) return true;
    }
    return false;
}

bool ExactEngine(const std::string& text)
{
    for (const char* name : kExactEngine) {
        if (text == name) return true;
    }
    return false;
}

} // namespace

bool Nt02::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Nt02::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Nt02::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Nt02::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (ExactEngine(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "NT-KV-004" || id == "NT-KV-007") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (id == "NT-LAN-001" && aux != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (id == "NT-LAN-002") {
        err = "HINT";
        return false;
    }
    for (const Row& row : m_rows) {
        if (row.id != id) continue;
        if (row.text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.push_back(Row{id, text});
    err.clear();
    return true;
}

bool Nt02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Nt02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Nt02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Nt02::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Nt02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
