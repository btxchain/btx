// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nt04/nt04.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "NT-DATA-005",
    "NT-ECON-001",
    "NT-ECON-002",
    "NT-ECON-003",
    "NT-ECON-004",
    "NT-QA-001",
    "NT-QA-002",
    "NT-QA-003",
    "NT-QA-004",
    "NT-QA-005",
    "NT-QA-006",
    "NT-QA-007",
    "NT-GOV-001",
    "NT-GOV-002",
    "NT-GOV-003",
    "NT-GOV-004",
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

bool ExactEngineAbsent(const std::string& text)
{
    for (const char* name : kExactEngine) {
        if (text == name) return true;
    }
    return false;
}

} // namespace

bool Nt04::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Nt04::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Nt04::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Nt04::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (ExactEngineAbsent(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "NT-QA-007") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "NT-ECON-004" || id == "NT-GOV-004") {
        err = NIFDT_AUTOMATIC_SPEND;
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

bool Nt04::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Nt04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Nt04::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Nt04::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Nt04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
