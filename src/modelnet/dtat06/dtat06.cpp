// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dtat06/dtat06.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "DT-AT-SIM-001",
    "DT-AT-SIM-002",
    "DT-AT-SIM-003",
    "DT-AT-SIM-004",
    "DT-AT-SIM-005",
    "DT-AT-SIM-006",
    "DT-AT-SIM-007",
    "DT-AT-SIM-008",
    "DT-AT-REL-001",
    "DT-AT-REL-002",
    "DT-AT-REL-003",
    "DT-AT-REL-004",
    "DT-AT-REL-005",
    "DT-AT-REL-006",
    "DT-AT-REL-007",
    "DT-AT-REL-008",
};

const char* const kEngines[] = {
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
    for (const char* name : kEngines) {
        if (text == name) return true;
    }
    return false;
}

bool UnqualifiedId(const std::string& id)
{
    return id == "DT-AT-REL-003" || id == "DT-AT-REL-007";
}

bool SimulationId(const std::string& id)
{
    return id.size() >= 9 && id.compare(0, 9, "DT-AT-SIM") == 0;
}

} // namespace

bool Dtat06::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Dtat06::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Dtat06::classification() const
{
    for (const Row& row : m_rows) {
        if (SimulationId(row.id)) return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
    }
    return "COMPONENT";
}

bool Dtat06::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (UnqualifiedId(id)) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DT-AT-REL-008") {
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

bool Dtat06::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Dtat06::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Dtat06::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Dtat06::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Dtat06::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
