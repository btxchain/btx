// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dtat03/dtat03.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "DT-AT-OPT-001",
    "DT-AT-OPT-002",
    "DT-AT-OPT-003",
    "DT-AT-OPT-004",
    "DT-AT-OPT-005",
    "DT-AT-OPT-006",
    "DT-AT-OPT-007",
    "DT-AT-OPT-008",
    "DT-AT-DAT-001",
    "DT-AT-DAT-002",
    "DT-AT-DAT-003",
    "DT-AT-DAT-004",
    "DT-AT-DAT-005",
    "DT-AT-DAT-006",
    "DT-AT-DAT-007",
    "DT-AT-DAT-008",
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

bool NonFinite(const std::string& text)
{
    return text.find("nan") != std::string::npos || text.find("inf") != std::string::npos;
}

bool UnqualifiedId(const std::string& id)
{
    return id == "DT-AT-OPT-005" || id == "DT-AT-OPT-006";
}

} // namespace

bool Dtat03::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Dtat03::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Dtat03::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Dtat03::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (NonFinite(text)) {
        err = "FINITE";
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

bool Dtat03::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Dtat03::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Dtat03::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Dtat03::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Dtat03::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
