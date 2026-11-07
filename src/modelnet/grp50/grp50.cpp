// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp50/grp50.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "DT-SEC-003",
    "DT-SEC-004",
    "DT-SEC-005",
    "DT-SEC-006",
    "DT-SEC-007",
    "DT-SEC-008",
    "DT-SIM-001",
    "DT-SIM-002",
    "DT-SIM-003",
    "DT-SIM-004",
    "DT-SIM-005",
    "DT-SIM-007",
    "DT-SIM-008",
    "DT-REL-001",
    "DT-REL-002",
    "DT-REL-004",
    "DT-REL-005",
    "DT-REL-006",
    "DT-REL-008",
};

bool Known(const std::string& id)
{
    for (const char* row : kKnown) {
        if (id == row) return true;
    }
    return false;
}

bool RemoteFp8OrDualpipe(const std::string& text)
{
    if (text == "fp8" || text == "dualpipe") return true;
    return !NifDtEngineLinked(text);
}

} // namespace

bool Grp50::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Grp50::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Grp50::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Grp50::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (id == "DT-REL-004" && text == "rdma") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (RemoteFp8OrDualpipe(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "DT-REL-008") {
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

bool Grp50::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp50::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp50::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp50::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp50::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
