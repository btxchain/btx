// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dtat04/dtat04.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kKnown[] = {
    "DT-AT-RLP-001",
    "DT-AT-RLP-002",
    "DT-AT-RLP-003",
    "DT-AT-RLP-004",
    "DT-AT-RLP-005",
    "DT-AT-RLP-006",
    "DT-AT-RLP-007",
    "DT-AT-RLP-008",
    "DT-AT-CKP-001",
    "DT-AT-CKP-002",
    "DT-AT-CKP-003",
    "DT-AT-CKP-004",
    "DT-AT-CKP-005",
    "DT-AT-CKP-006",
    "DT-AT-CKP-007",
    "DT-AT-CKP-008",
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
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool Dtat04::stored(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return true;
    }
    return false;
}

std::string Dtat04::text(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return row.text;
    }
    return std::string();
}

std::string Dtat04::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Dtat04::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
        if (id == "DT-AT-RLP-006") {
            err = "ROUTE";
            return false;
        }
        err = "ABSENT";
        return false;
    }
    if (ExactEngineAbsent(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("pickle") != std::string::npos) {
        err = "CODE";
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "DT-AT-CKP-004") {
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

bool Dtat04::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Dtat04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Dtat04::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Dtat04::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Dtat04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
