// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp45/grp45.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    static constexpr const char* kIds[] = {
        "NIF-ISL-003",
        "NIF-ISL-004",
        "NIF-ISL-005",
        "NIF-PKG-001",
        "NIF-PKG-002",
        "NIF-PKG-003",
        "NIF-PKG-004",
        "NIF-PKG-005",
        "NIF-DATA-001",
        "NIF-DATA-002",
        "NIF-DATA-003",
        "NIF-DATA-005",
        "NIF-ECON-001",
        "NIF-ECON-002",
        "NIF-ECON-003",
        "NIF-ECON-004",
        "NIF-QA-001",
        "NIF-QA-002",
        "NIF-QA-003",
    };
    for (const char* row : kIds) {
        if (id == row) return true;
    }
    return false;
}

} // namespace

const Grp45::Row* Grp45::Find(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool Grp45::stored(const std::string& id) const
{
    return Find(id) != nullptr;
}

std::string Grp45::text_of(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    return row->text;
}

int64_t Grp45::aux_of(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return static_cast<int64_t>(0);
    return row->aux;
}

bool Grp45::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (!NifDtEngineLinked(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "NIF-ECON-004") {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    if (id == "NIF-PKG-001") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (const Row* prior = Find(id)) {
        if (prior->text == text) {
            err = NIFDT_REPLAY;
        } else {
            err = "UNCHANGED";
        }
        return false;
    }
    Row row;
    row.id = id;
    row.text = text;
    row.aux = aux;
    m_rows.push_back(row);
    err.clear();
    return true;
}

bool Grp45::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp45::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp45::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp45::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp45::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
