// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp39/grp39.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    return id == "DS-PLAN-004" || id == "DS-PLAN-005" || id == "DS-PLAN-006" ||
           id == "DS-ACT-001" || id == "DS-ACT-002" || id == "DS-ACT-003" ||
           id == "DS-ACT-004" || id == "DS-ACT-005" || id == "DS-ACT-006" ||
           id == "DS-SHARE-001" || id == "DS-SHARE-002" || id == "DS-SHARE-003" ||
           id == "DS-SHARE-004" || id == "DS-SHARE-005" || id == "DS-SHARE-006" ||
           id == "DS-STD-001" || id == "DS-STD-002" || id == "DS-STD-003" ||
           id == "DS-STD-004" || id == "DS-STD-005";
}

} // namespace

const Grp39::Row* Grp39::Find(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool Grp39::stored(const std::string& id) const
{
    return Find(id) != nullptr;
}

std::string Grp39::text_of(const std::string& id) const
{
    const Row* row = Find(id);
    return row == nullptr ? std::string() : row->text;
}

int64_t Grp39::aux_of(const std::string& id) const
{
    const Row* row = Find(id);
    return row == nullptr ? static_cast<int64_t>(0) : row->aux;
}

bool Grp39::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
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
    if (id == "DS-ACT-002" && text == "D3") {
        err = "APPROVAL";
        return false;
    }
    if (id == "DS-SHARE-002") {
        err = "EMBARGO";
        return false;
    }
    const Row* existing = Find(id);
    if (existing != nullptr) {
        if (existing->text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.push_back(Row{id, text, aux});
    err.clear();
    return true;
}

bool Grp39::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Grp39::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp39::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp39::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp39::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
