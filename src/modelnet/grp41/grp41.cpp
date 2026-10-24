// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp41/grp41.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownId(const std::string& id)
{
    return id == "DS-PAY-002" || id == "DS-PAY-003" || id == "DS-PAY-004" ||
           id == "DS-PAY-005" || id == "DS-PAY-006" || id == "DS-OPS-001" ||
           id == "DS-OPS-002" || id == "DS-OPS-003" || id == "DS-OPS-004" ||
           id == "DS-OPS-005" || id == "DS-OPS-006" || id == "DS-EVAL-001" ||
           id == "DS-EVAL-002" || id == "DS-EVAL-003" || id == "DS-EVAL-004" ||
           id == "DS-EVAL-005" || id == "DS-EVAL-006" || id == "DS-REC-001" ||
           id == "DS-REC-002" || id == "DS-REC-003";
}

bool PayId(const std::string& id)
{
    return id == "DS-PAY-002" || id == "DS-PAY-003" || id == "DS-PAY-004" ||
           id == "DS-PAY-005" || id == "DS-PAY-006";
}

bool OpsId(const std::string& id)
{
    return id == "DS-OPS-001" || id == "DS-OPS-002" || id == "DS-OPS-003" ||
           id == "DS-OPS-004" || id == "DS-OPS-005" || id == "DS-OPS-006";
}

bool ContainsPrivate(const std::string& text)
{
    return text.find("private") != std::string::npos;
}

} // namespace

const Grp41::Row* Grp41::Find(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

bool Grp41::stored(const std::string& id) const
{
    return Find(id) != nullptr;
}

std::string Grp41::text_of(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    return row->text;
}

int64_t Grp41::aux_of(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return static_cast<int64_t>(0);
    return row->aux;
}

int64_t Grp41::count() const
{
    return static_cast<int64_t>(m_rows.size());
}

bool Grp41::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    if (id.empty() || !KnownId(id)) {
        err = GRP41_ID;
        return false;
    }
    if (text.empty()) {
        err = GRP41_FIELD;
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = GRP41_BOUND;
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = GRP41_CAP;
        return false;
    }
    if (!flag) {
        err = GRP41_ABSENT;
        return false;
    }
    if (!NifDtEngineLinked(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (ContainsPrivate(text)) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (PayId(id)) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (OpsId(id) && text != "benign") {
        err = GRP41_FIXTURE;
        return false;
    }
    if (id == "DS-EVAL-006") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }

    const Row* prior = Find(id);
    if (prior != nullptr) {
        if (prior->text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = GRP41_UNCHANGED;
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

bool Grp41::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = GRP41_HOSTS;
        return false;
    }
    err.clear();
    return true;
}

bool Grp41::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp41::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp41::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp41::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
