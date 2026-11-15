// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_data/dt_data.h>

namespace modelnet {

const DtData::Row* DtData::Find(const std::string& id) const
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) return nullptr;
    return &it->second;
}

bool DtData::Admit(const std::string& id,
                   const std::string& license,
                   const std::string& purpose,
                   const std::string& kind,
                   const std::string& partition,
                   std::string& err)
{
    if (id.empty()) {
        err = kDtDataDataset;
        return false;
    }
    if (m_rows.count(id) != 0) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (license.empty()) {
        err = kDtDataLicense;
        return false;
    }
    // private, incident, and every other kind store nothing.
    if (kind != kDtDataPublic && kind != kDtDataSynthetic) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    // defensive is not training or evaluation, so it is not admitted.
    if (purpose != kDtDataTraining && purpose != kDtDataEvaluation) {
        err = kDtDataNotAuthorized;
        return false;
    }
    Row row;
    row.license = license;
    row.purpose = purpose;
    row.kind = kind;
    row.partition = partition;
    m_rows.emplace(id, std::move(row));
    err.clear();
    return true;
}

int64_t DtData::Cursor(const std::string& id, std::string& err) const
{
    const Row* row = Find(id);
    if (row == nullptr) {
        err = kDtDataDataset;
        return static_cast<int64_t>(0);
    }
    if (row->purpose != kDtDataTraining) {
        err = kDtDataHoldout;
        return static_cast<int64_t>(0);
    }
    err.clear();
    return row->cursor;
}

bool DtData::Train(const std::string& id, std::string& err)
{
    const auto it = m_rows.find(id);
    if (it == m_rows.end()) {
        err = kDtDataDataset;
        return false;
    }
    if (it->second.purpose != kDtDataTraining) {
        err = kDtDataHoldout;
        return false;
    }
    it->second.cursor += static_cast<int64_t>(1);
    err.clear();
    return true;
}

bool DtData::admitted(const std::string& id) const
{
    return Find(id) != nullptr;
}

std::string DtData::license(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    return row->license;
}

std::string DtData::purpose(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    return row->purpose;
}

std::string DtData::kind(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    return row->kind;
}

std::string DtData::partition(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return {};
    return row->partition;
}

} // namespace modelnet
