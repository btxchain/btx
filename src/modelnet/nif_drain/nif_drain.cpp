// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_drain/nif_drain.h>

#include <modelnet/nifdt_contract/contract.h>

#include <limits>

namespace modelnet {

NifDrain::Row* NifDrain::Find(const std::string& id)
{
    for (Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

const NifDrain::Row* NifDrain::Find(const std::string& id) const
{
    for (const Row& row : m_rows) {
        if (row.id == id) return &row;
    }
    return nullptr;
}

int64_t NifDrain::physical_bytes() const
{
    int64_t total = static_cast<int64_t>(0);
    for (const Row& row : m_rows) {
        total += row.bytes;
    }
    return total;
}

int64_t NifDrain::deadline_ms(const std::string& id) const
{
    const Row* row = Find(id);
    if (row == nullptr) return static_cast<int64_t>(0);
    return row->deadline_ms;
}

bool NifDrain::canceled(const std::string& id) const
{
    const Row* row = Find(id);
    return row != nullptr && row->canceled;
}

bool NifDrain::drained(const std::string& id) const
{
    const Row* row = Find(id);
    return row != nullptr && row->drained;
}

bool NifDrain::drained() const
{
    if (m_rows.empty()) return false;
    for (const Row& row : m_rows) {
        if (!row.drained) return false;
    }
    return true;
}

bool NifDrain::Open(const std::string& id, int64_t deadline_ms, std::string& err)
{
    if (id.empty()) {
        err = NIF_DRAIN_REQUEST;
        return false;
    }
    if (deadline_ms < static_cast<int64_t>(1)) {
        err = NIF_DRAIN_DEADLINE;
        return false;
    }
    if (Find(id) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    Row row;
    row.id = id;
    row.deadline_ms = deadline_ms;
    m_rows.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifDrain::Hold(const std::string& id, int64_t bytes, std::string& err)
{
    Row* row = Find(id);
    if (row == nullptr) {
        err = NIF_DRAIN_REQUEST;
        return false;
    }
    if (bytes < static_cast<int64_t>(1)) {
        err = NIF_DRAIN_BYTES;
        return false;
    }
    if (row->drained) {
        err = NIF_DRAIN_UNCHANGED;
        return false;
    }
    const int64_t total = physical_bytes();
    if (bytes > std::numeric_limits<int64_t>::max() - total) {
        err = NIF_DRAIN_OVERFLOW;
        return false;
    }
    row->bytes += bytes;
    err.clear();
    return true;
}

bool NifDrain::Cancel(const std::string& id, std::string& err)
{
    Row* row = Find(id);
    if (row == nullptr) {
        err = NIF_DRAIN_REQUEST;
        return false;
    }
    if (row->canceled) {
        err = NIFDT_REPLAY;
        return false;
    }
    row->canceled = true;
    err.clear();
    return true;
}

bool NifDrain::Drain(const std::string& id, int64_t now_ms, std::string& err)
{
    Row* row = Find(id);
    if (row == nullptr) {
        err = NIF_DRAIN_REQUEST;
        return false;
    }
    if (row->drained) {
        err = NIF_DRAIN_UNCHANGED;
        return false;
    }
    if (!row->canceled) {
        err = NIF_DRAIN_ORDER;
        return false;
    }
    if (now_ms >= row->deadline_ms) {
        err = NIF_DRAIN_EXPIRED;
        return false;
    }
    row->bytes = static_cast<int64_t>(0);
    row->drained = true;
    err.clear();
    return true;
}

bool NifDrain::Release(const std::string& id, std::string& err)
{
    Row* row = Find(id);
    if (row == nullptr) {
        err = NIF_DRAIN_REQUEST;
        return false;
    }
    if (!row->drained) {
        err = NIF_DRAIN_PINNED;
        return false;
    }
    if (row->released) {
        err = NIF_DRAIN_UNCHANGED;
        return false;
    }
    row->released = true;
    err.clear();
    return true;
}

} // namespace modelnet
