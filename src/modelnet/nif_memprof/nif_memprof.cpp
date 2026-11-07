// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_memprof/nif_memprof.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {

namespace {

/** True when a >= 0, b >= 0, and a + b fits in int64. Writes the sum. */
bool SumFits(std::int64_t a, std::int64_t b, std::int64_t& out)
{
    if (a < static_cast<std::int64_t>(0) || b < static_cast<std::int64_t>(0)) {
        return false;
    }
    if (b > std::numeric_limits<std::int64_t>::max() - a) {
        return false;
    }
    out = a + b;
    return true;
}

} // namespace

const NifMemProf::Row* NifMemProf::Find(const std::string& profile) const
{
    const auto it = m_rows.find(profile);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second;
}

NifMemProf::Row* NifMemProf::Find(const std::string& profile)
{
    const auto it = m_rows.find(profile);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second;
}

bool NifMemProf::Missing(const std::string& profile, std::string& err) const
{
    if (profile.empty() || Find(profile) == nullptr) {
        err = NIF_MEMPROF_PROFILE;
        return true;
    }
    return false;
}

bool NifMemProf::Reserve(const std::string& profile, std::int64_t model_bytes, std::int64_t transient_bytes, std::string& err)
{
    if (profile.empty()) {
        err = NIF_MEMPROF_PROFILE;
        return false;
    }
    if (Find(profile) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (model_bytes < static_cast<std::int64_t>(1) || transient_bytes < static_cast<std::int64_t>(0)) {
        err = NIF_MEMPROF_BYTES;
        return false;
    }
    std::int64_t sum = 0;
    std::int64_t updated = 0;
    if (!SumFits(model_bytes, transient_bytes, sum) ||
        !SumFits(m_physical, sum, updated) ||
        updated > NIF_MEMPROF_CAPACITY_BYTES) {
        err = NIF_MEMPROF_CAPACITY;
        return false;
    }
    Row row;
    row.model_bytes = model_bytes;
    row.transient_bytes = transient_bytes;
    m_rows.emplace(profile, row);
    m_physical = updated;
    err.clear();
    return true;
}

bool NifMemProf::Cancel(const std::string& profile, std::string& err)
{
    if (Missing(profile, err)) {
        return false;
    }
    Find(profile)->canceled = true;
    err.clear();
    return true;
}

bool NifMemProf::Quiesce(const std::string& profile, std::string& err)
{
    if (Missing(profile, err)) {
        return false;
    }
    Row* row = Find(profile);
    if (!row->canceled) {
        err = NIF_MEMPROF_ORDER;
        return false;
    }
    row->quiesced = true;
    err.clear();
    return true;
}

bool NifMemProf::Release(const std::string& profile, std::string& err)
{
    if (Missing(profile, err)) {
        return false;
    }
    Row* row = Find(profile);
    if (row->released) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!row->quiesced) {
        err = NIF_MEMPROF_PINNED;
        return false;
    }
    // Reserve stored this pair only after the sum fit in int64 and in the budget.
    m_physical -= row->model_bytes + row->transient_bytes;
    row->released = true;
    err.clear();
    return true;
}

bool NifMemProf::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

std::int64_t NifMemProf::model_bytes(const std::string& profile) const
{
    const Row* row = Find(profile);
    if (row == nullptr) {
        return static_cast<std::int64_t>(0);
    }
    return row->model_bytes;
}

std::int64_t NifMemProf::transient_bytes(const std::string& profile) const
{
    const Row* row = Find(profile);
    if (row == nullptr) {
        return static_cast<std::int64_t>(0);
    }
    return row->transient_bytes;
}

} // namespace modelnet
