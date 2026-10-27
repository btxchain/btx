// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_reshard/dt_reshard.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool DtReshard::Map(const std::string& logical, const std::string& shard, std::string& err)
{
    if (logical.empty()) {
        err = DT_RESHARD_PARAM;
        return false;
    }
    if (shard.empty()) {
        err = DT_RESHARD_SHARD;
        return false;
    }
    if (m_rows.find(logical) != m_rows.end()) {
        err = NIFDT_REPLAY;
        return false;
    }

    Row row;
    row.shard = shard;
    m_rows.emplace(logical, row);
    err.clear();
    return true;
}

bool DtReshard::Move(const std::string& logical, const std::string& shard, int64_t weight, std::string& err)
{
    const auto it = m_rows.find(logical);
    if (logical.empty() || it == m_rows.end()) {
        err = DT_RESHARD_PARAM;
        return false;
    }
    Row& row = it->second;
    if (row.shard != shard) {
        err = DT_RESHARD_MAP;
        return false;
    }
    if (row.applied && row.moved == weight) {
        err.clear();
        return true;
    }
    row.moved = weight;
    row.has_move = true;
    row.applied = false;
    err.clear();
    return true;
}

bool DtReshard::Apply(const std::string& logical, std::string& err)
{
    const auto it = m_rows.find(logical);
    if (it == m_rows.end() || !it->second.has_move) {
        err = DT_RESHARD_UNMAPPED;
        return false;
    }
    Row& row = it->second;
    if (row.applied) {
        err = DT_RESHARD_UNCHANGED;
        return false;
    }

    const int64_t previous = m_live;
    m_prior = previous;
    m_live = m_live - row.contributed + row.moved;
    row.contributed = row.moved;
    row.applied = true;
    err.clear();
    return true;
}

bool DtReshard::Prior(const std::string& logical, std::string& err)
{
    if (logical.empty() || m_rows.find(logical) == m_rows.end()) {
        err = DT_RESHARD_PARAM;
        return false;
    }
    err.clear();
    return true;
}

bool DtReshard::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet
