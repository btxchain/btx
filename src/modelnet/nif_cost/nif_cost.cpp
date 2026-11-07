// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_cost/nif_cost.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <limits>
#include <string>

namespace modelnet {

namespace {

/** True when mean_us + uncertainty_us <= budget_us without signed overflow. */
bool SumFitsBudget(int64_t mean_us, int64_t uncertainty_us, int64_t budget_us)
{
    if (mean_us > static_cast<int64_t>(0)) {
        const int64_t room = std::numeric_limits<int64_t>::max() - mean_us;
        if (uncertainty_us > room) {
            return false;
        }
    }
    return mean_us + uncertainty_us <= budget_us;
}

} // namespace

const NifCost::Row* NifCost::Find(const std::string& peer) const
{
    const auto it = m_rows.find(peer);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second;
}

NifCost::Row* NifCost::Find(const std::string& peer)
{
    const auto it = m_rows.find(peer);
    if (it == m_rows.end()) {
        return nullptr;
    }
    return &it->second;
}

bool NifCost::Estimate(const std::string& peer, int64_t mean_us, int64_t uncertainty_us, bool qualified_device, std::string& err)
{
    if (peer.empty()) {
        err = NIF_COST_PEER;
        return false;
    }
    if (Find(peer) != nullptr) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (uncertainty_us < static_cast<int64_t>(0)) {
        err = NIF_COST_BOUND;
        return false;
    }
    if (!qualified_device) {
        err = NIF_COST_HARDWARE;
        return false;
    }
    Row row;
    row.mean_us = mean_us;
    row.uncertainty_us = uncertainty_us;
    m_rows.emplace(peer, row);
    err.clear();
    return true;
}

bool NifCost::Accept(const std::string& peer, int64_t budget_us, std::string& err)
{
    Row* row = Find(peer);
    if (peer.empty() || row == nullptr) {
        err = NIF_COST_PEER;
        return false;
    }
    if (!SumFitsBudget(row->mean_us, row->uncertainty_us, budget_us)) {
        err = NIF_COST_OVER;
        return false;
    }
    row->accepted = true;
    err.clear();
    return true;
}

bool NifCost::Place(const std::string& peer, std::string& err)
{
    Row* row = Find(peer);
    if (row == nullptr || !row->accepted) {
        err = NIF_COST_UNMEASURED;
        return false;
    }
    row->placed = true;
    err.clear();
    return true;
}

int64_t NifCost::mean_us(const std::string& peer) const
{
    const Row* row = Find(peer);
    if (row == nullptr) {
        return static_cast<int64_t>(0);
    }
    return row->mean_us;
}

int64_t NifCost::uncertainty_us(const std::string& peer) const
{
    const Row* row = Find(peer);
    if (row == nullptr) {
        return static_cast<int64_t>(0);
    }
    return row->uncertainty_us;
}

bool NifCost::accepted(const std::string& peer) const
{
    const Row* row = Find(peer);
    return row != nullptr && row->accepted;
}

bool NifCost::placed(const std::string& peer) const
{
    const Row* row = Find(peer);
    return row != nullptr && row->placed;
}

} // namespace modelnet
