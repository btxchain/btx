// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_guard/nif_guard.h>

#include <modelnet/nifdt_contract/contract.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace {

constexpr unsigned char kPickle[] = {
    'P', 'Y', 'T', 'H', 'O', 'N', '_', 'P', 'I', 'C', 'K', 'L', 'E',
};

bool BeginsWithElf(const std::vector<unsigned char>& body)
{
    return body.size() >= 4 &&
           body[0] == 0x7f &&
           body[1] == static_cast<unsigned char>('E') &&
           body[2] == static_cast<unsigned char>('L') &&
           body[3] == static_cast<unsigned char>('F');
}

bool ContainsPickle(const std::vector<unsigned char>& body)
{
    if (body.size() < sizeof(kPickle)) return false;
    return std::search(body.begin(), body.end(), std::begin(kPickle), std::end(kPickle)) != body.end();
}

} // namespace

namespace modelnet {

bool NifGuard::leader_stored(const std::string& id) const
{
    for (const LeaderRecord& row : m_leaders) {
        if (row.id == id) return true;
    }
    return false;
}

int64_t NifGuard::leader_epoch(const std::string& id) const
{
    for (const LeaderRecord& row : m_leaders) {
        if (row.id == id) return row.epoch;
    }
    return static_cast<int64_t>(0);
}

bool NifGuard::cohort_stored(const std::string& id) const
{
    for (const CohortRecord& row : m_cohorts) {
        if (row.id == id) return true;
    }
    return false;
}

bool NifGuard::data_stored(const std::string& id) const
{
    for (const DataRecord& row : m_data) {
        if (row.id == id) return true;
    }
    return false;
}

bool NifGuard::cache_stored(const std::string& tenant) const
{
    for (const CacheRecord& row : m_cache) {
        if (row.tenant == tenant) return true;
    }
    return false;
}

std::string NifGuard::cache_key(const std::string& tenant) const
{
    for (const CacheRecord& row : m_cache) {
        if (row.tenant == tenant) return row.key;
    }
    return {};
}

bool NifGuard::receipt_stored(const std::string& id) const
{
    for (const ReceiptRecord& row : m_receipts) {
        if (row.id == id) return true;
    }
    return false;
}

bool NifGuard::tensor_stored(int64_t rank) const
{
    for (int64_t stored : m_ranks) {
        if (stored == rank) return true;
    }
    return false;
}

bool NifGuard::Leader(const std::string& id, int64_t epoch, int64_t current_epoch, std::string& err)
{
    // A lower epoch is stale before the replay check, so it cannot replace
    // a leader already stored and it cannot insert a new one.
    if (epoch < current_epoch) {
        err = "STALE";
        return false;
    }
    if (leader_stored(id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    LeaderRecord row;
    row.id = id;
    row.epoch = epoch;
    m_leaders.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifGuard::Cohort(const std::string& id, int64_t now_ms, int64_t until_ms, std::string& err)
{
    // Equality is expiry. The closed window inserts nothing.
    if (now_ms >= until_ms) {
        err = "EXPIRED";
        return false;
    }
    if (cohort_stored(id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    CohortRecord row;
    row.id = id;
    row.now_ms = now_ms;
    row.until_ms = until_ms;
    m_cohorts.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifGuard::Data(const std::string& id, bool revoked, std::string& err)
{
    if (revoked) {
        err = NIFDT_REVOKED;
        return false;
    }
    if (data_stored(id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    DataRecord row;
    row.id = id;
    m_data.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifGuard::Cache(const std::string& tenant, const std::string& key, const std::string& other_tenant, std::string& err)
{
    if (other_tenant != tenant) {
        err = "TENANT";
        return false;
    }
    if (cache_stored(tenant)) {
        err = NIFDT_REPLAY;
        return false;
    }
    CacheRecord row;
    row.tenant = tenant;
    row.key = key;
    m_cache.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifGuard::Receipt(const std::string& id, std::string& err)
{
    if (receipt_stored(id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    ReceiptRecord row;
    row.id = id;
    m_receipts.push_back(std::move(row));
    err.clear();
    return true;
}

bool NifGuard::Checkpoint(const std::vector<unsigned char>& body, std::string& err)
{
    // Markers are refused before the body is copied. The copy is not run.
    if (BeginsWithElf(body) || ContainsPickle(body)) {
        err = "CODE";
        return false;
    }
    m_checkpoint = body;
    m_checkpoint_set = true;
    err.clear();
    return true;
}

bool NifGuard::Tensor(int64_t rank, std::string& err)
{
    if (rank < static_cast<int64_t>(0)) {
        err = "METADATA";
        return false;
    }
    m_ranks.push_back(rank);
    err.clear();
    return true;
}

bool NifGuard::Wallet(bool has_spend_key, std::string& err)
{
    // The argument is a flag. No spend key is accepted or retained.
    if (has_spend_key) {
        err = "WALLET";
        return false;
    }
    m_wallet_noted = true;
    err.clear();
    return true;
}

} // namespace modelnet
