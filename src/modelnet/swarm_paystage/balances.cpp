// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paystage/balances.h>

#include <limits>

namespace modelnet {
namespace {

bool FitsInBucket(int64_t have, int64_t atoms)
{
    if (atoms < 1 || have < 0) {
        return false;
    }
    // have + atoms would exceed int64 max.
    return have <= std::numeric_limits<int64_t>::max() - atoms;
}

} // namespace

int64_t* SwarmPayBalances::Slot(const std::string& bucket)
{
    if (bucket == SWARM_PAY_BUCKET_ESCROW) {
        return &m_escrow;
    }
    if (bucket == SWARM_PAY_BUCKET_COLLATERAL) {
        return &m_collateral;
    }
    if (bucket == SWARM_PAY_BUCKET_EARNED) {
        return &m_earned;
    }
    if (bucket == SWARM_PAY_BUCKET_FEES) {
        return &m_fees;
    }
    return nullptr;
}

const int64_t* SwarmPayBalances::Slot(const std::string& bucket) const
{
    if (bucket == SWARM_PAY_BUCKET_ESCROW) {
        return &m_escrow;
    }
    if (bucket == SWARM_PAY_BUCKET_COLLATERAL) {
        return &m_collateral;
    }
    if (bucket == SWARM_PAY_BUCKET_EARNED) {
        return &m_earned;
    }
    if (bucket == SWARM_PAY_BUCKET_FEES) {
        return &m_fees;
    }
    return nullptr;
}

bool SwarmPayBalances::Credit(const std::string& bucket, int64_t atoms, const std::string& memo_id, std::string& err)
{
    int64_t* slot = Slot(bucket);
    if (slot == nullptr) {
        err = "BUCKET";
        return false;
    }
    if (atoms < 1) {
        err = "ATOMS";
        return false;
    }
    if (memo_id.empty()) {
        err = "MEMO";
        return false;
    }
    if (m_memos.count(memo_id) != 0) {
        err = "REPLAY";
        return false;
    }
    if (!FitsInBucket(*slot, atoms)) {
        err = "ATOMS";
        return false;
    }
    *slot += atoms;
    m_memos.insert(memo_id);
    err.clear();
    return true;
}

bool SwarmPayBalances::Merge(std::string& err) const
{
    // The four balances stay separate. Nothing is moved.
    err = "NOT_MERGED";
    return false;
}

int64_t SwarmPayBalances::Balance(const std::string& bucket) const
{
    const int64_t* slot = Slot(bucket);
    if (slot == nullptr) {
        return -1;
    }
    return *slot;
}

bool SwarmPayBalances::HasMemo(const std::string& memo_id) const
{
    return m_memos.count(memo_id) != 0;
}

bool SwarmPayBalances::Fits(const std::string& bucket, int64_t atoms) const
{
    const int64_t* slot = Slot(bucket);
    if (slot == nullptr) {
        return false;
    }
    return FitsInBucket(*slot, atoms);
}

} // namespace modelnet
