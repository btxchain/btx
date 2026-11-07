// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYSTAGE_BALANCES_H
#define BTX_MODELNET_SWARM_PAYSTAGE_BALANCES_H

#include <cstdint>
#include <set>
#include <string>

namespace modelnet {

inline constexpr char SWARM_PAY_BUCKET_ESCROW[] = "escrow";
inline constexpr char SWARM_PAY_BUCKET_COLLATERAL[] = "collateral";
inline constexpr char SWARM_PAY_BUCKET_EARNED[] = "earned";
inline constexpr char SWARM_PAY_BUCKET_FEES[] = "fees";

/**
 * Four balances: escrow, collateral, earned, and fees.
 * Credit adds atoms to one bucket. The same memo is never applied twice,
 * so the same atoms are never added to both escrow and collateral.
 * Merge does not move atoms.
 */
class SwarmPayBalances {
public:
    /**
     * Unknown bucket is BUCKET and adds nothing.
     * atoms below 1 is ATOMS and adds nothing.
     * An empty memo id is MEMO and adds nothing.
     * A memo id already credited is REPLAY and adds nothing.
     * A sum that would exceed int64 max is ATOMS and leaves the bucket.
     * Otherwise the atoms are added to that one bucket.
     */
    bool Credit(const std::string& bucket, int64_t atoms, const std::string& memo_id, std::string& err);

    /** Always NOT_MERGED. No bucket changes. */
    bool Merge(std::string& err) const;

    /**
     * The bucket balance, or -1 when the bucket name is not one of the four.
     */
    int64_t Balance(const std::string& bucket) const;

    /** True when this memo id has already been credited. */
    bool HasMemo(const std::string& memo_id) const;

    /**
     * True when atoms can be added to bucket without passing int64 max.
     * atoms below 1 and an unknown bucket are false.
     */
    bool Fits(const std::string& bucket, int64_t atoms) const;

private:
    int64_t* Slot(const std::string& bucket);
    const int64_t* Slot(const std::string& bucket) const;

    int64_t m_escrow{0};
    int64_t m_collateral{0};
    int64_t m_earned{0};
    int64_t m_fees{0};
    std::set<std::string> m_memos;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYSTAGE_BALANCES_H
