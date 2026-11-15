// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_BUDGET_DT_BUDGET_H
#define BITCOIN_MODELNET_DT_BUDGET_DT_BUDGET_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty id. Nothing is stored. */
inline constexpr char DT_BUDGET_REQUEST[] = "REQUEST";

/** bytes below 1, or bytes above the remaining capacity. Nothing is stored. */
inline constexpr char DT_BUDGET_CAPACITY[] = "CAPACITY";

/** The id has no reserved lease. */
inline constexpr char DT_BUDGET_RESERVE[] = "RESERVE";

/** Release ran before Quiesce. The accounted bytes stay. */
inline constexpr char DT_BUDGET_PINNED[] = "PINNED";

/** Accounted capacity of one budget, in bytes. */
inline constexpr int64_t DT_BUDGET_CAPACITY_BYTES{100};

/**
 * Accounted byte budget for training leases.
 *
 * Capacity is 100 bytes. Reserve stores one id. An empty id is REQUEST.
 * bytes below 1, or bytes above the remaining capacity, is CAPACITY and
 * stores nothing. A second reserve of the same id is NIFDT_REPLAY and keeps
 * the first byte count. A successful reserve increases reserved() and
 * physical() by bytes.
 *
 * Schedule succeeds only for a reserved id. An unreserved id is RESERVE and
 * does not change physical().
 *
 * Cancel marks that logical lease canceled. physical() stays at the reserved
 * size. canceled() becomes true.
 *
 * Quiesce is required before Release. Release before Quiesce is PINNED and
 * leaves physical() unchanged. After Quiesce, Release decreases physical()
 * and reserved() by that id's bytes.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is "0".
 */
class DtBudget {
public:
    bool Reserve(const std::string& id, int64_t bytes, std::string& err);
    bool Schedule(const std::string& id, std::string& err);
    bool Cancel(const std::string& id, std::string& err);
    bool Quiesce(const std::string& id, std::string& err);
    bool Release(const std::string& id, std::string& err);

    int64_t reserved() const { return m_reserved; }
    int64_t physical() const { return m_physical; }
    bool canceled() const { return m_canceled_leases > 0; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Lease {
        int64_t bytes{0};
        bool scheduled{false};
        bool canceled{false};
        bool quiesced{false};
    };

    /** Empty id is REQUEST. Returns true when the caller must stop. */
    bool RejectEmpty(const std::string& id, std::string& err) const;

    std::map<std::string, Lease> m_leases;
    int64_t m_reserved{0};
    int64_t m_physical{0};
    int64_t m_canceled_leases{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_BUDGET_DT_BUDGET_H
