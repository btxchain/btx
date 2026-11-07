// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_COST_NIF_COST_H
#define BITCOIN_MODELNET_NIF_COST_NIF_COST_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty peer, or Accept named a peer with no stored estimate. */
inline constexpr char NIF_COST_PEER[] = "PEER";

/** uncertainty_us below 0. Nothing is stored. */
inline constexpr char NIF_COST_BOUND[] = "BOUND";

/** qualified_device is false. Nothing is stored. */
inline constexpr char NIF_COST_HARDWARE[] = "HARDWARE";

/** mean_us + uncertainty_us is above budget_us. The peer is not placed. */
inline constexpr char NIF_COST_OVER[] = "OVER";

/** Place ran before a successful Accept. */
inline constexpr char NIF_COST_UNMEASURED[] = "UNMEASURED";

/**
 * Stored peer cost. One estimate is a mean and an uncertainty, in
 * microseconds.
 *
 * Estimate stores that pair. An empty peer is PEER. A second estimate of
 * the same peer is NIFDT_REPLAY and keeps the first pair. uncertainty_us
 * below 0 is BOUND and stores nothing. qualified_device false is HARDWARE
 * and stores nothing.
 *
 * Accept returns true only when mean_us + uncertainty_us is less than or
 * equal to budget_us. A sum above the budget, or a sum that does not fit
 * in int64, is OVER, and Accept does not mark the peer placed. A missing
 * peer is PEER.
 *
 * Place requires a successful Accept first. Otherwise UNMEASURED.
 *
 * hardware_qualified() stays false. One accepted estimate is not a
 * hardware qualification. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is "0". physical_hosts() is 1.
 */
class NifCost {
public:
    bool Estimate(const std::string& peer, int64_t mean_us, int64_t uncertainty_us, bool qualified_device, std::string& err);
    bool Accept(const std::string& peer, int64_t budget_us, std::string& err);
    bool Place(const std::string& peer, std::string& err);

    int64_t mean_us(const std::string& peer) const;
    int64_t uncertainty_us(const std::string& peer) const;
    bool accepted(const std::string& peer) const;
    bool placed(const std::string& peer) const;

    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }

private:
    struct Row {
        int64_t mean_us{0};
        int64_t uncertainty_us{0};
        bool accepted{false};
        bool placed{false};
    };

    const Row* Find(const std::string& peer) const;
    Row* Find(const std::string& peer);

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_COST_NIF_COST_H
