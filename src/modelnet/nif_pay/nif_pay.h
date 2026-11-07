// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_PAY_NIF_PAY_H
#define BITCOIN_MODELNET_NIF_PAY_NIF_PAY_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_economyclass/swarm_economyclass.h>
#include <modelnet/swarm_settlebuild/swarm_settlebuild.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Atoms below 1. Nothing is stored. */
inline constexpr char NIF_PAY_ATOMS[] = "ATOMS";

/** Accept named an id that was never reserved. */
inline constexpr char NIF_PAY_ATTEMPT[] = "ATTEMPT";

/** The receipt is not independent. Atoms stay out of earned. */
inline constexpr char NIF_PAY_NOT_ACCEPTED[] = "NOT_ACCEPTED";

/**
 * In-process inference payment.
 *
 * Open calls SwarmEconomyClass::Open with the same pool on both sides.
 * An empty channel is ECONOMY.
 *
 * Reserve stores one liability. reserved_atoms() is the sum of first
 * reserves only. A duplicate id is REPLAY and does not add atoms again.
 *
 * Accept of an unknown id is ATTEMPT. independent false is NOT_ACCEPTED
 * and does not move atoms into earned. independent true moves that
 * reservation into earned_atoms() once. reserved_atoms() stays the sum
 * of first reserves. A second accept of the same id is REPLAY and does
 * not earn again.
 *
 * PayWork calls SwarmEconomyClass::PayWork and stays HELD. A held work
 * payment is not earned_atoms().
 *
 * Settle calls SwarmSettleBuild::Settle and returns false with
 * UNQUALIFIED. settlement_qualified() stays false. broadcast(),
 * launched(), and gpu() stay false. automatic_spend() is "0".
 * This class holds no spend key and opens no socket.
 */
class NifPay {
public:
    bool Open(const std::string& channel, const std::string& pool, std::string& err);
    bool Reserve(const std::string& id, int64_t atoms, std::string& err);
    bool Accept(const std::string& id, bool independent, std::string& err);
    bool PayWork(const std::string& pool, const std::string& work, const std::string& worker, std::string& err);
    bool Settle(std::string& err);

    int64_t reserved_atoms() const { return m_reserved; }
    int64_t earned_atoms() const { return m_earned; }
    bool settlement_qualified() const { return m_settle.qualified(); }
    bool broadcast() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Reservation {
        int64_t atoms{0};
        bool decided{false};
    };

    SwarmEconomyClass m_economy;
    SwarmSettleBuild m_settle;
    std::map<std::string, Reservation> m_items;
    int64_t m_reserved{0};
    int64_t m_earned{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_PAY_NIF_PAY_H
