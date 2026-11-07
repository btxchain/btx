// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PAY_REGTEST_PAY_REGTEST_H
#define BITCOIN_MODELNET_PAY_REGTEST_PAY_REGTEST_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_economyclass/swarm_economyclass.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** The same pool was named twice. This engine stores nothing for that pair. */
inline constexpr char PAY_REGTEST_ECONOMY[] = "ECONOMY";

/**
 * In-process regtest payment gate.
 *
 * Open forwards to SwarmEconomyClass::Open. The same pool twice is
 * PAY_REGTEST_ECONOMY and returns false.
 *
 * Pay forwards to SwarmEconomyClass::PayWork and keeps HELD.
 *
 * Settle returns false with NIFDT_UNQUALIFIED. atoms_moved() stays 0.
 * broadcast() stays false. network_opened() on this class stays false
 * even when the economy object can be read.
 *
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 *
 * qualified(), release_qualified(), hardware_qualified(), launched(),
 * and gpu() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0. automatic_spend() stays "0".
 * This class does not broadcast and does not move atoms.
 */
class PayRegtest {
public:
    bool Open(const std::string& channel, const std::string& pool_a, const std::string& pool_b, std::string& err);
    bool Pay(const std::string& pool, const std::string& work, const std::string& worker, std::string& err);
    bool Settle(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool network_opened() const;
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t atoms_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmEconomyClass m_economy;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_PAY_REGTEST_PAY_REGTEST_H
