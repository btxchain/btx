// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_OPS_DRILL_OPS_DRILL_H
#define BITCOIN_MODELNET_OPS_DRILL_OPS_DRILL_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Empty drill name or empty fixture. Nothing is stored. */
inline constexpr char OPS_DRILL_FIELD[] = "FIELD";

/** The name is not one of the six drills. Nothing is stored. */
inline constexpr char OPS_DRILL_DRILL[] = "DRILL";

/** Run fixture was not benign. Nothing is stored. */
inline constexpr char OPS_DRILL_FIXTURE[] = "FIXTURE";

/** Contain fixture was not benign. Nothing is stored. */
inline constexpr char OPS_DRILL_BLAST[] = "BLAST";

/**
 * Fixture-local drill record. The names are retainer, triage, contain,
 * mitigate, patch, and federate. This class opens no file, socket, or process.
 *
 * Run: an empty name or an empty fixture is FIELD. An unknown name is DRILL.
 * A fixture other than "benign" is FIXTURE. Each of those refusals stores
 * nothing. Success stores that drill name. A second success of the same name
 * keeps the one record.
 *
 * Contain: the fixture must be "benign". Any other fixture is BLAST and stores
 * nothing. A benign Contain stores the drill name "contain".
 *
 * effect_sent() and retaliation() stay false.
 * Release returns NIFDT_UNQUALIFIED. Spend returns NIFDT_AUTOMATIC_SPEND.
 * Vendor and Gpu return NIFDT_ENGINE_ABSENT.
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * launched(), gpu(), and broadcast() stay false.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * automatic_spend() is "0".
 */
class OpsDrill {
public:
    bool Run(const std::string& name, const std::string& fixture, std::string& err);
    bool Contain(const std::string& fixture, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool stored(const std::string& name) const;
    int64_t count() const;

    bool effect_sent() const { return false; }
    bool retaliation() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    void Remember(const std::string& name);

    std::vector<std::string> m_stored;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_OPS_DRILL_OPS_DRILL_H
