// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GUARD_PERMIT_GUARD_PERMIT_H
#define BITCOIN_MODELNET_GUARD_PERMIT_GUARD_PERMIT_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/guard_machine.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process permit gate. Prepare, Execute, Pause, and Resume forward to
 * GuardTable. launched() and process_present() stay false. This class has
 * no btx-guardd binary and starts no process.
 *
 * A second Execute of the same secret returns the table replay error
 * BTX035_REPLAY. Pause blocks Execute with BTX035_PAUSED until Resume.
 *
 * Release returns NIFDT_UNQUALIFIED. qualified(), release_qualified(), and
 * hardware_qualified() stay false. hosts() and physical_hosts() are 1.
 * bytes_moved() is 0. Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu
 * return NIFDT_ENGINE_ABSENT. gpu() and broadcast() stay false.
 */
class GuardPermitEngine {
public:
    bool Prepare(const std::string& effect, const std::string& fingerprint, uint64_t generation, int64_t now_ms,
                 GuardPermit& out, std::string& err);
    bool Execute(const std::string& secret, int64_t now_ms, std::string& err);
    void Pause();
    void Resume();

    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool launched() const { return false; }
    bool process_present() const { return false; }
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
    GuardTable m_table;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GUARD_PERMIT_GUARD_PERMIT_H
