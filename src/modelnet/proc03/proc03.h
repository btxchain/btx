// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC03_PROC03_H
#define BITCOIN_MODELNET_PROC03_PROC03_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Proc03. DS-REC-004. Payment recovery stays available while the model
 * runtime is down, and recovery does not stop a device.
 *
 * Recover applies the first matching rule. A negative balance returns
 * false with BOUND and stores nothing. A zero balance returns false with
 * EMPTY and stores nothing. runtime_up returns false with RUNTIME and
 * stores nothing; this path is the down-runtime recovery, not the live
 * path. A positive balance while the runtime is down stores that balance,
 * records that the runtime was down, clears err, and returns true. A
 * second successful Recover returns false with REPLAY and the first
 * balance stays.
 *
 * device_stopped() stays false. No method stops a device.
 * recovered() stays 0 until a success.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false.
 * automatic_spend() returns NIFDT_AUTOMATIC_SPEND. Recover does not spend
 * and does not change that string.
 * This class opens no socket, starts no process, and calls no RPC or wallet.
 */
class Proc03 {
public:
    bool Recover(int64_t balance_atoms, bool runtime_up, std::string& err);

    int64_t recovered() const { return m_recovered; }
    bool device_stopped() const { return false; } // always false
    bool runtime_was_down() const { return m_runtime_was_down; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    int64_t m_recovered{static_cast<int64_t>(0)};
    bool m_runtime_was_down{false};
    bool m_done{false};
};

} // namespace modelnet

#endif
