// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_P2P03_P2P03_H
#define BITCOIN_MODELNET_P2P03_P2P03_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * P2p03 counts a local family. It opens no socket and holds no scheduler.
 * JoinFamily applies the first matching rule and leaves joined() unchanged
 * on every refusal.
 * nodes below 1 returns false and sets err to FIELD.
 * scheduler true returns false and sets err to SCHEDULER. P2P-SCN-F
 * refuses a central scheduler. joined() stays 0 when nothing has joined.
 * gpus at or above 2 returns false and sets err to NIFDT_UNQUALIFIED.
 * This process cannot claim two GPUs. P2P-SCN-I stays unqualified.
 * nodes at or above 3, with scheduler false and gpus below 2, returns
 * true, clears err, and sets joined() to nodes. That count is local.
 * It is not three physical hosts on a public family. P2P-SCN-D.
 * nodes below 3, with scheduler false and gpus below 2, returns false
 * and sets err to NIFDT_UNQUALIFIED.
 * physical_hosts() returns static_cast<int64_t>(1). gpu_passed(),
 * windows_passed(), release_qualified(), hardware_qualified(), and
 * passed() stay false. automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 */
class P2p03 {
public:
    bool JoinFamily(int nodes, bool scheduler, int gpus, std::string& err);
    int joined() const { return m_joined; }

    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool passed() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    int m_joined{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_P2P03_P2P03_H
