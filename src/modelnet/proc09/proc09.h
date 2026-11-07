// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC09_PROC09_H
#define BITCOIN_MODELNET_PROC09_PROC09_H

#include <modelnet/nifdt_contract/contract.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Proc09. Deliver one fingerprint, one log digest, and the remaining blockers.
 * The first matching rule wins. An empty fingerprint, an empty log digest, an
 * empty blocker list, or any empty blocker string is refused with FIELD and
 * stores nothing. A later complete Deliver is refused with REPLAY and the
 * first record stays. ClaimTaskCount is refused with CLAIM and stores nothing,
 * including after a successful Deliver. It does not change blocker_count().
 * automatic_spend() returns NIFDT_AUTOMATIC_SPEND.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false.
 * The caller passes the fingerprint in. This class opens no file, socket,
 * process, or wallet.
 */
class Proc09 {
public:
    bool Deliver(const std::string& fingerprint, const std::string& log_digest, const std::vector<std::string>& blockers, std::string& err);
    bool ClaimTaskCount(int count, std::string& err);

    std::string fingerprint() const { return m_fingerprint; }
    std::string log_digest() const { return m_log_digest; }
    int blocker_count() const { return static_cast<int>(m_blockers.size()); }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_done{false};
    std::string m_fingerprint;
    std::string m_log_digest;
    std::vector<std::string> m_blockers;
};

} // namespace modelnet

#endif
