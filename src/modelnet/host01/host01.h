// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_HOST01_HOST01_H
#define BITCOIN_MODELNET_HOST01_HOST01_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Host01 binds two roles for a later process. It opens no socket.
 * role is exactly "cpu" or "gpu". Anything else is ROLE and stores nothing.
 * An empty endpoint is FIELD. An endpoint containing "://" is FIELD.
 * No URL is stored. A loopback endpoint is LOOPBACK. One machine is not
 * two hosts. A second Bind of the same role is NIFDT_REPLAY and the first
 * endpoint stays. Ready is true only when both roles are bound. Otherwise
 * it is NIFDT_UNQUALIFIED. physical_hosts() is 2 only when both are bound,
 * otherwise 1. passed(), release_qualified(), gpu_passed(),
 * windows_passed(), and hardware_qualified() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 */
class Host01 {
public:
    bool Bind(const std::string& role, const std::string& endpoint, std::string& err);
    bool bound(const std::string& role) const;
    std::string endpoint(const std::string& role) const;
    int64_t physical_hosts() const;
    bool Ready(std::string& err) const;

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool m_cpu{false};
    bool m_gpu{false};
    std::string m_cpu_endpoint;
    std::string m_gpu_endpoint;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_HOST01_HOST01_H
