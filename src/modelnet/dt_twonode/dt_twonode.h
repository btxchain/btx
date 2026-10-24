// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_TWONODE_DT_TWONODE_H
#define BITCOIN_MODELNET_DT_TWONODE_DT_TWONODE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Two ranks on one machine.
 * Exchange moves both payloads across a socket pair.
 * physical_hosts() is 1. This binary has no CUDA device, so GpuRank stays absent.
 * A real GPU pair runs as two processes on the GPU host, not inside this object.
 */
class DtTwoNode {
public:
    bool Exchange(const std::vector<unsigned char>& from_a, const std::vector<unsigned char>& from_b, std::string& err);
    bool GpuRank(std::string& err);

    const std::vector<unsigned char>& rank_a_received() const { return m_a; }
    const std::vector<unsigned char>& rank_b_received() const { return m_b; }
    int physical_hosts() const { return 1; }
    int ranks() const { return 2; }
    int64_t bytes_moved() const { return m_bytes; }
    bool gpu() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::vector<unsigned char> m_a;
    std::vector<unsigned char> m_b;
    int64_t m_bytes{0};
};

} // namespace modelnet

#endif
