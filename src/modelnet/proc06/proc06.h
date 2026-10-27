// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROC06_PROC06_H
#define BITCOIN_MODELNET_PROC06_PROC06_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Proc06 implements the in-memory half of P2P-SCN-H. Two workers exchange
 * one KV page when fingerprints match. Exchange copies those bytes into
 * received().
 * Exchange applies the first matching rule. An empty page_id returns KV
 * and copies nothing. An empty page returns EMPTY and copies nothing.
 * Fingerprints that differ, or either fingerprint empty, return
 * INCOMPATIBLE and copy nothing. bytes_copied() stays 0 on that path.
 * Matching non-empty fingerprints copy the page into received(), set
 * bytes_copied() to the page size, clear err, and return true. A second
 * successful Exchange of the same page_id returns REPLAY and the first
 * page stays.
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. automatic_spend() returns
 * NIFDT_AUTOMATIC_SPEND. hosts() returns 1. This is not a two-host result.
 * This class opens no socket, starts no process, touches no file, and
 * opens no wallet.
 */
class Proc06 {
public:
    bool Exchange(const std::string& page_id, const std::string& fingerprint_a, const std::vector<unsigned char>& page, const std::string& fingerprint_b, std::string& err);

    int64_t bytes_copied() const { return m_bytes; }
    std::vector<unsigned char> received() const { return m_received; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::vector<unsigned char> m_received;
    std::vector<std::string> m_page_ids;
    int64_t m_bytes{0};
};

} // namespace modelnet

#endif
