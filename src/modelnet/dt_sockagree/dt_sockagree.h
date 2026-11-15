// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_SOCKAGREE_DT_SOCKAGREE_H
#define BITCOIN_MODELNET_DT_SOCKAGREE_DT_SOCKAGREE_H

#include <modelnet/nifdt_contract/contract.h>
#include <sys/socket.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Local socket-pair comparison. One process is not a hardware measurement. */
inline constexpr char DT_SOCKAGREE_CLASSIFICATION[] = "SIMULATION_NOT_HARDWARE_MEASUREMENT";

/** socketpair, write, or read failed. agreed() is left unchanged. */
inline constexpr char DT_SOCKAGREE_IO[] = "IO";

/** The two int64 values differ. agreed() stays false. */
inline constexpr char DT_SOCKAGREE_DISAGREE[] = "DISAGREE";

/**
 * One process compares two int64 values across one AF_UNIX SOCK_STREAM
 * socket pair (DT-SIM-006).
 *
 * Compare writes both values in little-endian order from one end and reads
 * those same bytes from the other end. The bytes read are the bytes written.
 * Both descriptors are closed before Compare returns, including when the
 * transfer fails.
 *
 * socketpair failure returns false with IO and leaves agreed() and
 * bytes_moved() unchanged. A read that is not 16 bytes returns false with
 * IO and does not set agreed(). When 16 bytes cross and the values differ,
 * Compare returns false with DISAGREE, agreed() stays false, and
 * bytes_moved() is 16. When the values are equal, Compare returns true,
 * agreed() becomes true, and bytes_moved() is 16. A second Compare after
 * that success is NIFDT_REPLAY and does not add bytes again.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and does not change agreed().
 * hosts() and physical_hosts() stay 1. ranks() stays 2.
 * classification() is DT_SOCKAGREE_CLASSIFICATION.
 * hardware_qualified(), launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 */
class DtSockAgree {
public:
    bool Compare(int64_t left, int64_t right, std::string& err);
    bool Gpu(std::string& err);

    bool agreed() const { return m_agreed; }
    const char* classification() const { return DT_SOCKAGREE_CLASSIFICATION; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t ranks() const { return static_cast<int64_t>(2); }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t bytes_moved() const { return m_bytes; }

private:
    bool m_agreed{false};
    int64_t m_bytes{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_SOCKAGREE_DT_SOCKAGREE_H
