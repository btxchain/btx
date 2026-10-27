// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP29_GRP29_H
#define BITCOIN_MODELNET_GRP29_GRP29_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** amount below 1. Nothing is stored. */
inline constexpr char GRP29_BYTES[] = "BYTES";

/** Advance before any stored amount. generation() stays 0. */
inline constexpr char GRP29_ORDER[] = "ORDER";

/** The journal refused the next generation. generation() stays unchanged. */
inline constexpr char GRP29_JOURNAL[] = "JOURNAL";

/**
 * Node behaviors 11 and 12. One in-memory monetary record and one generation.
 * A worker failure does not change the stored amount. A later generation is
 * refused until the journal accepts. This class opens no file, socket, or
 * process.
 *
 * Store(amount) with amount below 1 is BYTES and leaves the stored amount
 * unchanged. A successful Store sets the stored amount to amount.
 *
 * FailWorker sets worker_failed() true. monetary_ok() stays true. The stored
 * amount and generation() stay unchanged.
 *
 * Advance before a stored amount is ORDER. journal_ok false is JOURNAL and
 * leaves generation() at 0 when no generation has been accepted. journal_ok
 * true sets generation() to 1 once. A second successful Advance is
 * NIFDT_REPLAY and keeps generation() at 1.
 *
 * Spend returns false with NIFDT_AUTOMATIC_SPEND. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. Release returns NIFDT_UNQUALIFIED.
 *
 * qualified(), release_qualified(), hardware_qualified(), launched(), gpu(),
 * and broadcast() stay false. hosts() and physical_hosts() stay 1.
 * bytes_moved() stays 0. automatic_spend() is "0".
 */
class Grp29 {
public:
    bool Store(int64_t amount, std::string& err);
    bool FailWorker(std::string& err);
    bool Advance(bool journal_ok, std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);
    bool Release(std::string& err);

    int64_t stored() const { return m_n; }
    bool worker_failed() const { return m_worker_failed; }
    bool monetary_ok() const { return true; }
    int64_t generation() const { return m_generation; }

    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    int64_t m_n{static_cast<int64_t>(0)};
    int64_t m_generation{static_cast<int64_t>(0)};
    bool m_have{false};
    bool m_worker_failed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GRP29_GRP29_H
