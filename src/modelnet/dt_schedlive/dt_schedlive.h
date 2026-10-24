// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_SCHEDLIVE_DT_SCHEDLIVE_H
#define BITCOIN_MODELNET_DT_SCHEDLIVE_DT_SCHEDLIVE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** bytes below 1. Nothing is stored. */
inline constexpr char DT_SCHEDLIVE_BYTES[] = "BYTES";

/** bytes above capacity, the sum would pass capacity, or the sum would overflow int64. Nothing is stored. */
inline constexpr char DT_SCHEDLIVE_CAPACITY[] = "CAPACITY";

/** Schedule before a successful Reserve, or Quiesce before Cancel. */
inline constexpr char DT_SCHEDLIVE_ORDER[] = "ORDER";

/** Release ran before Quiesce. physical_bytes() stays unchanged. */
inline constexpr char DT_SCHEDLIVE_PINNED[] = "PINNED";

/** Accounted capacity of this scheduler, in bytes. */
inline constexpr int64_t DT_SCHEDLIVE_CAPACITY_BYTES{100};

/**
 * DT-NAT-004 and NIF-NAT-005. One accounted host reservation.
 * Capacity is 100 bytes. This class opens no socket and starts no process.
 *
 * Reserve adds bytes to physical_bytes(). bytes below 1 is BYTES and stores
 * nothing. bytes above 100, a sum that would exceed 100, or a sum that would
 * overflow int64, is CAPACITY and stores nothing. A successful Reserve clears
 * quiesced so the new bytes stay pinned until Quiesce.
 *
 * Schedule before any successful Reserve is ORDER and does not set
 * scheduled(). After a reserve, Schedule returns true once. A second
 * Schedule is NIFDT_REPLAY.
 *
 * Cancel sets canceled and does not change physical_bytes(). Quiesce before
 * Cancel is ORDER. Release before Quiesce is PINNED. After Cancel and
 * Quiesce, Release returns physical_bytes() to 0.
 *
 * FailWorker sets worker_failed() true. monetary_ok() stays true.
 * validation_affected() stays false. physical_bytes() stays unchanged.
 * Spend returns false with NIFDT_AUTOMATIC_SPEND.
 *
 * launched(), gpu(), broadcast(), and qualified() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * hosts() stays 1.
 */
class DtSchedLive {
public:
    bool Reserve(int64_t bytes, std::string& err);
    bool Schedule(std::string& err);
    bool Cancel(std::string& err);
    bool Quiesce(std::string& err);
    bool Release(std::string& err);
    bool FailWorker(std::string& err);
    bool Spend(std::string& err);

    int64_t physical_bytes() const { return m_physical; }
    bool scheduled() const { return m_scheduled; }
    bool canceled() const { return m_canceled; }
    bool worker_failed() const { return m_worker_failed; }
    bool monetary_ok() const { return true; }
    bool validation_affected() const { return false; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t hosts() const { return static_cast<int64_t>(1); }

private:
    int64_t m_physical{0};
    bool m_had_reserve{false};
    bool m_scheduled{false};
    bool m_canceled{false};
    bool m_quiesced{false};
    bool m_worker_failed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_SCHEDLIVE_DT_SCHEDLIVE_H
