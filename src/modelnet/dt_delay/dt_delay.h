// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_DELAY_DT_DELAY_H
#define BITCOIN_MODELNET_DT_DELAY_DT_DELAY_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Empty base id. Nothing is stored. */
inline constexpr char DT_DELAY_BASE[] = "BASE";

/** A different id. The stored base and head() stay. */
inline constexpr char DT_DELAY_CHANGE[] = "CHANGE";

/** Lag above 2. The delta is not added to pending(). */
inline constexpr char DT_DELAY_STALE[] = "STALE";

/** Same base again while pending() is 0. head() stays. */
inline constexpr char DT_DELAY_UNCHANGED[] = "UNCHANGED";

/**
 * The accepted sum does not fit in int64.
 * pending() and head() stay.
 */
inline constexpr char DT_DELAY_OVERFLOW[] = "OVERFLOW";

/**
 * One stored base and a local pending sum.
 *
 * Base stores one id. An empty id is BASE and stores nothing. A second
 * base of a different id is CHANGE and does not replace the first. The
 * same id again is NIFDT_REPLAY and the first id stays.
 *
 * Delay adds delta to pending() when lag is 2 or below. Lag above 2 is
 * STALE and does not add that delta. pending() is the sum of accepted
 * deltas. A sum that does not fit in int64 is OVERFLOW and leaves
 * pending() unchanged.
 *
 * Resume with an id different from the stored base is CHANGE and does
 * not apply pending(). The same id applies pending() once onto head()
 * and then pending() becomes 0. A second Resume of the same id with
 * pending 0 is UNCHANGED and leaves head(). A later Delay may add to
 * pending() again. The next Resume of the same id applies that new sum
 * once.
 *
 * Wan returns false with NIFDT_NO_ROUTE. bytes_moved() stays 0.
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * "0". physical_hosts() is 1. diloco_complete() stays false. No socket
 * is opened.
 */
class DtDelay {
public:
    bool Base(const std::string& id, std::string& err);
    bool Delay(int64_t delta, int64_t lag, std::string& err);
    bool Resume(const std::string& id, std::string& err);
    bool Wan(std::string& err);

    const std::string& base() const { return m_base; }
    bool has_base() const { return m_have_base; }
    int64_t head() const { return m_head; }
    int64_t pending() const { return m_pending; }
    int64_t bytes_moved() const { return m_bytes_moved; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool diloco_complete() const { return false; }
    int physical_hosts() const { return 1; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    std::string m_base;
    bool m_have_base{false};
    bool m_resumed{false};
    int64_t m_head{0};
    int64_t m_pending{0};
    int64_t m_bytes_moved{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_DELAY_DT_DELAY_H
