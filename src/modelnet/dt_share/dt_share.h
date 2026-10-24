// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_SHARE_DT_SHARE_H
#define BITCOIN_MODELNET_DT_SHARE_DT_SHARE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** Empty owner, or an owner that was never stored. Nothing is stored. */
inline constexpr char DT_SHARE_OWNER[] = "OWNER";

/** Empty consumer, or a consumer that is not bound to that owner. */
inline constexpr char DT_SHARE_CONSUMER[] = "CONSUMER";

/** Owner and consumer are the same name. Nothing is stored. */
inline constexpr char DT_SHARE_SELF[] = "SELF";

/** Apply or CacheGrad found no new gradient. The weight stays. */
inline constexpr char DT_SHARE_UNCHANGED[] = "UNCHANGED";

/** The gradient cache was detached. The weight stays. */
inline constexpr char DT_SHARE_DETACHED[] = "DETACHED";

/**
 * Shared-weight gradient step with one optimizer owner.
 * qualified_v41() stays false.
 *
 * Bind stores one consumer under an owner. An empty owner is OWNER.
 * An empty consumer is CONSUMER. An owner equal to the consumer is SELF.
 * Those refusals store nothing. A second bind of the same consumer is
 * NIFDT_REPLAY and keeps the first owner. Several consumers of one owner
 * still leave optimizer_owners(owner) at 1.
 *
 * Grad adds an int64 value once into that owner's pending gradient.
 * The consumer must already be bound to that owner. An unbound consumer,
 * or a consumer bound to a different owner, is CONSUMER and adds nothing.
 * The same consumer again is NIFDT_REPLAY and does not add the value again.
 * A sum that does not fit in int64 is UNCHANGED and does not record the call.
 *
 * Apply adds the pending gradient once into weight(owner). The pending
 * mark is then clear, so a second Apply with no new gradient is UNCHANGED
 * and leaves the weight. A missing or empty owner is OWNER and stores nothing.
 *
 * The same accumulated gradient is held in a cache while the cache is
 * attached. Detach marks that cache detached and does not change the weight.
 * CacheGrad folds an attached cache into the weight once. A detached cache
 * returns false with DETACHED and does not change the weight. Apply and
 * CacheGrad spend the same pending sum, so a gradient is folded once.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and does not change the weight.
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0. No process is spawned and
 * no socket is opened.
 */
class DtShare {
public:
    bool Bind(const std::string& owner, const std::string& consumer, std::string& err);
    bool Grad(const std::string& owner, const std::string& consumer, std::int64_t value, std::string& err);
    bool Apply(const std::string& owner, std::string& err);
    bool Detach(const std::string& owner, std::string& err);
    bool CacheGrad(const std::string& owner, std::string& err);
    bool Gpu(std::string& err);

    /** 1 after a successful bind of this owner, otherwise 0. */
    int optimizer_owners(const std::string& owner) const;
    int consumer_count(const std::string& owner) const;
    std::int64_t weight(const std::string& owner) const;
    /** Accumulated gradient that Apply has not folded yet. */
    std::int64_t pending(const std::string& owner) const;
    bool detached(const std::string& owner) const;
    /** First owner stored for this consumer, or empty when unbound. */
    std::string owner_of(const std::string& consumer) const;

    bool qualified_v41() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::int64_t bytes_moved() const { return static_cast<std::int64_t>(0); }

private:
    struct Consumer {
        std::string owner;
        bool used{false};
    };

    struct Owner {
        std::int64_t weight{0};
        std::int64_t pending{0};
        bool pending_open{false};
        std::int64_t cache{0};
        bool cache_open{false};
        bool detached{false};
        int consumers{0};
    };

    Owner* FindOwner(const std::string& owner);
    const Owner* FindOwner(const std::string& owner) const;
    bool Fold(Owner& row, std::int64_t amount, std::string& err);

    std::map<std::string, Consumer> m_consumers;
    std::map<std::string, Owner> m_owners;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_SHARE_DT_SHARE_H
