// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_RL_DT_RL_H
#define BITCOIN_MODELNET_DT_RL_DT_RL_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/** Clipped group-relative objective. Objective id BTX-GRPO-CLIPPED/1. */
inline constexpr char DT_RL_OBJECTIVE[] = "BTX-GRPO-CLIPPED/1";

/** The group name was empty, or the group has fewer than two completed samples. */
inline constexpr char DT_RL_GROUP[] = "GROUP";

/** The sample id was empty. Nothing is stored. */
inline constexpr char DT_RL_SAMPLE[] = "SAMPLE";

/** The caller scored its own reward. Nothing is stored. */
inline constexpr char DT_RL_SELF[] = "SELF";

/** This sample id is already stored. The first record stays. */
inline constexpr char DT_RL_DEDUP[] = "DEDUP";

/** The sample version is below current_version() - 2. Nothing is stored. */
inline constexpr char DT_RL_STALE[] = "STALE";

/** The sample version is ahead of current_version(). Nothing is stored. */
inline constexpr char DT_RL_FUTURE[] = "FUTURE";

/**
 * In-memory clipped group-relative objective, BTX-GRPO-CLIPPED/1.
 *
 * Add stores one sample under a group. An empty group is GROUP. A
 * self-scored reward is SELF and is not stored. A repeated sample id is
 * DEDUP and the first reward stays. A version below current_version() - 2
 * is STALE and is not stored. A version above current_version() is FUTURE
 * and is not stored. complete false is stored and marked incomplete.
 *
 * current_version() starts at 1. SetVersion moves it forward only.
 *
 * Advantage(group) takes the mean of completed rewards in that group and
 * sets each completed sample's advantage to reward minus that mean.
 * Incomplete samples are excluded. Fewer than two completed samples
 * returns false with GROUP and does not invent or replace a mean.
 * The advantage is the rational (reward * n - sum) / n, reduced.
 *
 * Clip(ratio, advantage) returns
 * min(ratio * advantage, clamp(ratio, 1 - 0.2, 1 + 0.2) * advantage).
 * Ratio and advantage are scaled to the nearest 1/1000 and the products
 * are compared in integer arithmetic. The returned double is that chosen
 * product divided by 1e6. Compare it within 1e-9. A non-finite input
 * does not return a numeric stand-in.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * "0". No socket is opened and no process is started.
 */
class DtRl {
public:
    bool Add(const std::string& group,
             const std::string& sample,
             int64_t reward,
             int64_t logp,
             uint64_t version,
             bool complete,
             bool self_scored,
             std::string& err);

    /** Move current_version() forward. A lower version leaves it unchanged. */
    bool SetVersion(uint64_t version);
    uint64_t current_version() const { return m_version; }

    /**
     * Mean of completed rewards, then reward minus that mean.
     * On failure the stored mean and advantages stay as they were.
     */
    bool Advantage(const std::string& group, std::string& err);

    /**
     * Reduced advantage numerator and denominator for a completed sample
     * after a successful Advantage() call. Denominator is positive.
     * On failure, num and den are left unchanged.
     */
    bool advantage(const std::string& sample, int64_t& num, int64_t& den) const;

    /**
     * Clipped objective for one completed sample's advantage.
     * Scale is 1000. Tolerance for the double result is 1e-9.
     */
    double Clip(double ratio, double advantage, std::string& err) const;

    bool has_sample(const std::string& sample) const;
    bool has_mean(const std::string& group) const;
    /** Stored reward, or 0 when the sample was not stored. */
    int64_t reward_of(const std::string& sample) const;
    /** Stored logp, or 0 when the sample was not stored. Not part of the mean. */
    int64_t logp_of(const std::string& sample) const;
    /** Stored sample version, or 0 when the sample was not stored. */
    uint64_t version_of(const std::string& sample) const;
    /** Reduced mean numerator, or 0 when this group has no mean. */
    int64_t mean_num(const std::string& group) const;
    /** Reduced mean denominator, or 1 when this group has no mean. */
    int64_t mean_den(const std::string& group) const;
    int64_t stored_count() const;

    const char* objective() const { return DT_RL_OBJECTIVE; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Sample {
        int64_t reward{0};
        int64_t logp{0};
        uint64_t version{0};
        bool complete{false};
        bool advantage_set{false};
        int64_t adv_num{0};
        int64_t adv_den{1};
    };
    struct Group {
        std::vector<std::string> order;
        bool has_mean{false};
        int64_t mean_num{0};
        int64_t mean_den{1};
    };

    bool Stale(uint64_t version) const;
    bool Future(uint64_t version) const;

    std::map<std::string, Sample> m_samples;
    std::map<std::string, Group> m_groups;
    uint64_t m_version{1};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_RL_DT_RL_H
