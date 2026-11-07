// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_ROLLOUT_DT_ROLLOUT_H
#define BITCOIN_MODELNET_DT_ROLLOUT_DT_ROLLOUT_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** The sample id was empty, or Finish named a sample Route did not store. */
inline constexpr char DT_ROLLOUT_SAMPLE[] = "SAMPLE";

/** The route is structurally incompatible. Nothing is stored. */
inline constexpr char DT_ROLLOUT_ROUTE[] = "ROUTE";

/** A token count or a replenishment need is below 1. */
inline constexpr char DT_ROLLOUT_LENGTH[] = "LENGTH";

/** Finished samples that are not early are fewer than need. */
inline constexpr char DT_ROLLOUT_SHORT[] = "SHORT";

/** Generate was requested while the replenishment is open and not sealed. */
inline constexpr char DT_ROLLOUT_MODE[] = "MODE";

/**
 * In-memory sample rollout replenishment.
 *
 * The replenishment starts open and unsealed. Route stores one sample id
 * and its version. An empty id is SAMPLE and stores nothing. compatible
 * false is ROUTE and stores nothing. A second Route of a stored id is
 * NIFDT_REPLAY and keeps the first version.
 *
 * Finish records tokens for a stored sample. An unknown id is SAMPLE.
 * tokens below 1 is LENGTH and does not finish the sample. A second Finish
 * of the same id is NIFDT_REPLAY and keeps the first tokens and early flag.
 * early true stores the sample as short. A short sample stays stored and
 * does not count toward replenishment.
 *
 * Replenish(need) counts only finished samples that are not early. need
 * below 1 is LENGTH. A count below need returns false with SHORT and leaves
 * replenished() false when no earlier replenishment succeeded. A count at
 * or above need sets replenished().
 *
 * SwitchGenerate while the replenishment is open and not sealed returns
 * false with MODE and does not drop finished samples. Seal marks the
 * replenishment sealed. SwitchGenerate after Seal returns true.
 * generate_dropped_train() stays false.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is "0".
 * No socket is opened and no process is started.
 */
class DtRollout {
public:
    bool Route(const std::string& sample, uint64_t version, bool compatible, std::string& err);
    bool Finish(const std::string& sample, int64_t tokens, bool early, std::string& err);
    bool Replenish(int64_t need, std::string& err);
    bool Seal(std::string& err);
    bool SwitchGenerate(std::string& err);

    bool has_sample(const std::string& sample) const;
    /** First routed version, or 0 when the sample was not stored. */
    uint64_t version_of(const std::string& sample) const;
    /** Tokens recorded by Finish, or 0 when that sample has no finish. */
    int64_t tokens_of(const std::string& sample) const;
    /** True when Finish stored this sample and early was false. */
    bool finished(const std::string& sample) const;
    /** True when Finish stored this sample as short. */
    bool is_short(const std::string& sample) const;

    /** Finished samples that are not early. This is the replenishment count. */
    int64_t finished_count() const;
    /** Samples Finish stored as short. */
    int64_t short_count() const;
    /** Samples Route stored. */
    int64_t routed_count() const;

    bool replenished() const { return m_replenished; }
    bool sealed() const { return m_sealed; }
    bool generating() const { return m_generating; }
    bool generate_dropped_train() const { return false; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Sample {
        uint64_t version{0};
        int64_t tokens{0};
        bool done{false};
        bool early{false};
    };

    const Sample* Find(const std::string& sample) const;

    std::map<std::string, Sample> m_samples;
    bool m_open{true};
    bool m_sealed{false};
    bool m_replenished{false};
    bool m_generating{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_ROLLOUT_DT_ROLLOUT_H
