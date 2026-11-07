// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_RESHARD_DT_RESHARD_H
#define BITCOIN_MODELNET_DT_RESHARD_DT_RESHARD_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** The logical name was empty or unknown. Nothing is stored. */
inline constexpr char DT_RESHARD_PARAM[] = "PARAM";

/** The shard name was empty. Nothing is stored. */
inline constexpr char DT_RESHARD_SHARD[] = "SHARD";

/** The requested shard is not the mapped shard. Stored weight stays. */
inline constexpr char DT_RESHARD_MAP[] = "MAP";

/** Apply ran without a successful Move. The published weight stays. */
inline constexpr char DT_RESHARD_UNMAPPED[] = "UNMAPPED";

/** This moved weight was already applied. It is not added again. */
inline constexpr char DT_RESHARD_UNCHANGED[] = "UNCHANGED";

/**
 * Logical-parameter reshard map.
 *
 * Map binds one logical parameter name to one shard. An empty logical name
 * is PARAM and stores nothing. An empty shard name is SHARD and stores
 * nothing. A second Map of the same logical name is NIFDT_REPLAY and keeps
 * the first shard.
 *
 * Move copies a weight into the mapped shard only when that shard equals
 * the requested shard. A mismatch is MAP and does not change the stored
 * weight. An unknown logical name is PARAM and stores nothing. Copying the
 * weight already published leaves that publication in place.
 *
 * Apply publishes the stored weight as that logical parameter's
 * contribution to live_weight(). It returns true only after a successful
 * Move. Otherwise the result is UNMAPPED, and live_weight() stays 0 when
 * nothing has been published. A second Apply of the same moved weight is
 * UNCHANGED and does not add the weight again. A later Move of a different
 * weight replaces that contribution on the next successful Apply.
 *
 * prior_weight() is the live weight from before the latest successful
 * Apply. It starts at 0. Prior keeps that previous live weight available
 * until Apply succeeds. A failed Move leaves prior_weight() unchanged.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and leaves both weights
 * unchanged. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND ("0"). qualified() stays false.
 * No socket is opened and no process is started.
 */
class DtReshard {
public:
    bool Map(const std::string& logical, const std::string& shard, std::string& err);
    bool Move(const std::string& logical, const std::string& shard, int64_t weight, std::string& err);
    bool Apply(const std::string& logical, std::string& err);
    bool Prior(const std::string& logical, std::string& err);
    bool Gpu(std::string& err);

    /** Sum of each logical parameter's last published weight. 0 before Apply. */
    int64_t live_weight() const { return m_live; }
    /** Live weight from before the latest successful Apply. 0 before that. */
    int64_t prior_weight() const { return m_prior; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Row {
        std::string shard;
        bool has_move{false};
        int64_t moved{0};
        bool applied{false};
        int64_t contributed{0};
    };

    std::map<std::string, Row> m_rows;
    int64_t m_live{0};
    int64_t m_prior{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_RESHARD_DT_RESHARD_H
