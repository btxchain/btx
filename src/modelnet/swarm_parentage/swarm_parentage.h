// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_H

#include <modelnet/swarm_parentage/codes.h>
#include <modelnet/swarm_parentage/flags.h>
#include <modelnet/swarm_parentage/ledger.h>
#include <modelnet/swarm_parentage/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process parentage book.
 * Bind stores a checkpoint's parent, recipe, dataset, and license.
 * An empty argument is LINEAGE and stores nothing. An empty parent is not a baseline head.
 * The same four fields again are REPLAY and keep the first row.
 * Any different field is CONFLICT and keeps the first row.
 * Hub refuses a card. A hub card is not lineage authority and does not replace a parent.
 * Claim refuses a checkpoint id. A checkpoint id alone is not trust and stores nothing.
 * Trust of an unknown checkpoint is LINEAGE. Trust of a bound checkpoint is NOT_TRUST.
 * Promote of an unknown checkpoint is LINEAGE. Promote of a bound checkpoint is NOT_GRADUATED.
 * A stored license is not a training grant and not a realm admission.
 * Quality is not realm promotion.
 * trusted() stays false. realm_promoted() stays false. exact_replay_admitted() stays false.
 * launched() stays false. gpu() stays false. bytes_moved() stays 0.
 * There is no method that sets those true or above 0.
 */
class SwarmParentage {
public:
    /**
     * Store parent, recipe, dataset, and license under checkpoint.
     * Any empty argument is LINEAGE and stores nothing.
     * A second bind of the same checkpoint with the same four fields is REPLAY and keeps the first.
     * A second bind of the same checkpoint with any different field is CONFLICT and keeps the first.
     * Otherwise the four fields are stored and the function returns true.
     * trusted() stays false.
     */
    bool Bind(const std::string& checkpoint,
              const std::string& parent,
              const std::string& recipe,
              const std::string& dataset,
              const std::string& license,
              std::string& err);

    /**
     * An empty card is CARD and stores nothing.
     * A non-empty card returns false with NOT_AUTHORITY.
     * The call does not create a binding, does not replace a parent, and does not set trusted().
     * A stored parent stays stored.
     */
    bool Hub(const std::string& checkpoint, const std::string& card, std::string& err);

    /**
     * An empty checkpoint is LINEAGE.
     * Any non-empty checkpoint returns false with NOT_TRUST and does not create a binding.
     * A checkpoint id alone is not trust.
     */
    bool Claim(const std::string& checkpoint, std::string& err);

    /**
     * An unknown checkpoint is LINEAGE.
     * A bound checkpoint returns false with NOT_TRUST.
     * trusted() stays false.
     */
    bool Trust(const std::string& checkpoint, std::string& err);

    /**
     * An unknown checkpoint is LINEAGE.
     * A bound checkpoint returns false with NOT_GRADUATED.
     * realm_promoted() and exact_replay_admitted() stay false.
     * A stored license is not a training grant and not a realm admission.
     */
    bool Promote(const std::string& checkpoint, std::string& err);

    /** True when Bind has stored this checkpoint. */
    bool bound(const std::string& checkpoint) const;

    /** Stored parent, or empty when the checkpoint is absent. */
    std::string parent_of(const std::string& checkpoint) const;

    /** Stored recipe, or empty when the checkpoint is absent. */
    std::string recipe_of(const std::string& checkpoint) const;

    /** Stored dataset, or empty when the checkpoint is absent. */
    std::string dataset_of(const std::string& checkpoint) const;

    /** Stored license, or empty when the checkpoint is absent. */
    std::string license_of(const std::string& checkpoint) const;

    bool trusted() const;
    bool realm_promoted() const;
    bool exact_replay_admitted() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;

private:
    SwarmParentageLedger m_ledger;
    SwarmParentageFlags m_flags;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_H
