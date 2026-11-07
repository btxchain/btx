// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PARENTAGE_CODES_H
#define BITCOIN_MODELNET_SWARM_PARENTAGE_CODES_H

namespace modelnet {

/** Empty checkpoint, parent, recipe, dataset, or license. Also an unknown checkpoint. Nothing new is stored. */
inline constexpr char SWARM_PARENTAGE_LINEAGE[] = "LINEAGE";

/** The same checkpoint was bound again with the same parent, recipe, dataset, and license. The first binding stays. */
inline constexpr char SWARM_PARENTAGE_REPLAY[] = "REPLAY";

/** The same checkpoint was bound again with a different parent, recipe, dataset, or license. The first binding stays. */
inline constexpr char SWARM_PARENTAGE_CONFLICT[] = "CONFLICT";

/** Hub was given an empty card. Nothing is stored. */
inline constexpr char SWARM_PARENTAGE_CARD[] = "CARD";

/** A hub card is not lineage authority. No binding is created and no parent is replaced. */
inline constexpr char SWARM_PARENTAGE_NOT_AUTHORITY[] = "NOT_AUTHORITY";

/** A checkpoint id is not trust. Trust of a bound checkpoint stays refused. */
inline constexpr char SWARM_PARENTAGE_NOT_TRUST[] = "NOT_TRUST";

/** A bound checkpoint is not realm-promoted. A stored license is not a training grant. */
inline constexpr char SWARM_PARENTAGE_NOT_GRADUATED[] = "NOT_GRADUATED";

static_assert(sizeof(SWARM_PARENTAGE_LINEAGE) == 8, "LINEAGE");
static_assert(sizeof(SWARM_PARENTAGE_REPLAY) == 7, "REPLAY");
static_assert(sizeof(SWARM_PARENTAGE_CONFLICT) == 9, "CONFLICT");
static_assert(sizeof(SWARM_PARENTAGE_CARD) == 5, "CARD");
static_assert(sizeof(SWARM_PARENTAGE_NOT_AUTHORITY) == 14, "NOT_AUTHORITY");
static_assert(sizeof(SWARM_PARENTAGE_NOT_TRUST) == 10, "NOT_TRUST");
static_assert(sizeof(SWARM_PARENTAGE_NOT_GRADUATED) == 14, "NOT_GRADUATED");
static_assert(SWARM_PARENTAGE_LINEAGE[0] == 'L', "lineage code");
static_assert(SWARM_PARENTAGE_REPLAY[0] == 'R', "replay code");
static_assert(SWARM_PARENTAGE_CONFLICT[0] == 'C', "conflict code");
static_assert(SWARM_PARENTAGE_CARD[0] == 'C', "card code");
static_assert(SWARM_PARENTAGE_NOT_AUTHORITY[0] == 'N', "not authority code");
static_assert(SWARM_PARENTAGE_NOT_TRUST[0] == 'N', "not trust code");
static_assert(SWARM_PARENTAGE_NOT_GRADUATED[0] == 'N', "not graduated code");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PARENTAGE_CODES_H
