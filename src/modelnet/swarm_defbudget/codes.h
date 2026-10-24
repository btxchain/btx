// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFBUDGET_CODES_H
#define BITCOIN_MODELNET_SWARM_DEFBUDGET_CODES_H

namespace modelnet {

/** The pool name is not readiness, incident, or improvement. Nothing is stored. */
inline constexpr char kSwarmDefBudgetPool[] = "POOL";

/** atoms or requested is below 1, or a sum would pass int64 max. Nothing is stored. */
inline constexpr char kSwarmDefBudgetAmount[] = "AMOUNT";

/** The outpoint is empty or already recorded. This call stores nothing. */
inline constexpr char kSwarmDefBudgetOutpoint[] = "OUTPOINT";

/** Membership was recorded. No earned row is created. */
inline constexpr char kSwarmDefBudgetNotPaid[] = "NOT_PAID";

/** The pool has not been funded. Nothing is stored. */
inline constexpr char kSwarmDefBudgetFunding[] = "FUNDING";

/** That work id is already stored for this operation. The first row stays. */
inline constexpr char kSwarmDefBudgetReplay[] = "REPLAY";

/** That receipt text is already stored on any pool. Nothing is stored. */
inline constexpr char kSwarmDefBudgetDuplicate[] = "DUPLICATE";

/** requested is above cap. Nothing is paid and nothing is stored. */
inline constexpr char kSwarmDefBudgetCap[] = "CAP";

/** The payout is above the pool balance. Nothing is stored. */
inline constexpr char kSwarmDefBudgetNegative[] = "NEGATIVE";

/** The member is the recorded payer. No earned row is stored. */
inline constexpr char kSwarmDefBudgetSelf[] = "SELF";

/** The member id is empty. Nothing is stored. */
inline constexpr char kSwarmDefBudgetMember[] = "MEMBER";

/** The work id is empty. Nothing is stored. */
inline constexpr char kSwarmDefBudgetWork[] = "WORK";

/** The receipt text is empty. Nothing is stored. */
inline constexpr char kSwarmDefBudgetReceipt[] = "RECEIPT";

/** The payer is empty, or no payer has been recorded. Nothing is stored. */
inline constexpr char kSwarmDefBudgetPayer[] = "PAYER";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFBUDGET_CODES_H
