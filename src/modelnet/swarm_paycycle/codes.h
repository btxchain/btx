// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYCYCLE_CODES_H
#define BITCOIN_MODELNET_SWARM_PAYCYCLE_CODES_H

namespace modelnet {

/** Empty chain, lineage, or nonce, or the pool id is unknown. */
inline constexpr char SWARM_PAYCYCLE_POOL[] = "POOL";

/** Objective is outside the accepted set. Nothing is stored. */
inline constexpr char SWARM_PAYCYCLE_OBJECTIVE[] = "OBJECTIVE";

/** The same pool id, lease, reserve role, or payment id was presented again. */
inline constexpr char SWARM_PAYCYCLE_REPLAY[] = "REPLAY";

/** A raised policy string is empty. The old pool stays. */
inline constexpr char SWARM_PAYCYCLE_POLICY[] = "POLICY";

/** Split ppm values are negative or do not sum to 1000000. Nothing is stored. */
inline constexpr char SWARM_PAYCYCLE_SPLIT[] = "SPLIT";

/** The pool is unknown or unfunded, or a fund request is not refund-bound. */
inline constexpr char SWARM_PAYCYCLE_FUNDING[] = "FUNDING";

/** Work or worker is empty, or the lease is unknown. */
inline constexpr char SWARM_PAYCYCLE_WORK[] = "WORK";

/** Profit-share is refused. No earned row is created for that label. */
inline constexpr char SWARM_PAYCYCLE_REFUSED[] = "REFUSED";

/** The pay label is neither profit-share nor work-payment. */
inline constexpr char SWARM_PAYCYCLE_LABEL[] = "LABEL";

/** Work-payment is recorded and held. The scheduler does not spend. */
inline constexpr char SWARM_PAYCYCLE_HELD[] = "HELD";

/** The fiat quote string is empty. Nothing is stored. */
inline constexpr char SWARM_PAYCYCLE_QUOTE[] = "QUOTE";

/** A stored fiat amount is not a balance and moves no atoms. */
inline constexpr char SWARM_PAYCYCLE_NOT_BALANCE[] = "NOT_BALANCE";

/** Atoms are below 1, the outpoint is empty, or the reserve role is unknown. */
inline constexpr char SWARM_PAYCYCLE_COLLATERAL[] = "COLLATERAL";

/** This outpoint already funds a different pool. Nothing new is stored. */
inline constexpr char SWARM_PAYCYCLE_OUTPOINT[] = "OUTPOINT";

/** The same pool and outpoint cannot be both escrow and channel collateral. */
inline constexpr char SWARM_PAYCYCLE_COLLATERAL_REUSE[] = "COLLATERAL_REUSE";

/** A batch amount is below 1, or a credit would overflow. Nothing commits. */
inline constexpr char SWARM_PAYCYCLE_AMOUNT[] = "AMOUNT";

/** A batch would drive a pool balance negative. Nothing commits. */
inline constexpr char SWARM_PAYCYCLE_NEGATIVE[] = "NEGATIVE";

/** Freeze was requested. Earned rows stay. */
inline constexpr char SWARM_PAYCYCLE_FREEZE[] = "FREEZE";

/** Reserve or ApplyBatch was asked after freeze. Nothing commits. */
inline constexpr char SWARM_PAYCYCLE_FROZEN[] = "FROZEN";

/** Channel collateral. A successful reserve of this role adds pool balance. */
inline constexpr char SWARM_PAYCYCLE_ROLE_CHANNEL[] = "channel";

/** Escrow collateral. A successful reserve of this role does not add pool balance. */
inline constexpr char SWARM_PAYCYCLE_ROLE_ESCROW[] = "escrow";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYCYCLE_CODES_H
