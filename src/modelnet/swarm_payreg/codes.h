// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYREG_CODES_H
#define BITCOIN_MODELNET_SWARM_PAYREG_CODES_H

namespace modelnet {

/** The register is closed, or a second channel id was presented. Nothing new is stored. */
inline constexpr char kSwarmPayRegNotOpened[] = "NOT_OPENED";

/** atoms is below 1. Nothing is stored. */
inline constexpr char kSwarmPayRegAmount[] = "AMOUNT";

/** The outpoint is empty, or it already funds another pool. Nothing new is stored. */
inline constexpr char kSwarmPayRegOutpoint[] = "OUTPOINT";

/** The pool is not one of the two pools named at Open. Nothing is stored. */
inline constexpr char kSwarmPayRegPool[] = "POOL";

/** This outpoint already funds this pool. The first atoms stay. */
inline constexpr char kSwarmPayRegReplay[] = "REPLAY";

/** The route id is empty, or a later call changes atoms or timeout. The stored terms stay. */
inline constexpr char kSwarmPayRegTerms[] = "TERMS";

/** A timeout is below 1, or a refund timeout is other than the regtest pin. Nothing new is stored. */
inline constexpr char kSwarmPayRegTimeout[] = "TIMEOUT";

/** The payment hash is other than 32 bytes. The leaf builders are not called. */
inline constexpr char kSwarmPayRegPreimage[] = "PREIMAGE";

/** The pubkey size is other than the ML-DSA-44 size. The leaf builders are not called. */
inline constexpr char kSwarmPayRegKey[] = "KEY";

/** The work id is empty. No claim is stored. */
inline constexpr char kSwarmPayRegClaim[] = "CLAIM";

/** Settlement stays refused. No atoms move and nothing is broadcast. */
inline constexpr char kSwarmPayRegUnqualified[] = "UNQUALIFIED";

/** A credit note was stored. It is not backing and the funded balance stays. */
inline constexpr char kSwarmPayRegNotBacking[] = "NOT_BACKING";

/** Mode() stays this value. This process does not advertise a spendable balance. */
inline constexpr char kSwarmPayRegMode[] = "REGTEST_UNBROADCAST";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYREG_CODES_H
