// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STAGEHEAD_CODES_H
#define BITCOIN_MODELNET_SWARM_STAGEHEAD_CODES_H

namespace modelnet {

/** Empty candidate. The staged slot is left unchanged. */
inline constexpr char kSwarmStageHead[] = "HEAD";

/** Adopt found no staged candidate. The active id stays. */
inline constexpr char kSwarmStageAdopt[] = "ADOPT";

/** The staged candidate is not locally compatible. It stays staged. */
inline constexpr char kSwarmStageLocalIncompatible[] = "LOCAL_INCOMPATIBLE";

/** Rollback or regress found no remembered previous id. The active id stays. */
inline constexpr char kSwarmStageRollback[] = "ROLLBACK";

/** Realm promotion is refused. The active id stays. */
inline constexpr char kSwarmStageRealm[] = "REALM";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STAGEHEAD_CODES_H
