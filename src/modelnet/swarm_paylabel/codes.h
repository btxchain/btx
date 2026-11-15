// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_CODES_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_CODES_H

namespace modelnet {

/** The label is exactly "profit-share". Nothing is stored. */
inline constexpr char kSwarmPayLabelRefused[] = "REFUSED";

/** The label is empty or any text other than "work-payment". Nothing is stored. */
inline constexpr char kSwarmPayLabelLabel[] = "LABEL";

/** A second Accept of "work-payment". The first label stays. */
inline constexpr char kSwarmPayLabelReplay[] = "REPLAY";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_CODES_H
