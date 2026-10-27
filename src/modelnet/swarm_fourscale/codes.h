// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FOURSCALE_CODES_H
#define BITCOIN_MODELNET_SWARM_FOURSCALE_CODES_H

namespace modelnet {

/** Step ran before Open, or the scale is not one of the four. Nothing is stored. */
inline constexpr char kSwarmFourScaleScale[] = "SCALE";

/** Open ran again. Every step stays where it is. */
inline constexpr char kSwarmFourScaleReplay[] = "REPLAY";

/** Average is refused. No step is folded into another. */
inline constexpr char kSwarmFourScaleNotAveraged[] = "NOT_AVERAGED";

/** Graduate is refused. The plane does not leave these four scales. */
inline constexpr char kSwarmFourScaleRealm[] = "REALM";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FOURSCALE_CODES_H
