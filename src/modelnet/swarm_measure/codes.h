// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MEASURE_CODES_H
#define BITCOIN_MODELNET_SWARM_MEASURE_CODES_H

namespace modelnet {

/** An empty sample list, or any negative sample. Nothing is stored. */
inline constexpr char kSwarmMeasureMeasure[] = "MEASURE";

/** The platform name is empty, or it is neither windows nor linux. Nothing is stored. */
inline constexpr char kSwarmMeasurePlatform[] = "PLATFORM";

/** The name windows was given with empty evidence. Nothing is stored. */
inline constexpr char kSwarmMeasureWindowsAbsent[] = "WINDOWS_ABSENT";

/** The name linux was given with empty evidence. Nothing is stored. */
inline constexpr char kSwarmMeasureEvidence[] = "EVIDENCE";

/** Platform name that may store evidence. windows_passed() stays false. */
inline constexpr char kSwarmMeasureWindows[] = "windows";

/** Platform name that stores non-empty evidence. platform_name() returns this. */
inline constexpr char kSwarmMeasureLinux[] = "linux";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MEASURE_CODES_H
