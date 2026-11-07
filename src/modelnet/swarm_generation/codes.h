// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GENERATION_CODES_H
#define BITCOIN_MODELNET_SWARM_GENERATION_CODES_H

#include <string>

namespace modelnet {

inline constexpr char kSwarmGenerationWeakness[] = "WEAKNESS";
inline constexpr char kSwarmGenerationReplay[] = "REPLAY";
inline constexpr char kSwarmGenerationNoWeakness[] = "NO_WEAKNESS";
inline constexpr char kSwarmGenerationLicense[] = "LICENSE";
inline constexpr char kSwarmGenerationSlots[] = "SLOTS";
inline constexpr char kSwarmGenerationExplore[] = "EXPLORE";
inline constexpr char kSwarmGenerationTask[] = "TASK";
inline constexpr char kSwarmGenerationData[] = "DATA";
inline constexpr char kSwarmGenerationEngineAbsent[] = "ENGINE_ABSENT";
inline constexpr char kSwarmGenerationCandidate[] = "CANDIDATE";
inline constexpr char kSwarmGenerationProvenance[] = "PROVENANCE";
inline constexpr char kSwarmGenerationSelf[] = "SELF";
inline constexpr char kSwarmGenerationNotQuorum[] = "NOT_QUORUM";
inline constexpr char kSwarmGenerationHoldout[] = "HOLDOUT";
inline constexpr char kSwarmGenerationSafety[] = "SAFETY";
inline constexpr char kSwarmGenerationRegression[] = "REGRESSION";
inline constexpr char kSwarmGenerationNegative[] = "NEGATIVE";
inline constexpr char kSwarmGenerationNotAveraged[] = "NOT_AVERAGED";
inline constexpr char kSwarmGenerationNotGraduated[] = "NOT_GRADUATED";
inline constexpr char kSwarmGenerationSpecialist[] = "SPECIALIST";
inline constexpr char kSwarmGenerationPolicy[] = "POLICY";
inline constexpr char kSwarmGenerationNotStaged[] = "NOT_STAGED";
inline constexpr char kSwarmGenerationUnqualified[] = "UNQUALIFIED";

inline constexpr char kSwarmGenerationGeneralStable[] = "general/stable";
inline constexpr char kSwarmGenerationCodeStable[] = "code/stable";
inline constexpr char kSwarmGenerationFollow[] = "follow";
inline constexpr char kSwarmGenerationPin[] = "pin";
inline constexpr char kSwarmGenerationRefuse[] = "refuse";
inline constexpr char kSwarmGenerationAutomaticSpend[] = "0";

inline bool SwarmGenerationFail(std::string& err, const char* code)
{
    err = code;
    return false;
}

inline bool SwarmGenerationOk(std::string& err)
{
    err.clear();
    return true;
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GENERATION_CODES_H
