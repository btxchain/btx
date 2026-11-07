// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIFDT_CONTRACT_CONTRACT_H
#define BITCOIN_MODELNET_NIFDT_CONTRACT_CONTRACT_H

#include <cstdint>
#include <string>

namespace modelnet {

/** An engine name is not linked. Callers add no tokens and no bytes. */
inline constexpr char NIFDT_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/** Settlement or promotion is not qualified. */
inline constexpr char NIFDT_UNQUALIFIED[] = "UNQUALIFIED";

/** A private body was refused. Nothing is stored. */
inline constexpr char NIFDT_PRIVATE_DATA[] = "PRIVATE_DATA";

/** No WAN route is known. No socket is opened for that path. */
inline constexpr char NIFDT_NO_ROUTE[] = "NO_ROUTE";

/** Discovery must not scan. */
inline constexpr char NIFDT_NOT_SCAN[] = "NOT_SCAN";

/** The same identity was submitted again. The first record stays. */
inline constexpr char NIFDT_REPLAY[] = "REPLAY";

/** Current authority does not cover the next protected effect. */
inline constexpr char NIFDT_REVOKED[] = "REVOKED";

/** Research keys never receive a spend key. */
inline constexpr char NIFDT_AUTOMATIC_SPEND[] = "0";

enum class NifPrivacy {
    LocalOnly,
    LanOnly,
    PeerNetwork,
};

enum class NifExactness {
    ExactReproducible,
    ThroughputOptimized,
    ApproximateExperimental,
};

enum class DtPhase {
    Discovered,
    Eligible,
    Reserved,
    Prepared,
    Running,
    Snapshotting,
    CandidateCommitted,
    Evaluating,
    Waiting,
    Draining,
    Revoked,
    Failed,
    OutcomeUnknown,
};

/** Fields an accepted inference request keeps across a restart. */
struct NifRequestRecord {
    std::string principal;
    std::string receiver;
    std::string realm;
    std::string generation;
    std::string runtime_image;
    std::string commitment;
    std::string attempt;
    std::uint64_t epoch{0};
    std::uint64_t ceiling_bytes{0};
    std::uint64_t lease_until_ms{0};
    bool cancelled{false};
    std::uint64_t output_ceiling{0};
    std::string accepted_output;
    std::string economic_contract;
};

/**
 * False for engines that are not linked into this binary.
 * A false result means the caller emits no tokens and moves no bytes.
 * memory and local are linked in-process names and return true.
 */
inline bool NifDtEngineLinked(const std::string& name)
{
    return !(name == "deepinfer" || name == "vllm" || name == "sglang" ||
             name == "lmcache" || name == "deepep" || name == "deepgemm" ||
             name == "dualpipe" || name == "dualpipev" || name == "nixl" ||
             name == "mooncake" || name == "rdma");
}

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIFDT_CONTRACT_CONTRACT_H
