// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CLOSE_H
#define BITCOIN_MODELNET_SWARM_CLOSE_H

#include <consensus/consensus.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Mainnet settlement bounds. Target spacing is the chain parameter, not a promise that a block arrives on time. */
struct SwarmL1Limits {
    int target_spacing_seconds{90};
    unsigned max_block_serialized{MAX_BLOCK_SERIALIZED_SIZE};
    unsigned max_block_weight{MAX_BLOCK_WEIGHT};
    int witness_scale{WITNESS_SCALE_FACTOR};
    int blocks_per_day{960};
    int64_t max_serialized_bytes_per_day{0};
    bool wall_clock_guaranteed{false};
};

SwarmL1Limits SwarmMainnetLimits();

/** blocks * 90. wall_clock_guaranteed is always false. */
int64_t SwarmTargetElapsedSeconds(int blocks);

/** Survives a checkpoint fork. It is not a pool id. */
std::string SwarmEconomyIdentity(const std::string& lineage_id);

struct SwarmSponsorLot {
    std::string sponsor_id;
    std::vector<unsigned char> sponsor_pubkey;
    std::vector<unsigned char> claimant_pubkey;
    std::vector<unsigned char> preimage_hash;
    int64_t refund_height{0};
    int64_t atoms{0};
    std::vector<unsigned char> claim_script;
    std::vector<unsigned char> refund_script;
};

struct SwarmSponsorPool {
    std::vector<SwarmSponsorLot> lots;
    int64_t gross_atoms{0};
};

bool SwarmAddSponsorLot(SwarmSponsorPool& pool, const SwarmSponsorLot& lot, std::string& err);
bool SwarmAmendSponsorRefund(SwarmSponsorPool& pool, const std::string& sponsor_id, int64_t new_height, std::string& err);

/** A claimed hour or a bare gradient is not payable work. */
bool SwarmAcceptWorkEvidence(const std::string& kind, std::string& err);

/** An evaluation certificate is not received money. */
inline bool SwarmCertificateIsPayment() { return false; }

/** A revealed preimage does not prove the AI work. */
inline bool SwarmPreimageProvesWork() { return false; }

/** The cumulative channel does not prove the work. */
inline const char* SwarmChannelAssurance() { return "CUMULATIVE_NOT_WORK_PROOF"; }

struct SwarmOriginRecord {
    std::string url;
    bool is_lineage{false};
    bool exclusive{false};
};

SwarmOriginRecord SwarmImportOrigin(const std::string& url);
SwarmOriginRecord SwarmPublishBack(const std::string& url);

struct SwarmSpecialistSignal {
    bool ok{false};
    std::string kind;
    bool replaces_general{false};
};

SwarmSpecialistSignal SwarmOfferSpecialistSignal(const std::string& kind, std::string& err);

/** Threshold of evaluator keys. Does not move the sponsor refund key. */
std::vector<unsigned char> SwarmEvaluatorThreshold(
    const std::vector<std::vector<unsigned char>>& evaluator_pubkeys, uint8_t threshold);

struct SwarmChannelUse {
    std::string channel_id;
    std::string outpoint;
    std::string owner_pool;
    std::vector<std::string> referencing_pools;
};

class SwarmChannelMesh {
public:
    bool Open(const std::string& channel_id, const std::string& outpoint, const std::string& pool, std::string& err);
    bool Reference(const std::string& channel_id, const std::string& pool, std::string& err);
    const SwarmChannelUse* Find(const std::string& channel_id) const;

private:
    std::vector<SwarmChannelUse> m_channels;
};

struct SwarmRevenueSplit {
    int64_t compute_atoms{0};
    int64_t improvement_atoms{0};
    int64_t evaluation_atoms{0};
};

/** Caller-supplied ppm. The 7000/2000/1000 illustration is not a protocol tax. */
bool SwarmSplitRevenue(int64_t gross, int64_t compute_ppm, int64_t improvement_ppm, int64_t evaluation_ppm,
                       SwarmRevenueSplit& out, std::string& err);

/** One remaining peer is enough for the community to continue. */
bool SwarmCommunityContinues(int other_active_peers);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CLOSE_H
