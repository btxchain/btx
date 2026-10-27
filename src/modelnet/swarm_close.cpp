// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_close.h>

#include <modelnet/swarm_codec.h>
#include <pqkey.h>
#include <script/pqm.h>

#include <algorithm>

namespace modelnet {

SwarmL1Limits SwarmMainnetLimits()
{
    SwarmL1Limits limits;
    limits.target_spacing_seconds = 90;
    limits.max_block_serialized = MAX_BLOCK_SERIALIZED_SIZE;
    limits.max_block_weight = MAX_BLOCK_WEIGHT;
    limits.witness_scale = WITNESS_SCALE_FACTOR;
    limits.blocks_per_day = 86400 / limits.target_spacing_seconds;
    limits.max_serialized_bytes_per_day =
        static_cast<int64_t>(limits.blocks_per_day) * static_cast<int64_t>(limits.max_block_serialized);
    limits.wall_clock_guaranteed = false;
    return limits;
}

int64_t SwarmTargetElapsedSeconds(int blocks)
{
    if (blocks < 0) return 0;
    return static_cast<int64_t>(blocks) * 90;
}

std::string SwarmEconomyIdentity(const std::string& lineage_id)
{
    if (lineage_id.empty()) return {};
    return SwarmDigest("BTX/ModelEconomy/1", SwarmCanonical({{"lineage", lineage_id}}));
}

bool SwarmAddSponsorLot(SwarmSponsorPool& pool, const SwarmSponsorLot& lot, std::string& err)
{
    if (lot.sponsor_id.empty() || lot.atoms <= 0 || lot.refund_height < 1 || lot.preimage_hash.size() != 32 ||
        lot.sponsor_pubkey.size() != MLDSA44_PUBKEY_SIZE || lot.claimant_pubkey.size() != MLDSA44_PUBKEY_SIZE) {
        err = "SPONSOR_LOT";
        return false;
    }
    for (const SwarmSponsorLot& existing : pool.lots) {
        if (existing.sponsor_id == lot.sponsor_id) {
            err = "SPONSOR_DUP";
            return false;
        }
    }
    SwarmSponsorLot stored = lot;
    stored.claim_script = BuildP2MRHTLCSha256Leaf(lot.preimage_hash, PQAlgorithm::ML_DSA_44, lot.claimant_pubkey);
    stored.refund_script = BuildP2MRRefundLeaf(lot.refund_height, PQAlgorithm::ML_DSA_44, lot.sponsor_pubkey);
    if (stored.claim_script.empty() || stored.refund_script.empty()) {
        err = "SPONSOR_SCRIPT";
        return false;
    }
    pool.gross_atoms += stored.atoms;
    pool.lots.push_back(std::move(stored));
    err.clear();
    return true;
}

bool SwarmAmendSponsorRefund(SwarmSponsorPool& pool, const std::string& sponsor_id, int64_t new_height, std::string& err)
{
    (void)pool;
    (void)sponsor_id;
    (void)new_height;
    err = "REFUND_IMMUTABLE";
    return false;
}

bool SwarmAcceptWorkEvidence(const std::string& kind, std::string& err)
{
    if (kind == "hour-claim" || kind == "gradient-claim") {
        err = "NOT_CONTRIBUTION";
        return false;
    }
    if (kind == "SIGNED_WORK_RESULT" || kind == "REPRODUCIBLE_TEST" || kind == "INDEPENDENT_EVALUATION") {
        err.clear();
        return true;
    }
    err = "EVIDENCE_TYPE";
    return false;
}

SwarmOriginRecord SwarmImportOrigin(const std::string& url)
{
    return SwarmOriginRecord{url, false, false};
}

SwarmOriginRecord SwarmPublishBack(const std::string& url)
{
    return SwarmOriginRecord{url, false, false};
}

SwarmSpecialistSignal SwarmOfferSpecialistSignal(const std::string& kind, std::string& err)
{
    SwarmSpecialistSignal signal;
    if (kind != "data" && kind != "reward" && kind != "distillation") {
        err = "SIGNAL";
        return signal;
    }
    signal.ok = true;
    signal.kind = kind;
    signal.replaces_general = false;
    err.clear();
    return signal;
}

std::vector<unsigned char> SwarmEvaluatorThreshold(
    const std::vector<std::vector<unsigned char>>& evaluator_pubkeys, uint8_t threshold)
{
    if (threshold < 1 || evaluator_pubkeys.empty() || threshold > evaluator_pubkeys.size()) return {};
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys;
    keys.reserve(evaluator_pubkeys.size());
    for (const std::vector<unsigned char>& pubkey : evaluator_pubkeys) {
        if (pubkey.size() != MLDSA44_PUBKEY_SIZE) return {};
        keys.emplace_back(PQAlgorithm::ML_DSA_44, pubkey);
    }
    return BuildP2MRMultisigScript(threshold, keys);
}

bool SwarmChannelMesh::Open(const std::string& channel_id, const std::string& outpoint, const std::string& pool, std::string& err)
{
    if (channel_id.empty() || outpoint.empty() || pool.empty()) {
        err = "CHANNEL";
        return false;
    }
    for (const SwarmChannelUse& use : m_channels) {
        if (use.channel_id == channel_id || use.outpoint == outpoint) {
            err = "COLLATERAL_REUSE";
            return false;
        }
    }
    SwarmChannelUse use;
    use.channel_id = channel_id;
    use.outpoint = outpoint;
    use.owner_pool = pool;
    use.referencing_pools.push_back(pool);
    m_channels.push_back(std::move(use));
    err.clear();
    return true;
}

bool SwarmChannelMesh::Reference(const std::string& channel_id, const std::string& pool, std::string& err)
{
    for (SwarmChannelUse& use : m_channels) {
        if (use.channel_id != channel_id) continue;
        if (std::find(use.referencing_pools.begin(), use.referencing_pools.end(), pool) == use.referencing_pools.end()) {
            use.referencing_pools.push_back(pool);
        }
        err.clear();
        return true;
    }
    err = "CHANNEL";
    return false;
}

const SwarmChannelUse* SwarmChannelMesh::Find(const std::string& channel_id) const
{
    for (const SwarmChannelUse& use : m_channels) {
        if (use.channel_id == channel_id) return &use;
    }
    return nullptr;
}

bool SwarmSplitRevenue(int64_t gross, int64_t compute_ppm, int64_t improvement_ppm, int64_t evaluation_ppm,
                       SwarmRevenueSplit& out, std::string& err)
{
    if (gross < 0 || compute_ppm < 0 || improvement_ppm < 0 || evaluation_ppm < 0 ||
        compute_ppm + improvement_ppm + evaluation_ppm != 1000000) {
        err = "REVENUE_SPLIT";
        return false;
    }
    out.compute_atoms = gross * compute_ppm / 1000000;
    out.improvement_atoms = gross * improvement_ppm / 1000000;
    out.evaluation_atoms = gross * evaluation_ppm / 1000000;
    err.clear();
    return true;
}

bool SwarmCommunityContinues(int other_active_peers)
{
    return other_active_peers >= 1;
}

} // namespace modelnet
