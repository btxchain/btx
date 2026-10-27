// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_records.h>

#include <modelnet/swarm_codec.h>
#include <crypto/sha256.h>
#include <pqkey.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

namespace modelnet {
namespace {

enum class ReadStatus { Missing, Ok, Error };

ReadStatus ReadFile(const fs::path& path, std::string& raw)
{
    if (!fs::exists(path)) return ReadStatus::Missing;
    std::ifstream in(path, std::ios::binary);
    if (!in) return ReadStatus::Error;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return ReadStatus::Ok;
}

bool EnsureSwarmDir(const fs::path& modeldir, fs::path& swarm_dir, std::string& err, const char* code)
{
    swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = code;
        return false;
    }
    return true;
}

bool WriteAtomic(const fs::path& final_path, const fs::path& tmp, const UniValue& root, std::string& err,
                 const char* write_code, const char* rename_code)
{
    {
        std::ofstream file(tmp, std::ios::trunc);
        if (!file) {
            err = write_code;
            return false;
        }
        file << root.write(0, 0) << "\n";
        if (!file) {
            err = write_code;
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = rename_code;
        return false;
    }
    return true;
}

bool ReadStringArray(const UniValue& value, std::vector<std::string>& out)
{
    if (!value.isArray()) return false;
    out.clear();
    out.reserve(value.size());
    for (const UniValue& item : value.getValues()) {
        if (!item.isStr()) return false;
        out.push_back(item.get_str());
    }
    return true;
}

UniValue StringArray(const std::vector<std::string>& values)
{
    UniValue array(UniValue::VARR);
    for (const std::string& value : values) array.push_back(value);
    return array;
}

bool KnownKnowledgeKind(const std::string& kind)
{
    return kind == "finding" || kind == "strategy" || kind == "evaluation" || kind == "adapter" || kind == "generation";
}

bool RangeCovers(const SwarmPageHolder& holder, int page_start, int page_end)
{
    if (holder.page_start < 0 || holder.page_end < 0) return false;
    return holder.page_start <= page_start && holder.page_end >= page_end;
}

} // namespace

bool SwarmMakeLineage(const std::string& parent_lineage, const std::vector<std::string>& parent_ancestry,
                      const std::string& architecture, const std::string& license_id, bool license_allows_training,
                      ModelLineage& out, std::string& err)
{
    out = ModelLineage{};
    if (architecture.empty()) {
        err = "ARCHITECTURE";
        return false;
    }
    if (license_id.empty()) {
        err = "LICENSE";
        return false;
    }
    std::vector<std::string> ancestry = parent_ancestry;
    if (parent_lineage.empty()) {
        if (!ancestry.empty()) {
            err = "ANCESTRY";
            return false;
        }
    } else {
        if (!SwarmFixedId(parent_lineage)) {
            err = "PARENT";
            return false;
        }
        if (ancestry.empty() || ancestry.back() != parent_lineage) ancestry.push_back(parent_lineage);
    }
    const std::string canonical = SwarmCanonical({
        {"architecture", architecture},
        {"license_allows_training", license_allows_training ? "1" : "0"},
        {"license_id", license_id},
        {"parent_lineage", parent_lineage},
    });
    if (canonical.empty()) {
        err = "LINEAGE_CANONICAL";
        return false;
    }
    const std::string lineage_id = SwarmDigest("BTX/ModelLineage/1", canonical);
    if (!SwarmFixedId(lineage_id) || lineage_id == parent_lineage) {
        err = "LINEAGE_ID";
        return false;
    }
    ancestry.push_back(lineage_id);
    out.lineage_id = lineage_id;
    out.parent_lineage = parent_lineage;
    out.architecture = architecture;
    out.license_id = license_id;
    out.license_allows_training = license_allows_training;
    out.ancestry = std::move(ancestry);
    err.clear();
    return true;
}

bool SwarmLineageAllowsTraining(const ModelLineage& lineage, bool operator_grant)
{
    return lineage.license_allows_training && operator_grant;
}

bool SwarmStoreNetworks(const fs::path& modeldir, const SwarmNetworks& networks, std::string& err)
{
    fs::path swarm_dir;
    if (!EnsureSwarmDir(modeldir, swarm_dir, err, "NETWORKS_DIR")) return false;
    UniValue root(UniValue::VOBJ);
    UniValue family(UniValue::VOBJ);
    family.pushKV("lineage_id", networks.family.lineage_id);
    family.pushKV("member_artifact_ids", StringArray(networks.family.member_artifact_ids));
    UniValue neighborhood(UniValue::VOBJ);
    neighborhood.pushKV("peer_ids", StringArray(networks.neighborhood.peer_ids));
    UniValue cohort(UniValue::VOBJ);
    cohort.pushKV("checkpoint_id", networks.cohort.checkpoint_id);
    cohort.pushKV("lease_slots", networks.cohort.lease_slots);
    cohort.pushKV("lease_until_ms", networks.cohort.lease_until_ms);
    cohort.pushKV("member_ids", StringArray(networks.cohort.member_ids));
    cohort.pushKV("recipe_id", networks.cohort.recipe_id);
    UniValue frontier(UniValue::VOBJ);
    frontier.pushKV("candidate_ids", StringArray(networks.frontier.candidate_ids));
    root.pushKV("automatic_spend_atoms", "0");
    root.pushKV("cohort", cohort);
    root.pushKV("family", family);
    root.pushKV("frontier", frontier);
    root.pushKV("neighborhood", neighborhood);
    if (!WriteAtomic(swarm_dir / "networks.json", swarm_dir / "networks.json.tmp", root, err, "NETWORKS_WRITE",
                     "NETWORKS_RENAME")) {
        return false;
    }
    err.clear();
    return true;
}

bool SwarmLoadNetworks(const fs::path& modeldir, SwarmNetworks& out, std::string& err)
{
    out = SwarmNetworks{};
    out.automatic_spend_atoms = "0";
    const fs::path path = modeldir / "swarm" / "networks.json";
    std::string raw;
    const ReadStatus status = ReadFile(path, raw);
    if (status == ReadStatus::Missing) {
        err.clear();
        return true;
    }
    if (status == ReadStatus::Error) {
        err = "NETWORKS_READ";
        return false;
    }
    try {
        UniValue root;
        if (!root.read(raw) || !root.isObject()) {
            err = "NETWORKS_JSON";
            return false;
        }
        if (root.exists("automatic_spend_atoms") &&
            (!root["automatic_spend_atoms"].isStr() || root["automatic_spend_atoms"].get_str() != "0")) {
            err = "NETWORKS_JSON";
            return false;
        }
        if (!root.exists("family") || !root["family"].isObject() || !root.exists("neighborhood") ||
            !root["neighborhood"].isObject() || !root.exists("cohort") || !root["cohort"].isObject() ||
            !root.exists("frontier") || !root["frontier"].isObject()) {
            err = "NETWORKS_JSON";
            return false;
        }
        const UniValue& family = root["family"];
        const UniValue& neighborhood = root["neighborhood"];
        const UniValue& cohort = root["cohort"];
        const UniValue& frontier = root["frontier"];
        if (!family.exists("lineage_id") || !family["lineage_id"].isStr() || !family.exists("member_artifact_ids") ||
            !neighborhood.exists("peer_ids") || !cohort.exists("checkpoint_id") || !cohort["checkpoint_id"].isStr() ||
            !cohort.exists("recipe_id") || !cohort["recipe_id"].isStr() || !cohort.exists("member_ids") ||
            !cohort.exists("lease_slots") || !cohort["lease_slots"].isNum() || !cohort.exists("lease_until_ms") ||
            !cohort["lease_until_ms"].isNum() || !frontier.exists("candidate_ids")) {
            err = "NETWORKS_JSON";
            return false;
        }
        SwarmNetworks loaded;
        loaded.automatic_spend_atoms = "0";
        loaded.family.lineage_id = family["lineage_id"].get_str();
        if (!ReadStringArray(family["member_artifact_ids"], loaded.family.member_artifact_ids) ||
            !ReadStringArray(neighborhood["peer_ids"], loaded.neighborhood.peer_ids) ||
            !ReadStringArray(cohort["member_ids"], loaded.cohort.member_ids) ||
            !ReadStringArray(frontier["candidate_ids"], loaded.frontier.candidate_ids)) {
            err = "NETWORKS_JSON";
            return false;
        }
        loaded.cohort.checkpoint_id = cohort["checkpoint_id"].get_str();
        loaded.cohort.recipe_id = cohort["recipe_id"].get_str();
        loaded.cohort.lease_slots = cohort["lease_slots"].getInt<int>();
        loaded.cohort.lease_until_ms = cohort["lease_until_ms"].getInt<int64_t>();
        out = std::move(loaded);
    } catch (const std::exception&) {
        out = SwarmNetworks{};
        out.automatic_spend_atoms = "0";
        err = "NETWORKS_JSON";
        return false;
    }
    err.clear();
    return true;
}

uint256 SwarmPresenceHash(const SwarmPresence& presence)
{
    std::string caps;
    for (const std::string& capability : presence.capabilities) {
        caps += capability;
        caps.push_back(',');
    }
    const std::string body = presence.peer_id + "\n" + presence.endpoint + "\n" + presence.trust_domain + "\n" +
                             std::to_string(presence.expiry_ms) + "\n" + caps;
    CSHA256 sha;
    sha.Write(reinterpret_cast<const unsigned char*>(body.data()), body.size());
    uint256 hash;
    sha.Finalize(hash.begin());
    return hash;
}

bool SwarmAcceptPresence(const SwarmPresence& presence, int64_t now_ms, std::string& err)
{
    if (presence.expiry_ms <= now_ms) {
        err = "PRESENCE_EXPIRED";
        return false;
    }
    if (presence.signature_hex.empty()) {
        err = "PRESENCE_UNSIGNED";
        return false;
    }
    if (presence.claims_checkpoint_only) {
        err = "CHECKPOINT_CLAIM_IS_NOT_TRUST";
        return false;
    }
    const std::vector<unsigned char> sig = ParseHex(presence.signature_hex);
    if (presence.pubkey.size() != MLDSA44_PUBKEY_SIZE || sig.size() != MLDSA44_SIGNATURE_SIZE) {
        err = "PRESENCE_SIGNATURE";
        return false;
    }
    const CPQPubKey pubkey(PQAlgorithm::ML_DSA_44, presence.pubkey);
    if (!pubkey.Verify(SwarmPresenceHash(presence), sig)) {
        err = "PRESENCE_SIGNATURE";
        return false;
    }
    err.clear();
    return true;
}

std::vector<SwarmRoutePeer> SwarmFallbackRoutes(const std::vector<SwarmRoutePeer>& peers,
                                                const std::vector<std::string>& chosen, int max_routes)
{
    std::vector<SwarmRoutePeer> routes;
    if (max_routes <= 0) return routes;
    const std::set<std::string> chosen_ids(chosen.begin(), chosen.end());
    std::vector<SwarmRoutePeer> eligible;
    for (const SwarmRoutePeer& peer : peers) {
        if (!peer.authorized || !peer.available || peer.id.empty()) continue;
        if (chosen_ids.count(peer.id)) continue;
        eligible.push_back(peer);
    }
    std::sort(eligible.begin(), eligible.end(), [](const SwarmRoutePeer& a, const SwarmRoutePeer& b) {
        if (a.rtt_us != b.rtt_us) return a.rtt_us < b.rtt_us;
        return a.id < b.id;
    });
    std::set<std::string> seen;
    for (const SwarmRoutePeer& peer : eligible) {
        if (static_cast<int>(routes.size()) >= max_routes) break;
        if (!seen.insert(peer.id).second) continue;
        routes.push_back(peer);
    }
    return routes;
}

SwarmAcquireState SwarmAdvanceAcquire(SwarmAcquireStep step, const SwarmAcquireState& prior, bool verified,
                                      bool visibility_private, bool idle_allowed, bool specialist,
                                      bool generation_passed, std::string& err)
{
    SwarmAcquireState next = prior;
    next.private_prompts = false;
    next.automatic_spend_atoms = "0";
    next.general_replaced = false;
    err.clear();
    switch (step) {
    case SwarmAcquireStep::Verify:
        if (!verified) {
            next.verified = false;
            next.joined = false;
            err = "ARTIFACT_UNVERIFIED";
            return next;
        }
        next.verified = true;
        return next;
    case SwarmAcquireStep::Join:
        if (!verified) {
            next.verified = false;
            next.joined = false;
            err = "ARTIFACT_UNVERIFIED";
            return next;
        }
        next.verified = true;
        next.joined = true;
        next.visibility = visibility_private ? "private" : "public";
        return next;
    case SwarmAcquireStep::Load:
        if (!next.joined) {
            next.discovered_runtime = false;
            err = "NOT_JOINED";
            return next;
        }
        next.discovered_runtime = true;
        return next;
    case SwarmAcquireStep::Use:
        next.used = true;
        return next;
    case SwarmAcquireStep::Offer:
        if (!idle_allowed) {
            next.offered = false;
            err = "IDLE_OFF";
            return next;
        }
        next.offered = true;
        return next;
    case SwarmAcquireStep::Stage:
        if (!generation_passed) {
            next.staged = false;
            err = "GENERATION_FAILED";
            return next;
        }
        next.staged = true;
        return next;
    case SwarmAcquireStep::Specialist:
        if (!specialist) {
            next.specialist_published = false;
            err = "NOT_SPECIALIST";
            return next;
        }
        next.specialist_published = true;
        next.general_replaced = false;
        return next;
    }
    return next;
}

bool SwarmSameFamily(const SwarmCompat& a, const SwarmCompat& b)
{
    return !a.lineage.empty() && a.lineage == b.lineage;
}

bool SwarmKvCompatible(const SwarmCompat& a, const SwarmCompat& b)
{
    return SwarmSameFamily(a, b) && !a.checkpoint.empty() && a.checkpoint == b.checkpoint && !a.quantization.empty() &&
           a.quantization == b.quantization;
}

bool SwarmTrainCompatible(const SwarmCompat& a, const SwarmCompat& b)
{
    return SwarmSameFamily(a, b) && !a.checkpoint.empty() && a.checkpoint == b.checkpoint && !a.recipe.empty() &&
           a.recipe == b.recipe;
}

bool SwarmStoreKnowledge(const fs::path& modeldir, const SwarmKnowledge& record, std::string& err)
{
    if (record.kind == "prompt") {
        err = "PRIVATE_PROMPT";
        return false;
    }
    if (!KnownKnowledgeKind(record.kind)) {
        err = "KNOWLEDGE_KIND";
        return false;
    }
    if (record.id.empty()) {
        err = "KNOWLEDGE_ID";
        return false;
    }
    if (record.body_digest.empty()) {
        err = "KNOWLEDGE_DIGEST";
        return false;
    }
    if (record.visibility != "public" && record.visibility != "private") {
        err = "VISIBILITY";
        return false;
    }
    std::vector<SwarmKnowledge> existing;
    if (!SwarmLoadKnowledge(modeldir, existing, err)) return false;
    existing.push_back(record);
    fs::path swarm_dir;
    if (!EnsureSwarmDir(modeldir, swarm_dir, err, "KNOWLEDGE_DIR")) return false;
    UniValue records(UniValue::VARR);
    for (const SwarmKnowledge& item : existing) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("body_digest", item.body_digest);
        row.pushKV("id", item.id);
        row.pushKV("kind", item.kind);
        row.pushKV("visibility", item.visibility);
        records.push_back(std::move(row));
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("automatic_spend_atoms", "0");
    root.pushKV("records", records);
    if (!WriteAtomic(swarm_dir / "knowledge.json", swarm_dir / "knowledge.json.tmp", root, err, "KNOWLEDGE_WRITE",
                     "KNOWLEDGE_RENAME")) {
        return false;
    }
    err.clear();
    return true;
}

bool SwarmLoadKnowledge(const fs::path& modeldir, std::vector<SwarmKnowledge>& out, std::string& err)
{
    out.clear();
    const fs::path path = modeldir / "swarm" / "knowledge.json";
    std::string raw;
    const ReadStatus status = ReadFile(path, raw);
    if (status == ReadStatus::Missing) {
        err.clear();
        return true;
    }
    if (status == ReadStatus::Error) {
        err = "KNOWLEDGE_READ";
        return false;
    }
    try {
        UniValue root;
        if (!root.read(raw) || !root.isObject() || !root.exists("records") || !root["records"].isArray()) {
            err = "KNOWLEDGE_JSON";
            return false;
        }
        if (root.exists("automatic_spend_atoms") &&
            (!root["automatic_spend_atoms"].isStr() || root["automatic_spend_atoms"].get_str() != "0")) {
            err = "KNOWLEDGE_JSON";
            return false;
        }
        std::vector<SwarmKnowledge> loaded;
        for (const UniValue& row : root["records"].getValues()) {
            if (!row.isObject() || !row.exists("kind") || !row["kind"].isStr() || !row.exists("id") ||
                !row["id"].isStr() || !row.exists("body_digest") || !row["body_digest"].isStr() ||
                !row.exists("visibility") || !row["visibility"].isStr()) {
                err = "KNOWLEDGE_JSON";
                return false;
            }
            SwarmKnowledge item;
            item.kind = row["kind"].get_str();
            item.id = row["id"].get_str();
            item.body_digest = row["body_digest"].get_str();
            item.visibility = row["visibility"].get_str();
            if (item.kind == "prompt") {
                err = "PRIVATE_PROMPT";
                return false;
            }
            loaded.push_back(std::move(item));
        }
        out = std::move(loaded);
    } catch (const std::exception&) {
        out.clear();
        err = "KNOWLEDGE_JSON";
        return false;
    }
    err.clear();
    return true;
}

std::vector<SwarmKnowledge> SwarmPublicKnowledge(const std::vector<SwarmKnowledge>& records)
{
    std::vector<SwarmKnowledge> out;
    for (const SwarmKnowledge& record : records) {
        if (record.kind == "prompt") continue;
        if (record.visibility == "public") out.push_back(record);
    }
    return out;
}

bool SwarmMayExchangeUpdates(const SwarmIsland& a, const SwarmIsland& b)
{
    if (a.local_only || b.local_only) return false;
    if (a.checkpoint.empty() || a.recipe.empty()) return false;
    return a.checkpoint == b.checkpoint && a.recipe == b.recipe;
}

SwarmIsland SwarmForkBranch(const SwarmIsland& parent, const std::string& checkpoint, const std::string& recipe,
                            std::string& err)
{
    SwarmIsland fork;
    fork.checkpoint = checkpoint;
    fork.recipe = recipe;
    fork.local_only = parent.local_only;
    fork.compatible_average = false;
    if (parent.id.empty() || checkpoint.empty() || recipe.empty()) {
        err = "ISLAND_FORK";
        return fork;
    }
    const std::string canonical = SwarmCanonical({
        {"checkpoint", checkpoint},
        {"parent", parent.id},
        {"recipe", recipe},
    });
    const std::string id = SwarmDigest("BTX/IslandFork/1", canonical);
    if (!SwarmFixedId(id)) {
        err = "ISLAND_FORK";
        return fork;
    }
    fork.id = id;
    err.clear();
    return fork;
}

SwarmMergeProposal SwarmProposeMerge(const std::string& method, bool independent_evaluation, std::string& err)
{
    SwarmMergeProposal proposal;
    proposal.automatic_spend_atoms = "0";
    proposal.accepted = false;
    if (method != "EVALUATED_MERGE" && method != "DISTILL") {
        err = "MERGE_METHOD";
        return proposal;
    }
    proposal.method = method;
    if (!independent_evaluation) {
        err = "MERGE_UNEVALUATED";
        return proposal;
    }
    proposal.accepted = true;
    err.clear();
    return proposal;
}

bool SwarmSelectKvHolder(const std::vector<SwarmPageHolder>& holders, const std::string& wanted_fingerprint,
                         int page_start, int page_end, SwarmKvSelection& out, std::string& err)
{
    out = SwarmKvSelection{};
    out.bytes_moved = false;
    if (wanted_fingerprint.empty() || page_start < 0 || page_end <= page_start) {
        err = "KV_NO_HOLDER";
        return false;
    }
    for (const SwarmPageHolder& holder : holders) {
        if (holder.peer_id.empty() || holder.fingerprint != wanted_fingerprint) continue;
        if (!RangeCovers(holder, page_start, page_end)) continue;
        out.peer_id = holder.peer_id;
        out.bytes_moved = false;
        err.clear();
        return true;
    }
    err = "KV_NO_HOLDER";
    return false;
}

} // namespace modelnet
