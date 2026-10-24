// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_node.h>

#include <modelnet/swarm_close.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_codec.h>
#include <modelnet/swarm_form/atomic.h>
#include <modelnet/swarm_observer.h>
#include <crypto/sha256.h>
#include <psbt.h>
#include <script/pqm.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <set>

namespace modelnet {
namespace {

bool EnsureDir(const fs::path& modeldir, fs::path& swarm_dir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = "SWARM_DIR";
        return false;
    }
    return true;
}

bool WriteAtomic(const fs::path& final_path, const std::string& body, std::string& err)
{
    return SwarmFormWrite(final_path, body, err);
}

bool ReadRaw(const fs::path& path, std::string& raw)
{
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

UniValue SortedJson(const UniValue& value)
{
    if (value.isObject()) {
        // Sort positions, not keys: value[key] and pushKV are linear scans, so
        // the old loop was quadratic in the key count of the file on disk.
        const std::vector<std::string>& keys = value.getKeys();
        const std::vector<UniValue>& values = value.getValues();
        std::vector<size_t> order(keys.size());
        for (size_t i = 0; i < order.size(); ++i) order[i] = i;
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) { return keys[a] < keys[b]; });
        UniValue out(UniValue::VOBJ);
        for (size_t n = 0; n < order.size(); ++n) {
            // A repeated key keeps its first value, as value[key] did.
            if (n > 0 && keys[order[n]] == keys[order[n - 1]]) continue;
            out.pushKVEnd(keys[order[n]], SortedJson(values[order[n]]));
        }
        return out;
    }
    if (value.isArray()) {
        UniValue out(UniValue::VARR);
        for (const UniValue& item : value.getValues()) out.push_back(SortedJson(item));
        return out;
    }
    return value;
}

bool SameDocument(const std::string& existing, const std::string& body)
{
    UniValue left;
    UniValue right;
    if (!left.read(existing) || !right.read(body)) return false;
    return SortedJson(left).write(0, 0) == SortedJson(right).write(0, 0);
}

bool WriteIfChanged(const fs::path& final_path, const std::string& body, std::string& err)
{
    std::string existing;
    if (ReadRaw(final_path, existing) && SameDocument(existing, body)) {
        err.clear();
        return true;
    }
    return WriteAtomic(final_path, body, err);
}

SwarmBuiltinOffer OfferFrom(const SwarmGovernSnapshot& snap)
{
    SwarmBuiltinOffer offer;
    offer.seed_public = snap.roles.seeder;
    offer.cpu_evaluate = snap.roles.evaluator;
    offer.gpu_train = snap.roles.trainer;
    offer.private_prompts = snap.roles.private_prompts;
    offer.startup_flag = false;
    offer.cpu_threads = snap.budget.cpu_threads;
    offer.hardware_threads = snap.hardware_threads;
    offer.vram_bytes = snap.budget.vram_bytes;
    offer.automatic_spend_atoms = "0";
    return offer;
}

struct KvIdentity {
    std::string weights;
    std::string tokenizer;
    std::string adapter_order;
    std::string runtime;
    std::string layout;
    std::string dtype;
    std::string positional_encoding;
    std::string mask;

    bool complete() const
    {
        return !weights.empty() && !tokenizer.empty() && !adapter_order.empty() && !runtime.empty() && !layout.empty() &&
               !dtype.empty() && !positional_encoding.empty() && !mask.empty();
    }

    bool operator==(const KvIdentity& other) const
    {
        return weights == other.weights && tokenizer == other.tokenizer && adapter_order == other.adapter_order &&
               runtime == other.runtime && layout == other.layout && dtype == other.dtype &&
               positional_encoding == other.positional_encoding && mask == other.mask;
    }
};

std::string TextField(const UniValue& item, const char* key)
{
    if (!item.exists(key) || !item[key].isStr()) return {};
    return item[key].get_str();
}

std::string AdapterOrder(const UniValue& item)
{
    if (!item.exists("adapter_order")) return {};
    const UniValue& value = item["adapter_order"];
    if (value.isStr()) return value.get_str();
    if (!value.isArray()) return {};
    std::string joined;
    for (const UniValue& part : value.getValues()) {
        if (!part.isStr() || part.get_str().empty()) return {};
        if (!joined.empty()) joined.push_back(',');
        joined += part.get_str();
    }
    return joined;
}

void LoadIdentities(const fs::path& modeldir, std::map<std::string, KvIdentity>& out)
{
    std::string raw;
    UniValue root;
    if (!ReadRaw(modeldir / "catalog.json", raw) || !root.read(raw) || !root.isObject() || !root.exists("models") ||
        !root["models"].isArray()) {
        return;
    }
    for (const UniValue& item : root["models"].getValues()) {
        if (!item.isObject() || !item.exists("artifact_id") || !item["artifact_id"].isStr()) continue;
        KvIdentity identity;
        identity.weights = TextField(item, "weights");
        identity.tokenizer = TextField(item, "tokenizer");
        identity.adapter_order = AdapterOrder(item);
        identity.runtime = TextField(item, "runtime");
        identity.layout = TextField(item, "layout");
        identity.dtype = TextField(item, "dtype");
        identity.positional_encoding = TextField(item, "positional_encoding");
        identity.mask = TextField(item, "mask");
        out.insert_or_assign(item["artifact_id"].get_str(), std::move(identity));
    }
}

struct CohortKey {
    std::string lineage;
    std::string checkpoint;
    std::string recipe;
    bool operator<(const CohortKey& other) const
    {
        if (lineage != other.lineage) return lineage < other.lineage;
        if (checkpoint != other.checkpoint) return checkpoint < other.checkpoint;
        return recipe < other.recipe;
    }
};

} // namespace

SwarmBuiltinOffer SwarmDefaultOffer()
{
    SwarmGovernSnapshot snap;
    std::string err;
    if (!SwarmLoadGoverned({}, snap, err)) return SwarmBuiltinOffer{};
    return OfferFrom(snap);
}

SwarmCohortDecision SwarmAssignCohort(const std::string& quantization, const std::string& checkpoint,
                                      const std::string& recipe, const std::string& family_checkpoint,
                                      const std::string& family_recipe)
{
    SwarmCohortDecision decision;
    decision.quantization = quantization;
    decision.family = true;
    const bool same = !checkpoint.empty() && checkpoint == family_checkpoint && !recipe.empty() && recipe == family_recipe;
    decision.cohort = same && quantization == "full";
    decision.kv_share = false;
    return decision;
}

bool SwarmIntegrateCatalog(const fs::path& modeldir, std::string& err)
{
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    SwarmCatalog catalog;
    if (!SwarmReadCatalog(modeldir, catalog, err)) return false;
    SwarmGovernSnapshot governed;
    if (!SwarmLoadGoverned(modeldir, governed, err)) return false;
    const SwarmBuiltinOffer offer = OfferFrom(governed);
    std::map<std::string, KvIdentity> identities;
    LoadIdentities(modeldir, identities);
    struct Joined {
        std::string artifact;
        SwarmCatalogEntry entry;
        KvIdentity identity;
    };
    std::vector<Joined> joined;
    joined.reserve(catalog.size());
    for (const auto& [artifact, entry] : catalog) {
        Joined row;
        row.artifact = artifact;
        row.entry = entry;
        const auto found = identities.find(artifact);
        if (found != identities.end()) row.identity = found->second;
        joined.push_back(std::move(row));
    }
    std::map<CohortKey, std::vector<size_t>> groups;
    for (size_t i = 0; i < joined.size(); ++i) {
        const SwarmCatalogEntry& entry = joined[i].entry;
        if (entry.quantization == "full" && !entry.checkpoint.empty() && !entry.recipe.empty()) {
            groups[{entry.lineage_id, entry.checkpoint, entry.recipe}].push_back(i);
        }
    }
    std::vector<bool> share(joined.size(), false);
    for (const auto& [key, members] : groups) {
        (void)key;
        if (members.empty() || !joined[members[0]].identity.complete()) continue;
        const KvIdentity& first = joined[members[0]].identity;
        bool equal = true;
        for (size_t index : members) {
            if (!(joined[index].identity == first)) {
                equal = false;
                break;
            }
        }
        if (!equal) continue;
        for (size_t index : members) share[index] = true;
    }
    UniValue models(UniValue::VARR);
    for (size_t i = 0; i < joined.size(); ++i) {
        const SwarmCatalogEntry& entry = joined[i].entry;
        const bool is_public = entry.visibility == "public";
        const bool cohort = entry.quantization == "full" && !entry.checkpoint.empty() && !entry.recipe.empty();
        UniValue row(UniValue::VOBJ);
        row.pushKV("acquire", "joined");
        row.pushKV("artifact_id", joined[i].artifact);
        row.pushKV("checkpoint_id", entry.checkpoint);
        row.pushKV("cohort", cohort);
        row.pushKV("economy_id", SwarmEconomyIdentity(entry.lineage_id));
        row.pushKV("family", true);
        row.pushKV("kv_share", static_cast<bool>(share[i]));
        row.pushKV("lineage_assurance", entry.lineage_assurance);
        row.pushKV("lineage_id", entry.lineage_id);
        row.pushKV("model_id", entry.model_id);
        row.pushKV("private_acquire", !is_public);
        row.pushKV("quantization", entry.quantization);
        row.pushKV("recipe", entry.recipe);
        row.pushKV("seed", is_public && offer.seed_public);
        models.push_back(std::move(row));
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("automatic_spend_atoms", offer.automatic_spend_atoms);
    out.pushKV("cpu_evaluate", offer.cpu_evaluate);
    out.pushKV("cpu_threads", offer.cpu_threads);
    out.pushKV("gpu_train", offer.gpu_train);
    out.pushKV("hardware_threads", offer.hardware_threads);
    out.pushKV("models", models);
    out.pushKV("private_prompts", offer.private_prompts);
    out.pushKV("seed_public", offer.seed_public);
    out.pushKV("startup_flag", offer.startup_flag);
    out.pushKV("vram_bytes", offer.vram_bytes);
    return WriteIfChanged(swarm_dir / "contribution.json", out.write(0, 0) + "\n", err);
}

bool SwarmNotePresence(const fs::path& modeldir, const SwarmPresence& presence, int64_t now_ms, std::string& err)
{
    if (!SwarmAcceptPresence(presence, now_ms, err)) return false;
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    const fs::path path = swarm_dir / "seen-presence.json";
    std::set<std::string> seen;
    if (fs::exists(path)) {
        std::string raw;
        UniValue root;
        if (!ReadRaw(path, raw) || !root.read(raw) || !root.isObject() || !root.exists("signatures")) {
            err = "PRESENCE_SEEN";
            return false;
        }
        for (const UniValue& item : root["signatures"].getValues()) {
            if (item.isStr()) seen.insert(item.get_str());
        }
    }
    if (seen.count(presence.signature_hex) != 0) {
        err = "PRESENCE_REPLAY";
        return false;
    }
    seen.insert(presence.signature_hex);
    UniValue out(UniValue::VOBJ);
    UniValue sigs(UniValue::VARR);
    for (const std::string& sig : seen) sigs.push_back(sig);
    out.pushKV("signatures", sigs);
    return WriteAtomic(path, out.write(0, 0) + "\n", err);
}

bool SwarmValidateSepPolicy(const SwarmSepPolicy& policy, std::string& err)
{
    if (policy.expiry_height <= 0 || policy.backing_manifest.empty() || policy.liquidity_policy.empty() ||
        policy.max_pending <= 0 || policy.settlement_policy.empty() || policy.reward_schedule.empty() ||
        policy.dispute_policy.empty() || policy.evidence.empty() || policy.quorum < 1 ||
        policy.coordinator_id.empty() || policy.spend_limit != 0 || policy.custody != "external") {
        err = "SEP_POLICY";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmBuildFunding(const std::vector<unsigned char>& sponsor, const std::vector<unsigned char>& worker,
                       int64_t value, int64_t refund_height, SwarmFundingBundle& out, std::string& err)
{
    out.funding = CMutableTransaction();
    out.refund = CMutableTransaction();
    out.refund_bound = false;
    out.funded = false;
    if (value <= 0 || refund_height <= 0) {
        err = "FUNDING_TERMS";
        return false;
    }
    const std::vector<unsigned char> script = BuildP2MRMultisigScript(
        2, {{PQAlgorithm::ML_DSA_44, sponsor}, {PQAlgorithm::ML_DSA_44, worker}});
    const std::vector<unsigned char> refund_leaf = BuildP2MRRefundLeaf(refund_height, PQAlgorithm::ML_DSA_44, sponsor);
    if (script.empty() || refund_leaf.empty()) {
        err = "FUNDING_SCRIPT";
        return false;
    }
    out.funding.vout.emplace_back(value, CScript(script.begin(), script.end()));
    out.refund.vin.emplace_back(COutPoint(out.funding.GetHash(), 0));
    out.refund.vout.emplace_back(value, CScript(refund_leaf.begin(), refund_leaf.end()));
    out.refund_bound = out.refund.vin[0].prevout.hash == out.funding.GetHash() && out.refund.vin[0].prevout.n == 0;
    out.funded = false;
    if (!out.refund_bound) {
        err = "REFUND_UNBOUND";
        return false;
    }
    out.funded = true;
    err.clear();
    return true;
}

bool SwarmRefundPsbt(const SwarmFundingBundle& bundle, PartiallySignedTransaction& psbt, std::string& err)
{
    if (!bundle.refund_bound || !bundle.funded || bundle.refund.vin.empty()) {
        err = "REFUND_UNBOUND";
        return false;
    }
    psbt = PartiallySignedTransaction(bundle.refund);
    if (!psbt.tx || psbt.tx->vin[0].prevout.hash != bundle.funding.GetHash()) {
        err = "REFUND_UNBOUND";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmBuildWorkerRedeem(const Txid& funding, int64_t capacity, int64_t previous, int64_t cumulative, int height,
                            int refund_height, const std::vector<unsigned char>& worker_script,
                            const std::vector<unsigned char>& sponsor_script, CMutableTransaction& tx, std::string& err)
{
    tx = CMutableTransaction{};
    if (cumulative < previous) {
        err = "DECREASING_PAYMENT";
        return false;
    }
    if (cumulative > capacity || worker_script.empty() || sponsor_script.empty()) {
        err = "PAYOUT_OUTPUT";
        return false;
    }
    if (height + 160 >= refund_height) {
        err = "EXPIRY_MARGIN";
        return false;
    }
    tx.vin.emplace_back(COutPoint(funding, 0));
    tx.vout.emplace_back(cumulative, CScript(worker_script.begin(), worker_script.end()));
    tx.vout.emplace_back(capacity - cumulative, CScript(sponsor_script.begin(), sponsor_script.end()));
    if (tx.vin[0].prevout.hash != funding) {
        err = "PAYOUT_OUTPOINT";
        return false;
    }
    err.clear();
    return true;
}

std::vector<unsigned char> SwarmCtvRelease(const uint256& claimant, uint8_t threshold,
                                           const std::vector<std::vector<unsigned char>>& pubkeys, std::string& err)
{
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> keys;
    for (const std::vector<unsigned char>& pubkey : pubkeys) {
        keys.emplace_back(PQAlgorithm::ML_DSA_44, pubkey);
    }
    const std::vector<unsigned char> script = BuildP2MRMultisigCTVScript(claimant, threshold, keys);
    if (script.empty()) {
        err = "CTV_RELEASE";
        return {};
    }
    err.clear();
    return script;
}

bool SwarmFeeBump(int64_t parent_value, int64_t claim_fee, int64_t child_fee, CMutableTransaction& parent,
                  CMutableTransaction& child, SwarmClaimFees& fees, std::string& err)
{
    parent = CMutableTransaction{};
    child = CMutableTransaction{};
    fees = SwarmClaimFees{};
    if (claim_fee < 0 || child_fee <= 0 || parent_value <= claim_fee + child_fee) {
        err = "FEE_BUMP";
        return false;
    }
    parent.vout.emplace_back(parent_value - claim_fee, CScript());
    child.vin.emplace_back(COutPoint(parent.GetHash(), 0));
    child.vout.emplace_back(parent.vout[0].nValue - child_fee, CScript());
    fees.claim_fee = claim_fee;
    fees.child_fee = child_fee;
    fees.wall_clock_is_confirmation = false;
    err.clear();
    return true;
}

bool SwarmReleaseUpstream(std::vector<bool>& held, size_t failed_index, std::string& err)
{
    if (failed_index >= held.size()) {
        err = "HOP";
        return false;
    }
    for (size_t i = 0; i <= failed_index; ++i) held[i] = false;
    err.clear();
    return true;
}

int SwarmIncomingSlack(int hops, int margin_blocks)
{
    if (hops <= 0 || margin_blocks <= 0) return 0;
    return hops * margin_blocks;
}

bool SwarmRankFull(const SwarmFullCost& cost, int64_t& net, std::string& err)
{
    net = 0;
    if (!cost.backing_verified || !cost.payment_demonstrated || !cost.terms_signed) {
        err = "UNTRUSTED";
        return false;
    }
    if (cost.accept_ppm < 0 || cost.accept_ppm > 1000000) {
        err = "ACCEPT";
        return false;
    }
    const int64_t gross = (cost.reward_per_hour * cost.accept_ppm) / 1000000;
    net = gross - cost.expense - cost.mining - cost.depreciation - cost.idle - cost.duration - cost.settlement_fee -
          cost.fx_risk;
    err.clear();
    return true;
}

bool SwarmLeaseIsland(const std::string& island_checkpoint, const std::string& island_recipe,
                      const std::string& work_checkpoint, const std::string& work_recipe, std::string& err)
{
    if (island_checkpoint.empty() || island_checkpoint != work_checkpoint || island_recipe.empty() ||
        island_recipe != work_recipe) {
        err = "LEASE_INCOMPATIBLE";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmGrantAllowsTraining(const SwarmGrants& grants)
{
    return grants.download && grants.training;
}

bool SwarmGrantAllowsRedistribution(const SwarmGrants& grants)
{
    return grants.download && grants.redistribution;
}

bool SwarmRotateHoldout(const std::string& previous, const std::string& next, bool author_sees, std::string& err)
{
    if (next.empty() || next == previous) {
        err = "HOLDOUT_REUSED";
        return false;
    }
    if (author_sees) {
        err = "HOLDOUT_LEAKED";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmStoreSpecialistSignal(const fs::path& modeldir, const std::string& kind, const std::string& payload,
                                std::string& err)
{
    if (kind != "data" && kind != "reward" && kind != "distillation") {
        err = "SIGNAL_KIND";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue root(UniValue::VOBJ);
    UniValue signals(UniValue::VARR);
    const fs::path path = swarm_dir / "specialist-signals.json";
    if (fs::exists(path)) {
        std::string raw;
        if (!ReadRaw(path, raw) || !root.read(raw) || !root.exists("signals")) {
            err = "SIGNAL_READ";
            return false;
        }
        signals = root["signals"];
    }
    UniValue row(UniValue::VOBJ);
    row.pushKV("kind", kind);
    row.pushKV("payload", payload);
    row.pushKV("replaces_general", false);
    signals.push_back(std::move(row));
    root = UniValue(UniValue::VOBJ);
    root.pushKV("general_stable", "unchanged");
    root.pushKV("signals", signals);
    return WriteAtomic(path, root.write(0, 0) + "\n", err);
}

bool SwarmRecordPayoutQuote(const std::string& provider_id, int64_t atoms, int64_t fx_unix,
                            int64_t conversion_cost_atoms, const std::string& risk_holder, const std::string& dollars,
                            SwarmPayoutQuote& out, std::string& err)
{
    out = SwarmPayoutQuote{};
    if (provider_id.empty() || atoms < 0 || fx_unix <= 0 || conversion_cost_atoms < 0 || risk_holder.empty()) {
        err = "FIAT_QUOTE";
        return false;
    }
    out.provider_id = provider_id;
    out.atoms = atoms;
    out.fx_unix = fx_unix;
    out.conversion_cost_atoms = conversion_cost_atoms;
    out.risk_holder = risk_holder;
    out.dollars = dollars;
    out.usd_is_balance = false;
    err.clear();
    return true;
}

bool SwarmModelFileCreatesObligation(bool revenue_manifest_attached)
{
    (void)revenue_manifest_attached;
    return false;
}

bool SwarmStoreMiningNote(const fs::path& modeldir, int64_t swarm_atoms_per_hour, int64_t mining_atoms_per_hour,
                          std::string& err)
{
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue root(UniValue::VOBJ);
    root.pushKV("assumption", "measurement");
    root.pushKV("mining_atoms_per_hour", mining_atoms_per_hour);
    root.pushKV("security_increased", false);
    root.pushKV("swarm_atoms_per_hour", swarm_atoms_per_hour);
    return WriteAtomic(swarm_dir / "mining-note.json", root.write(0, 0) + "\n", err);
}

bool SwarmStoreWatchtower(const fs::path& modeldir, const std::string& action, int64_t sequence,
                          const std::string& secret_hex, std::string& err)
{
    if (action.empty() || sequence < 0) {
        err = "WATCHTOWER";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue root(UniValue::VOBJ);
    root.pushKV("action", action);
    root.pushKV("secret_hex", secret_hex);
    root.pushKV("sequence", sequence);
    root.pushKV("secp_penalty", false);
    return WriteAtomic(swarm_dir / "watchtower.json", root.write(0, 0) + "\n", err);
}

bool SwarmLoadWatchtower(const fs::path& modeldir, std::string& action, int64_t& sequence, std::string& secret_hex,
                         std::string& err)
{
    std::string raw;
    UniValue root;
    if (!ReadRaw(modeldir / "swarm" / "watchtower.json", raw) || !root.read(raw) || !root.isObject()) {
        err = "WATCHTOWER_READ";
        return false;
    }
    action = root["action"].get_str();
    sequence = root["sequence"].getInt<int64_t>();
    secret_hex = root["secret_hex"].get_str();
    err.clear();
    return true;
}

bool SwarmStoreAudit(const fs::path& modeldir, const std::string& certificate_id, const std::string& economy_id,
                     std::string& err)
{
    if (!SwarmFixedId(certificate_id) || !SwarmFixedId(economy_id)) {
        err = "AUDIT_ID";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue root(UniValue::VOBJ);
    root.pushKV("certificate_id", certificate_id);
    root.pushKV("economy_id", economy_id);
    root.pushKV("exact_replay_admission", false);
    root.pushKV("realm_promotion", false);
    return WriteAtomic(swarm_dir / "audit.json", root.write(0, 0) + "\n", err);
}

bool SwarmLoadAudit(const fs::path& modeldir, std::string& certificate_id, std::string& economy_id,
                    bool& realm_promotion, bool& exact_replay, std::string& err)
{
    std::string raw;
    UniValue root;
    if (!ReadRaw(modeldir / "swarm" / "audit.json", raw) || !root.read(raw) || !root.isObject()) {
        err = "AUDIT_READ";
        return false;
    }
    certificate_id = root["certificate_id"].get_str();
    economy_id = root["economy_id"].get_str();
    realm_promotion = root["realm_promotion"].isTrue();
    exact_replay = root["exact_replay_admission"].isTrue();
    err.clear();
    return true;
}

} // namespace modelnet
