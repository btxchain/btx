// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_live.h>

#include <modelnet/swarm_form/atomic.h>
#include <modelnet/swarm_records.h>
#include <univalue.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool ReadRaw(const fs::path& path, std::string& raw)
{
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool EnsureDir(const fs::path& modeldir, fs::path& swarm_dir, std::string& err, const char* code)
{
    if (modeldir.empty()) {
        err = code;
        return false;
    }
    swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = code;
        return false;
    }
    return true;
}

bool WriteAtomic(const fs::path& final_path, const std::string& body, std::string& err, const char* write_code,
                 const char* rename_code)
{
    if (SwarmFormWrite(final_path, body, err)) return true;
    if (err == "WRITE") err = write_code;
    if (err == "RENAME") err = rename_code;
    return false;
}

bool FourBit(const std::string& quantization)
{
    return quantization == "4bit" || quantization == "4-bit";
}

bool PrivateKnowledge(const std::string& kind)
{
    return kind == "prompt" || kind == "repository" || kind == "credential";
}

bool PublicKnowledgeKind(const std::string& kind)
{
    return kind == "finding" || kind == "strategy" || kind == "evaluation" || kind == "adapter" || kind == "generation";
}

bool LoadTextArray(const UniValue& root, const char* key, UniValue& out, std::string& err)
{
    out = UniValue(UniValue::VARR);
    if (!root.exists(key)) return true;
    if (!root[key].isArray()) {
        err = "KNOWLEDGE_JSON";
        return false;
    }
    for (const UniValue& item : root[key].getValues()) {
        if (!item.isStr()) {
            err = "KNOWLEDGE_JSON";
            return false;
        }
        out.push_back(item.get_str());
    }
    return true;
}

void RememberLineage(std::set<std::string>& lineages, const std::string& lineage)
{
    if (lineage.empty()) return;
    lineages.insert(lineage);
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

bool WriteIfChanged(const fs::path& final_path, const std::string& body, std::string& err, const char* write_code,
                    const char* rename_code)
{
    std::string existing;
    if (ReadRaw(final_path, existing) && SameDocument(existing, body)) {
        err.clear();
        return true;
    }
    return WriteAtomic(final_path, body, err, write_code, rename_code);
}

std::string TextField(const UniValue& item, const char* key)
{
    if (!item.exists(key) || !item[key].isStr()) return {};
    return item[key].get_str();
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

struct PublishedCohort {
    std::string lineage;
    std::string checkpoint;
    std::string recipe;
    std::vector<std::string> members;
};

} // namespace

bool SwarmPublishLive(const fs::path& modeldir, std::string& err)
{
    const fs::path contribution = modeldir / "swarm" / "contribution.json";
    if (!fs::exists(contribution)) {
        err.clear();
        return true;
    }
    std::string raw;
    if (!ReadRaw(contribution, raw)) {
        err = "CONTRIBUTION_READ";
        return false;
    }
    UniValue root;
    if (!root.read(raw) || !root.isObject() || !root.exists("models") || !root["models"].isArray()) {
        err = "CONTRIBUTION_JSON";
        return false;
    }

    std::map<std::string, std::vector<std::string>> family_ids;
    std::map<std::string, UniValue> family_rows;
    std::map<CohortKey, PublishedCohort> cohorts;
    std::set<std::string> lineages;
    for (const UniValue& item : root["models"].getValues()) {
        if (!item.isObject()) continue;
        if (!item.exists("acquire") || !item["acquire"].isStr() || item["acquire"].get_str() != "joined") continue;
        if (!item.exists("artifact_id") || !item["artifact_id"].isStr()) continue;
        const std::string artifact = item["artifact_id"].get_str();
        if (artifact.empty()) continue;
        const std::string lineage = TextField(item, "lineage_id");
        const std::string checkpoint = TextField(item, "checkpoint_id");
        std::string recipe = TextField(item, "recipe");
        if (recipe.empty()) recipe = TextField(item, "recipe_id");
        RememberLineage(lineages, lineage);
        family_ids[lineage].push_back(artifact);
        if (!family_rows.count(lineage)) family_rows[lineage] = UniValue(UniValue::VARR);
        const bool cohort = item.exists("cohort") && item["cohort"].isTrue();
        const bool kv_share = item.exists("kv_share") && item["kv_share"].isTrue();
        UniValue member(UniValue::VOBJ);
        member.pushKV("artifact_id", artifact);
        member.pushKV("checkpoint_id", checkpoint);
        member.pushKV("cohort", cohort);
        member.pushKV("kv_share", kv_share);
        member.pushKV("recipe", recipe);
        family_rows[lineage].push_back(std::move(member));
        const std::string quantization = TextField(item, "quantization");
        // A 4-bit row stays in the family and stays out of the cohort.
        if (!cohort || FourBit(quantization)) continue;
        PublishedCohort& published = cohorts[{lineage, checkpoint, recipe}];
        published.lineage = lineage;
        published.checkpoint = checkpoint;
        published.recipe = recipe;
        published.members.push_back(artifact);
    }

    UniValue families(UniValue::VARR);
    for (const auto& [lineage, ids] : family_ids) {
        UniValue row(UniValue::VOBJ);
        UniValue member_ids(UniValue::VARR);
        for (const std::string& id : ids) member_ids.push_back(id);
        row.pushKV("lineage_id", lineage);
        row.pushKV("member_artifact_ids", member_ids);
        row.pushKV("members", family_rows[lineage]);
        families.push_back(std::move(row));
    }
    UniValue cohort_rows(UniValue::VARR);
    for (const auto& [key, published] : cohorts) {
        (void)key;
        UniValue row(UniValue::VOBJ);
        UniValue member_ids(UniValue::VARR);
        for (const std::string& id : published.members) member_ids.push_back(id);
        row.pushKV("checkpoint_id", published.checkpoint);
        row.pushKV("lease_slots", 0);
        row.pushKV("lease_until_ms", 0);
        row.pushKV("lineage_id", published.lineage);
        row.pushKV("member_ids", member_ids);
        row.pushKV("recipe_id", published.recipe);
        cohort_rows.push_back(std::move(row));
    }

    UniValue family(UniValue::VOBJ);
    UniValue family_members(UniValue::VARR);
    std::string family_lineage;
    if (family_ids.size() == 1) {
        family_lineage = family_ids.begin()->first;
        for (const std::string& id : family_ids.begin()->second) family_members.push_back(id);
    }
    family.pushKV("lineage_id", family_lineage);
    family.pushKV("member_artifact_ids", family_members);

    UniValue cohort(UniValue::VOBJ);
    std::string cohort_checkpoint;
    std::string cohort_recipe;
    std::string cohort_lineage;
    UniValue cohort_members(UniValue::VARR);
    if (cohorts.size() == 1) {
        const PublishedCohort& only = cohorts.begin()->second;
        cohort_checkpoint = only.checkpoint;
        cohort_recipe = only.recipe;
        cohort_lineage = only.lineage;
        for (const std::string& id : only.members) cohort_members.push_back(id);
    }
    cohort.pushKV("checkpoint_id", cohort_checkpoint);
    cohort.pushKV("lease_slots", 0);
    cohort.pushKV("lease_until_ms", 0);
    cohort.pushKV("lineage_id", cohort_lineage);
    cohort.pushKV("member_ids", cohort_members);
    cohort.pushKV("recipe_id", cohort_recipe);

    UniValue neighborhood(UniValue::VOBJ);
    neighborhood.pushKV("peer_ids", UniValue(UniValue::VARR));
    UniValue frontier(UniValue::VOBJ);
    frontier.pushKV("candidate_ids", UniValue(UniValue::VARR));
    UniValue networks(UniValue::VOBJ);
    networks.pushKV("automatic_spend_atoms", "0");
    networks.pushKV("cohort", cohort);
    networks.pushKV("cohorts", cohort_rows);
    networks.pushKV("family", family);
    networks.pushKV("families", families);
    networks.pushKV("frontier", frontier);
    networks.pushKV("neighborhood", neighborhood);

    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err, "NETWORKS_DIR")) return false;
    if (!WriteIfChanged(swarm_dir / "networks.json", networks.write(0, 0) + "\n", err, "NETWORKS_WRITE",
                        "NETWORKS_RENAME")) {
        return false;
    }

    UniValue immediate(UniValue::VARR);
    UniValue short_term(UniValue::VARR);
    UniValue medium(UniValue::VARR);
    UniValue long_term(UniValue::VARR);
    for (const std::string& lineage : lineages) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("lineage_id", lineage);
        long_term.push_back(std::move(row));
    }
    UniValue times(UniValue::VOBJ);
    times.pushKV("automatic_spend_atoms", "0");
    times.pushKV("general_stable", "unchanged");
    times.pushKV("immediate", immediate);
    times.pushKV("long", long_term);
    times.pushKV("medium", medium);
    times.pushKV("short", short_term);
    return WriteIfChanged(swarm_dir / "timescales.json", times.write(0, 0) + "\n", err, "TIMESCALE_WRITE",
                          "TIMESCALE_RENAME");
}

bool SwarmStorePublicKnowledge(const fs::path& modeldir, const std::string& kind, const std::string& body,
                               std::string& err)
{
    if (PrivateKnowledge(kind)) {
        err = "PRIVATE_DATA";
        return false;
    }
    if (!PublicKnowledgeKind(kind)) {
        err = "KNOWLEDGE_KIND";
        return false;
    }

    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err, "KNOWLEDGE_DIR")) return false;
    const fs::path path = swarm_dir / "knowledge.json";
    UniValue finding(UniValue::VARR);
    UniValue strategy(UniValue::VARR);
    UniValue evaluation(UniValue::VARR);
    UniValue adapter(UniValue::VARR);
    UniValue generation(UniValue::VARR);
    if (fs::exists(path)) {
        std::string raw;
        UniValue existing;
        if (!ReadRaw(path, raw) || !existing.read(raw) || !existing.isObject()) {
            err = "KNOWLEDGE_JSON";
            return false;
        }
        if (!LoadTextArray(existing, "finding", finding, err) || !LoadTextArray(existing, "strategy", strategy, err) ||
            !LoadTextArray(existing, "evaluation", evaluation, err) ||
            !LoadTextArray(existing, "adapter", adapter, err) ||
            !LoadTextArray(existing, "generation", generation, err)) {
            return false;
        }
    }

    // Text under the kind key. Not a digest list and not a private prompt log.
    if (kind == "finding") finding.push_back(body);
    else if (kind == "strategy") strategy.push_back(body);
    else if (kind == "evaluation") evaluation.push_back(body);
    else if (kind == "adapter") adapter.push_back(body);
    else generation.push_back(body);

    UniValue root(UniValue::VOBJ);
    root.pushKV("adapter", adapter);
    root.pushKV("automatic_spend_atoms", "0");
    root.pushKV("evaluation", evaluation);
    root.pushKV("finding", finding);
    root.pushKV("generation", generation);
    root.pushKV("private_prompt_log", false);
    root.pushKV("strategy", strategy);
    return WriteAtomic(path, root.write(0, 0) + "\n", err, "KNOWLEDGE_WRITE", "KNOWLEDGE_RENAME");
}

} // namespace modelnet
