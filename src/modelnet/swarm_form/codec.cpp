// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_form/codec.h>

#include <univalue.h>

#include <algorithm>
#include <exception>

namespace modelnet {
namespace {

bool SpendIsZero(const UniValue& value)
{
    return value.isStr() && value.get_str() == kAutomaticSpend;
}

} // namespace

std::string EncodeMember(const SwarmFormMember& member)
{
    std::vector<std::string> ids = member.admitted;
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    UniValue admitted(UniValue::VARR);
    for (const std::string& id : ids) {
        admitted.push_back(id);
    }
    UniValue root(UniValue::VOBJ);
    root.pushKV("admitted", admitted);
    root.pushKV("automatic_spend", std::string(kAutomaticSpend));
    root.pushKV("cpu_thread_cap", member.cpu_thread_cap);
    root.pushKV("evaluator", member.evaluator);
    root.pushKV("family_id", member.family_id);
    root.pushKV("modelnet_on", member.modelnet_on);
    root.pushKV("node_id", member.node_id);
    root.pushKV("private_prompts", member.private_prompts);
    root.pushKV("seeder", member.seeder);
    root.pushKV("training", member.training);
    root.pushKV("vram_mib", member.vram_mib);
    return root.write(0, 0) + "\n";
}

bool DecodeMember(const std::string& raw, SwarmFormMember& out, std::string& err)
{
    UniValue root;
    if (!root.read(raw) || !root.isObject()) {
        err = "SCHEMA";
        return false;
    }
    const char* keys[] = {
        "admitted", "automatic_spend", "cpu_thread_cap", "evaluator", "family_id", "modelnet_on",
        "node_id", "private_prompts", "seeder", "training", "vram_mib",
    };
    for (const char* key : keys) {
        if (!root.exists(key)) {
            err = "SCHEMA";
            return false;
        }
    }
    try {
        if (!root["admitted"].isArray() || !root["automatic_spend"].isStr() || !root["cpu_thread_cap"].isNum() ||
            !root["evaluator"].isBool() || !root["family_id"].isStr() || !root["modelnet_on"].isBool() ||
            !root["node_id"].isStr() || !root["private_prompts"].isBool() || !root["seeder"].isBool() ||
            !root["training"].isBool() || !root["vram_mib"].isNum()) {
            err = "SCHEMA";
            return false;
        }
        if (!SpendIsZero(root["automatic_spend"])) {
            err = "SPEND";
            return false;
        }
        SwarmFormMember member;
        member.automatic_spend = root["automatic_spend"].get_str();
        member.cpu_thread_cap = root["cpu_thread_cap"].getInt<int>();
        member.evaluator = root["evaluator"].get_bool();
        member.family_id = root["family_id"].get_str();
        member.modelnet_on = root["modelnet_on"].get_bool();
        member.node_id = root["node_id"].get_str();
        member.private_prompts = root["private_prompts"].get_bool();
        member.seeder = root["seeder"].get_bool();
        member.training = root["training"].get_bool();
        member.vram_mib = root["vram_mib"].getInt<int64_t>();
        if (member.node_id.empty() || member.family_id.empty()) {
            err = "SCHEMA";
            return false;
        }
        for (const UniValue& item : root["admitted"].getValues()) {
            if (!item.isStr() || item.get_str().empty()) {
                err = "SCHEMA";
                return false;
            }
            member.admitted.push_back(item.get_str());
        }
        std::sort(member.admitted.begin(), member.admitted.end());
        if (std::adjacent_find(member.admitted.begin(), member.admitted.end()) != member.admitted.end()) {
            err = "SCHEMA";
            return false;
        }
        out = std::move(member);
    } catch (const std::exception&) {
        err = "SCHEMA";
        return false;
    }
    err.clear();
    return true;
}

std::string EncodeElection(const std::string& leader, uint64_t epoch)
{
    UniValue root(UniValue::VOBJ);
    root.pushKV("automatic_spend", std::string(kAutomaticSpend));
    root.pushKV("epoch", epoch);
    root.pushKV("leader", leader);
    return root.write(0, 0) + "\n";
}

bool DecodeElection(const std::string& raw, std::string& leader, uint64_t& epoch, std::string& err)
{
    UniValue root;
    if (!root.read(raw) || !root.isObject()) {
        err = "SCHEMA";
        return false;
    }
    if (!root.exists("automatic_spend") || !root.exists("epoch") || !root.exists("leader")) {
        err = "SCHEMA";
        return false;
    }
    try {
        if (!root["automatic_spend"].isStr() || !root["epoch"].isNum() || !root["leader"].isStr()) {
            err = "SCHEMA";
            return false;
        }
        if (!SpendIsZero(root["automatic_spend"])) {
            err = "SPEND";
            return false;
        }
        const uint64_t parsed_epoch = root["epoch"].getInt<uint64_t>();
        if (parsed_epoch < 1) {
            err = "SCHEMA";
            return false;
        }
        leader = root["leader"].get_str();
        epoch = parsed_epoch;
    } catch (const std::exception&) {
        err = "SCHEMA";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
