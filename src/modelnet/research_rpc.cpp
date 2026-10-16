// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_api.h>
#include <modelnet/research_rpc.h>

#include <modelnet/git_snapshot.h>
#include <modelnet/identity.h>
#include <modelnet/model_admission.h>
#include <modelnet/pq_delegation.h>
#include <modelnet/realm_channel.h>
#include <modelnet/research_graph.h>
#include <modelnet/training_evidence.h>
#include <span.h>
#include <support/cleanse.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

bool ParseObject(const std::string& request_json, UniValue& out, std::string& err)
{
    if (!out.read(request_json) || !out.isObject()) return Fail(err, "BTX035_INVALID_SCHEMA");
    return true;
}

bool ReadUint(const UniValue& value, uint64_t& out, std::string& err)
{
    if (!value.isNum()) return Fail(err, "BTX035_INVALID_SCHEMA");
    try {
        out = value.getInt<uint64_t>();
    } catch (const std::exception&) {
        return Fail(err, "BTX035_INVALID_SCHEMA");
    }
    return true;
}

bool ReadInt(const UniValue& value, int& out, std::string& err)
{
    if (!value.isNum()) return Fail(err, "BTX035_INVALID_SCHEMA");
    try {
        out = value.getInt<int>();
    } catch (const std::exception&) {
        return Fail(err, "BTX035_INVALID_SCHEMA");
    }
    return true;
}

bool ReadStrings(const UniValue& value, std::vector<std::string>& out, std::string& err)
{
    if (!value.isArray()) return Fail(err, "BTX035_INVALID_SCHEMA");
    out.clear();
    for (const UniValue& item : value.getValues()) {
        if (!item.isStr()) return Fail(err, "BTX035_INVALID_SCHEMA");
        out.push_back(item.get_str());
    }
    return true;
}

bool RequireString(const UniValue& obj, const char* key, std::string& out, std::string& err)
{
    if (!obj.exists(key) || !obj[key].isStr()) return Fail(err, "BTX035_INVALID_SCHEMA");
    out = obj[key].get_str();
    return true;
}

bool DigestField(const UniValue& obj, const char* key, Digest48& id, std::string& err)
{
    std::string hex;
    if (!RequireString(obj, key, hex, err)) return false;
    if (!Digest48::FromHex(hex, id, err)) return Fail(err, "BTX035_INVALID_SCHEMA");
    return true;
}

bool TopicField(const UniValue& obj, Digest48& topic, std::string& err)
{
    std::string label;
    if (!RequireString(obj, "topic", label, err)) {
        err = "BTX035_TOPIC";
        return false;
    }
    if (label.size() == 96) {
        Digest48 parsed;
        std::string hex_err;
        if (Digest48::FromHex(label, parsed, hex_err)) {
            topic = parsed;
            return true;
        }
    }
    return TopicId(label, topic, err);
}

bool ContentBytes(const UniValue& req, std::vector<unsigned char>& bytes, std::string& err)
{
    if (req.exists("content")) {
        if (!req["content"].isStr()) return Fail(err, "BTX035_INVALID_SCHEMA");
        const std::string& text = req["content"].get_str();
        bytes.assign(text.begin(), text.end());
        return true;
    }
    if (req.exists("content_hex")) {
        if (!req["content_hex"].isStr()) return Fail(err, "BTX035_INVALID_SCHEMA");
        const auto raw = TryParseHex<unsigned char>(req["content_hex"].get_str());
        if (!raw) return Fail(err, "BTX035_INVALID_SCHEMA");
        bytes = *raw;
        return true;
    }
    return Fail(err, "BTX035_INVALID_SCHEMA");
}

bool IdentityCreate(const UniValue& req, UniValue& out, std::string& err)
{
    if (ResearchMaySpendWallet()) return Fail(err, "BTX035_SCOPE_DENIED");
    std::string pubkey_hex;
    if (!RequireString(req, "pubkey_hex", pubkey_hex, err)) return Fail(err, "BTX035_KEY_LENGTH");
    const auto raw = TryParseHex<unsigned char>(pubkey_hex);
    if (!raw || raw->size() != MLDSA44_PK) return Fail(err, "BTX035_KEY_LENGTH");

    IdentityChain chain;
    Digest48 root;
    if (!chain.CreateRoot(Span<const unsigned char>{raw->data(), raw->size()}, root, err)) return false;
    uint64_t epoch = 0;
    if (!chain.CurrentEpoch(root, epoch, err)) return false;

    out.pushKV("root_id", root.Hex());
    out.pushKV("epoch", epoch);
    out.pushKV("wallet_spend", false);
    return true;
}

bool IdentityGenerate(const UniValue& req, UniValue& out, std::string& err)
{
    (void)req;
    if (ResearchMaySpendWallet()) return Fail(err, "BTX035_SCOPE_DENIED");
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
    if (!GenerateMlDsa44(pk, sk, err)) return false;
    memory_cleanse(sk.data(), sk.size());
    sk.clear();
    IdentityChain chain;
    Digest48 root;
    if (!chain.CreateRoot(pk, root, err)) return false;
    out.pushKV("root_id", root.Hex());
    out.pushKV("epoch", static_cast<uint64_t>(0));
    out.pushKV("wallet_spend", false);
    out.pushKV("secret_returned", false);
    return true;
}

bool GitDigest(const UniValue& req, UniValue& out, std::string& err)
{
    std::string kind;
    if (!RequireString(req, "kind", kind, err)) return Fail(err, "BTX035_GIT_TYPE");
    std::vector<unsigned char> bytes;
    if (!ContentBytes(req, bytes, err)) return false;
    std::string digest;
    if (!GitObjectDigest(kind, Span<const unsigned char>{bytes.data(), bytes.size()}, digest, err)) return false;
    out.pushKV("kind", kind);
    out.pushKV("digest", digest);
    return true;
}

bool ResearchPublish(const UniValue& req, UniValue& out, std::string& err)
{
    Digest48 topic;
    Digest48 contribution;
    Digest48 author;
    if (!TopicField(req, topic, err)) return false;
    if (!DigestField(req, "contribution_id", contribution, err)) return false;
    if (!DigestField(req, "author_id", author, err)) return false;
    if (req.exists("negative") && !req["negative"].isBool()) return Fail(err, "BTX035_INVALID_SCHEMA");
    const bool negative = req.exists("negative") && req["negative"].isTrue();
    std::string summary;
    if (req.exists("summary")) {
        if (!req["summary"].isStr()) return Fail(err, "BTX035_INVALID_SCHEMA");
        summary = req["summary"].get_str();
    }

    ResearchBook book;
    if (!book.Publish(topic, contribution, author, negative, summary, err)) return false;
    ResearchContribution row;
    if (!book.Find(topic, contribution, row)) return Fail(err, "BTX035_CONFLICT");

    out.pushKV("topic", row.topic.Hex());
    out.pushKV("contribution_id", row.contribution_id.Hex());
    out.pushKV("author_id", row.author_id.Hex());
    out.pushKV("negative", row.negative);
    out.pushKV("summary", row.summary);
    out.pushKV("peer", book.HasPeer(author));
    return true;
}

bool ReadInterval(const UniValue& value, Interval& interval, std::string& err)
{
    if (!value.isObject()) return Fail(err, "BTX035_INVALID_SCHEMA");
    if (!ReadUint(value["start_inclusive"], interval.start_inclusive, err)) return false;
    if (!ReadUint(value["end_exclusive"], interval.end_exclusive, err)) return false;
    if (!RequireString(value, "start_state", interval.start_state, err)) return false;
    if (!RequireString(value, "end_state", interval.end_state, err)) return false;
    if (value.exists("profile") && !RequireString(value, "profile", interval.profile, err)) return false;
    if (value.exists("rng") && !RequireString(value, "rng", interval.rng, err)) return false;
    if (value.exists("optimizer") && !RequireString(value, "optimizer", interval.optimizer, err)) return false;
    if (value.exists("data_cursor") && !RequireString(value, "data_cursor", interval.data_cursor, err)) return false;
    if (value.exists("ancestry") && !RequireString(value, "ancestry", interval.ancestry, err)) return false;
    if (value.exists("publisher_only")) {
        if (!value["publisher_only"].isBool()) return Fail(err, "BTX035_INVALID_SCHEMA");
        interval.publisher_only = value["publisher_only"].isTrue();
    }
    return true;
}

bool ParseAssurance(const std::string& name, Assurance& assurance, std::string& err)
{
    if (name == "PUBLIC_STRICT") {
        assurance = Assurance::PUBLIC_STRICT;
        return true;
    }
    if (name == "REALM_STRICT") {
        assurance = Assurance::REALM_STRICT;
        return true;
    }
    if (name == "RESEARCH_ONLY") {
        assurance = Assurance::RESEARCH_ONLY;
        return true;
    }
    return Fail(err, "BTX035_ADMISSION_DENIED");
}

bool AdmitRequest(const UniValue& req, UniValue& out, std::string& err)
{
    std::string assurance_name;
    if (!RequireString(req, "assurance", assurance_name, err)) return Fail(err, "BTX035_ADMISSION_DENIED");
    Assurance assurance;
    if (!ParseAssurance(assurance_name, assurance, err)) return false;
    if (!req.exists("byte_hash_matches") || !req["byte_hash_matches"].isBool()) return Fail(err, "BTX035_INVALID_SCHEMA");
    const bool byte_hash_matches = req["byte_hash_matches"].isTrue();
    if (!req.exists("total")) return Fail(err, "BTX035_INVALID_SCHEMA");
    uint64_t total = 0;
    if (!ReadUint(req["total"], total, err)) return false;
    std::string start_state;
    std::string final_state;
    if (!RequireString(req, "start_state", start_state, err)) return false;
    if (!RequireString(req, "final_state", final_state, err)) return false;
    if (!req.exists("intervals") || !req["intervals"].isArray()) return Fail(err, "BTX035_INVALID_SCHEMA");
    std::vector<Interval> intervals;
    for (const UniValue& item : req["intervals"].getValues()) {
        Interval interval;
        if (!ReadInterval(item, interval, err)) return false;
        intervals.push_back(std::move(interval));
    }
    if (!req.exists("independent_roots")) return Fail(err, "BTX035_INVALID_SCHEMA");
    std::vector<std::string> roots;
    if (!ReadStrings(req["independent_roots"], roots, err)) return false;
    if (req.exists("owner_authorized") && !req["owner_authorized"].isBool()) return Fail(err, "BTX035_INVALID_SCHEMA");
    const bool owner_authorized = req.exists("owner_authorized") && req["owner_authorized"].isTrue();

    const AdmissionResult result = Admit(assurance, byte_hash_matches, intervals, total, start_state, final_state, roots, owner_authorized);
    out.pushKV("admitted", result.admitted);
    out.pushKV("research_execution_permit", result.research_execution_permit);
    out.pushKV("code", result.code);
    out.pushKV("serve_allowed", result.ServeAllowed());
    return true;
}

bool WanQuorum(const UniValue& req, UniValue& out, std::string& err)
{
    std::string realm;
    if (!RequireString(req, "realm", realm, err)) return Fail(err, "BTX035_REALM");
    if (!req.exists("threshold")) return Fail(err, "BTX035_THRESHOLD");
    int threshold = 0;
    if (!ReadInt(req["threshold"], threshold, err)) return false;
    if (!req.exists("pinned_ids") || !req.exists("signer_ids")) return Fail(err, "BTX035_INVALID_SCHEMA");
    std::vector<std::string> pinned;
    std::vector<std::string> signers;
    if (!ReadStrings(req["pinned_ids"], pinned, err)) return false;
    if (!ReadStrings(req["signer_ids"], signers, err)) return false;

    RealmRollout rollout;
    if (!rollout.SetPolicy(realm, threshold, pinned, err)) return false;
    out.pushKV("realm", realm);
    out.pushKV("quorum", rollout.Quorum(realm, signers));
    out.pushKV("threshold", rollout.Threshold(realm));
    return true;
}

} // namespace

bool DispatchLab035(const std::string& method, const std::string& request_json, std::string& response_json, std::string& err)
{
    response_json.clear();
    std::string api_method = method;
    if (api_method.rfind("lab035.", 0) == 0) {
        const std::string rest = api_method.substr(7);
        if (rest.find('.') == std::string::npos) api_method = "lab." + rest;
    } else if (api_method.rfind("lab.", 0) == 0) {
        api_method = method;
    }
    if (api_method.rfind("lab.", 0) == 0) {
        if (DispatchLabApi(api_method, request_json, response_json, err)) return true;
        if (err != "BTX035_NOT_IMPLEMENTED") return false;
        response_json.clear();
    }
    const bool known = method == "lab035.identity.create" || method == "lab035.identity.generate" ||
                       method == "lab035.git.digest" ||
                       method == "lab035.research.publish" || method == "lab035.admit" ||
                       method == "lab035.wan.quorum";
    if (!known) {
        err = "BTX035_NOT_IMPLEMENTED";
        return false;
    }

    UniValue req;
    if (!ParseObject(request_json, req, err)) return false;

    UniValue out(UniValue::VOBJ);
    bool ok = false;
    if (method == "lab035.identity.create") {
        ok = IdentityCreate(req, out, err);
    } else if (method == "lab035.identity.generate") {
        ok = IdentityGenerate(req, out, err);
    } else if (method == "lab035.git.digest") {
        ok = GitDigest(req, out, err);
    } else if (method == "lab035.research.publish") {
        ok = ResearchPublish(req, out, err);
    } else if (method == "lab035.admit") {
        ok = AdmitRequest(req, out, err);
    } else {
        ok = WanQuorum(req, out, err);
    }
    if (!ok) {
        response_json.clear();
        if (err.empty()) err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    if (!out.isObject() || out.empty()) {
        response_json.clear();
        err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    response_json = out.write();
    err.clear();
    return true;
}

} // namespace modelnet
