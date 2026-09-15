// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/setup_common.h>
#include <rpc/register.h>
#include <rpc/server.h>
#include <crypto/sha256.h>
#include <modelnet/acl.h>
#include <modelnet/catalog.h>
#include <modelnet/cores.h>
#include <modelnet/crypto.h>
#include <modelnet/crypto.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/identity.h>
#include <modelnet/policy.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <modelnet/records.h>
#include <modelnet/release.h>
#include <modelnet/resource_uri.h>
#include <modelnet/router.h>
#include <modelnet/store.h>
#include <modelnet/swarm.h>
#include <modelnet/transfer.h>
#include <modelnet/pq1_runtime.h>
#include <thread>
#include <chrono>
#include <unistd.h>
#include <protocol.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <crypto/common.h>
#include <crypto/sha384.h>
#include <fstream>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <tinyformat.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <set>

BOOST_FIXTURE_TEST_SUITE(modelnet_tests, BasicTestingSetup)

static UniValue LoadVectors()
{
    std::ifstream in{MODELNET_V11_VECTORS_PATH};
    BOOST_REQUIRE(in);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue v;
    BOOST_REQUIRE(v.read(raw));
    return v;
}

BOOST_AUTO_TEST_CASE(sha384_nist_abc)
{
    CSHA384 hasher;
    hasher.Write(UCharCast("abc"), 3);
    unsigned char out[48];
    hasher.Finalize(out);
    BOOST_CHECK_EQUAL(HexStr(Span{out, 48}),
                      "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
}

BOOST_AUTO_TEST_CASE(resource_vectors)
{
    const UniValue vectors = LoadVectors();
    for (const auto& v : vectors["resource_vectors"].getValues()) {
        modelnet::Digest48 d;
        std::string err;
        BOOST_REQUIRE(modelnet::Digest48::FromHex(v["digest"].get_str(), d, err));
        modelnet::ResourceKind kind;
        BOOST_REQUIRE(modelnet::ResourceKindFromInt(v["kind"].getInt<int>(), kind));
        std::string uri;
        BOOST_REQUIRE(modelnet::EncodeResource(kind, d, uri, err));
        BOOST_CHECK_EQUAL(uri, v["uri"].get_str());
        BOOST_CHECK_EQUAL(uri.size(), 91U);
        BOOST_CHECK_EQUAL(uri.substr(6).size(), 85U);
        modelnet::Resource r;
        BOOST_REQUIRE(modelnet::DecodeResource(uri, r, err));
        BOOST_CHECK_EQUAL(r.Uri(), uri);
        BOOST_CHECK(r.digest == d);
        BOOST_CHECK(r.kind == kind);
        std::string path, host;
        BOOST_REQUIRE(modelnet::BridgePath(uri, "https://bridge.example.org", path, err));
        BOOST_CHECK_EQUAL(path, v["bridge_path"].get_str());
        BOOST_REQUIRE(modelnet::SplitBridgeHost(uri, "bridge.example.org", host, err));
        BOOST_CHECK_EQUAL(host, v["split_bridge_hostname"].get_str());
    }
}

BOOST_AUTO_TEST_CASE(resource_mutations_and_forms)
{
    std::vector<unsigned char> digest(48);
    for (int i = 0; i < 48; ++i) digest[i] = static_cast<unsigned char>(i);
    modelnet::Digest48 d;
    std::copy(digest.begin(), digest.end(), d.data.begin());
    std::string uri, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, d, uri, err));
    BOOST_CHECK_EQUAL(uri.size(), 91U);
    const std::string token = uri.substr(6);
    static const std::string alphabet{"qpzry9x8gf2tvdw0s3jn54khce6mua7l"};
    modelnet::Resource r;
    for (size_t i = 0; i < token.size(); ++i) {
        for (char c : alphabet) {
            if (c == token[i]) continue;
            std::string mut = token;
            mut[i] = c;
            BOOST_CHECK(!modelnet::DecodeResource("btx://" + mut, r, err));
        }
    }
    BOOST_REQUIRE(modelnet::DecodeResource(uri, r, err));
    BOOST_REQUIRE(modelnet::DecodeResource(token, r, err));
    BOOST_REQUIRE(modelnet::DecodeResource("btx:" + token, r, err));
    BOOST_REQUIRE(modelnet::DecodeResource(uri + "/", r, err));
    std::string upper = uri;
    for (char& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    BOOST_REQUIRE(modelnet::DecodeResource(upper, r, err));
    std::string mixed = token;
    for (size_t i = 0; i < mixed.size(); ++i) {
        if (std::isalpha(static_cast<unsigned char>(mixed[i]))) {
            mixed[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(mixed[i])));
            break;
        }
    }
    BOOST_CHECK(!modelnet::DecodeResource(mixed, r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "?pay=1", r, err));
    BOOST_CHECK(!modelnet::DecodeResource(uri + "#run", r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx://m/" + token, r, err));
    BOOST_CHECK(!modelnet::DecodeResource("btx1" + token, r, err));
    std::string origin_err;
    std::string dummy;
    BOOST_CHECK(!modelnet::BridgePath(uri, "http://example.org", dummy, origin_err));
}

BOOST_AUTO_TEST_CASE(record_vectors)
{
    const UniValue vectors = LoadVectors();
    for (const auto& v : vectors["record_vectors"].getValues()) {
        const uint8_t kind = static_cast<uint8_t>(v["kind"].getInt<int>());
        std::vector<unsigned char> encoded;
        std::string err;
        BOOST_REQUIRE(modelnet::EncodeRecord(kind, v["body"], encoded, err));
        BOOST_CHECK_EQUAL(HexStr(encoded), v["encoded_hex"].get_str());
        UniValue decoded;
        BOOST_REQUIRE(modelnet::DecodeRecord(kind, encoded, decoded, err));
        modelnet::Digest48 id, msg;
        BOOST_REQUIRE(modelnet::RecordId(kind, v["body"], id, err));
        BOOST_CHECK_EQUAL(id.Hex(), v["object_id"].get_str());
        BOOST_REQUIRE(modelnet::SigningMessage(kind, v["body"], msg, err));
        BOOST_CHECK_EQUAL(msg.Hex(), v["signing_message"].get_str());
        auto extra = encoded;
        extra.push_back(0);
        BOOST_CHECK(!modelnet::DecodeRecord(kind, extra, decoded, err));
        if (!encoded.empty()) {
            std::vector<unsigned char> trunc(encoded.begin(), encoded.end() - 1);
            BOOST_CHECK(!modelnet::DecodeRecord(kind, trunc, decoded, err));
        }
    }
}

BOOST_AUTO_TEST_CASE(free_first_and_reciprocity)
{
    modelnet::PaidPlan paid;
    paid.price_atoms = 100;
    paid.fee_atoms = 1;
    paid.total_eta_s = 10;
    modelnet::PlanChoice choice;
    std::string err;
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, 50, &paid, 0, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::FREE);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_ONLY, std::nullopt, &paid, 0, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::WAIT_FREE);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_APPROVAL, 50, &paid, 1000, true, std::nullopt, 100, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::APPROVAL_REQUIRED);
    BOOST_REQUIRE(modelnet::ChoosePlan(modelnet::RetrievalMode::FREE_FIRST_BUDGET, std::nullopt, &paid, 1000, true, std::nullopt, 0, false, choice, err));
    BOOST_CHECK(choice == modelnet::PlanChoice::PAID);

    modelnet::ReciprocityLedger ledger;
    BOOST_CHECK(ledger.Received("p1", "art", 0, 0, 64 * 1024 * 1024, 0, true, true, false, 1));
    BOOST_CHECK(!ledger.Received("p2", "art", 0, 0, 64 * 1024 * 1024, 0, true, true, false, 1)); // cross-peer dedupe
    BOOST_CHECK(ledger.Weight("p1", 0) >= 1);
    BOOST_CHECK(ledger.Received("new", "art2", 0, 1, 1024, 0, true, true, false, 8));
    BOOST_CHECK(modelnet::DecideAcl(false, true, false, false, false, false, false, false) == modelnet::AclDecision::REJECT_CRYPTO);
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, false, false, true, false) == modelnet::AclDecision::REQUIRE_SPEND_APPROVAL);
    BOOST_CHECK(modelnet::DecideAcl(true, true, false, false, false, false, false, false) == modelnet::AclDecision::ALLOW);
    auto lanes = modelnet::LaneSequence({{"bootstrap", 2}, {"reciprocal", 3}, {"preservation", 1}}, 10);
    BOOST_CHECK(!lanes.empty());
}

BOOST_AUTO_TEST_CASE(store_and_paths)
{
    std::string err;
    BOOST_CHECK(!modelnet::IsPortableRelPath("../etc/passwd", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("/abs", err));
    BOOST_CHECK(modelnet::IsPortableRelPath("model.safetensors", err));
    const std::string payload = "hello-modelnet-piece";
    std::vector<unsigned char> file(payload.begin(), payload.end());
    const auto rows = modelnet::BuildChunkTree(file);
    BOOST_REQUIRE(!rows.empty());
    const auto proof = modelnet::PieceProof(rows, 0);
    BOOST_CHECK(modelnet::VerifyPiece(rows.back()[0], file.size(), 0, file, proof));
    std::vector<unsigned char> corrupt = file;
    corrupt[0] ^= 0xff;
    BOOST_CHECK(!modelnet::VerifyPiece(rows.back()[0], file.size(), 0, corrupt, proof));

    const fs::path tmp = m_args.GetDataDirBase() / "modelstore";
    modelnet::ModelStore store{tmp, /*quota*/ 1024};
    modelnet::Digest48 art{};
    art.data[0] = 1;
    const auto leaf = modelnet::ChunkLeaf(0, file);
    BOOST_REQUIRE(store.PutVerifiedPiece(art, 0, 0, file, leaf, err));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetPiece(art, 0, 0, got, err));
    BOOST_CHECK(got == file);
    std::vector<unsigned char> big(2000, 'x');
    const auto leaf2 = modelnet::ChunkLeaf(1, big);
    BOOST_CHECK(!store.PutVerifiedPiece(art, 0, 1, big, leaf2, err));
}

BOOST_AUTO_TEST_CASE(demand_seed_and_preserve_rare_policy)
{
    uint64_t bytes = 0;
    std::string err;
    BOOST_REQUIRE(modelnet::ParseModelBytes("80GiB", bytes, err));
    BOOST_CHECK_EQUAL(bytes, 80ULL << 30);
    BOOST_REQUIRE(modelnet::ParseModelBytes("500G", bytes, err));
    BOOST_CHECK_EQUAL(bytes, 500ULL << 30);
    BOOST_REQUIRE(modelnet::ParseModelBytes("85899345920", bytes, err));
    BOOST_CHECK_EQUAL(bytes, 85899345920ULL);

    modelnet::PreservationPolicy auto_p;
    auto_p.storage_quota_bytes = 80ULL << 30;
    auto_p.seed_mode = modelnet::SeedMode::AUTO;
    auto_p.seed_upon_download = true;
    BOOST_CHECK(modelnet::ShouldDemandSeed(auto_p, modelnet::AdmissionLevel::STRUCTURE_VERIFIED));
    BOOST_CHECK(!modelnet::ShouldDemandSeed(auto_p, modelnet::AdmissionLevel::FAILED));
    auto_p.storage_quota_bytes = 0;
    BOOST_CHECK(!modelnet::ShouldDemandSeed(auto_p, modelnet::AdmissionLevel::STRUCTURE_VERIFIED));

    modelnet::PreservationPolicy off_p;
    off_p.storage_quota_bytes = 80ULL << 30;
    off_p.seed_mode = modelnet::SeedMode::OFF;
    off_p.seed_upon_download = false;
    BOOST_CHECK(!modelnet::ShouldDemandSeed(off_p, modelnet::AdmissionLevel::STRUCTURE_VERIFIED));

    modelnet::PreservationPolicy rare;
    rare.storage_quota_bytes = 500ULL << 30;
    rare.preserve_rare = true;
    BOOST_CHECK(modelnet::MayPreserveFetch(rare, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 1, 70ULL << 30, 200ULL << 30));
    BOOST_CHECK(!modelnet::MayPreserveFetch(rare, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 8, 70ULL << 30, 200ULL << 30));
    BOOST_CHECK(!modelnet::MayPreserveFetch(rare, modelnet::AdmissionLevel::BYTES_VERIFIED, true, 1, 10, 200ULL << 30));
    rare.preserve_rare = false;
    BOOST_CHECK(!modelnet::MayPreserveFetch(rare, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 1, 10, 200ULL << 30));

    modelnet::PreservationPolicy follow;
    follow.storage_quota_bytes = 80ULL << 30;
    follow.seed_mode = modelnet::SeedMode::AUTO;
    follow.follow_configured_peers = true;
    BOOST_CHECK(modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 10ULL << 30, 40ULL << 30));
    BOOST_CHECK(!modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 50ULL << 30, 40ULL << 30));
    follow.seed_mode = modelnet::SeedMode::OFF;
    BOOST_CHECK(!modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 10ULL << 30, 40ULL << 30));
    follow.seed_mode = modelnet::SeedMode::AUTO;
    follow.follow_configured_peers = false;
    BOOST_CHECK(!modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 10ULL << 30, 40ULL << 30));
    follow.follow_configured_peers = true;
    BOOST_CHECK(!modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, true, 10ULL << 30, 40ULL << 30));
    follow.allow_encrypted = true;
    BOOST_CHECK(modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, true, 10ULL << 30, 40ULL << 30));
    follow.allow_encrypted = false;
    follow.storage_quota_bytes = 0;
    BOOST_CHECK(!modelnet::MayFollowConfiguredPeer(follow, modelnet::AdmissionLevel::BYTES_VERIFIED, false, 10ULL << 30, 40ULL << 30));
    follow.storage_quota_bytes = 80ULL << 30;

    modelnet::PreserveCandidate granite, tiny, follow_pick;
    granite.model_id.data[0] = 9;
    granite.bytes = 13ULL << 30;
    granite.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
    granite.observed_sources = 8;
    tiny.model_id.data[0] = 3;
    tiny.bytes = 1ULL << 20;
    tiny.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
    follow.follow_configured_peers = true;
    follow.storage_quota_bytes = 80ULL << 30;
    std::set<modelnet::Digest48> follow_local;
    BOOST_REQUIRE(modelnet::SelectPeerFollow({granite, tiny}, follow_local, 20ULL << 30, follow, follow_pick));
    BOOST_CHECK_EQUAL(follow_pick.model_id.data[0], 3);
    BOOST_REQUIRE(modelnet::SelectPeerFollow({granite}, follow_local, 20ULL << 30, follow, follow_pick));
    BOOST_CHECK_EQUAL(follow_pick.model_id.data[0], 9);
    modelnet::PreserveCandidate cipher = granite;
    cipher.model_id.data[0] = 7;
    cipher.encrypted = true;
    cipher.bytes = 1ULL << 20;
    BOOST_REQUIRE(modelnet::SelectPeerFollow({cipher, granite}, follow_local, 20ULL << 30, follow, follow_pick));
    BOOST_CHECK_EQUAL(follow_pick.model_id.data[0], 9);
    const UniValue follow_json = modelnet::PolicyToJson(follow);
    BOOST_CHECK(follow_json["peer_follow_propagation"].get_bool());
    BOOST_CHECK(follow_json["follow_configured_peers"].get_bool());

    modelnet::PreserveCandidate a, b, pick;
    a.model_id.data[0] = 1;
    a.bytes = 110ULL << 30;
    a.observed_sources = 1;
    a.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
    b.model_id.data[0] = 2;
    b.bytes = 90ULL << 30;
    b.observed_sources = 8;
    b.admission = modelnet::AdmissionLevel::BYTES_VERIFIED;
    rare.preserve_rare = true;
    rare.storage_quota_bytes = 500ULL << 30;
    std::set<modelnet::Digest48> local;
    BOOST_REQUIRE(modelnet::SelectPreserveRare({a, b}, local, 200ULL << 30, rare, pick));
    BOOST_CHECK(pick.model_id.data[0] == 1);
    BOOST_CHECK(!modelnet::SelectPreserveRare({b}, local, 200ULL << 30, rare, pick));

    modelnet::EvictItem common, rare_item, pinned;
    common.seeded = true;
    common.observed_sources = 20;
    rare_item.seeded = true;
    rare_item.observed_sources = 1;
    pinned.pinned = true;
    BOOST_CHECK(modelnet::EvictPriority(common) < modelnet::EvictPriority(rare_item));
    BOOST_CHECK(modelnet::EvictPriority(rare_item) < modelnet::EvictPriority(pinned));

    const fs::path tmp = m_args.GetDataDirBase() / "model-demand";
    modelnet::ModelCatalog cat{tmp, /*quota*/ 8 << 20};
    BOOST_CHECK(cat.Policy().seed_mode == modelnet::SeedMode::AUTO);
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), st.size());
    }
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), /*pin=*/false, imported, err), err);
    BOOST_CHECK(imported.seeded);

    modelnet::PreservationPolicy manual = cat.Policy();
    manual.seed_mode = modelnet::SeedMode::OFF;
    manual.seed_upon_download = false;
    cat.SetPolicy(manual);
    const fs::path src2 = tmp / "src2";
    fs::create_directories(src2);
    {
        std::ofstream out(src2 / "other.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), st.size());
    }
    modelnet::CatalogEntry imported2;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src2), /*pin=*/false, imported2, err), err);
    BOOST_CHECK(!imported2.seeded);
    modelnet::NativeRequest nreq;
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported2.artifact_id.Hex() + "/pieces/0/0";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 404);

    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);

    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "getmodelpolicy");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK_EQUAL(result["seed"].get_str(), "off");
    BOOST_CHECK(!result["demand_propagation"].get_bool());
}

BOOST_AUTO_TEST_CASE(default_demand_propagation_is_not_opt_in)
{
    // v1.1 §2.3: a leftover B0 seed_upon_download=false bit is not a second gate.
    modelnet::PreservationPolicy stale_b0;
    stale_b0.storage_quota_bytes = 8 << 20;
    stale_b0.seed_mode = modelnet::SeedMode::AUTO;
    stale_b0.seed_upon_download = false;
    BOOST_CHECK(modelnet::ShouldDemandSeed(stale_b0, modelnet::AdmissionLevel::STRUCTURE_VERIFIED));
    const UniValue dumped = modelnet::PolicyToJson(stale_b0);
    BOOST_CHECK(dumped["demand_propagation"].get_bool());
    BOOST_CHECK(dumped["seed_upon_download"].get_bool());
    BOOST_CHECK(!dumped["seed_upon_download_opt_in"].get_bool());

    std::string err;
    UniValue mixed(UniValue::VOBJ);
    mixed.pushKV("seed", "auto");
    mixed.pushKV("seed_upon_download", false);
    mixed.pushKV("storage_quota_bytes", static_cast<uint64_t>(8 << 20));
    modelnet::PreservationPolicy parsed;
    BOOST_REQUIRE_MESSAGE(modelnet::PolicyFromJson(mixed, parsed, err), err);
    BOOST_CHECK(parsed.seed_mode == modelnet::SeedMode::AUTO);
    BOOST_CHECK(modelnet::ShouldDemandSeed(parsed, modelnet::AdmissionLevel::STRUCTURE_VERIFIED));

    const fs::path tmp = m_args.GetDataDirBase() / "demand-default-no-flag";
    modelnet::ModelCatalog cat{tmp, /*quota*/ 8 << 20};
    BOOST_CHECK(cat.Policy().seed_mode == modelnet::SeedMode::AUTO);
    BOOST_CHECK(modelnet::PolicyToJson(cat.Policy())["demand_propagation"].get_bool());
    BOOST_CHECK(!modelnet::PolicyToJson(cat.Policy())["seed_upon_download_opt_in"].get_bool());

    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), st.size());
    }
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "importmodel");
    UniValue params(UniValue::VARR);
    params.push_back(fs::PathToString(src));
    UniValue opts(UniValue::VOBJ);
    opts.pushKV("pin", false);
    params.push_back(opts);
    req.pushKV("params", params);
    UniValue result;
    std::string code;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, req, result, code, err), err);
    BOOST_CHECK(result["seeded"].get_bool());
    BOOST_CHECK_EQUAL(result["propagation"].get_str(), "demand");
    BOOST_CHECK_EQUAL(result["admission"].get_str(), "SEEDING");

    modelnet::CatalogEntry imported;
    modelnet::Digest48 mid;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(result["model_id"].get_str(), mid, err));
    BOOST_REQUIRE(cat.Find(mid, imported));
    BOOST_CHECK(imported.seeded);

    modelnet::NativeRequest nreq;
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);
}

BOOST_AUTO_TEST_CASE(qualification_rejects_unsafe)
{
    modelnet::QualReport report;
    const unsigned char pickle[] = {0x80, 0x04, 0x95};
    BOOST_CHECK(modelnet::QualifyBytes("model.pkl", Span<const unsigned char>{pickle, sizeof(pickle)}, report) == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char junk[] = {1, 2, 3};
    BOOST_CHECK(modelnet::QualifyBytes("model.pt", Span<const unsigned char>{junk, sizeof(junk)}, report) == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char encmagic[] = {'B', 'T', 'X', 'E', 'N', 'C', '2', 0};
    BOOST_CHECK(modelnet::QualifyBytes("x.btxenc", Span<const unsigned char>{encmagic, sizeof(encmagic)}, report) == modelnet::QualResult::ENCRYPTED_UNQUALIFIED);

    // Minimal SafeTensors: 8-byte header length + "{}" + no tensors, file size must match 8+2.
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    BOOST_CHECK(modelnet::QualifyBytes("x.safetensors", st, report) == modelnet::QualResult::STRUCTURE_VERIFIED);

    std::vector<unsigned char> gguf(24, 0);
    std::memcpy(gguf.data(), "GGUF", 4);
    WriteLE32(gguf.data() + 4, 3);
    BOOST_CHECK(modelnet::QualifyBytes("x.gguf", gguf, report) == modelnet::QualResult::STRUCTURE_VERIFIED);
}

BOOST_AUTO_TEST_CASE(store_recounts_used_bytes)
{
    const fs::path tmp = m_args.GetDataDirBase() / "modelstore-recount";
    const std::string payload = "hello-modelnet-piece";
    std::vector<unsigned char> file(payload.begin(), payload.end());
    modelnet::Digest48 art{};
    art.data[0] = 2;
    const auto leaf = modelnet::ChunkLeaf(0, file);
    std::string err;
    {
        modelnet::ModelStore store{tmp, /*quota*/ 1024};
        BOOST_REQUIRE(store.PutVerifiedPiece(art, 0, 0, file, leaf, err));
        BOOST_CHECK_EQUAL(store.UsedBytes(), file.size());
    }
    modelnet::ModelStore again{tmp, /*quota*/ 1024};
    BOOST_CHECK_EQUAL(again.UsedBytes(), file.size());
}

BOOST_AUTO_TEST_CASE(acl_does_not_ban_monetary)
{
    modelnet::ModelAcl acl;
    acl.deny_model.insert("abc");
    BOOST_CHECK(acl.Denied(modelnet::PolicyDim::RETRIEVE, "abc"));
    BOOST_CHECK(!acl.AffectsMonetaryBan());
}

BOOST_AUTO_TEST_CASE(release_hash_is_sha256_not_hash160)
{
    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 1);
    const auto h = modelnet::ReleaseHash(secret);
    BOOST_CHECK_EQUAL(h.Hex().size(), 64U);
    BOOST_CHECK(modelnet::ValidRefundWindow(100, 1, 10, 200));
    BOOST_CHECK(!modelnet::ValidRefundWindow(100, 50, 60, 150));
}

BOOST_AUTO_TEST_CASE(http_bridge_and_protocol)
{
    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/not-a-token", br));
    BOOST_CHECK_EQUAL(br.http_status, 400);
    const UniValue vectors = LoadVectors();
    const std::string uri = vectors["resource_vectors"][0]["uri"].get_str();
    BOOST_REQUIRE(modelnet::HandleBridgeGet("/" + uri.substr(6), br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK_EQUAL(br.canonical_btx, uri);

    modelnet::SendModels sm;
    std::vector<unsigned char> bytes;
    std::string err;
    BOOST_REQUIRE(modelnet::SerializeSendModels(sm, bytes, err));
    BOOST_CHECK_EQUAL(bytes.size(), 18U);
    modelnet::SendModels parsed;
    BOOST_REQUIRE(modelnet::ParseSendModels(bytes, parsed, err));
}

BOOST_AUTO_TEST_CASE(hybrid_free_first_scheduler)
{
    std::vector<modelnet::PieceNeed> missing(3);
    missing[0].piece_index = 0;
    missing[1].piece_index = 1;
    missing[2].piece_index = 2;
    std::vector<modelnet::SourceOffer> src{{"free", false, 0, 10, true}, {"paid", true, 50, 1, true}};
    auto plan = modelnet::PlanRetrieval(missing, src, modelnet::RetrievalMode::FREE_ONLY, 0, false);
    BOOST_CHECK(plan.paid_pieces.empty());
    BOOST_CHECK_EQUAL(plan.free_pieces.size(), 3U);
}

BOOST_AUTO_TEST_CASE(router_cpu_only)
{
    modelnet::RouterCache cache;
    modelnet::SignedRecordHint rec;
    rec.record_id.data[0] = 9;
    rec.expiry = 100;
    std::string err;
    BOOST_REQUIRE(cache.Insert(rec, 50, err));
    BOOST_CHECK_EQUAL(cache.LookupExact(rec.record_id, 50).size(), 1U);
    cache.Expire(200);
    BOOST_CHECK(cache.LookupExact(rec.record_id, 200).empty());
}

BOOST_AUTO_TEST_CASE(xchacha_roundtrip)
{
    unsigned char key[32];
    unsigned char nonce[24];
    for (int i = 0; i < 32; ++i) key[i] = static_cast<unsigned char>(i);
    for (int i = 0; i < 24; ++i) nonce[i] = static_cast<unsigned char>(100 + i);
    const std::vector<unsigned char> pt{'a', 'r', 't', 'i', 'f', 'a', 'c', 't'};
    std::vector<unsigned char> ct, recovered;
    BOOST_REQUIRE(modelnet::XChaCha20Poly1305Encrypt(key, nonce, {}, pt, ct));
    BOOST_REQUIRE(modelnet::XChaCha20Poly1305Decrypt(key, nonce, {}, ct, recovered));
    BOOST_CHECK(recovered == pt);
    ct[0] ^= 0x01;
    BOOST_CHECK(!modelnet::XChaCha20Poly1305Decrypt(key, nonce, {}, ct, recovered));
}

static std::string ReadAll(const fs::path& p)
{
    std::ifstream in(p);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

BOOST_AUTO_TEST_CASE(pq1_handshake_mlkem768)
{
    const fs::path dir = m_path_root / "pq1";
    fs::create_directories(dir);
    const fs::path key = dir / "key.pem";
    const fs::path cert = dir / "cert.pem";
    const fs::path openssl_err = dir / "openssl.err";
    const std::string openssl = modelnet::OpensslBin();
    const std::string cmd = strprintf(
        "%s req -x509 -new -newkey mldsa44 -keyout '%s' -out '%s' -nodes -subj '/CN=btx-model-test' -days 1 >'%s' 2>&1",
        openssl, fs::PathToString(key), fs::PathToString(cert), fs::PathToString(openssl_err));
    const int rc = std::system(cmd.c_str());
    BOOST_REQUIRE_MESSAGE(rc == 0, "openssl mldsa44 cert failed rc=" + std::to_string(rc) +
                                         " bin=" + openssl + " " + ReadAll(openssl_err));
    const std::string cert_pem = ReadAll(cert);
    const std::string key_pem = ReadAll(key);
    modelnet::Pq1Context server;
    modelnet::Pq1Context client;
    BOOST_REQUIRE_MESSAGE(server.Ready(), server.Error());
    BOOST_REQUIRE_MESSAGE(client.Ready(), client.Error());
    std::string err;
    BOOST_REQUIRE(server.LoadSelfSignedMlDsa(cert_pem, key_pem, err));
    BOOST_REQUIRE(client.LoadSelfSignedMlDsa(cert_pem, key_pem, err));
    modelnet::NegotiatedPq1 n;
    BOOST_REQUIRE_MESSAGE(modelnet::HandshakePair(server, client, n, err), err);
    BOOST_CHECK(modelnet::IsStrictPq1(n));
    BOOST_TEST_MESSAGE("PQ1 group=" + n.group + " cipher=" + n.ciphersuite + " ver=" + n.tls_version);
}

BOOST_AUTO_TEST_CASE(pq1_rejects_hybrid_peer)
{
    modelnet::Pq1Context client;
    BOOST_REQUIRE(client.Ready());
    SSL_CTX* rogue = SSL_CTX_new(TLS_method());
    BOOST_REQUIRE(rogue);
    SSL_CTX_set_min_proto_version(rogue, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(rogue, TLS1_3_VERSION);
    BOOST_REQUIRE_EQUAL(SSL_CTX_set1_groups_list(rogue, "X25519MLKEM768"), 1);
    SSL* ssl_s = SSL_new(rogue);
    SSL* ssl_c = SSL_new(static_cast<SSL_CTX*>(client.SslCtx()));
    BIO *b1 = nullptr, *b2 = nullptr;
    BOOST_REQUIRE_EQUAL(BIO_new_bio_pair(&b1, 0, &b2, 0), 1);
    SSL_set_bio(ssl_s, b1, b1);
    SSL_set_bio(ssl_c, b2, b2);
    SSL_set_accept_state(ssl_s);
    SSL_set_connect_state(ssl_c);
    int rc_c = 0, rc_s = 0;
    for (int i = 0; i < 32; ++i) {
        rc_c = SSL_do_handshake(ssl_c);
        rc_s = SSL_do_handshake(ssl_s);
        if (rc_c == 1 && rc_s == 1) break;
    }
    BOOST_CHECK(!(rc_c == 1 && rc_s == 1));
    SSL_free(ssl_c);
    SSL_free(ssl_s);
    SSL_CTX_free(rogue);
}

BOOST_AUTO_TEST_CASE(pq19_openssl_conf_cannot_weaken_pq1)
{
    const fs::path dir = m_path_root / "pq19";
    fs::create_directories(dir);
    const fs::path conf = dir / "hostile.cnf";
    {
        std::ofstream out(conf);
        out << "openssl_conf = openssl_init\n"
            << "[openssl_init]\n"
            << "ssl_conf = ssl_configuration\n"
            << "[ssl_configuration]\n"
            << "system_default = ssl_default\n"
            << "[ssl_default]\n"
            << "MinProtocol = TLSv1.2\n"
            << "MaxProtocol = TLSv1.3\n"
            << "Groups = X25519:X25519MLKEM768\n"
            << "Ciphersuites = TLS_AES_128_GCM_SHA256\n"
            << "SignatureAlgorithms = ECDSA+SHA256:ed25519\n";
    }
    BOOST_REQUIRE_EQUAL(setenv("OPENSSL_CONF", fs::PathToString(conf).c_str(), 1), 0);
    BOOST_REQUIRE_EQUAL(setenv("OPENSSL_MODULES", "/nonexistent-btx-pq19-modules", 1), 0);
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::Pq1HostileConfCannotWeaken(err), err);
    BOOST_CHECK(modelnet::Pq1OpenSslEnvIsClean());
    modelnet::Pq1Context server;
    modelnet::Pq1Context client;
    BOOST_REQUIRE_MESSAGE(server.Ready(), server.Error());
    BOOST_REQUIRE_MESSAGE(client.Ready(), client.Error());
    BOOST_CHECK_EQUAL(static_cast<int>(SSL_CTX_get_min_proto_version(static_cast<SSL_CTX*>(server.SslCtx()))),
                      static_cast<int>(TLS1_3_VERSION));
    BOOST_CHECK_EQUAL(static_cast<int>(SSL_CTX_get_max_proto_version(static_cast<SSL_CTX*>(server.SslCtx()))),
                      static_cast<int>(TLS1_3_VERSION));
}

BOOST_AUTO_TEST_CASE(identity_is_not_wallet_and_release_is_sha256)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    BOOST_CHECK_EQUAL(pk.size(), modelnet::MLDSA44_PK);
    BOOST_CHECK_EQUAL(sk.size(), modelnet::MLDSA44_SK);
    const std::vector<unsigned char> msg{'m', 'o', 'd', 'e', 'l'};
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(modelnet::SignMlDsa44(sk, msg, sig, err));
    BOOST_CHECK(modelnet::VerifyMlDsa44(pk, msg, sig));
    auto bad = msg;
    bad[0] ^= 0x01;
    BOOST_CHECK(!modelnet::VerifyMlDsa44(pk, bad, sig));
    const auto pid = modelnet::PublisherId(pk);
    BOOST_CHECK(!pid.IsNull());

    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 1);
    const auto h = modelnet::ReleaseHash(secret);
    unsigned char sha[32];
    CSHA256().Write(secret, 32).Finalize(sha);
    BOOST_CHECK(std::equal(h.data.begin(), h.data.end(), sha));
    BOOST_CHECK((SeedsServiceFlags() & NODE_MODEL_RELAY) == 0);
    BOOST_CHECK((SeedsServiceFlags() & NODE_MODEL_HOST) == 0);
    BOOST_CHECK(!MayHaveUsefulAddressDB(NODE_MODEL_RELAY));
    BOOST_CHECK(!MayHaveUsefulAddressDB(NODE_MODEL_HOST));
}

BOOST_AUTO_TEST_CASE(b0_model_core_codec_vectors)
{
    std::ifstream in{MODELNET_B0_CODEC_VECTORS_PATH};
    BOOST_REQUIRE(in);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue v;
    BOOST_REQUIRE(v.read(raw));
    const UniValue& mcj = v["model-core"]["object"];
    modelnet::ModelCore mc;
    mc.version = 2;
    mc.format_profile = static_cast<uint16_t>(mcj["format_profile"].getInt<int>());
    mc.execution_profile = static_cast<uint16_t>(mcj["execution_profile"].getInt<int>());
    std::string err;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(mcj["config_sha384"].get_str(), mc.config_sha384, err));
    BOOST_REQUIRE(modelnet::Digest48::FromHex(mcj["tokenizer_sha384"].get_str(), mc.tokenizer_sha384, err));
    modelnet::CoreFile cf;
    cf.path = mcj["files"][0]["path"].get_str();
    cf.role = modelnet::FileRole::WEIGHTS;
    cf.size = mcj["files"][0]["size"].getInt<uint64_t>();
    BOOST_REQUIRE(modelnet::Digest48::FromHex(mcj["files"][0]["sha384"].get_str(), cf.sha384, err));
    BOOST_REQUIRE(modelnet::Digest48::FromHex(mcj["files"][0]["pieces_root"].get_str(), cf.pieces_root, err));
    mc.files.push_back(cf);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(modelnet::EncodeModelCore(mc, encoded, err));
    BOOST_CHECK_EQUAL(HexStr(encoded), v["model-core"]["canonical_hex"].get_str());
    BOOST_CHECK_EQUAL(modelnet::ModelCoreId(encoded).Hex(), v["model-core"]["id"].get_str());

    modelnet::ArtifactCore ac;
    ac.version = 2;
    ac.codec = 1;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(v["artifact-core"]["object"]["model_id"].get_str(), ac.model_id, err));
    ac.files = mc.files;
    std::vector<unsigned char> aenc;
    BOOST_REQUIRE(modelnet::EncodeArtifactCore(ac, aenc, err));
    BOOST_CHECK_EQUAL(HexStr(aenc), v["artifact-core"]["canonical_hex"].get_str());
    BOOST_CHECK_EQUAL(modelnet::ArtifactCoreId(aenc).Hex(), v["artifact-core"]["id"].get_str());
}

BOOST_AUTO_TEST_CASE(catalog_import_seed_list_and_native_http)
{
    const fs::path tmp = m_args.GetDataDirBase() / "modelcatalog";
    modelnet::ModelCatalog cat{tmp, /*quota*/ 8 << 20};
    const fs::path src = tmp / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), st.size());
    }
    modelnet::QualReport qf;
    BOOST_CHECK(modelnet::QualifyFile(fs::PathToString(src / "model.safetensors"), qf) == modelnet::QualResult::STRUCTURE_VERIFIED);

    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), /*pin=*/true, imported, err), err);
    BOOST_CHECK(!imported.model_id.IsNull());
    BOOST_CHECK(imported.seeded);
    UniValue listed;
    BOOST_REQUIRE(cat.List(listed));
    BOOST_CHECK_EQUAL(listed["local_count"].getInt<int>(), 1);
    BOOST_REQUIRE(cat.Seed(imported.model_id, true, err));

    UniValue man;
    BOOST_REQUIRE(cat.GetManifest(imported.model_id, man, err));
    BOOST_CHECK_EQUAL(man["files"].size(), 1);

    std::vector<unsigned char> piece;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, piece, proof, file_size, err));
    BOOST_CHECK_EQUAL(file_size, 10U);
    BOOST_CHECK(piece == st);

    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "listmodels");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue rpc_result;
    std::string code;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, rpc_result, code, err));
    BOOST_CHECK_EQUAL(rpc_result["local_count"].getInt<int>(), 1);

    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/hello";
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    UniValue hello;
    BOOST_REQUIRE(hello.read(nresp.body));
    BOOST_CHECK_EQUAL(hello["suite"].get_str(), "pq1");

    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 403);

    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.body = "{\"model_id\":\"" + imported.model_id.Hex() + "\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    UniValue grantj;
    BOOST_REQUIRE(grantj.read(nresp.body));
    BOOST_REQUIRE(grantj.exists("payload_hex") && grantj.exists("sig_hex") && grantj.exists("pubkey_hex"));

    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + imported.artifact_id.Hex() + "/pieces/0/0";
    nreq.body.clear();
    nreq.headers = {
        {"X-BTX-Grant-Payload", grantj["payload_hex"].get_str()},
        {"X-BTX-Grant-Sig", grantj["sig_hex"].get_str()},
        {"X-BTX-Grant-Pubkey", grantj["pubkey_hex"].get_str()},
    };
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    BOOST_CHECK_EQUAL(nresp.content_type, "application/octet-stream");
    BOOST_CHECK_EQUAL(nresp.body.size(), st.size());
    BOOST_CHECK(std::vector<unsigned char>(nresp.body.begin(), nresp.body.end()) == st);
    const std::string wire = modelnet::FormatHttpResponse(nresp);
    BOOST_CHECK(wire.find("bytes_hex") == std::string::npos);
    BOOST_CHECK(wire.find("application/octet-stream") != std::string::npos);
    bool saw_size = false;
    for (const auto& h : nresp.headers) {
        if (h.first == "X-BTX-File-Size") {
            BOOST_CHECK_EQUAL(h.second, "10");
            saw_size = true;
        }
    }
    BOOST_CHECK(saw_size);

    nreq.method = "POST";
    nreq.path = "/btx-model/2/query";
    nreq.body = "{\"text\":\"model\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
    UniValue qj;
    BOOST_REQUIRE(qj.read(nresp.body));
    BOOST_CHECK_EQUAL(qj["coverage"].get_str(), "incomplete");
    BOOST_CHECK(qj["ids"].size() >= 1);

    nreq.path = "/btx-model/2/ext/caps";
    nreq.body.clear();
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    UniValue caps;
    BOOST_REQUIRE(caps.read(nresp.body));
    BOOST_CHECK_EQUAL(caps["extension_version"].getInt<int>(), 257);
    BOOST_CHECK_EQUAL(caps["features"].getInt<int>(), 127);

    nreq.path = "/btx-model/2/records/announce";
    nreq.body = "{\"record_id\":\"" + imported.model_id.Hex() + "\",\"kind\":19,\"provider_id\":\"local\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 400);

    UniValue join(UniValue::VOBJ);
    join.pushKV("method", "joinmodelcircle");
    UniValue jparams(UniValue::VARR);
    jparams.push_back(imported.model_id.Hex());
    join.pushKV("params", jparams);
    UniValue joined;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, join, joined, code, err));
    BOOST_CHECK_EQUAL(joined["on_chain_membership"].get_bool(), false);
    BOOST_REQUIRE(joined.exists("signed_record_id"));

    nreq.path = "/btx-model/2/records/get";
    nreq.body = "{\"ids\":[\"" + joined["signed_record_id"].get_str() + "\"]}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    UniValue got;
    BOOST_REQUIRE(got.read(nresp.body));
    BOOST_CHECK(got["records"].size() >= 1);

    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.body = "{\"model_id\":\"" + imported.model_id.Hex() + "\"}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);

    UniValue openreq(UniValue::VOBJ);
    openreq.pushKV("method", "openbtxuri");
    UniValue oparams(UniValue::VARR);
    std::string uri;
    std::string uerr;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, imported.model_id, uri, uerr));
    oparams.push_back(uri);
    openreq.pushKV("params", oparams);
    UniValue openres;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, openreq, openres, code, err));
    BOOST_CHECK_EQUAL(openres["inference"].get_bool(), false);

    unsigned char secret_for_campaign[32];
    for (int i = 0; i < 32; ++i) secret_for_campaign[i] = static_cast<unsigned char>(i + 3);
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, imported.model_id, uri, err));
    UniValue cparams(UniValue::VARR);
    cparams.push_back(uri);
    cparams.push_back(HexStr(Span{secret_for_campaign, 32}));
    cparams.push_back(100000);
    req = UniValue(UniValue::VOBJ);
    req.pushKV("method", "createmodelrelease");
    req.pushKV("params", cparams);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, req, rpc_result, code, err));
    BOOST_CHECK(rpc_result.exists("release_id"));
    BOOST_CHECK(rpc_result.exists("key_hash"));
    req.pushKV("method", "buildmodelhtlcclaim");
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, rpc_result, code, err));
    BOOST_CHECK(code != "NOT_IMPLEMENTED");
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    UniValue listed_after_seed;
    BOOST_REQUIRE(cat.List(listed_after_seed));
    BOOST_REQUIRE(listed_after_seed["models"].size() >= 1);
    bool orig_verified = false;
    for (const auto& m : listed_after_seed["models"].getValues()) {
        if (m.exists("model_id") && m["model_id"].isStr() && m["model_id"].get_str() == imported.model_id.Hex()) {
            orig_verified = m.exists("bytes_verified") && m["bytes_verified"].get_bool();
        }
    }
    BOOST_CHECK(orig_verified);
}

BOOST_AUTO_TEST_CASE(catalog_quota_zero_refuses_import)
{
    const fs::path tmp = m_args.GetDataDirBase() / "modelcatalog-zero";
    modelnet::ModelCatalog cat{tmp, /*quota*/ 0};
    const fs::path src = tmp / "model.safetensors";
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src, std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), st.size());
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_CHECK(!cat.ImportPath(fs::PathToString(src), true, imported, err));
    BOOST_CHECK(err.find("quota") != std::string::npos || err.find("0") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(payment_journal_and_tofu_pin)
{
    std::vector<modelnet::PaymentJournal> journal;
    BOOST_CHECK(!modelnet::DuplicatePayment(journal, "aa"));
    journal.push_back({"offer", "deadbeef", false, false});
    BOOST_CHECK(modelnet::DuplicatePayment(journal, "deadbeef"));

    const fs::path pinfile = m_args.GetDataDirBase() / "pins.json";
    modelnet::Digest48 a = modelnet::DomainHash("BTX/TransportKey/v2", Span{UCharCast("abc"), 3});
    modelnet::Digest48 b = modelnet::DomainHash("BTX/TransportKey/v2", Span{UCharCast("xyz"), 3});
    std::string err;
    BOOST_REQUIRE(modelnet::CheckOrStorePin(pinfile, "127.0.0.1:1", a, err));
    BOOST_REQUIRE(modelnet::CheckOrStorePin(pinfile, "127.0.0.1:1", a, err));
    BOOST_CHECK(!modelnet::CheckOrStorePin(pinfile, "127.0.0.1:1", b, err));
    BOOST_CHECK(err.find("pin") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(modelnet_rpc_table_constructs)
{
    CRPCTable table;
    RegisterModelNetRPCCommands(table);
}

BOOST_AUTO_TEST_CASE(helper_stop_interrupts_accept_loop)
{
    const fs::path tmp = m_args.GetDataDirBase() / "modeld-stop";
    fs::create_directories(tmp);
    modelnet::HelperConfig cfg;
    cfg.modeldir = tmp;
    cfg.quota_bytes = 1 << 20;
    cfg.rpc_socket = fs::PathFromString("/tmp/btx-md-stop-" + std::to_string(getpid()) + ".sock");
    ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    const int port = 39000 + (static_cast<int>(getpid()) % 500);
    cfg.bind = "127.0.0.1:" + std::to_string(port);
    std::atomic<bool> stop{false};
    std::thread t;
    auto join = [&] {
        stop.store(true);
        if (t.joinable()) t.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    };
    t = std::thread([&] { modelnet::RunModelDaemon(cfg, &stop); });
    const auto t0 = std::chrono::steady_clock::now();
    bool ready = false;
    try {
        while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
            if (fs::exists(cfg.rpc_socket)) {
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        BOOST_REQUIRE(ready);
        stop.store(true);
        t.join();
        BOOST_CHECK(std::chrono::steady_clock::now() - t0 < std::chrono::seconds(12));
    } catch (...) {
        join();
        throw;
    }
    join();
}

BOOST_AUTO_TEST_CASE(helper_unix_rpc_survives_peer_hup)
{
    const fs::path tmp = m_args.GetDataDirBase() / "modeld-hup";
    fs::create_directories(tmp);
    modelnet::HelperConfig cfg;
    cfg.modeldir = tmp;
    cfg.quota_bytes = 1 << 20;
    cfg.rpc_socket = fs::PathFromString("/tmp/btx-md-hup-" + std::to_string(getpid()) + ".sock");
    ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    const int port = 39500 + (static_cast<int>(getpid()) % 400);
    cfg.bind = "127.0.0.1:" + std::to_string(port);
    std::atomic<bool> stop{false};
    std::thread t;
    auto join = [&] {
        stop.store(true);
        if (t.joinable()) t.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
    };
    t = std::thread([&] { modelnet::RunModelDaemon(cfg, &stop); });
    const auto t0 = std::chrono::steady_clock::now();
    bool ready = false;
    try {
        while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
            if (fs::exists(cfg.rpc_socket)) {
                ready = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        BOOST_REQUIRE(ready);
        UniValue result;
        std::string err;
        UniValue params(UniValue::VARR);
        BOOST_REQUIRE_MESSAGE(modelnet::CallUnixRpc(cfg.rpc_socket, "getmodelnetworkinfo", params, result, err), err);
        BOOST_CHECK(result["helper_ready"].get_bool());
        BOOST_CHECK(result["enabled"].get_bool());
    } catch (...) {
        join();
        throw;
    }
    join();
}

BOOST_AUTO_TEST_SUITE_END()
