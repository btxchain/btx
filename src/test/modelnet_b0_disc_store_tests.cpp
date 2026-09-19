// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// B0 DISC-01..08 / STORE-01..08 at the library level (no WAN, no chain, no CUDA).
// Packaged acceptance-matrix.csv stays NOT_RUN.
//
// DISC-01  disc_01_cpu_router_introduces_hosts
// DISC-02  disc_02_sendmodels_not_useful_address
// DISC-03  disc_03_hidden_monetary_endpoints  (same surface as v11_resolve_10)
// DISC-04  disc_04_independent_bootstrap
// DISC-05  disc_05_router_loss_hosts_remain
// DISC-06  disc_06_stale_record_eviction
// DISC-07  disc_07_sybil_bounds
// DISC-08  disc_08_fresh_datadir_empty_peers
// STORE-01 store_01_multi_source_resume
// STORE-02 store_02_corrupt_piece_rejected
// STORE-03 store_03_whole_file_hash_mismatch
// STORE-04 store_04_metainfo_must_agree
// STORE-05 store_05_disk_exhaustion_preserves
// STORE-06 store_06_unsafe_paths_rejected
// STORE-07 store_07_crash_recovery_committed_pieces
// STORE-08 store_08_gc_pins_prevent_eviction

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/policy.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <modelnet/router.h>
#include <modelnet/store.h>
#include <protocol.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_b0_disc_store_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

fs::path WriteTinyModel(const fs::path& dir, unsigned char tag)
{
    fs::create_directories(dir);
    const auto st = TinySafeTensors(tag);
    std::ofstream out(dir / "model.safetensors", std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    return dir;
}

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat, const fs::path& dir, unsigned char tag, bool pin)
{
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(WriteTinyModel(dir, tag)), pin, imported, err), err);
    BOOST_REQUIRE(!imported.core.files.empty());
    return imported;
}

} // namespace

BOOST_AUTO_TEST_CASE(disc_01_cpu_router_introduces_hosts)
{
    BOOST_CHECK_EQUAL(modelnet::MAX_ROUTER_CONTACTS, 8);
    BOOST_CHECK_EQUAL(modelnet::MAX_CONCURRENT_RESOLVE_QUERIES, 4);

    modelnet::ResolveQueryPlan plan;
    BOOST_REQUIRE(modelnet::PlanRouterQueries({"192.0.2.10:29447", "192.0.2.11:29447"}, {}, plan));
    BOOST_REQUIRE_EQUAL(plan.contacts.size(), 2);
    BOOST_CHECK_EQUAL(plan.contacts[0], "192.0.2.10:29447");
    BOOST_CHECK_EQUAL(plan.contacts[1], "192.0.2.11:29447");
    BOOST_CHECK_LE(plan.contacts.size(), static_cast<size_t>(modelnet::MAX_ROUTER_CONTACTS));
    BOOST_CHECK_LE(plan.max_concurrent, modelnet::MAX_CONCURRENT_RESOLVE_QUERIES);
    BOOST_CHECK(!plan.reserved_independent);

    std::vector<std::string> many;
    for (int i = 0; i < 12; ++i) many.push_back("203.0.113." + std::to_string(i) + ":1");
    modelnet::ResolveQueryPlan capped;
    BOOST_REQUIRE(modelnet::PlanRouterQueries(many, {}, capped));
    BOOST_CHECK_EQUAL(capped.contacts.size(), static_cast<size_t>(modelnet::MAX_ROUTER_CONTACTS));

    modelnet::RouterCache cache;
    modelnet::SignedRecordHint a, b;
    a.record_id.data[0] = 0x01;
    b.record_id.data[0] = 0x02;
    a.kind = b.kind = 1;
    a.expiry = b.expiry = 100;
    a.signed_ok = b.signed_ok = true;
    a.provider_id = "host-a";
    b.provider_id = "host-b";
    std::string err;
    BOOST_REQUIRE(cache.Insert(a, /*now=*/10, err));
    BOOST_REQUIRE(cache.Insert(b, /*now=*/10, err));
    BOOST_CHECK_EQUAL(cache.LookupExact(a.record_id, 10).size(), 1);
    BOOST_CHECK_EQUAL(cache.LookupExact(b.record_id, 10).size(), 1);
    BOOST_CHECK(!modelnet::ModelWorkTakesConsensusLock());
}

BOOST_AUTO_TEST_CASE(disc_02_sendmodels_not_useful_address)
{
    BOOST_CHECK(!MayHaveUsefulAddressDB(NODE_MODEL_RELAY));
    BOOST_CHECK(!MayHaveUsefulAddressDB(NODE_MODEL_HOST));
    BOOST_CHECK(!MayHaveUsefulAddressDB(ServiceFlags(NODE_MODEL_RELAY | NODE_MODEL_HOST)));
    BOOST_CHECK(MayHaveUsefulAddressDB(NODE_NETWORK));
    BOOST_CHECK((SeedsServiceFlags() & NODE_MODEL_RELAY) == 0);
    BOOST_CHECK((SeedsServiceFlags() & NODE_MODEL_HOST) == 0);
    BOOST_CHECK_LE(std::strlen(NetMsgType::SENDMODELS), 12U);

    modelnet::SendModels msg;
    msg.version = modelnet::MODEL_PROTOCOL_VERSION;
    msg.role_mask = modelnet::ROLE_HOST | modelnet::ROLE_RELAY;
    std::vector<unsigned char> wire;
    std::string err;
    BOOST_REQUIRE(modelnet::SerializeSendModels(msg, wire, err));
    BOOST_CHECK_EQUAL(wire.size(), modelnet::SENDMODELS_BYTES);
    modelnet::SendModels parsed;
    BOOST_REQUIRE(modelnet::ParseSendModels(wire, parsed, err));
    BOOST_CHECK_EQUAL(parsed.version, modelnet::MODEL_PROTOCOL_VERSION);
    BOOST_CHECK_EQUAL(parsed.role_mask, msg.role_mask);
    BOOST_CHECK(!modelnet::ModelWorkTakesConsensusLock());
}

BOOST_AUTO_TEST_CASE(disc_03_hidden_monetary_endpoints)
{
    // Same library surface as v11_resolve_10_monetary_endpoints_hidden.
    const fs::path tmp = m_path_root / "disc-03";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    std::string err;
    for (const std::string method : {"getnewaddress", "sendtoaddress", "listunspent", "dumpwallet", "signrawtransaction"}) {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", UniValue(UniValue::VARR));
        UniValue result;
        std::string code;
        err.clear();
        BOOST_CHECK_MESSAGE(!modelnet::DispatchHelperRpc(cat, rpc, result, code, err), method);
        BOOST_CHECK_EQUAL(code, "METHOD_NOT_FOUND");
    }
    for (const std::string path : {"/btx-model/2/wallet/dump", "/btx-model/2/sendtoaddress", "/btx-model/2/wallet"}) {
        modelnet::NativeRequest req;
        req.method = "GET";
        req.path = path;
        modelnet::NativeResponse resp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
        BOOST_CHECK_EQUAL(resp.status, 404);
    }
    const UniValue caps = modelnet::CapabilitiesObject();
    const std::string dumped = caps.write();
    BOOST_CHECK(dumped.find("attestor") == std::string::npos);
    BOOST_CHECK(dumped.find("/rest/") == std::string::npos);
    BOOST_CHECK(dumped.find("addnode") == std::string::npos);
    BOOST_CHECK(!caps.exists("header_source"));
    BOOST_CHECK(!caps.exists("attestor_endpoint"));
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(disc_04_independent_bootstrap)
{
    modelnet::ResolveQueryPlan only_ind;
    BOOST_REQUIRE(modelnet::PlanRouterQueries({}, {"198.51.100.9:8443"}, only_ind));
    BOOST_REQUIRE_EQUAL(only_ind.contacts.size(), 1);
    BOOST_CHECK_EQUAL(only_ind.contacts[0], "198.51.100.9:8443");
    BOOST_CHECK(only_ind.reserved_independent);

    std::vector<std::string> preferred;
    for (int i = 0; i < 10; ++i) preferred.push_back("203.0.113." + std::to_string(i) + ":8443");
    modelnet::ResolveQueryPlan mixed;
    BOOST_REQUIRE(modelnet::PlanRouterQueries(preferred, {"198.51.100.9:8443"}, mixed));
    BOOST_CHECK_LE(mixed.contacts.size(), static_cast<size_t>(modelnet::MAX_ROUTER_CONTACTS));
    BOOST_CHECK(mixed.reserved_independent);
    bool saw_ind = false;
    for (const auto& c : mixed.contacts) {
        if (c == "198.51.100.9:8443") saw_ind = true;
    }
    BOOST_CHECK(saw_ind);
}

BOOST_AUTO_TEST_CASE(disc_05_router_loss_hosts_remain)
{
    const fs::path tmp = m_path_root / "disc-05";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    cat.AddPeer("192.0.2.10:29447");
    cat.AddPeer("192.0.2.11:29447");
    BOOST_CHECK_EQUAL(cat.Peers().size(), 2);

    modelnet::ResolveQueryPlan with_router;
    BOOST_REQUIRE(modelnet::PlanRouterQueries(cat.Peers(), {"independent.example:8443"}, with_router));
    BOOST_CHECK(with_router.reserved_independent);

    modelnet::RouterCache cache;
    modelnet::SignedRecordHint rec;
    rec.record_id.data[0] = 0x51;
    rec.kind = 1;
    rec.expiry = 50;
    rec.signed_ok = true;
    std::string err;
    BOOST_REQUIRE(cache.Insert(rec, 10, err));
    cache.Expire(51);
    BOOST_CHECK(cache.LookupExact(rec.record_id, 51).empty());

    modelnet::ResolveQueryPlan after_loss;
    BOOST_REQUIRE(modelnet::PlanRouterQueries(cat.Peers(), {}, after_loss));
    BOOST_CHECK_EQUAL(after_loss.contacts.size(), 2);
    BOOST_CHECK(!after_loss.reserved_independent);
    BOOST_CHECK_EQUAL(cat.Peers().size(), 2);

    const auto imported = ImportTiny(cat, tmp / "src", 0x51, /*pin=*/true);
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_CHECK(!bytes.empty());
}

BOOST_AUTO_TEST_CASE(disc_06_stale_record_eviction)
{
    modelnet::RouterCache cache;
    modelnet::SignedRecordHint rec;
    rec.record_id.data[0] = 0x66;
    rec.kind = 1;
    rec.expiry = 100;
    rec.signed_ok = true;
    rec.payload = {0x01};
    std::string err;
    BOOST_REQUIRE(cache.Insert(rec, /*now=*/50, err));
    BOOST_CHECK_EQUAL(cache.LookupExact(rec.record_id, 50).size(), 1);

    rec.payload = {0x02};
    BOOST_REQUIRE(cache.Insert(rec, 50, err));
    const auto hit = cache.LookupExact(rec.record_id, 50);
    BOOST_REQUIRE_EQUAL(hit.size(), 1);
    BOOST_REQUIRE_EQUAL(hit[0].payload.size(), 1);
    BOOST_CHECK_EQUAL(hit[0].payload[0], 0x02);

    cache.Expire(101);
    BOOST_CHECK(cache.LookupExact(rec.record_id, 101).empty());
    BOOST_CHECK(!cache.Insert(rec, /*now=*/200, err));

    modelnet::NegativeResolveCache neg;
    modelnet::Digest48 miss{};
    miss.data[0] = 0x06;
    BOOST_CHECK(!neg.HasIncomplete(0, miss, 10));
    neg.RememberIncomplete(0, miss, 10);
    BOOST_CHECK(neg.HasIncomplete(0, miss, 10));
    BOOST_CHECK(neg.HasIncomplete(0, miss, 69));
    BOOST_CHECK(!neg.HasIncomplete(0, miss, 70));
    BOOST_CHECK_EQUAL(modelnet::NEGATIVE_RESOLVE_TTL_S, 60);
}

BOOST_AUTO_TEST_CASE(disc_07_sybil_bounds)
{
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_INBOUND_PER_NETGROUP, 8);
    BOOST_CHECK_EQUAL(modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT, 4);
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_INBOUND, 16);
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_OUTBOUND, 8);
    BOOST_CHECK_LE(modelnet::PQ1_INFLIGHT_PIECES, modelnet::PQ1_MAX_INBOUND_PER_NETGROUP);

    const uint32_t ng = 0xD15C0007u;
    modelnet::ConnLimits lim;
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        BOOST_CHECK(lim.TryInbound(ng));
    }
    BOOST_CHECK(!lim.TryInbound(ng));
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        lim.ReleaseInbound(ng);
    }

    modelnet::ClearUnauth(ng);
    for (int i = 0; i < modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT; ++i) {
        BOOST_CHECK_LE(modelnet::CountUnauthAndBump(ng), modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT);
    }
    BOOST_CHECK_EQUAL(modelnet::CountUnauthAndBump(ng), modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT + 1);
    modelnet::ClearUnauth(ng);

    modelnet::BootstrapLimiter boot{int64_t{1} << 20};
    BOOST_CHECK(boot.Allow("svc", "ng-disc07", 1024));
    BOOST_CHECK(!boot.Allow("svc", "ng-disc07", modelnet::BootstrapLimiter::PER_KEY_DAY));
}

BOOST_AUTO_TEST_CASE(disc_08_fresh_datadir_empty_peers)
{
    const fs::path tmp = m_path_root / "disc-08-fresh";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    BOOST_CHECK(cat.Peers().empty());

    modelnet::ResolveQueryPlan plan;
    BOOST_REQUIRE(modelnet::PlanRouterQueries(cat.Peers(), {}, plan));
    BOOST_CHECK(plan.contacts.empty());
    BOOST_CHECK(!plan.reserved_independent);

    cat.AddPeer("192.0.2.80:29447");
    BOOST_CHECK_EQUAL(cat.Peers().size(), 1);

    modelnet::ModelCatalog reopened{tmp, 1 << 20};
    BOOST_CHECK_EQUAL(reopened.Peers().size(), 1);

    const fs::path empty = m_path_root / "disc-08-empty";
    modelnet::ModelCatalog fresh{empty, 1 << 20};
    BOOST_CHECK(fresh.Peers().empty());
}

BOOST_AUTO_TEST_CASE(store_01_multi_source_resume)
{
    const fs::path tmp = m_path_root / "store-01";
    modelnet::ModelCatalog host_a{tmp / "a", 1 << 20};
    modelnet::ModelCatalog host_b{tmp / "b", 1 << 20};
    const auto imported = ImportTiny(host_a, tmp / "src", 0xA1, /*pin=*/true);
    std::string err;
    modelnet::CatalogEntry from_b;
    BOOST_REQUIRE(host_b.ImportPath(fs::PathToString(tmp / "src"), /*pin=*/true, from_b, err));
    BOOST_CHECK(imported.artifact_id == from_b.artifact_id);

    std::vector<unsigned char> from_a, from_b_bytes;
    std::vector<modelnet::Digest48> proof_a, proof_b;
    uint64_t size_a = 0, size_b = 0;
    BOOST_REQUIRE(host_a.GetVerifiedPiece(imported.artifact_id, 0, 0, from_a, proof_a, size_a, err));
    BOOST_REQUIRE(host_b.GetVerifiedPiece(from_b.artifact_id, 0, 0, from_b_bytes, proof_b, size_b, err));
    BOOST_CHECK(from_a == from_b_bytes);

    {
        modelnet::ModelCatalog buyer{tmp / "buyer", 1 << 20};
        UniValue man;
        BOOST_REQUIRE(host_a.GetManifest(imported.model_id, man, err));
        BOOST_REQUIRE_MESSAGE(buyer.InstallFromManifest(man, err, /*complete=*/false), err);
        BOOST_REQUIRE_MESSAGE(buyer.PutFetchedPiece(imported.artifact_id, 0, 0, from_a, proof_a, size_a,
                                            imported.core.files[0].pieces_root, err), err);
        modelnet::PieceIndex idx;
        BOOST_REQUIRE(host_a.Store().LoadPieceIndex(imported.artifact_id, 0, idx, err));
        BOOST_REQUIRE(buyer.Store().SavePieceIndex(imported.artifact_id, 0, idx, err));
    }

    modelnet::ModelCatalog resumed{tmp / "buyer", 1 << 20};
    BOOST_REQUIRE(resumed.PutFetchedPiece(imported.artifact_id, 0, 0, from_b_bytes, proof_b, size_b,
                                          from_b.core.files[0].pieces_root, err));
    std::vector<unsigned char> got;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(resumed.GetVerifiedPiece(imported.artifact_id, 0, 0, got, proof, file_size, err));
    BOOST_CHECK(got == from_a);
    BOOST_REQUIRE(resumed.VerifyFileDigest(imported.artifact_id, 0, imported.core.files[0].sha384, err));
}

BOOST_AUTO_TEST_CASE(store_02_corrupt_piece_rejected)
{
    const fs::path tmp = m_path_root / "store-02";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0xA2, /*pin=*/true);
    std::string err;
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_REQUIRE(!bytes.empty());

    std::vector<unsigned char> corrupt = bytes;
    corrupt[0] ^= 0xff;
    BOOST_CHECK(!cat.PutFetchedPiece(imported.artifact_id, 0, 0, corrupt, proof, file_size,
                                     imported.core.files[0].pieces_root, err));
    BOOST_CHECK(err.find("corrupt") != std::string::npos);

    std::vector<unsigned char> again;
    std::vector<modelnet::Digest48> proof2;
    uint64_t size2 = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, again, proof2, size2, err));
    BOOST_CHECK(again == bytes);
    BOOST_CHECK(again != corrupt);
}

BOOST_AUTO_TEST_CASE(store_03_whole_file_hash_mismatch)
{
    const fs::path tmp = m_path_root / "store-03";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0xA3, /*pin=*/true);
    std::string err;
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_REQUIRE(cat.VerifyFileDigest(imported.artifact_id, 0, imported.core.files[0].sha384, err));
    modelnet::Digest48 wrong{};
    wrong.data[0] = 0xff;
    BOOST_CHECK(!cat.VerifyFileDigest(imported.artifact_id, 0, wrong, err));
    BOOST_CHECK(err.find("mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(store_04_metainfo_must_agree)
{
    const fs::path tmp = m_path_root / "store-04";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0xA4, /*pin=*/true);
    std::string err;
    UniValue man;
    BOOST_REQUIRE(cat.GetManifest(imported.artifact_id, man, err));
    BOOST_CHECK_EQUAL(man["model_id"].get_str(), imported.model_id.Hex());
    BOOST_CHECK_EQUAL(man["artifact_id"].get_str(), imported.artifact_id.Hex());
    BOOST_REQUIRE(man["files"].size() >= 1);
    BOOST_CHECK_EQUAL(man["files"][0]["path"].get_str(), imported.core.files[0].path);
    BOOST_CHECK_EQUAL(man["files"][0]["size"].getInt<uint64_t>(), imported.core.files[0].size);
    BOOST_CHECK_EQUAL(man["files"][0]["sha384"].get_str(), imported.core.files[0].sha384.Hex());
    BOOST_CHECK_EQUAL(man["files"][0]["pieces_root"].get_str(), imported.core.files[0].pieces_root.Hex());

    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_CHECK_EQUAL(file_size, imported.core.files[0].size);
    BOOST_CHECK(modelnet::VerifyPiece(imported.core.files[0].pieces_root, file_size, 0, bytes, proof));
    BOOST_CHECK(!modelnet::VerifyPiece(imported.core.files[0].pieces_root, file_size + 1, 0, bytes, proof));

    modelnet::Digest48 other_root{};
    other_root.data[0] = 0x44;
    BOOST_CHECK(!cat.PutFetchedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, other_root, err));

    UniValue bad_file(UniValue::VOBJ);
    bad_file.pushKV("path", imported.core.files[0].path);
    bad_file.pushKV("role", "NOT_A_ROLE");
    bad_file.pushKV("size", imported.core.files[0].size);
    bad_file.pushKV("sha384", imported.core.files[0].sha384.Hex());
    bad_file.pushKV("pieces_root", imported.core.files[0].pieces_root.Hex());
    UniValue bad_files(UniValue::VARR);
    bad_files.push_back(bad_file);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("model_id", imported.model_id.Hex());
    bad.pushKV("artifact_id", imported.artifact_id.Hex());
    bad.pushKV("format_profile", imported.core.format_profile);
    bad.pushKV("execution_profile", imported.core.execution_profile);
    bad.pushKV("files", bad_files);
    BOOST_CHECK(!cat.InstallFromManifest(bad, err));
}

BOOST_AUTO_TEST_CASE(store_05_disk_exhaustion_preserves)
{
    const fs::path tmp = m_path_root / "store-05";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0xA5, /*pin=*/true);
    std::string err;
    BOOST_CHECK(!cat.EnforceQuota(cat.QuotaBytes() + 1, err));
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));

    modelnet::ModelStore store{tmp / "tiny-quota", /*quota*/ 4096};
    modelnet::Digest48 art{};
    art.data[0] = 0x5A;
    const auto leaf = modelnet::ChunkLeaf(0, bytes);
    BOOST_REQUIRE(store.PutVerifiedPiece(art, 0, 0, bytes, leaf, err));
    std::vector<unsigned char> big(5000, 'x');
    const auto leaf_big = modelnet::ChunkLeaf(0, big);
    modelnet::Digest48 art2{};
    art2.data[0] = 0x5B;
    BOOST_CHECK(!store.PutVerifiedPiece(art2, 0, 0, big, leaf_big, err));
    std::vector<unsigned char> kept;
    BOOST_REQUIRE(store.GetPiece(art, 0, 0, kept, err));
    BOOST_CHECK(kept == bytes);
    const std::string root = fs::PathToString(store.Root());
    BOOST_CHECK(root.find("chainstate") == std::string::npos);
    BOOST_CHECK(root.find("wallet") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(store_06_unsafe_paths_rejected)
{
    std::string err;
    BOOST_CHECK(!modelnet::IsPortableRelPath("../etc/passwd", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("/abs", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("CON", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("CON.txt", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("nul.txt", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("foo/../bar", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("foo.", err));
    BOOST_CHECK(modelnet::IsPortableRelPath("model.safetensors", err));
    BOOST_CHECK(modelnet::IsPortableRelPath("tokenizer/vocab.json", err));

    const fs::path tmp = m_path_root / "store-06";
    fs::create_directories(tmp);
    const auto st = TinySafeTensors(0xA6);
    const fs::path reserved = tmp / "CON";
    {
        std::ofstream out(reserved, std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    modelnet::CatalogEntry imported;
    BOOST_CHECK(!cat.ImportPath(fs::PathToString(reserved), /*pin=*/false, imported, err));
}

BOOST_AUTO_TEST_CASE(store_07_crash_recovery_committed_pieces)
{
    const fs::path tmp = m_path_root / "store-07";
    modelnet::CatalogEntry imported;
    std::string err;
    {
        modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
        imported = ImportTiny(cat, tmp / "src", 0xA7, /*pin=*/true);
        std::vector<unsigned char> bytes;
        std::vector<modelnet::Digest48> proof;
        uint64_t file_size = 0;
        BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
        fs::create_directories(cat.Store().Root() / "tmp");
        std::ofstream junk(cat.Store().Root() / "tmp" / "crash.tmp", std::ios::binary);
        junk << "not-a-committed-piece";
    }
    modelnet::ModelCatalog resumed{tmp / "cat", 1 << 20};
    std::vector<unsigned char> got;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(resumed.GetVerifiedPiece(imported.artifact_id, 0, 0, got, proof, file_size, err));
    BOOST_CHECK_EQUAL(got.size(), imported.core.files[0].size);
    BOOST_REQUIRE(resumed.VerifyFileDigest(imported.artifact_id, 0, imported.core.files[0].sha384, err));
    modelnet::CatalogEntry found;
    BOOST_REQUIRE(resumed.Find(imported.artifact_id, found));
}

BOOST_AUTO_TEST_CASE(store_08_gc_pins_prevent_eviction)
{
    const fs::path tmp = m_path_root / "store-08";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto unpinned = ImportTiny(cat, tmp / "u", 0xB0, /*pin=*/false);
    const auto pinned = ImportTiny(cat, tmp / "p", 0xB1, /*pin=*/true);
    BOOST_CHECK(!unpinned.pinned);
    BOOST_CHECK(pinned.pinned);

    modelnet::EvictItem pin_item;
    pin_item.pinned = true;
    pin_item.artifact_id = pinned.artifact_id;
    modelnet::EvictItem free_item;
    free_item.pinned = false;
    free_item.artifact_id = unpinned.artifact_id;
    BOOST_CHECK_GT(modelnet::EvictPriority(pin_item), modelnet::EvictPriority(free_item));

    const uint64_t used = cat.UsedBytes();
    BOOST_REQUIRE(used > pinned.core.files[0].size);
    modelnet::PreservationPolicy p = cat.Policy();
    p.storage_quota_bytes = used - 1;
    cat.SetPolicy(p);
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.EnforceQuota(0, err), err);

    modelnet::CatalogEntry still;
    BOOST_REQUIRE(cat.Find(pinned.artifact_id, still));
    BOOST_CHECK(still.pinned);
    modelnet::CatalogEntry gone;
    BOOST_CHECK(!cat.Find(unpinned.artifact_id, gone));

    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(pinned.artifact_id, 0, 0, bytes, proof, file_size, err));
    BOOST_CHECK(!cat.GetVerifiedPiece(unpinned.artifact_id, 0, 0, bytes, proof, file_size, err));
}

BOOST_AUTO_TEST_CASE(store_verified_piece_cache_stable_proofs)
{
    const fs::path tmp = m_path_root / "store-piece-tree-cache";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const auto imported = ImportTiny(cat, tmp / "src", 0xC0, /*pin=*/true);
    std::string err;
    std::vector<unsigned char> first_bytes, second_bytes;
    std::vector<modelnet::Digest48> first_proof, second_proof;
    uint64_t first_size = 0, second_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, first_bytes, first_proof, first_size, err));
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, second_bytes, second_proof, second_size, err));
    // Second call must match first: Merkle cache must not change bytes, proof, or size.
    BOOST_CHECK(first_bytes == second_bytes);
    BOOST_REQUIRE_EQUAL(first_proof.size(), second_proof.size());
    BOOST_CHECK(first_proof == second_proof);
    BOOST_CHECK_EQUAL(first_size, second_size);
    BOOST_CHECK_EQUAL(first_size, imported.core.files[0].size);
    BOOST_CHECK(modelnet::VerifyPiece(imported.core.files[0].pieces_root, first_size, 0, first_bytes, first_proof));
    BOOST_CHECK(modelnet::VerifyPiece(imported.core.files[0].pieces_root, second_size, 0, second_bytes, second_proof));
}

BOOST_AUTO_TEST_SUITE_END()
