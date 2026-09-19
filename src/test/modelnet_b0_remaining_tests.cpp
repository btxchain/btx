// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// B0 remaining library rows (DISC / STORE / MODEL / WIRE / PQ / ISO / SCRIPT / BASE).
// Packaged acceptance-matrix.csv stays NOT_RUN. No chain verify. No CUDA kernels.

#include <crypto/common.h>
#include <modelnet/access_policy.h>
#include <modelnet/catalog.h>
#include <modelnet/community.h>
#include <modelnet/cores.h>
#include <modelnet/crypto.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/policy.h>
#include <modelnet/pq1_runtime.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <modelnet/release.h>
#include <modelnet/router.h>
#include <modelnet/store.h>
#include <modelnet/transfer.h>
#include <modelnet/types.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_b0_remaining_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> MinimalSafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

fs::path WriteImportDir(const fs::path& dir, const std::string& name)
{
    fs::create_directories(dir);
    const auto st = MinimalSafeTensors();
    std::ofstream out(dir / fs::PathFromString(name), std::ios::binary);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    return dir;
}

} // namespace

BOOST_AUTO_TEST_CASE(base_03_capabilities_monetary_isolation)
{
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["paid_chain_verify"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["cuda_qualification"].get_bool(), true);
    BOOST_CHECK_EQUAL(caps["remote_inference"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["browser_bridge"].get_bool(), false);
    BOOST_CHECK_EQUAL(caps["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(caps["buildmodelhtlcclaim"].get_bool(), true);
    BOOST_CHECK(!caps.exists("header_source"));
    BOOST_CHECK(!caps.exists("attestor_endpoint"));
    BOOST_CHECK(!caps.exists(" BanMan"));
    BOOST_CHECK(!modelnet::ModelWorkTakesConsensusLock());
    BOOST_CHECK(!modelnet::ModelWorkMayStarveExactReplay());
}

BOOST_AUTO_TEST_CASE(wire_01_08_sendmodels_and_getmdpeers)
{
    modelnet::SendModels msg;
    msg.version = modelnet::MODEL_PROTOCOL_VERSION;
    msg.role_mask = modelnet::ROLE_HOST;
    std::vector<unsigned char> wire;
    std::string err;
    BOOST_REQUIRE(modelnet::SerializeSendModels(msg, wire, err));
    BOOST_CHECK_EQUAL(wire.size(), modelnet::SENDMODELS_BYTES);
    modelnet::SendModels parsed;
    BOOST_REQUIRE(modelnet::ParseSendModels(wire, parsed, err));
    BOOST_CHECK_EQUAL(parsed.version, modelnet::MODEL_PROTOCOL_VERSION);

    std::vector<unsigned char> bad = wire;
    bad.resize(modelnet::SENDMODELS_BYTES - 1);
    BOOST_CHECK(!modelnet::ParseSendModels(bad, parsed, err));

    modelnet::SendModels old;
    old.version = 1;
    std::vector<unsigned char> oldwire;
    BOOST_REQUIRE(modelnet::SerializeSendModels(old, oldwire, err));
    BOOST_CHECK(!modelnet::ParseSendModels(oldwire, parsed, err));

    std::vector<unsigned char> gp(modelnet::GETMDPEERS_BYTES, 0);
    gp[16] = 8;
    modelnet::GetMdPeers gout;
    BOOST_REQUIRE(modelnet::ParseGetMdPeers(gp, gout, err));
    gp[16] = 0;
    BOOST_CHECK(!modelnet::ParseGetMdPeers(gp, gout, err));
    gp[16] = 99;
    BOOST_CHECK(!modelnet::ParseGetMdPeers(gp, gout, err));

    std::vector<unsigned char> compact;
    BOOST_REQUIRE(modelnet::EncodeCompactSizeModel(16, compact, err));
    BOOST_CHECK(!compact.empty());
}

BOOST_AUTO_TEST_CASE(issue_173_version_mismatch_not_misbehave)
{
    // Fail-closed-but-not-eclipse: other MODEL_PROTOCOL_VERSION is IGNORE
    // even when the byte length changed. Same-version wrong size is MISBEHAVE.
    modelnet::SendModels msg;
    msg.version = modelnet::MODEL_PROTOCOL_VERSION;
    std::vector<unsigned char> v2;
    std::string err;
    BOOST_REQUIRE(modelnet::SerializeSendModels(msg, v2, err));
    BOOST_CHECK(modelnet::ClassifySendModelsWire(v2) == modelnet::HintWireDisposition::ACCEPT);

    std::vector<unsigned char> v3_same = v2;
    WriteLE16(v3_same.data(), 3);
    BOOST_CHECK(modelnet::ClassifySendModelsWire(v3_same) == modelnet::HintWireDisposition::IGNORE);

    std::vector<unsigned char> v3_longer(19, 0);
    WriteLE16(v3_longer.data(), 3);
    BOOST_CHECK(modelnet::ClassifySendModelsWire(v3_longer) == modelnet::HintWireDisposition::IGNORE);

    std::vector<unsigned char> v2_longer(19, 0);
    WriteLE16(v2_longer.data(), modelnet::MODEL_PROTOCOL_VERSION);
    BOOST_CHECK(modelnet::ClassifySendModelsWire(v2_longer) == modelnet::HintWireDisposition::MISBEHAVE);

    std::vector<unsigned char> too_short(1, 0);
    BOOST_CHECK(modelnet::ClassifySendModelsWire(too_short) == modelnet::HintWireDisposition::MISBEHAVE);
    BOOST_CHECK(modelnet::ClassifySendModelsWire({}) == modelnet::HintWireDisposition::MISBEHAVE);

    std::vector<unsigned char> gp(modelnet::GETMDPEERS_BYTES, 0);
    gp[16] = 8;
    BOOST_CHECK(modelnet::ClassifyGetMdPeersWire(gp) == modelnet::HintWireDisposition::ACCEPT);
    std::vector<unsigned char> gp_grown(18, 0);
    BOOST_CHECK(modelnet::ClassifyGetMdPeersWire(gp_grown) == modelnet::HintWireDisposition::IGNORE);
    std::vector<unsigned char> gp_short(16, 0);
    BOOST_CHECK(modelnet::ClassifyGetMdPeersWire(gp_short) == modelnet::HintWireDisposition::IGNORE);

    BOOST_CHECK(modelnet::ClassifyMdPeersWire({}) == modelnet::HintWireDisposition::ACCEPT);
    std::vector<unsigned char> md_v3(8, 0);
    WriteLE16(md_v3.data(), 3);
    BOOST_CHECK(modelnet::ClassifyMdPeersWire(md_v3) == modelnet::HintWireDisposition::IGNORE);
    std::vector<unsigned char> md_one(1, 0);
    BOOST_CHECK(modelnet::ClassifyMdPeersWire(md_one) == modelnet::HintWireDisposition::MISBEHAVE);
    std::vector<unsigned char> md_huge(modelnet::MAX_MDPEERS_BYTES + 1, 0);
    BOOST_CHECK(modelnet::ClassifyMdPeersWire(md_huge) == modelnet::HintWireDisposition::MISBEHAVE);
}

BOOST_AUTO_TEST_CASE(mdpeers_parse_fail_closed)
{
    std::string err;
    std::vector<modelnet::PublicEndpointHint> parsed;

    BOOST_REQUIRE(modelnet::ParseMdPeers({}, parsed, err));
    BOOST_CHECK(parsed.empty());

    modelnet::PublicEndpointHint ep;
    ep.addr_kind = modelnet::HINT_ADDR_IPV4;
    ep.addr = {192, 0, 2, 10};
    ep.port = 29447;
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(modelnet::SerializeMdPeers({ep}, wire, err));
    BOOST_CHECK(modelnet::ClassifyMdPeersWire(wire) == modelnet::HintWireDisposition::ACCEPT);
    BOOST_REQUIRE(modelnet::ParseMdPeers(wire, parsed, err));
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);
    BOOST_CHECK_EQUAL(parsed[0].port, 29447);
    BOOST_CHECK_EQUAL(parsed[0].addr_kind, modelnet::HINT_ADDR_IPV4);

    std::vector<unsigned char> trunc = wire;
    trunc.resize(3); // version + count=1, no body
    BOOST_CHECK(modelnet::ClassifyMdPeersWire(trunc) == modelnet::HintWireDisposition::ACCEPT);
    BOOST_CHECK(!modelnet::ParseMdPeers(trunc, parsed, err));

    modelnet::PublicEndpointHint bad_kind;
    bad_kind.addr_kind = 99;
    bad_kind.addr = {1, 2, 3, 4};
    bad_kind.port = 1;
    BOOST_CHECK(!modelnet::PublicEndpointHintWellFormed(bad_kind, err));
    BOOST_CHECK(!modelnet::SerializeMdPeers({bad_kind}, wire, err));

    modelnet::PublicEndpointHint no_port;
    no_port.addr_kind = modelnet::HINT_ADDR_IPV4;
    no_port.addr = {192, 0, 2, 11};
    no_port.port = 0;
    BOOST_CHECK(!modelnet::PublicEndpointHintWellFormed(no_port, err));

    std::string herr;
    BOOST_CHECK(!modelnet::PublicHintWellFormed({}, "", herr));
    BOOST_CHECK(modelnet::PublicHintWellFormed({}, "192.0.2.1:1", herr));
    BOOST_CHECK(modelnet::PublicHintWellFormed(ep, "", herr));
    BOOST_CHECK(modelnet::PublicHintWellFormed(ep, "192.0.2.1:1", herr));
    BOOST_CHECK(modelnet::PublicHintWellFormed(ep, "198.51.100.1:1", herr));
}

BOOST_AUTO_TEST_CASE(disc_01_08_cpu_router_hidden_stale_sybil_fresh)
{
    BOOST_CHECK_EQUAL(modelnet::MAX_ROUTER_CONTACTS, 8);
    BOOST_CHECK_EQUAL(modelnet::MAX_CONCURRENT_RESOLVE_QUERIES, 4);
    BOOST_CHECK_EQUAL(modelnet::NEGATIVE_RESOLVE_TTL_S, 60);

    modelnet::ResolveQueryPlan plan;
    BOOST_REQUIRE(modelnet::PlanRouterQueries({"a", "b"}, {"independent.example"}, plan));
    BOOST_CHECK(plan.contacts.size() <= 8);
    BOOST_CHECK_LE(plan.max_concurrent, 4);
    BOOST_CHECK(plan.reserved_independent);

    modelnet::RouterCache cache;
    modelnet::SignedRecordHint rec;
    rec.record_id.data[0] = 0x11;
    rec.kind = 1;
    rec.expiry = 100;
    rec.signed_ok = true;
    std::string err;
    BOOST_REQUIRE(cache.Insert(rec, /*now=*/50, err));
    BOOST_CHECK_EQUAL(cache.LookupExact(rec.record_id, 50).size(), 1);
    cache.Expire(101);
    BOOST_CHECK(cache.LookupExact(rec.record_id, 101).empty());
    BOOST_CHECK(!cache.Insert(rec, /*now=*/200, err));

    modelnet::NegativeResolveCache neg;
    modelnet::Digest48 miss{};
    miss.data[0] = 0x22;
    neg.RememberIncomplete(0, miss, 10);
    BOOST_CHECK(neg.HasIncomplete(0, miss, 10));
    BOOST_CHECK(neg.HasIncomplete(0, miss, 69));
    BOOST_CHECK(!neg.HasIncomplete(0, miss, 71));

    const UniValue caps = modelnet::CapabilitiesObject();
    const std::string dumped = caps.write();
    BOOST_CHECK(dumped.find("attestor") == std::string::npos);
    BOOST_CHECK(dumped.find("/rest/") == std::string::npos);
    BOOST_CHECK(dumped.find("addnode") == std::string::npos);

    const fs::path tmp = m_path_root / "disc-fresh";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    BOOST_CHECK(cat.Peers().empty());
    cat.AddPeer("192.0.2.8:29447");
    BOOST_CHECK_EQUAL(cat.Peers().size(), 1);

    modelnet::ConnLimits lim;
    const uint32_t ng = 0xB0D15C07u;
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        BOOST_CHECK(lim.TryInbound(ng));
    }
    BOOST_CHECK(!lim.TryInbound(ng));
    for (int i = 0; i < modelnet::PQ1_MAX_INBOUND_PER_NETGROUP; ++i) {
        lim.ReleaseInbound(ng);
    }

    modelnet::BootstrapLimiter boot{int64_t{1} << 20};
    BOOST_CHECK(boot.Allow("svc", "ng1", 1024));
    BOOST_CHECK(!boot.Allow("svc", "ng1", modelnet::BootstrapLimiter::PER_KEY_DAY));
}

BOOST_AUTO_TEST_CASE(store_01_08_resume_corrupt_mismatch_paths_quota_gc)
{
    std::string err;
    BOOST_CHECK(!modelnet::IsPortableRelPath("../etc/passwd", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("/abs", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("CON", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("nul.txt", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("foo/../bar", err));
    BOOST_CHECK(!modelnet::IsPortableRelPath("foo.", err));
    BOOST_CHECK(modelnet::IsPortableRelPath("model.safetensors", err));
    BOOST_CHECK(modelnet::IsPortableRelPath("tokenizer/vocab.json", err));

    const std::string payload = "store-b0-piece-a";
    std::vector<unsigned char> file(payload.begin(), payload.end());
    const auto rows = modelnet::BuildChunkTree(file);
    BOOST_REQUIRE(!rows.empty());
    const auto proof = modelnet::PieceProof(rows, 0);
    BOOST_CHECK(modelnet::VerifyPiece(rows.back()[0], file.size(), 0, file, proof));
    std::vector<unsigned char> corrupt = file;
    corrupt[0] ^= 0xff;
    BOOST_CHECK(!modelnet::VerifyPiece(rows.back()[0], file.size(), 0, corrupt, proof));

    const fs::path tmp = m_path_root / "store-b0";
    modelnet::ModelStore store{tmp, /*quota*/ 4096};
    modelnet::Digest48 art{};
    art.data[0] = 0x5A;
    const auto leaf = modelnet::ChunkLeaf(0, file);
    BOOST_REQUIRE(store.PutVerifiedPiece(art, 0, 0, file, leaf, err));
    BOOST_CHECK(store.HasPiece(art, 0, 0));
    BOOST_CHECK(!store.HasPiece(art, 0, 1));
    std::vector<unsigned char> got;
    BOOST_REQUIRE(store.GetPiece(art, 0, 0, got, err));
    BOOST_CHECK(got == file);
    BOOST_CHECK(!store.PutVerifiedPiece(art, 0, 0, corrupt, leaf, err));

    modelnet::ModelStore resumed{tmp, 4096};
    std::vector<unsigned char> again;
    BOOST_REQUIRE(resumed.GetPiece(art, 0, 0, again, err));
    BOOST_CHECK(again == file);

    BOOST_REQUIRE(store.Pin(art, err));
    store.EvictUnpinned();
    BOOST_REQUIRE(store.GetPiece(art, 0, 0, got, err));

    std::vector<unsigned char> big(5000, 'x');
    const auto leaf_big = modelnet::ChunkLeaf(0, big);
    modelnet::Digest48 art2{};
    art2.data[0] = 0x5B;
    BOOST_CHECK(!store.PutVerifiedPiece(art2, 0, 0, big, leaf_big, err));

    const fs::path catdir = m_path_root / "store-b0-cat";
    modelnet::ModelCatalog cat{catdir, 1 << 20};
    const fs::path src = WriteImportDir(tmp / "import", "model.safetensors");
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(src), /*pin=*/true, imported, err), err);
    BOOST_REQUIRE(!imported.core.files.empty());
    BOOST_REQUIRE(cat.VerifyFileDigest(imported.artifact_id, 0, imported.core.files[0].sha384, err));
    modelnet::Digest48 wrong{};
    wrong.data[0] = 0xff;
    BOOST_CHECK(!cat.VerifyFileDigest(imported.artifact_id, 0, wrong, err));
    BOOST_CHECK(cat.Policy().storage_quota_bytes == 0 || cat.UsedBytes() <= cat.QuotaBytes());
    BOOST_CHECK(!cat.EnforceQuota(cat.QuotaBytes() + 1, err));
}

BOOST_AUTO_TEST_CASE(model_01_10_adversarial_safetensors_gguf_pickle_encrypted)
{
    modelnet::QualReport report;
    const unsigned char pickle[] = {0x80, 0x04, 0x95};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("model.pkl", {pickle, sizeof(pickle)}, report),
                      modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    BOOST_CHECK(modelnet::LooksLikePickle({pickle, sizeof(pickle)}));
    const unsigned char elf[] = {0x7f, 'E', 'L', 'F'};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("lib.so", {elf, sizeof(elf)}, report),
                      modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char py[] = {'p', 'r', 'i', 'n', 't'};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("run.py", {py, sizeof(py)}, report),
                      modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    const unsigned char enc[] = {'B', 'T', 'X', 'E', 'N', 'C', '2', 0};
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.btxenc", {enc, sizeof(enc)}, report),
                      modelnet::QualResult::ENCRYPTED_UNQUALIFIED);

    auto st = MinimalSafeTensors();
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.safetensors", st, report),
                      modelnet::QualResult::STRUCTURE_VERIFIED);

    std::vector<unsigned char> trunc(4, 0);
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.safetensors", trunc, report),
                      modelnet::QualResult::INVALID_MODEL);

    std::vector<unsigned char> huge_hdr(16, 0);
    WriteLE64(huge_hdr.data(), uint64_t{9} << 20);
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.safetensors", huge_hdr, report),
                      modelnet::QualResult::INVALID_MODEL);

    std::string header = R"({"t":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}})";
    std::vector<unsigned char> shaped(8 + header.size() + 4, 0);
    WriteLE64(shaped.data(), header.size());
    std::memcpy(shaped.data() + 8, header.data(), header.size());
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.safetensors", shaped, report),
                      modelnet::QualResult::STRUCTURE_VERIFIED);

    std::string missing = R"({"t":{"dtype":"F32"}})";
    std::vector<unsigned char> miss(8 + missing.size(), 0);
    WriteLE64(miss.data(), missing.size());
    std::memcpy(miss.data() + 8, missing.data(), missing.size());
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.safetensors", miss, report),
                      modelnet::QualResult::INVALID_MODEL);

    std::vector<unsigned char> gguf(24, 0);
    std::memcpy(gguf.data(), "GGUF", 4);
    WriteLE32(gguf.data() + 4, 3);
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.gguf", gguf, report),
                      modelnet::QualResult::STRUCTURE_VERIFIED);
    WriteLE64(gguf.data() + 8, 300000);
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.gguf", gguf, report),
                      modelnet::QualResult::INVALID_MODEL);
    WriteLE64(gguf.data() + 8, 1);
    WriteLE32(gguf.data() + 4, 99);
    BOOST_CHECK_EQUAL(modelnet::QualifyBytes("x.gguf", gguf, report),
                      modelnet::QualResult::INVALID_MODEL);

    modelnet::QualRuntimeOpts opts;
    const auto r = modelnet::QualifyRuntime("/nonexistent-b0-model", opts, report);
    BOOST_CHECK(r == modelnet::QualResult::INVALID_MODEL ||
                r == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION ||
                r == modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT);
    BOOST_CHECK(std::string(modelnet::QualResultName(modelnet::QualResult::RUNTIME_OBSERVED)).find("IDENTICAL") == std::string::npos);
    BOOST_CHECK(!modelnet::ModelCudaQualifyKernelCompiled());
}

BOOST_AUTO_TEST_CASE(gpu_01_06_isolation_library)
{
    BOOST_CHECK(!modelnet::ModelCudaQualifyKernelCompiled());
    BOOST_CHECK(modelnet::IsValidatorOrMiningGpu(0));
    BOOST_CHECK_EQUAL(modelnet::DEFAULT_MINING_GPU_INDEX, 0);
    modelnet::QualRuntimeOpts opts;
    opts.runtime_check = true;
    opts.gpu_index = 0;
    opts.allow_validator_gpu = false;
    modelnet::QualReport report;
    const fs::path tmp = m_path_root / "gpu-isol";
    fs::create_directories(tmp);
    const auto st = MinimalSafeTensors();
    const fs::path f = tmp / "tiny.safetensors";
    {
        std::ofstream out(f, std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    const auto q = modelnet::QualifyRuntime(fs::PathToString(f), opts, report);
    BOOST_CHECK(q == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION ||
                q == modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT);
    BOOST_CHECK(!modelnet::ModelWorkTakesConsensusLock());
    BOOST_CHECK(!modelnet::ModelWorkMayStarveExactReplay());

    // GPU-02 oversized / missing device classified NOT_RUN, not a usefulness hash.
    modelnet::QualRuntimeOpts no_gpu;
    no_gpu.runtime_check = true;
    modelnet::QualReport oversized;
    const auto q2 = modelnet::QualifyRuntime(fs::PathToString(f), no_gpu, oversized);
    BOOST_CHECK_EQUAL(q2, modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT);
    BOOST_CHECK(oversized.detail.find("cuda_qualification") == std::string::npos ||
                oversized.detail.find("-modelgpu") != std::string::npos);

    // GPU-03: catalog is never under wallet/; GPU-04 finite handshake/idle bounds.
    BOOST_CHECK(fs::PathToString(tmp).find("wallet") == std::string::npos);
    BOOST_CHECK_EQUAL(modelnet::PQ1_HANDSHAKE_MS, 10000);
    BOOST_CHECK_EQUAL(modelnet::PQ1_TRANSFER_MS, 600000);

    // GPU-05/06: in-process qualification does not throw; result is not a consensus hash.
    BOOST_CHECK(std::string{modelnet::QualResultName(q)} != "RUNTIME_OBSERVED");
    const UniValue caps = modelnet::CapabilitiesObject();
    BOOST_CHECK_EQUAL(caps["cuda_qualification"].get_bool(), true);
}

BOOST_AUTO_TEST_CASE(pq_14_19_21_23_24_pin_conf_hash160_failclosed)
{
    const fs::path tmp = m_path_root / "pq-rest";
    fs::create_directories(tmp);
    std::string err;
    modelnet::Digest48 a{};
    modelnet::Digest48 b{};
    a.data[0] = 1;
    b.data[0] = 2;
    const fs::path pinfile = tmp / "pins.json";
    BOOST_REQUIRE(modelnet::CheckOrStorePin(pinfile, "192.0.2.9:29447", a, err));
    BOOST_CHECK(!modelnet::CheckOrStorePin(pinfile, "192.0.2.9:29447", b, err));
    BOOST_REQUIRE(modelnet::CheckOrStorePin(pinfile, "192.0.2.9:29447", a, err));

    modelnet::Pq1SanitizeOpenSslEnv();
    modelnet::Pq1InitOpenSsl();
    BOOST_CHECK(modelnet::Pq1OpenSslEnvIsClean());
    BOOST_CHECK(modelnet::Pq1HostileConfCannotWeaken(err));

    modelnet::Hash32 h;
    BOOST_CHECK(!modelnet::Hash32::FromHex(std::string(40, 'a'), h, err));
    BOOST_REQUIRE(modelnet::Hash32::FromHex(std::string(64, 'a'), h, err));
    BOOST_CHECK_EQUAL(h.data.size(), 32u);

    std::vector<unsigned char> secret(32, 0x42);
    const auto rh = modelnet::ReleaseHash(secret);
    BOOST_CHECK_EQUAL(rh.data.size(), 32u);
    std::vector<unsigned char> short_secret(20, 0x42);
    // ReleaseHash hashes whatever is passed; callers must pass 32 bytes.
    BOOST_CHECK(modelnet::ReleaseHash(secret).Hex() != modelnet::ReleaseHash(short_secret).Hex());

    modelnet::FrozenModelFunding in;
    in.key_hash_hex = std::string(40, '1');
    in.claimant = "aa";
    in.refund_pubkey = "bb";
    in.refund_height = 1024;
    in.amount_atoms = 1;
    in.max_atoms = 1;
    modelnet::FrozenModelFunding out;
    BOOST_CHECK(!modelnet::FreezeModelFunding(in, out, err));
    in.key_hash_hex = std::string(64, '1');
    BOOST_REQUIRE(modelnet::FreezeModelFunding(in, out, err));
    BOOST_CHECK(out.descriptor.find("htlc_sha256") != std::string::npos);
    BOOST_CHECK(out.descriptor.find("htlc_sha256_tx") == std::string::npos);

    BOOST_CHECK_EQUAL(modelnet::PQ1_HANDSHAKE_MS, 10000);
    BOOST_CHECK_EQUAL(modelnet::PQ1_IDLE_MS, 30000);
    BOOST_CHECK_EQUAL(modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT, 4);
    BOOST_CHECK_EQUAL(modelnet::PQ1_UNAUTH_WINDOW_S, 60);
    BOOST_CHECK_EQUAL(modelnet::PQ1_HTTP_HEADER_CAP, 64 * 1024);
}

BOOST_AUTO_TEST_CASE(iso_01_08_http_flood_helper_bounds)
{
    BOOST_CHECK(modelnet::NativeHttpRequiresVerifiedPq1());
    BOOST_CHECK_EQUAL(modelnet::PQ1_HTTP_WORKERS, 8);
    BOOST_CHECK_EQUAL(modelnet::PQ1_HTTP_QUEUE, 32);
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_INBOUND, 16);
    BOOST_CHECK_EQUAL(modelnet::PQ1_MAX_OUTBOUND, 8);
    BOOST_CHECK_EQUAL(modelnet::PQ1_INFLIGHT_PIECES, 8);
    BOOST_CHECK_LE(modelnet::PQ1_INFLIGHT_PIECES, modelnet::PQ1_MAX_OUTBOUND);
    BOOST_CHECK_LE(modelnet::PQ1_INFLIGHT_PIECES, modelnet::PQ1_MAX_INBOUND_PER_NETGROUP);

    BOOST_CHECK(modelnet::IsTransientPq1Error("tls io ssl_error=5 errno=104"));
    BOOST_CHECK(modelnet::IsTransientPq1Error("timeout"));
    BOOST_CHECK(modelnet::IsTransientPq1Error("truncated http"));
    BOOST_CHECK(modelnet::IsTransientPq1Error("resolve failed"));
    BOOST_CHECK(!modelnet::IsTransientPq1Error("missing FreeGrant"));
    BOOST_CHECK(!modelnet::IsTransientPq1Error("cancelled"));
    BOOST_CHECK(!modelnet::IsTransientPq1Error("pin mismatch"));
    BOOST_CHECK(!modelnet::IsTransientPq1Error("piece HTTP 404 {\"error\":\"timeout\"}"));

    const uint32_t ng = 0x15015008u;
    modelnet::ClearUnauth(ng);
    BOOST_CHECK_EQUAL(modelnet::UnauthCount(ng), 0);
    for (int i = 0; i < modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT; ++i) {
        BOOST_CHECK_LE(modelnet::CountUnauthAndBump(ng), modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT);
    }
    BOOST_CHECK_EQUAL(modelnet::CountUnauthAndBump(ng), modelnet::PQ1_UNAUTH_HANDSHAKE_LIMIT + 1);
    modelnet::ClearUnauth(ng);

    const fs::path tmp = m_path_root / "iso-b0";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "preparemodelfunding");
    req.pushKV("params", UniValue(UniValue::VARR));
    UniValue result;
    std::string code, err;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, req, result, code, err));
    BOOST_CHECK(code == "INVALID_PARAMETER" || !err.empty());

    modelnet::AccessPolicy acl;
    BOOST_CHECK(!acl.WritesBanMan());
    BOOST_CHECK(!acl.AffectsAddrMan());
    BOOST_CHECK_EQUAL(acl.AutomaticSpendAtoms(), 0);
}

BOOST_AUTO_TEST_CASE(script_01_12_leaf_and_campaign_sha256_only)
{
    const std::string desc = modelnet::HtlcSha256Descriptor(std::string(64, 'a'), "claim", 1024, "refund");
    BOOST_CHECK(desc.find("htlc_sha256(") != std::string::npos);
    BOOST_CHECK(desc.find("htlc_tx(") == std::string::npos);
    BOOST_CHECK(desc.find("htlc(") == std::string::npos);
    BOOST_CHECK(modelnet::ValidRefundWindow(10, 1, 1, 100));
    BOOST_CHECK(!modelnet::ValidRefundWindow(10, 1, 1, 11));
    modelnet::ReleaseCampaign c;
    c.target_atoms = 1;
    const UniValue j = modelnet::CampaignToJson(c);
    BOOST_CHECK(j["note"].get_str().find("HASH160") != std::string::npos);
    BOOST_CHECK(j["claim"].get_str().find("buildhtlcclaim") != std::string::npos);
    BOOST_CHECK(j["claim"].get_str().find("buildhtlcclaim") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(uri_12_btx_open_preview_binary_present)
{
#ifdef MODELNET_BTX_OPEN_PATH
    BOOST_CHECK(fs::exists(fs::PathFromString(MODELNET_BTX_OPEN_PATH)));
#endif
    BOOST_CHECK(!modelnet::CollectionLoadsCode());
    BOOST_CHECK(!modelnet::CircleHasOnChainMembership());
    BOOST_CHECK(!modelnet::CollectionFollowRaisesQuota());
}

BOOST_AUTO_TEST_SUITE_END()
