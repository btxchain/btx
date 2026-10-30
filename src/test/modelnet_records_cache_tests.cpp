// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// /btx-model/2/records/announce and /ext/objects/announce cache typed records
// that any PQ1 peer signs with a key it made itself.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/records.h>
#include <modelnet/router.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

extern "C" {
#include <libbitcoinpqc/ml_dsa.h>
}

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_records_cache_tests, BasicTestingSetup)

namespace {

struct Signer {
    std::vector<unsigned char> pk, sk;
    modelnet::Digest48 id;
};

Signer NewSigner()
{
    Signer s;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(s.pk, s.sk, err));
    s.id = modelnet::PublisherId(s.pk);
    return s;
}

struct Record {
    UniValue body;
    std::vector<unsigned char> payload, sig;
};

/** A Collection record with `entries` model entries. */
Record MakeCollection(const Signer& s, int64_t now, int64_t expires_at, int entries, int salt)
{
    Record r;
    r.body = UniValue(UniValue::VOBJ);
    modelnet::FillRecordCommon(r.body, 1, s.id, now, 0);
    r.body.pushKV("expires_at", expires_at);
    r.body.pushKV("title", "c" + std::to_string(salt));
    r.body.pushKV("description", std::string(entries > 1 ? 1024 : 8, 'd'));
    std::vector<std::string> ids;
    for (int e = 0; e < entries; ++e) {
        unsigned char b[48];
        GetRandBytes(Span<unsigned char>{b, 32});
        GetRandBytes(Span<unsigned char>{b + 32, 16});
        ids.push_back(HexStr(b));
    }
    std::sort(ids.begin(), ids.end());
    UniValue arr(UniValue::VARR);
    for (const auto& id : ids) {
        UniValue en(UniValue::VOBJ);
        en.pushKV("model_id", id);
        en.pushKV("priority", 1);
        en.pushKV("retention_days", 1);
        arr.push_back(en);
    }
    r.body.pushKV("entries", arr);
    modelnet::Digest48 rid;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::SignTypedRecord(modelnet::RECORD_COLLECTION, r.body, s.sk, r.payload, r.sig, rid, err), err);
    return r;
}

/** Another valid signature over the same record (hedged ML-DSA signing). */
std::vector<unsigned char> FreshSignature(const Signer& s, const Record& r)
{
    modelnet::Digest48 msg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::SigningMessage(modelnet::RECORD_COLLECTION, r.body, msg, err), err);
    std::vector<unsigned char> sig(ML_DSA_44_SIGNATURE_SIZE);
    size_t len = sig.size();
    unsigned char rnd[32];
    GetRandBytes(rnd);
    BOOST_REQUIRE_EQUAL(ml_dsa_44_sign_with_randomness(sig.data(), &len, msg.data.data(), msg.data.size(),
                                                       s.sk.data(), rnd, sizeof(rnd)), 0);
    sig.resize(len);
    return sig;
}

modelnet::NativeResponse Announce(modelnet::ModelCatalog& cat, const std::string& route, const Signer& s,
                                  const Record& r, const std::vector<unsigned char>& sig)
{
    UniValue env(UniValue::VOBJ);
    env.pushKV("kind", modelnet::RECORD_COLLECTION);
    env.pushKV("payload_hex", HexStr(r.payload));
    env.pushKV("sig_hex", HexStr(sig));
    env.pushKV("pubkey_hex", HexStr(s.pk));
    modelnet::NativeRequest req;
    req.method = "POST";
    req.path = "/btx-model/2/" + route;
    req.body = env.write();
    modelnet::NativeResponse resp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
    return resp;
}

modelnet::NativeResponse Announce(modelnet::ModelCatalog& cat, const std::string& route, const Signer& s, const Record& r)
{
    return Announce(cat, route, s, r, r.sig);
}

size_t RecordsOnDisk(const fs::path& helper_dir)
{
    std::ifstream in(helper_dir / "records.json");
    if (!in) return 0;
    std::ostringstream ss;
    ss << in.rdbuf();
    UniValue arr;
    if (!arr.read(ss.str()) || !arr.isArray()) return 0;
    return arr.size();
}

int64_t Now() { return static_cast<int64_t>(std::time(nullptr)); }

} // namespace

BOOST_AUTO_TEST_CASE(announces_do_not_rewrite_records_json_each_time)
{
    const fs::path tmp = m_path_root / "records-batch";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const Signer s = NewSigner();
    for (int k = 0; k < 16; ++k) {
        const auto resp = Announce(cat, "records/announce", s, MakeCollection(s, Now(), 0, 1, k));
        BOOST_REQUIRE_MESSAGE(resp.status == 200, resp.body);
    }
    // The cache answers at once; the helper writes records.json on its own schedule.
    BOOST_CHECK(!fs::exists(tmp / "records.json"));
    modelnet::FlushRecords(cat);
    BOOST_CHECK_EQUAL(RecordsOnDisk(tmp), 16U);
    fs::remove(tmp / "records.json");
    modelnet::FlushRecords(cat);
    BOOST_CHECK(!fs::exists(tmp / "records.json"));
}

BOOST_AUTO_TEST_CASE(record_already_cached_is_not_written_again)
{
    const fs::path tmp = m_path_root / "records-again";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const Signer s = NewSigner();
    std::vector<Record> recs;
    for (int k = 0; k < 4; ++k) {
        recs.push_back(MakeCollection(s, Now(), 0, 1, k));
        const auto resp = Announce(cat, "ext/objects/announce", s, recs.back());
        BOOST_REQUIRE_MESSAGE(resp.status == 200, resp.body);
    }
    modelnet::FlushRecords(cat);
    BOOST_REQUIRE_EQUAL(RecordsOnDisk(tmp), 4U);
    fs::remove(tmp / "records.json");

    // The same record again: byte for byte, then with another valid signature.
    const auto fresh = FreshSignature(s, recs[0]);
    BOOST_REQUIRE(fresh != recs[0].sig);
    for (const auto& sig : {recs[0].sig, fresh}) {
        const auto resp = Announce(cat, "ext/objects/announce", s, recs[0], sig);
        BOOST_REQUIRE_MESSAGE(resp.status == 200, resp.body);
    }
    modelnet::FlushRecords(cat);
    BOOST_CHECK(!fs::exists(tmp / "records.json"));

    // A new record is written.
    const auto resp = Announce(cat, "ext/objects/announce", s, MakeCollection(s, Now(), 0, 1, 4));
    BOOST_REQUIRE_MESSAGE(resp.status == 200, resp.body);
    modelnet::FlushRecords(cat);
    BOOST_CHECK_EQUAL(RecordsOnDisk(tmp), 5U);
}

BOOST_AUTO_TEST_CASE(helper_writes_announced_records_when_it_stops)
{
    modelnet::HelperConfig cfg;
    cfg.modeldir = m_path_root / "records-daemon";
    fs::create_directories(cfg.modeldir);
    cfg.storage_mode = modelnet::StorageMode::FIXED;
    cfg.quota_bytes = 1 << 20;
    cfg.lan_discovery = false;
    cfg.natpmp = false;
    cfg.pwc_chain = "regtest";
    char sock_dir[] = "/tmp/btx-sock-XXXXXX";
    BOOST_REQUIRE(::mkdtemp(sock_dir) != nullptr);
    cfg.rpc_socket = fs::PathFromString(sock_dir) / "modeld.sock";
    std::atomic<bool> stop{false};
    std::thread daemon([&] { modelnet::RunModelDaemon(cfg, &stop); });
    auto finish = [&] {
        stop.store(true);
        if (daemon.joinable()) daemon.join();
        ::unlink(fs::PathToString(cfg.rpc_socket).c_str());
        ::rmdir(sock_dir);
    };
    try {
        const auto t0 = std::chrono::steady_clock::now();
        while (!fs::exists(cfg.rpc_socket) && std::chrono::steady_clock::now() - t0 < std::chrono::seconds(8)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        BOOST_REQUIRE(fs::exists(cfg.rpc_socket));
        // Same helper dir as the running helper, so the same record cache.
        modelnet::ModelCatalog cat{cfg.modeldir, 1 << 20};
        const Signer s = NewSigner();
        const auto resp = Announce(cat, "records/announce", s, MakeCollection(s, Now(), 0, 1, 0));
        BOOST_REQUIRE_MESSAGE(resp.status == 200, resp.body);
    } catch (...) {
        finish();
        throw;
    }
    finish();
    BOOST_CHECK_EQUAL(RecordsOnDisk(cfg.modeldir), 1U);
}

BOOST_AUTO_TEST_CASE(announced_records_are_bounded_in_bytes)
{
    const fs::path tmp = m_path_root / "records-bytes";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const Signer s = NewSigner();
    int accepted = 0;
    bool full = false;
    // 700 Collections of 512 entries are about 25 MB of payload, signature and key.
    for (int k = 0; k < 700 && !full; ++k) {
        const auto resp = Announce(cat, "ext/objects/announce", s, MakeCollection(s, Now(), 0, 512, k));
        if (resp.status == 200) {
            ++accepted;
        } else {
            BOOST_REQUIRE_MESSAGE(resp.body.find("router cache full") != std::string::npos, resp.body);
            full = true;
        }
    }
    modelnet::FlushRecords(cat);
    BOOST_TEST_MESSAGE("accepted " << accepted << " Collections of 512 entries; records.json "
                                   << fs::file_size(tmp / "records.json") << " bytes");
    BOOST_CHECK(full);
    BOOST_CHECK_LT(accepted, 700);
}

BOOST_AUTO_TEST_CASE(full_cache_still_refreshes_a_record_it_holds)
{
    const int64_t now = 1700000000;
    std::string err;
    const auto hint = [](uint32_t i, size_t payload_bytes) {
        modelnet::SignedRecordHint h;
        WriteLE32(h.record_id.data.data(), i);
        h.kind = modelnet::RECORD_COLLECTION;
        h.payload.assign(payload_bytes, 0x5a);
        return h;
    };
    {
        modelnet::RouterCache cache;
        for (uint32_t i = 0; i < 4096; ++i) BOOST_REQUIRE(cache.Insert(hint(i, 8), now, err));
        BOOST_CHECK_MESSAGE(cache.Insert(hint(0, 8), now, err), err);
        BOOST_CHECK(!cache.Insert(hint(4096, 8), now, err));
        BOOST_CHECK_EQUAL(cache.Size(), 4096U);
    }
    {
        // 64 KiB records: the byte budget ends this well before 300.
        modelnet::RouterCache cache;
        uint32_t n = 0;
        while (n < 300 && cache.Insert(hint(n, 64 << 10), now, err)) ++n;
        BOOST_CHECK_LT(n, 300U);
        BOOST_CHECK_MESSAGE(cache.Insert(hint(0, 64 << 10), now, err), err);
        BOOST_CHECK(!cache.Insert(hint(n, 64 << 10), now, err));
    }
}

BOOST_AUTO_TEST_CASE(announced_record_holds_its_slot_at_most_a_week)
{
    const fs::path tmp = m_path_root / "records-hold";
    modelnet::ModelCatalog cat{tmp, 1 << 20};
    const Signer s = NewSigner();
    const int64_t now = Now();
    const auto resp = Announce(cat, "records/announce", s, MakeCollection(s, now, int64_t{4102444800}, 1, 0));
    BOOST_REQUIRE_MESSAGE(resp.status == 200, resp.body);
    UniValue ann;
    BOOST_REQUIRE(ann.read(resp.body));
    modelnet::NativeRequest get;
    get.method = "POST";
    get.path = "/btx-model/2/records/get";
    get.body = "{\"ids\":[\"" + ann["record_id"].get_str() + "\"]}";
    modelnet::NativeResponse got;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, get, got));
    UniValue out;
    BOOST_REQUIRE(out.read(got.body));
    BOOST_REQUIRE_EQUAL(out["records"].size(), 1U);
    const int64_t held_until = out["records"][0]["expiry"].getInt<int64_t>();
    BOOST_TEST_MESSAGE("expires_at 4102444800 is held until " << held_until << " (now " << now << ")");
    BOOST_CHECK_LE(held_until, Now() + 7 * 86400);
    BOOST_CHECK_GE(held_until, now + 7 * 86400);
}

BOOST_AUTO_TEST_SUITE_END()
