// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admission_routes.h>
#include <modelnet/lab_api.h>
#include <modelnet/lab_exchange.h>
#include <modelnet/model_admission.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/string.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#ifndef _WIN32
#include <atomic>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace modelnet {
bool ReadLoopbackBounded(int fd, std::string& out, size_t max_bytes, int timeout_ms, std::string& err);
}

BOOST_FIXTURE_TEST_SUITE(lab_lifecycle_tests, BasicTestingSetup)

namespace {

struct TempTree {
    explicit TempTree(fs::path path_in) : path(std::move(path_in))
    {
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path);
    }
    ~TempTree()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    fs::path path;
};

struct LabDirEnv {
    explicit LabDirEnv(const fs::path& dir) { Point(dir); }
    void Point(const fs::path& dir) { ::setenv("BTX035_LAB_DIR", PathToString(dir).c_str(), 1); }
    ~LabDirEnv() { ::unsetenv("BTX035_LAB_DIR"); }
};

struct AdmissionGuard {
    ~AdmissionGuard() { modelnet::ClearAdmissionMemory(); }
};

void WriteFile(const fs::path& path, const std::string& bytes)
{
    std::ofstream out(PathToString(path), std::ios::binary);
    out << bytes;
    BOOST_REQUIRE(out.good());
}

std::string ReadFile(const fs::path& path)
{
    std::ifstream in(PathToString(path), std::ios::binary);
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

bool Call(const char* method, const UniValue& request, UniValue& result, std::string& err)
{
    std::string response;
    if (!modelnet::DispatchLabApi(method, request.write(), response, err)) return false;
    UniValue envelope;
    if (!envelope.read(response) || !envelope.isObject() || !envelope.exists("automatic_spend_atoms") ||
        !envelope["automatic_spend_atoms"].isStr() || envelope["automatic_spend_atoms"].get_str() != "0" ||
        !envelope.exists("result") || !envelope["result"].isObject()) {
        err = "BTX035_SCHEMA";
        return false;
    }
    result = envelope["result"];
    err.clear();
    return true;
}

UniValue Identity(const char* label, const char* key)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("label", label);
    req.pushKV("recovery_key_ids", UniValue(UniValue::VARR));
    req.pushKV("recovery_threshold", 1);
    req.pushKV("recovery_delay_ms", "1");
    req.pushKV("idempotency_key", key);
    req.pushKV("expected_state", UniValue());
    return req;
}

void PrepareDir(const fs::path& dir)
{
    ::unsetenv("BTX035_LAB_DIR");
    modelnet::ResetLabApi();
    ::setenv("BTX035_LAB_DIR", PathToString(dir).c_str(), 1);
    modelnet::ReloadLabFromDisk();
}

} // namespace

BOOST_AUTO_TEST_CASE(corrupt_image_refuses_mutation_and_keeps_the_file)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-corrupt"};
    LabDirEnv env(root.path);
    AdmissionGuard admission;

    const fs::path image = root.path / "lab.json";
    UniValue ignored;
    std::string err;

    WriteFile(image, "not-a-lab-image");
    const std::string garbage = ReadFile(image);
    PrepareDir(root.path);
    BOOST_CHECK(Call("lab.info", UniValue(UniValue::VOBJ), ignored, err));
    BOOST_CHECK_EQUAL(ignored["recovery_required"].get_str(), "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK(!Call("lab.identity_create", Identity("kept", "lifecycle-corrupt-key"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK_EQUAL(ReadFile(image), garbage);

    TempTree version_root{root.path / "version"};
    const fs::path version_image = version_root.path / "lab.json";
    env.Point(version_root.path);
    PrepareDir(version_root.path);
    BOOST_REQUIRE(Call("lab.identity_create", Identity("seed", "lifecycle-version-seed"), ignored, err));
    std::string versioned = ReadFile(version_image);
    const auto version_at = versioned.find("\"version\":1");
    BOOST_REQUIRE(version_at != std::string::npos);
    versioned.replace(version_at, std::string("\"version\":1").size(), "\"version\":2");
    WriteFile(version_image, versioned);
    const std::string unsupported = ReadFile(version_image);
    modelnet::ReloadLabFromDisk();
    BOOST_CHECK(Call("lab.info", UniValue(UniValue::VOBJ), ignored, err));
    BOOST_CHECK_EQUAL(ignored["recovery_required"].get_str(), "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK(!Call("lab.identity_create", Identity("next", "lifecycle-version-next"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK_EQUAL(ReadFile(version_image), unsupported);

    TempTree piece_root{root.path / "pieces"};
    const fs::path piece_image = piece_root.path / "lab.json";
    env.Point(piece_root.path);
    PrepareDir(piece_root.path);
    BOOST_REQUIRE(Call("lab.identity_create", Identity("pieces", "lifecycle-piece-seed"), ignored, err));
    UniValue disk;
    BOOST_REQUIRE(disk.read(ReadFile(piece_image)));
    UniValue repos = disk["repo_objects"].isObject() ? disk["repo_objects"] : UniValue(UniValue::VOBJ);
    const std::string digest(96, 'a');
    UniValue rows(UniValue::VARR);
    UniValue model(UniValue::VOBJ);
    model.pushKV("kind", "model");
    model.pushKV("digest", digest);
    model.pushKV("content", "hello");
    rows.push_back(std::move(model));
    UniValue first(UniValue::VOBJ);
    first.pushKV("kind", "piece");
    first.pushKV("digest", digest);
    first.pushKV("content", "0:hel");
    rows.push_back(std::move(first));
    UniValue gap(UniValue::VOBJ);
    gap.pushKV("kind", "piece");
    gap.pushKV("digest", digest);
    gap.pushKV("content", "2:o");
    rows.push_back(std::move(gap));
    repos.pushKV("lifecycle-gap", rows);
    disk.pushKV("repo_objects", repos);
    WriteFile(piece_image, disk.write());
    const std::string gapped = ReadFile(piece_image);
    modelnet::ReloadLabFromDisk();
    BOOST_CHECK(!Call("lab.identity_create", Identity("gap", "lifecycle-piece-gap"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK_EQUAL(ReadFile(piece_image), gapped);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(missing_store_initializes)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-missing"};
    LabDirEnv env(root.path);
    PrepareDir(root.path);
    BOOST_CHECK(!fs::exists(root.path / "lab.json"));

    UniValue created;
    std::string err;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("first", "lifecycle-missing-key"), created, err));
    BOOST_CHECK_EQUAL(created["state"].get_str(), "ACTIVE");
    BOOST_REQUIRE(fs::exists(root.path / "lab.json"));
    const std::string body = ReadFile(root.path / "lab.json");
    UniValue disk;
    BOOST_REQUIRE(disk.read(body));
    BOOST_CHECK_EQUAL(disk["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(!disk.exists("identity_sk"));
    BOOST_CHECK(body.find("identity_sk") == std::string::npos);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(failed_write_is_rolled_back_and_does_not_block_later_writes)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-write-fault"};
    LabDirEnv env(root.path);
    PrepareDir(root.path);
    const fs::path image = root.path / "lab.json";
    UniValue ignored;
    std::string err;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("first", "lifecycle-fault-first"), ignored, err));

    // The temp file cannot be opened, so the write fails before the rename and lab.json is untouched.
    const std::string before = ReadFile(image);
    const fs::path tmp = root.path / "lab.json.tmp";
    fs::create_directories(tmp);
    BOOST_CHECK(!Call("lab.identity_create", Identity("blocked", "lifecycle-fault-blocked"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK_EQUAL(ReadFile(image), before);
    fs::remove(tmp);
    BOOST_REQUIRE(Call("lab.info", UniValue(UniValue::VOBJ), ignored, err));
    BOOST_CHECK(!ignored.exists("recovery_required"));
    BOOST_REQUIRE(Call("lab.identity_create", Identity("blocked", "lifecycle-fault-blocked"), ignored, err));

    // With a model stored, every write also saves pieces. A pieces path that is not a directory throws after
    // lab.json was replaced: the call fails with a code, lab.json is put back, and the key is not remembered.
    const std::string intent(96, '1');
    UniValue prepare(UniValue::VOBJ);
    prepare.pushKV("intent_id", intent);
    prepare.pushKV("idempotency_key", "lifecycle-fault-prepare");
    prepare.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(Call("lab.action_prepare", prepare, ignored, err));
    UniValue exec(UniValue::VOBJ);
    exec.pushKV("input_capsule_id", std::string(96, '2'));
    exec.pushKV("recipe_id", "INTEGER_MODEL");
    exec.pushKV("runtime_binding_id", std::string(96, '3'));
    exec.pushKV("research_grant_id", std::string(96, '4'));
    exec.pushKV("local_capability_grant_id", intent);
    exec.pushKV("idempotency_key", "lifecycle-fault-execute");
    exec.pushKV("expected_state", UniValue());
    BOOST_REQUIRE(Call("lab.research_execute", exec, ignored, err));
    const fs::path pieces = root.path / "pieces";
    const fs::path kept = root.path / "pieces.kept";
    BOOST_REQUIRE(fs::is_directory(pieces));
    fs::rename(pieces, kept);
    WriteFile(pieces, "not a directory");
    UniValue disk;
    BOOST_REQUIRE(disk.read(ReadFile(image)));
    const size_t identities = disk["identity_pk"].size();
    BOOST_CHECK(!Call("lab.identity_create", Identity("thrown", "lifecycle-fault-thrown"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    BOOST_REQUIRE(disk.read(ReadFile(image)));
    BOOST_CHECK_EQUAL(disk["identity_pk"].size(), identities);
    BOOST_CHECK(ReadFile(image).find("lifecycle-fault-thrown") == std::string::npos);
    BOOST_CHECK(!Call("lab.identity_create", Identity("thrown", "lifecycle-fault-thrown"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    fs::remove(pieces);
    fs::rename(kept, pieces);
    BOOST_REQUIRE(Call("lab.identity_create", Identity("thrown", "lifecycle-fault-thrown"), ignored, err));
    BOOST_REQUIRE(disk.read(ReadFile(image)));
    BOOST_CHECK_EQUAL(disk["identity_pk"].size(), identities + 1);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(idempotency_replays_one_result_and_conflicts_on_a_different_body)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-idem"};
    LabDirEnv env(root.path);
    PrepareDir(root.path);

    UniValue first;
    std::string err;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("same", "lifecycle-idem-key1"), first, err));
    const std::string record = first["record_id"].get_str();
    BOOST_REQUIRE_EQUAL(record.size(), 96U);

    UniValue again;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("same", "lifecycle-idem-key1"), again, err));
    BOOST_CHECK_EQUAL(again["record_id"].get_str(), record);

    modelnet::ReloadLabFromDisk();
    UniValue restored;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("same", "lifecycle-idem-key1"), restored, err));
    BOOST_CHECK_EQUAL(restored["record_id"].get_str(), record);

    UniValue conflict;
    BOOST_CHECK(!Call("lab.identity_create", Identity("other", "lifecycle-idem-key1"), conflict, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY");

    const std::string body = ReadFile(root.path / "lab.json");
    UniValue disk;
    BOOST_REQUIRE(disk.read(body));
    BOOST_CHECK_EQUAL(disk["automatic_spend_atoms"].get_str(), "0");
    BOOST_CHECK(body.find("identity_sk") == std::string::npos);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(evicted_idempotency_key_is_not_reused)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-idem-evict"};
    LabDirEnv env(root.path);
    PrepareDir(root.path);

    UniValue first;
    std::string err;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("kept", "lifecycle-evict-00"), first, err));
    const std::string record = first["record_id"].get_str();
    // Further identity creates would change the caller. Realm creates keep it,
    // so the oldest key is retired under the same caller the retry will use.
    for (int i = 1; i <= 64; ++i) {
        UniValue realm(UniValue::VOBJ);
        realm.pushKV("name", "evict");
        realm.pushKV("nonce", "lifecycle-realm-" + std::to_string(i));
        realm.pushKV("policy_template", "local");
        realm.pushKV("idempotency_key", "lifecycle-realm-" + std::to_string(i));
        realm.pushKV("expected_state", UniValue());
        UniValue ignored;
        BOOST_REQUIRE(Call("lab.realm_create", realm, ignored, err));
    }

    UniValue again;
    BOOST_CHECK(!Call("lab.identity_create", Identity("kept", "lifecycle-evict-00"), again, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY_EXPIRED");
    BOOST_CHECK(!again.exists("record_id"));

    modelnet::ReloadLabFromDisk();
    UniValue restored;
    BOOST_CHECK(!Call("lab.identity_create", Identity("kept", "lifecycle-evict-00"), restored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY_EXPIRED");

    UniValue conflict;
    BOOST_CHECK(!Call("lab.identity_create", Identity("other", "lifecycle-evict-00"), conflict, err));
    BOOST_CHECK_EQUAL(err, "BTX035_IDEMPOTENCY");

    UniValue disk;
    BOOST_REQUIRE(disk.read(ReadFile(root.path / "lab.json")));
    BOOST_CHECK_EQUAL(disk["identity_pk"].size(), 1);
    BOOST_CHECK_EQUAL(disk["realms"].size(), 64);
    BOOST_CHECK(disk.write().find(record) != std::string::npos);
    bool retired = false;
    for (size_t i = 0; i < disk["idempotency"].size(); ++i) {
        const UniValue& row = disk["idempotency"][i];
        if (row["key"].get_str() == "lifecycle-evict-00") {
            BOOST_CHECK(row["retired"].isTrue());
            BOOST_CHECK(row["result"].get_str().empty());
            retired = true;
        }
    }
    BOOST_CHECK(retired);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(retired_idempotency_keys_stop_at_256)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-idem-retired-cap"};
    LabDirEnv env(root.path);
    PrepareDir(root.path);

    UniValue ignored;
    std::string err;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("kept", "lifecycle-retired-cap-0"), ignored, err));
    // 329 keys under one caller: 64 stay live and 265 are retired, of which the oldest 9 are dropped.
    for (int i = 1; i <= 328; ++i) {
        UniValue realm(UniValue::VOBJ);
        realm.pushKV("name", "cap");
        realm.pushKV("nonce", "lifecycle-retired-cap-" + std::to_string(i));
        realm.pushKV("policy_template", "local");
        realm.pushKV("idempotency_key", "lifecycle-retired-cap-" + std::to_string(i));
        realm.pushKV("expected_state", UniValue());
        BOOST_REQUIRE(Call("lab.realm_create", realm, ignored, err));
    }

    UniValue disk;
    BOOST_REQUIRE(disk.read(ReadFile(root.path / "lab.json")));
    size_t live = 0;
    size_t retired = 0;
    for (size_t i = 0; i < disk["idempotency"].size(); ++i) {
        if (disk["idempotency"][i].exists("retired")) {
            ++retired;
        } else {
            ++live;
        }
    }
    BOOST_CHECK_EQUAL(live, 64U);
    BOOST_CHECK_EQUAL(retired, 256U);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(retired_flag_that_is_not_a_bool_makes_the_image_corrupt)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-idem-retired-type"};
    LabDirEnv env(root.path);
    PrepareDir(root.path);

    UniValue ignored;
    std::string err;
    BOOST_REQUIRE(Call("lab.identity_create", Identity("kept", "lifecycle-retired-type"), ignored, err));
    modelnet::ResetLabApi();

    const fs::path image = root.path / "lab.json";
    std::string bytes = ReadFile(image);
    const std::string key = "\"key\":\"lifecycle-retired-type\"";
    const size_t at = bytes.find(key);
    BOOST_REQUIRE(at != std::string::npos);
    bytes.insert(at + key.size(), ",\"retired\":\"yes\"");
    WriteFile(image, bytes);

    PrepareDir(root.path);
    UniValue info;
    BOOST_CHECK(Call("lab.info", UniValue(UniValue::VOBJ), info, err));
    BOOST_CHECK_EQUAL(info["recovery_required"].getValStr(), "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK(!Call("lab.identity_create", Identity("other", "lifecycle-retired-type-2"), ignored, err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK_EQUAL(ReadFile(image), bytes);

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(bounded_read_does_not_hold_the_lab_mutex)
{
#ifndef _WIN32
    BOOST_REQUIRE(!m_path_root.empty());
    ::unsetenv("BTX035_LAB_DIR");
    modelnet::ResetLabApi();

    int stalled[2] = {-1, -1};
    BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, stalled), 0);
    std::atomic<bool> finished{false};
    std::string read_err;
    std::string read_out;
    std::thread reader([&] {
        modelnet::ReadLoopbackBounded(stalled[0], read_out, 1024, 1200, read_err);
        finished = true;
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    BOOST_CHECK(!finished.load());
    const auto info_started = std::chrono::steady_clock::now();
    UniValue info;
    std::string err;
    BOOST_CHECK(Call("lab.info", UniValue(UniValue::VOBJ), info, err));
    const auto info_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - info_started).count();
    BOOST_CHECK(info_ms < 800);
    BOOST_CHECK(!finished.load());
    reader.join();
    BOOST_CHECK(finished.load());
    BOOST_CHECK_EQUAL(read_err, "BTX035_TRANSPORT");
    BOOST_CHECK(read_out.empty());
    ::close(stalled[0]);
    ::close(stalled[1]);

    int oversized[2] = {-1, -1};
    BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, oversized), 0);
    const std::string extra(200, 'x');
    BOOST_REQUIRE_EQUAL(::send(oversized[1], extra.data(), extra.size(), 0), static_cast<ssize_t>(extra.size()));
    std::string limited;
    const auto limit_started = std::chrono::steady_clock::now();
    BOOST_CHECK(!modelnet::ReadLoopbackBounded(oversized[0], limited, 32, 500, err));
    const auto limit_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - limit_started).count();
    BOOST_CHECK(limit_ms < 500);
    BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
    BOOST_CHECK(limited.size() <= 32);
    ::close(oversized[0]);
    ::close(oversized[1]);

    // The cap is a multiple of the 4096-byte read chunk: one byte more is
    // refused instead of returned cut at the cap, and exactly the cap reads.
    for (const size_t sent : {size_t{4097}, size_t{4096}}) {
        int chunked[2] = {-1, -1};
        BOOST_REQUIRE_EQUAL(socketpair(AF_UNIX, SOCK_STREAM, 0, chunked), 0);
        const std::string body(sent, 'y');
        BOOST_REQUIRE_EQUAL(::send(chunked[1], body.data(), body.size(), 0), static_cast<ssize_t>(body.size()));
        ::shutdown(chunked[1], SHUT_WR);
        std::string got;
        const bool read = modelnet::ReadLoopbackBounded(chunked[0], got, 4096, 500, err);
        if (sent > 4096) {
            BOOST_CHECK(!read);
            BOOST_CHECK_EQUAL(err, "BTX035_LIMIT_EXCEEDED");
        } else {
            BOOST_CHECK(read);
            BOOST_CHECK_EQUAL(got.size(), sent);
        }
        ::close(chunked[0]);
        ::close(chunked[1]);
    }

    const int listener = static_cast<int>(::socket(AF_INET, SOCK_STREAM, 0));
    BOOST_REQUIRE(listener >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    BOOST_REQUIRE_EQUAL(::bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)), 0);
    BOOST_REQUIRE_EQUAL(::listen(listener, 1), 0);
    socklen_t length = sizeof(address);
    BOOST_REQUIRE_EQUAL(::getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length), 0);
    std::string result;
    const auto own_started = std::chrono::steady_clock::now();
    BOOST_CHECK(!modelnet::LabCallLoopback("127.0.0.1", ntohs(address.sin_port), "user", "pw", "lab.info", "{}", result, err));
    const auto own_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - own_started).count();
    BOOST_CHECK(own_ms < 500);
    BOOST_CHECK_EQUAL(err, "BTX035_SCOPE_DENIED");
    BOOST_CHECK(result.empty());
    ::close(listener);

    modelnet::ResetLabApi();
#endif
}

BOOST_AUTO_TEST_CASE(strict_admission_follows_the_registry_file)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-admit"};
    LabDirEnv env(root.path);
    AdmissionGuard admission;
    PrepareDir(root.path);

    const std::string model_a = "btx035-lifecycle-strict-a";
    const std::string model_b = "btx035-lifecycle-strict-b";
    const std::string digest_a(96, 'a');
    const std::string digest_b(96, 'b');
    modelnet::StrictAdmissionRecord record_a;
    record_a.digest = digest_a;
    modelnet::StrictAdmissionRecord record_b;
    record_b.digest = digest_b;
    modelnet::RegisterStrictModel(model_a, record_a);
    modelnet::RegisterStrictModel(model_b, record_b);

    std::string code;
    BOOST_CHECK(!modelnet::LivePathAllowed(model_a, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");
    BOOST_CHECK(modelnet::LivePathAllowed("btx035-lifecycle-unknown", false, code));
    BOOST_CHECK(code.empty());

    std::string err;
    BOOST_REQUIRE(modelnet::RecordModelAdmission(model_a, digest_a, "ADMITTED", err));
    BOOST_CHECK(modelnet::LivePathAllowed(model_a, false, code));
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!modelnet::LivePathAllowed(model_b, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");

    modelnet::ClearAdmissionMemory();
    BOOST_CHECK(modelnet::LivePathAllowed(model_a, false, code));
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!modelnet::LivePathAllowed(model_b, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");

    modelnet::Quarantine(model_a);
    BOOST_CHECK(!modelnet::LivePathAllowed(model_a, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_QUARANTINE");
    modelnet::ClearAdmissionMemory();
    BOOST_CHECK(!modelnet::LivePathAllowed(model_a, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_QUARANTINE");
    BOOST_CHECK(!modelnet::LivePathAllowed(model_b, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(admission_for_other_bytes_does_not_open_a_strict_model)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-admit-digest"};
    LabDirEnv env(root.path);
    AdmissionGuard admission;
    PrepareDir(root.path);

    const std::string model = "btx035-lifecycle-strict-digest";
    modelnet::StrictAdmissionRecord record;
    record.digest = std::string(96, 'a');
    modelnet::RegisterStrictModel(model, record);

    std::string err;
    BOOST_REQUIRE(modelnet::RecordModelAdmission(model, std::string(96, 'b'), "ADMITTED", err));
    std::string code;
    BOOST_CHECK(!modelnet::LivePathAllowed(model, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");

    modelnet::ClearAdmissionMemory();
    BOOST_CHECK(!modelnet::LivePathAllowed(model, false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");

    modelnet::ResetLabApi();
}

BOOST_AUTO_TEST_CASE(registry_write_after_restart_keeps_earlier_rows)
{
    BOOST_REQUIRE(!m_path_root.empty());
    TempTree root{m_path_root / "lab-lifecycle-restart"};
    LabDirEnv env(root.path);
    AdmissionGuard admission;

    const std::string refused = "btx035-lifecycle-refused";
    const std::string revoked = "btx035-lifecycle-revoked";
    const std::string held = "btx035-lifecycle-held";
    std::string err;
    std::string code;
    BOOST_REQUIRE(modelnet::RecordModelAdmission(refused, std::string(96, 'a'), "BTX035_REPLAY", err));
    BOOST_REQUIRE(modelnet::RecordModelAdmission(revoked, std::string(96, 'b'), "ADMITTED", err));
    modelnet::RevokeModel(revoked);
    modelnet::Quarantine(held);

    const auto check_denied = [&] {
        BOOST_CHECK(!modelnet::LivePathAllowed(refused, false, code));
        BOOST_CHECK_EQUAL(code, "BTX035_ADMISSION");
        BOOST_CHECK(!modelnet::LivePathAllowed(revoked, false, code));
        BOOST_CHECK_EQUAL(code, "BTX035_QUARANTINE");
        BOOST_CHECK(!modelnet::LivePathAllowed(held, false, code));
        BOOST_CHECK_EQUAL(code, "BTX035_QUARANTINE");
    };
    check_denied();

    // A restart drops process memory. The first registry call after it is a write.
    modelnet::ClearAdmissionMemory();
    BOOST_REQUIRE(modelnet::RecordModelAdmission("btx035-lifecycle-later", std::string(96, 'c'), "ADMITTED", err));
    check_denied();
    modelnet::ClearAdmissionMemory();
    modelnet::Quarantine("btx035-lifecycle-held-later");
    check_denied();
    modelnet::ClearAdmissionMemory();
    modelnet::RegisterLegacyModel("btx035-lifecycle-legacy-later");
    check_denied();

    // An unreadable registry stays in place for recovery and is not overwritten from memory.
    const fs::path file = root.path / "admission-registry.json";
    WriteFile(file, "{");
    BOOST_CHECK(!modelnet::RecordModelAdmission("btx035-lifecycle-after-corrupt", std::string(96, 'd'), "ADMITTED", err));
    BOOST_CHECK_EQUAL(err, "BTX035_RECOVERY_REQUIRED");
    modelnet::Quarantine("btx035-lifecycle-held-corrupt");
    BOOST_CHECK_EQUAL(ReadFile(file), "{");
    BOOST_CHECK(!modelnet::LivePathAllowed("btx035-lifecycle-unknown", false, code));
    BOOST_CHECK_EQUAL(code, "BTX035_RECOVERY_REQUIRED");
}

BOOST_AUTO_TEST_SUITE_END()
