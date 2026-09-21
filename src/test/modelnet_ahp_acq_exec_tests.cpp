// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-ACQ execute remainders: concurrent credit, stale cache reverify,
// multi-file materialize, lease hold, cancel/idempotency.

#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <span.h>
#include <modelnet/capability.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/package_acquisition.h>
#include <modelnet/package_execute.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_acq_exec_tests, BasicTestingSetup)

namespace {

std::string HexId(char nibble) { return std::string(96, nibble); }

std::string Sha384Of(const std::string& bytes)
{
    unsigned char d[CSHA384::OUTPUT_SIZE];
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    hasher.Finalize(d);
    return HexStr(Span<const unsigned char>{d, CSHA384::OUTPUT_SIZE});
}

struct CreditRestore {
    modelnet::CreditBroker& c;
    uint64_t ceil;
    explicit CreditRestore() : c(modelnet::GlobalAcquisitionCredits()), ceil(c.Ceiling())
    {
        c.Release(c.Reserved());
    }
    ~CreditRestore()
    {
        c.Release(c.Reserved());
        c.SetCeiling(ceil ? ceil : (64ull << 20));
    }
};

UniValue ModelCore()
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "MODEL");
    core.pushKV("label", "acq-exec");
    UniValue r(UniValue::VOBJ);
    r.pushKV("kind", "MODEL");
    r.pushKV("id", HexId('a'));
    r.pushKV("format", "GGUF");
    UniValue resources(UniValue::VARR);
    resources.push_back(r);
    core.pushKV("resources", resources);
    UniValue v(UniValue::VOBJ);
    v.pushKV("variant_id", "demo-q4");
    v.pushKV("name", "demo-q4");
    v.pushKV("resource_id", HexId('a'));
    v.pushKV("format", "GGUF");
    UniValue vs(UniValue::VARR);
    vs.push_back(v);
    core.pushKV("variants", vs);
    UniValue acq(UniValue::VOBJ);
    acq.pushKV("default_variant", "demo-q4");
    acq.pushKV("retrieval_mode", "FREE_ONLY");
    acq.pushKV("source_policy", "NATIVE_ONLY");
    UniValue ah(UniValue::VOBJ);
    ah.pushKV("acquisition", acq);
    core.pushKV("agent_handoff", ah);
    return core;
}

modelnet::AcquisitionPlan PlanTo(const fs::path& dest)
{
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("destination", dest.utf8string());
    policy.pushKV("explicit_variant", "demo-q4");
    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, plan, code, err), err);
    return plan;
}

UniValue Rpc(const std::string& method, const UniValue& o)
{
    UniValue params(UniValue::VARR);
    params.push_back(o);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_acq_06_concurrent_reservation_exhaustion)
{
    CreditRestore restore;
    auto& credits = restore.c;
    credits.SetCeiling(32);

    const fs::path dest = m_path_root / "acq-06-exec";
    const fs::path src = m_path_root / "src-06.bin";
    const std::string payload(64, 'x');
    {
        std::ofstream{fs::PathToString(src)} << payload;
    }
    modelnet::ExecuteAcquisitionRequest req;
    req.plan = PlanTo(dest);
    req.credit = &credits;
    req.reserve_bytes = 32;
    modelnet::VerifiedLocalFile f;
    f.relative_path = "weights.gguf";
    f.sha384_hex = Sha384Of(payload);
    f.source_path = fs::PathToString(src);
    req.files.push_back(f);

    modelnet::AcquisitionReceipt a, b;
    uint64_t ra = 0, rb = 0;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::ExecuteBtxAcquisition(req, a, ra, code, err), err);
    BOOST_CHECK_EQUAL(a.ready_state, "MODEL_READY");
    BOOST_CHECK(!modelnet::ExecuteBtxAcquisition(req, b, rb, code, err));
    BOOST_CHECK_EQUAL(code, "BUDGET_EXCEEDED");
}

BOOST_AUTO_TEST_CASE(ahp_acq_07_stale_cache_reverify)
{
    const fs::path dest = m_path_root / "acq-07-exec";
    const fs::path src = m_path_root / "src-07.bin";
    const std::string good = "verified-bytes";
    const std::string bad = "not-verified-bytes";
    {
        std::ofstream{fs::PathToString(src)} << good;
    }
    fs::create_directories(dest);
    {
        std::ofstream{fs::PathToString(dest / "weights.gguf")} << bad;
    }

    modelnet::ExecuteAcquisitionRequest req;
    req.plan = PlanTo(dest);
    modelnet::VerifiedLocalFile f;
    f.relative_path = "weights.gguf";
    f.sha384_hex = Sha384Of(good);
    f.source_path = fs::PathToString(src);
    req.files.push_back(f);

    modelnet::AcquisitionReceipt rec;
    uint64_t reserved = 0;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::ExecuteBtxAcquisition(req, rec, reserved, code, err), err);
    BOOST_CHECK_EQUAL(rec.ready_state, "MODEL_READY");
    BOOST_CHECK(rec.json["file_bytes_verified"].get_bool());
    BOOST_CHECK(rec.json["manifest_verified"].get_bool());
    std::string got;
    BOOST_REQUIRE(modelnet::Sha384Path(fs::PathToString(dest / "weights.gguf"), got, err));
    BOOST_CHECK_EQUAL(got, Sha384Of(good));
    BOOST_CHECK(got != Sha384Of(bad));
}

BOOST_AUTO_TEST_CASE(ahp_acq_08_multi_file_path_and_symlink)
{
    const fs::path dest = m_path_root / "acq-08-exec";
    const fs::path srcdir = m_path_root / "src-08";
    fs::create_directories(srcdir);
    const std::string a = "file-a";
    const std::string b = "file-b";
    {
        std::ofstream{fs::PathToString(srcdir / "a.bin")} << a;
        std::ofstream{fs::PathToString(srcdir / "b.bin")} << b;
    }

    modelnet::ExecuteAcquisitionRequest req;
    req.plan = PlanTo(dest);
    modelnet::VerifiedLocalFile fa, fb, evil;
    fa.relative_path = "shard/a.bin";
    fa.sha384_hex = Sha384Of(a);
    fa.source_path = fs::PathToString(srcdir / "a.bin");
    fb.relative_path = "shard/b.bin";
    fb.sha384_hex = Sha384Of(b);
    fb.source_path = fs::PathToString(srcdir / "b.bin");
    req.files = {fa, fb};

    modelnet::AcquisitionReceipt rec;
    uint64_t reserved = 0;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::ExecuteBtxAcquisition(req, rec, reserved, code, err), err);
    BOOST_CHECK_EQUAL(rec.json["local_paths"].size(), 2);
    BOOST_CHECK(rec.json["file_bytes_verified"].get_bool());
    BOOST_CHECK_EQUAL(rec.json["source_classes_used"][0].get_str(), "LOCAL_DISK");

    evil.relative_path = "../outside.bin";
    evil.sha384_hex = Sha384Of(a);
    evil.source_path = fs::PathToString(srcdir / "a.bin");
    req.files = {evil};
    BOOST_CHECK(!modelnet::ExecuteBtxAcquisition(req, rec, reserved, code, err));
    BOOST_CHECK_EQUAL(code, "DOCUMENT_PATH_REJECTED");
    BOOST_CHECK(!fs::exists(m_path_root / "outside.bin"));

    const fs::path link = m_path_root / "acq-08-link";
    fs::create_directory(m_path_root / "acq-08-target");
    fs::create_symlink(m_path_root / "acq-08-target", link);
    req.plan = PlanTo(link);
    req.files = {fa};
    BOOST_CHECK(!modelnet::ExecuteBtxAcquisition(req, rec, reserved, code, err));
    BOOST_CHECK_EQUAL(code, "SYMLINK_REFUSED");
}

BOOST_AUTO_TEST_CASE(ahp_acq_09_lease_blocks_eviction)
{
    const fs::path dest = m_path_root / "acq-09-lease";
    fs::create_directories(dest);
    const fs::path held = dest / "weights.gguf";
    {
        std::ofstream{fs::PathToString(held)} << "leased";
    }
    modelnet::OutputLease lease;
    lease.lease_id = "lease-1";
    lease.path = fs::PathToString(held);
    lease.active = true;
    std::string code, err;
    BOOST_CHECK(!modelnet::TryEvictUnleasedPath(lease.path, {lease}, code, err));
    BOOST_CHECK_EQUAL(code, "LEASE_HOLD");
    BOOST_CHECK(fs::exists(held));

    lease.active = false;
    BOOST_REQUIRE_MESSAGE(modelnet::TryEvictUnleasedPath(lease.path, {lease}, code, err), err);
    BOOST_CHECK(!fs::exists(held));
}

BOOST_AUTO_TEST_CASE(ahp_acq_10_cancel_releases_credit_and_idempotent_ready)
{
    const fs::path tmp = m_path_root / "acq-10-helper";
    fs::create_directories(tmp);
    const fs::path dest = tmp / "lease";
    const fs::path src = tmp / "src.bin";
    const std::string payload = "idempotent-bytes";
    {
        std::ofstream{fs::PathToString(src)} << payload;
    }

    CreditRestore restore;
    modelnet::ExecuteAcquisitionRequest req;
    req.plan = PlanTo(dest);
    req.credit = &restore.c;
    modelnet::VerifiedLocalFile f;
    f.relative_path = "weights.gguf";
    f.sha384_hex = Sha384Of(payload);
    f.source_path = fs::PathToString(src);
    req.files.push_back(f);
    modelnet::AcquisitionReceipt rec;
    uint64_t reserved = 0;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::ExecuteBtxAcquisition(req, rec, reserved, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::ExecuteBtxAcquisition(req, rec, reserved, code, err), err);
    BOOST_CHECK_EQUAL(rec.ready_state, "MODEL_READY");

    modelnet::OutputLease lease;
    lease.lease_id = rec.json["lease_id"].get_str();
    lease.path = rec.json["local_paths"][0].get_str();
    BOOST_CHECK(!modelnet::TryEvictUnleasedPath(lease.path, {lease}, code, err));
    BOOST_CHECK_EQUAL(code, "LEASE_HOLD");
}

BOOST_AUTO_TEST_CASE(ahp_acq_helper_verified_local_model_ready)
{
    const fs::path tmp = m_path_root / "acq-helper-ready";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const fs::path src = tmp / "src.bin";
    const std::string payload = "helper-ready";
    {
        std::ofstream{fs::PathToString(src)} << payload;
    }

#ifdef MODELNET_AHP_FIXTURE_DIR
    const fs::path fixture = fs::PathFromString(MODELNET_AHP_FIXTURE_DIR) / "model-agent.btx";
#else
    const fs::path fixture = fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package" /
                            "model-agent.btx";
#endif
    UniValue plan_o(UniValue::VOBJ);
    plan_o.pushKV("path", fs::PathToString(fixture));
    UniValue dest_pol(UniValue::VOBJ);
    dest_pol.pushKV("destination", (tmp / "out").utf8string());
    plan_o.pushKV("local_policy", dest_pol);

    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxacquisition", plan_o), result, code, err), err);
    const std::string plan_id = result["plan_id"].get_str();

    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("path", "weights.gguf");
    f.pushKV("sha384", Sha384Of(payload));
    f.pushKV("source_path", fs::PathToString(src));
    files.push_back(f);
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("plan_id", plan_id);
    ex.pushKV("verified_local_files", files);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ex), result, code, err), err);
    BOOST_CHECK_EQUAL(result["state"].get_str(), "MODEL_READY");
    BOOST_CHECK(result["file_bytes_verified"].get_bool());
    BOOST_CHECK(result["manifest_verified"].get_bool());
    BOOST_CHECK(!result["runtime_executed"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(result["source_classes_used"][0].get_str(), "LOCAL_DISK");

    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ex), result, code, err), err);
    BOOST_CHECK_EQUAL(result["state"].get_str(), "MODEL_READY");

    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("cancelbtxacquisition", ex), result, code, err));
    BOOST_CHECK(result["cancelled"].get_bool());
}

BOOST_AUTO_TEST_CASE(ahp_acq_10_execute_ensure_idempotency_conflict)
{
    const fs::path tmp = m_path_root / "acq-10-idem";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};

    UniValue recipe(UniValue::VOBJ);
    recipe.pushKV("recipe_kind", "FULL_MODEL");
    UniValue comps(UniValue::VARR);
    UniValue c(UniValue::VOBJ);
    c.pushKV("name", "base");
    UniValue res(UniValue::VOBJ);
    res.pushKV("kind", "MODEL");
    res.pushKV("digest48", std::string(96, 'a'));
    c.pushKV("resource", res);
    c.pushKV("role", "BASE");
    c.pushKV("required", true);
    comps.push_back(c);
    recipe.pushKV("components", comps);
    recipe.pushKV("readiness_contract", "FULL_REQUIRED_SET");

    UniValue grant(UniValue::VOBJ);
    grant.pushKV("caller", "local");
    grant.pushKV("host_bytes", 8388608);
    grant.pushKV("automatic_spend_atoms", 0);

    UniValue plan_in(UniValue::VOBJ);
    plan_in.pushKV("recipe", recipe);
    plan_in.pushKV("grant", grant);
    UniValue planned;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxcapability", plan_in), planned, code, err), err);
    BOOST_REQUIRE(planned.exists("plan_id") && planned["plan_id"].isStr());

    UniValue ens(UniValue::VOBJ);
    ens.pushKV("plan_id", planned["plan_id"].get_str());
    ens.pushKV("grant", grant);
    ens.pushKV("automatic_spend_atoms", 0);
    ens.pushKV("helper_alive", true);
    ens.pushKV("idempotency_key", "ahp-exec-k1");
    ens.pushKV("runtime_id", "synthetic-cpu-fixture");
    UniValue first, replay;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", ens), first, code, err), err);
    BOOST_REQUIRE(first.exists("job_id"));
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", ens), replay, code, err), err);
    BOOST_CHECK(replay["idempotent"].get_bool());
    BOOST_CHECK_EQUAL(replay["job_id"].get_str(), first["job_id"].get_str());
    BOOST_CHECK_EQUAL(replay["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue altered = ens;
    altered.pushKV("runtime_id", "synthetic-cpu-fixture-alt");
    UniValue conflict;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("ensurebtxcapability", altered), conflict, code, err));
    BOOST_CHECK_EQUAL(code, "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(conflict["error_code"].get_str(), "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(conflict["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(ahp_acq_10_execute_rpc_idempotency_conflict)
{
    const fs::path tmp = m_path_root / "acq-10-exec-rpc-idem";
    fs::create_directories(tmp);
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const fs::path src = tmp / "src.bin";
    const std::string payload = "exec-rpc-idem-bytes";
    {
        std::ofstream{fs::PathToString(src)} << payload;
    }

#ifdef MODELNET_AHP_FIXTURE_DIR
    const fs::path fixture = fs::PathFromString(MODELNET_AHP_FIXTURE_DIR) / "model-agent.btx";
#else
    const fs::path fixture = fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package" /
                            "model-agent.btx";
#endif
    UniValue plan_o(UniValue::VOBJ);
    plan_o.pushKV("path", fs::PathToString(fixture));
    UniValue dest_pol(UniValue::VOBJ);
    dest_pol.pushKV("destination", (tmp / "out").utf8string());
    plan_o.pushKV("local_policy", dest_pol);

    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxacquisition", plan_o), result, code, err), err);
    const std::string plan_id = result["plan_id"].get_str();

    UniValue files(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("path", "weights.gguf");
    f.pushKV("sha384", Sha384Of(payload));
    f.pushKV("source_path", fs::PathToString(src));
    files.push_back(f);

    UniValue ex(UniValue::VOBJ);
    ex.pushKV("plan_id", plan_id);
    ex.pushKV("caller", "ahp-acq-10-exec");
    ex.pushKV("idempotency_key", "ahp-acq-10-execute-k1");
    ex.pushKV("verified_local_files", files);

    UniValue first;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ex), first, code, err), err);
    BOOST_CHECK_EQUAL(first["state"].get_str(), "MODEL_READY");
    BOOST_REQUIRE(first.exists("job_id") && first["job_id"].isStr());
    const std::string job_id = first["job_id"].get_str();
    BOOST_CHECK_EQUAL(first["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue replay;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ex), replay, code, err), err);
    BOOST_CHECK_EQUAL(replay["job_id"].get_str(), job_id);
    BOOST_CHECK_EQUAL(replay["state"].get_str(), "MODEL_READY");
    BOOST_CHECK_EQUAL(replay["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue other(UniValue::VOBJ);
    other.pushKV("path", "other.gguf");
    other.pushKV("sha384", Sha384Of("different-verified-bytes"));
    other.pushKV("source_path", fs::PathToString(src));
    UniValue conflict_files(UniValue::VARR);
    conflict_files.push_back(other);
    UniValue altered(UniValue::VOBJ);
    altered.pushKV("plan_id", plan_id);
    altered.pushKV("caller", "ahp-acq-10-exec");
    altered.pushKV("idempotency_key", "ahp-acq-10-execute-k1");
    altered.pushKV("verified_local_files", conflict_files);

    UniValue conflicted;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", altered), conflicted, code, err));
    BOOST_CHECK_EQUAL(code, "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(conflicted["status"].get_str(), "REJECTED");
    BOOST_CHECK_EQUAL(conflicted["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!conflicted.exists("job_id"));
    BOOST_CHECK(!conflicted.exists("state") || conflicted["state"].get_str() != "MODEL_READY");

    UniValue unique_key_conflict(UniValue::VOBJ);
    unique_key_conflict.pushKV("plan_id", plan_id);
    unique_key_conflict.pushKV("caller", "ahp-acq-10-exec");
    unique_key_conflict.pushKV("idempotency_key", "ahp-acq-10-execute-k2");
    unique_key_conflict.pushKV("verified_local_files", conflict_files);
    UniValue unique_conflicted;
    BOOST_CHECK(!modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", unique_key_conflict), unique_conflicted, code, err));
    BOOST_CHECK_EQUAL(code, "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(unique_conflicted["status"].get_str(), "REJECTED");
    BOOST_CHECK_EQUAL(unique_conflicted["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
