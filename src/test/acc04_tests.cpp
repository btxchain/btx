// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc04/acc04.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/capability.h>
#include <modelnet/doc_claim/doc_claim.h>
#include <modelnet/git_snapshot.h>
#include <modelnet/lab_wire.h>
#include <modelnet/migrate_safe/migrate_safe.h>
#include <modelnet/nif_scope/nif_scope.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/provenance.h>
#include <modelnet/swarm_boundary.h>
#include <modelnet/swarm_engine.h>
#include <modelnet/swarm_fault02.h>
#include <modelnet/swarm_nottrainlicense.h>
#include <modelnet/swarm_payreg/swarm_payreg.h>
#include <modelnet/swarm_raftlog.h>
#include <modelnet/upload_scheduler.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace {

struct TempTree {
    fs::path path;
    bool armed{false};

    TempTree()
    {
        const auto tick = static_cast<unsigned long long>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        path = fs::temp_directory_path() / ("acc04-test-" + std::to_string(tick));
        std::error_code ec;
        fs::remove_all(path, ec);
        fs::create_directories(path);
        armed = fs::is_directory(path);
    }

    ~TempTree()
    {
        std::error_code ec;
        fs::remove_all(path, ec);
    }

    TempTree(const TempTree&) = delete;
    TempTree& operator=(const TempTree&) = delete;
};

void ExpectClosed(const modelnet::Acc04& eng)
{
    const char* closed[] = {
        "ASR-PAY-001", "ASR-PAY-002", "ASR-PAY-003", "ASR-PRT-001", "ASR-PRT-002",
        "ASR-RES-001", "ASR-RES-002", "ASR-SEC-001", "ASR-SEC-002", "ASR-REC-001",
        "ASR-REC-002", "ASR-MIG-001", "ASR-MIG-002", "ASR-ACC-002", "ASR-PUB-002",
        "ASR-PUB-004",
    };
    for (const char* id : closed) {
        BOOST_CHECK_EQUAL(std::string(eng.final_acceptance(id)), "CLOSED_IN_PROCESS");
    }
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-OBS-001")), "DEFINED_NEEDS_PROCESS");
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-PUB-001")), "DEFINED_NEEDS_PROCESS");
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-PAY-004")), "UNQUALIFIED");
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-ACC-001")), "UNQUALIFIED");
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-PUB-003")), "UNQUALIFIED");
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("NO-SUCH")), "");
}

void ProvePay(const modelnet::Acc04& eng)
{
    modelnet::SwarmPayReg reserve;
    std::string err = "stale";
    BOOST_REQUIRE(reserve.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_REQUIRE(reserve.Reserve("pool-a", "out-shared", static_cast<int64_t>(5), err));
    BOOST_REQUIRE(reserve.Reserve("pool-b", "out-b", static_cast<int64_t>(9), err));
    BOOST_CHECK(!reserve.Reserve("pool-b", "out-shared", static_cast<int64_t>(5), err));
    BOOST_CHECK_EQUAL(err, "OUTPOINT");
    BOOST_CHECK_EQUAL(reserve.reserve_pool("out-shared"), "pool-a");
    BOOST_CHECK_EQUAL(reserve.reserve_atoms("out-shared"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reserve.funded_balance("pool-a"), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(reserve.funded_balance("pool-b"), static_cast<int64_t>(9));
    BOOST_CHECK(reserve.holds_money("pool-a"));
    BOOST_CHECK(!reserve.holds_money("pool-b"));
    BOOST_CHECK_EQUAL(reserve.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(reserve.atoms_moved(), static_cast<int64_t>(0));

    modelnet::SwarmPayReg claim;
    BOOST_REQUIRE(claim.Claim("work-1", err));
    claim.FailCompute();
    BOOST_CHECK(claim.compute_failed());
    BOOST_CHECK(claim.claim_kept("work-1"));
    BOOST_CHECK(!claim.claim_kept("work-2"));
    BOOST_CHECK_EQUAL(claim.atoms_moved(), static_cast<int64_t>(0));

    modelnet::SwarmPayReg terms;
    BOOST_REQUIRE(terms.Open("channel-1", "pool-a", "pool-b", err));
    BOOST_REQUIRE(terms.Terms("route-1", static_cast<int64_t>(10), static_cast<int64_t>(160), err));
    BOOST_CHECK(!terms.Terms("route-1", static_cast<int64_t>(11), static_cast<int64_t>(160), err));
    BOOST_CHECK_EQUAL(err, "TERMS");
    BOOST_CHECK(!terms.Terms("route-1", static_cast<int64_t>(10), static_cast<int64_t>(161), err));
    BOOST_CHECK_EQUAL(terms.terms_atoms("route-1"), static_cast<int64_t>(10));
    BOOST_CHECK_EQUAL(terms.terms_timeout("route-1"), static_cast<int64_t>(160));

    modelnet::SwarmPayReg settle;
    BOOST_CHECK(!settle.Settle(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!settle.qualified());
    BOOST_CHECK(!settle.broadcast());
    BOOST_CHECK(!settle.spendable());
    BOOST_CHECK_EQUAL(settle.atoms_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(settle.Mode(), "REGTEST_UNBROADCAST");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-PAY-004")), "UNQUALIFIED");
}

void ProveProtocol()
{
    UniValue body(UniValue::VOBJ);
    body.pushKV("record", "envelope");
    std::string err = "stale";
    BOOST_CHECK(modelnet::AcceptCanonicalEnvelope(body, err));
    BOOST_CHECK(err.empty());
    UniValue parsed;
    BOOST_CHECK(!modelnet::StrictParseJson("{\"record\":1,\"record\":2}", parsed, err));

    modelnet::LeaseTable table;
    modelnet::LeaseRecord& rec = table.Create(modelnet::LeaseClass::TRANSFER, "worker", static_cast<uint64_t>(32),
                                              modelnet::NewGeneration());
    const std::string id = rec.lease_id;
    BOOST_CHECK(table.Cancel(id, true) == modelnet::PhysicalDisposition::STILL_IN_FLIGHT);
    BOOST_CHECK(!table.ReleaseIfQuiescent(id, err));
    BOOST_CHECK_EQUAL(err, "not quiescent");
}

void ProveResources()
{
    modelnet::HostResourceBroker broker;
    modelnet::MemoryLimits limits;
    limits.host_physical_bytes = static_cast<uint64_t>(100);
    std::string err = "stale";
    BOOST_REQUIRE(broker.Configure(limits, err));
    BOOST_REQUIRE(broker.Reserve(static_cast<uint64_t>(60), static_cast<uint64_t>(0), static_cast<uint64_t>(0), false, err));
    BOOST_CHECK(!broker.Reserve(static_cast<uint64_t>(50), static_cast<uint64_t>(0), static_cast<uint64_t>(0), false, err));
    BOOST_CHECK_EQUAL(err, "host budget");

    modelnet::UploadAdmission admission;
    admission.slots = 2;
    admission.max_slots = 2;
    admission.per_identity = 1;
    admission.per_netgroup = 2;
    modelnet::UploadScheduler scheduler(admission);
    modelnet::UploadRequest first;
    first.identity = "worker-a";
    first.netgroup = "group-a";
    first.cls = modelnet::UploadClass::NORMAL;
    first.bytes = static_cast<uint64_t>(8);
    modelnet::UploadRequest repeat = first;
    modelnet::UploadRequest second = first;
    second.identity = "worker-b";
    modelnet::UploadRequest third = first;
    third.identity = "worker-c";
    const modelnet::UploadDecision admitted = scheduler.Admit(first);
    const modelnet::UploadDecision unfair = scheduler.Admit(repeat);
    const modelnet::UploadDecision other = scheduler.Admit(second);
    const modelnet::UploadDecision full = scheduler.Admit(third);
    BOOST_CHECK(admitted.admitted);
    BOOST_CHECK(!unfair.admitted);
    BOOST_CHECK_EQUAL(unfair.reason, "per-identity");
    BOOST_CHECK(other.admitted);
    BOOST_CHECK(!full.admitted);
    BOOST_CHECK_EQUAL(full.reason, "slots full");
    BOOST_CHECK_EQUAL(scheduler.Active(), 2);
}

void ProveSecurity()
{
    std::string accepted;
    std::string err = "stale";
    BOOST_CHECK(modelnet::SwarmTrustLabel("realm-policy", "caller-domain", accepted, err));
    BOOST_CHECK_EQUAL(accepted, "realm-policy");
    BOOST_CHECK(!modelnet::SwarmTrustLabel("", "caller-domain", accepted, err));
    BOOST_CHECK_EQUAL(err, "TRUST_LABEL");
    BOOST_CHECK(accepted.empty());

    modelnet::NifScope scope;
    BOOST_CHECK(scope.policy() == modelnet::NifPrivacy::LocalOnly);
    const std::vector<unsigned char> payload{0x11, 0x22, 0x33};
    BOOST_REQUIRE(scope.SendLocal(payload, err));
    BOOST_CHECK(!scope.SendWan(err));
    BOOST_CHECK_EQUAL(err, "NO_ROUTE");
    BOOST_CHECK(!scope.Scan("notes", err));
    BOOST_CHECK_EQUAL(err, "NOT_SCAN");
    BOOST_CHECK(scope.received() == payload);
    BOOST_CHECK_EQUAL(scope.lan_packets(), static_cast<int64_t>(0));
    BOOST_CHECK(!scope.connected());
    BOOST_CHECK(!scope.broadcast());
}

void ProveRecovery(const fs::path& dir)
{
    modelnet::SwarmFault02 fault;
    fault.lease_id = "lease-1";
    fault.old_epoch = "1";
    fault.new_epoch = "2";
    fault.lease_expired = true;
    fault.durable = true;
    fault.payment_claim = true;
    std::string err = "stale";
    const modelnet::SwarmFault02Result result = modelnet::SwarmRecoverFault02(fault, err);
    BOOST_CHECK(result.recovered);
    BOOST_CHECK(result.payment_preserved);
    BOOST_CHECK(!result.committed);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK(err.empty());

    modelnet::SwarmCommandLog log;
    BOOST_REQUIRE(log.Open(dir, 1, err));
    BOOST_REQUIRE(log.Append(static_cast<int64_t>(1), static_cast<int64_t>(0), static_cast<int64_t>(0), "keep", err));
    BOOST_REQUIRE(log.Append(static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(1), "tail", err));
    BOOST_REQUIRE(log.Commit(static_cast<int64_t>(1), err));
    BOOST_CHECK(!log.Truncate(static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "COMMITTED_PREFIX");
    BOOST_CHECK_EQUAL(log.Entries().at(0).command, "keep");
    BOOST_REQUIRE(log.Truncate(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(log.Entries().size(), 1);
    BOOST_CHECK_EQUAL(log.Entries().at(0).command, "keep");
    BOOST_CHECK_EQUAL(log.CommitIndex(), static_cast<int64_t>(1));
}

void ProveStatusAndHardware(const modelnet::Acc04& eng, const fs::path& dir)
{
    const fs::path present = dir / "present";
    {
        std::ofstream file(present);
        BOOST_REQUIRE(file);
        file << "x";
    }
    std::string err = "stale";
    const modelnet::SwarmEngineStatus installed = modelnet::SwarmProbeEngine("local", present, err);
    BOOST_CHECK(installed.present);
    BOOST_CHECK(!installed.advertised);
    BOOST_CHECK(!installed.qualified);
    BOOST_CHECK_EQUAL(installed.code, "INSTALLED");
    modelnet::SwarmEngineStatus status = installed;
    BOOST_CHECK(!modelnet::SwarmQualifyEngine(status, true, 1.0, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!status.advertised);
    BOOST_CHECK(!status.qualified);
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-OBS-001")), "DEFINED_NEEDS_PROCESS");

    const modelnet::SwarmEngineStatus missing = modelnet::SwarmProbeEngine("local", dir / "absent", err);
    BOOST_CHECK(!missing.present);
    BOOST_CHECK(!missing.advertised);
    BOOST_CHECK(!missing.qualified);
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.windows_passed());
}

void ProveMigration()
{
    modelnet::MigrateSafe gate;
    std::string err = "stale";
    BOOST_REQUIRE(gate.Store("row", "body-1", static_cast<int64_t>(2), err));
    BOOST_CHECK(!gate.Move("row", static_cast<int64_t>(3), err));
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_UPGRADE);
    BOOST_CHECK_EQUAL(gate.assurance("row"), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(gate.body("row"), "body-1");
    gate.Fail();
    BOOST_CHECK(!gate.Move("row", static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, modelnet::MIGRATE_SAFE_JOURNAL);
    BOOST_CHECK_EQUAL(gate.body("row"), "body-1");
    gate.Clear();
    BOOST_CHECK(gate.Move("row", static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(gate.body("row"), "body-1");
    BOOST_CHECK_EQUAL(gate.assurance("row"), static_cast<int64_t>(2));
}

void ProvePublication(const modelnet::Acc04& eng)
{
    std::string err = "stale";
    BOOST_CHECK(!modelnet::SafeGitPath("notes/.git/objects", err));
    BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-PUB-001")), "DEFINED_NEEDS_PROCESS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));

    const unsigned char first = 0x41;
    const unsigned char second = 0x42;
    std::string digest;
    std::string other;
    BOOST_REQUIRE(modelnet::GitObjectDigest("blob", Span<const unsigned char>(&first, 1), digest, err));
    BOOST_REQUIRE(modelnet::GitObjectDigest("blob", Span<const unsigned char>(&second, 1), other, err));
    BOOST_CHECK(digest != other);
    BOOST_CHECK(modelnet::IsStrongGitDigest(digest));
    modelnet::RefJournal empty;
    BOOST_CHECK(!empty.AuthorizeAndStage({}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PUSH_STAGE");
    modelnet::GitRefUpdate update;
    update.refname = "refs/heads/note";
    update.sequence = static_cast<uint64_t>(0);
    update.record_id = digest;
    modelnet::RefJournal journal;
    BOOST_REQUIRE(journal.AuthorizeAndStage({update}, err));
    BOOST_REQUIRE(journal.Publish(err));
    BOOST_CHECK(err.empty());
    const auto found = journal.Committed().find(update.refname);
    BOOST_REQUIRE(found != journal.Committed().end());
    BOOST_CHECK_EQUAL(found->second.record_id, digest);

    modelnet::DocClaim docs;
    BOOST_CHECK(!docs.Claim("readme", "release qualified", err));
    BOOST_CHECK_EQUAL(err, modelnet::DOC_CLAIM_CLAIM);
    BOOST_CHECK(!docs.stored("readme"));
    BOOST_CHECK(!docs.release_qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-PUB-003")), "UNQUALIFIED");

    modelnet::SwarmNotTrainLicense note;
    note.license_id = "download-1";
    note.want_train = true;
    const modelnet::SwarmNotTrainLicenseResult license = modelnet::SwarmNoteNotTrainLicense(note, err);
    BOOST_CHECK_EQUAL(license.code, "NOT_GRANT");
    BOOST_CHECK(!license.granted);
    BOOST_CHECK(!license.trained);
    modelnet::ProvenanceEvidence evidence;
    evidence.kind = "unsigned";
    modelnet::ProvenanceVerifyResult verified;
    BOOST_CHECK(modelnet::VerifyProvenanceEvidence(evidence, verified));
    BOOST_CHECK(verified.parsed);
    BOOST_CHECK(!verified.verified_here);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(acc04_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pass_latches)
{
    modelnet::Acc04 eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Apply("ASR-PAY-001", "pool", static_cast<int64_t>(1), true, err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!eng.passed());

    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.advertised());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Hosts(static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(err, "HOSTS");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Hosts(static_cast<int64_t>(1), err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    ExpectClosed(eng);

    ProvePay(eng);
    ProveProtocol();
    ProveResources();
    ProveSecurity();
    TempTree tmp;
    BOOST_REQUIRE(tmp.armed);
    ProveRecovery(tmp.path);
    ProveStatusAndHardware(eng, tmp.path);
    ProveMigration();
    ProvePublication(eng);
    BOOST_CHECK_EQUAL(std::string(eng.final_acceptance("ASR-ACC-001")), "UNQUALIFIED");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.passed());
}

BOOST_AUTO_TEST_SUITE_END()
