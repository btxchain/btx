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
#include <univalue.h>
#include <util/fs.h>

#include <chrono>
#include <cstdint>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace modelnet {
namespace {

struct TempTree {
    fs::path path;
    bool armed{false};

    explicit TempTree(fs::path dir) : path(std::move(dir))
    {
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

fs::path MakeTemp()
{
    const auto tick = static_cast<unsigned long long>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    return fs::temp_directory_path() / ("acc04-" + std::to_string(tick));
}

bool QuietMoney(const SwarmPayReg& reg, std::string& err)
{
    if (reg.automatic_spend() != NIFDT_AUTOMATIC_SPEND || reg.atoms_moved() != static_cast<int64_t>(0) ||
        reg.qualified() || reg.broadcast() || reg.spendable()) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    return true;
}

bool ProvePayReserve(std::string& err)
{
    SwarmPayReg reg;
    if (!reg.Open("channel-1", "pool-a", "pool-b", err)) return false;
    if (!reg.Reserve("pool-a", "out-shared", static_cast<int64_t>(5), err)) return false;
    if (!reg.Reserve("pool-b", "out-b", static_cast<int64_t>(9), err)) return false;
    if (reg.Reserve("pool-b", "out-shared", static_cast<int64_t>(5), err) || err != kSwarmPayRegOutpoint) {
        err = kSwarmPayRegOutpoint;
        return false;
    }
    if (reg.reserve_pool("out-shared") != "pool-a" || reg.reserve_atoms("out-shared") != static_cast<int64_t>(5)) {
        err = kSwarmPayRegOutpoint;
        return false;
    }
    if (reg.funded_balance("pool-a") != static_cast<int64_t>(5) || reg.funded_balance("pool-b") != static_cast<int64_t>(9)) {
        err = kSwarmPayRegOutpoint;
        return false;
    }
    if (!reg.holds_money("pool-a") || reg.holds_money("pool-b")) {
        err = kSwarmPayRegOutpoint;
        return false;
    }
    return QuietMoney(reg, err);
}

bool ProvePayClaim(std::string& err)
{
    SwarmPayReg reg;
    if (!reg.Claim("work-1", err)) return false;
    reg.FailCompute();
    if (!reg.compute_failed() || !reg.claim_kept("work-1") || reg.claim_kept("work-2")) {
        err = kSwarmPayRegClaim;
        return false;
    }
    return QuietMoney(reg, err);
}

bool ProvePayTerms(std::string& err)
{
    SwarmPayReg reg;
    if (!reg.Open("channel-1", "pool-a", "pool-b", err)) return false;
    if (!reg.Terms("route-1", static_cast<int64_t>(10), static_cast<int64_t>(160), err)) return false;
    if (reg.Terms("route-1", static_cast<int64_t>(11), static_cast<int64_t>(160), err) || err != kSwarmPayRegTerms) {
        err = kSwarmPayRegTerms;
        return false;
    }
    if (reg.Terms("route-1", static_cast<int64_t>(10), static_cast<int64_t>(161), err) || err != kSwarmPayRegTerms) {
        err = kSwarmPayRegTerms;
        return false;
    }
    if (reg.terms_atoms("route-1") != static_cast<int64_t>(10) || reg.terms_timeout("route-1") != static_cast<int64_t>(160)) {
        err = kSwarmPayRegTerms;
        return false;
    }
    return QuietMoney(reg, err);
}

bool ProvePaySettle(std::string& err)
{
    SwarmPayReg reg;
    if (reg.Settle(err) || err != NIFDT_UNQUALIFIED) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (reg.qualified() || reg.broadcast() || reg.spendable() || reg.mainnet() ||
        reg.atoms_moved() != static_cast<int64_t>(0) || reg.Mode() != kSwarmPayRegMode ||
        reg.automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    return true;
}

bool ProveEnvelope(std::string& err)
{
    UniValue body(UniValue::VOBJ);
    body.pushKV("record", "envelope");
    if (!AcceptCanonicalEnvelope(body, err)) return false;
    UniValue parsed;
    const std::string duplicate = "{\"record\":1,\"record\":2}";
    if (StrictParseJson(duplicate, parsed, err)) {
        err = "BTX035_NONCANONICAL";
        return false;
    }
    return true;
}

bool ProveQuiescence(std::string& err)
{
    LeaseTable table;
    LeaseRecord& rec = table.Create(LeaseClass::TRANSFER, "worker", static_cast<uint64_t>(32), NewGeneration());
    const std::string id = rec.lease_id;
    if (table.Cancel(id, true) != PhysicalDisposition::STILL_IN_FLIGHT) {
        err = "QUIESCENT";
        return false;
    }
    if (table.ReleaseIfQuiescent(id, err) || err != "not quiescent") {
        err = "not quiescent";
        return false;
    }
    return true;
}

bool ProveCeiling(std::string& err)
{
    HostResourceBroker broker;
    MemoryLimits limits;
    limits.host_physical_bytes = static_cast<uint64_t>(100);
    if (!broker.Configure(limits, err)) return false;
    if (!broker.Reserve(static_cast<uint64_t>(60), static_cast<uint64_t>(0), static_cast<uint64_t>(0), false, err)) {
        return false;
    }
    if (broker.Reserve(static_cast<uint64_t>(50), static_cast<uint64_t>(0), static_cast<uint64_t>(0), false, err) ||
        err != "host budget") {
        err = "host budget";
        return false;
    }
    return true;
}

bool ProveBackpressure(std::string& err)
{
    UploadAdmission admission;
    admission.slots = 2;
    admission.max_slots = 2;
    admission.per_identity = 1;
    admission.per_netgroup = 2;
    UploadScheduler scheduler(admission);
    const UploadRequest first{"worker-a", "group-a", UploadClass::NORMAL, static_cast<uint64_t>(8)};
    const UploadRequest repeat{"worker-a", "group-a", UploadClass::NORMAL, static_cast<uint64_t>(8)};
    const UploadRequest second{"worker-b", "group-a", UploadClass::NORMAL, static_cast<uint64_t>(8)};
    const UploadRequest third{"worker-c", "group-a", UploadClass::NORMAL, static_cast<uint64_t>(8)};
    const UploadDecision admitted = scheduler.Admit(first);
    const UploadDecision unfair = scheduler.Admit(repeat);
    const UploadDecision other = scheduler.Admit(second);
    const UploadDecision full = scheduler.Admit(third);
    if (!admitted.admitted || unfair.admitted || unfair.reason != "per-identity" || !other.admitted ||
        full.admitted || full.reason != "slots full" || scheduler.Active() != 2) {
        err = "BACKPRESSURE";
        return false;
    }
    return true;
}

bool ProveTrust(std::string& err)
{
    std::string accepted;
    if (!SwarmTrustLabel("realm-policy", "caller-domain", accepted, err) || accepted != "realm-policy") {
        err = "TRUST_LABEL";
        return false;
    }
    if (SwarmTrustLabel("", "caller-domain", accepted, err) || err != "TRUST_LABEL" || !accepted.empty()) {
        err = "TRUST_LABEL";
        return false;
    }
    return true;
}

bool ProvePrivateScope(std::string& err)
{
    NifScope scope;
    if (scope.policy() != NifPrivacy::LocalOnly) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    const std::vector<unsigned char> payload{0x11, 0x22, 0x33};
    if (!scope.SendLocal(payload, err)) return false;
    if (scope.SendWan(err) || err != kSwarmLanWireNoRoute) {
        err = kSwarmLanWireNoRoute;
        return false;
    }
    if (scope.Scan("notes", err) || err != kSwarmLanWireNotScan) {
        err = kSwarmLanWireNotScan;
        return false;
    }
    if (scope.received() != payload || scope.lan_packets() != static_cast<int64_t>(0) || scope.connected() ||
        scope.broadcast()) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    return true;
}

bool ProveCombinedFailure(std::string& err)
{
    SwarmFault02 fault;
    fault.lease_id = "lease-1";
    fault.old_epoch = "1";
    fault.new_epoch = "2";
    fault.lease_expired = true;
    fault.durable = true;
    fault.payment_claim = true;
    const SwarmFault02Result result = SwarmRecoverFault02(fault, err);
    if (!result.recovered || !result.replaced || !result.payment_preserved || result.committed || result.bytes_moved ||
        result.broadcast || !err.empty()) {
        if (err.empty()) err = "LOST";
        return false;
    }
    return true;
}

bool ProvePrefix(const fs::path& dir, std::string& err)
{
    SwarmCommandLog log;
    if (!log.Open(dir, 1, err)) return false;
    if (!log.Append(static_cast<int64_t>(1), static_cast<int64_t>(0), static_cast<int64_t>(0), "keep", err)) return false;
    if (!log.Append(static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(1), "tail", err)) return false;
    if (!log.Commit(static_cast<int64_t>(1), err)) return false;
    if (log.Truncate(static_cast<int64_t>(1), err) || err != "COMMITTED_PREFIX") {
        err = "COMMITTED_PREFIX";
        return false;
    }
    if (log.CommitIndex() != static_cast<int64_t>(1) || log.Entries().size() != 2 || log.Entries()[0].command != "keep") {
        err = "COMMITTED_PREFIX";
        return false;
    }
    if (!log.Truncate(static_cast<int64_t>(2), err)) return false;
    if (log.CommitIndex() != static_cast<int64_t>(1) || log.Entries().size() != 1 || log.Entries()[0].command != "keep") {
        err = "COMMITTED_PREFIX";
        return false;
    }
    return true;
}

bool ProveStatus(const fs::path& dir, std::string& err)
{
    const fs::path present = dir / "present";
    {
        std::ofstream file(present);
        if (!file) {
            err = "ENGINE_ABSENT";
            return false;
        }
        file << "x";
    }
    const SwarmEngineStatus installed = SwarmProbeEngine("local", present, err);
    if (!installed.present || installed.advertised || installed.qualified || installed.code != "INSTALLED") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    SwarmEngineStatus status = installed;
    if (SwarmQualifyEngine(status, true, 1.0, err) || err != NIFDT_UNQUALIFIED || status.advertised || status.qualified) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    return true;
}

bool ProveMigration(std::string& err)
{
    MigrateSafe gate;
    if (!gate.Store("row", "body-1", static_cast<int64_t>(2), err)) return false;
    if (gate.Move("row", static_cast<int64_t>(3), err) || err != MIGRATE_SAFE_UPGRADE) {
        err = MIGRATE_SAFE_UPGRADE;
        return false;
    }
    if (gate.assurance("row") != static_cast<int64_t>(2) || gate.body("row") != "body-1") {
        err = MIGRATE_SAFE_UPGRADE;
        return false;
    }
    gate.Fail();
    if (gate.Move("row", static_cast<int64_t>(2), err) || err != MIGRATE_SAFE_JOURNAL) {
        err = MIGRATE_SAFE_JOURNAL;
        return false;
    }
    if (gate.body("row") != "body-1" || gate.assurance("row") != static_cast<int64_t>(2)) {
        err = MIGRATE_SAFE_JOURNAL;
        return false;
    }
    gate.Clear();
    if (!gate.Move("row", static_cast<int64_t>(1), err)) return false;
    if (gate.body("row") != "body-1" || gate.assurance("row") != static_cast<int64_t>(2) || gate.failed()) {
        err = MIGRATE_SAFE_JOURNAL;
        return false;
    }
    return true;
}

bool ProveHardware(const fs::path& dir, std::string& err)
{
    const SwarmEngineStatus missing = SwarmProbeEngine("local", dir / "absent", err);
    if (missing.present || missing.advertised || missing.qualified || err != "ENGINE_ABSENT" ||
        missing.code != "ENGINE_ABSENT") {
        err = "ENGINE_ABSENT";
        return false;
    }
    return true;
}

bool ProveResearchPath(std::string& err)
{
    if (SafeGitPath("notes/.git/objects", err)) {
        err = "BTX035_PATH_UNSAFE";
        return false;
    }
    if (err != "BTX035_PATH_UNSAFE") {
        err = "BTX035_PATH_UNSAFE";
        return false;
    }
    return true;
}

bool ProvePublication(std::string& err)
{
    const unsigned char first = 0x41;
    const unsigned char second = 0x42;
    std::string digest;
    std::string other;
    if (!GitObjectDigest("blob", Span<const unsigned char>(&first, 1), digest, err)) return false;
    if (!GitObjectDigest("blob", Span<const unsigned char>(&second, 1), other, err)) return false;
    if (digest == other || !IsStrongGitDigest(digest)) {
        err = "BTX035_ID_MISMATCH";
        return false;
    }
    RefJournal empty;
    if (empty.AuthorizeAndStage({}, err) || err != "BTX035_PUSH_STAGE") {
        err = "BTX035_PUSH_STAGE";
        return false;
    }
    GitRefUpdate update;
    update.refname = "refs/heads/note";
    update.sequence = static_cast<uint64_t>(0);
    update.record_id = digest;
    RefJournal journal;
    if (!journal.AuthorizeAndStage({update}, err)) return false;
    if (!journal.Publish(err)) return false;
    const auto found = journal.Committed().find(update.refname);
    if (found == journal.Committed().end() || found->second.record_id != digest) {
        err = "HISTORY";
        return false;
    }
    return true;
}

bool ProvePublicDoc(std::string& err)
{
    DocClaim docs;
    if (docs.Claim("readme", "release qualified", err) || err != DOC_CLAIM_CLAIM || docs.stored("readme") ||
        docs.release_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    return true;
}

bool ProveLicense(std::string& err)
{
    SwarmNotTrainLicense note;
    note.license_id = "download-1";
    note.want_train = true;
    const SwarmNotTrainLicenseResult license = SwarmNoteNotTrainLicense(note, err);
    if (license.code != "NOT_GRANT" || license.granted || license.trained || err != "NOT_GRANT") {
        err = "NOT_GRANT";
        return false;
    }
    ProvenanceEvidence evidence;
    evidence.kind = "unsigned";
    ProvenanceVerifyResult verified;
    if (!VerifyProvenanceEvidence(evidence, verified) || !verified.parsed || verified.verified_here) {
        err = "SIGNATURE_INVALID";
        return false;
    }
    return true;
}

} // namespace

bool Acc04::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (hosts() != static_cast<int64_t>(1) || passed() || gpu_passed() || windows_passed() || release_qualified() ||
        hardware_qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    TempTree tmp(MakeTemp());
    if (!tmp.armed) {
        err = "DIR";
        return false;
    }
    if (!ProvePayReserve(err)) return false;
    if (!ProvePayClaim(err)) return false;
    if (!ProvePayTerms(err)) return false;
    if (!ProvePaySettle(err)) return false;
    if (!ProveEnvelope(err)) return false;
    if (!ProveQuiescence(err)) return false;
    if (!ProveCeiling(err)) return false;
    if (!ProveBackpressure(err)) return false;
    if (!ProveTrust(err)) return false;
    if (!ProvePrivateScope(err)) return false;
    if (!ProveCombinedFailure(err)) return false;
    if (!ProvePrefix(tmp.path, err)) return false;
    if (!ProveStatus(tmp.path, err)) return false;
    if (!ProveMigration(err)) return false;
    if (hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (!ProveHardware(tmp.path, err)) return false;
    if (!ProveResearchPath(err)) return false;
    if (!ProvePublication(err)) return false;
    if (!ProvePublicDoc(err)) return false;
    if (!ProveLicense(err)) return false;
    if (automatic_spend() != NIFDT_AUTOMATIC_SPEND || bytes_moved() != static_cast<int64_t>(0)) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    m_done = true;
    err.clear();
    return true;
}

bool Acc04::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    static const char* const kJournal[] = {
        "ADM-003", "RUN-001", "RUN-002", "RUN-003", "RUN-004",
        "RSI-001", "RSI-002", "RSI-003",
        "REALM-001", "REALM-002", "REALM-003",
        "MDT-001", "MDT-002", "MDT-003", "MDT-004",
        "WAN-001",
    };
    bool known = false;
    for (const char* row : kJournal) {
        if (id == row) {
            known = true;
            break;
        }
    }
    if (id.empty() || !known) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (aux > static_cast<int64_t>(100)) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    static const char* const kAbsent[] = {
        "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer", "dualpipe", "fp8", "fp4",
    };
    for (const char* name : kAbsent) {
        if (text == name) {
            err = NIFDT_ENGINE_ABSENT;
            return false;
        }
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id == "ADM-003" && text == "kill") {
        err = "ADVISORY";
        return false;
    }
    if (id == "RUN-002" && text == "passthrough") {
        err = "SCOPE";
        return false;
    }
    if (id == "RUN-003" && text == "recall") {
        err = "SENT";
        return false;
    }
    if (id == "RSI-001" && text == "inherit") {
        err = "GRANT";
        return false;
    }
    if (id == "RSI-002" && text == "skip") {
        err = "REGRESSION";
        return false;
    }
    if (id == "RSI-003" && text == "transfer") {
        err = "GENERATION";
        return false;
    }
    if (id == "REALM-002" && text == "bridge") {
        err = "BRIDGE";
        return false;
    }
    if (id == "REALM-003" && text == "transitive") {
        err = "TRUST";
        return false;
    }
    if (id == "MDT-001" && text == "monetary") {
        err = "STORE";
        return false;
    }
    if (id == "MDT-002" && text == "latest") {
        err = "DISAGREE";
        return false;
    }
    if (id == "MDT-004" && text == "rewrite") {
        err = "FOREIGN";
        return false;
    }
    if (id == "WAN-001" && text == "older") {
        err = "ROLLBACK";
        return false;
    }
    const auto found = m_journal.find(id);
    if (found != m_journal.end()) {
        err = found->second == text ? NIFDT_REPLAY : "UNCHANGED";
        return false;
    }
    m_journal.emplace(id, text);
    err.clear();
    return true;
}

const char* Acc04::final_acceptance(const std::string& id) const
{
    if (id == "ASR-PAY-001" || id == "ASR-PAY-002" || id == "ASR-PAY-003" || id == "ASR-PRT-001" ||
        id == "ASR-PRT-002" || id == "ASR-RES-001" || id == "ASR-RES-002" || id == "ASR-SEC-001" ||
        id == "ASR-SEC-002" || id == "ASR-REC-001" || id == "ASR-REC-002" || id == "ASR-MIG-001" ||
        id == "ASR-MIG-002" || id == "ASR-ACC-002" || id == "ASR-PUB-002" || id == "ASR-PUB-004") {
        return "CLOSED_IN_PROCESS";
    }
    if (id == "ASR-OBS-001" || id == "ASR-PUB-001") return "DEFINED_NEEDS_PROCESS";
    if (id == "ASR-PAY-004" || id == "ASR-ACC-001" || id == "ASR-PUB-003") return "UNQUALIFIED";
    return "";
}

bool Acc04::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc04::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc04::Gpu(std::string& err) const
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc04::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc04::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
