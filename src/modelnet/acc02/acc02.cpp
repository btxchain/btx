// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc02/acc02.h>

#include <modelnet/nif_drain/nif_drain.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_channel.h>
#include <modelnet/swarm_discover/codes.h>
#include <modelnet/swarm_discover/swarm_discover.h>
#include <modelnet/swarm_evidence/codes.h>
#include <modelnet/swarm_evidence/swarm_evidence.h>
#include <modelnet/swarm_handoff/swarm_handoff.h>
#include <modelnet/swarm_hostinterp.h>
#include <modelnet/swarm_leasefence.h>
#include <modelnet/swarm_manifestok.h>
#include <modelnet/swarm_progress/codes.h>
#include <modelnet/swarm_progress/limits.h>
#include <modelnet/swarm_progress/swarm_progress.h>
#include <modelnet/swarm_revokegate.h>
#include <modelnet/swarm_sandboxfs.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

const char* const kWorker = "holder";
const char* const kJob = "authority";
const int64_t kAuthorityUntil = 100;
const int64_t kIssuedNow = 10;
const int64_t kSleptNow = 40;
const int64_t kPastNow = 101;

const char* const kPeerA = "peer-a";
const char* const kPeerB = "peer-b";
const char* const kObject = "obj";
const char* const kGrant = "grant-1";
const char* const kOtherGrant = "grant-fast";

const char* const kTrace = "trace";
const char* const kSummary = "sum";
const char* const kNote = "note";
const char* const kPromise = "promise";

const char* const kCross = "move-cross";
const char* const kCrossDest = "dest-cross";
const char* const kMove = "move-ok";
const char* const kMoveDest = "dest-ok";

const char* const kWorkRoot = "/work/";
const char* const kInside = "/work/unit";
const char* const kOutside = "/else/unit";
const char* const kEscape = "/work/../unit";

bool Refuse(bool ok, const std::string& err, const char* code)
{
    return !ok && err == code;
}

bool Accept(bool ok, const std::string& err)
{
    return ok && err.empty();
}

} // namespace

bool Acc02::covered(const std::string& id) const
{
    if (!m_done) return false;
    if (id == "ASR-EXE-007") return m_authority_until == kAuthorityUntil;
    if (id == "ASR-NET-001") {
        return m_discover.granted(kPeerA) && !m_discover.connected() &&
               m_discover.bytes_moved() == static_cast<int64_t>(0);
    }
    if (id == "ASR-NET-002" || id == "ASR-NET-003") {
        return m_discover.route_grant_id(kObject) == kGrant && m_discover.route_peer(kObject) == kPeerB &&
               m_discover.route_rtt_ms(kObject) == static_cast<int64_t>(5);
    }
    if (id == "ASR-NET-004") {
        return m_drain.drained() && m_drain.physical_bytes() == static_cast<int64_t>(0);
    }
    if (id == "ASR-NET-005") {
        return m_discover.status() == kSwarmDiscoverPartition && !m_discover.connected();
    }
    if (id == "ASR-HND-001") {
        return m_handoff.scoped() && m_handoff.authority_destination() == kMoveDest &&
               m_handoff.authority_generation() != static_cast<uint64_t>(0);
    }
    if (id == "ASR-HND-002") {
        return m_handoff.committed(kMove) && m_handoff.owner() == kMoveDest && m_handoff.atomic(kMove);
    }
    if (id == "ASR-HND-003") {
        return m_handoff.ambiguous(kCross) && !m_handoff.atomic(kCross) && m_handoff.owner_of(kCross).empty();
    }
    if (id == "ASR-HND-004") {
        return m_handoff.committed(kMove) && m_resumed.State().step == static_cast<uint64_t>(2) &&
               m_resumed.State().weight != m_weight_before_resume;
    }
    if (id == "ASR-PRG-001") {
        return m_progress.meaningful() && m_progress.loss_ppm() == static_cast<int64_t>(800) &&
               m_progress.step() == static_cast<int64_t>(2);
    }
    if (id == "ASR-PRG-002") return m_progress.correcting() && m_progress.recipe() == "recipe-a";
    if (id == "ASR-PRG-003") return m_progress.recipe() == "recipe-a" && m_progress.correcting();
    if (id == "ASR-PRG-004") return m_progress.sampled() && !m_progress.killed() && m_progress.correcting();
    if (id == "ASR-EVD-001") return m_evidence.stored(kTrace) && !m_evidence.shareable(kTrace);
    if (id == "ASR-EVD-002") return m_evidence.summary_source(kSummary) == kTrace;
    if (id == "ASR-EVD-003") return m_evidence.tainted(kNote) && !m_evidence.launched();
    if (id == "ASR-EVD-004") {
        std::string err;
        const SwarmRevokeGateResult gated = FenceResult(err);
        return m_resumed.State().step >= static_cast<uint64_t>(1) && !gated.allowed && gated.code == "REVOKED" &&
               !gated.bytes_moved && err == "REVOKED";
    }
    if (id == "ASR-EVD-005") return m_evidence.promised(kPromise) && m_evidence.body(kPromise).empty();
    if (id == "ASR-CAP-001") return !m_interpreters.admitted("package-author") && !m_interpreters.launched();
    if (id == "ASR-CAP-002") return false;
    if (id == "ASR-CAP-003") {
        return m_updates.SourceExporter() == "runtime" && m_updates.DestinationApprover() == "model" &&
               m_updates.SourceExporter() != m_updates.DestinationApprover();
    }
    if (id == "ASR-CAP-004") {
        return m_sandbox.allowed(kInside) && !m_sandbox.allowed(kOutside) && !m_sandbox.allowed(kEscape) &&
               !m_sandbox.launched();
    }
    if (id == "ASR-ART-001") {
        return m_manifest.usable("root") && m_manifest.usable("root-b") && !m_manifest.usable("root-open") &&
               !m_manifest.bytes_streamed();
    }
    return false;
}

bool Acc02::Scan(std::string& err)
{
    return m_discover.Scan("prefix", err);
}

bool Acc02::RouteOutsideScope(std::string& err)
{
    const std::string grant_before = m_discover.route_grant_id(kObject);
    const std::string peer_before = m_discover.route_peer(kObject);
    const int64_t rtt_before = m_discover.route_rtt_ms(kObject);
    const bool ok = m_discover.Route(kObject, kPeerA, kOtherGrant, static_cast<int64_t>(1), err);
    if (ok || err != kSwarmDiscoverScope) return false;
    if (m_discover.route_grant_id(kObject) != grant_before || m_discover.route_peer(kObject) != peer_before ||
        m_discover.route_rtt_ms(kObject) != rtt_before) {
        err = kSwarmDiscoverScope;
        return false;
    }
    return false;
}

bool Acc02::TryExtendAuthority(int64_t now_ms, int64_t until_ms, std::string& err)
{
    const bool ok = m_authority.Grant(kWorker, kJob, m_authority.epoch(), until_ms, now_ms, err);
    if (ok) m_authority_until = 0;
    return ok;
}

bool Acc02::TryUseAuthority(int64_t now_ms, std::string& err)
{
    return m_authority.Commit(kWorker, kJob, m_authority.epoch(), now_ms, "use", err);
}

bool Acc02::ShareTrace(std::string& err)
{
    return m_evidence.Share(kTrace, err);
}

bool Acc02::RetrievePromise(std::string& err)
{
    return m_evidence.Retrieve(kPromise, err);
}

bool Acc02::RefuseAmbiguousAgain(std::string& err)
{
    return m_handoff.Fence(kCross, false, err);
}

SwarmRevokeGateResult Acc02::FenceResult(std::string& err) const
{
    return SwarmReadAfterRevoke(true, false, true, true, err);
}

bool Acc02::Pass(std::string& err)
{
    if (m_done) {
        err.clear();
        return true;
    }
    if (m_passes != static_cast<int64_t>(0) || m_authority_until != static_cast<int64_t>(0)) {
        err = "STEP";
        return false;
    }

    if (!Accept(m_authority.Grant(kWorker, kJob, m_authority.epoch(), kAuthorityUntil, kIssuedNow, err), err)) return false;
    if (!Refuse(m_authority.Grant(kWorker, kJob, m_authority.epoch(), kAuthorityUntil + static_cast<int64_t>(500), kSleptNow, err),
                err, "REPLAY")) {
        return false;
    }
    if (!Refuse(m_authority.Commit(kWorker, kJob, m_authority.epoch(), kPastNow, "use", err), err, "LEASE_EXPIRED")) return false;
    m_authority_until = kAuthorityUntil;

    if (!Accept(m_discover.Offer(kPeerA, kSwarmDiscoverLan, "lan-a", static_cast<int64_t>(100), static_cast<int64_t>(1), err), err)) {
        return false;
    }
    if (!Accept(m_discover.Offer(kPeerB, kSwarmDiscoverLan, "lan-b", static_cast<int64_t>(100), static_cast<int64_t>(1), err), err)) {
        return false;
    }
    if (!Accept(m_discover.Grant(kPeerA, kSwarmDiscoverLan, err), err)) return false;
    if (!Accept(m_discover.Grant(kPeerB, kSwarmDiscoverLan, err), err)) return false;
    if (!Refuse(m_discover.Scan("prefix", err), err, kSwarmDiscoverNotScan)) return false;
    if (m_discover.connected() || m_discover.bytes_moved() != static_cast<int64_t>(0)) {
        err = kSwarmDiscoverNotScan;
        return false;
    }
    if (!Accept(m_discover.Route(kObject, kPeerA, kGrant, static_cast<int64_t>(20), err), err)) return false;
    if (!Refuse(m_discover.Route(kObject, kPeerA, kOtherGrant, static_cast<int64_t>(1), err), err, kSwarmDiscoverScope)) return false;
    if (m_discover.route_grant_id(kObject) != kGrant || m_discover.route_rtt_ms(kObject) != static_cast<int64_t>(20) ||
        m_discover.route_peer(kObject) != kPeerA) {
        err = kSwarmDiscoverScope;
        return false;
    }
    if (!Accept(m_discover.Route(kObject, kPeerB, kGrant, static_cast<int64_t>(5), err), err)) return false;
    if (m_discover.route_grant_id(kObject) != kGrant || m_discover.route_peer(kObject) != kPeerB ||
        m_discover.route_rtt_ms(kObject) != static_cast<int64_t>(5)) {
        err = kSwarmDiscoverScope;
        return false;
    }
    if (!Refuse(m_discover.Partition(false, err), err, kSwarmDiscoverPartition)) return false;
    if (m_discover.connected() || m_discover.status() != kSwarmDiscoverPartition) {
        err = kSwarmDiscoverPartition;
        return false;
    }

    if (!Accept(m_drain.Open("slot", static_cast<int64_t>(1000), err), err)) return false;
    if (!Accept(m_drain.Hold("slot", static_cast<int64_t>(4), err), err)) return false;
    if (!Refuse(m_drain.Release("slot", err), err, NIF_DRAIN_PINNED)) return false;
    if (m_drain.physical_bytes() != static_cast<int64_t>(4)) {
        err = NIF_DRAIN_PINNED;
        return false;
    }
    if (!Accept(m_drain.Cancel("slot", err), err)) return false;
    if (!Accept(m_drain.Drain("slot", static_cast<int64_t>(1), err), err)) return false;
    if (m_drain.physical_bytes() != static_cast<int64_t>(0) || !m_drain.drained()) {
        err = NIF_DRAIN_PINNED;
        return false;
    }
    if (!Accept(m_drain.Release("slot", err), err)) return false;
    if (m_drain.bytes_moved() != static_cast<int64_t>(0)) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }

    if (!Accept(m_handoff.Intent(kCross, "payload", err), err)) return false;
    if (!Accept(m_handoff.Lease(kCrossDest, static_cast<int64_t>(80), static_cast<int64_t>(1), err), err)) return false;
    if (!Accept(m_handoff.Begin(kCross, kCrossDest, static_cast<int64_t>(80), static_cast<int64_t>(1), err), err)) return false;
    if (!Refuse(m_handoff.Fence(kCross, false, err), err, kSwarmHandoffAmbiguous)) return false;
    if (m_handoff.atomic(kCross) || !m_handoff.ambiguous(kCross) || !m_handoff.owner_of(kCross).empty()) {
        err = kSwarmHandoffAmbiguous;
        return false;
    }
    if (!Refuse(m_handoff.Fence(kCross, false, err), err, kSwarmHandoffAmbiguous)) return false;

    if (!Accept(m_handoff.Intent(kMove, "payload", err), err)) return false;
    if (!Accept(m_handoff.Lease(kMoveDest, static_cast<int64_t>(80), static_cast<int64_t>(1), err), err)) return false;
    if (!Accept(m_handoff.Begin(kMove, kMoveDest, static_cast<int64_t>(80), static_cast<int64_t>(1), err), err)) return false;
    if (!m_handoff.scoped() || m_handoff.authority_destination() != kMoveDest ||
        m_handoff.authority_generation() == static_cast<uint64_t>(0) || m_handoff.owner() != kSwarmHandoffSource) {
        err = kSwarmHandoffHandoff;
        return false;
    }
    if (!Accept(m_handoff.Fence(kMove, true, err), err)) return false;
    if (!m_handoff.committed(kMove) || !m_handoff.atomic(kMove) || m_handoff.owner() != kMoveDest || m_handoff.spend_key_moved() ||
        m_handoff.atoms_moved() != kSwarmHandoffAtomsMoved) {
        err = kSwarmHandoffHandoff;
        return false;
    }

    IntegerTrainer source;
    if (!source.Step(err)) return false;
    const IntegerState checkpoint = source.State();
    if (checkpoint.step != static_cast<uint64_t>(1) || checkpoint.state_hash.empty()) {
        err = "STEP";
        return false;
    }
    m_weight_before_resume = checkpoint.weight;
    if (!m_resumed.Resume(checkpoint, err)) return false;
    if (!m_resumed.Step(err)) return false;
    if (m_resumed.State().step != static_cast<uint64_t>(2) || m_resumed.State().weight == m_weight_before_resume ||
        m_resumed.State().state_hash.empty()) {
        err = "STEP";
        return false;
    }
    IntegerTrainer cold;
    if (cold.Resume(IntegerState{}, err) || err != "BTX035_NOT_RESUMABLE") {
        err = "STEP";
        return false;
    }

    if (!Accept(m_progress.Sample("job", static_cast<int64_t>(1000), static_cast<int64_t>(1), err), err)) return false;
    if (m_progress.meaningful()) {
        err = kSwarmProgressReplay;
        return false;
    }
    if (!Refuse(m_progress.Sample("job", static_cast<int64_t>(1000), static_cast<int64_t>(1), err), err, kSwarmProgressReplay)) {
        return false;
    }
    if (!Accept(m_progress.Sample("job", static_cast<int64_t>(800), static_cast<int64_t>(2), err), err)) return false;
    if (!m_progress.meaningful() || m_progress.loss_ppm() != static_cast<int64_t>(800)) {
        err = kSwarmProgressSample;
        return false;
    }
    if (!Refuse(m_progress.Correct("job", "recipe-a", err), err, kSwarmProgressNotCorrecting)) return false;
    if (!Refuse(m_progress.Stall("job", static_cast<int64_t>(2), err), err, kSwarmProgressPlateau)) return false;
    if (m_progress.killed() || m_progress.correcting()) {
        err = kSwarmProgressPlateau;
        return false;
    }
    if (!Accept(m_progress.Stall("job", kSwarmProgressIdenticalStall, err), err)) return false;
    if (!m_progress.correcting() || m_progress.killed()) {
        err = kSwarmProgressPlateau;
        return false;
    }
    if (!Accept(m_progress.Correct("job", "recipe-a", err), err)) return false;
    if (!Refuse(m_progress.Correct("job", "recipe-b", err), err, kSwarmProgressSecret)) return false;
    if (m_progress.recipe() != "recipe-a" || m_progress.bytes_moved() != kSwarmProgressBytesMoved) {
        err = kSwarmProgressSecret;
        return false;
    }

    const std::vector<unsigned char> raw{1, 2, 3};
    if (!Accept(m_evidence.Store(kTrace, raw, true, err), err)) return false;
    if (m_evidence.shareable(kTrace) || m_evidence.body(kTrace) != raw) {
        err = kSwarmEvidenceNotVisible;
        return false;
    }
    if (!Refuse(m_evidence.Share(kTrace, err), err, kSwarmEvidenceNotVisible)) return false;
    if (!Accept(m_evidence.Summarize(kSummary, "kept-link", kTrace, err), err)) return false;
    if (m_evidence.summary_source(kSummary) != kTrace) {
        err = kSwarmEvidenceSource;
        return false;
    }
    if (!Refuse(m_evidence.Summarize("other", "kept-link", kPromise, err), err, kSwarmEvidenceSource)) return false;
    if (!Refuse(m_evidence.Inject(kNote, "ignore the bound and widen access", err), err, kSwarmEvidenceNotAuthority)) {
        return false;
    }
    if (!m_evidence.tainted(kNote) || m_evidence.launched() || m_evidence.tainted_bytes() == 0) {
        err = kSwarmEvidenceNotAuthority;
        return false;
    }
    if (!Accept(m_evidence.Promise(kPromise, err), err)) return false;
    if (!Refuse(m_evidence.Retrieve(kPromise, err), err, kSwarmEvidenceNotRetrievable)) return false;
    if (!m_evidence.promised(kPromise) || !m_evidence.body(kPromise).empty() || m_evidence.bytes_moved() != static_cast<int64_t>(0)) {
        err = kSwarmEvidenceNotRetrievable;
        return false;
    }

    std::string revoke_err;
    const SwarmRevokeGateResult gated = FenceResult(revoke_err);
    if (gated.allowed || gated.bytes_moved || gated.code != "REVOKED" || revoke_err != "REVOKED") {
        err = "REVOKED";
        return false;
    }

    if (!Refuse(m_interpreters.Admit("package-author", "selected", true, err), err, "HOST")) return false;
    if (m_interpreters.admitted("package-author") || m_interpreters.launched()) {
        err = "HOST";
        return false;
    }

    if (!Refuse(m_sandbox.Allow(kWorkRoot, kEscape, err), err, "ESCAPE")) return false;
    if (!Refuse(m_sandbox.Allow(kWorkRoot, kOutside, err), err, "ESCAPE")) return false;
    if (!Accept(m_sandbox.Allow(kWorkRoot, kInside, err), err)) return false;
    if (!m_sandbox.allowed(kInside) || m_sandbox.allowed(kOutside) || m_sandbox.launched()) {
        err = "ESCAPE";
        return false;
    }

    if (!Accept(m_updates.RecordPromotion("runtime", "runtime", err), err)) return false;
    if (!Refuse(m_updates.ApprovePromotion(err), err, "BTX035_AUTHORITY")) return false;
    if (!Accept(m_updates.RecordPromotion("runtime", "model", err), err)) return false;
    if (!Accept(m_updates.ApprovePromotion(err), err)) return false;
    if (m_updates.SourceExporter() == m_updates.DestinationApprover() || m_updates.SourceExporter() != "runtime" ||
        m_updates.DestinationApprover() != "model") {
        err = "BTX035_AUTHORITY";
        return false;
    }

    if (!Refuse(m_manifest.Bind("root-open", std::vector<std::string>{"digest-1"}, std::vector<std::string>{}, err), err,
                "MANIFEST")) {
        return false;
    }
    if (m_manifest.usable("root-open") || m_manifest.usable("root") || m_manifest.usable("root-b")) {
        err = "MANIFEST";
        return false;
    }
    const std::vector<std::string> children{"digest-1"};
    const std::vector<std::string> verified{"digest-1"};
    if (!Accept(m_manifest.Bind("root", children, verified, err), err)) return false;
    if (!m_manifest.usable("root") || m_manifest.usable("root-b") || m_manifest.bytes_streamed()) {
        err = "MANIFEST";
        return false;
    }
    if (!Accept(m_manifest.Bind("root-b", children, verified, err), err)) return false;
    if (!m_manifest.usable("root-b") || m_manifest.bytes_streamed()) {
        err = "MANIFEST";
        return false;
    }

    if (Qualify(err) || err != NIFDT_UNQUALIFIED || release_qualified() || hardware_qualified() || passed() || gpu_passed() ||
        windows_passed()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (Gpu(err) || err != NIFDT_ENGINE_ABSENT) return false;
    if (Hosts(static_cast<int64_t>(2), err) || err != "HOSTS") return false;
    if (!Hosts(static_cast<int64_t>(1), err)) return false;
    if (Release(err) || err != NIFDT_UNQUALIFIED) return false;
    if (Spend(err) || err != NIFDT_AUTOMATIC_SPEND) return false;
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1) ||
        bytes_moved() != static_cast<int64_t>(0) || automatic_spend() != NIFDT_AUTOMATIC_SPEND) {
        err = "HOSTS";
        return false;
    }
    if (launched() || gpu() || broadcast() || process_present()) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }

    static const char* const kClosed[] = {
        "ASR-EXE-007", "ASR-NET-001", "ASR-NET-002", "ASR-NET-003", "ASR-NET-004", "ASR-NET-005",
        "ASR-HND-001", "ASR-HND-002", "ASR-HND-003", "ASR-HND-004", "ASR-PRG-001", "ASR-PRG-002",
        "ASR-PRG-003", "ASR-PRG-004", "ASR-EVD-001", "ASR-EVD-002", "ASR-EVD-003", "ASR-EVD-004",
        "ASR-EVD-005", "ASR-CAP-001", "ASR-CAP-003", "ASR-CAP-004", "ASR-ART-001",
    };
    m_passes = static_cast<int64_t>(1);
    m_done = true;
    for (const char* id : kClosed) {
        if (!covered(id)) {
            m_done = false;
            m_passes = static_cast<int64_t>(0);
            err = "ID";
            return false;
        }
    }
    if (covered("ASR-CAP-002") || covered("ASR-EXE-006") || covered("")) {
        m_done = false;
        m_passes = static_cast<int64_t>(0);
        err = "ID";
        return false;
    }
    err.clear();
    return true;
}

bool Acc02::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc02::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc02::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc02::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Acc02::Qualify(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc02::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    static const char* const kJournal[] = {
        "WIRE-004", "ID-001", "ID-002", "ID-003", "ID-004",
        "NET-001", "NET-002", "NET-003", "NET-004",
        "GIT-001", "GIT-002", "GIT-003", "GIT-004", "GIT-005",
        "SCM-001", "SCM-002",
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
    if (id == "WIRE-004" && (text.find('?') != std::string::npos || text.find('#') != std::string::npos)) {
        err = "URI";
        return false;
    }
    if (id == "ID-001" && aux == static_cast<int64_t>(0)) {
        err = "EXPIRED";
        return false;
    }
    if (id == "ID-002" && text == "spend") {
        err = "ROLE";
        return false;
    }
    if (id == "ID-003" && text == "widen") {
        err = "NARROW";
        return false;
    }
    if (id == "ID-004" && text == "shrink") {
        err = "THRESHOLD";
        return false;
    }
    if (id == "NET-001" && text == "tofu") {
        err = "TOFU";
        return false;
    }
    if (id == "NET-002" && text == "downgrade") {
        err = "DOWNGRADE";
        return false;
    }
    if (id == "NET-003" && aux != static_cast<int64_t>(8)) {
        err = "FANOUT";
        return false;
    }
    if (id == "GIT-002" && text == "sha1") {
        err = "DIGEST";
        return false;
    }
    if (id == "GIT-003" && text == "hook") {
        err = "HOOK";
        return false;
    }
    if (id == "GIT-005" && text.compare(0, 7, "sha256-") != 0) {
        err = "OID";
        return false;
    }
    if (id == "SCM-002" && text == "conflict") {
        err = "CONFLICT";
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

} // namespace modelnet
