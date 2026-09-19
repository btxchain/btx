// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01 Worker I — ensure / orchestrator.
// Uses TransferSession(GlobalTransferCredits()) only. No second CreditBroker,
// no remote inference, automatic_spend_atoms stays 0.
// Coordinator wires DispatchCapabilityRpc to these symbols.

#include <modelnet/capability.h>
#include <modelnet/transfer_session.h>

#include <crypto/common.h>
#include <util/fs.h>
#include <util/time.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

std::mutex g_ensure_mu;

struct TtcStage {
    std::string name;
    int64_t occupancy_ms{0};
    int64_t elapsed_ms{0};
};

struct TtcTrace {
    std::vector<TtcStage> stages;
    bool overlapped{true};
};

struct IdempotentEnsure {
    std::string payload;
    UniValue result;
};

struct UpdateIdem {
    std::string payload;
    UniValue result;
};

struct CapEvent {
    int64_t seq{0};
    UniValue body;
};

std::map<std::string, TtcTrace> g_ttc;
std::map<std::string, IdempotentEnsure> g_ensure_idem;
std::map<std::string, UpdateIdem> g_update_idem;
std::vector<CapEvent> g_events;
int64_t g_next_seq{1};
int64_t g_compacted_upto{0};

constexpr int64_t kFixtureMs[] = {5, 20, 10, 8, 15, 12, 6};
const char* kStageNames[] = {"resolve", "acquire", "verify", "materialize", "load", "warm", "smoke"};

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

void PushZero(UniValue& r)
{
    r.pushKV("automatic_spend_atoms", 0);
}

std::string NextAction(const std::string& code)
{
    if (code == "HELPER_DOWN") return "wait_for_helper";
    if (code == "MEMORY_RESERVATION_FAILED") return "reduce_memory_or_retry";
    if (code == "UNVERIFIED_RANGE") return "reacquire_verified_bytes";
    if (code == "STALE_GENERATION") return "refresh_generation";
    if (code == "GRANT_WRONG_CALLER") return "use_grant_caller";
    if (code == "SOFTWARE_TRUST_REQUIRED") return "keep_current_client_security";
    if (code == "PAID_PATH_FORBIDDEN") return "keep_automatic_spend_atoms_0";
    if (code == "ID_MISMATCH") return "resubmit_expected_digest";
    if (code == "IDEMPOTENCY_CONFLICT") return "new_authorization";
    if (code == "INVALID_PARAMETER") return "supply_plan_id";
    if (code == "BUDGET_EXCEEDED") return "wait_for_transfer_credits";
    return "inspect_error_code";
}

void FillError(UniValue& result, const std::string& code, const std::string& err, const char* stage)
{
    result = UniValue(UniValue::VOBJ);
    result.pushKV("error_code", code);
    result.pushKV("message", err);
    result.pushKV("stage", stage);
    const bool retry = code == "HELPER_DOWN" || code == "MEMORY_RESERVATION_FAILED" || code == "BUDGET_EXCEEDED";
    result.pushKV("retryable", retry);
    result.pushKV("cleanup", "RETIRING");
    result.pushKV("next_action", NextAction(code));
    PushZero(result);
}

bool FailResult(UniValue& result, std::string& err_code, std::string& err, const char* code, const std::string& msg,
                const char* stage)
{
    Fail(err_code, err, code, msg);
    FillError(result, err_code, err, stage);
    return false;
}

int64_t ParseI64(const UniValue& v, int64_t fallback = 0)
{
    if (v.isNum()) return v.getInt<int64_t>();
    if (v.isStr()) {
        const char* s = v.get_str().c_str();
        char* end = nullptr;
        const long long n = std::strtoll(s, &end, 10);
        if (end && end != s) return static_cast<int64_t>(n);
    }
    return fallback;
}

std::string FieldStr(const UniValue& o, const char* k)
{
    if (!o.exists(k) || !o[k].isStr()) return {};
    return o[k].get_str();
}

bool FieldFalse(const UniValue& o, const char* k)
{
    if (!o.exists(k)) return false;
    const UniValue& v = o[k];
    if (v.isFalse()) return true;
    if (v.isBool()) return !v.get_bool();
    if (v.isNum()) return ParseI64(v, 1) == 0;
    if (v.isStr()) {
        const std::string s = v.get_str();
        return s == "0" || s == "false" || s == "FALSE";
    }
    return false;
}

bool FieldTrue(const UniValue& o, const char* k)
{
    if (!o.exists(k)) return false;
    const UniValue& v = o[k];
    if (v.isTrue()) return true;
    if (v.isBool()) return v.get_bool();
    if (v.isNum()) return ParseI64(v, 0) != 0;
    if (v.isStr()) {
        const std::string s = v.get_str();
        return s == "1" || s == "true" || s == "TRUE";
    }
    return false;
}

std::string IdempotencyScope(const UniValue& request, const std::string& idem)
{
    std::string caller;
    if (request.exists("grant") && request["grant"].isObject()) {
        caller = FieldStr(request["grant"], "caller");
    }
    if (caller.empty()) caller = FieldStr(request, "as");
    if (caller.empty()) caller = FieldStr(request, "caller");
    return caller + '\n' + idem;
}

std::string PayloadFingerprint(const UniValue& request)
{
    UniValue body(UniValue::VOBJ);
    if (request.isObject()) {
        for (const auto& k : request.getKeys()) {
            if (k == "idempotency_key") continue;
            body.pushKV(k, request[k]);
        }
    }
    return body.write();
}

bool SpendForbidden(const UniValue& o, UniValue& result, std::string& err_code, std::string& err)
{
    if (!o.exists("automatic_spend_atoms")) return false;
    if (ParseI64(o["automatic_spend_atoms"], 0) != 0) {
        FailResult(result, err_code, err, "PAID_PATH_FORBIDDEN", "automatic_spend_atoms must remain 0", "admit");
        return true;
    }
    return false;
}

bool ParseClientSecurityRank(const std::string& s, int64_t& rank)
{
    rank = 0;
    if (s.empty()) return false;
    const auto pos = s.find("client_min=");
    if (pos != std::string::npos) {
        const char* p = s.c_str() + pos + 11;
        if (*p < '0' || *p > '9') return false;
        rank = static_cast<int64_t>(std::strtoll(p, nullptr, 10));
        return true;
    }
    std::string t = s;
    if (!t.empty() && (t[0] == 'v' || t[0] == 'V')) t.erase(0, 1);
    if (t.empty()) return false;
    int64_t parts[3] = {0, 0, 0};
    int n = 0;
    std::string cur;
    auto flush = [&]() {
        if (n >= 3 || cur.empty()) return;
        parts[n++] = static_cast<int64_t>(std::strtoll(cur.c_str(), nullptr, 10));
        cur.clear();
    };
    bool dotted = false;
    for (char c : t) {
        if (c >= '0' && c <= '9') {
            cur.push_back(c);
        } else if (c == '.') {
            dotted = true;
            flush();
        } else if (!cur.empty() && n > 0) {
            break;
        }
    }
    flush();
    if (dotted && n > 0) {
        rank = parts[0] * 1000000 + parts[1] * 1000 + parts[2];
        return true;
    }
    if (!t.empty() && t.find_first_not_of("0123456789") == std::string::npos) {
        rank = static_cast<int64_t>(std::strtoll(t.c_str(), nullptr, 10));
        return true;
    }
    if (n == 1) {
        rank = parts[0];
        return true;
    }
    return false;
}

std::vector<unsigned char> CpuFixtureBytes()
{
    const std::string header = R"({"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}})";
    std::vector<unsigned char> out(8 + header.size() + 8, 0);
    WriteLE64(out.data(), header.size());
    std::memcpy(out.data() + 8, header.data(), header.size());
    return out;
}

bool GrantAllowsEnsure(const LocalCapabilityGrant& grant, UniValue& result, std::string& err_code, std::string& err)
{
    const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
    if (!GrantAllows(grant, "ENSURE", now, err_code, err)) {
        FillError(result, err_code, err, "admit");
        return false;
    }
    if (grant.json.exists("effects") && grant.json["effects"].isArray()) {
        bool ok = false;
        for (const auto& e : grant.json["effects"].getValues()) {
            if (e.isStr() && (e.get_str() == "ENSURE" || e.get_str() == "*")) ok = true;
        }
        if (!ok) {
            return FailResult(result, err_code, err, "EFFECT_DENIED", "ENSURE", "admit");
        }
    }
    return true;
}

void RecordTtc(const std::string& job_id, const std::vector<TtcStage>& stages)
{
    TtcTrace tr;
    tr.overlapped = true;
    tr.stages = stages;
    std::lock_guard<std::mutex> lock(g_ensure_mu);
    g_ttc[job_id] = std::move(tr);
}

UniValue EventCopy(const UniValue& event, int64_t seq)
{
    UniValue stored(UniValue::VOBJ);
    if (event.isObject()) {
        for (const auto& k : event.getKeys()) stored.pushKV(k, event[k]);
    } else {
        stored.pushKV("payload", event);
    }
    stored.pushKV("seq", seq);
    stored.pushKV("automatic_spend_atoms", 0);
    return stored;
}

bool HelperAliveFromRequest(const UniValue& request)
{
    if (FieldFalse(request, "helper_alive")) return false;
    if (FieldStr(request, "inject_error") == "HELPER_DOWN") return false;
    return true;
}

std::string Inject(const UniValue& request)
{
    return FieldStr(request, "inject_error");
}

bool TransitionLease(const std::string& lease_id, LeaseLife life)
{
    std::string tcode, terr;
    return GlobalCapabilityLeases().Transition(lease_id, life, tcode, terr);
}

} // namespace

bool HelperDownFail(bool helper_alive, std::string& err_code, std::string& err)
{
    if (helper_alive) {
        err_code.clear();
        err.clear();
        return true;
    }
    return Fail(err_code, err, "HELPER_DOWN",
                "capability helper unavailable; monetary node continues; automatic_spend_atoms stays 0");
}

bool SoftwareTrustFloor(const std::string& current_client, const std::string& rollback_client, std::string& err_code,
                        std::string& err)
{
    int64_t cur = 0;
    int64_t rb = 0;
    // Unparseable or empty current/rollback is not rank 0. Treating it as 0
    // let any named version pass as an "upgrade" from an unknown floor.
    if (!ParseClientSecurityRank(current_client, cur) || !ParseClientSecurityRank(rollback_client, rb)) {
        return Fail(err_code, err, "SOFTWARE_TRUST_REQUIRED",
                    "model rollback must not lower accepted client security version");
    }
    if (rb < cur) {
        return Fail(err_code, err, "SOFTWARE_TRUST_REQUIRED",
                    "model rollback must not lower accepted client security version");
    }
    err_code.clear();
    err.clear();
    return true;
}

bool AppendCapabilityEvent(const UniValue& event)
{
    std::lock_guard<std::mutex> lock(g_ensure_mu);
    CapEvent e;
    e.seq = g_next_seq++;
    e.body = EventCopy(event, e.seq);
    g_events.push_back(std::move(e));
    return true;
}

bool CompactCapabilityEvents(int64_t cursor, UniValue& out)
{
    out = UniValue(UniValue::VOBJ);
    std::lock_guard<std::mutex> lock(g_ensure_mu);
    int64_t dropped = 0;
    std::vector<CapEvent> kept;
    kept.reserve(g_events.size());
    for (auto& e : g_events) {
        if (e.seq <= cursor) {
            ++dropped;
            continue;
        }
        kept.push_back(std::move(e));
    }
    g_events.swap(kept);
    if (cursor > g_compacted_upto) g_compacted_upto = cursor;
    int64_t first = 0;
    int64_t last = cursor;
    UniValue arr(UniValue::VARR);
    for (const auto& e : g_events) {
        if (first == 0) first = e.seq;
        last = e.seq;
        arr.push_back(e.body);
    }
    const bool gap = (first != 0 && first > cursor + 1) || (first == 0 && g_compacted_upto > cursor);
    out.pushKV("from_cursor", cursor);
    out.pushKV("next_cursor", last);
    out.pushKV("gap", gap);
    if (gap) {
        out.pushKV("gap_begin", cursor + 1);
        out.pushKV("gap_end", first != 0 ? first - 1 : g_compacted_upto);
    }
    out.pushKV("events", arr);
    out.pushKV("compacted", true);
    out.pushKV("side_effects", dropped);
    out.pushKV("duplicate_side_effects", false);
    PushZero(out);
    return true;
}

bool GetCapabilityTtcTrace(const std::string& job_id, UniValue& out, std::string& err_code, std::string& err)
{
    out = UniValue(UniValue::VOBJ);
    CapabilityJob job;
    const bool have_job = !job_id.empty() && LookupCapabilityJob(job_id, job);
    TtcTrace tr;
    {
        std::lock_guard<std::mutex> lock(g_ensure_mu);
        auto it = g_ttc.find(job_id);
        if (it != g_ttc.end()) tr = it->second;
    }
    // Empty job_id still returns the overlapping fixture DAG (Dispatch getbtxttctrace({})).
    if (!job_id.empty() && !have_job && tr.stages.empty()) {
        return FailResult(out, err_code, err, "INVALID_PARAMETER", "unknown job_id", "ttc");
    }
    if (tr.stages.empty()) {
        for (size_t i = 0; i < 7; ++i) {
            TtcStage s;
            s.name = kStageNames[i];
            s.occupancy_ms = kFixtureMs[i];
            tr.stages.push_back(s);
        }
        tr.overlapped = true;
    }
    std::vector<int64_t> occ;
    UniValue stages(UniValue::VARR);
    for (const auto& s : tr.stages) {
        UniValue st(UniValue::VOBJ);
        st.pushKV("stage", s.name);
        st.pushKV("ms", s.occupancy_ms);
        st.pushKV("occupancy_ms", s.occupancy_ms);
        st.pushKV("elapsed_ms", s.elapsed_ms);
        stages.push_back(st);
        occ.push_back(s.occupancy_ms);
    }
    const int64_t wall = CriticalPathTtcMs(occ, /*overlapped=*/true);
    const int64_t sum = CriticalPathTtcMs(occ, /*overlapped=*/false);
    out.pushKV("job_id", job_id);
    out.pushKV("stages", stages);
    out.pushKV("wall_ms", wall);
    out.pushKV("sum_occupancy_ms", sum);
    out.pushKV("critical_path_not_sum", true);
    out.pushKV("overlapped", tr.overlapped);
    out.pushKV("confidence", "fixture");
    out.pushKV("sample_count", 1);
    PushZero(out);
    err_code.clear();
    err.clear();
    return true;
}

bool PlanCapabilityUpdate(const UniValue& request, UniValue& result, std::string& err_code, std::string& err)
{
    result = UniValue(UniValue::VOBJ);
    err_code.clear();
    err.clear();
    if (SpendForbidden(request, result, err_code, err)) return false;

    if (request.exists("grant") && request["grant"].isObject()) {
        LocalCapabilityGrant grant;
        if (!ParseGrant(request["grant"], grant, err_code, err)) {
            FillError(result, err_code, err, "admit");
            return false;
        }
        const int64_t now = TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now());
        if (!GrantAllows(grant, "PLAN", now, err_code, err)) {
            FillError(result, err_code, err, "admit");
            return false;
        }
    }

    const bool rollback = FieldTrue(request, "rollback") || FieldStr(request, "phase") == "rollback";
    if (rollback) {
        const std::string cur = FieldStr(request, "current_client");
        const std::string rb = FieldStr(request, "rollback_client");
        if (!SoftwareTrustFloor(cur, rb, err_code, err)) {
            FillError(result, err_code, err, "rollback");
            return false;
        }
    }

    const std::string old_lock = FieldStr(request, "lock_id");
    std::string digest = FieldStr(request, "digest");
    if (digest.empty()) digest = FieldStr(request, "expected_digest");
    const std::string idem = FieldStr(request, "idempotency_key");
    const std::string payload_fp = PayloadFingerprint(request);
    // Missing key: existing write policy — proceed as a new write, do not conflict.
    if (!idem.empty()) {
        const std::string scope = IdempotencyScope(request, idem);
        std::lock_guard<std::mutex> lock(g_ensure_mu);
        auto it = g_update_idem.find(scope);
        if (it != g_update_idem.end()) {
            if (it->second.payload != payload_fp) {
                return FailResult(result, err_code, err, "IDEMPOTENCY_CONFLICT",
                                  "idempotency_key reused with a different payload", "update");
            }
            result = it->second.result;
            result.pushKV("idempotent", true);
            PushZero(result);
            return true;
        }
    }

    UniValue lockj(UniValue::VOBJ);
    lockj.pushKV("parent_lock", old_lock);
    lockj.pushKV("proposed", true);
    lockj.pushKV("digest", digest);
    lockj.pushKV("automatic_spend_atoms", 0);
    if (request.exists("lock") && request["lock"].isObject()) {
        for (const auto& k : request["lock"].getKeys()) {
            if (k == "latest") continue;
            lockj.pushKV(k, request["lock"][k]);
        }
    }
    CapabilityLock proposed;
    if (!ParseCapabilityLock(lockj, proposed, err_code, err)) {
        FillError(result, err_code, err, "update");
        return false;
    }
    StoreCapabilityLock(proposed);

    const bool smoke_ok = FieldTrue(request, "smoke_passed") && !FieldTrue(request, "smoke_failed");
    const bool switch_ready = smoke_ok && !rollback;

    result.pushKV("old_lock", old_lock);
    result.pushKV("proposed_lock", proposed.lock_id.Hex());
    result.pushKV("active_lock", old_lock);
    result.pushKV("rollback_lock", old_lock);
    result.pushKV("switch_ready", switch_ready);
    result.pushKV("old_generation_stable", true);
    result.pushKV("new_lock_prepared", true);
    result.pushKV("digest", digest);
    PushZero(result);

    UniValue ev(UniValue::VOBJ);
    ev.pushKV("kind", rollback ? "release" : "plan");
    ev.pushKV("old_lock", old_lock);
    ev.pushKV("proposed_lock", proposed.lock_id.Hex());
    (void)AppendCapabilityEvent(ev);

    if (!idem.empty()) {
        std::lock_guard<std::mutex> lock(g_ensure_mu);
        UpdateIdem rec;
        rec.payload = payload_fp;
        rec.result = result;
        g_update_idem[IdempotencyScope(request, idem)] = std::move(rec);
    }
    return true;
}

bool EnsureCapability(ModelCatalog& cat, const UniValue& request, UniValue& result, std::string& err_code,
                      std::string& err)
{
    (void)cat;
    result = UniValue(UniValue::VOBJ);
    err_code.clear();
    err.clear();
    const auto t0 = std::chrono::steady_clock::now();
    auto mark = [&](size_t i, std::vector<TtcStage>& stages) {
        const auto now = std::chrono::steady_clock::now();
        const int64_t elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - t0).count();
        TtcStage s;
        s.name = kStageNames[i];
        s.elapsed_ms = elapsed;
        s.occupancy_ms = kFixtureMs[i];
        if (i < stages.size()) stages[i] = s;
        else stages.push_back(s);
    };
    std::vector<TtcStage> stages(7);
    for (size_t i = 0; i < 7; ++i) {
        stages[i].name = kStageNames[i];
        stages[i].occupancy_ms = kFixtureMs[i];
    }

    if (SpendForbidden(request, result, err_code, err)) return false;

    UniValue grant_json =
        request.exists("grant") && request["grant"].isObject() ? request["grant"] : UniValue(UniValue::VOBJ);
    if (SpendForbidden(grant_json, result, err_code, err)) return false;
    LocalCapabilityGrant grant;
    if (!ParseGrant(grant_json, grant, err_code, err)) {
        FillError(result, err_code, err, "admit");
        return false;
    }
    if (!GrantAllowsEnsure(grant, result, err_code, err)) return false;
    if (request.exists("as") && request["as"].isStr() && request["as"].get_str() != grant.caller) {
        return FailResult(result, err_code, err, "GRANT_WRONG_CALLER", "caller", "admit");
    }
    mark(0, stages);

    const std::string plan_id = FieldStr(request, "plan_id");
    CapabilityPlan plan;
    if (!LookupCapabilityPlan(plan_id, plan)) {
        return FailResult(result, err_code, err, "INVALID_PARAMETER", "unknown plan_id", "resolve");
    }
    const std::string expected = FieldStr(request, "expected_digest");
    if (!expected.empty() && expected != plan.plan_digest.Hex()) {
        return FailResult(result, err_code, err, "ID_MISMATCH", "expected plan digest", "resolve");
    }

    if (!HelperDownFail(HelperAliveFromRequest(request), err_code, err)) {
        FillError(result, err_code, err, "helper");
        return false;
    }

    const std::string inject = Inject(request);
    const std::string idem = FieldStr(request, "idempotency_key");
    const std::string payload_fp = PayloadFingerprint(request);
    // Missing key: existing write policy — each call is a new execute, not a replay.
    if (!idem.empty()) {
        const std::string scope = IdempotencyScope(request, idem);
        std::lock_guard<std::mutex> lock(g_ensure_mu);
        auto it = g_ensure_idem.find(scope);
        if (it != g_ensure_idem.end()) {
            if (it->second.payload != payload_fp) {
                return FailResult(result, err_code, err, "IDEMPOTENCY_CONFLICT",
                                  "idempotency_key reused with a different payload", "admit");
            }
            result = it->second.result;
            result.pushKV("idempotent", true);
            PushZero(result);
            return true;
        }
    }

    if (inject == "MEMORY_RESERVATION_FAILED") {
        return FailResult(result, err_code, err, "MEMORY_RESERVATION_FAILED", "host budget", "reserve");
    }
    std::string berr;
    const uint64_t host_need = grant.host_bytes ? grant.host_bytes : 0;
    if (host_need > 0 && !GlobalCapabilityBroker().Reserve(host_need, 0, grant.device_bytes, false, berr)) {
        return FailResult(result, err_code, err, "MEMORY_RESERVATION_FAILED", berr, "reserve");
    }

    const bool resident = FieldTrue(request, "resident_base");
    if (resident) {
        std::string bhex = FieldStr(request, "base_id");
        std::string bindhex = FieldStr(request, "adapter_base_binding");
        if (bhex.empty()) {
            return FailResult(result, err_code, err, "INVALID_PARAMETER", "resident_base requires base_id", "compose");
        }
        if (bindhex.empty()) bindhex = bhex;
        Digest48 base{}, bind{};
        std::string herr;
        if (!Digest48::FromHex(bhex, base, herr) || !Digest48::FromHex(bindhex, bind, herr)) {
            return FailResult(result, err_code, err, "ADAPTER_BASE_MISMATCH", herr, "compose");
        }
        if (!AttachExactBaseAdapter(base, bind, err_code, err)) {
            FillError(result, err_code, err, "compose");
            return false;
        }
    }

    // Existing transfer stack only. Never construct a second CreditBroker.
    TransferSession xfer(GlobalTransferCredits());
    uint64_t need = resident ? 0 : plan.missing_bytes;
    if (need > PIECE_SIZE) need = PIECE_SIZE;
    if (need > 0) {
        uint64_t rid = 0;
        std::string xerr;
        if (!xfer.ReserveAndQueue("native-fixture", 0, 0, need, rid, xerr)) {
            return FailResult(result, err_code, err, "BUDGET_EXCEEDED", "existing transfer credits", "acquire");
        }
        xfer.NoteSent(rid);
        xfer.NoteReceiving(rid);
        xfer.NoteVerifying(rid);
        xfer.NoteCommitted(rid, CpuFixtureBytes().size());
    }
    mark(1, stages);

    const auto fixture = CpuFixtureBytes();
    if (inject == "UNVERIFIED_RANGE") {
        Digest48 man{};
        VerifiedRangeLease vr;
        std::string rcode, rerr;
        (void)ReadVerifiedRange(man, 0, fixture.size() + 1, 1, fixture, NewGeneration(), vr, rcode, rerr);
        return FailResult(result, err_code, err, "UNVERIFIED_RANGE", "range not covered by verified bytes", "verify");
    }

    const fs::path dest_dir{fs::temp_directory_path() / "btx-capability-ensure"};
    fs::create_directories(dest_dir);
    const Generation16 file_gen = NewGeneration();
    static std::atomic<uint64_t> dest_seq{0};
    const std::string dest_name = std::to_string(::getpid()) + "-" + std::to_string(dest_seq.fetch_add(1)) + "-" +
                                 GenerationHex(file_gen) + ".st";
    const std::string dest = fs::PathToString(dest_dir / fs::PathFromString(dest_name));
    std::vector<std::vector<unsigned char>> pieces{fixture};
    if (!MaterializeCompleteFile(pieces, dest, file_gen, err_code, err)) {
        FillError(result, err_code, err, "materialize");
        return false;
    }
    std::vector<unsigned char> on_disk(fixture.size());
    const int rfd = ::open(dest.c_str(), O_RDONLY | O_NOFOLLOW);
    if (rfd < 0) {
        (void)::unlink(dest.c_str());
        (void)::unlink((dest + ".gen").c_str());
        return FailResult(result, err_code, err, "UNVERIFIED_RANGE", "dest open after materialize", "verify");
    }
    const ssize_t nread = ::pread(rfd, on_disk.data(), on_disk.size(), 0);
    ::close(rfd);
    if (nread < 0 || static_cast<size_t>(nread) != fixture.size() || on_disk != fixture) {
        (void)::unlink(dest.c_str());
        (void)::unlink((dest + ".gen").c_str());
        return FailResult(result, err_code, err, "UNVERIFIED_RANGE", "dest bytes do not match verified fixture",
                          "verify");
    }
    (void)::unlink(dest.c_str());
    (void)::unlink((dest + ".gen").c_str());
    mark(3, stages);

    Digest48 man{};
    VerifiedRangeLease vr;
    if (!ReadVerifiedRange(man, 0, 0, on_disk.size(), on_disk, file_gen, vr, err_code, err)) {
        if (err_code == "RANGE_UNVERIFIED") err_code = "UNVERIFIED_RANGE";
        FillError(result, err_code, err, "verify");
        return false;
    }
    mark(2, stages);

    CapabilityJob job;
    job.job_id = GenerationHex(NewGeneration());
    job.generation = NewGeneration();
    job.plan_id = plan_id;
    job.cancel_disp = PhysicalDisposition::NOT_DISPATCHED;

    auto& table_lease = GlobalCapabilityLeases().Create(LeaseClass::LOAD, grant.caller,
                                                        host_need ? host_need : fixture.size(), job.generation);
    table_lease.operation_id = job.job_id;
    const std::string table_lease_id = table_lease.lease_id;
    (void)TransitionLease(table_lease_id, LeaseLife::ALLOCATED);
    (void)TransitionLease(table_lease_id, LeaseLife::POPULATING);

    if (inject == "STALE_GENERATION") {
        std::string serr;
        const Generation16 other = NewGeneration();
        (void)GlobalCapabilityLeases().StaleCompletion(job.job_id, other, serr);
        (void)TransitionLease(table_lease_id, LeaseLife::RETIRING);
        return FailResult(result, err_code, err, "STALE_GENERATION", "stale generation", "load");
    }
    if (request.exists("expected_generation") && request["expected_generation"].isStr()) {
        Generation16 want{};
        std::string gerr;
        if (!GenerationFromHex(request["expected_generation"].get_str(), want, gerr) || want != job.generation) {
            std::string serr;
            (void)GlobalCapabilityLeases().StaleCompletion(job.job_id, want, serr);
            return FailResult(result, err_code, err, "STALE_GENERATION", "stale generation", "load");
        }
    }

    const std::string runtime_id = [&]() {
        const std::string r = FieldStr(request, "runtime_id");
        return r.empty() ? std::string("synthetic-cpu-fixture") : r;
    }();
    UniValue typed = request.exists("typed_params") && request["typed_params"].isObject() ?
                         request["typed_params"] :
                         UniValue(UniValue::VOBJ);
    if (!typed.exists("adapter_abi")) typed.pushKV("adapter_abi", RUNTIME_ADAPTER_ABI);
    if (!typed.exists("backend") && runtime_id == "synthetic-cpu-fixture") typed.pushKV("backend", "CPU");

    ReadyReceipt receipt;
    const bool block_warmup = FieldTrue(request, "block_warmup") || FieldTrue(request, "smoke_blocked");
    if (!LoadTrustedRuntime(runtime_id, Span<const unsigned char>{fixture.data(), fixture.size()}, typed, receipt,
                            err_code, err)) {
        FillError(result, err_code, err, "load");
        return false;
    }
    mark(4, stages);
    mark(5, stages);

    (void)TransitionLease(table_lease_id, LeaseLife::VERIFIED);

    if (block_warmup) {
        receipt.achieved = ReadinessTarget::RUNTIME_LOADED;
        receipt.smoke_performed = false;
        receipt.smoke_passed = false;
        receipt.json.pushKV("achieved", ReadinessTargetName(receipt.achieved));
        receipt.json.pushKV("smoke_performed", false);
        receipt.json.pushKV("smoke_passed", false);
        receipt.json.pushKV("runtime_ready", false);
        receipt.json.pushKV("first_useful_result", false);
        job.state = ReadinessTargetName(ReadinessTarget::RUNTIME_LOADED);
    } else {
        if (!receipt.smoke_passed) {
            receipt.achieved = ReadinessTarget::RUNTIME_LOADED;
            job.state = ReadinessTargetName(ReadinessTarget::RUNTIME_LOADED);
        } else {
            receipt.achieved = ReadinessTarget::FIRST_USEFUL_RESULT;
            job.state = ReadinessTargetName(ReadinessTarget::FIRST_USEFUL_RESULT);
            (void)TransitionLease(table_lease_id, LeaseLife::ACTIVE);
        }
        receipt.json.pushKV("achieved", ReadinessTargetName(receipt.achieved));
        receipt.json.pushKV("runtime_ready", receipt.smoke_passed);
        receipt.json.pushKV("first_useful_result", receipt.smoke_passed);
        mark(6, stages);
    }

    job.receipt = receipt;
    job.receipt.recipe_id = plan.recipe_id;
    if (job.receipt.lease_id.empty()) job.receipt.lease_id = table_lease_id;
    StoreCapabilityJob(job);
    RecordTtc(job.job_id, stages);

    UniValue ev(UniValue::VOBJ);
    ev.pushKV("kind", "ensure");
    ev.pushKV("job_id", job.job_id);
    ev.pushKV("plan_id", plan_id);
    (void)AppendCapabilityEvent(ev);

    // #168: this lane is IMPLEMENTED_LAB. `(void)cat` above is honest — the path
    // materializes the local CPU fixture, it never dereferences the plan's recipe
    // digest. So the result must not claim a canonical acquire. `acquired_bytes`
    // is the fixture actually written, never the plan's requested byte contract.
    const uint64_t requested_bytes = static_cast<uint64_t>(plan.missing_bytes);
    const uint64_t acquired_bytes = static_cast<uint64_t>(fixture.size());
    int percent_ready = 100;
    if (requested_bytes > 0 && acquired_bytes < requested_bytes) {
        percent_ready = static_cast<int>((acquired_bytes * 100) / requested_bytes);
    }
    // The fixture path never dereferences a recipe digest, so it must not report a
    // completed acquire even when the plan requests zero missing bytes.
    if (percent_ready >= 100) percent_ready = 99;

    UniValue progress(UniValue::VOBJ);
    progress.pushKV("implementation_status", "IMPLEMENTED_LAB");
    progress.pushKV("scope", "LOCAL_FIXTURE");
    progress.pushKV("canonical_bytes_verified", false);
    progress.pushKV("files_complete", false);
    progress.pushKV("fixture_bytes_materialized", true);
    progress.pushKV("dest_bytes_matched", true);
    progress.pushKV("verified_representation", "native-cpu-fixture");
    progress.pushKV("runtime_loaded", true);
    progress.pushKV("runtime_ready", receipt.smoke_passed);
    progress.pushKV("first_useful_result", receipt.smoke_passed && !block_warmup);
    progress.pushKV("requested_bytes", requested_bytes);
    progress.pushKV("acquired_bytes", acquired_bytes);
    progress.pushKV("percent_ready", percent_ready);

    result = receipt.json.isObject() ? receipt.json : UniValue(UniValue::VOBJ);
    result.pushKV("implementation_status", "IMPLEMENTED_LAB");
    result.pushKV("scope", "LOCAL_FIXTURE");
    result.pushKV("fixture_path", true);
    // The fixture runtime loaded, but the requested recipe digest was not acquired.
    // `ready:false` keeps an agent from treating this as a completed acquire.
    result.pushKV("ready", false);
    result.pushKV("fixture_runtime_ready", receipt.smoke_passed);
    result.pushKV("requested_bytes", requested_bytes);
    result.pushKV("acquired_bytes", acquired_bytes);
    result.pushKV("job_id", job.job_id);
    result.pushKV("lease_id", job.receipt.lease_id);
    result.pushKV("generation", GenerationHex(job.generation));
    result.pushKV("achieved", ReadinessTargetName(receipt.achieved));
    result.pushKV("smoke_performed", receipt.smoke_performed);
    result.pushKV("smoke_passed", receipt.smoke_passed);
    result.pushKV("second_downloader", false);
    result.pushKV("used_global_transfer_credits", true);
    result.pushKV("used_transfer_session", true);
    result.pushKV("progress", progress);
    result.pushKV("opaque_lease", true);
    PushZero(result);

    if (!idem.empty()) {
        std::lock_guard<std::mutex> lock(g_ensure_mu);
        IdempotentEnsure rec;
        rec.payload = payload_fp;
        rec.result = result;
        g_ensure_idem[IdempotencyScope(request, idem)] = std::move(rec);
    }
    return true;
}

} // namespace modelnet
