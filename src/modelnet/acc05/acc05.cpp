// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc05/acc05.h>
#include <modelnet/nif_scope/nif_scope.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_lanwire/codes.h>
#include <modelnet/swarm_lifecycle.h>
#include <modelnet/swarm_notcontrib.h>
#include <modelnet/swarm_notmandate.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool Owned(const std::string& id)
{
    return id == "DS-NAT-001" || id == "DS-NAT-002" || id == "DS-NAT-003" || id == "DS-NAT-004" ||
           id == "DS-NAT-005" || id == "DS-NAT-006" || id == "DS-HIRE-001" || id == "DS-HIRE-002" ||
           id == "DS-HIRE-003" || id == "DS-HIRE-004" || id == "DS-HIRE-005" || id == "DS-HIRE-006" ||
           id == "DS-AUTH-001" || id == "DS-AUTH-002" || id == "DS-AUTH-003" || id == "DS-AUTH-004" ||
           id == "DS-AUTH-005" || id == "DS-AUTH-006" || id == "DS-DATA-001" || id == "DS-DATA-002" ||
           id == "DS-DATA-003" || id == "DS-DATA-004" || id == "DS-DATA-005" || id == "DS-DATA-006";
}

bool FullFingerprint(const std::string& text, std::string& out)
{
    std::string part[3];
    int n = 0;
    std::string cur;
    for (char c : text) {
        if (c == ',') {
            if (n >= 2 || cur.empty()) return false;
            part[n++] = cur;
            cur.clear();
            continue;
        }
        cur.push_back(c);
    }
    if (n != 2 || cur.empty()) return false;
    part[2] = cur;
    out = part[0] + "," + part[1] + "," + part[2];
    return true;
}

bool SamePurpose(const std::string& text)
{
    return text == "read" || text == "effect" || text == "release" || text == "spend";
}

} // namespace

bool Acc05::purpose_granted(const std::string& purpose) const
{
    if (purpose == "read") return m_grant_read;
    if (purpose == "effect") return m_grant_effect;
    if (purpose == "release") return m_grant_release;
    if (purpose == "spend") return m_grant_spend;
    return false;
}

int Acc05::provenance_count() const
{
    if (!m_bytes_set) return 0;
    return static_cast<int>(1 + m_prov_more.size());
}

bool Acc05::gap_reported(const std::string& kind) const
{
    if (kind == "clock") return m_gap_clock;
    if (kind == "loss") return m_gap_loss;
    if (kind == "duplicate") return m_gap_duplicate;
    if (kind == "missing") return m_gap_missing;
    return false;
}

std::string Acc05::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

int64_t Acc05::stored(const std::string& id) const
{
    if (id == "DS-NAT-001" || id == "DS-NAT-002" || id == "DS-NAT-004") return m_nat.stored(id);
    if (id == "DS-HIRE-002" || id == "DS-HIRE-003" || id == "DS-HIRE-004" || id == "DS-HIRE-005" || id == "DS-HIRE-006") {
        return m_family.stored(id);
    }
    if (id == "DS-AUTH-001" || id == "DS-AUTH-002" || id == "DS-DATA-002") return m_auth.stored(id);
    if (id == "DS-DATA-005") return m_hire.stored(id);
    if (id == "DS-HIRE-001") return m_fingerprint_set ? static_cast<int64_t>(1) : static_cast<int64_t>(0);
    if (id == "DS-AUTH-003") return m_lease_set ? m_lease_aux : static_cast<int64_t>(0);
    if (id == "DS-DATA-003") return m_query_set ? m_query_bytes : static_cast<int64_t>(0);
    if (id == "DS-AUTH-005") {
        int64_t n = 0;
        if (m_grant_read) ++n;
        if (m_grant_effect) ++n;
        if (m_grant_release) ++n;
        if (m_grant_spend) ++n;
        return n;
    }
    return static_cast<int64_t>(0);
}

std::string Acc05::text_of(const std::string& id) const
{
    if (id == "DS-NAT-003") return m_observer;
    if (id == "DS-NAT-005") return m_case;
    if (id == "DS-HIRE-001") return m_fingerprint;
    if (id == "DS-AUTH-003") return m_lease_text;
    if (id == "DS-AUTH-004") return m_severity;
    if (id == "DS-DATA-001") return m_bytes;
    if (id == "DS-DATA-003") return m_asset;
    if (id == "DS-DATA-004") return m_local;
    if (id == "DS-NAT-001" || id == "DS-NAT-002" || id == "DS-NAT-004") return m_nat.text_of(id);
    if (id == "DS-HIRE-002" || id == "DS-HIRE-004" || id == "DS-HIRE-005" || id.rfind("DS-HIRE-002#", 0) == 0) {
        return m_family.text_of(id);
    }
    if (id == "DS-AUTH-001" || id == "DS-AUTH-002" || id == "DS-DATA-002") return m_auth.text_of(id);
    if (id == "DS-DATA-005") return m_hire.text_of(id);
    return std::string();
}

bool Acc05::bit_of(const std::string& id) const
{
    if (id == "DS-NAT-004") return m_nat.bit_of(id);
    if (id == "DS-HIRE-002" || id.rfind("DS-HIRE-002#", 0) == 0) return m_family.bit_of(id);
    if (id == "DS-DATA-005") return m_hire.bit_of(id);
    return false;
}

bool Acc05::Nat003(const std::string& op, const std::string& text, bool flag, std::string& err)
{
    if (text == "spend" || !flag) {
        err = "SPEND";
        return false;
    }
    SwarmDevice device;
    if (op == "observer") {
        device.idle_contribution = false;
        const SwarmRoles roles = SwarmEligibleRoles(device);
        if (!roles.observer || roles.seeder || roles.evaluator || roles.trainer) {
            err = "SPEND";
            return false;
        }
        if (roles.automatic_spend_atoms != NIFDT_AUTOMATIC_SPEND) {
            err = "SPEND";
            return false;
        }
        if (m_observer_set && m_observer == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (m_observer_set) {
            err = "UNCHANGED";
            return false;
        }
        m_observer = text;
        m_observer_set = true;
        err.clear();
        return true;
    }
    if (op == "enroll") {
        device.idle_contribution = true;
        device.slots = 1;
        const SwarmRoles roles = SwarmEligibleRoles(device);
        if (!roles.observer || !roles.seeder || roles.trainer) {
            err = "SPEND";
            return false;
        }
        if (roles.automatic_spend_atoms != NIFDT_AUTOMATIC_SPEND) {
            err = "SPEND";
            return false;
        }
        if (m_enroll_set && m_enroll == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (m_enroll_set) {
            err = "UNCHANGED";
            return false;
        }
        m_enroll = text;
        m_enroll_set = true;
        err.clear();
        return true;
    }
    err = "SPEND";
    return false;
}

bool Acc05::Nat005(const std::string& op, const std::string& text, const std::string& extra, bool flag, std::string& err)
{
    if (op == "restart") {
        if (!m_journal_armed) {
            err = "JOURNAL";
            return false;
        }
        m_case = m_journal_case;
        m_pending = m_journal_pending;
        err.clear();
        return true;
    }
    if (op == "scratch") {
        m_case = text;
        m_pending = extra;
        err.clear();
        return true;
    }
    if (!flag || text.empty()) {
        err = "JOURNAL";
        return false;
    }
    if (m_journal_armed && m_journal_case == text && m_journal_pending == extra) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (m_journal_armed) {
        err = "UNCHANGED";
        return false;
    }
    m_journal_case = text;
    m_journal_pending = extra;
    m_journal_armed = true;
    m_case = text;
    m_pending = extra;
    err.clear();
    return true;
}

bool Acc05::Nat006(const std::string& text, bool flag, std::string& err)
{
    if (text.empty()) {
        err = "WORKER";
        return false;
    }
    SwarmDevice device;
    device.idle_contribution = flag;
    const SwarmRoles roles = SwarmEligibleRoles(device);
    const SwarmBudget budget = SwarmGovern(device, 1);
    if (roles.automatic_spend_atoms != NIFDT_AUTOMATIC_SPEND) {
        err = "SPEND";
        return false;
    }
    NifScope scope;
    std::string wan_err;
    if (!scope.SetPolicy(NifPrivacy::LocalOnly, wan_err)) return false;
    if (scope.SendWan(wan_err) || wan_err != kSwarmLanWireNoRoute || scope.connected() || scope.broadcast()) {
        err = "OPTOUT";
        return false;
    }
    m_wan_refused = true;
    m_workers = budget.active_workers;
    m_published = false;
    if (!flag) {
        if (roles.seeder || roles.evaluator || roles.trainer || budget.active_workers != static_cast<int64_t>(0) ||
            budget.code != "IDLE_OFF") {
            err = "OPTOUT";
            return false;
        }
        SwarmNotContrib note;
        note.worker_id = text;
        note.want_publish = true;
        const SwarmNotContribResult noted = SwarmNoteNotContrib(note, err);
        if (noted.published || noted.accepted || noted.count != static_cast<int64_t>(0)) {
            err = "OPTOUT";
            return false;
        }
        m_published = noted.published;
        err = "OPTOUT";
        return false;
    }
    SwarmNotContrib note;
    note.worker_id = text;
    note.want_publish = false;
    const SwarmNotContribResult noted = SwarmNoteNotContrib(note, err);
    if (!err.empty() || noted.published || noted.accepted || noted.code != "NOTED") return false;
    m_published = false;
    err.clear();
    return true;
}

bool Acc05::Hire001(const std::string& text, std::string& err)
{
    std::string pinned;
    if (!FullFingerprint(text, pinned)) {
        err = "FINGERPRINT";
        return false;
    }
    if (m_fingerprint_set && m_fingerprint == pinned) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (m_fingerprint_set) {
        err = "UNCHANGED";
        return false;
    }
    m_fingerprint = pinned;
    m_fingerprint_set = true;
    err.clear();
    return true;
}

bool Acc05::Auth001(const std::string& text, const std::string& extra, bool flag, std::string& err)
{
    if (text.empty()) {
        err = "ASSET";
        return false;
    }
    if (extra.empty()) {
        err = "MANDATE";
        return false;
    }
    SwarmNotMandate note;
    note.mandate_id = extra;
    note.operator_signed = flag;
    note.want_spend = true;
    const SwarmNotMandateResult noted = SwarmNoteNotMandate(note, err);
    if (noted.spent || noted.broadcast) {
        err = "SPEND";
        return false;
    }
    if (!flag) {
        err = "UNSIGNED";
        return false;
    }
    if (noted.code != "HELD") {
        err = "MANDATE";
        return false;
    }
    return m_auth.Apply("DS-AUTH-001", "", text, extra, static_cast<int64_t>(0), static_cast<int64_t>(0), flag, err);
}

bool Acc05::Auth003(const std::string& text, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (flag || now_ms < static_cast<int64_t>(0)) {
        err = "UNCERTAIN";
        return false;
    }
    if (now_ms >= aux) {
        err = "EXPIRED";
        return false;
    }
    if (m_lease_set && m_lease_text == text && m_lease_aux == aux) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (m_lease_set) {
        err = "UNCHANGED";
        return false;
    }
    m_lease_text = text;
    m_lease_aux = aux;
    m_lease_set = true;
    err.clear();
    return true;
}

bool Acc05::Auth004(const std::string& op, const std::string& text, const std::string& extra, std::string& err)
{
    if (!m_sev_set) {
        if (text.empty() || extra.empty()) {
            err = "SCOPE";
            return false;
        }
        m_severity = text;
        m_scope = extra;
        m_sev_set = true;
        err.clear();
        return true;
    }
    if (op == "severity") {
        if (extra != m_scope) {
            err = "UNCHANGED";
            return false;
        }
        if (text == m_severity) {
            err = NIFDT_REPLAY;
            return false;
        }
        m_severity = text;
        err.clear();
        return true;
    }
    err = "UNCHANGED";
    return false;
}

bool Acc05::Auth005(const std::string& text, std::string& err)
{
    if (!SamePurpose(text)) {
        err = "PURPOSE";
        return false;
    }
    bool* slot = nullptr;
    if (text == "read") slot = &m_grant_read;
    else if (text == "effect") slot = &m_grant_effect;
    else if (text == "release") slot = &m_grant_release;
    else slot = &m_grant_spend;
    if (*slot) {
        err = NIFDT_REPLAY;
        return false;
    }
    *slot = true;
    if (ResearchMaySpend()) {
        *slot = false;
        err = "SPEND";
        return false;
    }
    err.clear();
    return true;
}

bool Acc05::Auth006(const std::string& op, const std::string& text, const std::string& extra, int64_t now_ms, std::string& err)
{
    if (op == "prepare") {
        if (m_revoked) {
            err = NIFDT_REVOKED;
            return false;
        }
        if (text.empty() || extra.empty()) {
            err = "PERMIT";
            return false;
        }
        ActionPermit permit;
        permit.permit_id = extra;
        permit.grant_id = "customer";
        permit.generation = 1;
        permit.effect = text;
        permit.not_after_ms = now_ms + static_cast<int64_t>(1000);
        permit.parameter_fingerprint = "bound";
        return m_gate.Issue(permit, err);
    }
    if (op == "revoke") {
        m_gate.Revoke();
        m_revoked = true;
        err = NIFDT_REVOKED;
        return false;
    }
    if (op == "run") {
        if (!m_gate.Consume(extra, text, static_cast<uint64_t>(1), now_ms, "bound", err)) {
            if (err == "BTX035_REVOKED") err = NIFDT_REVOKED;
            return false;
        }
        err.clear();
        return true;
    }
    err = "PERMIT";
    return false;
}

bool Acc05::Data001(const std::string& text, const std::string& extra, std::string& err)
{
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (extra.empty()) {
        err = "PROVENANCE";
        return false;
    }
    if (!m_bytes_set) {
        m_bytes = text;
        m_prov = extra;
        m_bytes_set = true;
        err.clear();
        return true;
    }
    if (text != m_bytes) {
        err = "PROVENANCE";
        return false;
    }
    if (extra == m_prov) {
        err = NIFDT_REPLAY;
        return false;
    }
    for (const std::string& line : m_prov_more) {
        if (line == extra) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    m_prov_more.push_back(extra);
    err.clear();
    return true;
}

bool Acc05::Data003(const std::string& text, const std::string& extra, int64_t now_ms, int64_t aux, std::string& err)
{
    if (text.empty() || extra.empty() || now_ms < static_cast<int64_t>(0) || now_ms > static_cast<int64_t>(1000) ||
        aux < static_cast<int64_t>(1) || aux > static_cast<int64_t>(1000)) {
        err = "BOUND";
        return false;
    }
    if (m_query_set && m_asset == text && m_purpose == extra && m_query_time == now_ms && m_query_bytes == aux) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (m_query_set) {
        err = "UNCHANGED";
        return false;
    }
    m_asset = text;
    m_purpose = extra;
    m_query_time = now_ms;
    m_query_bytes = aux;
    m_query_set = true;
    err.clear();
    return true;
}

bool Acc05::Data004(const std::string& op, const std::string& text, const std::string& extra, std::string& err)
{
    if (op == "local") {
        if (text.empty()) {
            err = "FIELD";
            return false;
        }
        if (m_local_set && m_local == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (m_local_set) {
            err = "UNCHANGED";
            return false;
        }
        m_local = text;
        m_local_set = true;
        err.clear();
        return true;
    }
    if (op == "grant") {
        if (extra.empty()) {
            err = NIFDT_PRIVATE_DATA;
            return false;
        }
        if (m_grant_set && m_grant == extra) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (m_grant_set) {
            err = "UNCHANGED";
            return false;
        }
        m_grant = extra;
        m_grant_set = true;
        err.clear();
        return true;
    }
    if (op == "export") {
        if (!m_local_set || extra.empty() || extra != m_grant) {
            err = NIFDT_PRIVATE_DATA;
            return false;
        }
        if (m_did_export) {
            err = NIFDT_REPLAY;
            return false;
        }
        m_exported = m_local;
        m_did_export = true;
        err.clear();
        return true;
    }
    err = NIFDT_PRIVATE_DATA;
    return false;
}

bool Acc05::Data006(const std::string& op, const std::string& text, std::string& err)
{
    if (op == "status") {
        if (!m_gap_clock || !m_gap_loss || !m_gap_duplicate || !m_gap_missing) {
            err = "GAP";
            return false;
        }
        err.clear();
        return true;
    }
    bool* slot = nullptr;
    if (text == "clock") slot = &m_gap_clock;
    else if (text == "loss") slot = &m_gap_loss;
    else if (text == "duplicate") slot = &m_gap_duplicate;
    else if (text == "missing") slot = &m_gap_missing;
    else {
        err = "GAP";
        return false;
    }
    if (*slot) {
        err = NIFDT_REPLAY;
        return false;
    }
    *slot = true;
    err.clear();
    return true;
}

bool Acc05::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    static const char* const kJournal[] = {
        "WAN-002", "WAN-003", "WAN-004", "WAN-005", "ENT-001", "ENT-002", "ENT-003",
        "ECON-001", "ECON-002", "STORE-001", "STORE-002", "STORE-003",
        "API-001", "API-002", "API-003", "API-004",
    };
    bool known = false;
    for (const char* row : kJournal) {
        if (id == row) {
            known = true;
            break;
        }
    }
    if (!known) {
        err = "ID";
        return false;
    }
    if (text.empty()) {
        err = "FIELD";
        return false;
    }
    if (aux < 0) {
        err = "BOUND";
        return false;
    }
    if (aux > 100) {
        err = "CAP";
        return false;
    }
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    static const char* const kAbsent[] = {
        "fp8", "fp4", "dualpipe", "vllm", "sglang", "lmcache", "nixl", "mooncake", "rdma", "deepinfer",
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
    const bool refused =
        (id == "WAN-002" && text == "other-state") ||
        (id == "WAN-003" && text == "mixed") ||
        (id == "WAN-005" && text == "symlink") ||
        (id == "ENT-001" && text == "rpc") ||
        (id == "ENT-003" && text == "endorse") ||
        (id == "ECON-001" && text == "spend") ||
        (id == "STORE-002" && text == "retry") ||
        (id == "STORE-003" && text == "skip-sig") ||
        (id == "API-001" && text == "s1") ||
        (id == "API-003" && text == "other") ||
        (id == "API-004" && text == "trusted");
    if (refused) {
        if (id == "WAN-002") err = "STATE";
        else if (id == "WAN-003") err = "GENERATION";
        else if (id == "WAN-005") err = "TAR";
        else if (id == "ENT-001") err = "ROUTE";
        else if (id == "ENT-003") err = "REVIEW";
        else if (id == "ECON-001") err = "WALLET";
        else if (id == "STORE-002") err = "UNKNOWN";
        else if (id == "STORE-003") err = "LIMIT";
        else if (id == "API-001") err = "IDEMPOTENT";
        else if (id == "API-003") err = "CLI";
        else err = "BADGE";
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

bool Acc05::Apply(const std::string& id, const std::string& op, const std::string& text,
                  const std::string& extra, int64_t now_ms, int64_t aux, bool flag, std::string& err)
{
    if (!Owned(id)) {
        err = "ID";
        return false;
    }
    if (id == "DS-NAT-001" || id == "DS-NAT-002" || id == "DS-NAT-004") {
        if (id == "DS-NAT-002" && op != "drop" && text.empty()) {
            err = "SOURCE";
            return false;
        }
        return m_nat.Apply(id, op, text, extra, now_ms, aux, flag, err);
    }
    if (id == "DS-NAT-003") return Nat003(op, text, flag, err);
    if (id == "DS-NAT-005") return Nat005(op, text, extra, flag, err);
    if (id == "DS-NAT-006") return Nat006(text, flag, err);
    if (id == "DS-HIRE-001") return Hire001(text, err);
    if (id == "DS-HIRE-002" || id == "DS-HIRE-004" || id == "DS-HIRE-005") {
        return m_family.Apply(id, op, text, extra, now_ms, aux, flag, err);
    }
    if (id == "DS-HIRE-003" || id == "DS-HIRE-006") {
        std::string local;
        m_family.Apply(id, op, text, extra, now_ms, aux, false, local);
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (id == "DS-AUTH-001") return Auth001(text, extra, flag, err);
    if (id == "DS-AUTH-002") {
        return m_auth.Apply(id, op, text, extra, now_ms, aux, flag, err);
    }
    if (id == "DS-AUTH-003") return Auth003(text, now_ms, aux, flag, err);
    if (id == "DS-AUTH-004") return Auth004(op, text, extra, err);
    if (id == "DS-AUTH-005") return Auth005(text, err);
    if (id == "DS-AUTH-006") return Auth006(op, text, extra, now_ms, err);
    if (id == "DS-DATA-001") return Data001(text, extra, err);
    if (id == "DS-DATA-002") return m_auth.Apply(id, op, text, extra, now_ms, aux, flag, err);
    if (id == "DS-DATA-003") return Data003(text, extra, now_ms, aux, err);
    if (id == "DS-DATA-004") return Data004(op, text, extra, err);
    if (id == "DS-DATA-005") return m_hire.Apply(id, op, text, extra, now_ms, aux, flag, err);
    if (id == "DS-DATA-006") return Data006(op, text, err);
    err = "ID";
    return false;
}

bool Acc05::Pass(std::string& err)
{
    if (passed() || gpu_passed() || windows_passed() || release_qualified() || hardware_qualified() || qualified()) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    if (hosts() != static_cast<int64_t>(1) || physical_hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    if (automatic_spend() != NIFDT_AUTOMATIC_SPEND || bytes_moved() != static_cast<int64_t>(0) ||
        atoms_moved() != static_cast<int64_t>(0)) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    err.clear();
    return true;
}

bool Acc05::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc05::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc05::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc05::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc05::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet
