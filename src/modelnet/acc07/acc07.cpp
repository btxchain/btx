// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/acc07/acc07.h>

#include <modelnet/dt_ckpt/codes.h>
#include <modelnet/dt_ckpt/dt_ckpt.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_defbudget/codes.h>
#include <modelnet/swarm_defbudget/limits.h>
#include <modelnet/swarm_generation/codes.h>
#include <modelnet/swarm_generation/generation.h>
#include <modelnet/swarm_notnopoison.h>
#include <modelnet/swarm_payreg/codes.h>
#include <modelnet/swarm_tenantlook.h>
#include <modelnet/training_integer.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

const char* kPayChannel = "case-channel";
const char* kPayIncident = "incident-pool";
const char* kPayReadiness = "readiness-pool";
const char* kOracleTrust = "ORACLE_NOT_SETTLEMENT";

bool AxisName(const std::string& axis)
{
    return axis == "time" || axis == "campaign" || axis == "tenant" || axis == "lineage";
}

} // namespace

const Acc07::KvRow* Acc07::FindKv(const std::string& tenant, const std::string& key) const
{
    for (const KvRow& row : m_kv) {
        if (row.tenant == tenant && row.key == key) return &row;
    }
    return nullptr;
}

bool Acc07::EnsurePay(std::string& err)
{
    if (m_pay_open) {
        err.clear();
        return true;
    }
    if (!m_pay.Open(kPayChannel, kPayIncident, kPayReadiness, err)) return false;
    m_pay_open = true;
    err.clear();
    return true;
}

bool Acc07::PutIncidentKv(const std::string& tenant, int64_t epoch, const std::string& key, const std::string& value,
                          bool authorized, std::string& err)
{
    if (epoch < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    if (key.empty()) {
        err = "FIELD";
        return false;
    }
    SwarmTenantLook look;
    look.tenant_id = tenant;
    look.caller_id = tenant;
    look.revoked = !authorized;
    look.want_read = false;
    const SwarmTenantLookResult gate = SwarmLookupTenantAccess(look, err);
    if (gate.code != "NOTED" || gate.allowed || gate.bytes_moved) return false;
    if (const KvRow* existing = FindKv(tenant, key)) {
        if (existing->epoch == epoch && existing->value == value) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    KvRow row;
    row.tenant = tenant;
    row.epoch = epoch;
    row.key = key;
    row.value = value;
    m_kv.push_back(std::move(row));
    err.clear();
    return true;
}

bool Acc07::ReadIncidentKv(const std::string& tenant, int64_t epoch, const std::string& caller, const std::string& key,
                           std::string& value, std::string& err)
{
    value.clear();
    if (epoch < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    SwarmTenantLook look;
    look.tenant_id = tenant;
    look.caller_id = caller;
    look.revoked = false;
    look.want_read = false;
    const SwarmTenantLookResult gate = SwarmLookupTenantAccess(look, err);
    if (gate.code != "NOTED" || gate.allowed || gate.bytes_moved) {
        value.clear();
        return false;
    }
    const KvRow* row = FindKv(tenant, key);
    if (row == nullptr) {
        err = "SCOPE";
        return false;
    }
    if (row->epoch != epoch) {
        err = "EPOCH";
        value.clear();
        return false;
    }
    value = row->value;
    err.clear();
    return true;
}

bool Acc07::ApprovePublic(const std::string& id, const std::string& author, const std::string& approver,
                          const std::string& body, const std::string& origin_case, std::string& err)
{
    if (body.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (id.empty() || author.empty() || approver.empty() || body.empty() || origin_case.empty() || author == approver) {
        err = "APPROVAL";
        return false;
    }
    for (const CtxRow& row : m_ctx) {
        if (row.id != id) continue;
        err = NIFDT_REPLAY;
        return false;
    }
    CtxRow row;
    row.id = id;
    row.author = author;
    row.approver = approver;
    row.body = body;
    row.origin = origin_case;
    m_ctx.push_back(std::move(row));
    err.clear();
    return true;
}

bool Acc07::ReusePublic(const std::string& id, const std::string& dest_case, std::string& err)
{
    if (dest_case.empty()) {
        err = "APPROVAL";
        return false;
    }
    for (const CtxRow& row : m_ctx) {
        if (row.id != id) continue;
        if (dest_case == row.origin) {
            err = "APPROVAL";
            return false;
        }
        if (row.body.find("private") != std::string::npos) {
            err = NIFDT_PRIVATE_DATA;
            return false;
        }
        err.clear();
        return true;
    }
    err = "APPROVAL";
    return false;
}

bool Acc07::MeasureCache(const std::vector<unsigned char>& src, std::vector<unsigned char>& dst, int64_t& measured,
                         std::string& err)
{
    measured = 0;
    dst.clear();
    if (src.empty()) {
        err = "PARTIAL";
        return false;
    }
    dst.assign(src.begin(), src.end());
    if (dst != src) {
        dst.clear();
        err = "PARTIAL";
        return false;
    }
    measured = static_cast<int64_t>(dst.size());
    m_measured = measured;
    err.clear();
    return true;
}

bool Acc07::CompleteCheckpoint(const std::vector<unsigned char>& weights, const std::vector<unsigned char>& adam_m,
                               const std::vector<unsigned char>& adam_v, std::string& err)
{
    if (weights.empty()) {
        err = kDtCkptWeights;
        return false;
    }
    DtCkpt::State state;
    state.weights = weights;
    state.adam_m = adam_m;
    state.adam_v = adam_v;
    state.step = 1;
    state.rng = 1;
    state.cursor = 1;
    state.recipe_id = "recipe";
    state.topology_id = "topo";
    state.cohort_epoch = 1;
    DtCkpt ckpt;
    if (!ckpt.Save(state, err)) return false;
    if (adam_m.empty() || adam_v.empty()) {
        if (ckpt.exact_resume() || ckpt.Promote(err) || err != kDtCkptPartial) {
            err = kDtCkptPartial;
            return false;
        }
        return false;
    }
    if (!ckpt.Resume(err)) return false;
    if (!ckpt.Promote(err)) return false;
    if (!ckpt.Restore(err)) return false;
    if (!ckpt.exact_resume() || !ckpt.promoted() || !(ckpt.live() == state) || ckpt.bytes_moved() != 0) {
        err = kDtCkptPartial;
        return false;
    }
    m_checkpoint = ckpt.live().weights;
    m_checkpoint_exact = true;
    err.clear();
    return true;
}

bool Acc07::OpenIncident(const std::string& incident, const std::string& generation, std::string& err)
{
    if (incident.empty() || generation.empty()) {
        err = "PIN";
        return false;
    }
    const auto it = m_pins.find(incident);
    if (it != m_pins.end() && it->second.active) {
        err = it->second.generation == generation ? NIFDT_REPLAY : "PIN";
        return false;
    }
    PinRow row;
    row.generation = generation;
    row.active = true;
    m_pins[incident] = std::move(row);
    err.clear();
    return true;
}

bool Acc07::SwapGeneration(const std::string& incident, const std::string& generation, std::string& err)
{
    const auto it = m_pins.find(incident);
    if (it == m_pins.end() || !it->second.active) {
        err = "PIN";
        return false;
    }
    if (generation != it->second.generation) {
        err = "PIN";
        return false;
    }
    err = NIFDT_REPLAY;
    return false;
}

bool Acc07::CloseIncident(const std::string& incident, std::string& err)
{
    const auto it = m_pins.find(incident);
    if (it == m_pins.end() || !it->second.active) {
        err = "PIN";
        return false;
    }
    it->second.active = false;
    err.clear();
    return true;
}

std::string Acc07::generation_of(const std::string& incident) const
{
    const auto it = m_pins.find(incident);
    if (it == m_pins.end()) return {};
    return it->second.generation;
}

bool Acc07::incident_active(const std::string& incident) const
{
    const auto it = m_pins.find(incident);
    return it != m_pins.end() && it->second.active;
}

bool Acc07::RestrictPlacement(const std::string& location, const std::string& processor, std::string& err)
{
    if (location.empty()) {
        err = "LOCATION";
        return false;
    }
    if (processor.empty()) {
        err = "PROCESSOR";
        return false;
    }
    if (m_restricted) {
        err = (location == m_location && processor == m_processor) ? NIFDT_REPLAY : "UNCHANGED";
        return false;
    }
    m_location = location;
    m_processor = processor;
    m_restricted = true;
    err.clear();
    return true;
}

bool Acc07::Place(const std::string& location, const std::string& processor, std::string& err)
{
    if (!m_restricted) {
        err = "ORDER";
        return false;
    }
    if (location != m_location) {
        err = "LOCATION";
        return false;
    }
    if (processor != m_processor) {
        err = "PROCESSOR";
        return false;
    }
    err.clear();
    return true;
}

bool Acc07::GrantCapability(std::string& err)
{
    if (m_withdrawn) {
        err = NIFDT_REVOKED;
        return false;
    }
    m_capability = true;
    err.clear();
    return true;
}

bool Acc07::PoisonCache(const std::string& sample, std::string& err)
{
    SwarmNotNoPoison note;
    note.sample_id = sample;
    note.poisoned = true;
    note.want_publish = false;
    const SwarmNotNoPoisonResult result = SwarmNoteNotNoPoison(note, err);
    if (result.published || result.trained || result.code != "FROZEN") {
        err = result.code.empty() ? std::string("POISON") : result.code;
        return false;
    }
    m_withdrawn = true;
    m_capability = false;
    err.clear();
    return true;
}

bool Acc07::FailRuntimeQualification(std::string& err)
{
    m_withdrawn = true;
    m_capability = false;
    err.clear();
    return true;
}

bool Acc07::UseCapability(std::string& err)
{
    if (m_withdrawn || !m_capability) {
        err = NIFDT_REVOKED;
        return false;
    }
    err.clear();
    return true;
}

bool Acc07::IssueLearningRelease(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc07::AssignHoldout(const std::string& sample, const std::string& axis, const std::string& lineage, std::string& err)
{
    if (sample.empty() || lineage.empty() || !AxisName(axis)) {
        err = "HOLDOUT";
        return false;
    }
    const auto sample_it = m_sample_axis.find(sample);
    if (sample_it != m_sample_axis.end()) {
        err = sample_it->second == axis ? NIFDT_REPLAY : "HOLDOUT";
        return false;
    }
    const auto lineage_it = m_lineage_axis.find(lineage);
    if (lineage_it != m_lineage_axis.end() && lineage_it->second != axis) {
        err = "HOLDOUT";
        return false;
    }
    m_sample_axis.emplace(sample, axis);
    m_lineage_axis[lineage] = axis;
    if (axis == "time") ++m_axis_time;
    else if (axis == "campaign") ++m_axis_campaign;
    else if (axis == "tenant") ++m_axis_tenant;
    else ++m_axis_lineage;
    err.clear();
    return true;
}

bool Acc07::holdouts_separated() const
{
    return m_axis_time > 0 && m_axis_campaign > 0 && m_axis_tenant > 0 && m_axis_lineage > 0;
}

bool Acc07::PreserveCase(const std::string& kind, const std::string& provenance, const std::string& license, std::string& err)
{
    if (kind != "synthetic" && kind != "public") {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (provenance.empty() || provenance.find("private") != std::string::npos) {
        err = provenance.empty() ? "PROVENANCE" : NIFDT_PRIVATE_DATA;
        return false;
    }
    SwarmGenerationEngine eng;
    if (!eng.Eligible(!license.empty() && license.find("private") == std::string::npos, true, err)) return false;
    if (!eng.eligible() || eng.gpu() || eng.launched()) {
        err = kSwarmGenerationLicense;
        return false;
    }
    for (const CaseRow& row : m_cases) {
        if (row.kind == kind) {
            err = NIFDT_REPLAY;
            return false;
        }
    }
    CaseRow row;
    row.kind = kind;
    row.provenance = provenance;
    row.license = license;
    m_cases.push_back(std::move(row));
    err.clear();
    return true;
}

std::string Acc07::provenance_of(const std::string& kind) const
{
    for (const CaseRow& row : m_cases) {
        if (row.kind == kind) return row.provenance;
    }
    return {};
}

std::string Acc07::license_of(const std::string& kind) const
{
    for (const CaseRow& row : m_cases) {
        if (row.kind == kind) return row.license;
    }
    return {};
}

bool Acc07::JointDecision(bool utility_ok, bool harm_ok, bool refusal_only, std::string& err)
{
    if (refusal_only || !harm_ok) {
        err = "HARM";
        return false;
    }
    if (!utility_ok) {
        err = "UTILITY";
        return false;
    }
    m_joint = true;
    err.clear();
    return true;
}

bool Acc07::TrainCompeting(std::string& err)
{
    IntegerTrainer parent;
    if (!parent.Run(1, err)) return false;
    IntegerTrainer left;
    if (!left.Resume(parent.State(), err)) return false;
    if (!left.Step(err)) return false;
    IntegerTrainer right;
    if (!right.Resume(parent.State(), err)) return false;
    if (!right.Run(2, err)) return false;
    const std::string parent_hash = parent.State().state_hash;
    const std::string left_hash = left.State().state_hash;
    const std::string right_hash = right.State().state_hash;
    if (parent_hash.empty() || left_hash.empty() || right_hash.empty() || parent_hash == left_hash ||
        parent_hash == right_hash || left_hash == right_hash || left.State().step <= parent.State().step ||
        right.State().step <= parent.State().step) {
        err = "SELF";
        return false;
    }
    m_parent_hash = parent_hash;
    m_left_hash = left_hash;
    m_right_hash = right_hash;
    err.clear();
    return true;
}

bool Acc07::EvaluateDescendant(const std::string& evaluator, bool author_is_evaluator, std::string& err)
{
    if (m_left_hash.empty()) {
        err = "TRAIN";
        return false;
    }
    const std::string author = "author";
    const std::string who = author_is_evaluator ? author : evaluator;
    if (who.empty()) {
        err = kSwarmGenerationSelf;
        return false;
    }
    SwarmGenerationEngine eng;
    const bool ok = eng.Evaluate(m_left_hash, author, who, "lab", author_is_evaluator ? "lab" : "audit", false, false, false, err);
    if (author_is_evaluator) {
        if (ok || err != kSwarmGenerationSelf) {
            err = kSwarmGenerationSelf;
            return false;
        }
        return false;
    }
    if (!ok || eng.gpu() || eng.qualified(m_left_hash)) return false;
    err.clear();
    return true;
}

bool Acc07::SecondResearchCycle(std::string& err)
{
    SwarmGenerationEngine eng;
    std::string inner;
    const bool advanced = eng.Continue(inner);
    m_cycle = eng.cycle();
    if (advanced || m_cycle != 0 || eng.gpu() || eng.launched() || eng.bytes_moved() != 0) {
        err = "CYCLE";
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc07::FundPool(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err)
{
    return m_budget.Fund(pool, outpoint, atoms, err);
}

bool Acc07::JoinPool(const std::string& pool, const std::string& member, std::string& err)
{
    const int64_t before = m_budget.earned_count();
    const bool paid = m_budget.Join(pool, member, err);
    if (paid || m_budget.earned_count() != before) {
        err = kSwarmDefBudgetNotPaid;
        return false;
    }
    return false;
}

bool Acc07::EarnWork(const std::string& pool, const std::string& work_id, const std::string& receipt, const std::string& member,
                     int64_t atoms, std::string& err)
{
    return m_budget.Earn(pool, work_id, receipt, member, atoms, err);
}

bool Acc07::PayMilestone(const std::string& pool, const std::string& work_id, int64_t requested, int64_t cap, std::string& err)
{
    return m_budget.Milestone(pool, work_id, requested, cap, err);
}

bool Acc07::SetPayer(const std::string& payer, std::string& err)
{
    return m_budget.SetPayer(payer, err);
}

bool Acc07::SelfDeal(const std::string& member, std::string& err)
{
    const int64_t before = m_budget.earned_count();
    const bool ok = m_budget.SelfDeal(member, err);
    if (m_budget.earned_count() != before) {
        err = kSwarmDefBudgetSelf;
        return false;
    }
    return ok;
}

bool Acc07::RaiseForUrgent(const std::string& pool, std::string& err)
{
    const int64_t earned_before = m_budget.earned_atoms(pool);
    const int64_t balance_before = m_budget.balance(pool);
    if (m_budget.earned_atoms(pool) != earned_before || m_budget.balance(pool) != balance_before) {
        err = "RATE";
        return false;
    }
    err = "RATE";
    return false;
}

int64_t Acc07::pool_balance(const std::string& pool) const
{
    return m_budget.balance(pool);
}

bool Acc07::member_of(const std::string& pool, const std::string& member) const
{
    return m_budget.member_of(pool, member);
}

bool Acc07::earned(const std::string& work_id) const
{
    return m_budget.earned(work_id);
}

int64_t Acc07::earned_atoms(const std::string& pool) const
{
    return m_budget.earned_atoms(pool);
}

int64_t Acc07::earned_count() const
{
    return m_budget.earned_count();
}

bool Acc07::ReconcileAtoms(int64_t confirmed, int64_t fee, int64_t settled, int64_t earned_unpaid, int64_t reserved_new,
                           std::string& err)
{
    if (confirmed < 0 || fee < 0 || settled < 0 || earned_unpaid < 0 || reserved_new < 0) {
        err = "BALANCE";
        return false;
    }
    int64_t left = confirmed;
    const int64_t parts[] = {fee, settled, earned_unpaid, reserved_new};
    for (const int64_t part : parts) {
        if (part > left) {
            err = "BALANCE";
            return false;
        }
        left -= part;
    }
    m_available = left;
    err.clear();
    return true;
}

bool Acc07::AllocateMilestones(int64_t pool, const std::vector<Acc07Weight>& rows, std::vector<int64_t>& paid,
                               int64_t& unallocated, std::string& err)
{
    paid.clear();
    unallocated = 0;
    if (pool < static_cast<int64_t>(0)) {
        err = "CAP";
        return false;
    }
    if (rows.empty()) {
        unallocated = pool;
        err.clear();
        return true;
    }
    int64_t sum_w = 0;
    std::set<std::string> seen;
    for (const Acc07Weight& row : rows) {
        if (row.contract.empty()) {
            err = "FIELD";
            return false;
        }
        if (!seen.insert(row.contract).second) {
            err = NIFDT_REPLAY;
            return false;
        }
        if (row.weight < static_cast<int64_t>(0) || row.cap < static_cast<int64_t>(0)) {
            err = "CAP";
            return false;
        }
        if (row.weight > static_cast<int64_t>(1000000) || row.cap > static_cast<int64_t>(1000000) ||
            pool > static_cast<int64_t>(1000000)) {
            err = "CAP";
            return false;
        }
        if (sum_w > std::numeric_limits<int64_t>::max() - row.weight) {
            err = "CAP";
            return false;
        }
        sum_w += row.weight;
    }
    paid.assign(rows.size(), static_cast<int64_t>(0));
    if (sum_w == static_cast<int64_t>(0) || pool == static_cast<int64_t>(0)) {
        unallocated = pool;
        err.clear();
        return true;
    }
    std::vector<int64_t> frac(rows.size(), static_cast<int64_t>(0));
    int64_t placed = 0;
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const int64_t raw = (pool * rows[i].weight) / sum_w;
        paid[i] = raw > rows[i].cap ? rows[i].cap : raw;
        frac[i] = (pool * rows[i].weight) % sum_w;
        placed += paid[i];
    }
    int64_t left = pool - placed;
    std::vector<std::size_t> order(rows.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
        if (frac[a] != frac[b]) return frac[a] > frac[b];
        return a < b;
    });
    bool moved = true;
    while (left > static_cast<int64_t>(0) && moved) {
        moved = false;
        for (const std::size_t i : order) {
            if (left == static_cast<int64_t>(0)) break;
            if (paid[i] >= rows[i].cap) continue;
            ++paid[i];
            --left;
            moved = true;
        }
    }
    int64_t check = left;
    for (const int64_t atoms : paid) {
        if (check > std::numeric_limits<int64_t>::max() - atoms) {
            err = "CAP";
            paid.clear();
            unallocated = 0;
            return false;
        }
        check += atoms;
    }
    if (check != pool) {
        err = "CAP";
        paid.clear();
        unallocated = 0;
        return false;
    }
    unallocated = left;
    err.clear();
    return true;
}

bool Acc07::DisclosePayment(Acc07Disclosure& out, std::string& err)
{
    SwarmPayReg reg;
    out.mode = reg.Mode();
    out.enforceable = reg.qualified() && reg.spendable();
    out.spendable = reg.spendable();
    out.oracle_trust = kOracleTrust;
    if (out.mode != kSwarmPayRegMode || out.enforceable || out.spendable || out.oracle_trust != kOracleTrust ||
        reg.broadcast() || reg.mainnet() || reg.atoms_moved() != 0) {
        err = "MODE";
        out = Acc07Disclosure{};
        return false;
    }
    err.clear();
    return true;
}

bool Acc07::QualifyNativeFunding(std::string& err)
{
    SwarmPayReg reg;
    if (!reg.Open(kPayChannel, kPayIncident, kPayReadiness, err)) return false;
    std::string settle_err;
    if (reg.Settle(settle_err) || settle_err != kSwarmPayRegUnqualified || reg.qualified() || reg.spendable() ||
        reg.broadcast() || reg.atoms_moved() != 0) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc07::ProvePaymentPaths(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc07::ReserveBacking(const std::string& pool, const std::string& outpoint, int64_t atoms, std::string& err)
{
    if (!EnsurePay(err)) return false;
    return m_pay.Reserve(pool, outpoint, atoms, err);
}

bool Acc07::NoteCredit(const std::string& pool, int64_t atoms, std::string& err)
{
    if (!EnsurePay(err)) return false;
    const int64_t before = m_pay.funded_balance(pool);
    const bool backed = m_pay.Credit(pool, atoms, err);
    if (backed || err != kSwarmPayRegNotBacking || m_pay.funded_balance(pool) != before) {
        err = kSwarmPayRegNotBacking;
        return false;
    }
    return false;
}

bool Acc07::RouteTerms(const std::string& route, int64_t atoms, int64_t timeout, std::string& err)
{
    if (!EnsurePay(err)) return false;
    const int64_t incident_before = m_pay.funded_balance(kPayIncident);
    const int64_t credit_before = m_pay.credit_note(kPayIncident);
    if (!m_pay.Terms(route, atoms, timeout, err)) return false;
    if (m_pay.funded_balance(kPayIncident) != incident_before || m_pay.credit_note(kPayIncident) != credit_before) {
        err = "TERMS";
        return false;
    }
    return true;
}

int64_t Acc07::funded_backing(const std::string& pool) const
{
    return m_pay.funded_balance(pool);
}

int64_t Acc07::credit_note(const std::string& pool) const
{
    return m_pay.credit_note(pool);
}

int64_t Acc07::route_atoms(const std::string& route) const
{
    return m_pay.terms_atoms(route);
}

bool Acc07::PromiseEmergency(int64_t atoms, std::string& err)
{
    if (atoms < static_cast<int64_t>(1)) {
        err = "LIQUIDITY";
        return false;
    }
    const int64_t funded = m_budget.balance(kSwarmDefBudgetPoolReadiness);
    if (funded < atoms) {
        err = "LIQUIDITY";
        return false;
    }
    m_emergency = atoms;
    err.clear();
    return true;
}

bool Acc07::NotePending(const std::string& work_id, std::string& err)
{
    if (work_id.empty()) {
        err = kSwarmPayRegClaim;
        return false;
    }
    if (m_pay.claim_kept(work_id)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_pending.insert(work_id);
    err.clear();
    return true;
}

bool Acc07::KeepClaim(const std::string& work_id, std::string& err)
{
    if (!m_pay.Claim(work_id, err)) return false;
    m_pending.erase(work_id);
    return true;
}

void Acc07::FailCompute()
{
    m_pay.FailCompute();
}

bool Acc07::Reorganize(std::string& err)
{
    m_pending.clear();
    err.clear();
    return true;
}

bool Acc07::pending(const std::string& work_id) const
{
    return m_pending.find(work_id) != m_pending.end();
}

bool Acc07::claim_kept(const std::string& work_id) const
{
    return m_pay.claim_kept(work_id);
}

bool Acc07::compute_failed() const
{
    return m_pay.compute_failed();
}

std::string Acc07::classification() const
{
    return "SIMULATION_NOT_HARDWARE_MEASUREMENT";
}

bool Acc07::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool Acc07::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Acc07::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc07::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Acc07::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Acc07::Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err)
{
    static const char* const kIds[] = {
        "E2E-006", "QA-001", "QA-002", "QA-003",
        "REV-001", "REV-002", "REV-003", "REV-004", "REV-005", "REV-006", "REV-007",
        "REV-008", "REV-009", "REV-010", "REV-011", "REV-012", "REV-013", "REV-014",
        "REV-015", "REV-016",
    };
    bool known = false;
    for (const char* row : kIds) {
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
    if (!flag) {
        err = "ABSENT";
        return false;
    }
    if (id == "REV-016") {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    const bool refused =
        (id == "E2E-006" && text == "backup") ||
        (id == "QA-001" && text == "skip") ||
        (id == "QA-002" && text == "native") ||
        (id == "QA-003" && text == "growth") ||
        (id == "REV-001" && text == "1.0.0") ||
        (id == "REV-002" && text == "signed-release") ||
        (id == "REV-004" && text == "cycle") ||
        (id == "REV-005" && text == "empty-keys") ||
        (id == "REV-008" && text == "early") ||
        (id == "REV-009" && text == "shell") ||
        (id == "REV-010" && text == "default") ||
        (id == "REV-011" && text == "weaker") ||
        (id == "REV-013" && text == "late") ||
        (id == "REV-014" && text == "shared") ||
        (id == "REV-015" && text == "score");
    if (refused) {
        if (id == "E2E-006") err = "ROLLBACK";
        else if (id == "QA-001") err = "FAIL";
        else if (id == "QA-002") err = "PACKAGE";
        else if (id == "QA-003") err = "CLAIM";
        else if (id == "REV-001") err = "REVISION";
        else if (id == "REV-002") err = "UNSIGNED";
        else if (id == "REV-004") err = "CYCLE";
        else if (id == "REV-005") err = "PENDING";
        else if (id == "REV-008") err = "BATCH";
        else if (id == "REV-009") err = "ACTION";
        else if (id == "REV-010") err = "PROFILE";
        else if (id == "REV-011") err = "STRICT";
        else if (id == "REV-013") err = "PLAN";
        else if (id == "REV-014") err = "TOKEN";
        else err = "BINDING";
        return false;
    }
    m_journal[id] = text;
    err.clear();
    return true;
}

bool Acc07::stored(const std::string& id) const
{
    return m_journal.find(id) != m_journal.end();
}

std::string Acc07::text(const std::string& id) const
{
    const auto found = m_journal.find(id);
    return found == m_journal.end() ? std::string() : found->second;
}

} // namespace modelnet
