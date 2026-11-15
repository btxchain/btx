// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mandate.h>

#include <univalue.h>

#include <charconv>
#include <fstream>
#include <iterator>
#include <limits>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

constexpr int64_t kInflightAtoms = 0;
const char* const kAutomaticSpendAtoms = "0";

bool EnsureDir(const fs::path& modeldir, fs::path& swarm_dir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    swarm_dir = modeldir / "swarm";
    fs::create_directories(swarm_dir);
    if (!fs::exists(swarm_dir)) {
        err = "SWARM_DIR";
        return false;
    }
    return true;
}

bool WriteAtomic(const fs::path& final_path, const std::string& body, std::string& err)
{
    const fs::path tmp = fs::u8path(final_path.utf8string() + ".tmp");
    {
        std::ofstream file(tmp, std::ios::trunc);
        if (!file) {
            err = "WRITE";
            return false;
        }
        file << body;
        if (!file) {
            err = "WRITE";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "RENAME";
        return false;
    }
    err.clear();
    return true;
}

bool ReadRaw(const fs::path& path, std::string& raw)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    raw.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true;
}

bool ParseInt(const UniValue& value, int64_t& out)
{
    if (!value.isNum()) return false;
    const std::string& text = value.getValStr();
    if (text.empty()) return false;
    int64_t parsed = 0;
    const char* const first = text.data();
    const char* const last = text.data() + text.size();
    const std::from_chars_result result = std::from_chars(first, last, parsed);
    if (result.ec != std::errc{} || result.ptr != last) return false;
    out = parsed;
    return true;
}

bool HasForbiddenSpend(const UniValue& obj, std::string& err)
{
    if (obj.exists("spend")) {
        err = "SPEND";
        return true;
    }
    for (const char* key : {"automatic_spend", "automatic_spend_atoms"}) {
        if (!obj.exists(key)) continue;
        const UniValue& value = obj[key];
        if (value.isStr()) {
            if (value.get_str() == kAutomaticSpendAtoms) continue;
            err = "SPEND";
            return true;
        }
        int64_t atoms = 0;
        if (!value.isNum() || !ParseInt(value, atoms) || atoms != 0) {
            err = "SPEND";
            return true;
        }
    }
    return false;
}

bool AddNonNegative(int64_t& acc, int64_t part)
{
    if (part < 0 || acc > std::numeric_limits<int64_t>::max() - part) return false;
    acc += part;
    return true;
}

bool CollateralAccepts(int64_t collateral, int64_t exit_reserve, int64_t fee_reserve)
{
    if (collateral <= 0 || exit_reserve < 0 || fee_reserve < 0) return false;
    if (exit_reserve >= collateral) return false;
    return fee_reserve < collateral - exit_reserve;
}

bool RecipientListed(const std::vector<std::string>& recipients, const std::string& recipient)
{
    for (const std::string& allowed : recipients) {
        if (allowed == recipient) return true;
    }
    return false;
}

bool AuthorizationFields(const SwarmMandate& mandate)
{
    if (mandate.mandate_id.empty() || mandate.pool_id.empty() || mandate.actor.empty() || mandate.nonce.empty()) return false;
    if (mandate.ceiling <= 0 || mandate.expiry_height <= 0 || mandate.recipients.empty()) return false;
    for (const std::string& recipient : mandate.recipients) {
        if (recipient.empty()) return false;
    }
    return true;
}

bool SameAuthorization(const SwarmMandate& stored, const SwarmMandate& incoming)
{
    return stored.pool_id == incoming.pool_id && stored.actor == incoming.actor && stored.recipients == incoming.recipients &&
           stored.ceiling == incoming.ceiling && stored.expiry_height == incoming.expiry_height && stored.nonce == incoming.nonce;
}

SwarmConservation ConservationOf(int64_t collateral, int64_t exit_reserve, int64_t fee_reserve, int64_t inflight, int64_t assigned)
{
    SwarmConservation out;
    out.collateral = collateral;
    out.exit_reserve = exit_reserve;
    out.fee_reserve = fee_reserve;
    out.inflight = inflight;
    out.assigned = assigned;
    if (!CollateralAccepts(collateral, exit_reserve, fee_reserve) || inflight < 0 || assigned < 0) return out;
    int64_t left = collateral;
    const int64_t parts[] = {exit_reserve, fee_reserve, inflight, assigned};
    for (const int64_t part : parts) {
        if (part > left) {
            out.available = left - part;
            return out;
        }
        left -= part;
    }
    out.available = left;
    int64_t sum = 0;
    if (!AddNonNegative(sum, out.available) || !AddNonNegative(sum, out.inflight) || !AddNonNegative(sum, out.assigned) ||
        !AddNonNegative(sum, out.exit_reserve) || !AddNonNegative(sum, out.fee_reserve)) {
        return out;
    }
    out.ok = out.available >= 0 && sum == out.collateral;
    return out;
}

} // namespace

bool SwarmMandateBook::Open(int64_t collateral, int64_t exit_reserve, int64_t fee_reserve, std::string& err)
{
    if (m_open) {
        err = "REOPEN";
        return false;
    }
    if (!CollateralAccepts(collateral, exit_reserve, fee_reserve)) {
        err = "COLLATERAL";
        return false;
    }
    m_open = true;
    m_collateral = collateral;
    m_exit = exit_reserve;
    m_fee = fee_reserve;
    m_mandates.clear();
    m_work.clear();
    err.clear();
    return true;
}

bool SwarmMandateBook::Grant(const SwarmMandate& mandate, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    if (!AuthorizationFields(mandate)) {
        err = "MANDATE";
        return false;
    }
    const auto it = m_mandates.find(mandate.mandate_id);
    if (it != m_mandates.end()) {
        if (!SameAuthorization(it->second, mandate)) {
            err = "CONFLICT";
            return false;
        }
        // Same authorization cap. Spent is unchanged. Revocation stays.
        err.clear();
        return true;
    }
    SwarmMandate stored = mandate;
    stored.revoked = false;
    stored.spent = 0;
    m_mandates.emplace(stored.mandate_id, std::move(stored));
    err.clear();
    return true;
}

bool SwarmMandateBook::Revoke(const std::string& mandate_id, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const auto it = m_mandates.find(mandate_id);
    if (it == m_mandates.end()) {
        err = "MANDATE";
        return false;
    }
    it->second.revoked = true;
    err.clear();
    return true;
}

bool SwarmMandateBook::Reserve(const std::string& mandate_id, const std::string& work_id, const std::string& recipient,
                               int64_t atoms, int64_t height, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const auto it = m_mandates.find(mandate_id);
    if (it == m_mandates.end()) {
        err = "MANDATE";
        return false;
    }
    if (it->second.revoked) {
        err = "REVOKED";
        return false;
    }
    if (height >= it->second.expiry_height) {
        err = "EXPIRED";
        return false;
    }
    if (!RecipientListed(it->second.recipients, recipient)) {
        err = "RECIPIENT";
        return false;
    }
    if (atoms <= 0) {
        err = "AMOUNT";
        return false;
    }
    if (work_id.empty()) {
        err = "WORK";
        return false;
    }
    const auto work = m_work.find(work_id);
    if (work != m_work.end()) {
        if (work->second.mandate_id == mandate_id && work->second.recipient == recipient && work->second.atoms == atoms) {
            err.clear();
            return true;
        }
        err = "CONFLICT";
        return false;
    }
    if (it->second.spent < 0 || it->second.spent > it->second.ceiling || atoms > it->second.ceiling - it->second.spent) {
        err = "CEILING";
        return false;
    }
    const SwarmConservation now = Conserved();
    if (!now.ok || atoms > now.available) {
        err = "CONSERVATION";
        return false;
    }
    it->second.spent += atoms;
    m_work.emplace(work_id, Work{mandate_id, recipient, atoms});
    err.clear();
    return true;
}

SwarmConservation SwarmMandateBook::Conserved() const
{
    if (!m_open) return {};
    int64_t assigned = 0;
    for (const auto& item : m_mandates) {
        if (!AddNonNegative(assigned, item.second.spent)) return {};
    }
    SwarmConservation out = ConservationOf(m_collateral, m_exit, m_fee, kInflightAtoms, assigned);
    out.ok = out.ok && out.inflight == kInflightAtoms;
    return out;
}

bool SwarmMandateBook::Persist(const fs::path& modeldir, std::string& err)
{
    if (!m_open) {
        err = "NOT_OPEN";
        return false;
    }
    const SwarmConservation now = Conserved();
    if (!now.ok) {
        err = "CONSERVATION";
        return false;
    }
    fs::path swarm_dir;
    if (!EnsureDir(modeldir, swarm_dir, err)) return false;
    UniValue mandates(UniValue::VARR);
    for (const auto& item : m_mandates) {
        const SwarmMandate& mandate = item.second;
        UniValue recipients(UniValue::VARR);
        for (const std::string& recipient : mandate.recipients) recipients.push_back(recipient);
        UniValue row(UniValue::VOBJ);
        row.pushKV("actor", mandate.actor);
        row.pushKV("ceiling", mandate.ceiling);
        row.pushKV("expiry_height", mandate.expiry_height);
        row.pushKV("mandate_id", mandate.mandate_id);
        row.pushKV("nonce", mandate.nonce);
        row.pushKV("pool_id", mandate.pool_id);
        row.pushKV("recipients", recipients);
        row.pushKV("revoked", mandate.revoked);
        row.pushKV("spent", mandate.spent);
        mandates.push_back(std::move(row));
    }
    UniValue works(UniValue::VARR);
    for (const auto& item : m_work) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("atoms", item.second.atoms);
        row.pushKV("mandate_id", item.second.mandate_id);
        row.pushKV("recipient", item.second.recipient);
        row.pushKV("work_id", item.first);
        works.push_back(std::move(row));
    }
    UniValue out(UniValue::VOBJ);
    out.pushKV("assigned", now.assigned);
    out.pushKV("automatic_spend_atoms", kAutomaticSpendAtoms);
    out.pushKV("available", now.available);
    out.pushKV("collateral", m_collateral);
    out.pushKV("exit_reserve", m_exit);
    out.pushKV("fee_reserve", m_fee);
    out.pushKV("inflight", kInflightAtoms);
    out.pushKV("mandates", mandates);
    out.pushKV("ok", now.ok);
    out.pushKV("works", works);
    return WriteAtomic(swarm_dir / "mandates.json", out.write(0, 0) + "\n", err);
}

bool SwarmMandateBook::Load(const fs::path& modeldir, std::string& err)
{
    if (modeldir.empty()) {
        err = "MODELDIR";
        return false;
    }
    const fs::path path = modeldir / "swarm" / "mandates.json";
    std::string raw;
    UniValue root;
    if (!ReadRaw(path, raw) || !root.read(raw) || !root.isObject()) {
        err = "LOAD";
        return false;
    }
    if (HasForbiddenSpend(root, err)) return false;
    if (!root.exists("assigned") || !root.exists("automatic_spend_atoms") || !root.exists("available") ||
        !root.exists("collateral") || !root.exists("exit_reserve") || !root.exists("fee_reserve") || !root.exists("inflight") ||
        !root.exists("mandates") || !root.exists("ok") || !root.exists("works") || !root["automatic_spend_atoms"].isStr() ||
        !root["ok"].isBool() || !root["mandates"].isArray() || !root["works"].isArray()) {
        err = "LOAD";
        return false;
    }
    if (root["automatic_spend_atoms"].get_str() != kAutomaticSpendAtoms) {
        err = "SPEND";
        return false;
    }
    int64_t assigned = 0;
    int64_t available = 0;
    int64_t collateral = 0;
    int64_t exit_reserve = 0;
    int64_t fee_reserve = 0;
    int64_t inflight = 0;
    if (!ParseInt(root["assigned"], assigned) || !ParseInt(root["available"], available) || !ParseInt(root["collateral"], collateral) ||
        !ParseInt(root["exit_reserve"], exit_reserve) || !ParseInt(root["fee_reserve"], fee_reserve) ||
        !ParseInt(root["inflight"], inflight) || inflight != kInflightAtoms) {
        err = "LOAD";
        return false;
    }
    std::map<std::string, SwarmMandate> mandates;
    for (const UniValue& item : root["mandates"].getValues()) {
        if (!item.isObject() || HasForbiddenSpend(item, err)) {
            if (err != "SPEND") err = "LOAD";
            return false;
        }
        if (!item.exists("actor") || !item.exists("ceiling") || !item.exists("expiry_height") || !item.exists("mandate_id") ||
            !item.exists("nonce") || !item.exists("pool_id") || !item.exists("recipients") || !item.exists("revoked") ||
            !item.exists("spent") || !item["actor"].isStr() || !item["mandate_id"].isStr() || !item["nonce"].isStr() ||
            !item["pool_id"].isStr() || !item["recipients"].isArray() || !item["revoked"].isBool()) {
            err = "LOAD";
            return false;
        }
        SwarmMandate mandate;
        mandate.actor = item["actor"].get_str();
        mandate.mandate_id = item["mandate_id"].get_str();
        mandate.nonce = item["nonce"].get_str();
        mandate.pool_id = item["pool_id"].get_str();
        mandate.revoked = item["revoked"].get_bool();
        if (!ParseInt(item["ceiling"], mandate.ceiling) || !ParseInt(item["expiry_height"], mandate.expiry_height) ||
            !ParseInt(item["spent"], mandate.spent)) {
            err = "LOAD";
            return false;
        }
        for (const UniValue& recipient : item["recipients"].getValues()) {
            if (!recipient.isStr()) {
                err = "LOAD";
                return false;
            }
            mandate.recipients.push_back(recipient.get_str());
        }
        if (!AuthorizationFields(mandate) || mandate.spent < 0 || mandate.spent > mandate.ceiling) {
            err = "LOAD";
            return false;
        }
        if (!mandates.emplace(mandate.mandate_id, std::move(mandate)).second) {
            err = "LOAD";
            return false;
        }
    }
    std::map<std::string, Work> works;
    std::map<std::string, int64_t> spent_from_works;
    for (const UniValue& item : root["works"].getValues()) {
        if (!item.isObject() || HasForbiddenSpend(item, err)) {
            if (err != "SPEND") err = "LOAD";
            return false;
        }
        if (!item.exists("atoms") || !item.exists("mandate_id") || !item.exists("recipient") || !item.exists("work_id") ||
            !item["mandate_id"].isStr() || !item["recipient"].isStr() || !item["work_id"].isStr()) {
            err = "LOAD";
            return false;
        }
        Work row;
        row.mandate_id = item["mandate_id"].get_str();
        row.recipient = item["recipient"].get_str();
        const std::string work_id = item["work_id"].get_str();
        if (work_id.empty() || row.recipient.empty() || !ParseInt(item["atoms"], row.atoms) || row.atoms <= 0) {
            err = "LOAD";
            return false;
        }
        const auto mit = mandates.find(row.mandate_id);
        if (mit == mandates.end() || !RecipientListed(mit->second.recipients, row.recipient)) {
            err = "LOAD";
            return false;
        }
        int64_t& tally = spent_from_works[row.mandate_id];
        if (!AddNonNegative(tally, row.atoms) || tally > mit->second.ceiling) {
            err = "LOAD";
            return false;
        }
        if (!works.emplace(work_id, std::move(row)).second) {
            err = "LOAD";
            return false;
        }
    }
    int64_t spent_sum = 0;
    for (const auto& item : mandates) {
        const int64_t tally = spent_from_works.count(item.first) ? spent_from_works[item.first] : 0;
        if (tally != item.second.spent || !AddNonNegative(spent_sum, item.second.spent)) {
            err = "LOAD";
            return false;
        }
    }
    if (spent_sum != assigned) {
        err = "LOAD";
        return false;
    }
    const SwarmConservation rebuilt = ConservationOf(collateral, exit_reserve, fee_reserve, inflight, assigned);
    if (!rebuilt.ok || rebuilt.available != available || root["ok"].get_bool() != rebuilt.ok) {
        err = "LOAD";
        return false;
    }
    m_open = true;
    m_collateral = collateral;
    m_exit = exit_reserve;
    m_fee = fee_reserve;
    m_mandates = std::move(mandates);
    m_work = std::move(works);
    err.clear();
    return true;
}

} // namespace modelnet
