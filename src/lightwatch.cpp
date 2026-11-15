// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lightwatch.h>

#include <blockfilter.h>
#include <consensus/consensus.h>
#include <core_io.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/descriptor.h>
#include <script/script.h>
#include <tinyformat.h>
#include <uint256.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <system_error>
#include <utility>

namespace {

constexpr std::array<const char*, 7> kMandatory{{
    "start",
    "cursor",
    "filter_ready",
    "filter_header",
    "anchor_set",
    "anchor",
    "fetched_total",
}};

bool MandatoryTag(const std::string& tag)
{
    for (const char* name : kMandatory) {
        if (tag == name) return true;
    }
    return false;
}

} // namespace

int LightWatch::NextHeight() const
{
    if (m_cursor < m_start) return m_start;
    return m_cursor + 1;
}

void LightWatch::RebuildScripts()
{
    m_scripts.clear();
    std::set<std::vector<unsigned char>> seen;
    for (const std::string& descriptor : m_descriptors) {
        FlatSigningProvider provider;
        std::string error;
        const auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
        if (parsed.size() != 1) continue;
        const int end = parsed[0]->IsRange() ? RANGE_WINDOW : 1;
        for (int i = 0; i < end; ++i) {
            std::vector<CScript> scripts;
            FlatSigningProvider out;
            if (!parsed[0]->Expand(i, provider, scripts, out)) continue;
            for (const CScript& script : scripts) {
                if (script.empty()) continue;
                std::vector<unsigned char> raw(script.begin(), script.end());
                if (seen.insert(raw).second) m_scripts.push_back(std::move(raw));
            }
        }
    }
}

void LightWatch::SetStartHeight(int height)
{
    m_start = height;
    if (m_cursor < m_start) {
        m_filter_ready = m_start == 0;
        if (m_start == 0) m_filter_header.SetNull();
    }
}

bool LightWatch::AddDescriptor(const std::string& descriptor, std::string& error, bool reset_progress)
{
    FlatSigningProvider provider;
    const auto parsed = Parse(descriptor, provider, error, /*require_checksum=*/false);
    if (parsed.size() != 1) {
        if (error.empty()) error = "BTX_LIGHTWATCH_DESCRIPTOR";
        return false;
    }
    std::string priv;
    if (!provider.keys.empty() || !provider.pq_keys.empty() || parsed[0]->ToPrivateString(provider, priv)) {
        error = "BTX_LIGHTWATCH_PRIVATE";
        return false;
    }
    const std::string stored = parsed[0]->ToString();
    if (std::find(m_descriptors.begin(), m_descriptors.end(), stored) != m_descriptors.end()) {
        return true;
    }
    const int end = parsed[0]->IsRange() ? RANGE_WINDOW : 1;
    bool produced{false};
    for (int i = 0; i < end && !produced; ++i) {
        std::vector<CScript> scripts;
        FlatSigningProvider out;
        if (!parsed[0]->Expand(i, provider, scripts, out)) continue;
        produced = std::any_of(scripts.begin(), scripts.end(), [](const CScript& script) { return !script.empty(); });
    }
    if (!produced) {
        error = "BTX_LIGHTWATCH_DESCRIPTOR";
        return false;
    }
    m_descriptors.push_back(stored);
    RebuildScripts();
    if (reset_progress && m_cursor >= m_start) {
        // Filters already applied did not include this script. Those blocks
        // are unknown again until the walk is repeated.
        RewindTo(m_start - 1);
    }
    return true;
}

std::optional<uint256> LightWatch::HashAt(int height) const
{
    const auto it = m_hashes.find(height);
    if (it == m_hashes.end()) return std::nullopt;
    return it->second;
}

bool LightWatch::IsOpen(const uint256& txid, uint32_t n, CAmount& value, bool& coinbase) const
{
    const auto it = m_open.find(std::make_pair(txid, n));
    if (it == m_open.end()) return false;
    value = it->second.value;
    coinbase = it->second.coinbase;
    return true;
}

void LightWatch::NoteEvent(const Event& event)
{
    const auto key = std::make_pair(event.txid, event.n);
    if (event.spend) {
        m_open.erase(key);
    } else {
        m_open[key] = OpenOutput{event.value, event.coinbase};
    }
}

void LightWatch::UndoEvent(const Event& event)
{
    const auto key = std::make_pair(event.txid, event.n);
    if (event.spend) {
        m_open[key] = OpenOutput{event.value, event.coinbase};
    } else {
        m_open.erase(key);
    }
}

void LightWatch::NoteFetch(int height, const uint256& block_hash)
{
    ++m_fetched_total;
    if (m_fetched.size() >= MAX_FETCHED) m_fetched.erase(m_fetched.begin());
    m_fetched.push_back(LightWatchFetch{height, block_hash});
}

LightWatch::Step LightWatch::ApplyFilter(int height, const uint256& block_hash, const uint256& prev_hash,
                                         const std::vector<unsigned char>& encoded_filter, const uint256& filter_header,
                                         const CBlock* block, std::string& error)
{
    // A cursor of INT_MAX is refused on load; never reach it here either,
    // so NextHeight() stays representable.
    if (height == std::numeric_limits<int>::max() || height != NextHeight()) {
        error = "BTX_BLOCK_LINK";
        return Step::REJECTED;
    }
    if (!m_filter_ready) {
        error = "BTX_FILTER_ANCHOR";
        return Step::REJECTED;
    }
    if (height == 0) {
        if (!prev_hash.IsNull()) {
            error = "BTX_BLOCK_LINK";
            return Step::REJECTED;
        }
    } else if (const auto prev = HashAt(height - 1)) {
        if (*prev != prev_hash) {
            error = "BTX_BLOCK_LINK";
            return Step::REJECTED;
        }
    } else if (m_anchor_set) {
        if (m_anchor != prev_hash) {
            error = "BTX_BLOCK_LINK";
            return Step::REJECTED;
        }
    } else if (height != m_start) {
        error = "BTX_BLOCK_LINK";
        return Step::REJECTED;
    }

    BlockFilter filter;
    try {
        filter = BlockFilter(BlockFilterType::BASIC, block_hash, encoded_filter, /*skip_decode_check=*/false);
    } catch (const std::exception&) {
        error = "BTX_FILTER_HEADER";
        return Step::REJECTED;
    }
    if (filter.ComputeHeader(m_filter_header) != filter_header) {
        error = "BTX_FILTER_HEADER";
        return Step::REJECTED;
    }

    GCSFilter::ElementSet needles;
    for (const auto& script : m_scripts) needles.insert(script);
    const bool matched = !needles.empty() && filter.GetFilter().MatchAny(needles);
    if (matched && block == nullptr) return Step::NEED_BLOCK;
    if (matched && block->GetHash() != block_hash) {
        error = "BTX_BLOCK_HASH";
        return Step::REJECTED;
    }

    std::vector<Event> added;
    // Credits discovered in this block, before they are committed. Historical
    // outputs are answered by the outpoint index.
    std::map<std::pair<uint256, uint32_t>, OpenOutput> staged;
    if (matched) {
        for (const auto& tx : block->vtx) {
            const bool coinbase = tx->IsCoinBase();
            const uint256 txid = tx->GetHash();
            for (uint32_t i = 0; i < tx->vout.size(); ++i) {
                const CTxOut& out = tx->vout[i];
                const std::vector<unsigned char> raw(out.scriptPubKey.begin(), out.scriptPubKey.end());
                if (std::find(m_scripts.begin(), m_scripts.end(), raw) == m_scripts.end()) continue;
                if (!MoneyRange(out.nValue)) {
                    error = "BTX_LIGHTWATCH_VALUE";
                    return Step::REJECTED;
                }
                added.push_back(Event{height, txid, i, out.nValue, coinbase, false});
                staged[std::make_pair(txid, i)] = OpenOutput{out.nValue, coinbase};
            }
        }
        for (const auto& tx : block->vtx) {
            if (tx->IsCoinBase()) continue;
            for (const CTxIn& input : tx->vin) {
                if (input.prevout.IsNull()) continue;
                const uint256 prev_txid = input.prevout.hash;
                const uint32_t prev_n = input.prevout.n;
                CAmount value{0};
                bool coinbase{false};
                bool open = IsOpen(prev_txid, prev_n, value, coinbase);
                if (!open) {
                    const auto created = staged.find(std::make_pair(prev_txid, prev_n));
                    if (created != staged.end()) {
                        open = true;
                        value = created->second.value;
                        coinbase = created->second.coinbase;
                    }
                }
                if (!open) continue;
                added.push_back(Event{height, prev_txid, prev_n, value, coinbase, true});
            }
        }
    }

    for (const Event& event : added) NoteEvent(event);
    m_events.insert(m_events.end(), added.begin(), added.end());
    m_hashes.insert_or_assign(height, block_hash);
    m_cursor = height;
    m_filter_header = filter_header;
    m_filter_ready = true;
    if (matched) NoteFetch(height, block_hash);
    return Step::APPLIED;
}

void LightWatch::RewindTo(int height)
{
    if (height < m_start) {
        m_cursor = m_start - 1;
        m_events.clear();
        m_hashes.clear();
        m_open.clear();
        m_fetched.clear();
        m_fetched_total = 0;
        m_anchor_set = false;
        m_filter_ready = m_start == 0;
        m_filter_header.SetNull();
        return;
    }
    // Events are applied in height order, so the disconnected suffix is a
    // tail. Undo it backwards to put spent outputs back.
    while (!m_events.empty() && m_events.back().height > height) {
        UndoEvent(m_events.back());
        m_events.pop_back();
    }
    m_hashes.erase(m_hashes.upper_bound(height), m_hashes.end());
    std::erase_if(m_fetched, [&](const LightWatchFetch& fetch) { return fetch.height > height; });
    m_cursor = height;
    m_filter_ready = false;
}

LightWatchStatus LightWatch::Status(int chain_height) const
{
    LightWatchStatus status;
    status.chain_height = chain_height;
    status.wallet_height = m_cursor;
    status.start_height = m_start;
    status.shielded_foreign_watch = false;
    status.shielded_omitted = true;
    status.fetched_total = m_fetched_total;
    status.descriptors = m_descriptors;
    status.fetched = m_fetched;
    if (chain_height < m_start) {
        status.ready = false;
        status.blocks_behind = 0;
        return status;
    }
    status.ready = m_cursor == chain_height;
    if (m_cursor < m_start) {
        const int64_t behind = static_cast<int64_t>(chain_height) - m_start + 1;
        status.blocks_behind = static_cast<int>(std::min<int64_t>(behind, std::numeric_limits<int>::max()));
    } else {
        status.blocks_behind = std::max(0, chain_height - m_cursor);
    }
    return status;
}

LightWatchAmount LightWatch::BalanceAt(int height) const
{
    LightWatchAmount result;
    if (height < m_start || height > m_cursor) return result;

    struct OpenCoin {
        CAmount value{0};
        bool coinbase{false};
        int created{0};
    };
    std::map<std::pair<uint256, uint32_t>, OpenCoin> open;
    for (const Event& event : m_events) {
        if (event.height > height) break;
        const auto key = std::make_pair(event.txid, event.n);
        if (event.spend) {
            open.erase(key);
        } else {
            open[key] = OpenCoin{event.value, event.coinbase, event.height};
        }
    }
    CAmount sum{0};
    CAmount immature{0};
    for (const auto& item : open) {
        const OpenCoin& coin = item.second;
        if (coin.coinbase) {
            const int64_t depth = static_cast<int64_t>(height) - coin.created + 1;
            if (depth < static_cast<int64_t>(COINBASE_MATURITY) + 1) {
                immature += coin.value;
                if (!MoneyRange(immature)) return LightWatchAmount{};
                continue;
            }
        }
        sum += coin.value;
        if (!MoneyRange(sum)) return LightWatchAmount{};
    }
    result.ready = true;
    result.amount = sum;
    result.immature = immature;
    return result;
}

bool LightWatch::IsCurrentAt(int height, int chain_height,
                            const std::function<UniValue(const std::string&, const std::vector<std::string>&)>& rpc) const
{
    if (height < m_start || height > m_cursor || height > chain_height) return false;
    const auto stored = HashAt(height);
    if (!stored) return false;
    const auto current = uint256::FromHex(rpc("getblockhash", {strprintf("%d", height)}).get_str());
    return current && *stored == *current;
}

bool LightWatch::Sync(const std::function<UniValue(const std::string&, const std::vector<std::string>&)>& rpc, std::string& error)
{
    const int tip = rpc("getblockcount", {}).getInt<int>();
    // A disconnected suffix has no active-chain hash to query. Drop it before
    // looking for the common ancestor, including when the tip is below start.
    if (m_cursor > tip) RewindTo(tip);
    while (m_cursor >= m_start) {
        const auto stored = HashAt(m_cursor);
        const auto now = uint256::FromHex(rpc("getblockhash", {strprintf("%d", m_cursor)}).get_str());
        if (!now || !stored || *stored != *now) {
            RewindTo(m_cursor - 1);
            continue;
        }
        break;
    }

    while (NextHeight() <= tip) {
        if (!m_filter_ready) {
            const int parent = NextHeight() - 1;
            if (parent < 0) {
                m_filter_header.SetNull();
                m_filter_ready = true;
            } else {
                const std::string parent_hash = rpc("getblockhash", {strprintf("%d", parent)}).get_str();
                const UniValue parent_filter = rpc("getblockfilter", {parent_hash, "basic"});
                const auto header = uint256::FromHex(parent_filter["header"].get_str());
                const auto hash = uint256::FromHex(parent_hash);
                if (!header || !hash) {
                    error = "BTX_FILTER_ANCHOR";
                    return false;
                }
                if (const auto stored = HashAt(parent); stored && *stored != *hash) {
                    RewindTo(parent - 1);
                    continue;
                }
                m_filter_header = *header;
                m_anchor = *hash;
                m_anchor_set = true;
                m_filter_ready = true;
            }
        }

        const int height = NextHeight();
        const std::string hash_hex = rpc("getblockhash", {strprintf("%d", height)}).get_str();
        const auto block_hash = uint256::FromHex(hash_hex);
        if (!block_hash) {
            error = "BTX_BLOCK_LINK";
            return false;
        }
        uint256 prev_hash;
        if (height == 0) {
            prev_hash.SetNull();
        } else {
            const UniValue header = rpc("getblockheader", {hash_hex});
            const UniValue prev = header.find_value("previousblockhash");
            if (prev.isNull()) {
                error = "BTX_BLOCK_LINK";
                return false;
            }
            const auto parsed = uint256::FromHex(prev.get_str());
            if (!parsed) {
                error = "BTX_BLOCK_LINK";
                return false;
            }
            prev_hash = *parsed;
        }
        const UniValue filter_json = rpc("getblockfilter", {hash_hex, "basic"});
        const auto filter_header = uint256::FromHex(filter_json["header"].get_str());
        if (!filter_header) {
            error = "BTX_FILTER_HEADER";
            return false;
        }
        const std::vector<unsigned char> encoded = ParseHex(filter_json["filter"].get_str());
        Step step = ApplyFilter(height, *block_hash, prev_hash, encoded, *filter_header, nullptr, error);
        if (step == Step::NEED_BLOCK) {
            const std::string raw = rpc("getblock", {hash_hex, "0"}).get_str();
            CBlock block;
            if (!DecodeHexBlk(block, raw)) {
                error = "BTX_BLOCK_HASH";
                return false;
            }
            step = ApplyFilter(height, *block_hash, prev_hash, encoded, *filter_header, &block, error);
        }
        if (step != Step::APPLIED) {
            if (error.empty()) error = "BTX_FILTER_HEADER";
            return false;
        }
    }
    return true;
}

bool LightWatch::Save(const std::string& path, std::string& error) const
{
    const fs::path dest = fs::PathFromString(path);
    if (!dest.parent_path().empty()) fs::create_directories(dest.parent_path());
    const fs::path tmp = fs::PathFromString(path + ".tmp");
    std::ofstream out(tmp);
    if (!out) {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    out << "btx-lightwatch 2\n";
    out << "start " << m_start << "\n";
    out << "cursor " << m_cursor << "\n";
    out << "filter_ready " << (m_filter_ready ? 1 : 0) << "\n";
    out << "filter_header " << m_filter_header.GetHex() << "\n";
    out << "anchor_set " << (m_anchor_set ? 1 : 0) << "\n";
    out << "anchor " << m_anchor.GetHex() << "\n";
    out << "fetched_total " << m_fetched_total << "\n";
    for (const std::string& descriptor : m_descriptors) {
        out << "desc " << descriptor << "\n";
    }
    for (const auto& item : m_hashes) {
        out << "hash " << item.first << " " << item.second.GetHex() << "\n";
    }
    for (const Event& event : m_events) {
        out << "event " << event.height << " " << event.txid.GetHex() << " " << event.n << " " << event.value
            << " " << (event.coinbase ? 1 : 0) << " " << (event.spend ? 1 : 0) << "\n";
    }
    for (const LightWatchFetch& fetch : m_fetched) {
        out << "fetch " << fetch.height << " " << fetch.block_hash.GetHex() << "\n";
    }
    // A file cut at the end of a line still parses. The trailer counts the
    // records, so a lost spend or credit is refused instead of read as ready.
    out << "end " << m_descriptors.size() << " " << m_hashes.size() << " " << m_events.size() << " "
        << m_fetched.size() << "\n";
    out.close();
    if (!out) {
        std::error_code ec;
        fs::remove(tmp, ec);
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    // A replacement that does not parse is not installed. The previous file
    // stays, and the partial temp is removed so it cannot be read as a snapshot.
    {
        LightWatch check;
        std::ifstream written(tmp);
        std::string parsed_error;
        if (!written || !check.ReadSnapshot(written, parsed_error)) {
            std::error_code ec;
            fs::remove(tmp, ec);
            error = "BTX_LIGHTWATCH_IO";
            return false;
        }
    }
    // Commit the temp before it replaces the file. Otherwise a power loss
    // after the rename can leave a short file under the final name.
    FILE* file = fsbridge::fopen(tmp, "rb+");
    const bool committed = file != nullptr && FileCommit(file);
    if (file != nullptr) fclose(file);
    if (!committed) {
        std::error_code ec;
        fs::remove(tmp, ec);
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    fs::rename(tmp, dest);
    DirectoryCommit(dest.parent_path());
    return true;
}

bool LightWatch::AcceptSnapshot(std::string& error)
{
    const auto reject = [&]() {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    };
    // NextHeight() returns m_cursor + 1, so a loaded cursor of INT_MAX could
    // never advance without overflowing.
    if (m_start < 0 || m_cursor < -1 || m_cursor == std::numeric_limits<int>::max()) return reject();
    if (m_cursor < m_start) {
        // Not caught up: the initial cursor is -1, and a rewind below start
        // lands on start-1. Either way there is no chain suffix to report.
        if (m_cursor != -1 && m_cursor != m_start - 1) return reject();
        if (!m_hashes.empty() || !m_events.empty() || !m_fetched.empty() || m_fetched_total != 0) return reject();
        m_open.clear();
        return true;
    }

    const int64_t span = static_cast<int64_t>(m_cursor) - static_cast<int64_t>(m_start) + 1;
    if (span < 1 || static_cast<int64_t>(m_hashes.size()) != span) return reject();
    int64_t expect = m_start;
    for (const auto& item : m_hashes) {
        if (item.first != expect) return reject();
        ++expect;
    }
    if (m_fetched.size() > MAX_FETCHED || m_fetched_total < m_fetched.size()) return reject();

    m_open.clear();
    int last_event = m_start - 1;
    for (const Event& event : m_events) {
        if (event.height < last_event || event.height < m_start || event.height > m_cursor) return reject();
        if (!m_hashes.count(event.height) || !MoneyRange(event.value)) return reject();
        last_event = event.height;
        const auto key = std::make_pair(event.txid, event.n);
        if (event.spend) {
            const auto it = m_open.find(key);
            if (it == m_open.end() || it->second.value != event.value || it->second.coinbase != event.coinbase) return reject();
            m_open.erase(it);
        } else if (!m_open.emplace(key, OpenOutput{event.value, event.coinbase}).second) {
            return reject();
        }
    }
    int last_fetch = m_start - 1;
    for (const LightWatchFetch& fetch : m_fetched) {
        if (fetch.height < last_fetch || fetch.height < m_start || fetch.height > m_cursor) return reject();
        const auto it = m_hashes.find(fetch.height);
        if (it == m_hashes.end() || it->second != fetch.block_hash) return reject();
        last_fetch = fetch.height;
    }
    return true;
}

bool LightWatch::ReadSnapshot(std::istream& in, std::string& error)
{
    const auto reject = [&]() {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    };
    std::string magic;
    int version{0};
    if (!(in >> magic >> version) || magic != "btx-lightwatch" || (version != 1 && version != 2)) return reject();
    *this = LightWatch{};

    for (int index = 0; index < static_cast<int>(kMandatory.size()); ++index) {
        std::string tag;
        if (!(in >> tag) || tag != kMandatory[static_cast<std::size_t>(index)]) return reject();
        switch (index) {
        case 0:
            if (!(in >> m_start) || m_start < 0) return reject();
            break;
        case 1:
            if (!(in >> m_cursor) || m_cursor < -1) return reject();
            break;
        case 2: {
            int ready{0};
            if (!(in >> ready) || (ready != 0 && ready != 1)) return reject();
            m_filter_ready = ready != 0;
            break;
        }
        case 3: {
            std::string hex;
            if (!(in >> hex)) return reject();
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) return reject();
            m_filter_header = *parsed;
            break;
        }
        case 4: {
            int set{0};
            if (!(in >> set) || (set != 0 && set != 1)) return reject();
            m_anchor_set = set != 0;
            break;
        }
        case 5: {
            std::string hex;
            if (!(in >> hex)) return reject();
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) return reject();
            m_anchor = *parsed;
            break;
        }
        case 6:
            if (!(in >> m_fetched_total)) return reject();
            break;
        default:
            return reject();
        }
    }

    enum class Phase { DESC, HASH, EVENT, FETCH };
    Phase phase = Phase::DESC;
    int last_hash = -1;
    bool saw_hash = false;
    bool saw_end = false;
    std::string tag;
    while (in >> tag) {
        if (saw_end || MandatoryTag(tag)) return reject();
        if (tag == "desc") {
            if (phase != Phase::DESC) return reject();
            std::string descriptor;
            if (!std::getline(in >> std::ws, descriptor) || descriptor.empty()) return reject();
            const std::size_t before = m_descriptors.size();
            if (!AddDescriptor(descriptor, error, /*reset_progress=*/false)) return reject();
            if (m_descriptors.size() != before + 1) return reject();
        } else if (tag == "hash") {
            if (phase == Phase::DESC) phase = Phase::HASH;
            if (phase != Phase::HASH) return reject();
            int height{0};
            std::string hex;
            if (!(in >> height >> hex) || height < 0) return reject();
            if (saw_hash && height <= last_hash) return reject();
            const auto parsed = uint256::FromHex(hex);
            if (!parsed || m_hashes.count(height)) return reject();
            m_hashes.emplace(height, *parsed);
            last_hash = height;
            saw_hash = true;
        } else if (tag == "event") {
            // Spends and credits follow the hash prefix. A record before any
            // hash, or after a fetch, is out of order.
            if (phase == Phase::HASH) phase = Phase::EVENT;
            if (phase != Phase::EVENT) return reject();
            Event event;
            int coinbase{0};
            int spend{0};
            std::string hex;
            // Every field must extract. A short line used to survive FromHex
            // on the txid alone and become a ready zero-value credit.
            if (!(in >> event.height >> hex >> event.n >> event.value >> coinbase >> spend)) return reject();
            if ((coinbase != 0 && coinbase != 1) || (spend != 0 && spend != 1)) return reject();
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) return reject();
            if (!m_events.empty() && event.height < m_events.back().height) return reject();
            event.txid = *parsed;
            event.coinbase = coinbase != 0;
            event.spend = spend != 0;
            m_events.push_back(event);
        } else if (tag == "fetch") {
            if (phase != Phase::HASH && phase != Phase::EVENT && phase != Phase::FETCH) return reject();
            phase = Phase::FETCH;
            LightWatchFetch fetch;
            std::string hex;
            if (!(in >> fetch.height >> hex) || fetch.height < 0) return reject();
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) return reject();
            if (!m_fetched.empty() && fetch.height < m_fetched.back().height) return reject();
            fetch.block_hash = *parsed;
            m_fetched.push_back(fetch);
        } else if (tag == "end" && version == 2) {
            std::size_t descriptors{0};
            std::size_t hashes{0};
            std::size_t events{0};
            std::size_t fetched{0};
            if (!(in >> descriptors >> hashes >> events >> fetched)) return reject();
            if (descriptors != m_descriptors.size() || hashes != m_hashes.size() || events != m_events.size() ||
                fetched != m_fetched.size()) {
                return reject();
            }
            saw_end = true;
        } else {
            return reject();
        }
    }
    if (in.bad() || !in.eof()) return reject();
    // Version 1 had no trailer. It is still read, and the next Save writes version 2.
    if (version == 2 && !saw_end) return reject();
    return AcceptSnapshot(error);
}

bool LightWatch::Load(const std::string& path, std::string& error)
{
    // Save writes path.tmp and renames it over path only after the temp parses.
    // A crash in between leaves the previous file intact and a torn temp beside
    // it. The temp is never a snapshot. A damaged primary is not adopted, so a
    // caller that already holds a complete snapshot keeps it.
    const fs::path primary = fs::PathFromString(path);
    std::ifstream in(primary);
    if (!in) {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    LightWatch loaded;
    if (!loaded.ReadSnapshot(in, error)) {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    *this = std::move(loaded);
    return true;
}
