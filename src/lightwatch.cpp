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
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <map>
#include <set>
#include <utility>

namespace {

const uint256* FindHash(const std::vector<std::pair<int, uint256>>& hashes, int height)
{
    for (const auto& item : hashes) {
        if (item.first == height) return &item.second;
    }
    return nullptr;
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

bool LightWatch::IsOpen(const uint256& txid, uint32_t n, CAmount& value, bool& coinbase) const
{
    bool open = false;
    for (const Event& event : m_events) {
        if (event.txid != txid || event.n != n) continue;
        if (event.spend) {
            open = false;
        } else {
            open = true;
            value = event.value;
            coinbase = event.coinbase;
        }
    }
    return open;
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
    if (height != NextHeight()) {
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
    } else if (const uint256* prev = FindHash(m_hashes, height - 1)) {
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
            }
        }
        for (const auto& tx : block->vtx) {
            if (tx->IsCoinBase()) continue;
            for (const CTxIn& input : tx->vin) {
                if (input.prevout.IsNull()) continue;
                CAmount value{0};
                bool coinbase{false};
                bool open = IsOpen(input.prevout.hash, input.prevout.n, value, coinbase);
                if (!open) {
                    for (const Event& event : added) {
                        if (!event.spend && event.txid == input.prevout.hash && event.n == input.prevout.n) {
                            open = true;
                            value = event.value;
                            coinbase = event.coinbase;
                        }
                    }
                }
                if (!open) continue;
                added.push_back(Event{height, input.prevout.hash, input.prevout.n, value, coinbase, true});
            }
        }
    }

    m_events.insert(m_events.end(), added.begin(), added.end());
    m_hashes.push_back({height, block_hash});
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
        m_fetched.clear();
        m_fetched_total = 0;
        m_anchor_set = false;
        m_filter_ready = m_start == 0;
        m_filter_header.SetNull();
        return;
    }
    m_cursor = height;
    std::erase_if(m_events, [&](const Event& event) { return event.height > height; });
    std::erase_if(m_hashes, [&](const std::pair<int, uint256>& item) { return item.first > height; });
    std::erase_if(m_fetched, [&](const LightWatchFetch& fetch) { return fetch.height > height; });
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
        status.blocks_behind = chain_height - m_start + 1;
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

bool LightWatch::Sync(const std::function<UniValue(const std::string&, const std::vector<std::string>&)>& rpc, std::string& error)
{
    const int tip = rpc("getblockcount", {}).getInt<int>();
    while (m_cursor >= m_start) {
        const uint256* stored = FindHash(m_hashes, m_cursor);
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
                if (const uint256* stored = FindHash(m_hashes, parent); stored && *stored != *hash) {
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
    out << "btx-lightwatch 1\n";
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
    out.close();
    if (!out) {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    fs::rename(tmp, dest);
    return true;
}

bool LightWatch::Load(const std::string& path, std::string& error)
{
    std::ifstream in(fs::PathFromString(path));
    if (!in) {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    std::string magic;
    int version{0};
    in >> magic >> version;
    if (!in || magic != "btx-lightwatch" || version != 1) {
        error = "BTX_LIGHTWATCH_IO";
        return false;
    }
    *this = LightWatch{};
    std::string tag;
    while (in >> tag) {
        if (tag == "start") {
            in >> m_start;
        } else if (tag == "cursor") {
            in >> m_cursor;
        } else if (tag == "filter_ready") {
            int ready{0};
            in >> ready;
            m_filter_ready = ready != 0;
        } else if (tag == "filter_header") {
            std::string hex;
            in >> hex;
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) {
                error = "BTX_LIGHTWATCH_IO";
                return false;
            }
            m_filter_header = *parsed;
        } else if (tag == "anchor_set") {
            int set{0};
            in >> set;
            m_anchor_set = set != 0;
        } else if (tag == "anchor") {
            std::string hex;
            in >> hex;
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) {
                error = "BTX_LIGHTWATCH_IO";
                return false;
            }
            m_anchor = *parsed;
        } else if (tag == "fetched_total") {
            in >> m_fetched_total;
        } else if (tag == "desc") {
            std::string descriptor;
            std::getline(in >> std::ws, descriptor);
            if (!AddDescriptor(descriptor, error, /*reset_progress=*/false)) return false;
        } else if (tag == "hash") {
            int height{0};
            std::string hex;
            in >> height >> hex;
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) {
                error = "BTX_LIGHTWATCH_IO";
                return false;
            }
            m_hashes.push_back({height, *parsed});
        } else if (tag == "event") {
            Event event;
            int coinbase{0};
            int spend{0};
            std::string hex;
            in >> event.height >> hex >> event.n >> event.value >> coinbase >> spend;
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) {
                error = "BTX_LIGHTWATCH_IO";
                return false;
            }
            event.txid = *parsed;
            event.coinbase = coinbase != 0;
            event.spend = spend != 0;
            m_events.push_back(event);
        } else if (tag == "fetch") {
            LightWatchFetch fetch;
            std::string hex;
            in >> fetch.height >> hex;
            const auto parsed = uint256::FromHex(hex);
            if (!parsed) {
                error = "BTX_LIGHTWATCH_IO";
                return false;
            }
            fetch.block_hash = *parsed;
            m_fetched.push_back(fetch);
        } else {
            error = "BTX_LIGHTWATCH_IO";
            return false;
        }
    }
    return true;
}
