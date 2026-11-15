// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <blockfilter.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <hash.h>
#include <key.h>
#include <lightwatch.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/util/random.h>
#include <tinyformat.h>
#include <undo.h>
#include <univalue.h>
#include <util/check.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iterator>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

// btx-cli lightwatch keeps a watch file and walks compact filters from the
// user's node. The file is read back on every command; the node answers
// getblockcount, getblockhash, getblockheader, getblockfilter and getblock.

namespace {

fs::path FuzzDir()
{
    static const fs::path dir = fs::path{fs::temp_directory_path()} /
                                fs::u8path(strprintf("btx-fuzz-lightwatch-%08x", std::random_device{}()));
    return dir;
}

fs::path FreshDir()
{
    const fs::path dir = FuzzDir();
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    return dir;
}

void PutFile(const fs::path& path, const std::string& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

std::string GetFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void initialize_lightwatch()
{
    static ECC_Context ecc_context{};
    SelectParams(ChainType::REGTEST);
}

/** Save, load, and save again: the two files are byte-identical. */
void AssertSaveRoundTrip(const LightWatch& watch, const fs::path& dir)
{
    std::string error;
    const std::string first = fs::PathToString(dir / "round-1.dat");
    const std::string second = fs::PathToString(dir / "round-2.dat");
    Assert(watch.Save(first, error));
    LightWatch loaded;
    Assert(loaded.Load(first, error));
    Assert(loaded.Save(second, error));
    Assert(GetFile(fs::PathFromString(first)) == GetFile(fs::PathFromString(second)));
}

const CScript WATCHED{CScript() << OP_TRUE};
const CScript OTHER{CScript() << OP_2};

struct FuzzChain {
    std::vector<CBlock> blocks;
    std::vector<uint256> filter_headers;
    std::vector<std::vector<unsigned char>> filters;
    /** Every block ever generated, so a stale hash still has a header. */
    std::map<uint256, CBlock> known;
};

struct Utxo {
    CTxOut out;
    bool coinbase{false};
};

CTxOut FuzzOutput(FuzzedDataProvider& fdp)
{
    return CTxOut{fdp.ConsumeIntegralInRange<CAmount>(0, MAX_MONEY / 64), fdp.ConsumeBool() ? WATCHED : OTHER};
}

/** Replace blocks from `fork` on with `count` fuzzed blocks. No output is spent twice. */
void Extend(FuzzChain& chain, FuzzedDataProvider& fdp, size_t fork, size_t count, uint32_t epoch)
{
    chain.blocks.resize(std::min(fork, chain.blocks.size()));
    chain.filter_headers.resize(chain.blocks.size());
    chain.filters.resize(chain.blocks.size());
    std::map<COutPoint, Utxo> utxos;
    for (const CBlock& block : chain.blocks) {
        for (const auto& tx : block.vtx) {
            for (const CTxIn& in : tx->vin) utxos.erase(in.prevout);
            for (uint32_t i = 0; i < tx->vout.size(); ++i) utxos[COutPoint{tx->GetHash(), i}] = Utxo{tx->vout[i], tx->IsCoinBase()};
        }
    }
    for (size_t n = 0; n < count; ++n) {
        const int height = static_cast<int>(chain.blocks.size());
        CBlock block;
        block.nVersion = 1;
        block.hashPrevBlock = height == 0 ? uint256{} : chain.blocks.back().GetHash();
        block.nTime = 1700000000 + height;
        CBlockUndo undo;

        CMutableTransaction coinbase;
        coinbase.vin.resize(1);
        coinbase.vin[0].prevout.SetNull();
        coinbase.vin[0].scriptSig = CScript() << height << static_cast<int64_t>(epoch);
        LIMITED_WHILE(fdp.ConsumeBool(), 3) coinbase.vout.push_back(FuzzOutput(fdp));
        if (coinbase.vout.empty()) coinbase.vout.push_back(CTxOut{0, OTHER});
        block.vtx.push_back(MakeTransactionRef(coinbase));
        const Txid coinbase_id = block.vtx.back()->GetHash();
        for (uint32_t i = 0; i < coinbase.vout.size(); ++i) utxos[COutPoint{coinbase_id, i}] = Utxo{coinbase.vout[i], true};

        LIMITED_WHILE(fdp.ConsumeBool(), 3)
        {
            CMutableTransaction tx;
            CTxUndo tx_undo;
            LIMITED_WHILE(tx.vin.empty() || fdp.ConsumeBool(), 2)
            {
                CTxIn in;
                if (!utxos.empty() && fdp.ConsumeBool()) {
                    auto it = utxos.begin();
                    std::advance(it, fdp.ConsumeIntegralInRange<size_t>(0, utxos.size() - 1));
                    in.prevout = it->first;
                    tx_undo.vprevout.emplace_back(it->second.out, height, it->second.coinbase);
                    utxos.erase(it);
                } else {
                    // A coin this watch never saw, with a txid no other input uses.
                    HashWriter h{};
                    h << epoch << height << static_cast<uint64_t>(block.vtx.size()) << static_cast<uint64_t>(tx.vin.size());
                    in.prevout = COutPoint{Txid::FromUint256(h.GetHash()), 0};
                    tx_undo.vprevout.emplace_back(CTxOut{0, OTHER}, 0, false);
                }
                tx.vin.push_back(in);
            }
            LIMITED_WHILE(fdp.ConsumeBool(), 3) tx.vout.push_back(FuzzOutput(fdp));
            block.vtx.push_back(MakeTransactionRef(tx));
            undo.vtxundo.push_back(std::move(tx_undo));
            const Txid txid = block.vtx.back()->GetHash();
            for (uint32_t i = 0; i < tx.vout.size(); ++i) utxos[COutPoint{txid, i}] = Utxo{tx.vout[i], false};
        }

        // The header commits to the transactions, as on a real chain.
        block.hashMerkleRoot = BlockMerkleRoot(block);
        const BlockFilter filter(BlockFilterType::BASIC, block, undo);
        const uint256 prev_header = height == 0 ? uint256{} : chain.filter_headers.back();
        chain.filter_headers.push_back(filter.ComputeHeader(prev_header));
        chain.filters.push_back(filter.GetEncodedFilter());
        chain.known[block.GetHash()] = block;
        chain.blocks.push_back(std::move(block));
    }
}

/** Unspent watched value created at or after `start`, as the watch should report it. */
CAmount ExpectedTotal(const FuzzChain& chain, int start)
{
    std::map<COutPoint, CAmount> open;
    for (size_t h = static_cast<size_t>(std::max(start, 0)); h < chain.blocks.size(); ++h) {
        for (const auto& tx : chain.blocks[h].vtx) {
            for (const CTxIn& in : tx->vin) open.erase(in.prevout);
            for (uint32_t i = 0; i < tx->vout.size(); ++i) {
                if (tx->vout[i].scriptPubKey == WATCHED) open[COutPoint{tx->GetHash(), i}] = tx->vout[i].nValue;
            }
        }
    }
    CAmount total{0};
    for (const auto& item : open) total += item.second;
    return total;
}

int FindHeight(const FuzzChain& chain, const std::string& hex)
{
    const auto hash = uint256::FromHex(hex);
    if (!hash) throw std::runtime_error("Block not found");
    for (size_t h = 0; h < chain.blocks.size(); ++h) {
        if (chain.blocks[h].GetHash() == *hash) return static_cast<int>(h);
    }
    return -1;
}

/** Answer as a node would for the active chain. A dishonest node sometimes answers anything. */
UniValue Answer(const FuzzChain& chain, FuzzedDataProvider& fdp, bool dishonest, const std::string& method,
                const std::vector<std::string>& args)
{
    if (dishonest && fdp.ConsumeBool()) {
        if (fdp.ConsumeBool()) throw std::runtime_error("RPC error");
        UniValue junk;
        if (!junk.read(fdp.ConsumeRandomLengthString(256))) junk = UniValue(fdp.ConsumeIntegral<int64_t>());
        return junk;
    }
    if (method == "getblockcount") return UniValue(static_cast<int64_t>(chain.blocks.size()) - 1);
    if (method == "getblockhash") {
        int64_t height{-1};
        if (args.size() != 1 || !ParseInt64(args[0], &height) || height < 0 ||
            height >= static_cast<int64_t>(chain.blocks.size())) {
            throw std::runtime_error("Block height out of range");
        }
        return UniValue(chain.blocks[static_cast<size_t>(height)].GetHash().GetHex());
    }
    if (args.empty()) throw std::runtime_error("missing argument");
    const auto hash = uint256::FromHex(args[0]);
    const auto known = hash ? chain.known.find(*hash) : chain.known.end();
    if (known == chain.known.end()) throw std::runtime_error("Block not found");
    const CBlock& block = known->second;
    if (method == "getblockheader") {
        UniValue header(UniValue::VOBJ);
        header.pushKV("hash", block.GetHash().GetHex());
        if (!block.hashPrevBlock.IsNull()) header.pushKV("previousblockhash", block.hashPrevBlock.GetHex());
        return header;
    }
    const int height = FindHeight(chain, args[0]);
    if (method == "getblockfilter") {
        if (height < 0) throw std::runtime_error("Filter not found");
        UniValue result(UniValue::VOBJ);
        result.pushKV("filter", HexStr(chain.filters[static_cast<size_t>(height)]));
        result.pushKV("header", chain.filter_headers[static_cast<size_t>(height)].GetHex());
        return result;
    }
    if (method == "getblock") {
        DataStream stream;
        stream << TX_WITH_WITNESS(block);
        return UniValue(HexStr(stream));
    }
    throw std::runtime_error("Method not found");
}

} // namespace

// The watch file: Load must refuse what it cannot fully check, and whatever it
// accepts must report sane values and survive Save and Load unchanged.
FUZZ_TARGET(lightwatch_snapshot, .init = initialize_lightwatch)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshDir();
    const fs::path path = dir / "watch.dat";
    PutFile(path, fdp.ConsumeRandomLengthString(1 << 16));

    LightWatch watch;
    std::string error;
    if (!watch.Load(fs::PathToString(path), error)) {
        Assert(error == "BTX_LIGHTWATCH_IO");
        return;
    }
    const int chain_height = fdp.ConsumeIntegralInRange<int>(-1, 1 << 30);
    const LightWatchStatus status = watch.Status(chain_height);
    Assert(status.blocks_behind >= 0);
    Assert(!status.ready || status.wallet_height == chain_height);
    const LightWatchAmount amount = watch.BalanceAt(fdp.ConsumeIntegralInRange<int>(-1, 1 << 30));
    if (amount.ready) Assert(MoneyRange(amount.amount) && MoneyRange(amount.immature));
    AssertSaveRoundTrip(watch, dir);
    if (watch.Cursor() >= watch.StartHeight()) {
        // A reorg rewinds the watch. The rewound state is saved the same way.
        watch.RewindTo(fdp.ConsumeIntegralInRange<int>(watch.StartHeight() - 1, watch.Cursor()));
        AssertSaveRoundTrip(watch, dir);
    }
}

// Sync against a node serving a fuzzed chain, then a fuzzed reorg. Against an
// honest node, the reported total is the unspent watched value; against any
// node, the watch never reaches a state it cannot save and load.
FUZZ_TARGET(lightwatch_sync, .init = initialize_lightwatch)
{
    SeedRandomStateForTest(SeedRand::ZEROS);
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const fs::path dir = FreshDir();
    const bool dishonest = fdp.ConsumeBool();

    LightWatch watch;
    std::string error;
    Assert(watch.AddDescriptor("raw(51)", error));
    FuzzChain chain;
    Extend(chain, fdp, 0, fdp.ConsumeIntegralInRange<size_t>(1, 12), 0);
    const int start = fdp.ConsumeIntegralInRange<int>(0, static_cast<int>(chain.blocks.size()));
    watch.SetStartHeight(start);

    unsigned calls{0};
    const auto rpc = [&](const std::string& method, const std::vector<std::string>& args) -> UniValue {
        if (++calls > 2000) throw std::runtime_error("too many calls");
        return Answer(chain, fdp, dishonest, method, args);
    };

    LIMITED_WHILE(true, 3)
    {
        bool synced{false};
        error.clear();
        std::string thrown;
        try {
            synced = watch.Sync(rpc, error);
        } catch (const std::exception& e) {
            // btx-cli reports the RPC error and exits.
            thrown = e.what();
        }
        AssertSaveRoundTrip(watch, dir);
        const int tip = static_cast<int>(chain.blocks.size()) - 1;
        if (!dishonest) {
            if (!synced) std::fprintf(stderr, "lightwatch_sync: honest sync failed: error=%s thrown=%s tip=%d start=%d cursor=%d\n",
                                      error.c_str(), thrown.c_str(), tip, start, watch.Cursor());
            Assert(synced);
            if (tip >= start) {
                Assert(watch.Cursor() == tip);
            } else {
                // Nothing to walk yet: the cursor stays below the start height.
                Assert(watch.Cursor() < start);
            }
            const CAmount expected = ExpectedTotal(chain, start);
            const LightWatchAmount amount = watch.BalanceAt(tip);
            if (tip >= start && MoneyRange(expected)) {
                Assert(amount.ready);
                if (amount.amount + amount.immature != expected) {
                    std::fprintf(stderr, "lightwatch_sync: total %lld + %lld != expected %lld (tip=%d start=%d)\n",
                                 (long long)amount.amount, (long long)amount.immature, (long long)expected, tip, start);
                }
                Assert(amount.amount + amount.immature == expected);
                Assert(watch.IsCurrentAt(tip, tip, rpc));
            }
        }
        if (fdp.remaining_bytes() == 0) break;
        // A reorg: the active chain from `fork` on is replaced, maybe by a shorter one.
        const size_t fork = fdp.ConsumeIntegralInRange<size_t>(0, chain.blocks.size());
        Extend(chain, fdp, fork, fdp.ConsumeIntegralInRange<size_t>(fork == 0 ? 1 : 0, 6), calls + 1);
    }
}
