// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <lightwatch.h>

#include <addresstype.h>
#include <blockfilter.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <core_io.h>
#include <key.h>
#include <key_io.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/transaction_identifier.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct MadeBlock {
    CBlock block;
    uint256 hash;
    uint256 prev;
    std::vector<unsigned char> encoded;
    uint256 header;
    uint256 txid;
};

MadeBlock MakeBlock(const uint256& prev, const uint256& filter_prev, const std::vector<CTxOut>& outputs,
                    const std::vector<CTxIn>& inputs, const GCSFilter::ElementSet& elements)
{
    CMutableTransaction mtx;
    mtx.version = 1;
    mtx.vin = inputs;
    if (inputs.empty()) mtx.vin.emplace_back(CTxIn(Txid{}, 0));
    mtx.vout = outputs;
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock = prev;
    block.nTime = 1296688602;
    block.nBits = 0x207fffff;
    block.vtx.push_back(MakeTransactionRef(CTransaction(mtx)));
    block.hashMerkleRoot = BlockMerkleRoot(block);

    MadeBlock made;
    made.block = std::move(block);
    made.hash = made.block.GetHash();
    made.prev = prev;
    made.txid = made.block.vtx[0]->GetHash();
    GCSFilter gcs({made.hash.GetUint64(0), made.hash.GetUint64(1), BASIC_FILTER_P, BASIC_FILTER_M}, elements);
    made.encoded = gcs.GetEncoded();
    BlockFilter filter(BlockFilterType::BASIC, made.hash, made.encoded, /*skip_decode_check=*/false);
    made.header = filter.ComputeHeader(filter_prev);
    return made;
}

GCSFilter::Element Element(const CScript& script)
{
    return GCSFilter::Element(script.begin(), script.end());
}

std::string PubkeyPkh(const CPubKey& pubkey)
{
    return "pkh(" + HexStr(pubkey) + ")";
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(lightwatch_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(lightwatch_refuses_private_and_withholds_unknown)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const CScript script = GetScriptForDestination(PKHash(key.GetPubKey()));
    const CScript other = GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey()));

    LightWatch watch;
    std::string error;
    BOOST_CHECK(!watch.AddDescriptor("pkh(" + EncodeSecret(key) + ")", error));
    BOOST_CHECK_EQUAL(error, "BTX_LIGHTWATCH_PRIVATE");
    BOOST_REQUIRE(watch.AddDescriptor(PubkeyPkh(key.GetPubKey()), error));

    const MadeBlock miss = MakeBlock(uint256{}, uint256{}, {CTxOut(10 * COIN, other)}, {}, {});
    BOOST_CHECK(watch.ApplyFilter(0, miss.hash, miss.prev, miss.encoded, miss.header, nullptr, error) == LightWatch::Step::APPLIED);
    const LightWatchAmount unknown = watch.BalanceAt(1);
    BOOST_CHECK(!unknown.ready);
    const LightWatchStatus behind = watch.Status(1);
    BOOST_CHECK(!behind.ready);
    BOOST_CHECK(!behind.shielded_foreign_watch);
    BOOST_CHECK(behind.shielded_omitted);
    BOOST_CHECK_EQUAL(behind.blocks_behind, 1);

    const MadeBlock hit = MakeBlock(miss.hash, miss.header, {CTxOut(10 * COIN, script)}, {}, {Element(script)});
    BOOST_CHECK(watch.ApplyFilter(1, hit.hash, hit.prev, hit.encoded, hit.header, nullptr, error) == LightWatch::Step::NEED_BLOCK);
    BOOST_CHECK_EQUAL(watch.Cursor(), 0);
    BOOST_CHECK(watch.ApplyFilter(1, hit.hash, hit.prev, hit.encoded, hit.header, &hit.block, error) == LightWatch::Step::APPLIED);

    const LightWatchAmount at_one = watch.BalanceAt(1);
    BOOST_CHECK(at_one.ready);
    BOOST_CHECK_EQUAL(at_one.amount, 10 * COIN);
    BOOST_CHECK_EQUAL(at_one.immature, 0);

    CTxIn coinbase_in;
    coinbase_in.prevout.SetNull();
    const MadeBlock mined = MakeBlock(hit.hash, hit.header, {CTxOut(3 * COIN, script)}, {coinbase_in}, {Element(script)});
    BOOST_REQUIRE(watch.ApplyFilter(2, mined.hash, mined.prev, mined.encoded, mined.header, &mined.block, error) == LightWatch::Step::APPLIED);
    const LightWatchAmount with_coinbase = watch.BalanceAt(2);
    BOOST_CHECK(with_coinbase.ready);
    BOOST_CHECK_EQUAL(with_coinbase.amount, 10 * COIN);
    BOOST_CHECK_EQUAL(with_coinbase.immature, 3 * COIN);
    BOOST_CHECK(watch.Status(2).ready);
    BOOST_CHECK_EQUAL(watch.Status(2).fetched_total, 2U);

    uint256 bad_header = mined.header;
    bad_header.SetNull();
    const MadeBlock next = MakeBlock(mined.hash, mined.header, {CTxOut(COIN, other)}, {}, {});
    BOOST_CHECK(watch.ApplyFilter(3, next.hash, next.prev, next.encoded, bad_header, nullptr, error) == LightWatch::Step::REJECTED);
    BOOST_CHECK_EQUAL(error, "BTX_FILTER_HEADER");
    BOOST_CHECK_EQUAL(watch.Cursor(), 2);
    BOOST_CHECK(!watch.BalanceAt(3).ready);
    BOOST_CHECK_EQUAL(watch.BalanceAt(2).amount, 10 * COIN);
    BOOST_CHECK_EQUAL(watch.BalanceAt(2).immature, 3 * COIN);
}

BOOST_AUTO_TEST_CASE(lightwatch_false_positive_spend_rewind_and_save)
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    const CScript script = GetScriptForDestination(PKHash(key.GetPubKey()));
    const CScript sink = GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey()));

    LightWatch watch;
    std::string error;
    BOOST_REQUIRE(watch.AddDescriptor(PubkeyPkh(key.GetPubKey()), error));

    const MadeBlock decoy = MakeBlock(uint256{}, uint256{}, {CTxOut(COIN, sink)}, {}, {Element(script)});
    BOOST_CHECK(watch.ApplyFilter(0, decoy.hash, decoy.prev, decoy.encoded, decoy.header, &decoy.block, error) == LightWatch::Step::APPLIED);
    const LightWatchAmount after_decoy = watch.BalanceAt(0);
    BOOST_CHECK(after_decoy.ready);
    BOOST_CHECK_EQUAL(after_decoy.amount, 0);
    BOOST_CHECK_EQUAL(watch.Status(0).fetched_total, 1U);

    const MadeBlock paid = MakeBlock(decoy.hash, decoy.header, {CTxOut(7 * COIN, script)}, {}, {Element(script)});
    BOOST_REQUIRE(watch.ApplyFilter(1, paid.hash, paid.prev, paid.encoded, paid.header, &paid.block, error) == LightWatch::Step::APPLIED);
    BOOST_CHECK_EQUAL(watch.BalanceAt(1).amount, 7 * COIN);

    CTxIn spend_in(Txid::FromUint256(paid.txid), 0);
    const MadeBlock spent = MakeBlock(paid.hash, paid.header, {CTxOut(6 * COIN, sink)}, {spend_in}, {Element(script)});
    BOOST_REQUIRE(watch.ApplyFilter(2, spent.hash, spent.prev, spent.encoded, spent.header, &spent.block, error) == LightWatch::Step::APPLIED);
    BOOST_CHECK_EQUAL(watch.BalanceAt(2).amount, 0);
    BOOST_CHECK_EQUAL(watch.BalanceAt(1).amount, 7 * COIN);

    watch.RewindTo(1);
    BOOST_CHECK_EQUAL(watch.Cursor(), 1);
    BOOST_CHECK_EQUAL(watch.BalanceAt(1).amount, 7 * COIN);
    BOOST_CHECK(!watch.BalanceAt(2).ready);
    BOOST_CHECK(!watch.FilterReady());

    const std::string path = PathToString(m_path_root / "lightwatch.txt");
    // Filter anchor was cleared by rewind. Mark it ready again by applying nothing:
    // Save the caught-up watch instead.
    LightWatch caught = watch;
    (void)caught;
    LightWatch fresh;
    BOOST_REQUIRE(fresh.AddDescriptor(PubkeyPkh(key.GetPubKey()), error));
    BOOST_REQUIRE(fresh.ApplyFilter(0, decoy.hash, decoy.prev, decoy.encoded, decoy.header, &decoy.block, error) == LightWatch::Step::APPLIED);
    BOOST_REQUIRE(fresh.ApplyFilter(1, paid.hash, paid.prev, paid.encoded, paid.header, &paid.block, error) == LightWatch::Step::APPLIED);
    BOOST_REQUIRE(fresh.Save(path, error));
    LightWatch loaded;
    BOOST_REQUIRE(loaded.Load(path, error));
    BOOST_CHECK_EQUAL(loaded.Cursor(), 1);
    BOOST_CHECK_EQUAL(loaded.BalanceAt(1).amount, 7 * COIN);
    BOOST_CHECK(loaded.Status(1).ready);
    BOOST_CHECK(!loaded.Status(1).shielded_foreign_watch);
}

BOOST_AUTO_TEST_CASE(lightwatch_sync_reorg_and_chain_binding)
{
    const CScript script = GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey()));
    CTxIn coinbase;
    coinbase.prevout.SetNull();
    const MadeBlock genesis = MakeBlock({}, {}, {}, {coinbase}, {});
    const MadeBlock paid = MakeBlock(genesis.hash, genesis.header, {CTxOut(7 * COIN, script)}, {coinbase}, {Element(script)});
    const MadeBlock replacement = MakeBlock(genesis.hash, genesis.header, {CTxOut(3 * COIN, script)}, {coinbase}, {Element(script)});
    std::vector<MadeBlock> chain{genesis, paid};
    const auto rpc = [&](const std::string& method, const std::vector<std::string>& args) -> UniValue {
        if (method == "getblockcount") return UniValue(static_cast<int>(chain.size()) - 1);
        if (method == "getblockhash") {
            // at() deliberately throws if Sync queries above the shortened tip.
            return UniValue(chain.at(std::stoi(args.at(0))).hash.GetHex());
        }
        for (const MadeBlock& block : chain) {
            if (block.hash.GetHex() != args.at(0)) continue;
            UniValue result(UniValue::VOBJ);
            if (method == "getblockheader") {
                result.pushKV("previousblockhash", block.prev.GetHex());
            } else if (method == "getblockfilter") {
                result.pushKV("filter", HexStr(block.encoded));
                result.pushKV("header", block.header.GetHex());
            } else if (method == "getblock") {
                DataStream raw;
                raw << TX_WITH_WITNESS(block.block);
                return UniValue(HexStr(raw));
            } else {
                throw std::runtime_error("unexpected RPC");
            }
            return result;
        }
        throw std::runtime_error("unknown block");
    };
    LightWatch watch;
    std::string error;
    BOOST_REQUIRE(watch.AddDescriptor("raw(" + HexStr(script) + ")", error));
    BOOST_REQUIRE_MESSAGE(watch.Sync(rpc, error), error);
    BOOST_CHECK(watch.IsCurrentAt(1, 1, rpc));
    BOOST_CHECK_EQUAL(watch.BalanceAt(1).immature, 7 * COIN);

    const std::string path = PathToString(m_path_root / "reorg-watch.txt");
    BOOST_REQUIRE(watch.Save(path, error));
    LightWatch loaded;
    BOOST_REQUIRE(loaded.Load(path, error));
    chain.pop_back();
    BOOST_CHECK(!loaded.IsCurrentAt(1, 0, rpc));
    BOOST_CHECK(loaded.IsCurrentAt(0, 0, rpc));
    BOOST_REQUIRE_MESSAGE(loaded.Sync(rpc, error), error);
    BOOST_CHECK_EQUAL(loaded.Cursor(), 0);
    BOOST_CHECK(!loaded.BalanceAt(1).ready);
    BOOST_REQUIRE(loaded.Save(path, error));
    BOOST_REQUIRE(loaded.Load(path, error));
    chain.push_back(replacement);
    BOOST_REQUIRE_MESSAGE(loaded.Sync(rpc, error), error);
    BOOST_CHECK_EQUAL(loaded.BalanceAt(1).immature, 3 * COIN);

    // Same-height replacement must invalidate a saved amount even though the
    // cursor is already at the tip; the unchanged prefix remains queryable.
    BOOST_CHECK(!watch.IsCurrentAt(1, 1, rpc));
    BOOST_CHECK(watch.IsCurrentAt(0, 1, rpc));
    BOOST_REQUIRE_MESSAGE(watch.Sync(rpc, error), error);
    BOOST_CHECK(watch.IsCurrentAt(1, 1, rpc));
    BOOST_CHECK_EQUAL(watch.BalanceAt(1).immature, 3 * COIN);
    const auto unavailable = [](const std::string&, const std::vector<std::string>&) -> UniValue {
        throw std::runtime_error("RPC unavailable");
    };
    BOOST_CHECK_THROW(watch.IsCurrentAt(1, 1, unavailable), std::runtime_error);

    // A reorg below a nonzero starting height clears the anchor, and a later
    // resync must reacquire it before scanning the replacement branch.
    LightWatch late;
    late.SetStartHeight(1);
    BOOST_REQUIRE(late.AddDescriptor("raw(" + HexStr(script) + ")", error, false));
    BOOST_REQUIRE_MESSAGE(late.Sync(rpc, error), error);
    chain.pop_back();
    BOOST_REQUIRE_MESSAGE(late.Sync(rpc, error), error);
    BOOST_CHECK(!late.IsCurrentAt(1, 0, rpc));
    BOOST_CHECK(!late.BalanceAt(0).ready);
    chain.push_back(paid);
    BOOST_REQUIRE_MESSAGE(late.Sync(rpc, error), error);
    BOOST_CHECK_EQUAL(late.BalanceAt(1).immature, 7 * COIN);
}

BOOST_AUTO_TEST_CASE(lightwatch_truncated_event_is_not_ready_and_reorg_waits_for_sync)
{
    const CScript script = GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey()));
    CTxIn coinbase;
    coinbase.prevout.SetNull();
    const MadeBlock genesis = MakeBlock({}, {}, {}, {coinbase}, {});
    const MadeBlock paid = MakeBlock(genesis.hash, genesis.header, {CTxOut(7 * COIN, script)}, {coinbase}, {Element(script)});

    LightWatch watch;
    std::string error;
    BOOST_REQUIRE(watch.AddDescriptor("raw(" + HexStr(script) + ")", error));
    BOOST_REQUIRE(watch.ApplyFilter(0, genesis.hash, genesis.prev, genesis.encoded, genesis.header, nullptr, error) == LightWatch::Step::APPLIED);
    BOOST_REQUIRE(watch.ApplyFilter(1, paid.hash, paid.prev, paid.encoded, paid.header, &paid.block, error) == LightWatch::Step::APPLIED);
    BOOST_CHECK_EQUAL(watch.BalanceAt(1).immature, 7 * COIN);

    const std::string path = PathToString(m_path_root / "lightwatch-trunc.txt");
    BOOST_REQUIRE(watch.Save(path, error));
    std::string text;
    {
        std::ifstream input(path);
        BOOST_REQUIRE(input);
        std::string line;
        while (std::getline(input, line)) {
            text += line;
            text.push_back('\n');
        }
    }
    const auto event_at = text.find("\nevent ");
    BOOST_REQUIRE(event_at != std::string::npos);
    const auto event_end = text.find('\n', event_at + 1);
    BOOST_REQUIRE(event_end != std::string::npos);
    const auto cut = event_at + (event_end - event_at) / 2;
    BOOST_REQUIRE(cut > event_at + std::string("\nevent ").size());
    BOOST_REQUIRE(cut < event_end);
    const std::string torn = text.substr(0, cut);

    // An interrupted replacement leaves a partial temp beside the complete file.
    {
        std::ofstream partial(path + ".tmp", std::ios::trunc);
        BOOST_REQUIRE(partial);
        partial << torn;
    }
    LightWatch kept;
    BOOST_REQUIRE(kept.Load(path, error));
    const LightWatchAmount loaded = kept.BalanceAt(1);
    BOOST_CHECK(loaded.ready);
    BOOST_CHECK_EQUAL(loaded.immature, 7 * COIN);
    std::remove((path + ".tmp").c_str());

    {
        std::ofstream damaged_file(path, std::ios::trunc);
        BOOST_REQUIRE(damaged_file);
        damaged_file << torn;
    }
    LightWatch damaged;
    BOOST_CHECK(!damaged.Load(path, error));
    BOOST_CHECK_EQUAL(error, "BTX_LIGHTWATCH_IO");
    const LightWatchAmount hidden = damaged.BalanceAt(1);
    BOOST_CHECK(!hidden.ready);
    BOOST_CHECK_EQUAL(hidden.amount, 0);
    BOOST_CHECK_EQUAL(hidden.immature, 0);
    BOOST_CHECK_EQUAL(damaged.Cursor(), -1);
    // The damaged file is refused. The snapshot already loaded stays put.
    BOOST_CHECK(!kept.Load(path, error));
    BOOST_CHECK(kept.BalanceAt(1).ready);
    BOOST_CHECK_EQUAL(kept.BalanceAt(1).immature, 7 * COIN);

    const MadeBlock replacement = MakeBlock(genesis.hash, genesis.header, {CTxOut(3 * COIN, script)}, {coinbase}, {Element(script)});
    std::vector<MadeBlock> chain{genesis, paid};
    const auto rpc = [&](const std::string& method, const std::vector<std::string>& args) -> UniValue {
        if (method == "getblockcount") return UniValue(static_cast<int>(chain.size()) - 1);
        if (method == "getblockhash") {
            return UniValue(chain.at(std::stoi(args.at(0))).hash.GetHex());
        }
        for (const MadeBlock& block : chain) {
            if (block.hash.GetHex() != args.at(0)) continue;
            UniValue result(UniValue::VOBJ);
            if (method == "getblockheader") {
                result.pushKV("previousblockhash", block.prev.GetHex());
            } else if (method == "getblockfilter") {
                result.pushKV("filter", HexStr(block.encoded));
                result.pushKV("header", block.header.GetHex());
            } else if (method == "getblock") {
                DataStream raw;
                raw << TX_WITH_WITNESS(block.block);
                return UniValue(HexStr(raw));
            } else {
                throw std::runtime_error("unexpected RPC");
            }
            return result;
        }
        throw std::runtime_error("unknown block");
    };
    LightWatch bound;
    BOOST_REQUIRE(bound.AddDescriptor("raw(" + HexStr(script) + ")", error));
    BOOST_REQUIRE_MESSAGE(bound.Sync(rpc, error), error);
    BOOST_CHECK(bound.IsCurrentAt(1, 1, rpc));
    BOOST_CHECK_EQUAL(bound.BalanceAt(1).immature, 7 * COIN);
    chain[1] = replacement;
    BOOST_CHECK(!bound.IsCurrentAt(1, 1, rpc));
    BOOST_CHECK(bound.IsCurrentAt(0, 1, rpc));
    BOOST_REQUIRE_MESSAGE(bound.Sync(rpc, error), error);
    BOOST_CHECK(bound.IsCurrentAt(1, 1, rpc));
    BOOST_CHECK_EQUAL(bound.BalanceAt(1).immature, 3 * COIN);
}

BOOST_AUTO_TEST_CASE(lightwatch_file_cut_at_a_line_end_is_refused)
{
    const CScript script = GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey()));
    const CScript sink = GetScriptForDestination(PKHash(GenerateRandomKey().GetPubKey()));
    const MadeBlock decoy = MakeBlock(uint256{}, uint256{}, {CTxOut(COIN, sink)}, {}, {Element(script)});
    const MadeBlock paid = MakeBlock(decoy.hash, decoy.header, {CTxOut(7 * COIN, script)}, {}, {Element(script)});
    const MadeBlock spent = MakeBlock(paid.hash, paid.header, {CTxOut(6 * COIN, sink)},
                                      {CTxIn(Txid::FromUint256(paid.txid), 0)}, {Element(script)});

    LightWatch watch;
    std::string error;
    BOOST_REQUIRE(watch.AddDescriptor("raw(" + HexStr(script) + ")", error));
    BOOST_REQUIRE(watch.ApplyFilter(0, decoy.hash, decoy.prev, decoy.encoded, decoy.header, &decoy.block, error) == LightWatch::Step::APPLIED);
    BOOST_REQUIRE(watch.ApplyFilter(1, paid.hash, paid.prev, paid.encoded, paid.header, &paid.block, error) == LightWatch::Step::APPLIED);
    BOOST_REQUIRE(watch.ApplyFilter(2, spent.hash, spent.prev, spent.encoded, spent.header, &spent.block, error) == LightWatch::Step::APPLIED);
    BOOST_REQUIRE_EQUAL(watch.BalanceAt(1).amount, 7 * COIN);
    BOOST_REQUIRE_EQUAL(watch.BalanceAt(2).amount, 0);

    const std::string path = PathToString(m_path_root / "lightwatch-lines.txt");
    BOOST_REQUIRE(watch.Save(path, error));
    const auto read = [&]() {
        std::ifstream input(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    };
    const auto write = [&](const std::string& text) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << text;
    };
    const std::string text = read();
    BOOST_REQUIRE(!text.empty() && text.back() == '\n');

    // Every record before a line end is well formed, so a cut there used to
    // load: without the spend line the spent coin was a ready 7, and without
    // the credit line the coin was a ready 0.
    int cuts{0};
    for (std::size_t end = text.find('\n'); end != std::string::npos && end + 1 < text.size(); end = text.find('\n', end + 1)) {
        for (const std::size_t cut : {end, end + 1}) {
            write(text.substr(0, cut));
            LightWatch torn;
            BOOST_CHECK_MESSAGE(!torn.Load(path, error), "file cut at byte " << cut << " was loaded");
            BOOST_CHECK(!torn.BalanceAt(2).ready);
            ++cuts;
        }
    }
    BOOST_CHECK_GT(cuts, 10);

    // The trailer counts records, so a line missing from the middle is refused too.
    const std::size_t spend_line = text.find("\nevent 2 ");
    BOOST_REQUIRE(spend_line != std::string::npos);
    write(text.substr(0, spend_line) + text.substr(text.find('\n', spend_line + 1)));
    LightWatch missing;
    BOOST_CHECK(!missing.Load(path, error));

    // A version 1 file has no trailer. It is still read, and saving it writes version 2.
    std::string v1 = text.substr(0, text.rfind("end "));
    BOOST_REQUIRE_EQUAL(v1.rfind("btx-lightwatch 2\n", 0), 0U);
    v1.replace(0, std::string("btx-lightwatch 2").size(), "btx-lightwatch 1");
    write(v1);
    LightWatch old;
    BOOST_REQUIRE(old.Load(path, error));
    BOOST_CHECK_EQUAL(old.BalanceAt(1).amount, 7 * COIN);
    BOOST_CHECK_EQUAL(old.BalanceAt(2).amount, 0);
    BOOST_REQUIRE(old.Save(path, error));
    BOOST_CHECK(read() == text);
}

BOOST_AUTO_TEST_SUITE_END()
