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

#include <map>
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

BOOST_AUTO_TEST_SUITE_END()
