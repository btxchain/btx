// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <hash.h>
#include <node/attested_utxo_snapshot.h>
#include <node/attested_utxo_snapshot_p2p.h>
#include <span.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/fs_helpers.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstring>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(attested_utxo_snapshot_p2p_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(chunk_bytes_hash_detects_corruption)
{
    std::vector<uint8_t> data(1024, 0xab);
    const uint256 good{
        node::AttestedUTXOSnapshotBytesHash(Span{data.data(), data.size()})};
    data[10] ^= 0xff;
    const uint256 bad{
        node::AttestedUTXOSnapshotBytesHash(Span{data.data(), data.size()})};
    BOOST_CHECK(good != bad);
}

BOOST_AUTO_TEST_CASE(server_rate_limits_manifest_and_chunk_requests)
{
    auto& coord{node::AttestedUTXOSnapshotP2P::Get()};
    coord.ResetForTest();
    const auto now{GetTime<std::chrono::microseconds>()};
    const NodeId peer{7};

    size_t admitted{0};
    for (size_t i = 0; i < node::ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_REQ_PER_MIN + 2; ++i) {
        if (coord.AdmitManifestRequest(peer, now)) ++admitted;
    }
    BOOST_CHECK_EQUAL(admitted, node::ATTESTED_UTXO_SNAPSHOT_MAX_MANIFEST_REQ_PER_MIN);

    admitted = 0;
    for (size_t i = 0; i < node::ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_REQ_PER_SEC + 2; ++i) {
        if (coord.AdmitChunkRequest(peer, now)) {
            ++admitted;
            coord.ReleaseChunkTransfer(peer);
        }
    }
    BOOST_CHECK_EQUAL(admitted, node::ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_REQ_PER_SEC);
}

BOOST_AUTO_TEST_CASE(server_caps_concurrent_transfers)
{
    auto& coord{node::AttestedUTXOSnapshotP2P::Get()};
    coord.ResetForTest();
    const auto now{GetTime<std::chrono::microseconds>()};

    BOOST_CHECK(coord.AdmitChunkRequest(/*peer=*/1, now));
    BOOST_CHECK(coord.AdmitChunkRequest(/*peer=*/2, now));
    // Global cap is 2.
    BOOST_CHECK(!coord.AdmitChunkRequest(/*peer=*/3, now));
    // Per-peer cap is 1.
    BOOST_CHECK(!coord.AdmitChunkRequest(/*peer=*/1, now));

    coord.ReleaseChunkTransfer(/*peer=*/1);
    BOOST_CHECK(coord.AdmitChunkRequest(/*peer=*/3, now));
    coord.PeerDisconnected(/*peer=*/2);
    coord.PeerDisconnected(/*peer=*/3);
}

BOOST_AUTO_TEST_CASE(quorum_before_body_gate_is_enforced_by_fetch_ordering)
{
    // The fetch RPC verifies the manifest before requesting chunks. This unit
    // test locks the coordinator contract that DeliverChunk is ignored unless
    // a chunk wait was armed after a successful manifest wait.
    auto& coord{node::AttestedUTXOSnapshotP2P::Get()};
    coord.ResetForTest();

    node::AttestedUTXOSnapshotChunkMsg early_chunk;
    early_chunk.block_hash = uint256::ONE;
    early_chunk.chunk_index = 0;
    early_chunk.data = {1, 2, 3};
    early_chunk.chunk_hash = node::AttestedUTXOSnapshotBytesHash(
        Span{early_chunk.data.data(), early_chunk.data.size()});
    coord.DeliverChunk(/*peer=*/9, early_chunk);
    BOOST_CHECK(!coord.WaitChunk(std::chrono::milliseconds{1}).has_value());

    coord.BeginManifestWait(/*peer=*/9, uint256{});
    node::AttestedUTXOSnapshotManifestMsg man;
    man.block_hash = uint256::ONE;
    man.height = 1;
    man.file_size = 3;
    man.chunk_size = 3;
    man.chunk_count = 1;
    man.file_hash = early_chunk.chunk_hash;
    coord.DeliverManifest(/*peer=*/9, man);
    auto got_man{coord.WaitManifest(std::chrono::milliseconds{50})};
    BOOST_REQUIRE(got_man);
    BOOST_CHECK_EQUAL(got_man->height, 1);

    // Only after explicit BeginChunkWait may a chunk be delivered.
    coord.BeginChunkWait(/*peer=*/9, uint256::ONE, /*chunk_index=*/0);
    coord.DeliverChunk(/*peer=*/9, early_chunk);
    auto got_chunk{coord.WaitChunk(std::chrono::milliseconds{50})};
    BOOST_REQUIRE(got_chunk);
    BOOST_CHECK_EQUAL(got_chunk->chunk_index, 0U);
}

BOOST_AUTO_TEST_CASE(offer_roundtrip_chunk_read)
{
    const auto dir{m_args.GetDataDirBase() / "attested_offer"};
    fs::create_directories(dir);
    const fs::path snap{dir / "snap.dat"};
    const fs::path man_path{dir / "snap.manifest"};

    {
        FILE* f{fsbridge::fopen(snap, "wb")};
        BOOST_REQUIRE(f);
        const std::string payload(4096, 'Z');
        BOOST_REQUIRE_EQUAL(fwrite(payload.data(), 1, payload.size(), f), payload.size());
        fclose(f);
    }

    matmul::trusted::UtxoSnapshotManifest manifest;
    manifest.statement.block_hash = uint256::ONE;
    manifest.statement.block_height = 42;
    manifest.statement.coins_count = 1;
    manifest.signatures.push_back({});
    {
        FILE* f{fsbridge::fopen(man_path, "wb")};
        BOOST_REQUIRE(f);
        AutoFile a{f};
        a << manifest;
        // AutoFile requires an explicit fclose after write (streams.h).
        BOOST_REQUIRE_EQUAL(a.fclose(), 0);
    }

    node::AttestedUTXOSnapshotOffer offer;
    std::string error;
    BOOST_REQUIRE(node::BuildAttestedUTXOSnapshotOfferFromFiles(
        snap, man_path, /*chunk_size=*/1024, offer, error));
    BOOST_CHECK_EQUAL(offer.chunk_count, 4U);
    BOOST_CHECK_EQUAL(offer.height, 42);

    std::vector<uint8_t> chunk;
    uint256 chunk_hash;
    BOOST_REQUIRE(node::ReadAttestedUTXOSnapshotChunk(offer, 0, chunk, chunk_hash, error));
    BOOST_CHECK_EQUAL(chunk.size(), 1024U);
    BOOST_CHECK(chunk_hash == node::AttestedUTXOSnapshotBytesHash(
                    Span{chunk.data(), chunk.size()}));

    // Out-of-range chunk fails closed.
    BOOST_CHECK(!node::ReadAttestedUTXOSnapshotChunk(offer, 99, chunk, chunk_hash, error));
}

BOOST_AUTO_TEST_SUITE_END()
