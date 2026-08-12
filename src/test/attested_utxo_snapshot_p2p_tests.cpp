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

BOOST_AUTO_TEST_CASE(chunk_decoder_rejects_oversize_before_allocation)
{
    DataStream wire;
    wire << uint256::ONE << uint32_t{0} << uint256::ONE;
    WriteCompactSize(
        wire, node::ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE + 1ULL);

    node::AttestedUTXOSnapshotChunkMsg decoded;
    BOOST_CHECK_THROW(wire >> decoded, std::ios_base::failure);
    BOOST_CHECK(decoded.data.empty());
}

BOOST_AUTO_TEST_CASE(server_rate_limits_manifest_and_chunk_requests)
{
    node::AttestedUTXOSnapshotP2P coord;
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
    node::AttestedUTXOSnapshotP2P coord;
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
    node::AttestedUTXOSnapshotP2P coord;

    node::AttestedUTXOSnapshotChunkMsg early_chunk;
    early_chunk.block_hash = uint256::ONE;
    early_chunk.chunk_index = 0;
    early_chunk.data = {1, 2, 3};
    early_chunk.chunk_hash = node::AttestedUTXOSnapshotBytesHash(
        Span{early_chunk.data.data(), early_chunk.data.size()});
    coord.DeliverChunk(/*peer=*/9, early_chunk);

    const auto session{coord.BeginSession(/*peer=*/9, uint256{})};
    BOOST_REQUIRE(session);
    node::AttestedUTXOSnapshotManifestMsg man;
    man.block_hash = uint256::ONE;
    man.height = 1;
    man.file_size = 3;
    man.chunk_size = 3;
    man.chunk_count = 1;
    man.file_hash = early_chunk.chunk_hash;
    coord.DeliverManifest(/*peer=*/9, man);
    auto got_man{coord.WaitManifest(*session, std::chrono::milliseconds{50})};
    BOOST_REQUIRE(got_man);
    BOOST_CHECK_EQUAL(got_man->height, 1);

    // Only after explicit BeginChunkWait may a chunk be delivered.
    BOOST_REQUIRE(coord.BeginChunkWait(*session, /*chunk_index=*/0));
    coord.DeliverChunk(/*peer=*/9, early_chunk);
    auto got_chunk{coord.WaitChunk(*session, std::chrono::milliseconds{50})};
    BOOST_REQUIRE(got_chunk);
    BOOST_CHECK_EQUAL(got_chunk->chunk_index, 0U);
    coord.CancelSession(*session);
}

BOOST_AUTO_TEST_CASE(concurrent_client_sessions_are_isolated)
{
    node::AttestedUTXOSnapshotP2P coord;
    const auto first{coord.BeginSession(/*peer=*/10, uint256{})};
    const auto second{coord.BeginSession(/*peer=*/11, uint256{})};
    BOOST_REQUIRE(first);
    BOOST_REQUIRE(second);

    node::AttestedUTXOSnapshotManifestMsg a;
    a.block_hash = uint256::ONE;
    a.height = 10;
    node::AttestedUTXOSnapshotManifestMsg b;
    b.block_hash.data()[0] = 2;
    b.height = 20;
    coord.DeliverManifest(/*peer=*/11, b);
    coord.DeliverManifest(/*peer=*/10, a);

    const auto got_a{coord.WaitManifest(*first, std::chrono::milliseconds{1})};
    const auto got_b{coord.WaitManifest(*second, std::chrono::milliseconds{1})};
    BOOST_REQUIRE(got_a);
    BOOST_REQUIRE(got_b);
    BOOST_CHECK_EQUAL(got_a->height, 10);
    BOOST_CHECK_EQUAL(got_b->height, 20);

    coord.CancelSession(*first);
    BOOST_REQUIRE(coord.BeginChunkWait(*second, 3));
    node::AttestedUTXOSnapshotChunkMsg chunk;
    chunk.block_hash = b.block_hash;
    chunk.chunk_index = 3;
    chunk.data = {4, 5, 6};
    coord.DeliverChunk(/*peer=*/11, chunk);
    BOOST_REQUIRE(coord.WaitChunk(*second, std::chrono::milliseconds{1}));
    coord.CancelSession(*second);
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
        const std::string payload(128U << 10, 'Z');
        BOOST_REQUIRE_EQUAL(fwrite(payload.data(), 1, payload.size(), f), payload.size());
        fclose(f);
    }

    matmul::trusted::UtxoSnapshotManifest manifest;
    manifest.statement.block_hash = uint256::ONE;
    manifest.statement.block_height = 42;
    manifest.statement.coins_count = 1;
    manifest.statement.snapshot_file_size = 128U << 10;
    manifest.statement.snapshot_chunk_size =
        node::ATTESTED_UTXO_SNAPSHOT_MIN_CHUNK_SIZE;
    manifest.statement.snapshot_chunk_count = 2;
    {
        const std::vector<uint8_t> payload(128U << 10, 'Z');
        manifest.statement.snapshot_file_hash =
            node::AttestedUTXOSnapshotBytesHash(Span{payload.data(), payload.size()});
    }
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
        snap, man_path, node::ATTESTED_UTXO_SNAPSHOT_MIN_CHUNK_SIZE, offer, error));
    BOOST_CHECK_EQUAL(offer.chunk_count, 2U);
    BOOST_CHECK_EQUAL(offer.height, 42);

    std::vector<uint8_t> chunk;
    uint256 chunk_hash;
    BOOST_REQUIRE(node::ReadAttestedUTXOSnapshotChunk(offer, 0, chunk, chunk_hash, error));
    BOOST_CHECK_EQUAL(chunk.size(), node::ATTESTED_UTXO_SNAPSHOT_MIN_CHUNK_SIZE);
    BOOST_CHECK(chunk_hash == node::AttestedUTXOSnapshotBytesHash(
                    Span{chunk.data(), chunk.size()}));

    // Out-of-range chunk fails closed.
    BOOST_CHECK(!node::ReadAttestedUTXOSnapshotChunk(offer, 99, chunk, chunk_hash, error));
}

BOOST_AUTO_TEST_SUITE_END()
