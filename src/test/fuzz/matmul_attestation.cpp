// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <key.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <matmul/trusted_utxo_snapshot_attestation.h>
#include <node/attested_utxo_snapshot.h>
#include <node/attested_utxo_snapshot_p2p.h>
#include <pubkey.h>
#include <streams.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <uint256.h>
#include <util/check.h>

#include <chrono>
#include <cstdint>
#include <ios>
#include <optional>
#include <set>
#include <stdexcept>
#include <vector>

using namespace matmul::trusted;

namespace {

constexpr size_t KEY_POOL{8};
// Never destroyed: CKey frees through the locked-page pool, which can be torn
// down before ordinary globals at process exit.
std::vector<CKey>& g_keys{*new std::vector<CKey>};

void initialize_matmul_attestation()
{
    static ECC_Context ecc_context{};
    g_keys.clear();
    for (size_t i = 0; i < KEY_POOL; ++i) {
        unsigned char secret[32]{};
        secret[0] = 0x42;
        secret[31] = static_cast<unsigned char>(i + 1);
        CKey key;
        key.Set(secret, secret + sizeof(secret), /*fCompressedIn=*/true);
        Assert(key.IsValid());
        g_keys.push_back(key);
    }
}

template <typename T>
std::optional<T> Deserialize(Span<const uint8_t> bytes)
{
    DataStream ds{bytes};
    T obj;
    try {
        ds >> obj;
    } catch (const std::ios_base::failure&) {
        return std::nullopt;
    }
    return obj;
}

template <typename T>
DataStream Serialized(const T& obj)
{
    DataStream ds{};
    ds << obj;
    return ds;
}

/** Re-encoding a decoded object and decoding it again is stable. */
template <typename T>
void CheckRoundTrip(const T& obj)
{
    DataStream first = Serialized(obj);
    T decoded;
    first >> decoded;
    Assert(first.empty());
    Assert(Serialized(decoded).str() == Serialized(obj).str());
}

std::set<CPubKey> UsableSigners(const std::vector<CPubKey>& keys)
{
    std::set<CPubKey> out;
    for (const CPubKey& key : keys) {
        if (key.IsFullyValid() && key.IsCompressed()) out.insert(key);
    }
    return out;
}

const uint256 CHAIN_ID{uint256::ONE};
const uint256 CONTEXT{uint256{"0000000000000000000000000000000000000000000000000000000000000002"}};

uint256 BlockHash(uint8_t n)
{
    uint256 hash;
    hash.data()[0] = static_cast<unsigned char>(n + 1);
    return hash;
}

ExactReplayStatement ConsumeStatement(FuzzedDataProvider& fdp)
{
    ExactReplayStatement statement;
    statement.chain_id = fdp.ConsumeBool() ? CHAIN_ID : ConsumeUInt256(fdp);
    statement.replay_authority_context = fdp.ConsumeBool() ? CONTEXT : ConsumeUInt256(fdp);
    statement.block_hash = BlockHash(fdp.ConsumeIntegralInRange<uint8_t>(0, 7));
    statement.block_height = fdp.ConsumeBool() ? fdp.ConsumeIntegralInRange<int32_t>(100, 107) : fdp.ConsumeIntegral<int32_t>();
    if (fdp.ConsumeBool()) {
        statement.version = fdp.ConsumeIntegral<uint8_t>();
        statement.matmul_major = fdp.ConsumeIntegral<uint8_t>();
        statement.profile = fdp.ConsumeIntegral<uint8_t>();
    }
    return statement;
}

} // namespace

// Wire objects carried by mmattest / mmattestpq / utxomanifest / utxochunk and
// the attested snapshot manifest file, plus their stateless verifiers.
FUZZ_TARGET(matmul_attestation_deserialize, .init = initialize_matmul_attestation)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    const uint8_t which = fdp.ConsumeIntegralInRange<uint8_t>(0, 5);
    const std::vector<uint8_t> bytes = fdp.ConsumeRemainingBytes<uint8_t>();

    switch (which) {
    case 0: {
        const auto att = Deserialize<ExactReplayAttestation>(bytes);
        if (!att) return;
        CheckRoundTrip(*att);
        const ExactReplayStatement& st = att->statement;
        (void)StatementHash(st);
        (void)VerifyResultName(VerifyAttestationCrypto(*att, st.chain_id, st.replay_authority_context, st.block_hash, st.block_height));
        (void)VerifyAttestation(*att, st.chain_id, st.replay_authority_context, st.block_hash, st.block_height,
                                UsableSigners({att->signer}));
        break;
    }
    case 1: {
        const auto att = Deserialize<ExactReplayPqAttestation>(bytes);
        if (!att) return;
        CheckRoundTrip(*att);
        const ExactReplayStatement& st = att->statement;
        (void)StatementHashPq(st);
        (void)VerifyAttestationPqCrypto(*att, st.chain_id, st.replay_authority_context, st.block_hash, st.block_height);
        (void)VerifyAttestationPq(*att, st.chain_id, st.replay_authority_context, st.block_hash, st.block_height, {att->signer});
        break;
    }
    case 2: {
        const auto ref = Deserialize<ExactReplayRefutation>(bytes);
        if (!ref) return;
        CheckRoundTrip(*ref);
        const ExactReplayStatement& st = ref->statement;
        (void)RefutationHash(st);
        (void)VerifyRefutationCrypto(*ref, st.chain_id, st.replay_authority_context, st.block_hash, st.block_height);
        break;
    }
    case 3: {
        const auto manifest = Deserialize<UtxoSnapshotManifest>(bytes);
        if (!manifest) return;
        CheckRoundTrip(*manifest);
        const UtxoSnapshotStatement& st = manifest->statement;
        (void)UtxoSnapshotStatementHash(st);
        std::vector<CPubKey> signers;
        for (const UtxoSnapshotSignature& sig : manifest->signatures) signers.push_back(sig.signer);
        const std::set<CPubKey> trusted = UsableSigners(signers);
        const size_t threshold = trusted.empty() ? 1 : trusted.size();
        (void)UtxoSnapshotVerifyResultName(VerifyUtxoSnapshotManifestSelfConsistent(
            *manifest, st.chain_id, st.replay_authority_context, trusted, threshold));
        (void)VerifyUtxoSnapshotManifest(*manifest, st.chain_id, st.replay_authority_context, st.block_hash,
                                         st.block_height, st.hash_serialized, st.coins_count, st.m_chain_tx_count,
                                         st.shielded_state_commitment, trusted, threshold);
        break;
    }
    case 4: {
        const auto msg = Deserialize<node::AttestedUTXOSnapshotManifestMsg>(bytes);
        if (!msg) return;
        Assert(Serialized(*msg).size() <= bytes.size());
        break;
    }
    case 5: {
        const auto msg = Deserialize<node::AttestedUTXOSnapshotChunkMsg>(bytes);
        if (!msg) return;
        Assert(msg->data.size() <= node::ATTESTED_UTXO_SNAPSHOT_MAX_CHUNK_SIZE);
        (void)node::AttestedUTXOSnapshotBytesHash(msg->data);
        break;
    }
    }
}

// The trusted-attestation store behind mmattest relay and getmmattest
// answers, including the open (heard) directory: bounded state and serve
// rules under any order of signed and unsigned inputs.
FUZZ_TARGET(matmul_attestation_store, .init = initialize_matmul_attestation)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());

    StoreConfig config;
    config.chain_id = CHAIN_ID;
    config.replay_authority_context = CONTEXT;
    const size_t pin_n = fdp.ConsumeIntegralInRange<size_t>(1, 4);
    for (size_t i = 0; i < pin_n; ++i) config.trusted_signers.push_back(g_keys[i].GetPubKey());
    config.threshold = fdp.ConsumeIntegralInRange<size_t>(1, pin_n);
    config.max_blocks = fdp.ConsumeIntegralInRange<size_t>(1, 8);
    config.max_attestations = fdp.ConsumeIntegralInRange<size_t>(config.threshold, 32);
    config.open_attestors = fdp.ConsumeBool();
    config.open_threshold = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_heard_attestations = fdp.ConsumeIntegralInRange<size_t>(1, 16);
    config.max_admitted_open = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_open_signed_heights = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    config.max_open_signed_entries = fdp.ConsumeIntegralInRange<size_t>(0, 16);
    config.max_open_signers_per_height = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_frozen_open = fdp.ConsumeIntegralInRange<size_t>(0, 4);
    config.max_refutations = fdp.ConsumeIntegralInRange<size_t>(0, 8);
    config.max_log_leaves = fdp.ConsumeIntegralInRange<size_t>(0, 16);
    if (fdp.ConsumeBool()) config.local_signer = g_keys[fdp.ConsumeIntegralInRange<size_t>(0, KEY_POOL - 1)];

    std::optional<AttestationStore> store;
    try {
        store.emplace(config);
    } catch (const std::invalid_argument&) {
        return; // operator configuration the node refuses at startup
    }
    const std::optional<CPubKey> local = store->LocalSignerPubKey();

    LIMITED_WHILE(fdp.remaining_bytes() > 0, 64)
    {
        const uint256 hash = BlockHash(fdp.ConsumeIntegralInRange<uint8_t>(0, 7));
        const int32_t height = fdp.ConsumeIntegralInRange<int32_t>(100, 107);
        CallOneOf(
            fdp,
            [&] {
                const ExactReplayStatement st = ConsumeStatement(fdp);
                const auto att = SignStatement(st, g_keys[fdp.ConsumeIntegralInRange<size_t>(0, KEY_POOL - 1)]);
                if (!att) return;
                const bool own_block = fdp.ConsumeBool();
                (void)AddResultName(store->Add(*att, own_block ? st.block_hash : hash, own_block ? st.block_height : height));
            },
            [&] {
                const auto att = Deserialize<ExactReplayAttestation>(fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 256)));
                if (att) (void)store->Add(*att, hash, height);
            },
            [&] {
                ExactReplayAttestation produced;
                (void)store->SignLocal(hash, height, &produced);
            },
            [&] {
                const ExactReplayStatement st = ConsumeStatement(fdp);
                const auto ref = SignRefutation(st, g_keys[fdp.ConsumeIntegralInRange<size_t>(0, KEY_POOL - 1)]);
                if (ref) (void)store->AddRefutation(*ref, st.block_hash, st.block_height);
            },
            [&] { (void)store->NotifyActiveChainBlockDisconnected(height, hash); },
            [&] { store->NotifyActiveChainBlockConnected(height, hash); },
            [&] { (void)store->ClearLocalMintSlots(height, fdp.ConsumeIntegralInRange<int32_t>(100, 107)); },
            [&] { (void)store->AddBlocklistedSigner(g_keys[fdp.ConsumeIntegralInRange<size_t>(0, KEY_POOL - 1)].GetPubKey()); },
            [&] { store->AdmitOpenSigner(g_keys[fdp.ConsumeIntegralInRange<size_t>(0, KEY_POOL - 1)].GetPubKey()); },
            [&] { store->ChallengeWindowReplay(height, hash); },
            [&] { store->Erase(hash, height); },
            [&] { store->PruneExpired(); },
            [&] {
                std::vector<ExactReplayAttestation> atts = store->GetAttestations(hash, height);
                const std::vector<ExactReplayAttestation> heard = store->GetHeard(hash, height);
                atts.insert(atts.end(), heard.begin(), heard.end());
                (void)store->HasQuorumFromAttestations(atts, hash, height);
            },
            [&] {
                const size_t max_items = fdp.ConsumeIntegralInRange<size_t>(0, 8);
                const auto served = store->GetHeardForServe(hash, height, max_items, fdp.ConsumeIntegral<uint32_t>());
                Assert(served.size() <= max_items);
                for (const ExactReplayAttestation& att : served) {
                    Assert(!store->IsBlocked(att.signer));
                    Assert(!local || att.signer != *local);
                    Assert(att.statement.block_hash == hash && att.statement.block_height == height);
                }
            },
            [&] {
                for (const ExactReplayAttestation& att : store->ExportAll()) {
                    const auto proof = store->LogInclusionProof(StatementHash(att.statement));
                    if (proof) Assert(VerifyAttestationLogInclusion(*proof));
                }
            });

        (void)store->HasQuorum(hash, height);
        (void)store->HasOpenQuorum(hash, height);
        const StoreStats stats = store->GetStats();
        // One partial bucket may stage above the base limits (MakeRoomLocked).
        Assert(stats.stored_blocks <= store->MaxBlocks() + 1);
        Assert(stats.stored_attestations <= store->MaxAttestations() + store->Threshold() - 1);
        Assert(stats.heard_attestations <= store->MaxHeardAttestations());
        Assert(stats.admitted_open <= store->MaxAdmittedOpen());
        Assert(stats.open_signed_heights <= store->MaxOpenSignedHeights());
        Assert(stats.open_signed_entries <= store->MaxOpenSignedEntries());
        Assert(stats.refutation_buckets <= store->MaxRefutations());
        Assert(stats.log_leaves <= store->MaxLogLeaves());
        Assert(store->GetAttestations(hash, height).size() <= store->MaxVotesPerBlock());
    }
}

// Client sessions and server budgets of the attested UTXO snapshot fetch
// (getutxomanif / utxomanifest / getutxochunk / utxochunk).
FUZZ_TARGET(attested_snapshot_p2p_session, .init = initialize_matmul_attestation)
{
    FuzzedDataProvider fdp(buffer.data(), buffer.size());
    node::AttestedUTXOSnapshotP2P p2p;
    std::vector<node::AttestedUTXOSnapshotP2P::SessionId> sessions;
    std::chrono::microseconds now{fdp.ConsumeIntegralInRange<int64_t>(0, int64_t{1} << 40)};

    LIMITED_WHILE(fdp.remaining_bytes() > 0, 128)
    {
        const NodeId peer = fdp.ConsumeIntegralInRange<NodeId>(0, 3);
        const uint256 hash = fdp.ConsumeBool() ? uint256{} : BlockHash(fdp.ConsumeIntegralInRange<uint8_t>(0, 3));
        now += std::chrono::microseconds{fdp.ConsumeIntegralInRange<int64_t>(0, 120'000'000)};
        CallOneOf(
            fdp,
            [&] { (void)p2p.AdmitManifestRequest(peer, now); },
            [&] { (void)p2p.AdmitChunkRequest(peer, now); },
            [&] { p2p.ReleaseChunkTransfer(peer); },
            [&] { p2p.PeerDisconnected(peer); },
            [&] {
                const auto id = p2p.BeginSession(peer, hash);
                if (id) sessions.push_back(*id);
            },
            [&] {
                if (sessions.empty()) return;
                (void)p2p.BeginChunkWait(sessions[fdp.ConsumeIntegralInRange<size_t>(0, sessions.size() - 1)],
                                         fdp.ConsumeIntegral<uint32_t>());
            },
            [&] {
                if (sessions.empty()) return;
                const size_t i = fdp.ConsumeIntegralInRange<size_t>(0, sessions.size() - 1);
                p2p.CancelSession(sessions[i]);
                sessions.erase(sessions.begin() + i);
            },
            [&] {
                const auto msg = Deserialize<node::AttestedUTXOSnapshotManifestMsg>(fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 512)));
                if (msg) p2p.DeliverManifest(peer, *msg);
            },
            [&] {
                node::AttestedUTXOSnapshotChunkMsg msg;
                msg.block_hash = hash;
                msg.chunk_index = fdp.ConsumeIntegralInRange<uint32_t>(0, 3);
                msg.data = fdp.ConsumeBytes<uint8_t>(fdp.ConsumeIntegralInRange<size_t>(0, 64));
                p2p.DeliverChunk(peer, std::move(msg));
            },
            [&] {
                if (sessions.empty()) return;
                (void)p2p.WaitManifest(sessions[fdp.ConsumeIntegralInRange<size_t>(0, sessions.size() - 1)], std::chrono::milliseconds{0});
            },
            [&] {
                if (sessions.empty()) return;
                (void)p2p.WaitChunk(sessions[fdp.ConsumeIntegralInRange<size_t>(0, sessions.size() - 1)], std::chrono::milliseconds{0});
            });
    }
    for (const auto id : sessions) p2p.CancelSession(id);
}
