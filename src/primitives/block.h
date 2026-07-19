// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_BLOCK_H
#define BITCOIN_PRIMITIVES_BLOCK_H

#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
class CBlockHeader
{
public:
    // Legacy identity size (pre–Header-PoW commitment): nVersion(4) + hashPrevBlock(32)
    // + hashMerkleRoot(32) + nTime(4) + nBits(4) + nNonce64(8) + matmul_digest(32)
    // + matmul_dim(2) + seed_a(32) + seed_b(32). Post-activation headers that set
    // BTX_HEADER_POW_COMMIT_VERSION_BIT append nNonce (+4 => 186) and fold it into
    // GetHash() — see doc/btx-matmul-v4.4-lt-hardening-response-2026-07-19.md §4.
    static constexpr size_t BTX_HEADER_SIZE = 182;
    static_assert(BTX_HEADER_SIZE == (4 + 32 + 32 + 4 + 4 + 8 + 32 + 2 + 32 + 32));
    static constexpr size_t BTX_HEADER_SIZE_WITH_POW_COMMIT = BTX_HEADER_SIZE + sizeof(uint32_t);
    static_assert(BTX_HEADER_SIZE_WITH_POW_COMMIT == 186);

    // Hard-fork format bit (nVersion bit 26). Self-describing: SERIALIZE_METHODS
    // and GetHash() key off this bit alone — no compile-time wire fork, no height
    // needed at (de)serialize time. Consensus requires the bit at/above the
    // unified v4 height and forbids it below. Unused by BIP9 deployments
    // (taproot=2, testdummy=28).
    static constexpr int32_t BTX_HEADER_POW_COMMIT_VERSION_BIT = (1 << 26);

    // Deprecated compile-time wire opt-in. Kept so transitional cmake
    // -DBTX_ENABLE_HEADER_NONCE_ON_WIRE=ON builds still compile, but it MUST NOT
    // alter consensus/P2P serialization (that forked peers). Wire + identity are
    // exclusively version-bit gated via HasHeaderPoWCommitment().
    static constexpr bool BTX_HEADER_NONCE_ON_WIRE =
#if defined(BTX_ENABLE_HEADER_NONCE_ON_WIRE) && BTX_ENABLE_HEADER_NONCE_ON_WIRE
        true // build tag only; see SERIALIZE_METHODS — does not change wire
#else
        false
#endif
        ;

    // Legacy alias: base identity size. Prefer GetSerializeSize(header) or
    // BTX_HEADER_SIZE_WITH_POW_COMMIT when the commitment bit is set.
    static constexpr size_t BTX_HEADER_WIRE_SIZE = BTX_HEADER_SIZE;

    // header
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint64_t nNonce64;
    uint256 matmul_digest;
    uint16_t matmul_dim;
    uint256 seed_a;
    uint256 seed_b;

    // Legacy nonce/mix members kept for transitional compatibility.
    // nNonce is the HeaderPoW grind field: on the wire and in GetHash() iff
    // HasHeaderPoWCommitment() (BTX_HEADER_POW_COMMIT_VERSION_BIT).
    uint32_t nNonce;
    uint256 mix_hash;

    CBlockHeader()
    {
        SetNull();
    }

    bool HasHeaderPoWCommitment() const
    {
        return (nVersion & BTX_HEADER_POW_COMMIT_VERSION_BIT) != 0;
    }

    void SetHeaderPoWCommitment(bool enabled)
    {
        if (enabled) {
            nVersion |= BTX_HEADER_POW_COMMIT_VERSION_BIT;
        } else {
            nVersion &= ~BTX_HEADER_POW_COMMIT_VERSION_BIT;
        }
    }

    SERIALIZE_METHODS(CBlockHeader, obj)
    {
        // Identity fields (182 bytes) — always on the wire.
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce64, obj.matmul_digest, obj.matmul_dim, obj.seed_a, obj.seed_b);
        // Versioned HeaderPoW commitment (v4.4 hard fork): nNonce rides on the
        // wire iff the self-describing version bit is set. Both ON and OFF
        // cmake builds speak this protocol — BTX_HEADER_NONCE_ON_WIRE is not
        // consulted here (must not fork peers).
        if (obj.HasHeaderPoWCommitment()) {
            READWRITE(obj.nNonce);
        } else if constexpr (Operation::ForRead()) {
            obj.nNonce = 0;
        }
    }

    /** Explicit 186-byte commitment wire image (version bit forced on for the
     *  stream). Does not mutate @p header. */
    template <typename Stream>
    static void SerializeWithNonce(Stream& s, const CBlockHeader& header)
    {
        const int32_t ver = header.nVersion | BTX_HEADER_POW_COMMIT_VERSION_BIT;
        s << ver << header.hashPrevBlock << header.hashMerkleRoot << header.nTime
          << header.nBits << header.nNonce64 << header.matmul_digest << header.matmul_dim
          << header.seed_a << header.seed_b << header.nNonce;
    }
    template <typename Stream>
    static void UnserializeWithNonce(Stream& s, CBlockHeader& header)
    {
        s >> header;
    }

    /** Legacy 182-byte identity image (never includes nNonce), for tests/goldens. */
    template <typename Stream>
    static void SerializeIdentityOnly(Stream& s, const CBlockHeader& header)
    {
        s << header.nVersion << header.hashPrevBlock << header.hashMerkleRoot << header.nTime
          << header.nBits << header.nNonce64 << header.matmul_digest << header.matmul_dim
          << header.seed_a << header.seed_b;
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce64 = 0;
        matmul_digest.SetNull();
        matmul_dim = 0;
        seed_a.SetNull();
        seed_b.SetNull();
        nNonce = 0;
        mix_hash.SetNull();
    }

    bool IsNull() const
    {
        return (nBits == 0);
    }

    uint256 GetHash() const;

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;
    // Optional v2 arbitrary-matrix proof payload (flattened row-major matrices).
    std::vector<uint32_t> matrix_a_data;
    std::vector<uint32_t> matrix_b_data;
    // Optional Freivalds' product matrix payload: the claimed C' = A'B'.
    // Enables O(n^2) probabilistic verification instead of O(n^3) recomputation.
    std::vector<uint32_t> matrix_c_data;

    // Memory-only flags for caching expensive checks
    mutable bool fChecked;                            // CheckBlock()
    mutable bool m_checked_witness_commitment{false}; // CheckWitnessCommitment()
    mutable bool m_checked_merkle_root{false};        // CheckMerkleRoot()

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
        // Header relay encodes CBlock objects with an empty vtx as a transport
        // shim to include the required trailing nTx=0 varint. Never include
        // MatMul payload vectors in that path or the headers message framing
        // becomes ambiguous.
        //
        // For full blocks (vtx non-empty), write payload vectors and accept
        // legacy blocks that predate payload serialization by treating missing
        // trailing payload bytes as empty vectors.
        //
        // v4.4 ENC-DR DIGEST-ONLY WIRE INVARIANT (tension-resolution §4.1
        // clause 2). SERIALIZE_METHODS has NO height context, so the digest-only
        // carriage is expressed as a CONTENT invariant rather than a
        // serialization flag: at DIGEST_RECOMPUTE heights
        // (GetMatMulProfileParams(height).commitment) matrix_c_data MUST be
        // EMPTY on the wire and on disk — the header's matmul_digest =
        // H(sigma||Chat) is the ENTIRE PoW commitment and Chat is re-derivable
        // from the header by anyone. Enforced at the two ends that DO know the
        // height — the miner (rpc/mining.cpp: offloads the solved sketch to the
        // non-consensus sketch cache and clears matrix_c_data) and validation
        // (ContextualCheckBlock: rejects a non-empty inline sketch at an ENC-DR
        // height). A v4 block also always has matrix_a_data / matrix_b_data
        // empty (spec §H.2), so an ENC-DR block writes exactly two zero-length
        // varints (a,b) and ZERO bytes for the sketch (the
        // `!matrix_c_data.empty()` guard below emits nothing for an empty c).
        // Round-trips are byte-identical (read: two empty vectors, then no
        // trailing bytes -> c stays empty). On the regtest-only
        // FLAT_SKETCH_INBLOCK replay path this serialization is UNCHANGED from
        // the legacy in-block carriage — the format is chosen by
        // height/carriage, deterministically.
        if constexpr (Operation::ForRead()) {
            if (!obj.vtx.empty() && obj.StreamHasTrailingPayload(s)) {
                READWRITE(obj.matrix_a_data, obj.matrix_b_data);
                // Freivalds' product matrix payload (C' = A'B') is optional and
                // appended after matrix_b_data. Legacy blocks without it are valid.
                if (obj.StreamHasTrailingPayload(s)) {
                    READWRITE(obj.matrix_c_data);
                } else {
                    obj.matrix_c_data.clear();
                }
            } else {
                obj.matrix_a_data.clear();
                obj.matrix_b_data.clear();
                obj.matrix_c_data.clear();
            }
        } else {
            if (!obj.vtx.empty()) {
                READWRITE(obj.matrix_a_data, obj.matrix_b_data);
                if (!obj.matrix_c_data.empty()) {
                    READWRITE(obj.matrix_c_data);
                }
            }
        }
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        matrix_a_data.clear();
        matrix_b_data.clear();
        matrix_c_data.clear();
        fChecked = false;
        m_checked_witness_commitment = false;
        m_checked_merkle_root = false;
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce64       = nNonce64;
        block.matmul_digest  = matmul_digest;
        block.matmul_dim     = matmul_dim;
        block.seed_a         = seed_a;
        block.seed_b         = seed_b;
        block.nNonce         = nNonce;
        block.mix_hash       = mix_hash;
        return block;
    }

    std::string ToString() const;

private:
    template <typename Stream>
    static bool StreamHasTrailingPayload(Stream& s)
    {
        if constexpr (requires(Stream& stream) { stream.GetStream(); }) {
            return StreamHasTrailingPayload(s.GetStream());
        } else if constexpr (requires(Stream& stream) { stream.size(); }) {
            return s.size() != 0;
        } else if constexpr (requires(Stream& stream) { stream.empty(); }) {
            return !s.empty();
        }
        return false;
    }
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() = default;

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // BITCOIN_PRIMITIVES_BLOCK_H
