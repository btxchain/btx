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
    // Serialized BTX header size:
    // nVersion(4) + hashPrevBlock(32) + hashMerkleRoot(32) + nTime(4) + nBits(4)
    // + nNonce64(8) + matmul_digest(32) + matmul_dim(2) + seed_a(32) + seed_b(32)
    static constexpr size_t BTX_HEADER_SIZE = 182;
    static_assert(BTX_HEADER_SIZE == (4 + 32 + 32 + 4 + 4 + 8 + 32 + 2 + 32 + 32));

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
    uint32_t nNonce;
    uint256 mix_hash;

    CBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce64, obj.matmul_digest, obj.matmul_dim, obj.seed_a, obj.seed_b);
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
