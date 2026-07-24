// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHash() const
{
    // Canonical block identity: fixed 182-byte field set. nNonce is excluded so
    // historical genesis / goldens stay stable and so a previously-legal
    // nVersion bit cannot fork identity pre-activation (withdrawn bit-26
    // HeaderPoW commitment wire — see block.h).
    HashWriter hw{};
    hw << nVersion << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce64
       << matmul_digest << matmul_dim << seed_a << seed_b;
    return hw.GetHash();
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce64=%llu, matmul_digest=%s, matmul_dim=%u, seed_a=%s, seed_b=%s, nNonce=%u, matrix_a_words=%u, matrix_b_words=%u, matrix_c_words=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, static_cast<unsigned long long>(nNonce64), matmul_digest.ToString(), matmul_dim, seed_a.ToString(), seed_b.ToString(),
        nNonce,
        matrix_a_data.size(), matrix_b_data.size(), matrix_c_data.size(), vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
