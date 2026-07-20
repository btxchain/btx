// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_verify_bakeoff.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/translation.h>

#include <iostream>

// ENC_RC Stage E bake-off binary — toy measurements only.
// Never raises nMatMulRCHeight. Never wires into consensus validation.

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

CBlockHeader MakeHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

} // namespace

int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    const auto header = MakeHeader(42);
    const auto params = matmul::v4::rc::MakeToyRCEpisodeParams();
    uint256 seed;
    for (int i = 0; i < 32; ++i) seed.data()[i] = static_cast<unsigned char>(0x5a);

    std::cout << matmul::v4::rc::RunBakeoffReport(header, params, seed);
    std::cout << "# E1: " << matmul::v4::rc::kBakeoffE1Statement << "\n";
    std::cout << "# E2: " << matmul::v4::rc::kBakeoffE2Statement << "\n";
    std::cout << "# nMatMulRCHeight remains INT32_MAX (NO-GO)\n";
    return 0;
}
