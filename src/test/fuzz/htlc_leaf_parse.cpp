// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pqm.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <vector>

// Invariants for the P2MR HTLC leaf parsers, which consensus (the 32-byte
// preimage pre-check), policy and the wallet all rely on:
//  - a parser accepts only the exact script its builder would produce;
//  - no script is accepted by more than one claim-leaf parser;
//  - P2MRClaimLeafPinsPreimageLength() is exactly "one of the three
//    transaction-bound claim parsers accepts".
FUZZ_TARGET(htlc_leaf_parse)
{
    FuzzedDataProvider provider(buffer.data(), buffer.size());
    const std::vector<unsigned char> script = provider.ConsumeRemainingBytes<unsigned char>();

    std::vector<unsigned char> h1, h2, h3, h4, k1, k2, k3, k4;
    PQAlgorithm a1{}, a2{}, a3{}, a4{};
    const bool p_new = ParseP2MRHTLCSha256Leaf(script, h1, a1, k1);
    const bool p_old = ParseP2MRHTLCSha256LegacyLeaf(script, h2, a2, k2);
    const bool p_tx = ParseP2MRHTLCTxLeaf(script, h3, a3, k3);
    const bool p_csfs = ParseP2MRLegacyHTLCLeaf(script, h4, a4, k4);

    assert(int{p_new} + int{p_old} + int{p_tx} + int{p_csfs} <= 1);
    if (p_new) assert(BuildP2MRHTLCSha256Leaf(h1, a1, k1) == script);
    if (p_old) assert(BuildP2MRHTLCSha256LegacyLeaf(h2, a2, k2) == script);
    if (p_tx) assert(BuildP2MRHTLCTxLeaf(h3, a3, k3) == script);
    if (p_csfs) assert(BuildP2MRHTLCLeaf(h4, a4, k4) == script);
    assert(P2MRClaimLeafPinsPreimageLength(script) == (p_new || p_old || p_tx));
}
