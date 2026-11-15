// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <consensus/amount.h>
#include <pqkey.h>
#include <primitives/transaction.h>
#include <psbt.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/util.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <wallet/bcp1_package.h>

#include <cassert>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace {

void initialize_bcp1_package()
{
    SelectParams(ChainType::REGTEST);
}

//! Encode's output must decode, a decoded package must re-encode unchanged, and
//! the later RPC steps must cope with whatever survived ValidateStructure.
//! A package built field by field (`from_decode` false) may be normalised once:
//! Decode fills in what it can infer, such as `algo` from the public key size.
void CheckPackage(FuzzedDataProvider& fdp, const wallet::bcp1::Package& pkg, bool from_decode)
{
    namespace bcp1 = wallet::bcp1;
    std::string err;
    const UniValue encoded{bcp1::Encode(pkg)};
    assert(encoded.isObject());
    assert(!encoded.exists("automatic_spend_atoms"));
    bcp1::Package decoded;
    assert(bcp1::Decode(encoded, decoded, err));
    const UniValue reencoded{bcp1::Encode(decoded)};
    if (from_decode) assert(reencoded.write() == encoded.write());
    bcp1::Package stable;
    assert(bcp1::Decode(reencoded, stable, err));
    assert(bcp1::Encode(stable).write() == reencoded.write());

    std::string err_a, err_b;
    const bool valid{bcp1::ValidateStructure(decoded, err_a)};
    assert(valid == bcp1::ValidateStructure(stable, err_b));
    if (from_decode) assert(valid == bcp1::ValidateStructure(pkg, err_b));
    if (!valid) return;

    (void)bcp1::FillCanonicalDigests(decoded, err);
    for (size_t i = 0; i < decoded.inputs.size() && fdp.ConsumeBool(); ++i) {
        const std::vector<unsigned char> sig{ConsumeRandomLengthByteVector(fdp, 8192)};
        (void)bcp1::InsertSignature(decoded, i, sig, err);
    }
    if (bcp1::PackageReadyToBroadcast(decoded, err)) {
        CMutableTransaction tx;
        (void)bcp1::TryExtractSignedTx(decoded, tx, err);
    }
    PartiallySignedTransaction psbt{decoded.unsigned_tx};
    (void)bcp1::ApplyToPSBT(decoded, psbt, err);
}

} // namespace

FUZZ_TARGET(bcp1_package, .init = initialize_bcp1_package)
{
    namespace bcp1 = wallet::bcp1;
    FuzzedDataProvider fdp{buffer.data(), buffer.size()};
    std::string err;

    std::vector<uint32_t> path;
    (void)bcp1::ParseDerivationPath(fdp.ConsumeRandomLengthString(64), path);
    PQAlgorithm algo;
    if (bcp1::ParseAlgo(fdp.ConsumeRandomLengthString(16), algo)) (void)bcp1::FormatAlgo(algo);

    bcp1::Package pkg;
    const bool from_decode{fdp.ConsumeBool()};
    if (from_decode) {
        // A package as an exchange or an external signer hands it back.
        UniValue json;
        if (!json.read(fdp.ConsumeRandomLengthString(16384))) return;
        if (!bcp1::Decode(json, pkg, err)) return;
    } else {
        // A package as prepareexternalsign builds it.
        const CMutableTransaction tx{ConsumeTransaction(fdp, std::nullopt)};
        std::vector<CTxOut> prevouts;
        for (size_t i = 0; i < tx.vin.size(); ++i) prevouts.emplace_back(ConsumeMoney(fdp), ConsumeScript(fdp));
        const std::string network{fdp.PickValueInArray({"main", "test", "testnet4", "signet", "regtest", "shieldedv2dev", ""})};
        if (!bcp1::FromUnsignedTx(tx, prevouts, network, pkg, err)) return;
        for (auto& in : pkg.inputs) {
            if (fdp.ConsumeBool()) in.pubkey = ConsumeRandomLengthByteVector(fdp, 4096);
            if (fdp.ConsumeBool()) in.algo = fdp.ConsumeBool() ? PQAlgorithm::ML_DSA_44 : PQAlgorithm::SLH_DSA_128S;
            if (fdp.ConsumeBool()) in.derivation_path = fdp.ConsumeRandomLengthString(48);
        }
        (void)bcp1::FillCanonicalDigests(pkg, err);
    }
    CheckPackage(fdp, pkg, from_decode);
}
