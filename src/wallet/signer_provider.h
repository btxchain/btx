// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_SIGNER_PROVIDER_H
#define BITCOIN_WALLET_SIGNER_PROVIDER_H

#include <external_signer.h>
#include <pqkey.h>
#include <span.h>
#include <support/allocators/secure.h>
#include <uint256.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <wallet/bcp1_package.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

class ArgsManager;

namespace wallet {

/**
 * Vendor-neutral signing backend for BTX Custody Profile 1.
 *
 * Adapters wrap command (`-signer`), a regtest-only software signer, a
 * loopback HTTPS **stub** (no HTTP client), a PKCS#11 **stub** (no PKCS#11
 * library), and a KMIP **stub** (no KMIP library). Only the command adapter is
 * wired to wallet RPC. Type names are venue-neutral.
 *
 * ML-DSA-44 (and SLH-DSA-128s under the same m/87h scheme) are seed-hardened
 * only. `DerivePublicKey` cannot produce BIP32-style public children and
 * returns PUBLIC_CHILD_UNSUPPORTED. Watch-only addresses must come from
 * `GetPublicKey` (signer holds the seed) or an imported deposit pool.
 */
class SignerProvider
{
public:
    static constexpr const char* ERR_PUBLIC_CHILD_UNSUPPORTED = "PUBLIC_CHILD_UNSUPPORTED";
    static constexpr const char* ERR_SOFTWARE_SIGNER_REGTEST_ONLY = "SOFTWARE_SIGNER_REGTEST_ONLY";
    static constexpr const char* ERR_SOFTWARE_SIGNER_DISABLED = "SOFTWARE_SIGNER_DISABLED";
    static constexpr const char* ERR_HTTPS_UNAVAILABLE = "HTTPS_UNAVAILABLE";
    static constexpr const char* ERR_HTTPS_NOT_LOOPBACK = "HTTPS_NOT_LOOPBACK";
    static constexpr const char* ERR_PKCS11_UNAVAILABLE = "PKCS11_UNAVAILABLE";
    static constexpr const char* ERR_PKCS11_LIB_MISSING = "PKCS11_LIB_MISSING";
    static constexpr const char* ERR_KMIP_UNAVAILABLE = "KMIP_UNAVAILABLE";
    static constexpr const char* ERR_KMIP_LIB_MISSING = "KMIP_LIB_MISSING";

    virtual ~SignerProvider() = default;

    virtual std::string Backend() const = 0;

    /** Signer-side derivation from seed/HSM. Not public-child derivation. */
    virtual bool GetPublicKey(const std::string& path, PQAlgorithm algo,
                              std::vector<unsigned char>& pubkey, std::string& error) = 0;

    /**
     * Public-only child derivation from an existing PQ pubkey.
     *
     * Always fails for ML-DSA-44 (and the BCP/1 SLH-DSA path): there is no
     * BIP32-style non-hardened public child. Callers must use GetPublicKey
     * or a pre-generated address pool. `error` is PUBLIC_CHILD_UNSUPPORTED.
     */
    virtual bool DerivePublicKey(Span<const unsigned char> parent_pubkey, const std::string& path,
                                 PQAlgorithm algo, std::vector<unsigned char>& pubkey,
                                 std::string& error) = 0;

    virtual bool SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                            std::vector<unsigned char>& signature, std::string& error) = 0;

    /** JSON object containing at least `p2mr` (bool) and `pq_algorithms` (array). */
    virtual UniValue Health() const = 0;

    /** Optional PSBT path used by CommandSigner (`<cmd> signtx`). Default: unsupported. */
    virtual bool SignTransaction(PartiallySignedTransaction& psbt, std::string& error)
    {
        error = "SIGN_TRANSACTION_UNSUPPORTED";
        return false;
    }
};

/** `-signer` command protocol (enumerate / getp2mrpubkeys / signtx) plus BCP/1 getpubkey + signdigest. */
class CommandSigner final : public SignerProvider
{
    std::string m_command;
    std::string m_chain;
    ExternalSigner m_signer;

    std::string NetworkArg() const;
    bool SafeArg(const std::string& value) const;

public:
    CommandSigner(std::string command, std::string chain, ExternalSigner signer);

    std::string Backend() const override { return "command"; }
    bool GetPublicKey(const std::string& path, PQAlgorithm algo,
                      std::vector<unsigned char>& pubkey, std::string& error) override;
    bool DerivePublicKey(Span<const unsigned char> parent_pubkey, const std::string& path,
                         PQAlgorithm algo, std::vector<unsigned char>& pubkey,
                         std::string& error) override;
    bool SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                    std::vector<unsigned char>& signature, std::string& error) override;
    UniValue Health() const override;
    bool SignTransaction(PartiallySignedTransaction& psbt, std::string& error) override;
};

/**
 * In-process PQ keys. Production factory requires ChainType::REGTEST and
 * `-bcp1software=1`. `MakeSoftwareSignerForTests` is the test-only factory.
 */
class SoftwareSigner final : public SignerProvider
{
    std::vector<unsigned char, secure_allocator<unsigned char>> m_seed;
    bool m_test_only{false};

public:
    SoftwareSigner(Span<const unsigned char> master_seed, bool test_only);
    ~SoftwareSigner() override;

    SoftwareSigner(const SoftwareSigner&) = delete;
    SoftwareSigner& operator=(const SoftwareSigner&) = delete;
    SoftwareSigner(SoftwareSigner&&) = default;
    SoftwareSigner& operator=(SoftwareSigner&&) = default;

    std::string Backend() const override { return "software"; }
    bool GetPublicKey(const std::string& path, PQAlgorithm algo,
                      std::vector<unsigned char>& pubkey, std::string& error) override;
    bool DerivePublicKey(Span<const unsigned char> parent_pubkey, const std::string& path,
                         PQAlgorithm algo, std::vector<unsigned char>& pubkey,
                         std::string& error) override;
    bool SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                    std::vector<unsigned char>& signature, std::string& error) override;
    UniValue Health() const override;
};

/** Loopback HTTPS adapter. Fail-closes: no TLS client is linked in this TU. */
class LoopbackHttpsSigner final : public SignerProvider
{
    std::string m_url;

public:
    explicit LoopbackHttpsSigner(std::string url);
    std::string Backend() const override { return "https"; }
    bool GetPublicKey(const std::string& path, PQAlgorithm algo,
                      std::vector<unsigned char>& pubkey, std::string& error) override;
    bool DerivePublicKey(Span<const unsigned char> parent_pubkey, const std::string& path,
                         PQAlgorithm algo, std::vector<unsigned char>& pubkey,
                         std::string& error) override;
    bool SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                    std::vector<unsigned char>& signature, std::string& error) override;
    UniValue Health() const override;
};

/** PKCS#11 adapter. Fail-closes when the PKCS#11 module is not linked. */
class Pkcs11Signer final : public SignerProvider
{
    std::string m_module_path;

public:
    explicit Pkcs11Signer(std::string module_path);
    std::string Backend() const override { return "pkcs11"; }
    bool GetPublicKey(const std::string& path, PQAlgorithm algo,
                      std::vector<unsigned char>& pubkey, std::string& error) override;
    bool DerivePublicKey(Span<const unsigned char> parent_pubkey, const std::string& path,
                         PQAlgorithm algo, std::vector<unsigned char>& pubkey,
                         std::string& error) override;
    bool SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                    std::vector<unsigned char>& signature, std::string& error) override;
    UniValue Health() const override;
};

/** KMIP adapter. Fail-closes when the KMIP client is not linked. */
class KmipSigner final : public SignerProvider
{
    std::string m_server_uri;

public:
    explicit KmipSigner(std::string server_uri);
    std::string Backend() const override { return "kmip"; }
    bool GetPublicKey(const std::string& path, PQAlgorithm algo,
                      std::vector<unsigned char>& pubkey, std::string& error) override;
    bool DerivePublicKey(Span<const unsigned char> parent_pubkey, const std::string& path,
                         PQAlgorithm algo, std::vector<unsigned char>& pubkey,
                         std::string& error) override;
    bool SignDigest(const std::string& path, PQAlgorithm algo, const uint256& digest,
                    std::vector<unsigned char>& signature, std::string& error) override;
    UniValue Health() const override;
};

std::unique_ptr<SignerProvider> MakeCommandSigner(const std::string& command, const std::string& chain,
                                                  const std::optional<std::string>& fingerprint,
                                                  std::string& error);

/** Requires `chain == REGTEST` and `args.GetBoolArg("-bcp1software", false)`. */
std::unique_ptr<SignerProvider> MakeSoftwareSigner(ChainType chain, Span<const unsigned char> master_seed,
                                                   const ArgsManager& args, std::string& error);

/** Test-only factory: does not consult `-bcp1software`. Do not call from wallet RPC. */
std::unique_ptr<SignerProvider> MakeSoftwareSignerForTests(Span<const unsigned char> master_seed);

std::unique_ptr<SignerProvider> MakeLoopbackHttpsSigner(const std::string& url, std::string& error);
std::unique_ptr<SignerProvider> MakePkcs11Signer(const std::string& module_path, std::string& error);
std::unique_ptr<SignerProvider> MakeKmipSigner(const std::string& server_uri, std::string& error);

/** Sign every input that has a path + digest. InsertSignature verifies each sig. */
bool SignBcp1Package(SignerProvider& signer, bcp1::Package& pkg, std::string& error);

} // namespace wallet

#endif // BITCOIN_WALLET_SIGNER_PROVIDER_H
