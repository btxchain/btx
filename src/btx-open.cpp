// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/firstrun.h>
#include <modelnet/resource_uri.h>
#include <util/translation.h>

#include <iostream>
#include <string>

const TranslateFn G_TRANSLATION_FUN{nullptr};

int main(int argc, char* argv[])
{
    if (argc < 2 || std::string(argv[1]) == "-help" || std::string(argv[1]) == "-h") {
        std::cerr <<
            "btx-open — bounded BTX resource URI dispatcher (0.34.7)\n"
            "Opens an inspection preview only. Does not run inference, mine,\n"
            "open the spending wallet, import trust, or upload files.\n"
            "Usage: btx-open <btx://resource>\n";
        return argc < 2 ? 1 : 0;
    }
    if (argc != 2) {
        std::cerr << "btx-open accepts exactly one URI argument and does not invoke a shell\n";
        return 1;
    }
    modelnet::Resource r;
    std::string err;
    if (!modelnet::DecodeResource(argv[1], r, err)) {
        std::cerr << err << "\n";
        return 1;
    }
    uint64_t storage_bytes = 0;
    std::string storage_err;
    const bool have_budget = modelnet::EnvHasPositiveStorageBudget(storage_bytes, storage_err);
    (void)storage_err;
    std::cout << "canonical=" << r.Uri() << "\n"
              << "display=" << modelnet::ShortDisplayUri(r.Uri()) << "\n"
              << "copy=" << modelnet::CopyUri(r.Uri()) << "\n"
              << "kind=" << modelnet::ResourceKindName(r.kind) << "\n"
              << "digest=" << r.digest.Hex() << "\n"
              << "action=preview-only\n"
              << "storage_consent_required=" << (have_budget ? "false" : "true") << "\n"
              << "storage_bytes=" << storage_bytes << "\n"
              << "wallet=not-opened\n"
              << "note=download, seed, payment and local execution require separate approval\n";
    return 0;
}
