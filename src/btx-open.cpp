// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/common.h>
#include <modelnet/firstrun.h>
#include <modelnet/package_bundle.h>
#include <modelnet/package_core.h>
#include <modelnet/package_documents.h>
#include <modelnet/package_export.h>
#include <modelnet/resource_uri.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/translation.h>

#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

/** BTXPKG1 payload cap plus 68-byte frame; refuse unbounded reads. */
constexpr size_t kMaxInspectBytes = 68 + 4 * 1024 * 1024;
constexpr size_t kAgentsSnippetChars = 200;

bool StartsWithBtxUri(const std::string& s)
{
    return s.size() >= 6 && s.compare(0, 6, "btx://") == 0;
}

bool HasWhitespace(const std::string& s)
{
    return s.find_first_of(" \t\n\r") != std::string::npos;
}

bool EndsWithBtx(const std::string& s)
{
    if (s.size() < 4) return false;
    return s[s.size() - 4] == '.' &&
           (s[s.size() - 3] == 'b' || s[s.size() - 3] == 'B') &&
           (s[s.size() - 2] == 't' || s[s.size() - 2] == 'T') &&
           (s[s.size() - 1] == 'x' || s[s.size() - 1] == 'X');
}

/** argc remains 2: one argv that mixes a URI with a file path is rejected. */
bool MixedUriAndFile(const std::string& s)
{
    if (StartsWithBtxUri(s)) return HasWhitespace(s);
    return s.find("btx://") != std::string::npos;
}

int PrintErrorJson(const std::string& code, const std::string& message)
{
    UniValue inner(UniValue::VOBJ);
    inner.pushKV("code", code);
    inner.pushKV("message", message);
    UniValue o(UniValue::VOBJ);
    o.pushKV("error", inner);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("agents_md_write", false);
    std::cout << o.write() << "\n";
    return 1;
}

bool ReadBoundedFile(const std::string& path, std::vector<unsigned char>& bytes, std::string& err)
{
    bytes.clear();
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open path for local inspect";
        return false;
    }
    bytes.reserve(4096);
    char buf[4096];
    while (in) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n <= 0) break;
        if (bytes.size() + static_cast<size_t>(n) > kMaxInspectBytes) {
            err = "PACKAGE_TOO_LARGE";
            bytes.clear();
            return false;
        }
        bytes.insert(bytes.end(), buf, buf + n);
    }
    return true;
}

bool FileLooksLikeBtxBundle(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    unsigned char mag[8] = {};
    in.read(reinterpret_cast<char*>(mag), 8);
    if (in.gcount() < 8) return false;
    return modelnet::LooksLikeBtxBundle(Span<const unsigned char>{mag, 8});
}

bool TryPackageCoreId(const UniValue& core, modelnet::Digest48& out)
{
    std::string err;
    return modelnet::PackageCoreId(core, out, err);
}

const UniValue* DocumentsArray(const UniValue& decoded, const UniValue* core)
{
    if (core && core->exists("documents") && (*core)["documents"].isArray()) {
        return &(*core)["documents"];
    }
    if (decoded.exists("documents") && decoded["documents"].isArray()) {
        return &decoded["documents"];
    }
    return nullptr;
}

std::string DocumentPaths(const UniValue& docs)
{
    std::string list;
    for (const auto& d : docs.getValues()) {
        if (!d.isObject() || !d.exists("path") || !d["path"].isStr()) continue;
        if (!list.empty()) list += ",";
        list += modelnet::EscapeForTerminal(d["path"].get_str());
    }
    return list;
}

std::string AgentsSnippet(const UniValue& docs)
{
    for (const auto& d : docs.getValues()) {
        if (!d.isObject() || !d.exists("path") || !d["path"].isStr()) continue;
        if (d["path"].get_str() != "AGENTS.md") continue;
        if (!d.exists("text") || !d["text"].isStr()) return {};
        const std::string& text = d["text"].get_str();
        const size_t n = text.size() < kAgentsSnippetChars ? text.size() : kAgentsSnippetChars;
        return modelnet::EscapeForTerminal(text.substr(0, n));
    }
    return {};
}

int PrintUriPreview(const char* arg)
{
    modelnet::Resource r;
    std::string err;
    if (!modelnet::DecodeResource(arg, r, err)) {
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

void PrintInspectFooter()
{
    std::cout << "action=preview-only\n"
              << "wallet=not-opened\n"
              << "install=false\n"
              << "network=false\n"
              << "agents_md_write=false\n"
              << "note=local inspect only; does not install, open the wallet, use the network, or write AGENTS.md\n";
}

/** Range-check core.version without getInt (which throws on overflow). */
bool InspectCoreVersion(const UniValue& core, int& ver, std::string& err_code)
{
    ver = 0;
    err_code.clear();
    if (!core.exists("version") || !core["version"].isNum()) {
        err_code = "UNSUPPORTED_CORE_VERSION";
        return false;
    }
    const std::string& vs = core["version"].getValStr();
    if (vs == "1") {
        ver = 1;
        return true;
    }
    if (vs == "2") {
        ver = 2;
        return true;
    }
    if (vs == "3") {
        ver = 3;
        return true;
    }
    if (vs == "4") {
        err_code = "CORE_V4_FORBIDDEN";
        return false;
    }
    err_code = "UNSUPPORTED_CORE_VERSION";
    return false;
}

bool ClaimedLengthTooLarge(Span<const unsigned char> bytes)
{
    if (bytes.size() < 20) return false;
    if (std::memcmp(bytes.data(), modelnet::BTXPKG_MAGIC, 8) != 0) return false;
    const uint64_t n = ReadLE64(bytes.data() + 12);
    if (n == std::numeric_limits<uint64_t>::max()) return true;
    if (n > 4ull * 1024 * 1024) return true;
    if (n > std::numeric_limits<size_t>::max() - 68) return true;
    return false;
}

int InspectLocalPackage(const std::string& path)
{
    std::vector<unsigned char> bytes;
    std::string err;
    if (!ReadBoundedFile(path, bytes, err)) {
        const std::string code = (err == "PACKAGE_TOO_LARGE") ? err : "INVALID_PARAMETER";
        return PrintErrorJson(code, err);
    }
    const bool magic = modelnet::LooksLikeBtxBundle(Span<const unsigned char>{bytes.data(), bytes.size()});
    if (magic && ClaimedLengthTooLarge(Span<const unsigned char>{bytes.data(), bytes.size()})) {
        return PrintErrorJson("PACKAGE_TOO_LARGE", "PACKAGE_TOO_LARGE");
    }

    UniValue decoded(UniValue::VOBJ);
    bool parsed = false;
    modelnet::DecodedBtxPackage pkg;
    UniValue bundle(UniValue::VOBJ);
    std::string pkg_err, bundle_err;
    bool as_pkg = false;
    bool as_bundle = false;
    if (magic) {
        as_pkg = modelnet::DecodeBtxPackage(Span<const unsigned char>{bytes.data(), bytes.size()}, pkg, pkg_err);
        as_bundle = modelnet::DecodeBtxBundle(Span<const unsigned char>{bytes.data(), bytes.size()}, bundle, bundle_err);
        if (as_pkg && as_bundle) {
            return PrintErrorJson("BAD_PACKAGE_MAGIC", "conflicting dual body");
        }
        if (as_pkg) {
            decoded = pkg.payload;
            parsed = true;
            err.clear();
        } else if (as_bundle) {
            decoded = bundle;
            parsed = true;
            err = bundle_err;
        } else if (bundle_err == "conflicting dual body") {
            return PrintErrorJson("BAD_PACKAGE_MAGIC", "conflicting dual body");
        } else if (pkg.err_code == "PACKAGE_TOO_LARGE" || bundle_err == "flags/size/trailing") {
            if (ClaimedLengthTooLarge(Span<const unsigned char>{bytes.data(), bytes.size()})) {
                return PrintErrorJson("PACKAGE_TOO_LARGE", "PACKAGE_TOO_LARGE");
            }
        }
    }
    if (!parsed) {
        decoded = UniValue(UniValue::VOBJ);
        const std::string raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!decoded.read(raw) || !decoded.isObject()) {
            const std::string code = pkg.err_code.empty() ? "INVALID_PARAMETER" : pkg.err_code;
            return PrintErrorJson(code, err.empty() ? (pkg_err.empty() ? "unreadable package" : pkg_err) : err);
        }
        parsed = true;
    }

    const UniValue* core = nullptr;
    if (decoded.exists("core") && decoded["core"].isObject()) {
        core = &decoded["core"];
    }

    int ver = 0;
    if (core) {
        std::string ver_code;
        if (!InspectCoreVersion(*core, ver, ver_code)) {
            return PrintErrorJson(ver_code, ver_code);
        }
    }

    std::cout << "path=" << modelnet::EscapeForTerminal(path) << "\n"
              << "looks_like_btxbundle=" << (magic ? "true" : "false") << "\n";

    if (core) {
        std::cout << "core_version=" << ver << "\n";
        modelnet::Digest48 id;
        if (TryPackageCoreId(*core, id)) {
            std::cout << "package_core_id=" << id.Hex() << "\n";
        }
    } else {
        std::cout << "core_version=unparseable\n";
    }

    const UniValue* docs = DocumentsArray(decoded, core);
    std::cout << "documents=" << (docs ? DocumentPaths(*docs) : "") << "\n";
    if (docs) {
        const std::string snippet = AgentsSnippet(*docs);
        if (!snippet.empty()) {
            std::cout << "agents_snippet=" << snippet << "\n";
        }
    }
    PrintInspectFooter();
    return 0;
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        if (argc < 2 || std::string(argv[1]) == "-help" || std::string(argv[1]) == "-h") {
            std::cerr <<
                "btx-open — bounded BTX resource URI dispatcher (0.34.7)\n"
                "Opens an inspection preview only. Does not run inference, mine,\n"
                "open the spending wallet, import trust, or upload files.\n"
                "Usage: btx-open <btx://resource>\n"
                "       btx-open <path.btx>\n";
            return argc < 2 ? 1 : 0;
        }
        if (argc != 2) {
            std::cerr << "btx-open accepts exactly one URI or .btx path argument and does not invoke a shell\n";
            return 1;
        }
        const std::string arg{argv[1]};
        if (MixedUriAndFile(arg)) {
            std::cerr << "btx-open rejects mixed URI and file arguments; pass exactly one btx:// URI or one path\n";
            return 1;
        }
        if (StartsWithBtxUri(arg)) {
            return PrintUriPreview(argv[1]);
        }
        if (EndsWithBtx(arg) || FileLooksLikeBtxBundle(arg)) {
            return InspectLocalPackage(arg);
        }
        return PrintUriPreview(argv[1]);
    } catch (const std::exception& e) {
        return PrintErrorJson("INVALID_PARAMETER", e.what());
    } catch (...) {
        return PrintErrorJson("INVALID_PARAMETER", "unreadable package");
    }
}
