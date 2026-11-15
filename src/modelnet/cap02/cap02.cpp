// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/cap02/cap02.h>
#include <modelnet/nifdt_contract/contract.h>
#include <util/fs.h>
#include <modelnet/swarm_native_io.h>
#include <modelnet/swarm_fsjail.h>
#include <modelnet/swarm_process_guard.h>
#include <chrono>
#include <map>
#include <set>
#ifndef _WIN32
#include <sys/utsname.h>
#include <sys/wait.h>
#endif

#include <cstdint>
#include <fstream>
#include <limits>
#include <string>

namespace modelnet {
namespace {

constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

void MixBytes(std::uint64_t& hash, const char* data, std::streamsize n)
{
    for (std::streamsize i = 0; i < n; ++i) {
        hash ^= static_cast<unsigned char>(data[i]);
        hash *= kFnvPrime;
    }
}

std::string Hex64(std::uint64_t hash)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 0; i < 16; ++i) {
        const int shift = (15 - i) * 4;
        out[static_cast<std::size_t>(i)] = kHex[(hash >> shift) & 0xF];
    }
    return out;
}

bool IsHex16(const std::string& hex)
{
    if (hex.size() != 16) {
        return false;
    }
    for (unsigned char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
            return false;
        }
    }
    return true;
}

bool SingleComponent(const std::string& name)
{
    if (name.empty() || name == "." || name == "..") {
        return false;
    }
    const fs::path name_path = fs::PathFromString(name);
    if (name_path.has_parent_path() || name_path.is_absolute()) {
        return false;
    }
    return fs::PathToString(name_path.filename()) == name;
}

bool FileDigest(const fs::path& file, std::string& hex)
{
    std::ifstream in{file, std::ios::binary};
    if (!in) {
        return false;
    }
    std::uint64_t hash = kFnvOffset;
    char buf[4096];
    while (true) {
        in.read(buf, sizeof(buf));
        const std::streamsize n = in.gcount();
        if (n > 0) {
            MixBytes(hash, buf, n);
        }
        if (in.bad()) {
            return false;
        }
        if (!in) {
            break;
        }
    }
    hex = Hex64(hash);
    return true;
}

bool LineMatches(const fs::path& root, const std::string& line)
{
    const std::size_t sp = line.find(' ');
    if (sp == std::string::npos || line.find(' ', sp + 1) != std::string::npos) {
        return false;
    }
    const std::string name = line.substr(0, sp);
    const std::string expect = line.substr(sp + 1);
    if (!SingleComponent(name) || !IsHex16(expect)) {
        return false;
    }
    const fs::path child = root / fs::PathFromString(name);
    try {
        if (!fs::exists(child) || !fs::is_regular_file(child)) {
            return false;
        }
    } catch (const fs::filesystem_error&) {
        return false;
    }
    std::string got;
    if (!FileDigest(child, got)) {
        return false;
    }
    return got == expect;
}

} // namespace

bool Cap02::Qualify(const std::string& dir, std::string& err)
{
    m_files = 0;
    m_native = false;
    m_evidence = {};
    if (dir.empty()) {
        err = "FIELD";
        return false;
    }

    const fs::path root = fs::PathFromString(dir);
    fs::path manifest;
    try {
        if (!fs::exists(root) || !fs::is_directory(root)) {
            err = "ABSENT";
            return false;
        }
        manifest = root / "manifest.txt";
        if (!fs::exists(manifest) || !fs::is_regular_file(manifest)) {
            err = "ABSENT";
            return false;
        }
    } catch (const fs::filesystem_error&) {
        err = "ABSENT";
        return false;
    }

    std::ifstream in{manifest};
    if (!in) {
        err = "ABSENT";
        return false;
    }

    int count = 0;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (!LineMatches(root, line)) {
            err = "DIGEST";
            return false;
        }
        if (count == std::numeric_limits<int>::max()) {
            err = "DIGEST";
            return false;
        }
        ++count;
    }
    if (in.bad() || !in.eof()) {
        err = "DIGEST";
        return false;
    }
    if (count < 1) {
        err = "DIGEST";
        return false;
    }
    m_files = count;
    err.clear();
    return true;
}

namespace {
bool SafeRelative(const std::string& text)
{
    if (text.empty() || text.size() > 4096 || text.find('\0') != std::string::npos ||
        text.find('\\') != std::string::npos || text.find(':') != std::string::npos) return false;
    const fs::path path = fs::PathFromString(text);
    if (path.is_absolute() || path.has_root_name()) return false;
    for (const auto& part : path) if (part == ".." || part == "." || part.empty()) return false;
    return true;
}
}
bool Cap02::QualifyNative(const NativeToolProbe& probe, std::string& err)
{
    m_native = false; m_evidence = {}; m_files = 0;
    const fs::path root = fs::PathFromString(probe.root);
    if (!SafeRelative(probe.executable) || !SafeRelative(probe.output_relative_path) ||
        !process_guard::NoSymlinkPath(root) || probe.files.empty() || probe.files.size() > 4096 ||
        probe.wall_seconds <= 0 || probe.wall_seconds > 86400 || probe.expected_output_bytes == 0 ||
        probe.expected_output_bytes > 16 * 1024 * 1024 || !native_io::IsDigest(probe.expected_output_sha384)) {
        err = "NATIVE_TOOL_POLICY"; return false;
    }
    const fs::path output = root / fs::PathFromString(probe.output_relative_path);
    std::error_code ec;
    const auto output_status = fs::symlink_status(output, ec);
    if (fs::exists(output_status) || fs::is_symlink(output_status)) { err = "NATIVE_TOOL_STALE_OUTPUT"; return false; }
    ec.clear();
    if (!process_guard::NoSymlinkPath(output.parent_path())) { err = "NATIVE_TOOL_OUTPUT_PATH"; return false; }
    std::set<std::string> paths;
    std::vector<unsigned char> identity;
    native_io::AppendField(identity, "BTX/NativeToolPackage/v1");
    uint64_t total = 0;
    std::string executable_digest;
    auto verify = [&](bool record) {
        for (const NativeToolFile& file : probe.files) {
            if (!SafeRelative(file.relative_path) || file.relative_path == probe.output_relative_path ||
                file.bytes > probe.max_package_bytes - total) { err = "NATIVE_TOOL_FILE_POLICY"; return false; }
            const fs::path path = root / fs::PathFromString(file.relative_path);
            if (!process_guard::InsideRoot(path, root)) { err = "NATIVE_TOOL_FILE_PATH"; return false; }
            std::vector<unsigned char> bytes;
            if (!native_io::ReadVerified(path, file.sha384, file.bytes, probe.max_package_bytes, bytes, err)) return false;
            if (record) {
                if (!paths.insert(file.relative_path).second) { err = "NATIVE_TOOL_DUPLICATE"; return false; }
                native_io::AppendField(identity, file.relative_path);
                native_io::AppendField(identity, file.sha384);
                native_io::AppendNumber(identity, file.bytes);
                if (file.relative_path == probe.executable) executable_digest = file.sha384;
            }
            total += file.bytes;
        }
        return true;
    };
    if (!verify(true)) return false;
    auto verify_tree = [&](bool allow_output) {
        size_t entries=0;
        fs::recursive_directory_iterator item(root,fs::directory_options::none,ec),end;
        if(ec){err="NATIVE_TOOL_TREE";return false;}
        for(;item!=end;item.increment(ec)) {
            if(ec || ++entries>8192 || item.depth()>64 || !process_guard::NoSymlinkPath(item->path())) {
                err="NATIVE_TOOL_TREE";return false;
            }
            if(item->is_directory(ec) && !ec)continue;
            if(ec || !item->is_regular_file(ec) || ec){err="NATIVE_TOOL_TREE";return false;}
            const auto relative=item->path().lexically_relative(root);
            const bool known=std::any_of(paths.begin(),paths.end(),[&](const auto& path){return fs::PathFromString(path)==relative;});
            if(!known && (!allow_output || relative!=fs::PathFromString(probe.output_relative_path))) {
                err="NATIVE_TOOL_UNPINNED_FILE";return false;
            }
        }
        if(ec){err="NATIVE_TOOL_TREE";return false;}
        return true;
    };
    if(!verify_tree(false))return false;
    if (executable_digest.empty()) { err = "NATIVE_TOOL_EXECUTABLE_UNPINNED"; return false; }
    NativeToolEvidence evidence;
#ifndef _WIN32
    struct utsname host{};
    if (uname(&host) != 0) { err = "NATIVE_TOOL_HOST"; return false; }
    evidence.operating_system = host.sysname; evidence.architecture = host.machine;
#else
    evidence.operating_system = "Windows";
    SYSTEM_INFO system{};GetNativeSystemInfo(&system);
    switch(system.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:evidence.architecture="x86_64";break;
    case PROCESSOR_ARCHITECTURE_ARM64:evidence.architecture="aarch64";break;
    case PROCESSOR_ARCHITECTURE_INTEL:evidence.architecture="x86";break;
    default:err="NATIVE_TOOL_HOST";return false;
    }
#endif
    const auto start = std::chrono::steady_clock::now();
    SwarmFilesystemJailRequest request;
    request.root = root; request.helper = root / fs::PathFromString(probe.executable);
    request.network_denied = true; request.max_wall_seconds = probe.wall_seconds;
    request.max_tree_bytes = probe.max_package_bytes;
    const auto run = SwarmRunFilesystemJail(request, err);
    evidence.elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
    if (!run.launched || !run.jailed) return false;
#ifndef _WIN32
    if (!WIFEXITED(run.child_status) || WEXITSTATUS(run.child_status) != 0) { err = "NATIVE_TOOL_EXIT"; return false; }
#else
    if (run.child_status != 0) { err = "NATIVE_TOOL_EXIT"; return false; }
#endif
    if (!process_guard::InsideRoot(output, root)) { err = "NATIVE_TOOL_OUTPUT_PATH"; return false; }
    std::vector<unsigned char> result;
    if (!native_io::ReadVerified(output, probe.expected_output_sha384, probe.expected_output_bytes,
                                16 * 1024 * 1024, result, err)) return false;
    total = 0;
    if (!verify(false) || !verify_tree(true)) return false;
    evidence.exit_code = 0;
    evidence.package_sha384 = native_io::Digest(identity);
    evidence.executable_sha384 = executable_digest;
    evidence.output_sha384 = native_io::Digest(result);
    m_files = static_cast<int>(probe.files.size());
    m_evidence = std::move(evidence); m_native = true;
    err.clear(); return true;
}
} // namespace modelnet
