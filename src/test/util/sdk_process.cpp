// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/sdk_process.h>

// Keep native process headers out of the Boost fixture translation units.
#include <util/subprocess.h>

#include <cstdlib>
#include <sstream>

namespace sdk_test {
int Spawn(const std::vector<std::string>& argv, std::string& output, bool include_stderr)
{
    if (argv.empty() || argv.front().empty()) return -1;
    try {
        subprocess::Popen child(argv, subprocess::output{subprocess::PIPE}, subprocess::error{subprocess::PIPE});
        const auto result = child.communicate();
        output.append(result.first.buf.data(), result.first.length);
        if (include_stderr) output.append(result.second.buf.data(), result.second.length);
        return child.retcode();
    } catch (const std::exception& e) {
        output += e.what();
        return -1;
    }
}

std::string Which(const char* name)
{
#ifdef _WIN32
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    const auto wide = converter.from_bytes(name);
    const DWORD size = SearchPathW(nullptr, wide.c_str(), L".exe", 0, nullptr, nullptr);
    if (!size) return {};
    std::vector<wchar_t> path(size);
    const DWORD length = SearchPathW(nullptr, wide.c_str(), L".exe", size, path.data(), nullptr);
    if (!length || length >= size) return {};
    return converter.to_bytes(path.data(), path.data() + length);
#else
    const char* path = std::getenv("PATH");
    if (!path) return {};
    std::istringstream paths(path);
    std::string dir;
    while (std::getline(paths, dir, ':')) {
        const std::string candidate = (dir.empty() ? "." : dir) + "/" + name;
        if (::access(candidate.c_str(), X_OK) == 0) return candidate;
    }
    return {};
#endif
}

std::string Python3()
{
#ifndef _WIN32
    const std::vector<std::string> candidates{::access("/usr/bin/python3", X_OK) == 0 ? "/usr/bin/python3" : Which("python3")};
#else
    // A python3 Windows Store alias is not proof of a working interpreter.
    const std::vector<std::string> candidates{Which("python3"), Which("python")};
#endif
    for (const auto& executable : candidates) {
        if (executable.empty()) continue;
        std::string output;
        if (Spawn({executable, "-c", "import sys; sys.exit(0 if sys.version_info.major == 3 else 1)"}, output) == 0) return executable;
    }
    return {};
}
} // namespace sdk_test
