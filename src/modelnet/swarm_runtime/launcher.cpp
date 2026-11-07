// Copyright (c) 2026 The BTX developers. MIT license.
#include "supervisor.h"
#include <filesystem>
#include <cstdio>
#include <vector>
#include <string>
#ifndef _WIN32
#include <unistd.h>
extern char** environ;
#endif
#ifndef BTX_SWARM_MODULE
#define BTX_SWARM_MODULE "btxmesh.cli"
#endif
#ifndef BTX_SWARM_PYTHON
#define BTX_SWARM_PYTHON "/usr/bin/python3"
#endif
#ifndef BTX_SWARM_SOURCE_ROOT
#define BTX_SWARM_SOURCE_ROOT ""
#endif
int main(int argc, char* argv[])
{
#ifndef _WIN32
    const auto bindir = modelnet::swarm::ExecutableDirectory();
    const auto packaged = bindir.parent_path() / "libexec" / "btx-swarm";
    const auto source = std::filesystem::path(BTX_SWARM_SOURCE_ROOT);
    const auto root = std::filesystem::is_regular_file(packaged / "btxmesh" / "__init__.py") ? packaged : source;
    if (root.empty() || !std::filesystem::is_regular_file(root / "btxmesh" / "__init__.py")) {
        std::fprintf(stderr, "BTX swarm Python runtime package missing\n"); return 2;
    }
    const auto venv_python = packaged / "venv" / "bin" / "python3";
    const auto python = std::filesystem::exists(venv_python) ? venv_python : std::filesystem::path(BTX_SWARM_PYTHON);
    std::vector<std::string> args{python.string(), "-I", "-c",
        "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('" BTX_SWARM_MODULE "',run_name='__main__')", root.string()};
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    auto environment = modelnet::swarm::SanitizeEnvironment(environ);
    // Preserve only lifecycle variables owned by the trusted native supervisor.
    for (const char* key : {"BTX_SWARM_PARENT_WATCH", "BTX_SWARM_PARENT_PID"})
        if (const char* value = std::getenv(key)) environment.emplace_back(std::string(key) + "=" + value);
    std::vector<char*> av, ev;
    for (auto& a : args) av.push_back(a.data()); av.push_back(nullptr);
    for (auto& e : environment) ev.push_back(e.data()); ev.push_back(nullptr);
    execve(python.c_str(), av.data(), ev.data());
    std::perror("BTX swarm trusted Python launch"); return 2;
#else
    std::fprintf(stderr, "BTX swarm Windows launcher is not release-qualified\n"); return 2;
#endif
}
