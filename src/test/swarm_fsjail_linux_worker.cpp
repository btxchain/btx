// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Static helper for the Linux filesystem-jail supervision regression.
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <csignal>
#include <cstdio>

int main()
{
    int mode = 0;
    FILE* input = std::fopen("mode", "r");
    if (input == nullptr) return 90;
    const bool parsed = std::fscanf(input, "%d", &mode) == 1;
    std::fclose(input);
    if (!parsed) return 90;
    rlimit cap{};
    if (getrlimit(RLIMIT_AS, &cap) != 0) return 91;
    const pid_t child = fork();
    if (child < 0) return 92;
    if (child == 0) _exit(17);
    int status{};
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 17) return 93;
    FILE* output = std::fopen("result", "w");
    if (output == nullptr) return 94;
    std::fprintf(output, "pid=%ld cap=%llu hard=%llu child=17\n", static_cast<long>(getpid()),
                 static_cast<unsigned long long>(cap.rlim_cur), static_cast<unsigned long long>(cap.rlim_max));
    if (std::fclose(output) != 0) return 94;
    if (mode == 99) {
        std::raise(SIGTERM);
        return 95;
    }
    return mode;
}
