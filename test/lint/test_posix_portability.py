#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Regression controls for lint-posix-portability.py."""

import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


LINT = Path(__file__).with_name("lint-posix-portability.py").resolve()
PROFILE_FINDINGS = runpy.run_path(str(LINT))["profile_findings"]


def findings(source):
    return {(line, label, detail) for line, label, detail, _ in PROFILE_FINDINGS(source)}


class PosixPortabilityTest(unittest.TestCase):
    def test_unguarded_apis_and_offsets(self):
        result = findings("""#include /* comment */ "unistd.h"
void f() {
    auto pid = ::fork();
    pipe
        (fds);
    long off = std::ftell(file);
    std::fseek(file, static_cast<long>(off), SEEK_SET);
}
""")
        self.assertEqual({(line, kind) for line, kind, _ in result},
                         {(1, "POSIX header"), (3, "POSIX call"), (4, "POSIX call"),
                          (6, "long file offset"), (7, "long file offset")})

    def test_guarded_code_and_literals(self):
        self.assertEqual(findings(r'''
#ifdef WIN32
    return portable();
#elif defined(__linux__) || defined(__APPLE__)
    ::fork();
#else
# if !defined(_WIN32)
    #include <sys/wait.h>
    waitpid(pid, &status, 0);
# endif
#endif
#if HAVE_DECL_FORK && \
    (FOO || BAR)
    fork();
#endif
#if defined(HAVE_SYS_PRCTL_H)
    #include <sys/prctl.h>
#endif
#if !(defined(_MSC_VER) || defined(__MINGW32__))
    setsid();
#endif
    std::filesystem::symlink(a, b);
    obj . kill();
    obj -> pipe();
    /* chmod("ignored", 0); */
    // #include <unistd.h>
    const char* x = R"code(
        fork();
        #include <unistd.h>
    )code";
'''), set())

    def test_guard_that_still_allows_windows(self):
        result = findings("""
#if defined(HAVE_DECL_FORK)
    fork();
#endif
#ifdef _MSC_VER
#else
    kill(pid, 0);
#endif
#if !defined(WIN32) || MAYBE
    getuid();
#endif
#if !defined(_WIN32) && MAYBE
    pipe(fds);
#endif
#if !defined(WIN32) && MAYBE ? 0 : 1
    chmod(path, 0);
#endif
""")
        self.assertEqual({(line, detail) for line, _, detail in result},
                         {(3, "fork"), (7, "kill"), (10, "getuid"), (16, "chmod")})

    def test_commit_range_detects_removed_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def git(*args):
                return subprocess.check_output(["git", *args], cwd=root, text=True).strip()

            git("init", "-q")
            git("config", "user.name", "BTX lint test")
            git("config", "user.email", "lint-test@example.invalid")
            git("config", "commit.gpgsign", "false")
            source = root / "src/probe.cpp"
            source.parent.mkdir()
            baseline = "int old_site() { return ::getuid(); }\n"
            guard = "#ifndef WIN32\nint guarded() { return ::fork(); }\n#endif\n"

            def commit(contents):
                source.write_text(contents, encoding="utf-8")
                git("add", "src/probe.cpp")
                git("commit", "-qm", "fixture")

            def lint(base):
                return subprocess.run([sys.executable, str(LINT), "--range", f"{base}..HEAD"],
                                      cwd=source.parent, capture_output=True, text=True, check=False)

            commit(baseline + guard)
            base = git("rev-parse", "HEAD")
            commit("// harmless edit\n" + baseline + guard)
            clean = lint(base)
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)
            commit("// harmless edit\n" + baseline + "int guarded() { return ::fork(); }\n")
            exposed = lint(base)
            self.assertEqual(exposed.returncode, 1, exposed.stdout + exposed.stderr)
            self.assertEqual(exposed.stdout.strip(), "src/probe.cpp:3: POSIX call reachable on Windows: fork")

            commit("#ifdef _MSC_VER\n" + baseline + "#endif\n")
            one_compiler = git("rev-parse", "HEAD")
            commit(baseline)
            widened = lint(one_compiler)
            self.assertEqual(widened.returncode, 1, widened.stdout + widened.stderr)
            self.assertIn("POSIX call reachable on Windows: getuid", widened.stdout)


if __name__ == "__main__":
    unittest.main()
