#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Flag POSIX APIs reachable on Windows and explicit long stdio offsets.

This lexical check does not expand macros or infer CMake source selection.
Unknown preprocessor conditions are considered possible in both branches.
"""

import argparse
import os
import re
import subprocess
from pathlib import Path, PurePosixPath

from lint_ignore_dirs import SHARED_EXCLUDED_SUBTREES


EXCLUDED = ("src/compat/", "src/test/", "src/univalue/", *SHARED_EXCLUDED_SUBTREES)
SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".ipp", ".tpp"}
HEADERS = re.compile(
    r'^(?:<|")(?:unistd|sys/(?:wait|socket|mman|resource|prctl|un|ioctl|select|uio)'
    r'|pwd|grp|dlfcn|poll|termios|syslog)\.h(?:>|")'
)
CALLS = re.compile(
    r'\b(fork|kill|waitpid|getuid|chmod|symlink|pipe|setsid|sigaction)\s*\('
)
CALL_PREFIX = re.compile(r"(?:(?P<qualifier>\w+|[>\]])\s*)?::\s*$|(?:\.|->)\s*$")
GLOBAL_CALL_PREFIXES = {"return", "co_return", "throw", "case", "else"}
LONG_OFFSET = re.compile(
    r'\blong\s+\w+\s*=\s*(?:std::)?ftell\s*\('
    r'|\b(?:fseek|fseeko|_fseeki64)\s*\([^,]*,\s*[-+]?\s*'
    r'(?:\(*\s*\(\s*long\s*\)|static_cast\s*<\s*long\s*>)'
)
DIRECTIVE = re.compile(r'^\s*#\s*(\w+)\b(.*)')
NON_CODE = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/'
    r'|(?:u8|u|U|L)?R"(?P<delim>[^\s()\\]{0,16})\([\s\S]*?\)(?P=delim)"'
    r'|"(?:\\.|[^"\\\n])*"|(?<![\w\x27])\x27(?:\\.|[^\x27\\\n])*\x27'
)

# CMake emits the first group as 0 on native Windows. The second group is
# undefined there. Keep the distinction for defined(HAVE_DECL_*) tests.
WINDOWS_VALUES = {"WIN32": True, "_WIN32": True,
                  "HAVE_DECL_FORK": False, "HAVE_DECL_SETSID": False,
                  "HAVE_DECL_PIPE2": False}
WINDOWS_UNDEFINED = {"__linux__", "__APPLE__", "__unix__", "__unix", "__MACH__",
                     "__FreeBSD__", "__OpenBSD__", "__NetBSD__", "__DragonFly__",
                     "HAVE_SYS_PRCTL_H", "HAVE_SYS_RESOURCES_H", "HAVE_SYS_VMMETER_H",
                     "HAVE_VM_VM_PARAM_H"}
WINDOWS_PROFILES = ("_MSC_VER", "__MINGW32__")
FALSE, TRUE, UNKNOWN = frozenset({False}), frozenset({True}), frozenset({False, True})


def condition(expression, macros, compiler):
    """Evaluate boolean preprocessor structure without guessing unknown atoms."""
    expression = expression.strip()
    parts = []
    depth = 0
    start = 0
    for i, char in enumerate(expression):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif depth == 0 and char == "?":
            return UNKNOWN
        elif depth == 0 and expression[i:i + 2] in ("&&", "||"):
            parts.extend((expression[start:i], expression[i:i + 2]))
            start = i + 2
    parts.append(expression[start:])
    if len(parts) > 1:
        # Split on || first to preserve && precedence.
        operator = "||" if "||" in parts[1::2] else "&&"
        terms = []
        start = 0
        for i in range(1, len(parts), 2):
            if parts[i] == operator:
                terms.append("".join(parts[start:i]))
                start = i + 1
        terms.append("".join(parts[start:]))
        values = [condition(term, macros, compiler) for term in terms]
        combine = any if operator == "||" else all
        return frozenset(combine(value) for value in (tuple(min(v) for v in values),
                                                       tuple(max(v) for v in values)))
    if expression.startswith("(") and expression.endswith(")"):
        depth = 0
        for i, char in enumerate(expression):
            depth += (char == "(") - (char == ")")
            if depth == 0:
                if i == len(expression) - 1:
                    return condition(expression[1:-1], macros, compiler)
                break
    if re.fullmatch(r'!\s*(?:!\s*)*(?:\w+|defined\s*\(\s*\w+\s*\)|\(.*\))', expression):
        return invert(condition(expression[1:], macros, compiler))
    defined = re.fullmatch(r'defined\s*(?:\(\s*(\w+)\s*\)|\s+(\w+))', expression)
    if defined:
        name = defined.group(1) or defined.group(2)
        if name in WINDOWS_PROFILES:
            return TRUE if name == compiler else FALSE
        if name in macros:
            return TRUE
        return FALSE if name in WINDOWS_UNDEFINED else UNKNOWN
    if expression in macros:
        return frozenset({macros[expression]})
    if expression in WINDOWS_PROFILES:
        return TRUE if expression == compiler else FALSE
    if expression in WINDOWS_UNDEFINED:
        return FALSE
    if re.fullmatch(r'[01]', expression):
        return TRUE if expression == "1" else FALSE
    return UNKNOWN


def conjunction(left, right):
    return frozenset(a and b for a in left for b in right)


def invert(values):
    return frozenset(not value for value in values)


def strip_non_code(source):
    parts = []
    end = 0
    for match in NON_CODE.finditer(source):
        parts.append(source[end:match.start()])
        token = match.group()
        line_start = source.rfind("\n", 0, match.start()) + 1
        if token.startswith('"') and re.match(r"\s*#", source[line_start:match.start()]) and re.fullmatch(
                r"\s*#\s*include\s*", "".join(parts).rsplit("\n", 1)[-1]):
            parts.append(token)
        else:
            parts.append(re.sub(r"[^\n]", " ", token))
        end = match.end()
    parts.append(source[end:])
    return "".join(parts)


def scan(source, compiler):
    # Join preprocessing continuations, retaining a map to physical line numbers.
    line_numbers = [1]
    physical_line = 1
    fragments = []
    for line in source.splitlines(keepends=True):
        physical_line += 1
        if line.endswith("\\\n"):
            fragments.append(line[:-2])
        else:
            fragments.append(line)
            line_numbers.append(physical_line)
    cleaned = strip_non_code("".join(fragments))
    branches = []
    macros = dict(WINDOWS_VALUES)
    active = TRUE
    segment = []

    def check_segment():
        if True not in active or not segment:
            return
        text = "\n".join(line for _, line in segment)
        for match in CALLS.finditer(text):
            prefix = CALL_PREFIX.search(text[:match.start()].rstrip()[-128:])
            if prefix and (not prefix.group().strip().endswith("::")
                           or prefix["qualifier"] and prefix["qualifier"] not in GLOBAL_CALL_PREFIXES):
                continue
            index = text.count("\n", 0, match.start())
            yield segment[index][0], "POSIX call", match[1]
        for match in LONG_OFFSET.finditer(text):
            index = text.count("\n", 0, match.start())
            yield segment[index][0], "long file offset", " ".join(match.group().split())

    for number, line in zip(line_numbers, cleaned.splitlines()):
        directive = DIRECTIVE.match(line)
        if directive is None:
            segment.append((number, line))
            continue
        yield from check_segment()
        segment.clear()
        kind, argument = directive.groups()
        argument = argument.strip()
        if kind in ("ifdef", "ifndef", "elifdef", "elifndef"):
            argument = ("!" if kind in ("ifndef", "elifndef") else "") + f"defined({argument})"
        if kind in ("if", "ifdef", "ifndef"):
            possibilities = condition(argument, macros, compiler)
            branches.append((active, invert(possibilities)))
            active = conjunction(active, possibilities)
        elif kind in ("elif", "elifdef", "elifndef", "else"):
            parent, remaining = branches.pop()
            possibilities = TRUE if kind == "else" else condition(argument, macros, compiler)
            active = conjunction(parent, conjunction(remaining, possibilities))
            branches.append((parent, conjunction(remaining, invert(possibilities))))
        elif kind == "endif":
            active, _ = branches.pop()
        elif kind == "include" and True in active:
            match = HEADERS.match(argument)
            if match:
                yield number, "POSIX header", match.group()
        elif kind == "define" and argument == "__USING_WINDOWS__" and active == TRUE:
            # util/subprocess.h defines this empty marker for both Windows compilers.
            macros[argument] = False
        elif kind == "undef" or kind == "define":
            # A local redefinition invalidates any modeled value from this point.
            name = re.match(r"\w+", argument)
            if True in active and name:
                macros.pop(name.group(), None)
    yield from check_segment()


def profile_findings(source):
    source = source.replace("\r\n", "\n")
    return {(line, label, detail, compiler) for compiler in WINDOWS_PROFILES
            for line, label, detail in scan(source, compiler)}


def git(*args):
    return subprocess.check_output(["git", *args]).decode("utf-8", errors="surrogateescape")


HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def new_findings(before, after, diff):
    """Compare against the old findings at unchanged lines in Git's diff."""
    mapping = {}
    for line, label, detail, compiler in after:
        mapping.setdefault(line, set()).add((label, detail, compiler))

    if not mapping:
        return set()

    def forget_unchanged(start, stop, offset):
        for line in mapping:
            if start <= line < stop:
                mapping[line] = {(label, detail, compiler) for label, detail, compiler in mapping[line]
                                 if (line + offset, label, detail, compiler) not in before}

    old_line = new_line = 1
    for match in HUNK.finditer(diff):
        old_start, old_count, new_start, new_count = (int(n) if n is not None else 1 for n in match.groups())
        # An empty hunk range starts after the line in the hunk header.
        old_start += old_count == 0
        new_start += new_count == 0
        forget_unchanged(new_line, new_start, old_line - new_line)
        old_line, new_line = old_start + old_count, new_start + new_count

    forget_unchanged(new_line, max(mapping) + 1, old_line - new_line)
    return {(line, label, detail, compiler) for line, items in mapping.items() for label, detail, compiler in items}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="check all tracked files in a full working tree")
    parser.add_argument("--range", default=os.environ.get("COMMIT_RANGE") or "HEAD^..HEAD",
                        help="two Git revisions, BASE..TIP (default: COMMIT_RANGE or HEAD^..HEAD)")
    options = parser.parse_args()
    root = Path(git("rev-parse", "--show-toplevel").rstrip("\n"))
    os.chdir(root)
    if options.all:
        paths = git("ls-files", "-z", "src")
    else:
        revisions = options.range.split("..")
        if len(revisions) != 2 or not all(revisions) or revisions[1].startswith("."):
            parser.error("use a two-dot BASE..TIP range")
        base, tip = (git("rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}").strip()
                     for rev in revisions)
        paths = git("diff", "--name-only", "-z", "--no-renames", "--diff-filter=AMT", base, tip, "--", "src")

    failed = False
    for name in paths.split("\0"):
        if name.startswith(EXCLUDED) or PurePosixPath(name).suffix not in SUFFIXES:
            continue
        if options.all:
            source = (root / name).read_text(encoding="utf-8", errors="surrogateescape")
        else:
            source = git("show", f"{tip}:{name}")
        after = profile_findings(source)
        if not options.all and after:
            diff = git("diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--text", "--unified=0", base, tip, "--", name)
            if not diff.startswith("diff --git"):
                raise RuntimeError(f"missing Git diff for {name}")
            if "\nnew file mode " not in diff:
                after = new_findings(profile_findings(git("show", f"{base}:{name}")), after, diff)
        for line, label, detail in sorted({(line, label, detail) for line, label, detail, _ in after}):
            print(f"{name}:{line}: {label} reachable on Windows: {detail}")
            failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
