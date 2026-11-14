#!/usr/bin/env python3
#
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Keep the RPC fuzz target's command lists complete.

src/test/fuzz/rpc.cpp calls std::terminate() while the `rpc` target
initialises if any command in CRPCTable is in neither
RPC_COMMANDS_SAFE_FOR_FUZZING nor RPC_COMMANDS_NOT_SAFE_FOR_FUZZING, or is in
both. A new RPC that is not added to one list therefore kills the whole
target, and nothing in the non-fuzz CI notices.

This lint reads the same information from the sources, without a build:

1. the Register*RPCCommands() calls made by RegisterAllCoreRPCCommands() in
   src/rpc/register.h, plus the static table in src/rpc/server.cpp,
2. the `{"category", &function}` rows of each of those functions, and literal
   appendCommand("alias", ...) calls,
3. the command name each function declares: the first string passed to
   RPCHelpMan or to a helper such as ProxyOrLocal, or the name a
   BOUNTY_PROXY or PWC_RPC style macro stringifies (#ifdef is ignored),
4. the two lists in src/test/fuzz/rpc.cpp.

It fails if a registered command is in neither list or in both, if a name is
listed twice in one list, or if a register function or table row cannot be
resolved. A name
that is only in a list (a wallet command, for example, or a command that is
registered elsewhere) is allowed: the fuzz target does not reject it either.

Which list a new command belongs in is a decision for the author. Put a
command in RPC_COMMANDS_NOT_SAFE_FOR_FUZZING if it can write or read files,
start network or helper-process activity, spend or move funds, change node
state that other targets rely on, or run for a long time on small inputs. Use
RPC_COMMANDS_SAFE_FOR_FUZZING only for a command that is cheap and has no side
effect outside the in-memory test setup. When unsure, use NOT_SAFE.

Run `lint-rpc-fuzz-lists.py --registered` to print the registered names.
"""

import re
import subprocess
import sys
from pathlib import Path

REGISTER_H = Path("src/rpc/register.h")
SERVER_CPP = Path("src/rpc/server.cpp")
FUZZ_RPC_CPP = Path("src/test/fuzz/rpc.cpp")


def git_ls_files(pathspecs):
    out = subprocess.check_output(["git", "ls-files", "--", *pathspecs], text=True, encoding="utf8")
    return [Path(line) for line in out.splitlines() if line]


_TOKEN_RE = re.compile(r'"(?:\\.|[^"\\\n])*"' + r"|'(?:\\.|[^'\\\n])'" + r"|/\*.*?\*/|//[^\n]*", re.DOTALL)


def strip_comments(text):
    """Drop comments but keep string and character literals intact."""
    return _TOKEN_RE.sub(lambda m: m.group(0) if m.group(0)[0] in "\"'" else " ", text)


CHAR_LITERAL_RE = re.compile(r"'(?:\\.|[^'\\\n])'")


def matching_brace(text, open_index):
    """Index of the } that closes the { at open_index, skipping string literals."""
    depth = 0
    i = open_index
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c == "'" and CHAR_LITERAL_RE.match(text, i):
            i = CHAR_LITERAL_RE.match(text, i).end() - 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced braces")


def register_function_names():
    text = strip_comments(REGISTER_H.read_text(encoding="utf8"))
    m = re.search(r"RegisterAllCoreRPCCommands\s*\([^)]*\)\s*\{", text)
    if not m:
        raise ValueError(f"{REGISTER_H}: RegisterAllCoreRPCCommands not found")
    body = text[m.end() - 1:matching_brace(text, m.end() - 1) + 1]
    names = re.findall(r"\b(Register\w+RPCCommands)\s*\(", body)
    if not names:
        raise ValueError(f"{REGISTER_H}: no Register*RPCCommands calls found")
    return names


def function_to_rpc_names(sources):
    """Map each `RPCHelpMan name()` function to the command name it declares.

    The name is the first string handed to RPCHelpMan{...} or to a helper that
    builds one (for example ProxyOrLocal("name", ...)), directly or through a
    named string constant.
    """
    constants = {}  # (path, identifier) -> string; a definition in the same file wins over any other file
    for path, text in sources.items():
        for m in re.finditer(r"\b(\w+)\s*(?:\[\s*\])?\s*=\s*\"([a-z0-9_]+)\"\s*;", text):
            constants.setdefault((path, m.group(1)), m.group(2))

    def constant(path, identifier):
        if (path, identifier) in constants:
            return constants[(path, identifier)]
        return next((v for (_, k), v in constants.items() if k == identifier), None)

    mapping = {}
    for path, text in sources.items():
        for m in re.finditer(r"\bRPCHelpMan\s+(\w+)\s*\(\s*\)\s*\{", text):
            body = text[m.end() - 1:matching_brace(text, m.end() - 1) + 1]
            r = re.search(r"\breturn\s+(?:RPCHelpMan\s*\{|\w+\s*\()\s*(?:\"([^\"]+)\"|(\w+)\s*[,)])", body)
            if not r:
                continue
            name = r.group(1) or constant(path, r.group(2))
            if name:
                mapping.setdefault(m.group(1), set()).add(name)
        # A macro that defines `RPCHelpMan n()` and stringifies its first
        # parameter (`#n`) names the command after that parameter.
        for d in re.finditer(r"#define\s+(\w+)\(\s*(\w+)\s*(?:,[^)]*)?\)((?:[^\n]*\\\n)*[^\n]*)", text):
            macro, param, body = d.groups()
            if re.search(r"\bRPCHelpMan\s+" + param + r"\s*\(", body) and "#" + param in body:
                for use in re.finditer(r"^[ \t]*" + macro + r"\(\s*(\w+)\s*,", text, re.MULTILINE):
                    mapping.setdefault(use.group(1), set()).add(use.group(1))
    return mapping


def table_rows(text):
    """Function names referenced as `{"category", &function ...}` rows."""
    return [name.split("::")[-1] for name in re.findall(r"\{\s*\"[^\"]*\"\s*,\s*&\s*([\w:]+)\s*[,}]", text)]


def registered_rpc_names():
    sources = {p: strip_comments(p.read_text(encoding="utf8", errors="replace"))
               for p in git_ls_files(["src/*.cpp", "src/**/*.cpp"])}
    functions = function_to_rpc_names(sources)
    problems = []
    rows = []  # (origin, function)
    aliases = []  # (origin, command name)
    for reg in register_function_names():
        found = False
        for path, text in sources.items():
            m = re.search(r"\bvoid\s+" + reg + r"\s*\([^)]*\)\s*\{", text)
            if m:
                body = text[m.end() - 1:matching_brace(text, m.end() - 1) + 1]
                rows += [(f"{path}:{reg}", f) for f in table_rows(body)]
                # Aliases registered by literal name: table.appendCommand("alias", &command)
                aliases += [(f"{path}:{reg}", a) for a in re.findall(r"\bappendCommand\s*\(\s*\"([^\"]+)\"", body)]
                found = True
        if not found:
            problems.append(f"{reg} is called by RegisterAllCoreRPCCommands but its definition was not found")
    server = sources[SERVER_CPP]
    m = re.search(r"\bCRPCCommand\s+vRPCCommands\s*\[\s*\]\s*\{", server)
    if m:
        rows += [(f"{SERVER_CPP}:vRPCCommands", f)
                 for f in table_rows(server[m.end() - 1:matching_brace(server, m.end() - 1) + 1])]
    names = {}
    for origin, alias in aliases:
        names.setdefault(alias, origin)
    for origin, func in rows:
        if func not in functions:
            problems.append(f"{origin}: could not find the RPCHelpMan definition of {func}()")
            continue
        for name in functions[func]:
            names.setdefault(name, origin)
    return names, problems


def fuzz_lists():
    text = strip_comments(FUZZ_RPC_CPP.read_text(encoding="utf8"))
    lists = {}
    for key in ("RPC_COMMANDS_SAFE_FOR_FUZZING", "RPC_COMMANDS_NOT_SAFE_FOR_FUZZING"):
        m = re.search(r"\b" + key + r"\s*\{", text)
        if not m:
            raise ValueError(f"{FUZZ_RPC_CPP}: {key} not found")
        body = text[m.end() - 1:matching_brace(text, m.end() - 1) + 1]
        lists[key] = re.findall(r"\"([^\"]+)\"", body)
    return lists


def main():
    names, problems = registered_rpc_names()
    if "--registered" in sys.argv[1:]:
        print("\n".join(sorted(names)))
        return 1 if problems else 0
    lists = fuzz_lists()
    safe = set(lists["RPC_COMMANDS_SAFE_FOR_FUZZING"])
    unsafe = set(lists["RPC_COMMANDS_NOT_SAFE_FOR_FUZZING"])
    for name in sorted(set(lists["RPC_COMMANDS_SAFE_FOR_FUZZING"])):
        if lists["RPC_COMMANDS_SAFE_FOR_FUZZING"].count(name) > 1:
            problems.append(f"\"{name}\" is listed twice in RPC_COMMANDS_SAFE_FOR_FUZZING")
    for name in sorted(unsafe):
        if lists["RPC_COMMANDS_NOT_SAFE_FOR_FUZZING"].count(name) > 1:
            problems.append(f"\"{name}\" is listed twice in RPC_COMMANDS_NOT_SAFE_FOR_FUZZING")
    for name in sorted(names):
        if name in safe and name in unsafe:
            problems.append(f"\"{name}\" is in both RPC_COMMANDS_SAFE_FOR_FUZZING and RPC_COMMANDS_NOT_SAFE_FOR_FUZZING")
        elif name not in safe and name not in unsafe:
            problems.append(f"\"{name}\" ({names[name]}) is registered but in neither RPC_COMMANDS_SAFE_FOR_FUZZING "
                            f"nor RPC_COMMANDS_NOT_SAFE_FOR_FUZZING in {FUZZ_RPC_CPP}")
    if problems:
        print("The RPC fuzz target (src/test/fuzz/rpc.cpp) aborts at start-up unless every registered RPC is in "
              "exactly one of its two lists.")
        print("Add each new command to RPC_COMMANDS_NOT_SAFE_FOR_FUZZING unless it is plainly cheap and free of "
              "side effects; see the header of this script.\n")
        print("\n".join(problems))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
