#!/usr/bin/env python3
# Copyright (c) 2026 The BTX developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Fail if a UniValue is assigned from a reference into itself.

UniValue::operator[], find_value() and getValues() return references into the
value's own storage, and UniValue's copy assignment is the implicit
member-wise one. So

    UniValue v = request.params[0];
    if (v.exists("inner")) v = v["inner"];         // also v = v[0]

copies out of the vector that the same assignment overwrites (and can free).
That is undefined behaviour: it has crashed btxd on macOS (libc++) and parsed
wrong values on Linux (libstdc++). Copy the member out first, or bind a const
reference instead of assigning:

    UniValue inner = v["inner"];
    v = std::move(inner);

What is flagged (false negatives are accepted, false positives are not):
- comments, string literals and character literals are blanked first;
- the left side is a plain variable name, not a member, a subscript or a
  dereference, and not an init-capture;
- the right side is that variable followed only by accessors: [], find_value(),
  getValues() followed by [], at(), front() or back(), get_obj() and
  get_array(), with at least one accessor that indexes. Parentheses and
  std::move() around it are looked through. In a conditional expression both
  arms must be UniValue lvalues: NullUniValue, or a plain name declared as
  UniValue (the variable or another one), alone or followed by such accessors.
  A temporary, a value of another type or an arm in std::move() makes the
  result a copy, which is safe; an arm whose type the lint cannot tell (a
  member, a call) is not flagged;
- the variable is declared as UniValue (or as auto from a subscript or
  find_value()) within the LOOKBACK lines above the assignment.

Usage: test/lint/lint-univalue-self-assignment.py [FILE...]
Without arguments, every tracked C++ file outside the vendored subtrees is
checked.
"""

import os
import re
import sys

from functools import partial
from subprocess import check_output

from lint_ignore_dirs import SHARED_EXCLUDED_SUBTREES


EXCLUDED_DIRS = ["src/crypto/ctaes/"] + SHARED_EXCLUDED_SUBTREES
SUFFIXES = (".cpp", ".h", ".hpp", ".cc", ".mm")
LOOKBACK = 60
MAX_SCAN = 4000

# Comments, raw and plain string literals, and character literals. A quote right after a hex
# digit is a digit separator (1'000). An encoding prefix (u8, u, U, L, R) stays behind as a name.
LITERALS = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r'|"(?<=R")(?P<delim>[^()\\\s"]{0,16})\(.*?\)(?P=delim)"'
    r'|"(?:\\.|[^"\\\n])*"'
    r"|'(?<![0-9A-Fa-f']')(?:\\.|[^'\\\n])+'",
    re.DOTALL,
)
# "name =" where the same name appears again before the next ';'.
ASSIGNMENT = re.compile(r"\b([A-Za-z_]\w*)\s*=(?!=)(?=[^;]*?\b\1\b)")
# A name or a member chain (a.b, a->b, a::b); a component followed by '(' is a call, not a member.
NAME = re.compile(r"[A-Za-z_]\w*(?:\s*(?:::|\.|->)\s*[A-Za-z_]\w*(?!\w)(?!\s*\())*")
CLOSERS = {")": "(", "]": "[", "}": "{"}


def blank(match):
    text = match.group(0)
    if "\n" not in text:
        return " " * len(text)
    return re.sub(r"[^\n]", " ", text)


def matching(text, start):
    """Index of the bracket that closes text[start], or -1."""
    stack = []
    for i in range(start, min(len(text), start + MAX_SCAN)):
        c = text[i]
        if c in "([{":
            stack.append(c)
        elif c in CLOSERS:
            if not stack or stack.pop() != CLOSERS[c]:
                return -1
            if not stack:
                return i
    return -1


def right_side(code, start):
    """The expression that starts at code[start]: up to ';' or ',' at depth 0, or an unmatched closer."""
    depth = 0
    end = min(len(code), start + MAX_SCAN)
    for i in range(start, end):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in CLOSERS:
            if depth == 0:
                return code[start:i]
            depth -= 1
        elif c in ";," and depth == 0:
            return code[start:i]
    return code[start:end]


def previous_token(code, pos):
    """What ends right before code[pos], skipping blanks: '->', '::' or one character."""
    i = pos - 1
    while i >= 0 and code[i].isspace():
        i -= 1
    if i >= 1 and code[i - 1:i + 1] in ("->", "::"):
        return code[i - 1:i + 1]
    return code[i] if i >= 0 else ""


def inside_square_brackets(code, pos):
    """True if code[pos] sits in an unclosed '[' of its statement: an init-capture or a subscript."""
    depth = 0
    for i in range(pos - 1, max(-1, pos - MAX_SCAN), -1):
        c = code[i]
        if c in CLOSERS:
            depth += 1
        elif c in "([{":
            if depth == 0:
                return c == "["
            depth -= 1
        elif c == ";" and depth == 0:
            return False
    return False


def unwrap(expr, moves=True):
    expr = expr.strip()
    while True:
        move = moves and re.match(r"std\s*::\s*move\s*\(", expr)
        if move and matching(expr, move.end() - 1) == len(expr) - 1:
            expr = expr[move.end():-1].strip()
        elif expr.startswith("(") and matching(expr, 0) == len(expr) - 1:
            expr = expr[1:-1].strip()
        else:
            return expr


def split_conditional(expr):
    """(true arm, false arm) of a conditional expression at depth 0, or None."""
    depth, question, nested = 0, -1, 0
    for i, c in enumerate(expr):
        if c in "([{":
            depth += 1
        elif c in CLOSERS:
            depth -= 1
        elif depth == 0 and c == "?":
            if question < 0:
                question = i
            else:
                nested += 1
        elif depth == 0 and c == ":" and question >= 0:
            if expr[i + 1:i + 2] == ":" or expr[i - 1:i] == ":":
                continue
            if nested:
                nested -= 1
            else:
                return expr[question + 1:i], expr[i + 1:]
    return None


def accessor_chain(rest):
    """For text after a name: (only accessors follow, at least one of them indexes)."""
    indexes = False
    while True:
        rest = rest.lstrip()
        if not rest:
            return True, indexes
        if rest.startswith("["):
            close = matching(rest, 0)
            if close < 0:
                return False, indexes
            rest, indexes = rest[close + 1:], True
            continue
        call = re.match(r"\.\s*(find_value|get_obj|get_array|getValues)\s*\(", rest)
        if not call:
            return False, indexes
        close = matching(rest, call.end() - 1)
        if close < 0:
            return False, indexes
        method, rest = call.group(1), rest[close + 1:]
        if method == "find_value":
            indexes = True
        elif method == "getValues":
            element = re.match(r"\s*(?:\[|\.\s*(?:at|front|back)\s*\()", rest)
            if not element:
                return False, indexes
            close = matching(rest, element.end() - 1)
            if close < 0:
                return False, indexes
            rest, indexes = rest[close + 1:], True


def kind(name, expr, univalue, arm=False):
    """'self' if expr may refer into name's storage, 'ref' for another UniValue lvalue, None otherwise.

    univalue(n) tells whether the plain name n is declared as UniValue. A conditional is an lvalue
    only if both arms are; an arm in std::move() is an xvalue, so it is not looked through there."""
    expr = unwrap(expr, moves=not arm)
    arms = split_conditional(expr)
    if arms:
        kinds = (kind(name, arms[0], univalue, True), kind(name, arms[1], univalue, True))
        if None in kinds:
            return None
        return "self" if "self" in kinds else "ref"
    head = NAME.match(expr)
    if not head:
        return None
    only_accessors, indexes = accessor_chain(expr[head.end():])
    if not only_accessors:
        return None
    if head.group(0) == name and indexes:
        return "self"
    if head.group(0) == "NullUniValue" or univalue(head.group(0)):
        return "ref"
    return None


def declared_univalue(lines, name, line_index):
    if not re.fullmatch(r"[A-Za-z_]\w*", name):
        return False
    declaration = re.compile(
        r"\bUniValue\s*&?\s*\b" + name + r"\b(?!\s*::)"
        r"|\bauto\s*&?\s*\b" + name + r"\s*=[^;]*(?:\[|\bfind_value\s*\()"
    )
    first = max(0, line_index - LOOKBACK)
    return any(declaration.search(line) for line in lines[first:line_index + 1])


def find_hits(text):
    code = LITERALS.sub(blank, text)
    lines = code.split("\n")
    hits = []
    for assignment in ASSIGNMENT.finditer(code):
        name = assignment.group(1)
        if previous_token(code, assignment.start(1)) in (".", "->", "::", "*", "&"):
            continue
        rhs = right_side(code, assignment.end())
        line_index = code.count("\n", 0, assignment.start(1))
        if kind(name, rhs, partial(declared_univalue, lines, line_index=line_index)) != "self":
            continue
        if inside_square_brackets(code, assignment.start(1)):
            continue
        if declared_univalue(lines, name, line_index):
            hits.append(line_index + 1)
    return hits


def tracked_files(root):
    """Tracked C++ files outside the vendored subtrees, relative to the current directory."""
    exclude = [":(exclude)" + d for d in EXCLUDED_DIRS]
    files = check_output(["git", "ls-files", "--"] + exclude, cwd=root, text=True, encoding="utf8").splitlines()
    return [os.path.relpath(os.path.join(root, f)) for f in files if f.endswith(SUFFIXES)]


def main():
    if len(sys.argv) > 1:
        paths = sys.argv[1:]
    else:
        root = check_output(["git", "rev-parse", "--show-toplevel"], text=True, encoding="utf8").strip()
        paths = tracked_files(root)

    found = []
    for path in paths:
        with open(path, encoding="utf8", errors="replace") as f:
            source = f.read()
        if "UniValue" not in source and "auto" not in source:
            continue  # nothing can pass declared_univalue()
        source_lines = source.split("\n")
        for line in find_hits(source):
            found.append(f"{path}:{line}: {source_lines[line - 1].strip()}")

    if not found:
        return 0
    print("A UniValue is assigned from a reference into its own storage (operator[], find_value() or")
    print("getValues()): the copy assignment overwrites the storage it is still reading from. Copy the")
    print("member into a local first (UniValue inner = v[key]; v = std::move(inner);) or bind a const")
    print("reference instead of assigning.\n")
    print("\n".join(found))
    return 1


if __name__ == "__main__":
    sys.exit(main())
