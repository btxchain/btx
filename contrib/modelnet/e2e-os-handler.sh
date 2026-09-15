#!/usr/bin/env bash
# V11-URI-12: OS handler is btx-open with exactly one URI. Extra args fail.
# Registers via install-os-handler.sh into scratch XDG_DATA_HOME (no real sudo).
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OPEN="${BIN_DIR:-$ROOT/build-gcc13/bin}/btx-open"
URI='btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25'
die() { echo "e2e-os-handler: $*" >&2; exit 1; }
[[ -x "$OPEN" ]] || die "missing $OPEN"
out="$("$OPEN" "$URI")"
printf '%s\n' "$out" | grep -q 'action=preview-only' || die "preview"
printf '%s\n' "$out" | grep -q 'wallet=not-opened' || die "wallet"
canonical="$(printf '%s\n' "$out" | awk -F= '/^canonical=/{print $2}')"
display="$(printf '%s\n' "$out" | awk -F= '/^display=/{print $2}')"
copy="$(printf '%s\n' "$out" | awk -F= '/^copy=/{print $2}')"
[[ -n "$canonical" && "$copy" == "$canonical" ]] || die "copy must be the full canonical URI"
[[ "$display" != "$canonical" ]] || die "display must be shorter than canonical"
[[ "$display" == *...* ]] || die "display must truncate"
set +e
"$OPEN" "$URI" extra >/dev/null 2>&1
rc=$?
set -e
[[ "$rc" -eq 1 ]] || die "extra args must fail rc=$rc"

SCRATCH="$ROOT/e2e-scratch/os-handler"
rm -rf "$SCRATCH"
mkdir -p "$SCRATCH/data" "$SCRATCH/config" "$SCRATCH/fakebin"
cat >"$SCRATCH/fakebin/sudo" <<'EOF'
#!/bin/sh
echo "e2e-os-handler: sudo must not run" >&2
exit 1
EOF
cat >"$SCRATCH/fakebin/pkexec" <<'EOF'
#!/bin/sh
echo "e2e-os-handler: pkexec must not run" >&2
exit 1
EOF
chmod +x "$SCRATCH/fakebin/sudo" "$SCRATCH/fakebin/pkexec"

export XDG_DATA_HOME="$SCRATCH/data"
export XDG_CONFIG_HOME="$SCRATCH/config"
export BTX_OPEN="$OPEN"
export INSTALL_SYSTEM=0
PATH="$SCRATCH/fakebin:$PATH" "$ROOT/contrib/modelnet/install-os-handler.sh"

DESK="$XDG_DATA_HOME/applications/btx-open.desktop"
[[ -f "$DESK" ]] || die "desktop missing: $DESK"
grep -q 'MimeType=x-scheme-handler/btx;' "$DESK" || die "mime"
exec_line="$(grep -E '^Exec=' "$DESK")"
[[ "$exec_line" == "Exec=$OPEN %u" || "$exec_line" == "Exec=\"$OPEN\" %u" ]] || die "Exec=$exec_line"
if printf '%s\n' "$exec_line" | grep -Eq '^Exec=(sh|bash|dash|zsh)( |$)'; then
  die "Exec must not be a shell"
fi
grep -q 'Exec=.*%u' "$DESK" || die "desktop %u"
if [[ -f "$XDG_CONFIG_HOME/mimeapps.list" ]]; then
  grep -q 'x-scheme-handler/btx=btx-open.desktop' "$XDG_CONFIG_HOME/mimeapps.list" || \
    die "mimeapps.list missing btx handler"
fi
echo "E2E_OS_HANDLER_USER_LOCAL PASS"

# GUI first-run --system: pkexec preferred, then sudo. Never write /usr.
# Fake elevation records argv and installs into scratch via BTX_SYSTEM_DESKTOP.
FAKEROOT="$SCRATCH/fakeroot"
mkdir -p "$FAKEROOT" "$SCRATCH/system/applications" "$SCRATCH/system-sudo/applications"
cat >"$FAKEROOT/id" <<'EOF'
#!/bin/sh
if [ "$1" = "-u" ]; then echo 0; exit 0; fi
exec /usr/bin/id "$@"
EOF
cat >"$FAKEROOT/update-desktop-database" <<'EOF'
#!/bin/sh
exit 0
EOF
cat >"$FAKEROOT/xdg-mime" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$FAKEROOT/id" "$FAKEROOT/update-desktop-database" "$FAKEROOT/xdg-mime"

link_coreutils() {
  local dest="$1" c src
  for c in id mkdir dirname cat grep chmod mv basename readlink rm ln cp echo env bash sh true false mktemp uname touch install; do
    for src in "/usr/bin/$c" "/bin/$c"; do
      if [[ -x "$src" ]]; then
        ln -sf "$src" "$dest/$c"
        break
      fi
    done
  done
}

SYSBIN="$SCRATCH/sysbin"
mkdir -p "$SYSBIN"
link_coreutils "$SYSBIN"
cat >"$SYSBIN/pkexec" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$SCRATCH/pkexec.args"
export BTX_SYSTEM_DESKTOP="$SCRATCH/system/applications/btx-open.desktop"
export PATH="$FAKEROOT:\$PATH"
exec "\$@"
EOF
cat >"$SYSBIN/sudo" <<'EOF'
#!/bin/sh
echo "e2e-os-handler: sudo must not run when pkexec exists" >&2
exit 1
EOF
chmod +x "$SYSBIN/pkexec" "$SYSBIN/sudo"
unset INSTALL_SYSTEM
PATH="$SYSBIN" BTX_OPEN="$OPEN" \
  "$ROOT/contrib/modelnet/install-os-handler.sh" --system
[[ -s "$SCRATCH/pkexec.args" ]] || die "pkexec was not invoked"
grep -q -- '--system' "$SCRATCH/pkexec.args" || die "pkexec args missing --system"
SYS_DESK="$SCRATCH/system/applications/btx-open.desktop"
[[ -f "$SYS_DESK" ]] || die "system desktop missing after pkexec"
grep -q 'MimeType=x-scheme-handler/btx;' "$SYS_DESK" || die "system mime"
sys_exec="$(grep -E '^Exec=' "$SYS_DESK")"
[[ "$sys_exec" == "Exec=$OPEN %u" || "$sys_exec" == "Exec=\"$OPEN\" %u" ]] || die "system Exec=$sys_exec"
echo "E2E_OS_HANDLER_SYSTEM_PKEXEC PASS"

SUDOBIN="$SCRATCH/sudobin"
mkdir -p "$SUDOBIN"
link_coreutils "$SUDOBIN"
cat >"$SUDOBIN/sudo" <<EOF
#!/bin/sh
printf '%s\n' "\$@" > "$SCRATCH/sudo.args"
export BTX_SYSTEM_DESKTOP="$SCRATCH/system-sudo/applications/btx-open.desktop"
export PATH="$FAKEROOT:\$PATH"
if [ "\$1" = "--" ]; then shift; fi
exec "\$@"
EOF
chmod +x "$SUDOBIN/sudo"
# Closed PATH: sudo wrapper + coreutils, no pkexec, no fakeroot/id.
PATH="$SUDOBIN" BTX_OPEN="$OPEN" \
  "$ROOT/contrib/modelnet/install-os-handler.sh" --system
[[ -s "$SCRATCH/sudo.args" ]] || die "sudo was not invoked"
grep -q -- '--system' "$SCRATCH/sudo.args" || die "sudo args missing --system"
SUDO_DESK="$SCRATCH/system-sudo/applications/btx-open.desktop"
[[ -f "$SUDO_DESK" ]] || die "system desktop missing after sudo"
echo "E2E_OS_HANDLER_SYSTEM_SUDO PASS"
echo "E2E_OS_HANDLER PASS"
