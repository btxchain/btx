#!/usr/bin/env bash
# Register btx-open as the x-scheme-handler/btx desktop handler.
# User-local (default): $XDG_DATA_HOME/applications or ~/.local/share/applications
#   plus `xdg-mime default`. No pkexec/sudo.
# System: INSTALL_SYSTEM=1 or --system — pkexec (preferred) then sudo, write
#   /usr/share/applications/btx-open.desktop, update-desktop-database.
# Exec= is btx-open %u or $BTX_OPEN %u. Never a shell. Never SIGKILL. Fail-fast.
export LC_ALL=C
set -euo pipefail

die() { echo "install-os-handler: $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: install-os-handler.sh [--system] [--btx-open=PATH]

  User-local (default): write btx-open.desktop under XDG_DATA_HOME (or
  $HOME/.local/share) and run xdg-mime default x-scheme-handler/btx.

  --system / INSTALL_SYSTEM=1: pkexec (preferred) or sudo, install to
  /usr/share/applications/btx-open.desktop and update-desktop-database.

  BTX_OPEN / --btx-open: absolute path used as Exec= (must be the btx-open
  binary, never a shell). Unset → Exec=btx-open %u.
EOF
}

INSTALL_SYSTEM="${INSTALL_SYSTEM:-0}"
BTX_OPEN="${BTX_OPEN:-}"

for arg in "$@"; do
  case "$arg" in
    --system) INSTALL_SYSTEM=1 ;;
    --btx-open=*) BTX_OPEN="${arg#--btx-open=}" ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown argument: $arg" ;;
  esac
done

case "$INSTALL_SYSTEM" in
  1) INSTALL_SYSTEM=1 ;;
  0|'') INSTALL_SYSTEM=0 ;;
  *) die "INSTALL_SYSTEM must be 0 or 1 (got $INSTALL_SYSTEM)" ;;
esac

self="$(readlink -f "$0" 2>/dev/null || true)"
[[ -n "$self" && -f "$self" ]] || die "cannot resolve installer path"

exec_field="btx-open"
if [[ -n "$BTX_OPEN" ]]; then
  [[ "$BTX_OPEN" != *$'\n'* ]] || die "BTX_OPEN must be a single path"
  [[ "$BTX_OPEN" != *'$'* && "$BTX_OPEN" != *'`'* && "$BTX_OPEN" != *'"'* ]] || \
    die "BTX_OPEN must not contain \$ \` or quotes"
  [[ -e "$BTX_OPEN" ]] || die "BTX_OPEN not found: $BTX_OPEN"
  BTX_OPEN="$(readlink -f "$BTX_OPEN")"
  [[ -x "$BTX_OPEN" ]] || die "BTX_OPEN not executable: $BTX_OPEN"
  base="$(basename "$BTX_OPEN")"
  case "$base" in
    sh|bash|dash|zsh|ksh|csh|tcsh|fish) die "Exec must not be a shell ($base)" ;;
  esac
  if [[ "$BTX_OPEN" == *[[:space:]]* ]]; then
    exec_field="\"$BTX_OPEN\""
  else
    exec_field="$BTX_OPEN"
  fi
fi

write_desktop() {
  local dest="$1"
  local dir tmp
  dir="$(dirname "$dest")"
  mkdir -p "$dir" || die "mkdir $dir"
  tmp="$dest.tmp.$$"
  cat >"$tmp" <<EOF
[Desktop Entry]
Name=BTX Open
Comment=Bounded BTX resource URI preview (no inference, wallet, or download)
Exec=$exec_field %u
Type=Application
Terminal=false
NoDisplay=true
MimeType=x-scheme-handler/btx;
Categories=Network;
EOF
  grep -E '^Exec=' "$tmp" | grep -q ' %u$' || die "Exec must end with %u"
  if grep -E '^Exec=' "$tmp" | grep -Eq '^Exec=(sh|bash|dash|zsh)( |$)'; then
    rm -f "$tmp"
    die "Exec must not be a shell"
  fi
  if grep -E '^Exec=' "$tmp" | grep -Fq ' -c '; then
    rm -f "$tmp"
    die "Exec must not be a shell"
  fi
  mv -f "$tmp" "$dest"
  chmod 644 "$dest"
}

elevate_system() {
  local -a extra=()
  extra+=(--system)
  if [[ -n "$BTX_OPEN" ]]; then
    extra+=("--btx-open=$BTX_OPEN")
  fi
  # Prefer pkexec, then sudo. exec replaces this process — never SIGKILL.
  if command -v pkexec >/dev/null 2>&1; then
    exec pkexec "$self" "${extra[@]}"
  fi
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -- "$self" "${extra[@]}"
  fi
  die "system install requires pkexec or sudo"
}

if [[ "$INSTALL_SYSTEM" == "1" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    elevate_system
    die "elevation returned unexpectedly"
  fi
  dest="${BTX_SYSTEM_DESKTOP:-/usr/share/applications/btx-open.desktop}"
  write_desktop "$dest"
  desk_dir="$(dirname "$dest")"
  command -v update-desktop-database >/dev/null 2>&1 || \
    die "update-desktop-database missing"
  update-desktop-database "$desk_dir" || \
    die "update-desktop-database failed"
  if command -v xdg-mime >/dev/null 2>&1; then
    xdg-mime default btx-open.desktop x-scheme-handler/btx || \
      die "xdg-mime default failed"
  fi
  echo "install-os-handler: system $dest"
  exit 0
fi

# User-local: never pkexec/sudo.
data_home="${XDG_DATA_HOME:-}"
if [[ -z "$data_home" ]]; then
  [[ -n "${HOME:-}" ]] || die "HOME unset and XDG_DATA_HOME unset"
  data_home="$HOME/.local/share"
fi
dest="$data_home/applications/btx-open.desktop"
write_desktop "$dest"
command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database "$(dirname "$dest")" || true
if command -v xdg-mime >/dev/null 2>&1; then
  xdg-mime default btx-open.desktop x-scheme-handler/btx || \
    die "xdg-mime default failed"
else
  echo "install-os-handler: xdg-mime not found; wrote $dest"
fi
echo "install-os-handler: user-local $dest"
exit 0
