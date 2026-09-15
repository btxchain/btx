#!/usr/bin/env bash
# Second-process OpenSSL 3.5.8 runtimes for btx-modeld and btxd.
# Does NOT replace a running production btxd.real. Does not cmake a second tree.
# NEVER install over ~/.local/opt/btx-0.34.7-b094c6ba420f/libexec/btxd.real.
set -euo pipefail
if [[ -z "${OPENSSL358_PREFIX:-}" && -d "$HOME/.local/opt/openssl-3.5.8" ]]; then
  OPENSSL358_PREFIX="$HOME/.local/opt/openssl-3.5.8"
fi
PREFIX="${OPENSSL358_PREFIX:-$HOME/.local/opt/openssl-3.5.8}"
ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
BUILD="$ROOT/build-gcc13"
DEST="${DEST:-$BUILD/openssl358-second}"
PROD_LIBEXEC="$HOME/.local/opt/btx-0.34.7-b094c6ba420f/libexec"
PROD_REAL="$PROD_LIBEXEC/btxd.real"
dest_abs="$(realpath -m "$DEST")"
prod_abs="$(realpath -m "$PROD_LIBEXEC")"
if [[ "$dest_abs" == "$prod_abs" ]]; then
  echo "relink-openssl-358: refusing DEST=$DEST (production libexec)" >&2
  exit 1
fi
if [[ -e "$DEST/btxd.real" && -e "$PROD_REAL" ]]; then
  dest_id="$(stat -c '%d:%i' "$DEST/btxd.real" 2>/dev/null || true)"
  prod_id="$(stat -c '%d:%i' "$PROD_REAL" 2>/dev/null || true)"
  if [[ -n "$dest_id" && "$dest_id" == "$prod_id" ]]; then
    echo "relink-openssl-358: refusing to overwrite production btxd.real" >&2
    exit 1
  fi
fi
mkdir -p "$DEST"
export LD_LIBRARY_PATH="$PREFIX/lib:${LD_LIBRARY_PATH:-}"
"$PREFIX/bin/openssl" version
# btxd is wrapped here as a SECOND PROCESS only. Never copy onto production libexec.
for b in btxd btx-modeld test_btx btx-open btx-cli; do
  if [[ -x "$BUILD/bin/$b" ]]; then
    cp -a "$BUILD/bin/$b" "$DEST/$b.real"
    if [[ "$b" == "btxd" && -e "$PROD_REAL" ]]; then
      wrap_id="$(stat -c '%d:%i' "$DEST/btxd.real" 2>/dev/null || true)"
      prod_id="$(stat -c '%d:%i' "$PROD_REAL" 2>/dev/null || true)"
      if [[ -n "$wrap_id" && "$wrap_id" == "$prod_id" ]]; then
        echo "relink-openssl-358: DEST/btxd.real is production; abort" >&2
        exit 1
      fi
    fi
    cat >"$DEST/$b" <<EOF
#!/usr/bin/env bash
export LD_LIBRARY_PATH="$PREFIX/lib:\${LD_LIBRARY_PATH:-}"
exec "\$(dirname "\$0")/$b.real" "\$@"
EOF
    chmod +x "$DEST/$b"
  fi
done
echo "wrappers in $DEST"
if [[ -x "$DEST/btx-modeld.real" ]]; then
  ldd "$DEST/btx-modeld.real" | grep -E 'libssl|libcrypto' || true
fi
if [[ -x "$DEST/btxd.real" ]]; then
  ldd "$DEST/btxd.real" | grep -E 'libssl|libcrypto' || true
fi
echo "Run as $DEST/btx-modeld or $DEST/btxd (LD_LIBRARY_PATH=3.5.8)."
echo "Do not swap live $PROD_REAL. Do not SIGKILL production btxd."
