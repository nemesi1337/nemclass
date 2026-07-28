#!/usr/bin/env bash
#
# install-dkms.sh — register linux/nemclass_mod with DKMS by symlinking this
# repo directory into /usr/src, then build + install for the running kernel.
# Idempotent: safe to re-run after editing the source (re-run to rebuild).
#
#   sudo ./install-dkms.sh              # symlink + add + build + install
#   sudo ./install-dkms.sh uninstall    # dkms remove + delete the symlink
#
# The symlink means DKMS always builds the current repo tree — no copying,
# no drift. After `git pull` / local edits just re-run to rebuild.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(sed -n 's/^PACKAGE_NAME="\(.*\)"/\1/p'    "$SRC_DIR/dkms.conf")"
VER="$(sed -n 's/^PACKAGE_VERSION="\(.*\)"/\1/p' "$SRC_DIR/dkms.conf")"
LINK="/usr/src/${PKG}-${VER}"

[[ $EUID -eq 0 ]]        || { echo "error: run as root (sudo)"; exit 1; }
command -v dkms >/dev/null || { echo "error: dkms is not installed"; exit 1; }

uninstall() {
	dkms remove -m "$PKG" -v "$VER" --all 2>/dev/null || true
	[[ -L "$LINK" ]] && rm -v "$LINK"
	echo "removed $PKG/$VER"
}

case "${1:-install}" in
	uninstall|remove) uninstall; exit 0 ;;
	install)          ;;
	*) echo "usage: $0 [install|uninstall]"; exit 2 ;;
esac

# Refuse to clobber a real directory someone else placed at the DKMS path.
if [[ -e "$LINK" && ! -L "$LINK" ]]; then
	echo "error: $LINK exists and is not a symlink; refusing to touch it"; exit 1
fi

# Build in a clean tree (DKMS copies from the symlink target).
make -C "$SRC_DIR" clean >/dev/null 2>&1 || true

ln -sfn "$SRC_DIR" "$LINK"
echo "symlinked $LINK -> $SRC_DIR"

dkms status -m "$PKG" -v "$VER" | grep -q . || dkms add -m "$PKG" -v "$VER"
# --force on BOTH: PACKAGE_VERSION never bumps across source edits, so a plain
# `dkms build` would see the cached object for this version and skip — silently
# reinstalling a STALE .ko. Force the rebuild so re-running always ships the
# current tree (the symlink already points DKMS at these live sources).
dkms build   -m "$PKG" -v "$VER" --force
dkms install -m "$PKG" -v "$VER" --force

cat <<EOF

Installed $PKG/$VER for kernel $(uname -r).
Load it:   sudo modprobe $PKG key=\$(head -c 32 /dev/urandom | xxd -p -c 64)   # random hex key
Access:    sudo install -D -m 0644 access.conf.example /etc/nemclass/access.conf  # then add your uid/gid
Check:     modinfo $PKG && cat /proc/nemclass/acl   # /proc/nemclass/ appears after load
Remove:    sudo $0 uninstall
EOF
