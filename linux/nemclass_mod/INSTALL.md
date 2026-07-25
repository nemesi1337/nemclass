# Installing `nemclass_mod`

An out-of-tree Linux kernel module that exposes `/proc/nemclass/`: kernel-side
process memory access + a non-ptrace debugger, gated by a symmetric key and a
uid/gid allowlist. This guide covers a throwaway dev build, a persistent DKMS
install via a symlink, loading with the key, the access-control config, and
removal.

> Loading any kernel module needs root. The **symmetric key** replaces a
> capability check for *clients* of the loaded module — it does not change the
> fact that installing/loading is a root operation.

---

## 1. Prerequisites

- Kernel build tree for the running kernel at `/lib/modules/$(uname -r)/build`
  (Manjaro/Arch: `pacman -S linux-headers` for a stock kernel; a
  self-built kernel already has it).
- `base-devel` (make, gcc) and, for the persistent install, `dkms`
  (`pacman -S dkms`).
- Required kernel config (all present on the current 7.2.0-rc3 kernel):

```sh
for c in CONFIG_MODULES CONFIG_MODULE_UNLOAD CONFIG_UPROBES \
         CONFIG_HAVE_HW_BREAKPOINT CONFIG_PERF_EVENTS; do
  printf '%s=' "$c"; zgrep -h "^$c=" /proc/config.gz \
      /lib/modules/$(uname -r)/build/.config 2>/dev/null | head -1 | cut -d= -f2
done
```

Unsigned modules load on this machine (Secure Boot off, no `module.sig_enforce`).
For Secure Boot systems see [§7](#7-secure-boot--module-signing).

---

## 2. Quick dev build (no install)

Best while iterating — build in-tree and load the `.ko` directly.

```sh
cd linux/nemclass_mod
make                                  # -> nemclass_mod.ko
sudo insmod ./nemclass_mod.ko key=deadbeefcafe
dmesg | tail -3                       # "loaded: /proc/nemclass/attach (abi 1)"
# ... use it ...
sudo rmmod nemclass_mod
```

`make clean` to wipe build artifacts (they are git-ignored).

---

## 3. Persistent install via DKMS + symlink (recommended)

DKMS rebuilds the module automatically on kernel upgrades. Instead of *copying*
the source into `/usr/src`, we **symlink** this repo directory there, so DKMS
always builds the live tree and local edits take effect on the next rebuild.

### Automated

```sh
cd linux/nemclass_mod
sudo ./install-dkms.sh                 # symlink + dkms add + build + install
```

Re-run `sudo ./install-dkms.sh` any time after editing the source to rebuild
and reinstall. Remove everything with `sudo ./install-dkms.sh uninstall`.

### Manual (what the script does)

The DKMS source path must be `/usr/src/<PACKAGE_NAME>-<PACKAGE_VERSION>`, i.e.
`/usr/src/nemclass_mod-2.0` (from `dkms.conf`).

```sh
REPO=$(pwd)/linux/nemclass_mod                 # absolute path to this dir
sudo ln -sfn "$REPO" /usr/src/nemclass_mod-2.0 # the symlink

sudo dkms add     -m nemclass_mod -v 2.0
sudo dkms build   -m nemclass_mod -v 2.0
sudo dkms install -m nemclass_mod -v 2.0
sudo dkms status  nemclass_mod                 # -> nemclass_mod/2.0, <kernel>: installed
```

`dkms install` runs `depmod`, so afterwards the module is loadable by name with
`modprobe` (no path needed).

---

## 4. Loading the module + the key

The module **fails closed**: with no `key=`, every gated ioctl returns
`-EACCES`. The key is raw hex (no `0x`), up to 64 bytes, and must match what
clients present via the AUTH handshake.

```sh
sudo modprobe nemclass_mod key=deadbeefcafe
# optional, experimental, off by default:
sudo modprobe nemclass_mod key=deadbeefcafe allow_ptrace_hide=1
```

### Load automatically at boot

```sh
# 1. auto-load the module on boot
echo nemclass_mod | sudo tee /etc/modules-load.d/nemclass_mod.conf

# 2. supply the key (and options) to modprobe
printf 'options nemclass_mod key=deadbeefcafe allow_ptrace_hide=0\n' \
  | sudo tee /etc/modprobe.d/nemclass_mod.conf
sudo chmod 600 /etc/modprobe.d/nemclass_mod.conf   # the key is a secret
```

> **Security:** persisting the key in `/etc/modprobe.d` puts the shared secret
> on disk. `chmod 600` it, or skip persistence and `modprobe` with the key by
> hand. Rotating the key = change it in both places and reload.

---

## 5. Interface & access control

The module publishes two files under `/proc/nemclass/`:

- **`attach`** — the ioctl endpoint clients open (replaces the old
  `/dev/nemclass` char device).
- **`acl`** — read-only; prints the live access policy (handy for debugging a
  denial).

Opening `attach` is **not** governed by the file's mode bits. Instead the module
enforces a uid/gid allowlist in `open()`, driven by a config file it re-reads
whenever it changes (default every 2 s — no reload needed):

```
# /etc/nemclass/access.conf  — numeric IDs only (the kernel can't resolve names)
uid 1000        # allow this user;   id -u <name>            to find it
gid 1001        # allow this group;  getent group <name>     field 3 is the gid
```

Install the shipped example and fill in your IDs:

```sh
sudo install -D -m 0644 access.conf.example /etc/nemclass/access.conf
sudoedit /etc/nemclass/access.conf                 # add your uid/gid
cat /proc/nemclass/acl                             # confirm the policy loaded
```

Rules of the gate:

- **root / `CAP_SYS_ADMIN` is always allowed** and can never be locked out.
- A missing, empty, or unparsable config **fails closed** — everyone except root
  is denied.
- The allowlist only controls *who may open* `attach`; the symmetric **key still
  gates every operation** ([§4](#4-loading-the-module--the-key)).
- A different path / poll interval can be set at load:
  `modprobe nemclass_mod key=… access_config=/etc/nemclass/access.conf access_poll_ms=2000`
  (`access_poll_ms=0` loads once and stops watching).

> Denied with `EACCES` on open? `dmesg` prints `open denied for uid N`; add that
> uid (or a gid the user is in) to the config — it takes effect within
> `access_poll_ms`, no reload.

---

## 6. Userspace tools

The test client/fixture (see `test/README.md`) build without kernel headers:

```sh
make -C linux/nemclass_mod/test        # -> test/fixture, test/nemclient
```

The Rust client lives in `nemclass-core` (`internal/process/kernel/`) and is
built by the normal `cargo build`.

---

## 7. Secure Boot / module signing

Not needed here (Secure Boot is off). On a Secure-Boot system, DKMS can sign the
module with a MOK you enroll:

```sh
# generate a MOK once, enroll it (reboot to confirm), then DKMS auto-signs:
sudo mokutil --import /var/lib/dkms/mok.pub    # follow enrollment prompt + reboot
# DKMS uses mok.key/mok.pub when present; otherwise set sign_tool in /etc/dkms/framework.conf
```

If loading is refused with `Key was rejected by service` or `Operation not
permitted`, Secure Boot + unsigned module is the cause.

---

## 8. Uninstall

```sh
sudo rmmod nemclass_mod 2>/dev/null || true
sudo ./install-dkms.sh uninstall       # dkms remove + delete the symlink
# or manually:
sudo dkms remove -m nemclass_mod -v 2.0 --all
sudo rm -f /usr/src/nemclass_mod-2.0
sudo rm -f /etc/modules-load.d/nemclass_mod.conf \
           /etc/modprobe.d/nemclass_mod.conf
sudo rm -f /etc/nemclass/access.conf              # the access allowlist
```

---

## 9. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `insmod: ... Invalid module format` | Built against a different kernel. `make clean && make`, or `dkms build` for the running kernel. |
| `modprobe: module not found` after DKMS | `dkms install` didn't run `depmod`, or wrong kernel. Check `dkms status`; run `sudo depmod -a`. |
| `open()` returns `EACCES` | Caller's uid/gid isn't in `/etc/nemclass/access.conf` (and isn't root). `dmesg` shows `open denied for uid N`; add it, or `cat /proc/nemclass/acl`. |
| gated ioctl returns `EACCES` | Module loaded without `key=`, or the client's key doesn't match. Check `dmesg` for "loaded without key". |
| `dkms build` produces nothing | Ensure the symlink target has a clean tree (`make clean`); confirm `/usr/src/nemclass_mod-2.0/dkms.conf` resolves through the symlink. |
| `/proc/nemclass/` missing after load | Load failed — check `dmesg` for the init error. |
| Load refused under Secure Boot | Sign the module ([§7](#7-secure-boot--module-signing)) or disable Secure Boot. |

Verify a healthy install:

```sh
modinfo nemclass_mod | grep -E 'filename|version|vermagic|parm'
lsmod | grep nemclass_mod
ls -l /proc/nemclass/ && cat /proc/nemclass/acl
```
