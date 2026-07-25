# nemclass_mod — manual test harness

Two small programs to exercise `/proc/nemclass/attach` end-to-end:

- **`fixture`** — a target process. Holds `nem_secret` and `nem_counter` at stable
  addresses, prints its pid + those addresses, then increments `nem_counter` every
  200 ms (so a write-watchpoint has something to fire on).
- **`nemclient`** — drives every ioctl (auth, read/write, region enum, hw
  watchpoint, uprobe, ptrace query/hide).

## Build

```sh
make -C linux/nemclass_mod            # the module (nemclass_mod.ko)
make -C linux/nemclass_mod/test       # fixture + nemclient
```

## Load the module

Opening `/proc/nemclass/attach` is gated by the uid/gid allowlist (root always
allowed). The `key=` value is the shared secret clients must present; it is raw
hex (no `0x`), up to 64 bytes (use a random one in real use). Add
`allow_ptrace_hide=1` only if you intend to test the experimental hide path.

```sh
sudo insmod linux/nemclass_mod/nemclass_mod.ko key=000102030405060708090a0b0c0d0e0f
dmesg | tail -3          # expect: "loaded: /proc/nemclass/attach (abi 1)"
```

Run `nemclient` as root (the device is root-only; the key gates *what* an
authenticated client may do, not who may open the node).

## Walkthrough

```sh
cd linux/nemclass_mod/test
./fixture &             # note: pid=..., secret_addr=0x..., counter_addr=0x...

KEY=000102030405060708090a0b0c0d0e0f     # must equal the module's key=
PID=<pid from fixture>
SEC=<secret_addr>
CNT=<counter_addr>

sudo ./nemclient $KEY version                 # -> abi=1
sudo ./nemclient $KEY read    $PID $SEC 8      # -> u64[0]=0x1122334455667788
sudo ./nemclient $KEY write   $PID $SEC 00000000000000ff
sudo ./nemclient $KEY read    $PID $SEC 8      # -> confirms the new value
sudo ./nemclient $KEY regions $PID             # -> /proc/pid/maps-style listing
sudo ./nemclient $KEY watch   $PID $CNT 8      # -> streams HIT events (Ctrl-C to stop)
sudo ./nemclient $KEY ptrace  $PID             # -> traced=0 tracer_pid=0
```

`watch` sets a hardware **write** watchpoint on `nem_counter`; each 200 ms increment
produces a `HIT` line with the faulting `ip` and a register snapshot — no ptrace
involved. Pass a 4th arg (`x|w|r|rw`) to change the trigger type.

### ptrace detect + hide (experimental)

```sh
# In another shell, attach a tracer so TracerPid is set:
sudo gdb -p $PID
sudo ./nemclient $KEY ptrace $PID              # -> traced=1 tracer_pid=<gdb>
# hide REFUSES while a real external tracer is attached (only with allow_ptrace_hide=1):
sudo ./nemclient $KEY hide   $PID              # -> EBUSY (external tracer would be raced)
```

> **Note:** `hide` clears the target's ptrace flag word without unlinking the
> tracer (a safe unlink needs `tasklist_lock`/`__ptrace_unlink`, not exported to
> modules), so it is racy against a live external tracer and can destabilise it.
> The module therefore **refuses** (`EBUSY`) when the tracer is in another thread
> group — as with the `gdb` above — and only permits the spoof for a process that
> ptraces *itself* as anti-debug. Off by default (`allow_ptrace_hide=1`).

## Unload

```sh
sudo rmmod nemclass_mod
kill %1                  # stop the fixture
```

Negative checks worth running: a wrong key (`sudo ./nemclient deadbeef version`
still works — VERSION is unauthenticated — but `read` returns `AUTH: Permission
denied`), and any gated ioctl before AUTH returns `-EACCES`.
