# Root My Pixel Payloads

Native exploit payloads for Google Pixel devices. This checkout contains the
bluejay-specific KernelSU-Next LKM loader used by the Pixel 6a workflow.

## Available targets

The `src/targets/` directory contains **35 target definitions** ported from
the [IonStack](https://github.com/NebuSec/CyberMeowfia) project, covering
multiple Pixel devices and firmware versions (CP1A through CP2A).

To see the full list:

```sh
ls src/targets/
```

## How it works

1. **CVE-2026-43499** (GhostLock) — futex PI stack UAF
   - KASLR bypass via KernelSnitch or P0 Physical Oracle
   - Arbitrary kernel R/W via pipe buffer corruption + ashmem
   - CFI bypass via fake file_operations
   - Root + SELinux permissive via credential/SID patching

2. **Root daemon** — spawns via `call_usermodehelper`
   - Listens on a Unix socket for commands from the adb/Shizuku shell and the
     configured application UID
   - Keeps a temporary root client at `/data/local/tmp/su` until reboot

3. **KernelSU-Next late-load for bluejay**
   - `ksu_load.c` embeds the release `.ko` and a compact table of its 209
     imported kernel symbols
   - It reads the current `slide=...` from the exploit log and rewrites
     `SHN_UNDEF` imports to `SHN_ABS` using `link address + KASLR slide`
   - It loads the patched module with `allow_shell=1`, then runs
     `post-fs-data`, `services` and `boot-completed` through `ksud debug su`
   - `--ksu-full` performs the LKM load and all stages; `--ksu-mount` only
     repeats the stages for an already-live module
   - LKM mode on this device does not create `/dev/kernelsu`; liveness is
     checked through the KSUN Manager or `kernelsu` in `/proc/modules`

The app integration sets `PSELECT_ACCEPT_NONREADY_CFI=1`, matching the
bluejay runner. Without that environment variable the payload can reject a
valid pselect route as `quality miss` even though the same binary succeeds in
the adb runner.

## Build

```sh
export ANDROID_NDK_HOME=/path/to/android-ndk

# Build for a specific target
make TARGET=mustang-CP2A.260705.006

# Or use convenience targets
make pixel10pro      # blazer-CP2A.260705.006
make pixel10proxl    # mustang-CP2A.260705.006
make pixel10profold  # rango-CP2A.260705.006
make pixel8pro       # husky-CP2A.260705.006
make pixel8          # shiba-CP2A.260705.006
make pixel7a         # lynx-CP2A.260705.006
make pixel7pro       # cheetah-CP2A.260705.006
make pixel7          # panther-CP2A.260705.006
```

## Bluejay helper modes

The helper built for `bluejay-CP1A.260405.005` supports these additional
entry points:

```sh
# Full path after the exploit has produced /data/local/tmp/exploit.log
/data/local/tmp/cve-2026-43499-root --ksu-full \
    /data/local/tmp/ksud /data/local/tmp/exploit.log

# Re-run module stages without loading the LKM again
/data/local/tmp/cve-2026-43499-root --ksu-mount /data/local/tmp/ksud
```

The Root My Pixel fork invokes these modes through a Shizuku UserService, so
the same operations are available from the `Install` and `Mount KSU modules`
buttons without a computer or typed shell commands.

## Credits

- Exploit: [NebuSec IonStack](https://github.com/NebuSec/CyberMeowfia)
- App architecture: Adapted from [Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)
