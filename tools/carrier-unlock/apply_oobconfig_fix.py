#!/usr/bin/env python3
"""Remove the confirmed OobConfig carrier-lock enforcer for Android user 0.

This is intentionally build-specific. It requires the temporary KernelSU root
workflow from this repository and reboots immediately after replacing package
state so PackageManager cannot rewrite the old in-memory state.
"""

import argparse
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path


PACKAGE = "com.google.android.apps.work.oobconfig"
SUPPORTED_DEVICE = "bluejay"
SUPPORTED_BUILD = "CP1A.260405.005"
REMOTE_TMP = "/data/local/tmp/oobconfig-fix"
KSUD = "/data/local/tmp/ksud"


def run(command, *, input_text=None, check=True, timeout=120):
    try:
        result = subprocess.run(
            command,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise RuntimeError(f"command not found: {command[0]}") from error
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"command failed ({result.returncode}): {detail}")
    return result


def adb_command(adb, serial, *arguments):
    command = [adb]
    if serial:
        command += ["-s", serial]
    return command + list(arguments)


def adb_shell(adb, serial, command, *, check=True, timeout=120):
    return run(
        adb_command(adb, serial, "shell", command),
        check=check,
        timeout=timeout,
    )


def root_shell(adb, serial, script, *, check=True, timeout=120):
    return run(
        adb_command(adb, serial, "shell", KSUD, "debug", "su"),
        input_text=script.rstrip() + "\n",
        check=check,
        timeout=timeout,
    )


def quote(path):
    return shlex.quote(str(path))


def adb_exists(adb):
    if os.sep in adb:
        return Path(adb).is_file()
    return shutil.which(adb) is not None


def patch_package_state(source, target):
    tree = ET.parse(source)
    root = tree.getroot()
    matches = [node for node in root.findall("pkg") if node.get("name") == PACKAGE]
    if len(matches) != 1:
        raise RuntimeError(f"expected one pkg entry for {PACKAGE}, found {len(matches)}")

    package = matches[0]
    package.set("inst", "false")
    package.set("stopped", "true")
    package.set("nl", "true")
    tree.write(target, encoding="utf-8", xml_declaration=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="acknowledge the destructive package-state change and run it",
    )
    parser.add_argument("--serial", default=os.environ.get("SERIAL"))
    parser.add_argument(
        "--force-unsupported",
        action="store_true",
        help="bypass the exact device/build check (not recommended)",
    )
    args = parser.parse_args()

    if not args.apply:
        parser.error("refusing to modify package state without --apply")

    adb = os.environ.get("ADB", "adb")
    if adb == "adb" and not adb_exists(adb):
        for candidate in (
            "/usr/local/share/android-commandlinetools/platform-tools/adb",
            str(Path.home() / "Library/Android/sdk/platform-tools/adb"),
        ):
            if Path(candidate).is_file():
                adb = candidate
                break
    if not adb_exists(adb):
        raise RuntimeError(f"adb not found: {adb}")
    base = Path(__file__).resolve().parent
    helper = base / "carrier-unlock.jar"
    if not helper.is_file():
        raise RuntimeError(f"missing {helper}; run tools/carrier-unlock/build.sh first")

    if adb_shell(adb, args.serial, "getprop sys.boot_completed").stdout.strip() != "1":
        raise RuntimeError("device is not fully booted")

    device = adb_shell(adb, args.serial, "getprop ro.product.device").stdout.strip()
    build = adb_shell(adb, args.serial, "getprop ro.build.display.id").stdout.strip()
    print(f"device={device} build={build}")
    if not args.force_unsupported and (device, build) != (SUPPORTED_DEVICE, SUPPORTED_BUILD):
        raise RuntimeError(
            f"supported only on {SUPPORTED_DEVICE}/{SUPPORTED_BUILD}; "
            "use --force-unsupported only after auditing the target build"
        )

    root_id = root_shell(adb, args.serial, "id").stdout.strip()
    print(f"root={root_id}")
    if "uid=0(root)" not in root_id:
        raise RuntimeError("KernelSU root is not active")

    user_id = 0
    installed = adb_shell(
        adb,
        args.serial,
        f"pm list packages --user {user_id} {quote(PACKAGE)}",
    ).stdout
    if f"package:{PACKAGE}" not in installed:
        print(f"{PACKAGE} is already absent for user {user_id}")
        return 0

    state_dir = f"/data/system/users/{user_id}"
    state = f"{state_dir}/package-restrictions.xml"
    reserve = f"{state}.reservecopy"
    stamp = time.strftime("%Y%m%d-%H%M%S")

    with tempfile.TemporaryDirectory(prefix="oobconfig-fix-") as temporary:
        temporary = Path(temporary)
        plain = temporary / "package-restrictions.xml"
        patched = temporary / "package-restrictions.patched.xml"

        print("disabling Wi-Fi and staging package state...")
        state_replaced = False
        try:
            root_shell(
                adb,
                args.serial,
                f"""
set -eu
svc wifi disable
svc data disable
am force-stop {quote(PACKAGE)} || true
rm -rf {quote(REMOTE_TMP)}
mkdir -p {quote(REMOTE_TMP)}
cp {quote(state)} {quote(f'{state_dir}/package-restrictions.oobconfig-{stamp}.bak')}
if [ -f {quote(reserve)} ]; then
  cp {quote(reserve)} {quote(f'{state_dir}/package-restrictions.oobconfig-{stamp}.reservecopy.bak')}
fi
abx2xml {quote(state)} {quote(f'{REMOTE_TMP}/package-restrictions.xml')}
chmod 644 {quote(f'{REMOTE_TMP}/package-restrictions.xml')}
""",
            )

            run(
                adb_command(
                    adb,
                    args.serial,
                    "pull",
                    f"{REMOTE_TMP}/package-restrictions.xml",
                    str(plain),
                )
            )
            patch_package_state(plain, patched)
            run(
                adb_command(
                    adb,
                    args.serial,
                    "push",
                    str(patched),
                    f"{REMOTE_TMP}/package-restrictions.patched.xml",
                )
            )
            run(
                adb_command(
                    adb,
                    args.serial,
                    "push",
                    str(helper),
                    f"{REMOTE_TMP}/carrier-unlock.jar",
                )
            )

            print("verifying ABX, clearing carrier rules, and replacing package state...")
            transaction = root_shell(
                adb,
                args.serial,
                f"""
set -eu
xml2abx {quote(f'{REMOTE_TMP}/package-restrictions.patched.xml')} {quote(f'{REMOTE_TMP}/package-restrictions.patched.abx')}
abx2xml {quote(f'{REMOTE_TMP}/package-restrictions.patched.abx')} {quote(f'{REMOTE_TMP}/verify.xml')}
grep -q 'name="{PACKAGE}".*inst="false"' {quote(f'{REMOTE_TMP}/verify.xml')}

pid=$(pidof {quote(PACKAGE)} || true)
[ -z "$pid" ] || kill -9 $pid
CLASSPATH={quote(f'{REMOTE_TMP}/carrier-unlock.jar')} app_process / CarrierUnlock clear

new_main={quote(f'{state_dir}/package-restrictions.oobconfig-new')}
new_reserve={quote(f'{state_dir}/package-restrictions.oobconfig-reserve-new')}
cp {quote(f'{REMOTE_TMP}/package-restrictions.patched.abx')} "$new_main"
cp {quote(f'{REMOTE_TMP}/package-restrictions.patched.abx')} "$new_reserve"
chown system:system "$new_main" "$new_reserve"
chmod 660 "$new_main" "$new_reserve"
restorecon "$new_main" "$new_reserve"
mv -f "$new_main" {quote(state)}
mv -f "$new_reserve" {quote(reserve)}
rm -rf {quote(REMOTE_TMP)}
sync
echo STATE_REPLACED
(reboot) >/dev/null 2>&1 &
""",
                check=False,
                timeout=180,
            )
            output = transaction.stdout
            print(output.strip())
            if "STATE_REPLACED" not in output:
                detail = (transaction.stderr or output).strip()
                if detail:
                    print(detail, file=sys.stderr)
                raise RuntimeError("root transaction did not confirm state replacement")
            state_replaced = True
            print("package state replaced; root shell requested immediate reboot")
            return 0
        finally:
            if not state_replaced:
                try:
                    root_shell(
                        adb,
                        args.serial,
                        f"svc wifi enable; svc data enable; rm -rf {quote(REMOTE_TMP)}",
                        timeout=30,
                    )
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    print(f"WARNING: cleanup/network restore failed: {error}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, subprocess.TimeoutExpired, ET.ParseError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
