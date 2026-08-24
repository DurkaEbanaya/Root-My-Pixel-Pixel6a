# Financed-device carrier/SIM lock: diagnosis and persistent removal

This document describes the exact lock observed on a Pixel 6a (`bluejay`) running
`CP1A.260405.005`. It is **not** a generic SIM-unlock recipe and is not expected
to help with bootloader locks, SIM PIN/PUK, carrier blacklists, eSIM activation,
or locks implemented only inside modem firmware.

Use it only on a device you own or are authorized to service. Removing local
enforcement does not cancel financing, contractual obligations, account blocks,
or a server-side carrier registration.

## Confirmed architecture

The visible symptom was:

```text
gsm.sim.state=CARD_RESTRICTED
```

The modem restriction list contained Verizon identifiers and was restored within
milliseconds every time it was cleared. The component doing that was not
DeviceLock Controller. Correlated main/radio logs identified:

```text
package: com.google.android.apps.work.oobconfig
APK:     /product/priv-app/OTAConfigNoZeroTouchPrebuilt/...
tag:     OobConfig
```

Its local `oobconfig_prefs.xml` contained base64 protobuf values named
`provisioning_config` and `last_applied_simlock_config`. The decoded fields
included a SIM-lock carrier list, a carrier support URL, OEM-unlock restriction,
attestation policy, and device identifiers. Do **not** publish that file: it can
contain IMEI, serial, SIM identifiers, and an FCM token.

The runtime sequence was:

1. `CarrierRestrictionRules` is cleared through `ITelephony`.
2. The SIM briefly becomes usable.
3. `OobConfig` receives a SIM/connectivity event, runs `SimLockTask`, and calls
   `setAllowedCarriers` with the financed carrier list.
4. The SIM returns to `CARD_RESTRICTED`.

Clearing DeviceLock state, force-stopping DeviceLock Controller, wiping only
modem rules, toggling airplane mode, disabling Wi-Fi, or using `pm clear` is not
a persistent fix. `OobConfig` is a protected package: PackageManager rejects
`clear`, `uninstall`, `disable-user`, `hide`, `suspend`, and component-disable.

## Prerequisites

- exact supported Pixel/build from this repository;
- temporary root plus KernelSU-Next from this repository;
- `/system/bin/abx2xml` and `/system/bin/xml2abx` (present on the tested build);
- a workstation with Python 3 for the ABX patching script;
- `tools/carrier-unlock/carrier-unlock.jar`, either built from this repository
  or downloaded from the matching GitHub release (keep it beside the script);
- Wi-Fi/mobile data temporarily disabled while diagnosing, so provisioning is
  not downloaded again during the procedure. The script disables both Wi-Fi and
  mobile data before staging state.

The helper and package-state patch are deliberately separate:

- `CarrierUnlock` clears the current modem carrier restriction;
- `apply_oobconfig_fix.py` prevents the enforcer from running for user 0.

## 1. Identify this exact lock

```bash
adb shell getprop gsm.sim.state
adb shell 'logcat -b main -d 2>/dev/null | grep -a OobConfig | tail -20'
adb shell 'logcat -b radio -d 2>/dev/null | grep -a SET_ALLOWED_CARRIERS | tail -10'
adb shell 'pm path com.google.android.apps.work.oobconfig'
```

The key evidence is an `OobConfig: SimLockTask.run` line immediately followed by
a Verizon/carrier `SET_ALLOWED_CARRIERS`. Do not continue if that correlation is
absent: another lock owner needs another fix.

## 2. Obtain the current root session

Run `python3 run_exploit.py`, load KernelSU-Next as documented in the main README,
and verify:

```bash
adb shell "echo id | /data/local/tmp/ksud debug su"
# uid=0(root) ... context=u:r:ksu:s0
```

Disable network temporarily before clearing application state:

```bash
adb shell "echo 'svc wifi disable' | /data/local/tmp/ksud debug su"
```

## 3. Build and push the carrier helper

See [`tools/carrier-unlock/README.md`](../tools/carrier-unlock/README.md):

```bash
./tools/carrier-unlock/build.sh
adb push tools/carrier-unlock/carrier-unlock.jar /data/local/tmp/
```

Inspect before changing anything:

```bash
adb shell "echo 'CLASSPATH=/data/local/tmp/carrier-unlock.jar \
  app_process / CarrierUnlock' | /data/local/tmp/ksud debug su"
```

## 4. Apply the persistent user-state fix

Run the host-side patcher; it pulls ABX state through the KernelSU root shell,
patches it with Python on the workstation, pushes it back, clears current modem
rules, atomically swaps the state, and reboots:

```bash
python3 tools/carrier-unlock/apply_oobconfig_fix.py --apply
```

The script:

1. verifies that the protected package is installed for user 0;
2. backs up `package-restrictions.xml` and its reserve copy in
   `/data/system/users/0/`;
3. converts Android Binary XML (ABX) to ordinary XML;
4. changes the package entry to the standard per-user uninstalled state:

   ```xml
   inst="false" stopped="true" nl="true"
   ```

5. converts back to ABX and verifies the round trip;
6. kills the live `OobConfig` process and clears current modem restrictions;
7. atomically replaces the fs-verity-protected package state files and reboots.

Atomic rename is required. On the tested Android build these files have the
`fs-verity` `V` inode flag; overwriting them with `cp`/`dd` fails with `EPERM`,
while replacing the directory entry with a new inode works like Android's own
`AtomicFile` path. The reboot must happen immediately because PackageManager
still has the old installed state in memory and may otherwise rewrite the file.

## 5. Verify after reboot, with network available

Do not run the exploit again before this check. Enable Wi-Fi and verify the real
non-root runtime path:

```bash
adb shell 'cmd wifi status | grep -m1 "^Wifi is"'
adb shell 'pm list packages --user 0 | grep -c oobconfig'
adb shell 'pidof com.google.android.apps.work.oobconfig || echo PROC-NONE'
adb shell 'logcat -b main -d 2>/dev/null | grep -ac OobConfig:'
adb shell 'logcat -b radio -d 2>/dev/null | grep -c SET_ALLOWED_CARRIERS'
adb shell getprop gsm.sim.state
```

Expected result:

```text
0                 # package absent for user 0
PROC-NONE
0                 # no OobConfig activity
0                 # no carrier-rule reassertion during this boot
LOADED
```

The Wi-Fi check matters. Wiping preferences alone appeared successful offline,
but the package downloaded the provisioning config again as soon as Wi-Fi was
available and relocked the SIM in the same session. Removing the package only
for user 0 closed that runtime path while leaving the read-only system APK
untouched.

## Rollback

The script stores timestamped backups beside the original state file. Rollback
requires temporary root again:

1. convert the chosen backup with `abx2xml` and confirm it contains the original
   `com.google.android.apps.work.oobconfig` entry without `inst="false"`;
2. replace `package-restrictions.xml` and `.reservecopy` using the same atomic
   rename technique;
3. restore `system:system`, mode `0660`, and the SELinux context with `restorecon`;
4. reboot immediately.

`pm install-existing` may still be rejected while the package is protected, so
keep the generated backups until rollback is no longer needed.

The host script also uses a temporary workstation directory and does not copy
package-state XML into the repository. Treat every backup as sensitive device
state even though the main file normally contains package names rather than SIM
credentials.

## What this does not fix

### Mobile data roaming

On the tested Activ/Kcell SIM, voice registered in Russia but packet data did
not. The device was correctly configured with mobile data enabled, roaming
enabled, and the stock `Kcell Internet` APN selected. The modem reported:

```text
GPRS_SERVICES_NOT_ALLOWED_IN_PLMN
```

That is a network/HLR roaming-provisioning rejection, not a remaining phone lock.
The account or roaming agreement must be enabled by the SIM carrier.

### OEM/bootloader unlock

The OEM lock binder reported `Carrier does not allow OEM unlock`. That state is
enforced by the OEM-lock HAL/RPMB and requires a carrier-authorized signature.
Removing local SIM-lock enforcement does not make `fastboot flashing unlock`
available and does not justify editing the FRP partition blindly.

## Diagnostic notes

- Dialer secret code `*#*#7465625#*#*` maps to the package's `SIMLOCK`
  receiver, but it is diagnostic UI, not a confirmed unlock mechanism.
- `setAllowedCarriers -> 0` is not sufficient proof: correlate delayed readback,
  radio logs, process logs, and `gsm.sim.state`.
- Never commit raw `oobconfig_prefs.xml`, radio dumps, IMSI/ICCID, serial, IMEI,
  Firebase tokens, or package-state backups to a public repository.
