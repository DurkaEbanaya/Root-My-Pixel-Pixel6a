# CarrierUnlock helper

`CarrierUnlock` is a small `app_process` utility used by the financed-device
carrier-lock procedure documented in [`docs/carrier-lock.md`](../../docs/carrier-lock.md).

It uses reflection to call hidden `ITelephony` methods on Android 16:

- no arguments: print the current `CarrierRestrictionRules`;
- `clear`: call `CarrierRestrictionRules.Builder.setAllCarriersAllowed()`, submit
  the result with `setAllowedCarriers`, wait 2.5 seconds, and print the readback.

## Build

Requires a JDK and Android SDK platform/build-tools (tested with API/build-tools 36):

```bash
./tools/carrier-unlock/build.sh
```

The output is `tools/carrier-unlock/carrier-unlock.jar`. A matching prebuilt jar
is also attached to the GitHub release; keep it beside `apply_oobconfig_fix.py`.

Apply the full confirmed fix only after reading the main guide:

```bash
python3 tools/carrier-unlock/apply_oobconfig_fix.py --apply
```

The host-side script performs strict device/build/root preflight checks, creates
timestamped on-device backups, patches ABX package state, and reboots immediately.

## Run

Push the jar and run it from an already working root shell:

```bash
adb push tools/carrier-unlock/carrier-unlock.jar /data/local/tmp/

# inspect only
adb shell "echo 'CLASSPATH=/data/local/tmp/carrier-unlock.jar app_process / CarrierUnlock' \
  | /data/local/tmp/ksud debug su"

# clear restrictions
adb shell "echo 'CLASSPATH=/data/local/tmp/carrier-unlock.jar app_process / CarrierUnlock clear' \
  | /data/local/tmp/ksud debug su"
```

`setAllowedCarriers -> 0` only proves that telephony accepted the request. Always
inspect the delayed `readback`, `gsm.sim.state`, and the radio log: an enforcement
app may reapply the old list immediately.
