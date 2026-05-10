# Huawei CH100S -> openScale HANDOFF

## Source of truth

This file is the primary handoff for the Huawei Body Fat Scale work in:

`/Users/alex/experimenting/openScale`

If older notes, compacted summaries, or side-workspace notes disagree with this file, prefer this file first.

## Goal

Continue the Huawei Body Fat Scale -> openScale work for the CH100S scale.

The scale advertises as `CH100S` and uses the Huawei companion app package:

`com.huawei.ch100`

The core problem is still protocol correctness: openScale's CH100S handling has been decrypting measurement frames incorrectly, producing garbage values such as multi-ton weights, absurd body-fat percentages, and broken timestamps.

## Current status

Repository state as of 2026-05-10:

- Repo path: `/Users/alex/experimenting/openScale`
- Worktree status: clean
- Current `HEAD`: `e8ebe094`
- Latest commits:
  - `e8ebe094` Fix MAC-XOR application in CH100S - apply to concatenated result
  - `3c8ae7dc` Derive magicKey in CH100S handler - match Huawei app key derivation
  - `278d9bc9` Revert fabricated ABCDEF keys, remove double MAC-XOR from CH100S handler
  - `89b83fc5` Fix AES keys in both Huawei handlers - use real keys extracted from APK
  - `be6ccfb6` Switch to BouncyCastle SICBlockCipher for AES-CTR decryption
  - `3d65ca31` Add `huaweiDecrypt()` - exact match for `EeUtilNew.decrypt`

Latest build status:

- Latest installed build corresponding to this line of work: commit `e8ebe094`
- This exact build was described as installed but not yet validated against a fresh real measurement

## What was actually fixed

### Commit `e8ebe094`

Latest build installed, but not yet fully field-tested with a successful real CH100S measurement:

- MagicKey derivation after AUTH matching Huawei app `setKeyBytes`
- MAC-XOR restored and applied to the concatenated decrypted result
- AES CTR path aligned with Huawei flow, using CTR symmetry

### Commit `3c8ae7dc`

- `magicKey = macXor(authCode) + AES_KEY[7..15]`
- Derived on AUTH send and AUTH success
- Used in `handleEncryptedPair` and `sendEncrypted`
- Falls back to `AES_KEY` if `magicKey` is null

### Commit `278d9bc9`

- Reverted fabricated `ABCDEF` keys
- Restored correct decompiled key material
- Removed broken MAC-XOR behavior from the bad branch of experimentation

### Commit `89b83fc5`

- Applied keys extracted from the Huawei APK
- This replaced fabricated values from an unreliable summary

## Bug behavior seen across iterations

| Change | Weight | Fat | Timestamp | Notes |
|---|---:|---:|---|---|
| Original code with wrong decompiler-derived behavior | ~4000 kg | ~4800% | Dec 4802 | Both handlers were wrong |
| Fabricated `ABCDEF` keys | ~5800 kg | ~2600% | garbled | Bad summary data, not real protocol constants |
| `ABCDEF` plus no MAC-XOR | ~3900 kg | ~4800% | garbled | Still wrong |
| MagicKey plus no MAC-XOR | ~4000 kg | ~4800% | garbled | Key derivation alone was not enough |
| MagicKey plus MAC-XOR on concatenated result | not yet tested | not yet tested | not yet tested | Current installed build |

## Critical lesson

Auto-compacted summaries previously introduced fabricated protocol data. That happened once already and wasted time.

Never trust a compacted summary for:

- AES keys
- IV bytes
- claimed decrypted values
- claimed successful test results
- claimed APK reverse-engineering outputs

For constants and protocol mechanics, always re-verify from the decompiled Huawei APK.

## Verified protocol facts from Huawei APK

The Huawei app APK was pulled from device and decompiled with jadx.

APK path:

`/tmp/huawei_ch100.apk`

Decompile path:

`/tmp/huawei_decompiled/`

Important reference files:

- `sources/com/belter/btlibrary/util/EeUtilNew.java`
- `sources/com/belter/btlibrary/ble/bluetooth/device/WeightDataHandle.java`

### Correct crypto constants

Verified from `EeUtilNew.java`:

```text
keyBytes = {0x3D, 0xA2, 0x78, 0x4A, 0xFB, 0x87, 0xB1, 0x2A, 0x98, 0x0F, 0xDE, 0x34, 0x56, 0x73, 0x21, 0x56}
ivBytes  = {0x4E, 0xF7, 0x64, 0x32, 0x2F, 0xDA, 0x76, 0x32, 0x12, 0x3D, 0xEB, 0x87, 0x90, 0xFE, 0xA2, 0x19}
```

Do not change these unless a fresh APK decompile proves otherwise.

### AUTH key derivation

From Huawei `sendDataToDevice`, when `cmd == 0x24`:

1. MAC-XOR the AUTH payload with device MAC.
2. Copy those MAC-XOR'd auth bytes into `keyBytes[0..6]`.
3. Leave `keyBytes[7..15]` unchanged.
4. Write the MAC-XOR'd packet to BLE.

### Measurement decryption flow

From `WeightDataHandle.java`:

1. Receive `0xBC` frame with op `0x0E`, extract `data[3..18]`, store as first package.
2. Receive `0xBC` frame with op `0x8E`, extract `data[3..18]`, store as second package.
3. AES-CTR decrypt each 16-byte half individually with the current `keyBytes`.
4. Reconstruct a wrapped packet as `[0xBD, originalLen, 0x0E, decrypted1..., decrypted2...]`.
5. Apply MAC-XOR to the reconstructed payload starting at offset `3`.
6. Parse the resulting CMD 14 measurement structure.

### CMD 14 measurement layout

After decrypt + concatenate + MAC-XOR:

```text
data[0]    = userId              uint8
data[1-2]  = weight              LE uint16, tenths of kg
data[3-4]  = fat                 LE uint16, tenths of percent
data[5-6]  = year                LE uint16
data[7]    = month               1..12
data[8]    = day
data[9]    = hour
data[10]   = minute
data[11]   = second
data[12]   = weekOfYear
data[13-14]= resistance          LE uint16, ohms
```

### CMD 9 USER_INFO encryption

Huawei flow:

1. MAC-XOR the payload.
2. AES-CTR encrypt the MAC-XOR'd payload with current `keyBytes`.
3. Wrap with `[0xDC, len, 0x09]`.

## Code location

Primary files in this repo:

- [HuaweiCH100SHandler.kt](/Users/alex/experimenting/openScale/android_app/app/src/main/java/com/health/openscale/core/bluetooth/scales/HuaweiCH100SHandler.kt)
- [HuaweiAH100Handler.kt](/Users/alex/experimenting/openScale/android_app/app/src/main/java/com/health/openscale/core/bluetooth/scales/HuaweiAH100Handler.kt)

The active path is this repo:

`/Users/alex/experimenting/openScale`

The older `/tmp/openscale_310/` workspace from a previous session is not the primary working copy for this handoff.

## What may still be wrong

These are still plausible failure points and should be checked in this order.

1. Auth token format.
   Current implementation uses a compact synthetic auth token like:
   `[0x11, 0x22, 0x33, 0x44, 0x55, checksum, userId]`
   Huawei app uses `HuaweiAccountUtil.genertUserId()` based on random plus timestamp. If the scale expects semantics beyond "7 bytes exist", our auth payload may still be wrong even if key derivation logic matches structurally.

2. AES mode direction.
   CTR is symmetric, so `ENCRYPT_MODE` and `DECRYPT_MODE` should both work mathematically. Huawei explicitly uses `DECRYPT_MODE`. If results are still garbage, match Huawei exactly.

3. Padding/provider behavior.
   Huawei uses `AES/CTR/PKCS7Padding`. If our provider path or wrapper differs in a subtle way, match it exactly rather than reasoning from theory.

4. MAC-XOR boundary.
   Current logic must be equivalent to XORing the wrapped `0xBD` packet from byte offset `3`. Any mismatch there will corrupt every parsed field.

5. USER_INFO auth bytes.
   Be careful not to MAC-XOR auth material twice. The old notes already flagged this as suspicious.

6. Device-name matching.
   Handler currently expects `CH100S`. If the device advertises a slightly different name, the right handler will never attach.

## Next test procedure

Use a fresh real measurement on the currently installed `e8ebe094` build and verify these exact outcomes:

1. App connects and stays connected through the full measurement.
2. Weight is plausible and close to the scale display.
3. Timestamp is in the current year, not an ancient or future garbage value.
4. Resistance is plausible.
5. Body-fat value is plausible.
6. The measurement is actually persisted in openScale.

If it still fails, capture focused logs around:

- AUTH send
- AUTH success
- both measurement halves `0x0E` and `0x8E`
- derived key bytes at that moment
- post-decrypt, pre-XOR payload
- post-XOR parsed fields

## Build and install

```bash
cd /Users/alex/experimenting/openScale/android_app
echo "sdk.dir=/Users/alex/Library/Android/sdk" > local.properties
JAVA_HOME=/Library/Java/JavaVirtualMachines/openjdk-21.jdk/Contents/Home ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/openScale-debug.apk
```

## Lower-priority context from older workspace

This section is intentionally lower priority than everything above. Keep it only as supporting context, not as protocol truth.

An older parallel workspace existed at:

`/tmp/openscale_310/android_app`

What that earlier work suggested:

- Adding heartbeat/session maintenance improved connection stability and prevented timeout-style disconnects during measurement.
- That older branch showed a likely distinction between "Bluetooth session broke" and "decryption/parsing still wrong".
- It is therefore plausible that there are two separate issues:
  - transport/session stability
  - protocol correctness for decrypted composition data

What not to import blindly from that older workspace:

- any claimed successful decrypted CH100 values
- any summary-only protocol constants
- any side-by-side package naming or temporary build assumptions

Only port ideas from that workspace if they are re-verified in this repo or against fresh logs.

## Things not to do again

- Do not trust compacted summaries for protocol constants.
- Do not change the verified AES key or IV without re-decompiling the APK.
- Do not remove MAC-XOR from measurement handling.
- Do not apply MAC-XOR per half if Huawei applies it after reconstruction.
- Do not fall back to the initial key for post-AUTH measurement flow unless logs prove the magic key was never established.
- Do not rely on `adb backup` or `run-as` for the Huawei app.
- Do not use root, bootloader unlock, factory reset, or destructive scale/app actions.

## Short version

If resuming cold, start here:

1. Trust this repo and this file first.
2. Re-test commit `e8ebe094` against a real CH100S measurement.
3. If output is still garbage, instrument the exact AUTH -> key derivation -> decrypt -> MAC-XOR -> parse chain.
4. Re-verify every constant against `/tmp/huawei_decompiled/`, not against summaries.
