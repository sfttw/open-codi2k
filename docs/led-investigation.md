# Red recording-status LED investigation

## Goal

Restore the solid **red** status LED the original Momentum Secure app showed during motion-triggered SD recording on a Momentum Codi 2K (MOCAMIND2K-01; protocol model `CI2K`), while preserving successful motion recording.

## Confirmed behavior

- Motion-triggered recording continues to work.
- The red LED does **not** illuminate during motion recording.
- The blue LED illuminates during live-streaming.
- The legacy app can no longer be relied on for normal operation.
- Stable local LAN manager: `codi_all_in_one_v10.py`. **Do not overwrite or modify this baseline while probing.**

## Read-only RPC observations

Both idle and an attempted motion-recording sample produced identical responses:

| RPC | Purpose | Response (hex) | Protobuf observations |
| --- | --- | --- | --- |
| `0xA61` | status LED getter | `1001` | field 2 = 1 |
| `0xA3C` | general light getter | `1001180220034001` | fields 2=1, 3=2, 4=3, 8=1 |
| `0xA8E` | motion-activated deterrent light getter | `1890b1ec07` | field 3=16455824; **not verified as a valid setting** |
| `0xA3A` | alarm getter | `1002` | field 2=2 |

**Caveat:** The probe does not independently certify that an SD recording was in progress at the exact instant a query was made.

## Native SDK leads

Recovered Ghidra decompilation shows:

- `sdk_user_led_set`: command `0xA60`, 1 configuration argument.
- `sdk_user_led_get`: command `0xA61`.
- `sdk_user_light_set`: command `0xA3B`, 7 configuration arguments.
- `sdk_user_light_get`: command `0xA3C`.
- `sdk_user_motionactivateddeterrent_light_set`: command `0xA8D`, 2 configuration arguments.
- `sdk_user_motionactivateddeterrent_light_get`: command `0xA8E`.

The exact meaning of the `0xA60` argument and whether it controls red LED behavior have **not** been established.

The original app exposes the motion-deterrent modes Off/Constant/Strobe for a **different device family** (`CODC`). The tested camera identifies as `CI2K`; treat `0xA8D` as an unlikely path, not a validated fix.

## Next research steps

1. Inspect the native SDK's `sdk_user_led_set` serialization and return status mapping using the existing Ghidra export.
2. Trace JNI callers and CI2K-specific device initialization paths in original application code, without redistributing proprietary files.
3. Determine whether firmware owns the LED transitions or whether a persistent enable/disable flag controls them.
4. Only when a specific candidate setting is supported by evidence, write an **isolated, reversible** test utility that reads before writing, captures a response, verifies behavior, and documents restoration.
5. Once confirmed on physical hardware, integrate the feature into a future version while preserving the v10 baseline.

## Privacy

Never commit unique camera IDs, device keys, IP addresses, recordings, SDK or APK binaries, or identifiable logs. Record generalized command and response structures only.
