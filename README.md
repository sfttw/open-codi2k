# open-codi2k

Unofficial, community-oriented **local-network tooling for the Momentum Codi 2K camera** (MOCAMIND2K-01 / CI2K). No affiliation with Momentum.

This project documents a working, cloud-independent LAN connection and research into the camera's native control protocol. It is a work in progress, not a security-hardened general-purpose client.

## Current capabilities

- Live video and microphone audio to FFmpeg / VLC (`live-av`)
- Browse and retrieve MicroSD recordings
- Decode supported recording data
- Read-only diagnostic queries for camera light/LED/alarm configuration
- Tools for examining the discontinued Android app with JADX

**Stable baseline:** `codi_all_in_one_v10.py` is the tested v1.0 baseline. Preserve it unchanged; experimental work should use separate scripts.

## Requirements

- Python 3.10+
- AES implementation: `python3 -m pip install pycryptodomex`
- FFmpeg and VLC for live video/audio playback
- Access to your **own** camera's LAN IP, DID and device key

## First run

```powershell
python3 .\codi_all_in_one_v10.py live-av --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

Open VLC and listen to `udp://@:12345`. Press **q**, then Enter, in the script console to stop live capture.

The command-line tool also supports `--help`. Some actions can delete or format SD card data: verify a command before running it.

## Red motion-recording LED research

The original app illuminated a **solid red LED** while motion-triggered recording was active. Motion recording on the tested camera still works, but the red indicator no longer illuminates.

Findings so far:

- Native SDK: `sdk_user_led_set` → RPC `0xA60`; `sdk_user_led_get` → RPC `0xA61`.
- The `0xA61` readout is identical in idle and motion-recording tests (`1001`). The general-light, alarm and motion-deterrent getters also remain unchanged.
- The APK's motion-deterrent-light UI is for the `CODC` model family, *not* the `CI2K`; do not assume that its values apply to this camera.
- **Unknown:** whether the LED setter controls the red recording lamp or a general enable/disable preference.

See the GitHub issues for the investigation. **Do not send speculative writes to a camera.**

## Project layout

- `codi_all_in_one_v10.py` — stable LAN interface
- `codi_motion_light_readonly_probe.py` — read-only RPCs for LED/light/alarm investigation
- `export_jadx_led_analysis.py` — APK Java source/call-site exporter for JADX CLI
- `docs/led-investigation.md` — working research notes

## Privacy and licensing

Never commit device authentication keys, actual device IDs, private network details, user recordings, logs containing sensitive data, or proprietary APK/SDK/firmware binaries. Original app and SDK content is not redistributed here.

Use only with cameras you own or are authorized to access. No license has been selected yet; contribution and reuse terms should be established before broader distribution.
