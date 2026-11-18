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

## First-time setup: provision Wi-Fi first

**Important:** A factory-reset / unpaired Codi 2K is not reachable using the LAN client. The camera must first be provisioned with your Wi-Fi credentials using **Bluetooth Low Energy (BLE)**. The original Momentum app is discontinued, so the reverse-engineered setup path below replaces its Wi-Fi onboarding flow.

### 1. Put the camera in pairing mode

Power on the camera. The tested camera announced that it was **ready to be paired** and flashed its LED **red/blue**.

### 2. Provision over Bluetooth

Use a computer with working Bluetooth LE. The tested setup used **macOS with Python and Bleak**, because the Windows desktop did not have Bluetooth hardware.

```bash
python3 -m pip install bleak pycryptodomex
```

The working setup used a local `codi_wifi.py` script with:

```bash
python3 codi_wifi.py --send
```

The script prompted for the Wi-Fi SSID and password, then sent an AES-128-CBC-encrypted `MOIOT_WIFISET_REQ` over BLE to the camera. It located the camera as `CI2K`, using the BLE user-data service `0x181C` and characteristic `0x181D` for packet writes. The tested connection wrote **7 of 7 packets**; BLE notifications were unavailable on that macOS setup, but the Wi-Fi provisioning succeeded anyway.

**Current limitation:** `codi_wifi.py` is **not yet included in this repository**. The command above documents the original successfully tested onboarding step; it cannot be run from a fresh clone until a reviewed, sanitized provisioning script is added. Track this as a project issue. Never paste a Wi-Fi password into a shell command, log, or GitHub issue.

### 3. Confirm the camera joined your LAN

Check your router's connected-device list for the newly joined camera. On the tested network it appeared as a **SHENZEN** device; names and addresses will differ across networks. Note the camera's new LAN IP address.

The BLE Wi-Fi setup step and LAN authentication are **separate**. The LAN client also requires the camera's **device ID (DID)** and **device key**. These must be obtained for your own camera; a first-run setup/discovery tool for those values is not yet included here. Do not use another person's DID or key.

### 4. Run the LAN manager

Once the camera is online and you have its correct IP, DID, and device key, run on Windows (PowerShell):

```powershell
python3 .\codi_all_in_one_v10.py live-av --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

Open VLC and listen to `udp://@:12345`. Press **q**, then Enter, in the script console to stop live capture.

Run `python3 .\codi_all_in_one_v10.py --help` to explore other commands. Some actions can delete or format SD card data: verify a command before running it.

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
