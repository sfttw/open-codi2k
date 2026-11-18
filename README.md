# open-codi2k

Unofficial, community-oriented **local-network tooling for the Momentum Codi 2K camera** (MOCAMIND2K-01 / CI2K). No affiliation with Momentum.

This project documents a working, cloud-independent LAN connection and research into the camera's native control protocol. It is a work in progress, not a security-hardened general-purpose client.

## Current capabilities

- Stream live 1080p camera video and microphone audio to FFmpeg / VLC (`live-av`)
- **Browser livestream with audio over HTTP / HLS**, available to other computers on the local network (`http-live`, v12)
- **Night-vision mode control:** read the current setting or set On / Off / Auto, with readback verification (`nightvision`, v12)
- Browse and retrieve MicroSD recordings; decode and recover supported recording data
- Read-only diagnostic queries for camera light/LED/alarm configuration
- Tools for examining the discontinued Android app with JADX

**Current tested version:** `codi_all_in_one_v12.py` — night-vision GET/SET and LAN HTTP/HLS streaming have been tested on a physical CI2K. **Preserved baseline:** `codi_all_in_one_v10.py` remains unchanged.

## Requirements

- Python 3.10+
- AES implementation: `python3 -m pip install pycryptodomex`
- FFmpeg on PATH for live audio/video and HLS streaming; VLC is optional for UDP playback
- A modern browser for the HTTP livestream (uses hls.js from a CDN in Firefox/Chrome; internet may be required for the player library)
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

This repository includes a reconstructed `codi_wifi.py` provisioning script. Start with a dry run (prompts for Wi-Fi credentials, but **does not transmit**):

```bash
python3 codi_wifi.py
```

To actually provision an unpaired camera in BLE pairing mode:

```bash
python3 codi_wifi.py --send
```

The script prompted for the Wi-Fi SSID and password, then sent an AES-128-CBC-encrypted `MOIOT_WIFISET_REQ` over BLE to the camera. It located the camera as `CI2K`, using the BLE user-data service `0x181C` and characteristic `0x181D` for packet writes. The tested connection wrote **7 of 7 packets**; BLE notifications were unavailable on that macOS setup, but the Wi-Fi provisioning succeeded anyway.

**Validation status:** The earlier `codi_wifi.py` implementation successfully provisioned the test camera. The version newly committed here reconstructs its BLE framing and encryption from the original app and test findings but **has not yet been re-tested against a factory-reset device**. Do not assume success until your router shows the camera has joined. Never paste a Wi-Fi password into a shell command, log, or GitHub issue.

### 3. Confirm the camera joined your LAN

Check your router's connected-device list for the newly joined camera. On the tested network it appeared as a **SHENZEN** device; names and addresses will differ across networks. Note the camera's new LAN IP address.

The BLE Wi-Fi setup step and LAN authentication are **separate**. The LAN client also requires the camera's **device ID (DID)** and **device key**. These must be obtained for your own camera; a first-run setup/discovery tool for those values is not yet included here. Do not use another person's DID or key.

### 4. Run the LAN manager

Once the camera is online and you have its correct IP, DID, and device key, run on Windows (PowerShell), replacing the example values with **your own**:

```powershell
python3 .\codi_all_in_one_v12.py live-av --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

Open VLC at `udp://@:12345`. Press **q**, then Enter, in the script console to stop live capture.

### 5. Watch the livestream in a web browser (v12)

```powershell
python3 .\codi_all_in_one_v12.py http-live --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY" --http-port 9080
```

On the host PC, visit **http://localhost:9080/livecam**. From another device on the same LAN, visit **http://HOST_PC_LAN_IP:9080/livecam** (use the Windows host computer's IP, **not** the camera's IP). The script displays reachable URLs when possible.

The server binds to `0.0.0.0` by default, so multiple LAN clients can connect. To restrict it to the host PC, add `--http-host 127.0.0.1`. If remote clients cannot connect, allow inbound TCP port `9080` on the Windows **Private** firewall profile. Run PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "Codi 2K HTTP Livestream" -Direction Inbound -Protocol TCP -LocalPort 9080 -Action Allow -Profile Private
```

The HTTP server has **no login or HTTPS**. Everyone who can reach that port can view the camera. Use it only on a trusted private network; do **not** expose the port to the internet or forward it on your router. The browser player uses HLS, so playback typically lags live activity by several seconds. Press Ctrl+C in the script console to stop the HTTP server and worker processes.

### 6. Read and change night vision (v12)

Read the current setting without making changes:

```powershell
python3 .\codi_all_in_one_v12.py nightvision --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

Set On, Off or Auto (writes require `--confirm`):

```powershell
python3 .\codi_all_in_one_v12.py nightvision --mode on --confirm --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
python3 .\codi_all_in_one_v12.py nightvision --mode off --confirm --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
python3 .\codi_all_in_one_v12.py nightvision --mode auto --confirm --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

The native CI2K RPCs are `0xA5F` (GET) and `0xA5E` (SET). The confirmed values are **1 = On, 2 = Off, 3 = Auto**. The script checks the existing setting, sends a change only when requested, and verifies using an independent GET. These modes and transitions were verified on a physical camera.

Run `python3 .\codi_all_in_one_v12.py --help` to explore other commands. Some actions can delete or format SD-card data: verify a command before running it.

## Red motion-recording LED research

The original app illuminated a **solid red LED** while motion-triggered recording was active. Motion recording on the tested camera still works, but the red indicator no longer illuminates.

Findings so far:

- Native SDK: `sdk_user_led_set` → RPC `0xA60`; `sdk_user_led_get` → RPC `0xA61`.
- The `0xA61` readout is identical in idle and motion-recording tests (`1001`). The general-light, alarm and motion-deterrent getters also remain unchanged.
- The APK's motion-deterrent-light UI is for the `CODC` model family, *not* the `CI2K`; do not assume that its values apply to this camera.
- **Unknown:** whether the LED setter controls the red recording lamp or a general enable/disable preference.

See the GitHub issues for the investigation. **Do not send speculative writes to a camera.**

## Project layout

- `codi_wifi.py` — first-time BLE Wi-Fi provisioning (reconstructed; requires device retest)
- `codi_all_in_one_v10.py` — preserved stable baseline
- `codi_all_in_one_v12.py` — current LAN manager with HTTP/HLS streaming, night vision and existing video/SD tools
- `codi_motion_light_readonly_probe.py` — read-only RPCs for LED/light/alarm investigation
- `export_jadx_led_analysis.py` — APK Java source/call-site exporter for JADX CLI
- `docs/led-investigation.md` — working research notes

## Privacy and licensing

Never commit device authentication keys, actual device IDs, private network details, user recordings, logs containing sensitive data, or proprietary APK/SDK/firmware binaries. Provide personal IP, DID and device key via command-line options, not source-code defaults. Original app and SDK content is not redistributed here.

Use only with cameras you own or are authorized to access. No license has been selected yet; contribution and reuse terms should be established before broader distribution.
