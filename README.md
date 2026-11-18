# open-codi2k

Unofficial, community-oriented **local-network tooling for the Momentum Codi 2K camera** (MOCAMIND2K-01 / CI2K). No affiliation with Momentum.

This project documents a working, cloud-independent LAN connection and research into the camera's native control protocol. It is a work in progress, not a security-hardened general-purpose client.

## Current capabilities

- Stream live 1080p camera video and microphone audio to FFmpeg / VLC (`live-av`)
- **Browser livestream with audio over HTTP / HLS**, available to other computers on the local network (`http-live`, v17)
- **Night-vision mode control:** read the current setting or set On / Off / Auto, with readback verification (`nightvision`, v17)
- Browse and retrieve MicroSD recordings; decode and recover supported recording data
- Read-only diagnostic queries for camera light/LED/alarm configuration
- Tools for examining the discontinued Android app with JADX

**Current tested version:** `codi_all_in_one_v17.py` — LAN streaming with audio and browser HLS has been tested on two physical CI2K cameras. After correcting the camera frame clock to approximately **50/3 FPS**, browser latency remained near **3 seconds** during a one-minute hands-on test. The original `live-av` VLC path, night-vision controls, and microSD operations remain available. Historical versions are retained in Git history, not as extra scripts in the repository.

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
python3 -m pip install bleak cryptography
```

**Wi-Fi provisioning has been tested on macOS Catalina with Python 3.8.2.** The BLE setup script uses the `cryptography` package; the separate LAN manager requires `pycryptodomex`.

With the camera flashing red/blue in pairing mode, run:

```bash
python3 codi_wifi.py
```

**The command above sends Wi-Fi credentials immediately; there is no `--send` flag or dry-run mode.** It prompts interactively for the Wi-Fi SSID and a hidden password, then sends an AES-128-CBC-encrypted `MOIOT_WIFISET_REQ` over BLE. The camera advertises as `CI2K`; the relevant service is `0x181C`, with write characteristic `0x181D`.

If more than one camera is advertising over BLE, use `python3 codi_wifi.py --select` to choose by BLE device address. Only the selected camera receives the provisioning packets.

On the tested Mac, all **7 of 7 packets** were successfully written. Enabling BLE notifications failed with a macOS CoreBluetooth error; the script deliberately continued sending and then waited 10 seconds for camera processing. **Successful BLE writes alone do not prove the camera joined Wi-Fi:** verify the new device in your router's LAN client list. Never paste a Wi-Fi password into a shell command, log, or GitHub issue.

### 3. Confirm the camera joined your LAN

Check your router's connected-device list for the newly joined camera. On the tested network it appeared as a **SHENZEN** device; names and addresses will differ across networks. Note the camera's new LAN IP address.

The BLE Wi-Fi setup step and LAN authentication are **separate**. The LAN client also requires the camera's **device ID (DID)** and **device key**, which are different for each device. No automatic LAN credential-discovery tool is currently provided.

### 4. Retrieve your own DID and device key from the microSD startup log

The tested Codi 2K firmware writes its identity and LAN authentication key to a **startup diagnostic log on the camera's microSD card**. This worked on two separate owned cameras.

1. Insert a compatible, formatted microSD card and allow the camera to boot and run long enough to write its diagnostic files. If the card is newly formatted, check that log files were generated.
2. Power off the camera, remove the microSD card, and mount it on your computer. Avoid removing the card while the camera is writing.
3. Find the **`19700101_LOGDATA*.txt`** file (for example, `19700101_LOGDATA.txt`). The date `19700101` is a startup-clock placeholder before the camera has acquired the correct time; it does **not** mean the log is from 1970.
4. Open that file locally and search for **`===[DID]:`** and **`===[KEY]:`**. On the tested cameras these lines were near the **beginning** of the startup log. A later section may repeat the same values as **`deviceid =`** and **`device_key =`**.
5. Record the values securely, together with the IP address you found on the router. Do **not** commit them, paste them into public bug reports, or share the full diagnostic log publicly.

Example **format only** (not real credentials):

```text
===[DID]:CI2K-YOUR_DEVICE_ID
===[KEY]:YOUR_DEVICE_KEY
```

A second log named for the current date (for example, `YYYYMMDD_LOGDATA.txt`) may contain ongoing operating and network messages. **For the two tested cameras, the `19700101_LOGDATA` startup log is the file that disclosed both credentials; the current-date log was not needed.** If you don't see these fields, check other startup logs from the same camera and firmware; do not assume every firmware version uses identical filenames or logging.

**Security warning:** The device key grants access to the camera's authenticated LAN protocol. Treat the log like a password and keep it off GitHub.

### 5. Run the LAN manager

**For every camera, specify its own `--host`, `--did`, and `--device-key`.** The repository version of v17 intentionally uses nonfunctional placeholder IP/DID defaults instead of publishing a real camera's identity. Testing with two owned CI2K cameras showed that an incorrect DID was accepted for some LAN commands when the IP and key were correct; this does **not** prove the DID is ignored throughout the protocol. Use the correct DID from that camera's startup log.

Once the camera is online and you have its correct IP, DID, and device key, run on Windows (PowerShell), replacing the example values with **your own**:

```powershell
python3 .\codi_all_in_one_v17.py live-av --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

Open VLC at `udp://@:12345`. Press **q**, then Enter, in the script console to stop live capture.

### 6. Watch the livestream in a web browser (v17)

```powershell
python3 .\codi_all_in_one_v17.py http-live --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY" --http-port 9080
```

On the host PC, visit **http://localhost:9080/livecam**. From another device on the same LAN, visit **http://HOST_PC_LAN_IP:9080/livecam** (use the Windows host computer's IP, **not** the camera's IP). The script displays reachable URLs when possible.

The server binds to `0.0.0.0` by default, so multiple LAN clients can connect. To restrict it to the host PC, add `--http-host 127.0.0.1`. If remote clients cannot connect, allow inbound TCP port `9080` on the Windows **Private** firewall profile. Run PowerShell as Administrator:

```powershell
New-NetFirewallRule -DisplayName "Codi 2K HTTP Livestream" -Direction Inbound -Protocol TCP -LocalPort 9080 -Action Allow -Profile Private
```

The HTTP server has **no login or HTTPS**. Everyone who can reach that port can view the camera. Use it only on a trusted private network; do **not** expose the port to the internet or forward it on your router. The v17 browser player uses HLS, with approximately 3 seconds of latency on the tested setup; actual delay may vary. Press Ctrl+C in the script console to stop the HTTP server and worker processes.

### 7. Read and change night vision (v17)

Read the current setting without making changes:

```powershell
python3 .\codi_all_in_one_v17.py nightvision --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

Set On, Off or Auto (writes require `--confirm`):

```powershell
python3 .\codi_all_in_one_v17.py nightvision --mode on --confirm --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
python3 .\codi_all_in_one_v17.py nightvision --mode off --confirm --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
python3 .\codi_all_in_one_v17.py nightvision --mode auto --confirm --host CAMERA_IP --did CI2K-YOUR_DEVICE_ID --device-key "YOUR_DEVICE_KEY"
```

The native CI2K RPCs are `0xA5F` (GET) and `0xA5E` (SET). The confirmed values are **1 = On, 2 = Off, 3 = Auto**. The script checks the existing setting, sends a change only when requested, and verifies using an independent GET. These modes and transitions were verified on a physical camera.

Run `python3 .\codi_all_in_one_v17.py --help` to explore other commands. Some actions can delete or format SD-card data: verify a command before running it.

## Red motion-recording LED research

The original app illuminated a **solid red LED** while motion-triggered recording was active. Motion recording on the tested camera still works, but the red indicator no longer illuminates.

Findings so far:

- Native SDK: `sdk_user_led_set` → RPC `0xA60`; `sdk_user_led_get` → RPC `0xA61`.
- The `0xA61` readout is identical in idle and motion-recording tests (`1001`). The general-light, alarm and motion-deterrent getters also remain unchanged.
- The APK's motion-deterrent-light UI is for the `CODC` model family, *not* the `CI2K`; do not assume that its values apply to this camera.
- **Unknown:** whether the LED setter controls the red recording lamp or a general enable/disable preference.

See the GitHub issues for the investigation. **Do not send speculative writes to a camera.**

## Project layout

- `codi_wifi.py` — tested first-time BLE Wi-Fi provisioning; Python 3.8-compatible on macOS, with optional `--select` for multiple cameras
- `codi_all_in_one_v17.py` — current tested LAN manager with low-latency HTTP/HLS streaming, VLC mode, night vision and microSD tools
- `codi_motion_light_readonly_probe.py` — read-only RPCs for LED/light/alarm investigation
- `export_jadx_led_analysis.py` — APK Java source/call-site exporter for JADX CLI
- `docs/led-investigation.md` — working research notes

## Privacy and licensing

Never commit device authentication keys, actual device IDs, private network details, user recordings, logs containing sensitive data, or proprietary APK/SDK/firmware binaries. Provide personal IP, DID and device key via command-line options, not source-code defaults. Original app and SDK content is not redistributed here.

Use only with cameras you own or are authorized to access. No license has been selected yet; contribution and reuse terms should be established before broader distribution.
