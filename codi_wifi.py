#!/usr/bin/env python3
"""Provision an owned Momentum Codi 2K (CI2K) with Wi-Fi over Bluetooth LE.

Requires: python3 -m pip install bleak pycryptodomex
Usage: python3 codi_wifi.py --send
The camera must be in red/blue flashing pairing mode.
Does NOT retrieve the camera LAN DID or device key.
"""
import argparse
import asyncio
import getpass
import json
import sys

SERVICE_UUID = "0000181c-0000-1000-8000-00805f9b34fb"
WRITE_UUID = "0000181d-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000181e-0000-1000-8000-00805f9b34fb"
# Fixed protocol constants identified from the discontinued Android app.
AES_KEY = b"!moiot@xc#ipc$00"
AES_IV = b"0000000000000000"
FRAME_BYTES = 20
CHUNK_BYTES = FRAME_BYTES - 6


def make_frames(ssid: str, password: str) -> list[bytes]:
    try:
        from Cryptodome.Cipher import AES
        from Cryptodome.Util.Padding import pad
    except ImportError as exc:
        raise SystemExit(
            "Install AES dependency: python3 -m pip install pycryptodomex"
        ) from exc

    message = {
        "message": "MOIOT_WIFISET_REQ",
        "data": {"ssid": ssid, "passwd": password},
    }
    plaintext = json.dumps(
        message, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    encrypted = AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(
        pad(plaintext, AES.block_size)
    )
    if len(encrypted) > 0xFFFFFFFF:
        raise ValueError("Provisioning message too long")
    frames = []
    for offset in range(0, len(encrypted), CHUNK_BYTES):
        chunk = encrypted[offset:offset + CHUNK_BYTES]
        if offset == 0:
            flag = 1
        elif offset + len(chunk) >= len(encrypted):
            flag = 0
        else:
            flag = 2
        header = len(encrypted).to_bytes(4, "little") + bytes((len(chunk), flag))
        frames.append((header + chunk).ljust(FRAME_BYTES, b"\x00"))
    return frames


async def find_camera(name_filter: str, scan_seconds: float):
    from bleak import BleakScanner

    devices = await BleakScanner.discover(timeout=scan_seconds)
    matches = [
        d for d in devices
        if name_filter.casefold() in (d.name or "").casefold()
    ]
    if not matches:
        print("Camera not found. Check power, red/blue pairing mode, and BLE permissions.")
        return None
    if len(matches) == 1:
        print("Found:", matches[0].name or "(unnamed)")
        return matches[0]
    for number, device in enumerate(matches, 1):
        print(f"{number}. {device.name or '(unnamed)'} ({device.address})")
    while True:
        choice = input("Choose device number (Enter to cancel): ").strip()
        if not choice:
            return None
        if choice.isdecimal() and 1 <= int(choice) <= len(matches):
            return matches[int(choice) - 1]
        print("Invalid selection.")


async def provision(args, ssid: str, password: str) -> None:
    from bleak import BleakClient

    frames = make_frames(ssid, password)
    print(f"Prepared {len(frames)} encrypted, {FRAME_BYTES}-byte BLE packets.")
    if not args.send:
        print("DRY RUN: Nothing sent. Use --send to provision the camera.")
        return
    device = await find_camera(args.name, args.scan_seconds)
    if device is None:
        raise SystemExit(1)
    print("Connecting...")
    async with BleakClient(device, timeout=20) as client:
        if not client.is_connected:
            raise RuntimeError("BLE connection failed")
        service = client.services.get_service(SERVICE_UUID)
        if not service or not service.get_characteristic(WRITE_UUID):
            raise RuntimeError("Expected CI2K BLE write characteristic not found")
        try:
            await client.start_notify(
                NOTIFY_UUID, lambda _characteristic, _data: None
            )
            print("BLE notifications enabled.")
        except Exception:
            print("BLE notifications unavailable; continuing as in the tested Mac setup.")
        for number, packet in enumerate(frames, 1):
            await client.write_gatt_char(WRITE_UUID, packet, response=True)
            print(f"Wrote encrypted BLE packet {number}/{len(frames)}")
            await asyncio.sleep(args.packet_delay)
    print("BLE writes completed; Wi-Fi connection not yet verified.")
    print("Check your router for the camera on 2.4 GHz Wi-Fi.")
    print("Then use the LAN manager with your own camera IP, DID and device key.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Configure Codi 2K Wi-Fi via BLE. Credentials are prompted securely."
    )
    parser.add_argument("--send", action="store_true", help="Actually send Wi-Fi credentials")
    parser.add_argument("--name", default="CI2K", help="BLE name substring")
    parser.add_argument("--scan-seconds", type=float, default=8.0)
    parser.add_argument("--packet-delay", type=float, default=0.12)
    args = parser.parse_args()
    if args.scan_seconds <= 0 or args.packet_delay < 0:
        parser.error("Invalid scan or packet-delay value")
    ssid = input("2.4 GHz Wi-Fi SSID: ")
    password = getpass.getpass("Wi-Fi password (hidden): ")
    if not ssid or not password:
        raise SystemExit("SSID and password are required")
    if len(ssid.encode("utf-8")) > 32:
        raise SystemExit("SSID exceeds Wi-Fi's 32-byte limit")
    try:
        asyncio.run(provision(args, ssid, password))
    except KeyboardInterrupt:
        raise SystemExit("Cancelled") from None
    except Exception as exc:
        print(
            f"Provisioning failed ({type(exc).__name__}). "
            "Check pairing mode and retry.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
