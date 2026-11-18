#!/usr/bin/env python3

import argparse
import asyncio
import getpass
import json
import struct

# This version intentionally supports Python 3.8 on macOS Catalina.
# It preserves the original, camera-tested BLE packet format and callbacks.

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

SERVICE_UUID = "0000181c-0000-1000-8000-00805f9b34fb"
WRITE_UUID = "0000181d-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000181e-0000-1000-8000-00805f9b34fb"

KEY = b"!moiot@xc#ipc$00"
IV = b"0000000000000000"


def encrypt_message(message):
    data = message.encode("utf-8")

    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    encryptor = cipher.encryptor()

    return encryptor.update(padded) + encryptor.finalize()


def decrypt_message(data):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    decryptor = cipher.decryptor()

    padded = decryptor.update(data) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode("utf-8")


def build_packets(encrypted):
    total = len(encrypted)
    count = total // 14 + 1
    packets = []

    for index in range(count):
        chunk = encrypted[index * 14:(index + 1) * 14]
        last = index == count - 1

        if index == 0:
            flag = 1
        elif last:
            flag = 0
        else:
            flag = 2

        packet = (
            struct.pack("<I", total)
            + bytes([len(chunk), flag])
            + chunk.ljust(14, b"\x00")
        )

        packets.append(packet)

    return packets


async def find_camera(select_camera=False):
    """Find one CI2K camera without sending credentials to any other camera.

    Without --select, use the original proven Bleak discovery behavior.
    With --select, display all currently advertising CI2K devices so the
    operator can explicitly choose the right camera by its BLE address.
    """
    if not select_camera:
        return await BleakScanner.find_device_by_filter(
            lambda d, adv: d.name == "CI2K",
            timeout=15.0
        )

    print("\nScanning for CI2K devices (15 seconds)...")
    devices = await BleakScanner.discover(timeout=15.0)
    cameras = [device for device in devices if device.name == "CI2K"]
    if not cameras:
        return None

    if len(cameras) == 1:
        print("Only one CI2K found:", cameras[0].address)
        return cameras[0]

    print("\nMultiple CI2K cameras found:")
    for index, camera in enumerate(cameras, 1):
        print("{}. {} ({})".format(index, camera.name, camera.address))
    while True:
        choice = input("Select camera number (Enter to cancel): ").strip()
        if not choice:
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(cameras):
            return cameras[int(choice) - 1]
        print("Please enter a listed number.")

async def main():
    parser = argparse.ArgumentParser(
        description="Momentum Codi 2K BLE Wi-Fi provisioning"
    )

    parser.add_argument(
        "--select", action="store_true",
        help="List nearby CI2K devices and select one if multiple are found"
    )

    args = parser.parse_args()

    ssid = input("Wi-Fi SSID: ")
    password = getpass.getpass("Wi-Fi password: ")

    message = json.dumps(
        {
            "message": "MOIOT_WIFISET_REQ",
            "data": {
                "ssid": ssid,
                "passwd": password
            }
        },
        separators=(",", ":"),
        ensure_ascii=False
    )

    encrypted = encrypt_message(message)
    packets = build_packets(encrypted)

    print("\nJSON length:", len(message.encode("utf-8")))
    print("Encrypted length:", len(encrypted))
    print("BLE packets:", len(packets))

    # Running the script now provisions the selected camera by default.
    print("\nScanning for CI2K...")

    # Without --select, this preserves the original, tested discovery path.
    # With --select, multiple cameras are listed before any BLE writes occur.
    device = await find_camera(args.select)

    if device is None:
        print("Camera not found. Check pairing mode.")
        return

    response = bytearray()
    expected_length = None
    response_complete = asyncio.Event()

    def on_notification(sender, data):
        nonlocal expected_length, response

        if len(data) < 6:
            print("Short notification:", data.hex())
            return

        total = struct.unpack("<I", data[:4])[0]
        length = data[4]
        flag = data[5]

        if length > 14 or len(data) < 6 + length:
            print("Invalid notification:", data.hex())
            return

        if flag == 1:
            response = bytearray()
            expected_length = total

        if expected_length is None:
            print("Notification without start:", data.hex())
            return

        response.extend(data[6:6 + length])

        if flag == 0:
            if len(response) != expected_length:
                print(
                    "Incomplete response:",
                    len(response),
                    "of",
                    expected_length
                )
                return

            try:
                decrypted = decrypt_message(bytes(response))
                print("\nCamera response:", decrypted)
            except Exception as exc:
                print("Could not decrypt response:", exc)

            response_complete.set()

    try:
        async with BleakClient(device) as client:
            print("Connected:", client.is_connected)

            notifications_enabled = False

            # Attempt notifications, but don't abort if macOS
            # refuses to enable them.
            try:
                await client.start_notify(
                    NOTIFY_UUID,
                    on_notification
                )
                notifications_enabled = True
                print("Notifications enabled.")

            except Exception as exc:
                print("\nNotifications unavailable:")
                print(exc)
                print(
                    "\nContinuing with Wi-Fi provisioning "
                    "without notifications."
                )

            print("\nSending Wi-Fi configuration...")

            for index, packet in enumerate(packets, 1):
                try:
                    await client.write_gatt_char(
                        WRITE_UUID,
                        packet,
                        response=True
                    )

                    print(
                        "Sent packet {}/{}".format(
                            index,
                            len(packets)
                        )
                    )

                    await asyncio.sleep(0.08)

                except Exception as exc:
                    print(
                        "\nBLE write failed on packet {}:".format(
                            index
                        )
                    )
                    print(exc)
                    return

            print("\nAll BLE packets written successfully.")

            if notifications_enabled:
                print("Waiting for camera response...")

                try:
                    await asyncio.wait_for(
                        response_complete.wait(),
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    print(
                        "No complete camera response "
                        "within 30 seconds."
                    )
            else:
                print(
                    "\nCannot receive a response because "
                    "notifications are unavailable."
                )
                print(
                    "Waiting 10 seconds for the camera "
                    "to process the configuration..."
                )
                await asyncio.sleep(10)

            if notifications_enabled:
                try:
                    await client.stop_notify(NOTIFY_UUID)
                except Exception:
                    pass

    except Exception as exc:
        print("\nBluetooth connection error:")
        print(repr(exc))
        return

    print("\nProvisioning attempt finished.")
    print("Check the camera LED and router device list.")
    print(
        "Successful BLE writes do not guarantee "
        "successful Wi-Fi configuration."
    )


if __name__ == "__main__":
    asyncio.run(main())
