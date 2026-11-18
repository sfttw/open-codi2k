#!/usr/bin/env python3
"""Read the Codi 2K IR-cut / night-vision mode without changing camera settings.

Requires codi_all_in_one_v10.py in the same directory.
Original Momentum Secure application maps 1=On, 2=Off, 3=Auto.
Native SDK uses RPC 0xA5F (GET) and 0xA5E (SET); this program sends GET only.
"""
import argparse
import time

import codi_all_in_one_v10 as sdk


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.1.100")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--did", default="CI2K-YOUR_DEVICE_ID")
    parser.add_argument("--device-key", required=True)
    parser.add_argument("--channel", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=6.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    print("READ ONLY: night-vision / IR-cut GET (0xA5F); no settings changes.")
    with sdk.Camera(args) as cam:
        for _ in cam.packets(1.5):
            pass
        cam.send(0xA5F, sdk.integer(1, args.channel))
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            for kind, msgid, flags, plain in cam.packets(
                min(0.5, max(0.01, deadline - time.monotonic()))
            ):
                if kind != "control" or msgid != 0xA5F:
                    continue
                print(f"flags=0x{flags:02x}; raw={plain.hex()}")
                try:
                    fields = list(sdk.protobuf(plain))
                    print("fields=", fields)
                    values = [v for f, w, v in fields if w == 0 and v in (1, 2, 3)]
                    if values:
                        print("Possible night-vision mode values:", values)
                        print("App mapping: 1=On, 2=Off, 3=Auto")
                        print("Verify response status before treating any value as confirmed.")
                except (ValueError, IndexError) as exc:
                    print("Decode error:", exc)
                return
        raise RuntimeError("No response to 0xA5F before timeout")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"ERROR: {exc}")
