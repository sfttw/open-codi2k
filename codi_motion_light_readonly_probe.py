#!/usr/bin/env python3
"""Read-only Codi 2K motion/deterrent/status LED configuration probe.

Requires codi_all_in_one_v10.py in the same directory. Never sends SET RPCs.
"""
import argparse
import time
import codi_all_in_one_v10 as sdk

GETTERS = [
    (0xA8E, 'motion-activated deterrent light GET'),
    (0xA3C, 'general light GET'),
    (0xA61, 'status LED GET'),
    (0xA3A, 'alarm GET'),
]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='192.168.1.100')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--did', default='CI2K-YOUR_DEVICE_ID')
    parser.add_argument('--device-key', required=True)
    parser.add_argument('--channel', type=int, default=0)
    parser.add_argument('--timeout', type=float, default=4)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error('--timeout must be positive')
    print('READ ONLY: four GET RPCs, no settings changes or recording commands.', flush=True)
    with sdk.Camera(args) as cam:
        # Authenticate and service heartbeats before querying.
        for _ in cam.packets(1.5):
            pass
        for rpc, label in GETTERS:
            print(f'\n{label}: RPC 0x{rpc:03X}', flush=True)
            cam.send(rpc, sdk.integer(1, args.channel))
            deadline = time.monotonic() + args.timeout
            result = None
            while time.monotonic() < deadline:
                for kind, msgid, flags, plain in cam.packets(min(0.5, max(0.01, deadline-time.monotonic()))):
                    if kind == 'control' and msgid == rpc:
                        try:
                            fields = list(sdk.protobuf(plain))
                        except (ValueError, IndexError) as exc:
                            fields = f'protobuf decode error: {exc}'
                        result = (flags, plain.hex(), fields)
                        break
                if result is not None:
                    break
            if result is None:
                print('  No response (timeout)', flush=True)
            else:
                flags, raw, fields = result
                print(f'  flags=0x{flags:02x}; raw={raw}; fields={fields}', flush=True)
                if rpc == 0xA8E:
                    print('  NOTE: This feature may be unsupported; do not interpret field 3 as an on/off value.', flush=True)
    print('\nFinished; no write RPCs were sent.', flush=True)

if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f'ERROR: {exc}')