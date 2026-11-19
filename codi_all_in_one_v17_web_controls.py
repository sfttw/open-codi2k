#!/usr/bin/env python3
"""Local camera manager for the Momentum Codi 2K (CI2K), development v17.

The original cloud app has been discontinued. This program communicates with
an already-provisioned camera directly over its private LAN protocol.

QUICK START (PowerShell, with your own camera credentials):
    python3 .\\codi_all_in_one_v17_web_controls.py live-av --device-key YOUR_KEY
    python3 .\\codi_all_in_one_v17_web_controls.py http-live --http-port 9080 --device-key YOUR_KEY
    python3 .\\codi_all_in_one_v17_web_controls.py nightvision --device-key YOUR_KEY

BROWSER VIEWER:
    On this PC: http://localhost:9080/livecam
    Other PCs:   http://THIS-PC-LAN-IP:9080/livecam

ARCHITECTURE OVERVIEW:
    Camera TCP connection (encrypted control RPCs, H.264 video, A-law audio)
         |  Python decrypts video and handles keepalive packets
         +--> localhost UDP 12348 (H.264) ----+
         +--> localhost UDP 12347 (A-law) ----+--> ONE FFmpeg process
                                                  | live-av: MPEG-TS to VLC
                                                  | http-live: HLS files
                                                      -> HTTP on port 9080

The HTTP server only SERVES HLS files; it does not process camera packets.
v17 retains the single-FFmpeg pipeline, console shutdown, browser player,
and camera-reconnect logic. The HTTP video clock is corrected to the rate
inferred from real camera video/audio packet counts (50/3 FPS).
The browser now uses adaptive playback-rate correction and occasional guarded
live-edge seeks to prevent latency from accumulating over long sessions.
A read-only /livecam/health.json endpoint reveals whether FFmpeg continues to
publish new HLS segments, allowing upstream delay to be distinguished from
browser-side buffering.
All HLS settings can be tuned without editing this file.

For BOTH live-av and http-live, type q or quit, then Enter, to stop the camera,
FFmpeg, and (when applicable) the HTTP server cleanly. Ctrl+C still works.
The legacy v12 design had a second FFmpeg/UDP hop; v13 removes that hop.
The camera's existing RPC, SD recording, and night-vision functions remain.

Python 3.10+; AES dependency: python3 -m pip install pycryptodomex
FFmpeg must be installed and discoverable on PATH for live streaming.
This program is development software and its HTTP viewer has no password.
"""
import argparse
import http.server
import json
import subprocess
from urllib.parse import urlsplit
import hashlib
import re
import socket
import sys
import time
from datetime import date, datetime
from pathlib import Path

try:
    from Cryptodome.Cipher import AES
except ImportError:
    try:
        from Crypto.Cipher import AES
    except ImportError:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        except ImportError:
            raise SystemExit('Install AES support: python3 -m pip install pycryptodomex')
        class AES:
            MODE_CBC = 2
            @staticmethod
            def new(key, mode, iv):
                if mode != 2: raise ValueError('CBC required')
                class _Cipher:
                    def encrypt(self, data):
                        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
                        return e.update(data) + e.finalize()
                    def decrypt(self, data):
                        d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
                        return d.update(data) + d.finalize()
                return _Cipher()

# Camera's proprietary RPC framing uses an MD5-derived AES-CBC key per message.
# This is reverse-engineered compatibility logic, not modern transport security.
# Keep the authentication and encrypted-payload routines unchanged unless the
# camera protocol itself has been revalidated against hardware.
RPC_SECRET = 'P2p0r1p8c0622'
CHUNK = 4096
ENCRYPTED_PREFIX = 496


def vi(n):
    """Encode an unsigned protobuf-style variable-length integer (varint)."""
    if n < 0: raise ValueError('negative varint')
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def read_vi(data, pos):
    """Decode one varint; return (value, next_offset), or None if truncated."""
    n = 0
    for shift in range(0, 70, 7):
        if pos >= len(data): return None
        b = data[pos]; pos += 1
        n |= (b & 127) << shift
        if b < 128: return n, pos
    raise ValueError('oversized varint')


def integer(field, value): return vi(field << 3) + vi(value)


def string(field, value):
    data = value.encode('utf-8')
    return vi((field << 3) | 2) + vi(len(data)) + data


def rpc_crypt(data, msgid, seq, flags, decrypt=False):
    """Encrypt/decrypt a control RPC with its message-specific AES-CBC key.

    The camera derives key material from the message ID, sequence and flags.
    Padding is PKCS#7. These details are specific to the original SDK.
    """
    digest = hashlib.md5(f'{RPC_SECRET},ID:{msgid}-SEQ:{seq}-RPC:{flags & 3}'.encode()).hexdigest().encode('ascii')
    aes = AES.new(digest, AES.MODE_CBC, iv=digest[:16])
    if decrypt:
        if len(data) % 16: raise ValueError('RPC ciphertext not block-aligned')
        plain = aes.decrypt(data)
        if not plain: raise ValueError('empty RPC plaintext')
        pad = plain[-1]
        if pad < 1 or pad > 16 or plain[-pad:] != bytes([pad]) * pad:
            raise ValueError('bad RPC padding')
        return plain[:-pad]
    pad = 16 - len(data) % 16
    return aes.encrypt(data + bytes([pad]) * pad)


def make_packet(seq, msgid, flags, payload):
    body = vi(seq) + vi(msgid) + bytes([flags])
    if flags & 3: body += vi(0)
    body += rpc_crypt(payload, msgid, seq, flags)
    return b'\x48' + vi(len(body)) + body


def parse_control(body):
    """Parse and decrypt a 0x48 control frame (including login/RPC replies)."""
    a = read_vi(body, 0)
    if a is None: raise ValueError('missing sequence')
    seq, pos = a
    a = read_vi(body, pos)
    if a is None: raise ValueError('missing message ID')
    msgid, pos = a
    if pos >= len(body): raise ValueError('missing flags')
    flags = body[pos]; pos += 1
    if flags & 3:
        a = read_vi(body, pos)
        if a is None: raise ValueError('missing RPC extra')
        _, pos = a
    return seq, msgid, flags, rpc_crypt(body[pos:], msgid, seq, flags, decrypt=True)


def protobuf(data):
    """Iterate protobuf wire fields: (field_number, wire_type, value).

    The observed firmware uses wire type 0 (integer) and 2 (byte string) for
    the commands handled here. Other wire types deliberately raise an error.
    """
    pos = 0
    while pos < len(data):
        a = read_vi(data, pos)
        if a is None: raise ValueError('truncated protobuf tag')
        tag, pos = a
        field, wire = tag >> 3, tag & 7
        if wire == 0:
            a = read_vi(data, pos)
            if a is None: raise ValueError('truncated protobuf integer')
            value, pos = a
        elif wire == 2:
            a = read_vi(data, pos)
            if a is None: raise ValueError('truncated protobuf length')
            length, pos = a
            value = data[pos:pos+length]
            if len(value) != length: raise ValueError('truncated protobuf bytes')
            pos += length
        else:
            raise ValueError(f'unsupported protobuf wire type {wire}')
        yield field, wire, value


def decode_chunk(data, file_id, offset, secret='', encrypted_length=ENCRYPTED_PREFIX):
    """Decrypt the first 496 bytes (or aligned available prefix) of one 4096-byte chunk."""
    if offset % CHUNK:
        raise ValueError(f'Unaligned file offset {offset}')
    n = min(encrypted_length, len(data))
    n -= n % 16
    if not n: return data
    digest = hashlib.md5(f'{secret},FileID:{file_id}-:-FileOffset:{offset}'.encode()).hexdigest().encode('ascii')
    plain = AES.new(digest, AES.MODE_CBC, iv=digest[16:32]).decrypt(data[:n])
    return plain + data[n:]


class Camera:
    """Authenticated TCP session for the camera's proprietary LAN protocol.

    send() creates encrypted RPC frames; packets() yields control/data frames.
    RPC 0x6B is a keepalive request and must be acknowledged to keep the
    session healthy. This class is shared by SD management and night vision.
    """
    def __init__(self, args):
        self.args = args
        self.sock = None
        self.buffer = bytearray()
        self.seq = 1

    def __enter__(self):
        # Camera login: SDK RPC 0xA32 carries DID, Unix timestamp and key.
        # The connection uses a short recv timeout so keepalives and stop
        # checks are serviced even when the camera temporarily goes quiet.
        self.sock = socket.create_connection((self.args.host, self.args.port), timeout=8)
        self.sock.settimeout(0.4)
        self.send(0xa32, string(1, self.args.did) + integer(3, int(time.time())) + string(4, self.args.device_key))
        print(f'Connected to {self.args.host}:{self.args.port}', flush=True)
        return self

    def __exit__(self, *exc):
        if self.sock: self.sock.close()

    def send(self, msgid, payload, seq=None, flags=0x0c):
        """Send one encrypted command RPC with a monotonically increasing ID."""
        if seq is None:
            seq = self.seq
            self.seq += 1
        self.sock.sendall(make_packet(seq, msgid, flags, payload))

    def packets(self, seconds):
        """Yield fully assembled frames, even when TCP splits them across recv calls.

        0x48 is a control response. 0x88 is binary data (e.g. recordings).
        The buffer may contain multiple complete frames or a partial frame.
        The parser must preserve any incomplete bytes for the next recv.
        """
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while self.buffer:
                marker = self.buffer[0]
                if marker not in (0x48, 0x88):
                    raise ValueError(f'Unexpected packet marker 0x{marker:02x}')
                head = read_vi(self.buffer, 1)
                if head is None: break
                size, start = head
                if size > 8 * 1024 * 1024: raise ValueError('Implausible packet length')
                end = start + size
                if len(self.buffer) < end: break
                body = bytes(self.buffer[start:end]); del self.buffer[:end]
                if marker == 0x48:
                    seq, msgid, flags, plain = parse_control(body)
                    if msgid == 0x6b and not (flags & 3):
                        self.send(0x6b, plain, seq=seq, flags=0x0d)
                    yield 'control', msgid, flags, plain
                else:
                    yield 'data', None, None, body
            try:
                data = self.sock.recv(65536)
                if not data: return
                self.buffer.extend(data)
            except socket.timeout:
                yield 'tick', None, None, None

    def history(self, day):
        # Give camera time to process authentication before requesting history.
        for _ in self.packets(3): pass
        req = ((integer(1, self.args.channel) if self.args.channel else b'') +
               integer(2, day.year) + integer(3, day.month) + integer(4, day.day) +
               integer(5, 1) + integer(6, self.args.page_size) + integer(7, 86400) + integer(8, 1))
        self.send(0xa73, req)
        for kind, msgid, flags, plain in self.packets(self.args.timeout):
            if kind == 'control' and msgid == 0xa73 and flags & 3:
                entries = []
                for field, wire, value in protobuf(plain):
                    if field == 2 and wire == 2:
                        item = {f: v for f, w, v in protobuf(value) if w == 0}
                        if 3 in item: entries.append(item)
                return entries
        raise RuntimeError('Timed out waiting for recording history')

    def download(self, file_id, destination):
        temp = destination.with_name(destination.name + '.part')
        if destination.exists() or temp.exists():
            raise FileExistsError(f'File exists, refusing overwrite: {destination} or {temp}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        request = (integer(1, self.args.channel) if self.args.channel else b'') + integer(2, file_id)
        self.send(0xa76, request)
        print(f'Downloading {file_id} -> {destination.name}', flush=True)
        total = 0
        packets = 0
        expected_size = None
        last_data = None
        start = time.monotonic()
        saw_response = False
        try:
            with temp.open('wb') as fp:
                for kind, msgid, flags, plain in self.packets(self.args.timeout):
                    if kind == 'tick':
                        if packets and last_data and time.monotonic() - last_data >= self.args.idle:
                            break
                        continue
                    if kind == 'control':
                        if msgid == 0xa76 and flags & 3:
                            saw_response = True
                            fields = list(protobuf(plain))
                            status = [v for f, w, v in fields if f == 1 and w == 0]
                            if status and status[0] != 0:
                                raise RuntimeError(f'Camera rejected download: status {status[0]}')
                            # Field 3 appears to be the file size in tested responses.
                            sizes = [v for f, w, v in fields if f == 3 and w == 0 and v > 0]
                            if sizes: expected_size = sizes[0]
                    else:
                        a = read_vi(plain, 0)
                        if a is None: raise ValueError('Missing recording ID')
                        rec_id, pos = a
                        a = read_vi(plain, pos)
                        if a is None: raise ValueError('Missing recording offset')
                        offset, pos = a
                        # File-packet header: processing mode 3, followed by a
                        # varint giving the encrypted prefix length. A short final
                        # packet can use 384 instead of the usual 496 bytes.
                        if pos >= len(plain):
                            raise ValueError(f'Truncated packet metadata at offset {offset}')
                        mode = plain[pos]
                        if mode != 3:
                            raise ValueError(f'Unknown packet processing mode {mode} at offset {offset}')
                        parsed = read_vi(plain, pos + 1)
                        if parsed is None:
                            raise ValueError(f'Truncated encryption length at offset {offset}')
                        encrypted_length, payload_start = parsed
                        payload = plain[payload_start:]
                        if encrypted_length > len(payload) or encrypted_length > ENCRYPTED_PREFIX or encrypted_length % 16:
                            raise ValueError(
                                f'Invalid encrypted prefix length {encrypted_length} for '
                                f'{len(payload)}-byte packet at offset {offset}; '
                                f'prefix={plain[:32].hex()}')
                        if rec_id != file_id: raise ValueError(f'Wrong recording ID: {rec_id}')
                        if offset != total: raise ValueError(f'Gap or overlap: expected {total}, got {offset}')
                        if len(payload) > CHUNK: raise ValueError('Oversized recording chunk')
                        if total % CHUNK: raise ValueError('Unaligned recording chunk')
                        if len(payload) < CHUNK:
                            print(f'  Final-size candidate: {len(payload)}-byte chunk, {encrypted_length} encrypted bytes')
                        fp.write(decode_chunk(payload, file_id, offset, self.args.media_secret, encrypted_length))
                        total += len(payload)
                        packets += 1
                        last_data = time.monotonic()
                        if packets % 50 == 0:
                            print(f'  {total:,} bytes ({packets} packets)', flush=True)
                        if expected_size is not None and total >= expected_size:
                            if total != expected_size:
                                raise ValueError(f'Exceeded expected file size {expected_size}')
                            break
                    if packets and last_data and time.monotonic() - last_data >= self.args.idle:
                        break
                    if time.monotonic() - start >= self.args.timeout:
                        break
                fp.flush()
            if not packets: raise RuntimeError('No recording data received')
            if expected_size is not None and total != expected_size:
                raise RuntimeError(f'Incomplete recording: got {total}, expected {expected_size}')
            if expected_size is None:
                # A completed 4096-byte chunk is not proof of EOF. A shorter
                # final chunk is useful evidence but not a cryptographic guarantee.
                if total % CHUNK == 0:
                    raise RuntimeError(
                        'Unconfirmed completion: transfer stopped on a full 4096-byte chunk; '
                        'keeping .part instead of publishing a possibly truncated MP4')
                print('  Warning: camera file size not confirmed; short final chunk suggests EOF (not independently verified)')
            with temp.open('rb') as fp:
                header = fp.read(12)
            if header[4:8] != b'ftyp':
                raise RuntimeError('Decrypted output lacks MP4 ftyp signature; preserving .part for inspection')
            temp.replace(destination)
            print(f'Saved playable MP4: {destination.resolve()} ({total:,} bytes)', flush=True)
            return total
        except BaseException:
            print(f'Incomplete/invalid transfer preserved (if created): {temp}', file=sys.stderr)
            raise



# Unified live-capture support; shares the same Camera authentication and RPC codec.
class LiveCamera(Camera):
    """Camera session that also parses 0x68 real-time video/audio packets.

    packets() in the base class handles 0x48 control and 0x88 data packets;
    live frames add 0x68 and keep track of remote connection closure.
    """
    def __enter__(self):
        self.disconnected = False
        return super().__enter__()

    def frames(self, seconds):
        """Yield realtime 0x68 media frames plus control frames.

        This method deliberately shares the base Camera's existing TCP socket,
        authentication sequence, receive buffer and heartbeat handling.
        """
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while self.buffer:
                marker = self.buffer[0]
                if marker not in (0x48, 0x68, 0x88):
                    raise ValueError(f'Unknown marker 0x{marker:02x}; buffer prefix={self.buffer[:64].hex()}')
                parsed = read_vi(self.buffer, 1)
                if parsed is None: break
                size, start = parsed
                if size > 8 * 1024 * 1024:
                    raise ValueError(f'Implausible packet length {size} after marker 0x{marker:02x}; prefix={self.buffer[:64].hex()}')
                end = start + size
                if len(self.buffer) < end: break
                raw = bytes(self.buffer[:end])
                body = bytes(self.buffer[start:end])
                del self.buffer[:end]
                if marker == 0x48:
                    seq, msgid, flags, plain = parse_control(body)
                    if msgid == 0x6b and not (flags & 3):
                        self.send(0x6b, plain, seq=seq, flags=0x0d)
                    yield marker, msgid, flags, plain, raw
                else:
                    yield marker, None, None, body, raw
            try:
                data = self.sock.recv(65536)
                if not data:
                    self.disconnected = True
                    return
                self.buffer.extend(data)
            except socket.timeout:
                yield None, None, None, None, b''


# Offline reference-based recovery. No camera connection is used.
def recovery_vi(b,p):
 v=s=0
 while p<len(b):
  c=b[p];p+=1;v|=(c&127)<<s
  if c<128:return v,p
  s+=7
 raise ValueError('bad varint')
def recovery_frames(path):
 b=path.read_bytes();p=0
 while p<len(b):
  marker=b[p];p+=1
  n,p=recovery_vi(b,p)
  if p+n>len(b):raise ValueError('truncated capture')
  body=b[p:p+n];p+=n
  if marker==0x68:yield body



def run_recovery(args):
    import subprocess
    from collections import Counter
    ref = subprocess.check_output(['ffmpeg', '-v', 'error', '-i', str(args.recording),
                                   '-map', '0:v:0', '-c', 'copy', '-bsf:v', 'h264_mp4toannexb', '-f', 'h264', '-'])
    hits, stats, last = [], Counter(), -1
    for i, b in enumerate(recovery_frames(args.capture)):
        key = b[:4] == b'\x81\x03\x00\x00'
        if key:
            if len(b) < 560: stats['short_key'] += 1; continue
            if b[10:12] != b'\xf0\x03': stats['other_key_prefix'] += 1; continue
            off = 508
        elif b[:4] == b'\x01\x00\x00\x00': off = 12
        else: stats['unknown_frame'] += 1; continue
        pos = ref.find(b[off:off+48])
        if pos < 0: stats['no_match'] += 1; continue
        if pos <= last: stats['nonmonotonic'] += 1; continue
        clear = b[off:]
        if ref[pos:pos+len(clear)] != clear: stats['partial_match'] += 1; continue
        if key:
            if pos < 496: stats['key_outside_reference'] += 1; continue
            frame = ref[pos-496:pos] + clear
        else: frame = clear
        hits.append((i, pos, frame, key)); last = pos
        stats['matched_key' if key else 'matched_delta'] += 1
    if not hits: raise RuntimeError('No matching frames; recording must overlap live capture')
    first = next((j for j, (_, _, _, k) in enumerate(hits) if k), None)
    if first is None: raise RuntimeError('No matching keyframe')
    chosen = hits[first:]
    args.output.write_bytes(b''.join(frame for _, _, frame, _ in chosen))
    print('Matched frames:', dict(stats))
    print('Recovered H.264:', args.output, f'({args.output.stat().st_size:,} bytes)')
    print('Note: matching SD recording is still required for encrypted keyframe prefixes.')
    if args.mp4:
        mp4 = args.mp4
        subprocess.run(['ffmpeg','-y','-v','error','-fflags','+genpts','-r','15','-f','h264',
                        '-i',str(args.output),'-c','copy','-movflags','+faststart',str(mp4)], check=True)
        print('Recovered MP4:', mp4)


def decode_live_frame(body):
    """Decode the H.264 payload carried in one SDK 0x68 video frame.

    First bytes: 0x81 for a keyframe or 0x01 for a delta frame, followed by
    mode, four varints (channel, sequence, timestamp, encrypted prefix size).
    Some frames encrypt a short AES-CBC prefix; the rest is plain H.264.
    The decryption key is derived from the camera's sequence/timestamp fields.
    The formula was validated against known plaintext while investigating the
    camera. Raises rather than attempting to guess an unsupported format.

    Returns (complete_h264_bytes, is_keyframe, original_camera_timestamp).
    """
    if len(body) < 8:
        raise ValueError('short live media packet')
    kind, mode = body[:2]
    p = 2
    fields = []
    for _ in range(4):
        result = read_vi(body, p)
        if result is None: raise ValueError('truncated media header')
        value, p = result
        fields.append(value)
    channel, seq, timestamp, enc_len = fields
    if p + enc_len > len(body): raise ValueError('encrypted prefix beyond packet')
    if kind not in (0x81, 0x01): raise ValueError(f'unsupported media kind {kind:#x}')
    if mode != (3 if kind == 0x81 else 0):
        raise ValueError(f'unexpected media mode {mode}')
    if enc_len:
        if enc_len % 16: raise ValueError('encrypted prefix is not block aligned')
        formula = f',AVSeq:{seq}-TT:{timestamp}-AVChannel:{channel}'
        digest = hashlib.md5(formula.encode('ascii')).hexdigest().encode('ascii')
        prefix = AES.new(digest, AES.MODE_CBC, iv=digest[-16:]).decrypt(body[p:p+enc_len])
    else:
        prefix = b''
    return prefix + body[p+enc_len:], kind == 0x81, timestamp


def run_decode_live(args):
    """Offline, reference-free recovery from a saved live capture."""
    import subprocess
    from collections import Counter
    stats = Counter()
    output = args.output or Path('codi_live_independent.h264')
    output.parent.mkdir(parents=True, exist_ok=True)
    started = False
    with output.open('wb') as fp:
        for body in recovery_frames(args.capture):
            try:
                frame, is_key, ts = decode_live_frame(body)
            except ValueError as exc:
                stats['skipped'] += 1
                if stats['skipped'] <= 3: print('Skipped media packet:', exc)
                continue
            if is_key: started = True
            if not started:
                stats['before_first_key'] += 1
                continue
            fp.write(frame)
            stats['keyframes' if is_key else 'delta_frames'] += 1
    print('Independent AES recovery:', dict(stats))
    print(f'H.264 output: {output} ({output.stat().st_size:,} bytes)')
    if not stats['keyframes']:
        raise RuntimeError('No keyframes decoded; no playable stream produced')
    if args.mp4:
        subprocess.run(['ffmpeg', '-y', '-v', 'error', '-fflags', '+genpts',
                        '-r', '15', '-f', 'h264', '-i', str(output), '-c', 'copy',
                        '-movflags', '+faststart', str(args.mp4)], check=True)
        print('MP4 output:', args.mp4)


def run_live(args):
    """Timestamped live MPEG-TS over localhost UDP, with camera reconnects.

    FFmpeg re-encodes at 15 FPS to establish explicit presentation timestamps.
    The known-good v5 copy path remains available via --video-mode copy.
    """
    import shutil
    import subprocess
    import threading
    from collections import Counter

    if shutil.which('ffmpeg') is None:
        raise RuntimeError('FFmpeg not found on PATH')
    if not 1 <= args.udp_port <= 65535:
        raise ValueError('--udp-port must be 1..65535')
    if args.reconnect_delay <= 0 or args.stall_timeout <= 0:
        raise ValueError('--reconnect-delay and --stall-timeout must be positive')
    if args.video_mode == 'timestamped':
        # Explicit PTS are created by setpts. Re-encoding is necessary for this
        # filter; use ultrafast / zero latency to keep overhead low.
        codec = ['-vf', 'setpts=N/(15*TB)', '-c:v', 'libx264',
                 '-preset', 'ultrafast', '-tune', 'zerolatency',
                 '-bf', '0', '-g', '15', '-pix_fmt', 'yuv420p']
    else:
        codec = ['-c:v', 'copy']
    url = f'udp://127.0.0.1:{args.udp_port}?pkt_size=1316'
    command = ['ffmpeg', '-hide_banner', '-loglevel', 'warning', '-nostdin',
               '-fflags', '+genpts', '-r', '15', '-f', 'h264', '-i', 'pipe:0',
               '-an', *codec, '-muxdelay', '0', '-muxpreload', '0',
               '-f', 'mpegts', url]
    print(f'VLC: Media > Open Network Stream > udp://@:{args.udp_port}', flush=True)
    print(f'Video mode: {args.video_mode} (15 FPS); VLC is NOT launched automatically.', flush=True)
    print('Streaming; type q and press Enter to stop cleanly. Camera reconnection is enabled.', flush=True)
    stop_requested = threading.Event()

    def console_commands():
        # A daemon reader works with Windows PowerShell (select() cannot poll
        # console stdin there). It never sends Ctrl+C to the batch wrapper.
        while not stop_requested.is_set():
            try:
                line = sys.stdin.readline()
            except (OSError, ValueError):
                return
            if not line:
                return
            if line.strip().lower() in ('q', 'quit', 'exit'):
                stop_requested.set()
                return
            print('Type q then Enter to stop the live stream.', flush=True)

    threading.Thread(target=console_commands, name='live-console', daemon=True).start()
    stats = Counter()
    start = time.monotonic()
    deadline = start + args.seconds if args.seconds else None
    attempt = 0

    def stop_ffmpeg(proc):
        if proc is None:
            return
        if proc.stdin:
            try: proc.stdin.close()
            except (OSError, BrokenPipeError): pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    try:
        while not stop_requested.is_set() and (deadline is None or time.monotonic() < deadline):
            attempt += 1
            proc = None
            try:
                with LiveCamera(args) as cam:
                    # Recreate FFmpeg after each disconnect: H.264 decoder
                    # needs a fresh keyframe and a clean codec context.
                    proc = subprocess.Popen(command, stdin=subprocess.PIPE, bufsize=0)
                    for _ in cam.frames(2):
                        pass
                    cam.send(0xA29, integer(1, args.channel) + integer(2, args.stream))
                    print(f'Attempt {attempt}: video-start sent; waiting for keyframe ...', flush=True)
                    started = False
                    last_media = time.monotonic()
                    while not stop_requested.is_set() and (deadline is None or time.monotonic() < deadline):
                        received = False
                        for marker, msgid, flags, body, raw in cam.frames(0.4):
                            if marker == 0x48 and msgid == 0xA29:
                                print('Video-start response:', list(protobuf(body)), flush=True)
                            if marker != 0x68:
                                continue
                            received = True
                            last_media = time.monotonic()
                            try:
                                frame, key, ts = decode_live_frame(body)
                            except ValueError as exc:
                                stats['skipped'] += 1
                                if stats['skipped'] <= 3:
                                    print('Skipped frame:', exc, flush=True)
                                continue
                            if key:
                                started = True
                            if not started:
                                continue
                            if proc.poll() is not None:
                                raise RuntimeError(f'FFmpeg exited ({proc.returncode})')
                            try:
                                proc.stdin.write(frame)
                            except (BrokenPipeError, OSError) as exc:
                                raise RuntimeError(f'FFmpeg pipe failed: {exc}') from exc
                            stats['keyframes' if key else 'delta_frames'] += 1
                            if key and stats['keyframes'] == 1:
                                print('First keyframe decrypted; VLC can now play.', flush=True)
                            elif key and not (stats['keyframes'] - 1) % 150:
                                print(f"Streaming: {stats['keyframes']} keyframes, "
                                      f"{stats['delta_frames']} delta frames", flush=True)
                        if not received and time.monotonic() - last_media > args.stall_timeout:
                            raise ConnectionError(f'No video packets for {args.stall_timeout:g}s')
                        # frames() returns immediately when socket recv() reaches EOF;
                        # detect this using the flag added to LiveCamera below.
                        if cam.disconnected:
                            raise ConnectionError('Camera closed the TCP connection')
                    # Send the stop RPC on normal exit, including q + Enter.
                    try: cam.send(0xA2A, integer(1, args.channel))
                    except OSError: pass
            except (OSError, ValueError, RuntimeError, ConnectionError) as exc:
                stats['reconnects'] += 1
                print(f'Connection/stream interrupted: {exc}', flush=True)
            finally:
                stop_ffmpeg(proc)
            if stop_requested.is_set() or (deadline is not None and time.monotonic() >= deadline):
                break
            print(f'Reconnecting in {args.reconnect_delay:g}s (attempt {attempt + 1}) ...', flush=True)
            time.sleep(min(args.reconnect_delay, max(0, deadline - time.monotonic())
                           if deadline is not None else args.reconnect_delay))
    except KeyboardInterrupt:
        print('Ctrl+C received; stopping live stream ...', flush=True)
    finally:
        stop_requested.set()
        print('Live stream stopped.', flush=True)
        print('Live stream summary:', dict(stats), flush=True)


def build_live_av_ffmpeg_command(args, *, hls_directory=None):
    """Create ONE FFmpeg command for the selected streaming destination.

    The camera gives us encrypted H.264 frames and 8 kHz G.711 A-law audio.
    Python decrypts the frames and sends both media types into *local* UDP
    sockets, which FFmpeg reads as two separate inputs.

    For VLC (the existing live-av command): MPEG-TS is sent to localhost UDP.
    For browsers (http-live): the SAME FFmpeg process writes HLS files.

    This is the central v13 change. v12 did the following instead:

        Python -> FFmpeg -> MPEG-TS UDP -> SECOND FFmpeg -> HLS

    Restarting the first FFmpeg caused timestamp discontinuities for the
    second. v13 removes that extra FFmpeg/UDP handoff altogether.
    """
    video_input_port = args.audio_input_port + 1
    audio_input_port = args.audio_input_port

    # FFmpeg consumes decrypted H.264 (camera video) and raw A-law audio.
    video_input = (
        f"udp://127.0.0.1:{video_input_port}"
        "?fifo_size=1000000&overrun_nonfatal=1"
    )
    audio_input = (
        f"udp://127.0.0.1:{audio_input_port}"
        "?fifo_size=1000000&overrun_nonfatal=1"
    )

    # --- Media clock selection --------------------------------------------------
    # IMPORTANT: the default 15 FPS in earlier versions was NOT the real
    # camera rate. In a clean v16 run, the camera sent ~675 video pictures
    # while the microphone sent ~2,024 x 160-byte A-law packets. At 8 kHz,
    # each A-law packet contains 0.020 s of audio, so the measured rate is:
    #
    #     675 / (2024 * 0.020) ~= 16.675 FPS
    #
    # The nearest simple rational is 50/3 = 16.6667 frames/second, or one
    # frame every 60 ms. By incorrectly telling FFmpeg to use 15 FPS, we
    # stretched each second of captured video into ~1.111 seconds of playback.
    # That explains the ever-growing camera-to-browser latency (the browser
    # alone cannot fix a media timestamp clock running too slowly).
    #
    # Keep the existing direct VLC mode unchanged for regression safety.
    # This fix applies to the HTTP/HLS pipeline, and can be tuned without
    # editing source with --hls-video-fps (e.g. 50/3 or 16.67).
    from fractions import Fraction
    if hls_directory is None:
        video_fps = Fraction(15, 1)
    else:
        try:
            video_fps = Fraction(args.hls_video_fps).limit_denominator(1000)
        except (ValueError, ZeroDivisionError) as exc:
            raise ValueError('--hls-video-fps must be a number or fraction, e.g. 50/3') from exc
        if not 5 <= video_fps <= 60:
            raise ValueError('--hls-video-fps must be between 5 and 60')

    fps_text = f'{video_fps.numerator}/{video_fps.denominator}'
    # We need actual *timestamps*, not merely a displayed framerate.
    # N is FFmpeg's frame index; TB is its filter time-base (seconds per tick).
    # This expression assigns frame N the exact time N / FPS, avoiding
    # floating-point drift over long streams.
    timestamp_filter = (
        f'setpts=N*{video_fps.denominator}/'
        f'({video_fps.numerator}*TB)'
    )

    command = [
        'ffmpeg', '-hide_banner', '-loglevel', 'warning',
        '-thread_queue_size', '1024',
        '-fflags', '+genpts', '-probesize', '32', '-analyzeduration', '0',
        '-r', fps_text, '-f', 'h264', '-i', video_input,
        '-thread_queue_size', '1024',
        '-probesize', '32', '-analyzeduration', '0',
        '-f', 'alaw', '-ar', '8000', '-ac', '1', '-i', audio_input,
        '-map', '0:v:0', '-map', '1:a:0',
    ]

    if args.video_mode == 'timestamped':
        # Re-encoding lets us set presentation timestamps explicitly. The
        # camera H.264 bitstream itself does not transport timestamps through
        # our raw UDP pipe, so FFmpeg cannot infer the correct cadence.
        # We set *both* input rate and output encoder time-base consistently.
        # For the default 50/3 fps, each output frame is exactly 3/50 s.
        #
        # HLS segments can end only on keyframes: an approximately 1-second
        # GOP (17 frames at 50/3 fps) makes segments close to the requested
        # --hls-segment-time, without forcing an excessive keyframe rate.
        from math import ceil
        gop_frames = max(1, ceil(float(video_fps) * (
            args.hls_segment_time if hls_directory is not None else 1.0
        )))
        command.extend([
            '-vf', timestamp_filter,
            '-c:v', 'libx264', '-preset', 'ultrafast',
            '-tune', 'zerolatency', '-bf', '0',
            '-g', str(gop_frames), '-pix_fmt', 'yuv420p',
            '-r:v', fps_text,
            '-enc_time_base:v', f'{video_fps.denominator}:{video_fps.numerator}',
            '-fps_mode:v', 'cfr',
        ])
    else:
        # Raw camera-copy mode remains available for comparison, but it
        # cannot repair missing per-frame timing in the original H.264.
        command.extend(['-c:v', 'copy'])

    # Shared audio gain and clock synchronization for both output formats.
    command.extend([
        '-af', f'volume={args.gain_db}dB,aresample=48000:async=1:first_pts=0',
    ])

    if hls_directory is None:
        # Keep the previously working VLC output EXACTLY as before.
        output = f'udp://127.0.0.1:{args.udp_port}?pkt_size=1316'
        command.extend([
            '-c:a', 'mp2', '-b:a', '128k', '-ar', '48000', '-ac', '1',
            '-muxdelay', '0', '-muxpreload', '0', '-flush_packets', '1',
            '-f', 'mpegts', output,
        ])
    else:
        # Browser-friendly audio is AAC; H.264 remains browser-compatible.
        # A single FFmpeg handles encoding *and* writing HLS segments.
        # append_list + discont_start let each restarted encoder publish a
        # new segment sequence without simply erasing the existing playlist.
        # temp_file avoids HTTP clients reading half-written segment files.
        # epoch numbering also minimizes filename collisions on reconnect.
        directory = Path(hls_directory)
        command.extend([
            '-c:a', 'aac', '-b:a', '96k', '-ar', '48000', '-ac', '1',
            '-f', 'hls',
            # A target, NOT a guarantee: HLS can cut cleanly only at an
            # encoded keyframe. GOP size above follows the measured camera
            # frame rate. Playlist EXTINF is the actual segment duration.
            '-hls_time', str(args.hls_segment_time),
            '-hls_list_size', str(args.hls_list_size),
            '-hls_start_number_source', 'epoch',
            '-hls_flags',
            'append_list+discont_start+delete_segments+omit_endlist+temp_file',
            '-hls_segment_filename', str(directory / 'seg_%012d.ts'),
            str(directory / 'stream.m3u8'),
        ])

    return command


def run_live_av(args, *, hls_directory=None, external_stop=None):
    """Capture both video and microphone audio from a local CI2K camera.

    The working connection/authentication/media parsing is carried forward
    from v12. Only the FFmpeg destination changes when HLS is requested.

    Connection lifecycle:
      1. Authenticate with the camera over TCP (handled by LiveCamera).
      2. Launch ONE FFmpeg process listening on two local UDP input ports.
      3. Request video (RPC 0xA29) and audio (RPC 0xA2B).
      4. Decrypt incoming video; send video and audio to local FFmpeg inputs.
      5. On a *real* transport/stall error, close and reopen the connection.

    Importantly, a reconnection delay is NOT a playback timer. No reconnect
    should occur while video frames continue arriving, as your direct VLC
    test demonstrated. If the new HLS stream still reports stalls, we'll
    have isolated the problem to this shared capture path / encoder load.
    """
    import shutil
    import threading
    from collections import Counter

    if shutil.which('ffmpeg') is None:
        raise RuntimeError('FFmpeg not found on PATH')

    # These ports are used only between Python and FFmpeg on the host PC.
    # They are NOT the HTTP port used by other computers.
    video_input_port = args.audio_input_port + 1
    if not 1 <= args.audio_input_port <= 65534:
        raise ValueError('--audio-input-port must be 1..65534')
    if not 1 <= args.udp_port <= 65535:
        raise ValueError('--udp-port must be 1..65535')
    if len({args.udp_port, args.audio_input_port, video_input_port}) != 3:
        raise ValueError('Internal UDP ports overlap; choose other ports')
    if args.stall_timeout <= 0 or args.reconnect_delay < 0:
        raise ValueError('Stall timeout must be positive; reconnect delay nonnegative')
    if hls_directory is not None:
        if not 0.5 <= args.hls_segment_time <= 10:
            raise ValueError('--hls-segment-time must be between 0.5 and 10 seconds')
        if not 3 <= args.hls_list_size <= 30:
            raise ValueError('--hls-list-size must be between 3 and 30')
        if not 1 <= args.live_sync_segments < args.hls_list_size:
            raise ValueError('--live-sync-segments must be >= 1 and smaller than --hls-list-size')

    ffmpeg_command = build_live_av_ffmpeg_command(
        args, hls_directory=hls_directory,
    )
    # The same stop signal is shared by the console listener and camera loop.
    # stdin is read ONLY by this daemon thread, so a blocking readline() does
    # not interfere with the network/FFmpeg loops or keepalive exchanges.
    stop = external_stop if external_stop is not None else threading.Event()

    def keyboard_stop():
        """Accept both `q` and `quit`, with Enter, in either stream mode.

        EOF (for example, a detached service with no console) is NOT treated
        as a stop request. The server continues normally without a terminal.
        """
        while not stop.is_set():
            try:
                line = sys.stdin.readline()
            except (OSError, ValueError):
                return
            if not line:
                return
            command = line.strip().lower()
            if command in ('q', 'quit', 'exit'):
                print('Quit requested; shutting down stream ...', flush=True)
                stop.set()
                return
            if command:
                print('Type q or quit, then Enter, to stop the livestream.', flush=True)

    if external_stop is None:
        threading.Thread(target=keyboard_stop, name='codi-console', daemon=True).start()

    if hls_directory is None:
        print(f'Combined VIDEO + AUDIO VLC URL: udp://@:{args.udp_port}', flush=True)
    else:
        print('Single-FFmpeg HLS mode: browser receives segments directly from the camera worker.', flush=True)
        print(f'Video clock: {args.hls_video_fps} FPS (measured camera rate; v16 used 15 FPS).', flush=True)
        print(f'HLS settings: target segment {args.hls_segment_time:g}s; '
              f'playlist {args.hls_list_size} segments; '
              f'browser sync target {args.live_sync_segments} segments.', flush=True)
    print('Type q or quit, then Enter, to stop (Ctrl+C also works).', flush=True)

    print(f'Audio gain: {args.gain_db:g} dB; video mode: {args.video_mode}', flush=True)
    print(f'Internal FFmpeg inputs: video UDP {video_input_port}, '
          f'audio UDP {args.audio_input_port}', flush=True)

    stats = Counter()
    attempt = 0
    deadline = time.monotonic() + args.seconds if args.seconds else None
    audio_capture = None
    if args.save_audio:
        args.save_audio.parent.mkdir(parents=True, exist_ok=True)
        audio_capture = open(args.save_audio.with_suffix('.alaw'), 'wb')
        print(f'Saving microphone samples to {args.save_audio.with_suffix(".alaw")}', flush=True)

    def cleanup_ffmpeg(proc):
        """Ask FFmpeg to finish its output, then fall back to termination.

        Sending q is preferable to killing the process: FFmpeg can finish
        the in-progress HLS segment and close its output files. If FFmpeg is
        unresponsive, terminate() and finally kill() prevent leaked sockets.
        """
        if proc is None or proc.poll() is not None:
            return
        if proc.stdin is not None:
            try:
                proc.stdin.write(b'q\n')
                proc.stdin.flush()
            except (OSError, ValueError, BrokenPipeError):
                pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        finally:
            if proc.stdin is not None:
                proc.stdin.close()

    try:
        while not stop.is_set() and (deadline is None or time.monotonic() < deadline):
            attempt += 1
            ffmpeg = None
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.setblocking(False)

            try:
                with LiveCamera(args) as camera:
                    # Starting FFmpeg after opening the camera mirrors v12.
                    ffmpeg = subprocess.Popen(ffmpeg_command, stdin=subprocess.PIPE)
                    for _ in camera.frames(1.5):
                        pass  # Allow initial camera authentication to settle.

                    # These are requests, not configuration changes.
                    camera.send(0xA29, integer(1, args.channel) + integer(2, args.stream))
                    camera.send(0xA2B, integer(1, args.channel))
                    print(f'Attempt {attempt}: video and microphone requested', flush=True)
                    video_started = False
                    last_video = time.monotonic()

                    while not stop.is_set() and (deadline is None or time.monotonic() < deadline):
                        for marker, rpc_id, flags, body, raw in camera.frames(0.35):
                            if marker == 0x48 and rpc_id in (0xA29, 0xA2B):
                                label = 'Video' if rpc_id == 0xA29 else 'Audio'
                                print(f'{label} response:', list(protobuf(body)), flush=True)

                            # Only media packets (0x68) contain video or audio.
                            if marker != 0x68 or not body:
                                continue

                            if body[0] == 0x15:
                                # 0x15 = microphone packet: 11-byte SDK header
                                # followed by exactly 160 G.711 A-law bytes.
                                samples = body[11:]
                                if len(body) >= 12 and len(samples) == 160:
                                    try:
                                        sender.sendto(samples, ('127.0.0.1', args.audio_input_port))
                                    except (BlockingIOError, OSError):
                                        stats['audio_udp_drops'] += 1
                                    if audio_capture is not None:
                                        audio_capture.write(samples)
                                    stats['audio_packets'] += 1
                                    if stats['audio_packets'] == 1:
                                        print('First microphone packet received.', flush=True)
                                else:
                                    stats['audio_skipped'] += 1
                                continue

                            # 0x81 = H.264 keyframe; 0x01 = H.264 delta frame.
                            if body[0] not in (0x81, 0x01):
                                stats['other_media'] += 1
                                continue

                            last_video = time.monotonic()
                            try:
                                frame, is_keyframe, timestamp = decode_live_frame(body)
                            except ValueError as exc:
                                stats['video_skipped'] += 1
                                if stats['video_skipped'] <= 3:
                                    print('Skipped video frame:', exc, flush=True)
                                continue

                            if is_keyframe:
                                video_started = True
                            if not video_started:
                                continue  # Delta frames are unusable before a keyframe.

                            if ffmpeg.poll() is not None:
                                raise RuntimeError(f'FFmpeg exited ({ffmpeg.returncode})')

                            # Small UDP datagrams avoid fragmentation on loopback.
                            # FFmpeg reconstructs the elementary H.264 byte stream.
                            for offset in range(0, len(frame), 1200):
                                try:
                                    sender.sendto(
                                        frame[offset:offset + 1200],
                                        ('127.0.0.1', video_input_port),
                                    )
                                except (BlockingIOError, OSError):
                                    stats['video_udp_drops'] += 1

                            stats['keyframes' if is_keyframe else 'delta_frames'] += 1
                            if stats['keyframes'] == 1 and is_keyframe:
                                print('First keyframe decrypted.', flush=True)
                            elif is_keyframe and stats['keyframes'] % 15 == 0:
                                print(
                                    f"Streaming progress: {stats['keyframes']} keyframes, "
                                    f"{stats['delta_frames']} delta frames, "
                                    f"{stats['audio_packets']} audio packets; "
                                    f"FFmpeg running={ffmpeg.poll() is None}",
                                    flush=True,
                                )

                        # These two checks are the ONLY reasons for a normal
                        # disconnect/reconnect decision. A quiet browser or
                        # stopped HLS viewer does not reconnect the camera.
                        if camera.disconnected:
                            raise ConnectionError('Camera closed the connection')
                        if time.monotonic() - last_video > args.stall_timeout:
                            raise ConnectionError('Video stream stalled')

                    # A normal stop asks the camera to stop media delivery.
                    for rpc_id in (0xA2C, 0xA2A):
                        try:
                            camera.send(rpc_id, integer(1, args.channel))
                        except OSError:
                            pass

            except (OSError, ValueError, RuntimeError, ConnectionError) as exc:
                stats['reconnects'] += 1
                if not stop.is_set():
                    print('Stream interrupted:', exc, flush=True)
            finally:
                sender.close()
                cleanup_ffmpeg(ffmpeg)

            if stop.is_set() or (deadline is not None and time.monotonic() >= deadline):
                break
            print(f'Reconnecting in {args.reconnect_delay:g}s ...', flush=True)
            stop.wait(args.reconnect_delay)

    except KeyboardInterrupt:
        print('Ctrl+C received; stopping ...', flush=True)
    finally:
        stop.set()
        if audio_capture is not None:
            audio_capture.close()
            raw_file = args.save_audio.with_suffix('.alaw')
            if raw_file.stat().st_size:
                result = subprocess.run(
                    ['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
                     '-f', 'alaw', '-ar', '8000', '-ac', '1', '-i', str(raw_file),
                     '-af', 'volume=12dB', '-c:a', 'pcm_s16le', str(args.save_audio)],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    print(f'Saved microphone WAV: {args.save_audio} '
                          f'({args.save_audio.stat().st_size} bytes)', flush=True)
                else:
                    print('WAV conversion failed:', result.stderr.strip(), flush=True)
            else:
                print('No microphone samples captured; WAV not created.', flush=True)
        print('Combined live stream stopped. Summary:', dict(stats), flush=True)

def run_capture(args):
    import time
    counts, written = {}, 0
    print(f'Video-start request: 0xA29 channel={args.channel}, stream={args.stream}')
    print(f'Capture: {args.seconds:g}s, output: {args.output}')
    with LiveCamera(args) as cam:
        try:
            for _ in cam.frames(2): pass
            cam.send(0xA29, integer(1, args.channel) + integer(2, args.stream))
            deadline = time.monotonic() + args.seconds
            with args.output.open('wb') as fp:
                while time.monotonic() < deadline:
                    for marker, msgid, flags, body, raw in cam.frames(min(0.5, max(0.01, deadline-time.monotonic()))):
                        if marker is None: continue
                        label = f'0x{marker:02x}'
                        counts[label] = counts.get(label, 0) + 1
                        n = counts[label]
                        if marker == 0x48:
                            if msgid != 0x6b or n <= 3:
                                print(f'Control 0x{msgid:X}, flags=0x{flags:02x}, payload={body[:80].hex()}')
                                if msgid == 0xA29:
                                    try: print('  protobuf:', list(protobuf(body)))
                                    except Exception as exc: print('  protobuf error:', exc)
                        elif n <= 10:
                            print(f'Media marker {label} packet #{n}: body={len(body)} bytes, first64={body[:64].hex()}')
                        if written + len(raw) <= 64 * 1024 * 1024:
                            fp.write(raw); written += len(raw)
                        if time.monotonic() >= deadline: break
        except (ValueError, OSError) as exc:
            print('Capture parsing stopped:', exc)
            if cam.buffer:
                print('Unparsed buffer prefix:', cam.buffer[:128].hex())
                with args.output.open('ab') as fp: fp.write(cam.buffer)
                written += len(cam.buffer)
        finally:
            try:
                print('Sending video-stop RPC 0xA2A ...')
                cam.send(0xA2A, integer(1, args.channel))
                print('Video-stop request sent; closing connection.')
            except (OSError, ValueError) as exc: print('Could not send stop:', exc)
    print('Packet counts:', counts)
    print(f'Capture saved: {written:,} bytes to {args.output}')


def run_sd(args):
    if args.action == 'delete':
        if not args.file_id or args.file_id < 1: raise ValueError('delete requires --file-id')
        rpc, payload = 0xA7C, integer(1,args.channel)+integer(2,args.file_id)
    elif args.action == 'format':
        rpc, payload = 0xA7B, integer(1,args.channel)
    else: rpc, payload = 0xA7A, integer(1,args.channel)
    print(f'Action: {args.action}; RPC: 0x{rpc:X}; protobuf request: {payload.hex()}')
    if args.action in ('delete','format'):
        question = (f'Delete recording {args.file_id}? [y/yes to confirm]: ' if args.action=='delete'
                    else 'Format the entire SD card? [y/yes to confirm]: ')
        print('WARNING: destructive SD-card operation.')
        try: confirmed = input(question).strip().lower()
        except (EOFError, KeyboardInterrupt): raise SystemExit('Cancelled. Nothing sent.')
        if confirmed not in ('y','yes'): raise SystemExit('Cancelled. Nothing sent.')
    with Camera(args) as cam:
        for _ in cam.packets(2): pass
        print(f'Sending RPC 0x{rpc:X} ...', flush=True)
        cam.send(rpc,payload)
        got=False
        for kind,msgid,flags,plain in cam.packets(args.timeout):
            if kind!='control' or msgid!=rpc: continue
            got=True
            print(f'Response flags: 0x{flags:02x}; hex: {plain.hex()}')
            values={}
            for f,w,v in protobuf(plain):
                print(f'  field {f} (wire {w}): {v if w==0 else v.hex()}')
                if w==0: values[f]=v
            if args.action=='status' and 2 in values:
                total,used=values[2],values.get(3,0)
                if used>total: print('WARNING: used exceeds total; check field mapping')
                else:
                    print('  Interpreted storage (assuming KiB counters):')
                    print(f'    Total: {total:,} KiB ({total/1048576:.2f} GiB)')
                    print(f'    Used:  {used:,} KiB ({used/1024:.2f} MiB)')
                    print(f'    Free:  {total-used:,} KiB ({(total-used)/1048576:.2f} GiB)')
                    print(f'    Usage: {used/total*100:.3f}%' if total else '    Usage: unknown')
                    if 3 not in values: print('    Note: omitted field 3 interpreted as zero')
            break
        if not got: print('No response received; command may still have executed. Verify history/status before retrying.')
        elif args.action!='status': print('Response received; verify history/status to confirm the outcome.')


def run_recordings(args):
    try: day=date.fromisoformat(args.date)
    except ValueError: raise ValueError('Invalid --date; use YYYY-MM-DD')
    if args.action=='download':
        if args.file_id is None: raise ValueError('download requires --file-id')
        with Camera(args) as cam:
            for _ in cam.packets(3): pass
            cam.download(args.file_id,args.output_dir/f'P{args.file_id}.mp4')
        return
    with Camera(args) as cam: entries=cam.history(day)
    print(f'Found {len(entries)} recordings on {day} (one history page; maximum {args.page_size}; newest first)')
    for idx,e in enumerate(entries,1): print(f'  {idx:3d}. ID {e[3]}  metadata {e}')
    if args.action=='list' or not entries:return
    if args.action=='pick':
        answer=input(f'Choose recording number (1-{len(entries)}) or q to cancel: ').strip()
        if answer.lower()=='q':return
        if not answer.isdigit() or not 1<=int(answer)<=len(entries):raise ValueError('Invalid recording number')
        file_id=entries[int(answer)-1][3]
        with Camera(args) as cam:
            for _ in cam.packets(3):pass
            cam.download(file_id,args.output_dir/f'P{file_id}.mp4')
        return
    if len(entries)>=args.page_size:print('Warning: page full; additional recordings may exist')
    failures=0
    for idx,e in enumerate(entries,1):
        file_id=e[3];dest=args.output_dir/f'P{file_id}.mp4'
        if dest.exists():print(f'[{idx}/{len(entries)}] Already exists; skipping {dest}');continue
        if dest.with_name(dest.name+'.part').exists():print('Partial file exists; skipping',dest);failures+=1;continue
        try:
            with Camera(args) as cam:
                for _ in cam.packets(3):pass
                cam.download(file_id,dest)
        except (OSError,ValueError,RuntimeError,TimeoutError) as exc:
            failures+=1;print(f'[{idx}/{len(entries)}] FAILED {file_id}: {exc}',file=sys.stderr)
    print(f'Batch finished: {len(entries)} entries, {failures} failures')
    if failures:raise SystemExit(1)



def run_motion_recover(args):
    """Capture video while the user triggers motion, then poll for an SD reference."""
    from types import SimpleNamespace
    from datetime import datetime
    import time as _time
    base = args.output_dir
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    print('Checking camera history before live capture ...', flush=True)
    with Camera(args) as cam:
        before = {e[3] for e in cam.history(date.today())}
    capture = base / f'live_{stamp}.bin'
    print(f'Existing recordings: {len(before)}', flush=True)
    print('IMPORTANT: You MUST physically trigger motion during this capture.', flush=True)
    print('When capture begins, wait about 5 seconds, then move in front of the camera for 10-15 seconds.', flush=True)
    try:
        ready = input('Ready to start the motion test? [y/yes]: ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        raise SystemExit('Cancelled. No capture started.')
    if ready not in ('y', 'yes'):
        raise SystemExit('Cancelled. No capture started.')
    cap_args = SimpleNamespace(**vars(args))
    cap_args.output = capture
    run_capture(cap_args)
    print('Capture saved. Polling for a newly finalized SD recording...', flush=True)
    candidates = []
    for attempt in range(1, 13):
        _time.sleep(5)
        try:
            with Camera(args) as cam:
                entries = cam.history(date.today())
            candidates = [e[3] for e in entries if e[3] not in before]
            print(f'  Poll {attempt}/12: {len(entries)} recordings, {len(candidates)} new', flush=True)
            if candidates:
                break
        except (OSError, ValueError, RuntimeError) as exc:
            print(f'  Poll {attempt}/12 failed: {exc}', flush=True)
    if not candidates:
        print('No new SD recording appeared within 60 seconds. Live capture preserved:', capture)
        print('Motion must be enabled and physically triggered for reference-assisted recovery.')
        return
    print('New recording IDs:', candidates)
    for fid in candidates[:5]:
        recording = base / f'P{fid}.mp4'
        if not recording.exists():
            try:
                with Camera(args) as cam:
                    for _ in cam.packets(2): pass
                    cam.download(fid, recording)
            except (OSError, ValueError, RuntimeError) as exc:
                print('Download failed for', fid, ':', exc)
                continue
        out = base / f'live_{stamp}_{fid}.h264'
        mp4 = base / f'live_{stamp}_{fid}.mp4'
        rec_args = SimpleNamespace(**vars(args))
        rec_args.capture, rec_args.recording = capture, recording
        rec_args.output, rec_args.mp4 = out, mp4
        try:
            run_recovery(rec_args)
            print('SUCCESS: recovered motion-test video:', mp4)
            print('This remains reference-assisted recovery, not independent live decoding.')
            return
        except (OSError, ValueError, RuntimeError, __import__('subprocess').CalledProcessError) as exc:
            print('No usable overlap for recording', fid, ':', exc)
    print('No overlapping reference was recovered; live capture saved at:', capture)


# CI2K night-vision (IR-cut) control; confirmed on physical hardware.
# Original app values: ON=1, OFF=2, AUTO=3.
NIGHTVISION_MODES = {'on': 1, 'off': 2, 'auto': 3}
NIGHTVISION_NAMES = {v: k for k, v in NIGHTVISION_MODES.items()}


def nightvision_rpc(cam, rpc, payload, timeout):
    """Issue a control RPC and wait for its response while servicing heartbeats."""
    cam.send(rpc, payload)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        window = min(0.5, max(0.02, deadline - time.monotonic()))
        for kind, msgid, flags, plain in cam.packets(window):
            if kind != 'control' or msgid != rpc or not (flags & 1):
                continue
            fields = list(protobuf(plain))
            print(f'RPC 0x{rpc:03X} reply flags=0x{flags:02X}, '
                  f'raw={plain.hex()}, fields={fields}', flush=True)
            return fields
    raise TimeoutError(f'No response to 0x{rpc:03X} within {timeout:g}s')


def get_nightvision(cam, args):
    fields = nightvision_rpc(cam, 0xA5F, integer(1, args.channel), args.timeout)
    values = [value for field, wire, value in fields if field == 2 and wire == 0]
    if len(values) != 1 or values[0] not in NIGHTVISION_NAMES:
        raise RuntimeError(f'Unrecognized night-vision mode response: {values}')
    mode = values[0]
    print(f'Current night vision: {NIGHTVISION_NAMES[mode].upper()} ({mode})', flush=True)
    return mode


def run_nightvision(args):
    """Read mode, or set ON/OFF/AUTO with explicit consent and GET verification."""
    target_name = args.nightvision_mode
    print('Night vision: RPC 0xA5F GET / 0xA5E SET', flush=True)
    if target_name == 'get':
        print('READ ONLY; no settings changes.', flush=True)
    with Camera(args) as cam:
        # Allow the connection/authentication exchange to settle.
        for _ in cam.packets(2.0):
            pass
        original = get_nightvision(cam, args)
        if target_name == 'get':
            return
        target = NIGHTVISION_MODES[target_name]
        if original == target:
            print(f'Already {target_name.upper()}; no SET sent.', flush=True)
            return
        print(f'Changing {NIGHTVISION_NAMES[original].upper()} -> '
              f'{target_name.upper()}...', flush=True)
        # Confirmed CI2K wire request: field 1=channel, field 2=mode.
        request = integer(1, args.channel) + integer(2, target)
        try:
            nightvision_rpc(cam, 0xA5E, request, args.timeout)
        except TimeoutError as exc:
            # A lost SET reply does not mean the camera ignored the write.
            print(f'WARNING: {exc}; checking actual mode...', file=sys.stderr)
        time.sleep(0.4)
        actual = get_nightvision(cam, args)
        if actual != target:
            raise RuntimeError(
                f'Night-vision SET verification failed: requested {target_name.upper()}, '
                f'camera reports {NIGHTVISION_NAMES[actual].upper()}; '
                f'previously {NIGHTVISION_NAMES[original].upper()}.')
        print(f'VERIFIED: {NIGHTVISION_NAMES[original].upper()} -> '
              f'{target_name.upper()}.', flush=True)
        print('Restore previous mode with: nightvision --mode '
              f'{NIGHTVISION_NAMES[original]} --confirm', flush=True)

HTML = '''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Codi 2K — Live Camera</title>
<style>
body{margin:0;padding:24px;display:flex;align-items:center;flex-direction:column;gap:12px;background:#111;color:#eee;font:16px system-ui,sans-serif}
h1{font-size:1.25rem}video{width:min(95vw,1100px);background:#000;aspect-ratio:16/9}
#status,#diagnostics{color:#aaa;font-size:.9rem;text-align:center}button{font:inherit;padding:10px 24px;border:0;border-radius:6px;cursor:pointer}button:disabled{opacity:.5;cursor:wait}
</style></head><body>
<h1>Codi 2K · Live camera</h1>
<video id="video" controls autoplay muted playsinline></video>
<div id="status">Checking camera stream…</div>
<div><button id="start" hidden>Start Stream</button> <button id="stop" hidden>Stop Stream</button></div>
<div id="diagnostics"></div><p>Sound starts muted; unmute in the video player.</p>
<script src="https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js"></script>
<script>
'use strict';
const video=document.getElementById('video'),status=document.getElementById('status'),diagnostics=document.getElementById('diagnostics');
const start=document.getElementById('start'),stop=document.getElementById('stop');
const syncSegments=LIVE_SYNC_SEGMENTS_TOKEN,segmentSeconds=HLS_SEGMENT_SECONDS_TOKEN;
const playlist='/livecam/stream.m3u8';
let hls=null,attached=false,phase='offline',newestSegmentAge=NaN,mostRecentSeek=0;
function resetPlayer(){if(hls){hls.destroy();hls=null;}video.pause();video.removeAttribute('src');video.load();attached=false;video.playbackRate=1;}
function attachPlayer(){
 if(attached)return;
 attached=true;
 if(window.Hls&&Hls.isSupported()){
  hls=new Hls({liveSyncDurationCount:syncSegments,liveMaxLatencyDurationCount:Math.max(syncSegments+4,syncSegments*3),maxLiveSyncPlaybackRate:1,lowLatencyMode:false,enableWorker:true});
  hls.attachMedia(video);hls.loadSource(playlist);
  hls.on(Hls.Events.MANIFEST_PARSED,()=>video.play().catch(()=>{status.textContent='Click Play to watch the stream';}));
  hls.on(Hls.Events.ERROR,(_event,detail)=>{if(!detail.fatal)return;
    if(detail.type===Hls.ErrorTypes.NETWORK_ERROR)hls.startLoad();
    else if(detail.type===Hls.ErrorTypes.MEDIA_ERROR)hls.recoverMediaError();
    else{status.textContent='Playback error: '+detail.details;resetPlayer();}
  });
 }else if(video.canPlayType('application/vnd.apple.mpegurl')){
  video.src=playlist;video.addEventListener('loadedmetadata',()=>video.play().catch(()=>{}),{once:true});
 }else{status.textContent='Browser cannot play HLS. Check hls.js CDN access.';}
}
async function command(action){
 start.disabled=true;stop.disabled=true;
 try{const r=await fetch('/livecam/'+action,{method:'POST',headers:{'X-Codi-Control':'1'},cache:'no-store'});
  const data=await r.json();if(!r.ok)throw Error(data.error||'HTTP '+r.status);
  if(action==='stop')resetPlayer();await poll();
 }catch(e){status.textContent='Could not '+action+' stream: '+e.message;}
 finally{start.disabled=false;stop.disabled=false;}
}
start.onclick=()=>command('start');stop.onclick=()=>command('stop');
async function poll(){
 try{const r=await fetch('/livecam/status.json',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);
 const d=await r.json();phase=d.state;newestSegmentAge=d.newest_segment_age_seconds;
 start.hidden=!(phase==='offline'||phase==='error');stop.hidden=(phase==='offline'||phase==='error');
 start.textContent=phase==='error'?'Retry Stream':'Start Stream';
 if(phase==='live'){
   if(!attached)attachPlayer();
   status.textContent='Live stream connected';
 }else{
   if(attached)resetPlayer();
   status.textContent=phase==='starting'?'Starting camera and preparing video…':phase==='stopping'?'Stopping stream…':phase==='error'?'Stream error: '+(d.error||'unknown'):'Stream offline';
   diagnostics.textContent='';
 }
 }catch(e){status.textContent='Website status unavailable: '+e.message;}
}
setInterval(()=>{
 if(phase!=='live'||!hls)return;
 const lag=hls.latency,playing=!video.paused&&!video.ended&&!video.seeking;
 const fresh=Number.isFinite(newestSegmentAge)&&newestSegmentAge<Math.max(5,segmentSeconds*4);
 if(!fresh||!playing||!Number.isFinite(lag)){video.playbackRate=1;return;}
 const target=Number.isFinite(hls.targetLatency)?hls.targetLatency:syncSegments*segmentSeconds;
 const excess=lag-target;
 if(excess>Math.max(4,3*segmentSeconds)&&Date.now()-mostRecentSeek>10000&&Number.isFinite(hls.liveSyncPosition)){
  let destination=hls.liveSyncPosition;
  if(video.seekable.length)destination=Math.min(destination,video.seekable.end(video.seekable.length-1)-.15);
  if(destination-video.currentTime>1){mostRecentSeek=Date.now();video.playbackRate=1;video.currentTime=destination;}
 }else if(excess>2)video.playbackRate=1.20;
 else if(excess>.75)video.playbackRate=1.08;
 else video.playbackRate=1;
 diagnostics.textContent='HLS-edge delay ≈ '+lag.toFixed(1)+'s · Newest segment ≈ '+newestSegmentAge.toFixed(1)+'s · Speed '+video.playbackRate.toFixed(2)+'×';
},1000);
poll();setInterval(poll,1500);
</script></body></html>'''
class LiveHTTPHandler(http.server.SimpleHTTPRequestHandler):
    """Tiny read-only web server for the player and generated HLS files.

    /livecam                 -> self-contained player HTML (loads hls.js CDN)
    /livecam/stream.m3u8     -> current rolling HLS playlist
    /livecam/seg_XXXX.ts     -> finished MPEG-TS video/audio segments
    /livecam/health.json     -> read-only HLS freshness statistics

    All other paths are rejected, preventing accidental file disclosure.
    HTTP is deliberately not authenticated; limit access with your firewall.
    """
    def __init__(self, *args, directory=None, live_sync_segments=2,
                 segment_seconds=1.0, controller=None, **kwargs):
        # An HTTP request gets the same playback policy the stream was given.
        self.live_sync_segments = live_sync_segments
        self.segment_seconds = segment_seconds
        self.controller = controller
        super().__init__(*args, directory=directory, **kwargs)

    def do_GET(self):
        route = urlsplit(self.path).path
        if route in ('/', '/livecam', '/livecam/'):
            body = (HTML
                    .replace('LIVE_SYNC_SEGMENTS_TOKEN', str(self.live_sync_segments))
                    .replace('HLS_SEGMENT_SECONDS_TOKEN', str(self.segment_seconds))
                    .encode('utf-8'))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if route == '/livecam/status.json':
            return self.send_json(self.controller.snapshot())
        if route == '/livecam/health.json':
            # Segment timestamps are server-local filesystem metadata. No
            # camera key, DID, internal file path, or network configuration
            # is disclosed here. The player uses only the freshness field.
            directory = Path(self.directory)
            # Old segments may disappear between directory listing and stat()
            # because FFmpeg deletes files outside its rolling HLS playlist.
            # Skip such files instead of returning HTTP 500 to the player.
            newest = None
            for segment in directory.glob('seg_*.ts'):
                try:
                    modified_at = segment.stat().st_mtime
                except OSError:
                    continue
                if newest is None or modified_at > newest:
                    newest = modified_at
            age = None if newest is None else max(0, time.time() - newest)
            payload = json.dumps({
                'newest_segment_age_seconds': round(age, 2) if age is not None else None,
            }).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        if not route.startswith('/livecam/'):
            self.send_error(404)
            return
        return super().do_GET()

    def send_json(self, value, code=200):
        body = json.dumps(value).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        route = urlsplit(self.path).path
        if route not in ('/livecam/start', '/livecam/stop'):
            return self.send_json({'error': 'Unknown action'}, 404)
        # Reject cross-origin browser requests; no credentials or user commands
        # are accepted. Keep this LAN-only; HTTP has no user authentication.
        from urllib.parse import urlsplit as parse_url
        origin = self.headers.get('Origin')
        host = self.headers.get('Host', '')
        if (self.headers.get('X-Codi-Control') != '1' or
            (origin and parse_url(origin).netloc != host)):
            return self.send_json({'error': 'Request not permitted'}, 403)
        if int(self.headers.get('Content-Length', '0') or '0') > 0:
            return self.send_json({'error': 'Request body not supported'}, 400)
        action = 'start' if route.endswith('/start') else 'stop'
        self.controller.change(action)
        return self.send_json(self.controller.snapshot())

    def translate_path(self, path):
        # No arbitrary file serving. Only playlist and numbered MPEG-TS segments.
        name = urlsplit(path).path.split('/')[-1]
        if name == 'stream.m3u8' or (name.startswith('seg_') and name.endswith('.ts') and name[4:-3].isdigit()):
            return str(Path(self.directory) / name)
        return str(Path(self.directory) / '__not_found__')

    def end_headers(self):
        self.send_header('Cache-Control','no-store, no-cache, must-revalidate')
        super().end_headers()

    def log_message(self, fmt, *args):
        message = fmt % args
        if ('stream.m3u8' not in message and 'health.json' not in message
                and ' 404 ' not in message):
            print('[HTTP]', message, flush=True)

    def guess_type(self, path):
        if path.endswith('.m3u8'): return 'application/vnd.apple.mpegurl'
        if path.endswith('.ts'): return 'video/mp2t'
        return super().guess_type(path)


def stop_live_http_process(proc, name, stdin_stop=False):
    if proc is None or proc.poll() is not None: return
    if stdin_stop and proc.stdin:
        try: proc.stdin.write('q\n');proc.stdin.flush();proc.wait(timeout=4)
        except (OSError, BrokenPipeError, subprocess.TimeoutExpired): pass
    if proc.poll() is None:
        proc.terminate()
        try:proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=5)
    print(f'{name} stopped.',flush=True)



def detect_lan_ip():
    """Identify a local IPv4 address for printing an easy LAN viewer URL.

    Connecting an unbound UDP socket to a documentation-only address makes the
    OS choose the interface it would use; no packets are actually transmitted.
    This is informational and does NOT alter which interface HTTP binds to.
    """
    import socket as _socket
    try:
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as sock:
            sock.connect(('192.0.2.1', 9))
            return sock.getsockname()[0]
    except OSError:
        return None


class LiveStreamController:
    """Own exactly one worker; keep HTTP alive while the camera is stopped."""
    def __init__(self, args, directory):
        import threading
        self.args, self.directory = args, Path(directory)
        self.lock = threading.RLock()
        self.worker = None
        self.stop_event = None
        self.state = 'offline'
        self.error = None
        self.started_at = None

    def freshness(self):
        newest = None
        for segment in self.directory.glob('seg_*.ts'):
            try: mtime = segment.stat().st_mtime
            except OSError: continue
            newest = mtime if newest is None else max(newest, mtime)
        return None if newest is None else max(0, time.time()-newest)

    def snapshot(self):
        with self.lock:
            state, error = self.state, self.error
            worker_alive = self.worker is not None and self.worker.is_alive()
            started_at = self.started_at
        age = self.freshness()
        # A fresh completed segment is the actual playback-ready signal.
        fresh = age is not None and age < max(5, self.args.hls_segment_time*4)
        if state == 'starting' and worker_alive and fresh:
            state = 'live'
        if state == 'live' and not fresh:
            state = 'starting' if worker_alive else 'offline'
        if not worker_alive and state in ('starting','live','stopping'):
            state = 'error' if error else 'offline'
        with self.lock:
            if self.state not in ('stopping','offline','error'):
                self.state = state
        return {'state': state, 'error': error,
                'newest_segment_age_seconds': round(age,2) if age is not None else None}

    def change(self, action):
        import threading
        with self.lock:
            if action == 'stop':
                if self.stop_event is not None:
                    self.state = 'stopping'
                    self.stop_event.set()
                return
            if self.worker is not None and self.worker.is_alive():
                return
            # Remove stale HLS data before starting, so the player never
            # attaches to a previous run's completed segments.
            for path in self.directory.iterdir():
                if path.name == 'stream.m3u8' or (path.name.startswith('seg_') and path.suffix == '.ts'):
                    try: path.unlink()
                    except OSError: pass
            self.error = None
            self.state = 'starting'
            self.started_at = time.monotonic()
            self.stop_event = threading.Event()
            event = self.stop_event
            def worker():
                try:
                    run_live_av(self.args, hls_directory=self.directory, external_stop=event)
                except Exception as exc:
                    with self.lock:
                        self.error = str(exc)
                    print('Camera worker failed:', exc, flush=True)
                finally:
                    with self.lock:
                        self.state = 'error' if self.error and not event.is_set() else 'offline'
            self.worker = threading.Thread(target=worker, name='codi-camera', daemon=True)
            self.worker.start()

    def shutdown(self):
        with self.lock:
            event, worker = self.stop_event, self.worker
            if event: event.set()
        if worker and worker.is_alive(): worker.join(timeout=12)


def run_http_livecam(args):
    """Persistent LAN website with browser-controlled camera start/stop."""
    import functools
    import shutil
    import tempfile
    import threading
    if shutil.which('ffmpeg') is None:
        raise RuntimeError('FFmpeg not found on PATH')
    if not 1 <= args.http_port <= 65535:
        raise ValueError('--http-port must be 1..65535')
    with tempfile.TemporaryDirectory(prefix='codi_http_') as output:
        controller = LiveStreamController(args, output)
        handler = functools.partial(LiveHTTPHandler, directory=output,
            live_sync_segments=args.live_sync_segments,
            segment_seconds=args.hls_segment_time, controller=controller)
        server = http.server.ThreadingHTTPServer((args.http_host, args.http_port), handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(f'Local viewer: http://localhost:{args.http_port}/livecam', flush=True)
        if args.http_host == '0.0.0.0':
            print(f'LAN viewer: http://{detect_lan_ip() or "YOUR-PC-LAN-IP"}:{args.http_port}/livecam', flush=True)
            print('LAN access has NO PASSWORD. Do not expose this port to the Internet.', flush=True)
        print('Open the website and press Start Stream. Type q or quit to exit the server.', flush=True)
        try:
            while True:
                line = sys.stdin.readline()
                if not line:
                    # In a noninteractive service, stay online until interrupted.
                    while True: time.sleep(1)
                if line.strip().lower() in ('q','quit','exit'):
                    break
        except KeyboardInterrupt:
            pass
        finally:
            controller.shutdown()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            print('HTTP viewer stopped.', flush=True)

def main():
    ap=argparse.ArgumentParser(description='Codi 2K all-in-one LAN manager v17 + web controls (Python 3.10+)')
    ap.add_argument('action',choices=['list','pick','download','all','status','delete','format','capture','recover','motion-recover','decode-live','live','live-av','nightvision','http-live'])
    ap.add_argument('--host',default='192.168.1.100')
    ap.add_argument('--port',type=int,default=9000)
    ap.add_argument('--did',default='CI2K-YOUR_DEVICE_ID')
    ap.add_argument('--device-key',help='Required for camera-connected actions; not needed for offline recover')
    ap.add_argument('--date',default=date.today().isoformat())
    ap.add_argument('--channel',type=int,default=0)
    ap.add_argument('--file-id',type=int)
    ap.add_argument('--output-dir',type=Path,default=Path('codi_recordings'))
    ap.add_argument('--media-secret',default='')
    ap.add_argument('--page-size',type=int,default=100)
    ap.add_argument('--timeout',type=float,default=25)
    ap.add_argument('--idle',type=float,default=2)
    ap.add_argument('--stream',type=int,default=0)
    ap.add_argument('--udp-port',type=int,default=12345,help='Local UDP port for VLC live playback')
    ap.add_argument('--http-port',type=int,default=9080,help='HTTP player port (default 9080)')
    ap.add_argument('--http-host',default='0.0.0.0',help='HTTP bind address: 0.0.0.0 for LAN (default), 127.0.0.1 for localhost only')
    # HLS knobs: these affect only `http-live`, not SD-card recording or VLC.
    # Roughly 1-second segments plus a 2-segment live target aim for low delay
    # while retaining a small safety margin for typical home networks.
    ap.add_argument('--hls-segment-time', type=float, default=1.0,
                    help='Target HLS segment seconds for http-live (default 1; actual cuts need keyframes)')
    # The camera's measured cadence is ~16.67 FPS, not 15. Using 15 FPS
    # slowly accumulates latency because each decoded frame is assigned too
    # much time. Exposed as an option so another CI2K firmware can be tested.
    ap.add_argument('--hls-video-fps', default='50/3',
                    help='Camera video rate used for HTTP timestamps (default 50/3 = 16.667 FPS)')
    ap.add_argument('--hls-list-size', type=int, default=6,
                    help='How many recent HLS segments to advertise (default 6)')
    ap.add_argument('--live-sync-segments', type=int, default=2,
                    help='Browser target delay in HLS segments (default 2)')
    ap.add_argument('--video-mode',choices=['timestamped','copy'],default='timestamped',help='timestamped re-encodes with explicit PTS; copy uses original v5 remux')
    ap.add_argument('--audio-input-port',type=int,default=12347,help='Internal FFmpeg audio UDP input port')
    ap.add_argument('--gain-db',type=float,default=0.0,help='Microphone gain for live-av (default 0 dB)')
    ap.add_argument('--save-audio',type=Path,default=None,help='For live-av, also save microphone to WAV on exit')
    ap.add_argument('--stall-timeout',type=float,default=8,help='Reconnect if no live video packets arrive for this many seconds')
    ap.add_argument('--reconnect-delay',type=float,default=3,help='Recovery backoff in seconds after an actual connection interruption (not normal buffering)')
    ap.add_argument('--seconds',type=float,default=None,help='Duration; live defaults to unlimited, capture to 8s, motion-recover to 30s')
    ap.add_argument('--output',type=Path,help='Output .bin for capture or .h264 for recover')
    ap.add_argument('--capture',type=Path,help='Raw live .bin for offline recover')
    ap.add_argument('--recording',type=Path,help='Overlapping decrypted SD MP4 for offline recover')
    ap.add_argument('--mp4',type=Path,help='Optional recovered MP4 path (requires FFmpeg)')
    ap.add_argument('--mode',dest='nightvision_mode',choices=['get','on','off','auto'],default='get',help='For nightvision: read mode (default) or choose on/off/auto')
    ap.add_argument('--confirm',action='store_true',help='Required for nightvision mode changes')
    args=ap.parse_args()
    if args.action=='recover':
        if not args.capture or not args.recording:ap.error('recover requires --capture and --recording')
        if args.output is None:args.output=Path('codi_live_recovered.h264')
        run_recovery(args);return
    if args.action=='decode-live':
        if not args.capture: ap.error('decode-live requires --capture')
        run_decode_live(args);return
    if not args.device_key:ap.error(f'{args.action} requires --device-key')
    if args.timeout<=0 or args.idle<=0 or args.page_size<=0:ap.error('timeout, idle, page-size must be positive')
    if args.seconds is None:
        args.seconds = 0 if args.action in ('live','live-av','http-live') else (30 if args.action=='motion-recover' else 8)
    if args.action=='nightvision':
        if args.nightvision_mode != 'get' and not args.confirm:
            ap.error('nightvision setting changes require --confirm')
        run_nightvision(args);return
    if args.action=='http-live':
        if args.seconds != 0:
            print('Note: --seconds is ignored for http-live; type q or quit to stop.', flush=True)
            args.seconds = 0
        run_http_livecam(args)
        return
    if args.action=='live-av':
        if args.seconds < 0: ap.error('--seconds must be >= 0')
        run_live_av(args)
    elif args.action=='live':
        if args.seconds < 0:ap.error('--seconds must be >= 0 (0 means unlimited)')
        run_live(args)
    elif args.action=='motion-recover':
        if not 5<=args.seconds<=120:ap.error('--seconds must be 5..120')
        run_motion_recover(args)
    elif args.action=='capture':
        if not 1<=args.seconds<=120:ap.error('--seconds must be 1..120')
        if args.output is None:args.output=Path('codi_live_capture.bin')
        run_capture(args)
    elif args.action in ('status','delete','format'):run_sd(args)
    else:run_recordings(args)

if __name__=='__main__':
    try:main()
    except (OSError,ValueError,RuntimeError,TimeoutError) as exc:raise SystemExit(f'ERROR: {exc}')
