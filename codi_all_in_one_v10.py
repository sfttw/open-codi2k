#!/usr/bin/env python3
"""Codi 2K LAN recording browser/downloader with integrated AES-CBC decoding.

Python 3.10+; install: python3 -m pip install pycryptodomex
Uses the camera's local TCP protocol; no cloud service is required.
"""
import argparse
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

RPC_SECRET = 'P2p0r1p8c0622'
CHUNK = 4096
ENCRYPTED_PREFIX = 496


def vi(n):
    if n < 0: raise ValueError('negative varint')
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def read_vi(data, pos):
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
    def __init__(self, args):
        self.args = args
        self.sock = None
        self.buffer = bytearray()
        self.seq = 1

    def __enter__(self):
        self.sock = socket.create_connection((self.args.host, self.args.port), timeout=8)
        self.sock.settimeout(0.4)
        self.send(0xa32, string(1, self.args.did) + integer(3, int(time.time())) + string(4, self.args.device_key))
        print(f'Connected to {self.args.host}:{self.args.port}', flush=True)
        return self

    def __exit__(self, *exc):
        if self.sock: self.sock.close()

    def send(self, msgid, payload, seq=None, flags=0x0c):
        if seq is None:
            seq = self.seq
            self.seq += 1
        self.sock.sendall(make_packet(seq, msgid, flags, payload))

    def packets(self, seconds):
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
    def __enter__(self):
        self.disconnected = False
        return super().__enter__()

    def frames(self, seconds):
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
    """Decode one SDK 0x68 H.264 frame, including encrypted keyframe prefix.

    Verified key formula for channel 0, AVSeq 0 using five independent
    first-block known-plaintext comparisons. Raises for unsupported framing.
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


def run_live_av(args):
    """Experimental single MPEG-TS output with live video + A-law microphone.

    Both video and audio are sent via nonblocking localhost UDP sockets.
    FFmpeg never receives camera packets through a blocking stdin pipe.
    The camera is opened once and both media-start RPCs use that connection.
    """
    import shutil
    import subprocess
    import threading
    from collections import Counter

    if shutil.which('ffmpeg') is None:
        raise RuntimeError('FFmpeg not found on PATH')
    if not 1 <= args.udp_port <= 65535 or not 1 <= args.audio_input_port <= 65535:
        raise ValueError('UDP ports must be 1..65535')
    if args.udp_port == args.audio_input_port:
        raise ValueError('--udp-port and --audio-input-port must differ')
    if args.stall_timeout <= 0 or args.reconnect_delay <= 0:
        raise ValueError('Timeouts must be positive')

    video_codec = (['-vf', 'setpts=N/(15*TB)', '-c:v', 'libx264',
                    '-preset', 'ultrafast', '-tune', 'zerolatency',
                    '-bf', '0', '-g', '15', '-pix_fmt', 'yuv420p']
                   if args.video_mode == 'timestamped' else ['-c:v', 'copy'])
    video_input_port = args.audio_input_port + 1
    if video_input_port == args.udp_port or video_input_port > 65535:
        raise ValueError('Choose --audio-input-port so its next port does not conflict with --udp-port')
    audio_input = f'udp://127.0.0.1:{args.audio_input_port}?fifo_size=1000000&overrun_nonfatal=1'
    video_input = f'udp://127.0.0.1:{video_input_port}?fifo_size=1000000&overrun_nonfatal=1'
    output = f'udp://127.0.0.1:{args.udp_port}?pkt_size=1316'
    command = ['ffmpeg', '-hide_banner', '-loglevel', 'warning', '-nostdin',
               '-thread_queue_size', '1024', '-fflags', '+genpts',
               '-probesize', '32', '-analyzeduration', '0',
               '-r', '15', '-f', 'h264', '-i', video_input,
               '-thread_queue_size', '1024', '-probesize', '32', '-analyzeduration', '0', '-f', 'alaw', '-ar', '8000', '-ac', '1',
               '-i', audio_input,
               '-map', '0:v:0', '-map', '1:a:0',
               *video_codec,
               '-af', f'volume={args.gain_db}dB,aresample=48000:async=1:first_pts=0',
               '-c:a', 'mp2', '-b:a', '128k', '-ar', '48000', '-ac', '1',
               '-muxdelay', '0', '-muxpreload', '0', '-flush_packets', '1', '-f', 'mpegts', output]

    stop = threading.Event()
    def keyboard():
        while not stop.is_set():
            try: line = sys.stdin.readline()
            except (OSError, ValueError): return
            if not line: return
            if line.strip().lower() in ('q', 'quit', 'exit'):
                stop.set()
                return
            print('Type q and press Enter to stop.', flush=True)
    threading.Thread(target=keyboard, daemon=True).start()

    print(f'Combined VIDEO + AUDIO VLC URL: udp://@:{args.udp_port}', flush=True)
    print('VLC is not launched automatically. Type q + Enter to stop.', flush=True)
    print(f'Audio gain: {args.gain_db:g} dB; video mode: {args.video_mode}', flush=True)
    print(f'Internal FFmpeg inputs: video UDP {video_input_port}, audio UDP {args.audio_input_port}', flush=True)
    stats = Counter()
    attempt = 0
    deadline = time.monotonic() + args.seconds if args.seconds else None
    audio_capture = None
    if args.save_audio:
        args.save_audio.parent.mkdir(parents=True, exist_ok=True)
        audio_capture = open(args.save_audio.with_suffix('.alaw'), 'wb')
        print(f'Saving raw microphone samples to {args.save_audio.with_suffix(".alaw")}', flush=True)

    def cleanup(proc):
        if proc is None: return
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try: proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait()

    try:
        while not stop.is_set() and (deadline is None or time.monotonic() < deadline):
            attempt += 1
            proc = None
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.setblocking(False)
            try:
                with LiveCamera(args) as cam:
                    proc = subprocess.Popen(command, stdin=subprocess.DEVNULL)
                    for _ in cam.frames(1.5): pass
                    cam.send(0xA29, integer(1, args.channel) + integer(2, args.stream))
                    cam.send(0xA2B, integer(1, args.channel))
                    print(f'Attempt {attempt}: video and microphone requested', flush=True)
                    video_started = False
                    last_video = time.monotonic()
                    while not stop.is_set() and (deadline is None or time.monotonic() < deadline):
                        for marker, mid, flags, body, raw in cam.frames(.35):
                            if marker == 0x48 and mid in (0xA29, 0xA2B):
                                print(('Video' if mid == 0xA29 else 'Audio') +
                                      ' response:', list(protobuf(body)), flush=True)
                            if marker != 0x68 or not body:
                                continue
                            # SDK video packets begin 0x81 (keyframe) or 0x01 (delta).
                            # Observed audio packets begin 0x15 and contain 11 bytes
                            # of metadata followed by 160 A-law samples.
                            if body[0] == 0x15:
                                if len(body) >= 12 and len(body[11:]) == 160:
                                    try: sender.sendto(body[11:], ('127.0.0.1', args.audio_input_port))
                                    except (BlockingIOError, OSError): stats['audio_udp_drops'] += 1
                                    if audio_capture is not None:
                                        audio_capture.write(body[11:])
                                    stats['audio_packets'] += 1
                                    if stats['audio_packets'] == 1:
                                        print('First microphone packet received.', flush=True)
                                else:
                                    stats['audio_skipped'] += 1
                                continue
                            if body[0] not in (0x81, 0x01):
                                stats['other_media'] += 1
                                continue
                            last_video = time.monotonic()
                            try: frame, key, timestamp = decode_live_frame(body)
                            except ValueError as exc:
                                stats['video_skipped'] += 1
                                if stats['video_skipped'] <= 3:
                                    print('Skipped video frame:', exc, flush=True)
                                continue
                            if key: video_started = True
                            if not video_started: continue
                            if proc.poll() is not None:
                                raise RuntimeError(f'FFmpeg exited ({proc.returncode})')
                            for offset in range(0, len(frame), 1200):
                                try: sender.sendto(frame[offset:offset+1200], ('127.0.0.1', video_input_port))
                                except (BlockingIOError, OSError): stats['video_udp_drops'] += 1
                            stats['keyframes' if key else 'delta_frames'] += 1
                            if stats['keyframes'] == 1 and key:
                                print('First keyframe decrypted. Open VLC now.', flush=True)
                            elif key and stats['keyframes'] % 15 == 0:
                                print(f"Streaming progress: {stats['keyframes']} keyframes, {stats['delta_frames']} delta frames, {stats['audio_packets']} audio packets; FFmpeg running={proc.poll() is None}", flush=True)
                        if cam.disconnected:
                            raise ConnectionError('Camera closed the connection')
                        if time.monotonic() - last_video > args.stall_timeout:
                            raise ConnectionError('Video stream stalled')
                    for msgid in (0xA2C, 0xA2A):
                        try: cam.send(msgid, integer(1, args.channel))
                        except OSError: pass
            except (OSError, ValueError, RuntimeError, ConnectionError) as exc:
                stats['reconnects'] += 1
                if not stop.is_set(): print('Stream interrupted:', exc, flush=True)
            finally:
                sender.close()
                cleanup(proc)
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
                result = subprocess.run(['ffmpeg', '-y', '-hide_banner', '-loglevel', 'error',
                                         '-f', 'alaw', '-ar', '8000', '-ac', '1', '-i', str(raw_file),
                                         '-af', 'volume=12dB', '-c:a', 'pcm_s16le', str(args.save_audio)], capture_output=True, text=True)
                if result.returncode == 0:
                    print(f'Saved microphone WAV: {args.save_audio} ({args.save_audio.stat().st_size} bytes)', flush=True)
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
        except (OSError,ValueError,RuntimeError) as exc:
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

def main():
    ap=argparse.ArgumentParser(description='Codi 2K all-in-one LAN manager v9 (Python 3.10+)')
    ap.add_argument('action',choices=['list','pick','download','all','status','delete','format','capture','recover','motion-recover','decode-live','live','live-av'])
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
    ap.add_argument('--video-mode',choices=['timestamped','copy'],default='timestamped',help='timestamped re-encodes with explicit PTS; copy uses original v5 remux')
    ap.add_argument('--audio-input-port',type=int,default=12347,help='Internal FFmpeg audio UDP input port')
    ap.add_argument('--gain-db',type=float,default=0.0,help='Microphone gain for live-av (default 0 dB)')
    ap.add_argument('--save-audio',type=Path,default=None,help='For live-av, also save microphone to WAV on exit')
    ap.add_argument('--stall-timeout',type=float,default=8,help='Reconnect if no live video packets arrive for this many seconds')
    ap.add_argument('--reconnect-delay',type=float,default=3,help='Seconds between reconnection attempts')
    ap.add_argument('--seconds',type=float,default=None,help='Duration; live defaults to unlimited, capture to 8s, motion-recover to 30s')
    ap.add_argument('--output',type=Path,help='Output .bin for capture or .h264 for recover')
    ap.add_argument('--capture',type=Path,help='Raw live .bin for offline recover')
    ap.add_argument('--recording',type=Path,help='Overlapping decrypted SD MP4 for offline recover')
    ap.add_argument('--mp4',type=Path,help='Optional recovered MP4 path (requires FFmpeg)')
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
        args.seconds = 0 if args.action in ('live','live-av') else (30 if args.action=='motion-recover' else 8)
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
    except (OSError,ValueError,RuntimeError) as exc:raise SystemExit(f'ERROR: {exc}')