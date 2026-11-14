"""Encode deterministic synthetic handshake records; no network operations.

The ClientHello field shape follows the worker's canonical test fixture.
These bytes exercise parsing and grouping, not a completed TLS negotiation.
"""

import argparse
from pathlib import Path


def u16(value: int) -> bytes:
    """Encode a two-byte unsigned integer."""
    return value.to_bytes(2, "big")


def vector(values: list[int]) -> bytes:
    """Encode an ordered sequence of two-byte values."""
    return b"".join(u16(value) for value in values)


def extension(kind: int, body: bytes) -> bytes:
    """Encode a TLS extension with its declared length."""
    return u16(kind) + u16(len(body)) + body


def handshake(kind: int, body: bytes) -> bytes:
    """Wrap a body in a handshake message header."""
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def client(
    *, reverse: bool = False, grease: int = 0x0A0A, host: str = "shared-soon.example"
) -> bytes:
    """Create one authored ClientHello; preserve signature-algorithm order."""
    ciphers = [
        0x002F,
        0x0035,
        0x009C,
        0x009D,
        0x1301,
        0x1302,
        0x1303,
        0xC013,
        0xC014,
        0xC02B,
        0xC02C,
        0xC02F,
        0xC030,
        0xCCA8,
        0xCCA9,
    ]
    if reverse:
        ciphers.reverse()
    ciphers = [grease, *ciphers]
    name = host.encode("ascii")
    sni = u16(len(name) + 3) + b"\x00" + u16(len(name)) + name
    curves = vector([29, 23, 24, 25])
    signatures = vector([0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601])
    versions = vector([grease, 0x0304, 0x0303])
    extensions = b"".join(
        [
            extension(0, sni),
            extension(5, b"\x01\x00\x00\x00\x00"),
            extension(10, u16(len(curves)) + curves),
            extension(11, b"\x01\x00"),
            extension(13, u16(len(signatures)) + signatures),
            extension(16, b"\x00\x03\x02h2"),
            extension(18, b""),
            extension(21, b""),
            extension(23, b""),
            extension(27, b""),
            extension(grease, b""),
            extension(35, b""),
            extension(43, bytes([len(versions)]) + versions),
            extension(45, b"\x01\x00"),
            extension(51, b""),
            extension(17513, b""),
            extension(65281, b"\x00"),
        ]
    )
    body = u16(771) + b"\x11" * 32 + b"\x00" + u16(len(ciphers) * 2) + vector(ciphers)
    body += b"\x01\x00" + u16(len(extensions)) + extensions
    return handshake(1, body)


def main() -> None:
    """Write variant and diagnostic bytes to the requested directory."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    base = client()
    server_extensions = extension(65281, b"\x00") + extension(16, b"\x00\x03\x02h2")
    server_body = u16(771) + b"\x22" * 32 + b"\x00" + u16(0xC02F) + b"\x00"
    server_body += u16(len(server_extensions)) + server_extensions
    variants = {
        "base": base,
        "record": b"\x16\x03\x01" + u16(len(base)) + base,
        "reversed-ciphers": client(reverse=True),
        "different-grease": client(grease=0x2A2A),
        "other-server": client(host="long.example"),
        "header-only": handshake(1, u16(771) + b"\x11" * 32),
        "server-hello": handshake(2, server_body),
        "not-handshake": b"synthetic non-handshake bytes",
    }
    for name, data in variants.items():
        (args.output / f"{name}.bin").write_bytes(data)


if __name__ == "__main__":
    main()
