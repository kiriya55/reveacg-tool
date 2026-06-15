#!/usr/bin/env python3
import argparse
from pathlib import Path


DEFAULT_KEY = b"zaq8jfokp1j4"
DEFAULT_SIGN = b"trainjs"
DELTA = 0x9E3779B9


def _to_uint32_array(data: bytes, include_length: bool) -> list[int]:
    length = len(data)
    n = (length + 3) // 4
    result = []
    for i in range(n):
        chunk = data[i * 4 : i * 4 + 4]
        result.append(int.from_bytes(chunk.ljust(4, b"\0"), "little"))
    if include_length:
        result.append(length)
    return result


def _to_bytes(values: list[int], include_length: bool) -> bytes:
    if not values:
        return b""

    data = b"".join((value & 0xFFFFFFFF).to_bytes(4, "little") for value in values)
    if not include_length:
        return data

    length = values[-1]
    max_length = (len(values) - 1) * 4
    if length < 0 or length > max_length:
        return b""
    return data[:length]


def xxtea_decrypt(data: bytes, key: bytes) -> bytes:
    if not data:
        return b""

    v = _to_uint32_array(data, False)
    k = _to_uint32_array(key[:16].ljust(16, b"\0"), False)
    n = len(v) - 1
    if n < 1:
        return data

    rounds = 6 + 52 // (n + 1)
    total = (rounds * DELTA) & 0xFFFFFFFF
    y = v[0]

    while total:
        e = (total >> 2) & 3
        for p in range(n, 0, -1):
            z = v[p - 1]
            mx = (
                (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)))
                ^ ((total ^ y) + (k[(p & 3) ^ e] ^ z))
            )
            v[p] = (v[p] - mx) & 0xFFFFFFFF
            y = v[p]

        z = v[n]
        mx = (
            (((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) + ((y >> 3) ^ ((z << 4) & 0xFFFFFFFF)))
            ^ ((total ^ y) + (k[e] ^ z))
        )
        v[0] = (v[0] - mx) & 0xFFFFFFFF
        y = v[0]
        total = (total - DELTA) & 0xFFFFFFFF

    return _to_bytes(v, True)


def decrypt_bytes(data: bytes, key: bytes, sign: bytes) -> bytes:
    if sign and data.startswith(sign):
        return xxtea_decrypt(data[len(sign) :], key)
    return data


def decrypt_file(src: Path, dst: Path, key: bytes, sign: bytes) -> bool:
    data = src.read_bytes()
    out = decrypt_bytes(data, key, sign)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(out)
    return out != data


def is_relative_to(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt Revetrain/Cocos .jsc files encrypted with XXTEA."
    )
    parser.add_argument("input", type=Path, help="Input .jsc file or directory")
    parser.add_argument("output", type=Path, help="Output file or directory")
    parser.add_argument("--key", default=DEFAULT_KEY.decode("ascii"), help="XXTEA key")
    parser.add_argument("--sign", default=DEFAULT_SIGN.decode("ascii"), help="Encrypted file signature")
    parser.add_argument(
        "--ext",
        default=".js",
        help="Output extension for decrypted .jsc files in directory mode; use empty string to preserve names",
    )
    args = parser.parse_args()

    key = args.key.encode("utf-8")
    sign = args.sign.encode("utf-8")
    input_path = args.input.resolve()
    output_path = args.output.resolve()

    if input_path.is_file():
        changed = decrypt_file(input_path, output_path, key, sign)
        print(f"{'decrypted' if changed else 'copied'}: {input_path} -> {output_path}")
        return 0

    if not input_path.is_dir():
        raise SystemExit(f"input not found: {input_path}")

    if input_path == output_path or is_relative_to(output_path, input_path):
        raise SystemExit(
            "refusing to write the output directory inside the input directory; "
            "choose a sibling or another external path"
        )

    total = changed = 0
    input_files = [src for src in input_path.rglob("*") if src.is_file()]
    for src in input_files:
        rel = src.relative_to(input_path)
        if rel.suffix.lower() == ".jsc" and args.ext:
            rel = rel.with_suffix(args.ext)
        total += 1
        if decrypt_file(src, output_path / rel, key, sign):
            changed += 1

    print(f"processed {total} files, decrypted {changed}, output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
