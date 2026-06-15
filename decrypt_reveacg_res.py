#!/usr/bin/env python3
import argparse
from pathlib import Path


MAGIC = bytes([0x32, 0x67, 0x98])


def decrypt_bytes(data: bytes) -> bytes:
    if len(data) >= 4 and data[:3] == MAGIC:
        key = data[3]
        return bytes(b ^ key for b in data[4:])
    return data


def decrypt_file(src: Path, dst: Path) -> bool:
    data = src.read_bytes()
    out = decrypt_bytes(data)
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
        description="Decrypt Revetrain/Cocos resource files with 32 67 98 key-prefixed XOR."
    )
    parser.add_argument("input", type=Path, help="Input file or directory")
    parser.add_argument("output", type=Path, help="Output file or directory")
    args = parser.parse_args()

    input_path = args.input.resolve()
    output_path = args.output.resolve()

    if input_path.is_file():
        changed = decrypt_file(input_path, output_path)
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
        total += 1
        if decrypt_file(src, output_path / rel):
            changed += 1

    print(f"processed {total} files, decrypted {changed}, output: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
