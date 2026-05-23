#!/usr/bin/env python3
"""
Tomb Raider 4/5 SCRIPT.DAT and language DAT viewer.

TR4/TR5 split the old TOMBPC.DAT data into SCRIPT.DAT for gameflow and a
regional language DAT, such as ENGLISH.DAT or US.DAT, for text strings.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="replace")

LANGUAGE_XOR = 0xA5
MAX_REASONABLE_STRINGS = 4096

OPCODE_LENGTHS = {
    0x80: ("FMV", 1),
    0x81: ("Level", 5),
    0x82: ("Title Level", 4),
    0x83: ("Level Data End", 0),
    0x84: ("Cut", 1),
    0x85: ("ResidentCut1", 1),
    0x86: ("ResidentCut2", 1),
    0x87: ("ResidentCut3", 1),
    0x88: ("ResidentCut4", 1),
    0x89: ("Layer1", 4),
    0x8A: ("Layer2", 4),
    0x8B: ("UVrotate", 1),
    0x8C: ("Legend", 1),
    0x8D: ("LensFlare", 9),
    0x8E: ("Mirror", 5),
    0x8F: ("Fog", 3),
    0x90: ("AnimatingMIP", 1),
    0x91: ("LoadCamera", 25),
    0x92: ("ResetHUB", 1),
}


class ParseError(RuntimeError):
    pass


@dataclass
class OpcodeEntry:
    level_index: int
    offset: int
    code: int
    name: str
    arguments: str
    summary: str = ""
    string_index: Optional[int] = None


@dataclass
class DatInfo:
    file_size: int
    format: str
    counts: dict[str, int] = field(default_factory=dict)
    arrays: dict[str, list[str]] = field(default_factory=dict)
    opcodes: list[OpcodeEntry] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class ByteReader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def tell(self) -> int:
        return self.pos

    def require(self, size: int, context: str) -> None:
        if self.remaining < size:
            raise ParseError(
                f"Unexpected end of file while reading {context}: "
                f"need {size} bytes, have {self.remaining}"
            )

    def read(self, size: int, context: str) -> bytes:
        self.require(size, context)
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def skip(self, size: int, context: str) -> None:
        self.read(size, context)

    def u8(self, context: str) -> int:
        return self.read(1, context)[0]

    def u16(self, context: str) -> int:
        return struct.unpack_from("<H", self.read(2, context))[0]

    def u32(self, context: str) -> int:
        return struct.unpack_from("<I", self.read(4, context))[0]


class Tr45DatParser:
    def __init__(self, path: str, verbose: bool = True):
        self.path = path
        self.verbose = verbose
        self.data = b""
        self.warnings: list[str] = []

    def log(self, message: str = "") -> None:
        if self.verbose:
            print(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self.log(f"WARNING: {message}")

    def load(self) -> None:
        with open(self.path, "rb") as f:
            self.data = f.read()

    def parse(self) -> DatInfo:
        self.load()
        self.log(f"Analyzing file: {os.path.basename(self.path)}")
        self.log(f"Size: {len(self.data)} bytes")

        errors: list[str] = []
        for parser in (self.parse_language_dat, self.parse_script_dat):
            try:
                info = parser()
                info.warnings = self.warnings
                return info
            except ParseError as ex:
                errors.append(str(ex))

        raise ParseError("; ".join(errors))

    def parse_language_dat(self) -> DatInfo:
        if len(self.data) < 12:
            raise ParseError("file is too small for a TR4/TR5 language DAT header")

        reader = ByteReader(self.data)
        generic_count = reader.u16("generic string count")
        psx_count = reader.u16("PSX string count")
        pc_count = reader.u16("PC string count")
        generic_length = reader.u16("generic string block length")
        psx_length = reader.u16("PSX string block length")
        pc_length = reader.u16("PC string block length")

        total_count = generic_count + psx_count + pc_count
        total_length = generic_length + psx_length + pc_length
        if total_count <= 0 or total_count > MAX_REASONABLE_STRINGS:
            raise ParseError(f"language string count looks invalid: {total_count}")
        if 12 + (2 * total_count) + total_length > len(self.data):
            raise ParseError("language offset table and string blocks exceed file size")

        offsets = [reader.u16(f"string offset {i}") for i in range(total_count)]
        if any(offset >= total_length for offset in offsets):
            raise ParseError("language offset table points outside string data")

        block = reader.read(total_length, "language string data")
        groups = {
            "generic_strings": [],
            "psx_strings": [],
            "pc_strings": [],
        }

        for index, offset in enumerate(offsets):
            text = read_language_string(block, offset)
            if index < generic_count:
                groups["generic_strings"].append(text)
            elif index < generic_count + psx_count:
                groups["psx_strings"].append(text)
            else:
                groups["pc_strings"].append(text)

        self.log("\n--- DETECTED TR4/TR5 LANGUAGE DAT ---")
        self.log(f"Generic strings: {generic_count}")
        self.log(f"PSX strings: {psx_count}")
        self.log(f"PC strings: {pc_count}")

        return DatInfo(
            file_size=len(self.data),
            format="TR4/TR5 language DAT",
            counts={
                "generic_strings": generic_count,
                "psx_strings": psx_count,
                "pc_strings": pc_count,
                "total_strings": total_count,
                "generic_block_length": generic_length,
                "psx_block_length": psx_length,
                "pc_block_length": pc_length,
            },
            arrays=groups,
            strings=unique(text for values in groups.values() for text in values if text),
        )

    def parse_script_dat(self) -> DatInfo:
        if len(self.data) < 43:
            raise ParseError("file is too small for a TR4/TR5 SCRIPT.DAT header")

        reader = ByteReader(self.data)
        options = reader.u8("options")
        header_filler = reader.read(3, "header filler")
        input_timeout = reader.u32("input timeout")
        security = reader.u8("security")
        level_count = reader.u8("level count")
        unique_level_path_count = reader.u16("unique level path count")
        path_block_length = reader.u16("path block length")
        level_block_length = reader.u16("level block length")
        psx_level_ext = decode_text(reader.read(5, "PSX level extension"))
        psx_fmv_ext = decode_text(reader.read(5, "PSX FMV extension"))
        psx_cut_ext = decode_text(reader.read(5, "PSX cut extension"))
        extension_filler = reader.read(5, "extension filler")
        pc_level_ext = decode_text(reader.read(5, "PC level extension"))
        pc_fmv_ext = decode_text(reader.read(5, "PC FMV extension"))
        pc_cut_ext = decode_text(reader.read(5, "PC cut extension"))
        unused = reader.read(5, "unused extension bytes")

        if level_count <= 0:
            raise ParseError("SCRIPT.DAT has zero levels")
        required = 2 * level_count + path_block_length + 2 * level_count + level_block_length
        if required > reader.remaining:
            raise ParseError(f"SCRIPT.DAT blocks exceed file size: need {required}, have {reader.remaining}")

        path_offsets = [reader.u16(f"path offset {i}") for i in range(level_count)]
        path_block = reader.read(path_block_length, "path block")
        level_offsets = [reader.u16(f"level offset {i}") for i in range(level_count)]
        level_block = reader.read(level_block_length, "level block")

        level_paths = [read_plain_string(path_block, offset) for offset in path_offsets]
        language_files = read_trailing_strings(reader.read(reader.remaining, "language filenames"))
        opcodes: list[OpcodeEntry] = []
        string_refs: list[str] = []

        for level_index, start in enumerate(level_offsets):
            end = level_offsets[level_index + 1] if level_index + 1 < level_count else len(level_block)
            if start >= len(level_block) or end > len(level_block) or start > end:
                self.warn(f"level {level_index}: invalid opcode range {start}..{end}")
                continue
            for entry in parse_level_opcodes(level_index, level_block, start, end):
                opcodes.append(entry)
                if entry.string_index is not None:
                    string_refs.append(f"level {level_index} {entry.name} string index {entry.string_index}")

        arrays = {
            "level_paths": level_paths,
            "language_files": language_files,
            "opcode_string_refs": string_refs,
            "psx_extensions": [psx_level_ext, psx_fmv_ext, psx_cut_ext],
            "pc_extensions": [pc_level_ext, pc_fmv_ext, pc_cut_ext],
        }

        self.log("\n--- DETECTED TR4/TR5 SCRIPT.DAT ---")
        self.log(f"Levels: {level_count}")
        self.log(f"Language DAT files: {len(language_files)}")
        self.log(f"Opcode string refs: {len(string_refs)}")

        _ = header_filler, extension_filler, unused
        return DatInfo(
            file_size=len(self.data),
            format="TR4/TR5 SCRIPT.DAT",
            counts={
                "levels": level_count,
                "unique_level_paths": unique_level_path_count,
                "path_block_length": path_block_length,
                "level_block_length": level_block_length,
                "input_timeout": input_timeout,
                "security": security,
                "options": options,
            },
            arrays=arrays,
            opcodes=opcodes,
            strings=unique(level_paths + language_files + string_refs),
        )

    def print_results(self, info: DatInfo) -> None:
        print("\n" + "=" * 80)
        print("TR4/TR5 SCRIPT ANALYSIS - RESULTS")
        print("=" * 80)
        print("\nFILE INFORMATION:")
        print(f"  File: {os.path.basename(self.path)}")
        print(f"  Size: {info.file_size:,} bytes")
        print(f"  Format: {info.format}")
        print(f"  Total strings found: {len(info.strings)}")

        if info.counts:
            print("\nCOUNTS:")
            for key, value in info.counts.items():
                print(f"  {key}: {value}")

        for title, key in (
            ("LEVEL PATHS", "level_paths"),
            ("LANGUAGE FILES", "language_files"),
            ("OPCODE STRING REFS", "opcode_string_refs"),
            ("RESOLVED STRING REFS", "resolved_string_refs"),
            ("GENERIC STRINGS", "generic_strings"),
            ("PSX STRINGS", "psx_strings"),
            ("PC STRINGS", "pc_strings"),
            ("PC EXTENSIONS", "pc_extensions"),
            ("PSX EXTENSIONS", "psx_extensions"),
        ):
            print_section(title, info.arrays.get(key, []))

        if info.opcodes:
            print(f"\nOPCODES ({len(info.opcodes)}):")
            for i, opcode in enumerate(info.opcodes[:80], 1):
                print(f"  {i:2d}. {opcode.summary}")
            if len(info.opcodes) > 80:
                print(f"      ... and {len(info.opcodes) - 80} more")

        if info.warnings:
            print("\nWARNINGS:")
            for warning in info.warnings:
                print(f"  - {warning}")

        print("\nALL STRINGS:")
        print("-" * 80)
        for i, text in enumerate(info.strings, 1):
            display = text[:100] + "..." if len(text) > 100 else text
            print(f"{i:3d}. ({len(text):2d} chars) {display}")
        print("\n" + "=" * 80)


def parse_level_opcodes(level_index: int, block: bytes, start: int, end: int) -> list[OpcodeEntry]:
    entries: list[OpcodeEntry] = []
    position = start
    while position < end:
        offset = position
        code = block[position]
        position += 1
        name, length = opcode_info(code)
        length = min(length, end - position)
        args = block[position:position + length]
        position += length
        string_index = opcode_string_index(code, args)
        entries.append(
            OpcodeEntry(
                level_index=level_index,
                offset=offset,
                code=code,
                name=name,
                arguments=args.hex(" ").upper(),
                summary=summarize_opcode(level_index, offset, code, name, args, string_index),
                string_index=string_index,
            )
        )
        if code == 0x83:
            break
    return entries


def opcode_info(code: int) -> tuple[str, int]:
    known = OPCODE_LENGTHS.get(code)
    if known:
        return known
    if 0x93 <= code <= 0xD9:
        return item_opcode_name(code), 14
    return f"Unknown 0x{code:02X}", 0


def item_opcode_name(code: int) -> str:
    if 0x93 <= code <= 0x9E:
        return f"KEY_ITEM{code - 0x92}"
    if 0x9F <= code <= 0xAA:
        return f"PUZZLE_ITEM{code - 0x9E}"
    if 0xAB <= code <= 0xAE:
        return f"PICKUP_ITEM{code - 0xAA}"
    if 0xAF <= code <= 0xB1:
        return f"EXAMINE{code - 0xAE}"
    return "Combo Item"


def opcode_string_index(code: int, args: bytes) -> Optional[int]:
    if code == 0x81 and args:
        return args[0]
    if code == 0x8C and args:
        return args[0]
    if 0x93 <= code <= 0xD9 and len(args) >= 2:
        return struct.unpack_from("<H", args, 0)[0]
    return None


def summarize_opcode(
    level_index: int,
    offset: int,
    code: int,
    name: str,
    args: bytes,
    string_index: Optional[int],
) -> str:
    prefix = f"level {level_index} @0x{offset:04X}: {name}"
    if code == 0x81 and len(args) >= 5:
        return (
            f"{prefix} string={args[0]}, options=0x{struct.unpack_from('<H', args, 1)[0]:04X}, "
            f"path={args[3]}, audio={args[4]}"
        )
    if code == 0x82 and len(args) >= 4:
        return (
            f"{prefix} path={args[0]}, options=0x{struct.unpack_from('<H', args, 1)[0]:04X}, "
            f"audio={args[3]}"
        )
    if string_index is not None:
        return f"{prefix} string={string_index}"
    if args:
        return f"{prefix} args={args.hex(' ').upper()}"
    return prefix


def merge_language(script: DatInfo, language: DatInfo) -> None:
    for key in ("generic_strings", "psx_strings", "pc_strings"):
        if key in language.arrays:
            script.arrays[key] = language.arrays[key]

    language_strings = (
        language.arrays.get("generic_strings", [])
        + language.arrays.get("psx_strings", [])
        + language.arrays.get("pc_strings", [])
    )
    resolved = []
    for opcode in script.opcodes:
        if opcode.string_index is not None and 0 <= opcode.string_index < len(language_strings):
            resolved.append(
                f"level {opcode.level_index} {opcode.name} string index "
                f"{opcode.string_index}: {language_strings[opcode.string_index]}"
            )
    if resolved:
        script.arrays["resolved_string_refs"] = resolved
    script.counts.update({f"language_{key}": value for key, value in language.counts.items()})
    script.strings = unique(script.strings + language.strings)


def read_language_string(data: bytes, offset: int) -> str:
    raw = bytearray()
    position = offset
    while position < len(data) and data[position] != 0:
        raw.append(data[position] ^ LANGUAGE_XOR)
        position += 1
    return decode_text(bytes(raw))


def read_plain_string(data: bytes, offset: int) -> str:
    if offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return decode_text(data[offset:end])


def read_trailing_strings(data: bytes) -> list[str]:
    strings = []
    start = 0
    for index, value in enumerate(data):
        if value == 0:
            if index > start:
                strings.append(decode_text(data[start:index]))
            start = index + 1
    if start < len(data):
        strings.append(decode_text(data[start:]))
    return strings


def decode_text(data: bytes) -> str:
    data = data.split(b"\x00", 1)[0]
    for encoding in ("ascii", "cp1252", "latin1"):
        try:
            return data.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return data.decode("latin1", errors="replace").strip()


def unique(values: Iterable[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def print_section(title: str, values: list[str], limit: int = 40) -> None:
    if not values:
        return
    print(f"\n{title} ({len(values)}):")
    for i, value in enumerate(values[:limit], 1):
        display = value[:100] + "..." if len(value) > 100 else value
        print(f"  {i:2d}. {display}")
    if len(values) > limit:
        print(f"      ... and {len(values) - limit} more")


def to_jsonable(info: DatInfo) -> dict[str, Any]:
    return asdict(info)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tr45-dat-viewer",
        description="Parse TR4/TR5 SCRIPT.DAT with its matching language DAT."
    )
    parser.add_argument("script_file", help="Path to SCRIPT.DAT")
    parser.add_argument("language_file", help="Path to the matching language DAT, such as Italian.DAT")
    parser.add_argument("--json", action="store_true", help="Print parsed data as JSON")
    parser.add_argument("--quiet", action="store_true", help="Suppress parser progress output")
    args = parser.parse_args(argv)

    if not os.path.exists(args.script_file):
        print(f"File not found: {args.script_file}", file=sys.stderr)
        return 1
    if not os.path.exists(args.language_file):
        print(f"File not found: {args.language_file}", file=sys.stderr)
        return 1

    dat_parser = Tr45DatParser(args.script_file, verbose=not args.quiet and not args.json)
    try:
        info = dat_parser.parse()
        if info.format != "TR4/TR5 SCRIPT.DAT":
            raise ParseError(f"first argument must be SCRIPT.DAT, detected {info.format}")

        language = Tr45DatParser(args.language_file, verbose=False).parse()
        if language.format != "TR4/TR5 language DAT":
            raise ParseError(f"second argument must be a language DAT, detected {language.format}")
        merge_language(info, language)
    except ParseError as ex:
        print(f"Parse failed: {ex}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(to_jsonable(info), indent=2, ensure_ascii=False))
    else:
        dat_parser.print_results(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
