#!/usr/bin/env python3
"""
Tomb Raider 2/3 TOMBPC.DAT script parser.

The structured parser is based on the layout used by TombPC-Editor:
fixed 256-byte description, gameflow fields, flags/XOR key, and
TPCStringArray blocks made of offset table + total size + string data.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional


DESCRIPTION_LENGTH = 256
EXPECTED_GAMEFLOW_SIZES = {128, 512}

UNKNOWN1_LENGTH = 36
UNKNOWN2_LENGTH = 32
UNKNOWN3_LENGTH = 6
UNKNOWN4_LENGTH = 4

FLAG_XOR_ENCRYPTION = 0x0100
NUM_PC_STRINGS = 41
NUM_PUZZLE_TYPES = 4
NUM_PICKUP_TYPES = 2
NUM_KEY_TYPES = 4

MAX_REASONABLE_COUNT = 512
MAX_OFFSET_THRESHOLD = 1000
MIN_TOTAL_SIZE_FOR_LARGE_OFFSETS = 1000

LANGUAGES = {
    0: "English",
    1: "French",
    2: "German",
    3: "Spanish",
    4: "Italian",
    5: "Russian",
    6: "Polish",
    7: "Czech",
    8: "Hungarian",
}


class ParseError(RuntimeError):
    """Raised when the structured DAT parser cannot continue safely."""


@dataclass
class StringEntry:
    index: int
    offset: int
    length: int
    text: str


@dataclass
class TpcStringArray:
    name: str
    count: int
    offsets: List[int] = field(default_factory=list)
    total_size: int = 0
    data_offset: int = 0
    strings: List[StringEntry] = field(default_factory=list)
    warning: Optional[str] = None


@dataclass
class SequenceEntry:
    level_index: int
    opcode: int
    argument: Optional[int] = None


@dataclass
class ScriptInfo:
    file_size: int
    version: int = 0
    description: str = ""
    gameflow_size: int = 0
    language: str = "Unknown"
    flags: int = 0
    xor_key: int = 0
    uses_xor: bool = False
    counts: Dict[str, int] = field(default_factory=dict)
    arrays: Dict[str, List[str]] = field(default_factory=dict)
    sequences: List[SequenceEntry] = field(default_factory=list)
    demo_level_ids: List[int] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    level_files: List[str] = field(default_factory=list)
    bitmap_files: List[str] = field(default_factory=list)
    key_items: List[str] = field(default_factory=list)
    game_text: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


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

    def read_bytes(self, size: int, context: str = "bytes") -> bytes:
        self.require(size, context)
        start = self.pos
        self.pos += size
        return self.data[start:self.pos]

    def skip(self, size: int, context: str = "padding") -> None:
        self.read_bytes(size, context)

    def u8(self, context: str) -> int:
        return self.read_bytes(1, context)[0]

    def u16(self, context: str) -> int:
        return struct.unpack_from("<H", self.read_bytes(2, context))[0]

    def i32(self, context: str) -> int:
        return struct.unpack_from("<i", self.read_bytes(4, context))[0]

    def u32(self, context: str) -> int:
        return struct.unpack_from("<I", self.read_bytes(4, context))[0]


class TombPCDATParser:
    """Parser for TR2/TR3 TOMBPC.DAT files."""

    def __init__(self, filepath: str, verbose: bool = True):
        self.filepath = filepath
        self.verbose = verbose
        self.data: bytes = b""
        self.reader: Optional[ByteReader] = None
        self.warnings: List[str] = []
        self.uses_xor = False
        self.xor_key = 0

    def log(self, message: str = "") -> None:
        if self.verbose:
            print(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)
        self.log(f"WARNING: {message}")

    def load_file(self) -> None:
        with open(self.filepath, "rb") as f:
            self.data = f.read()
        self.reader = ByteReader(self.data)

    def hex_dump(self, start: int = 0, length: int = 128) -> None:
        if not self.verbose:
            return
        print(f"\nHEX DUMP (offset {start}, {length} bytes):")
        print("-" * 60)
        end = min(start + length, len(self.data))
        for i in range(start, end, 16):
            chunk = self.data[i:i + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            print(f"{i:08X}: {hex_part:<48} {ascii_part}")

    def parse(self) -> ScriptInfo:
        self.load_file()
        self.log(f"Analyzing file: {os.path.basename(self.filepath)}")
        self.log(f"Size: {len(self.data)} bytes")
        self.hex_dump(0, 128)

        try:
            info = self.parse_structured()
        except ParseError as ex:
            self.warn(f"Structured parser failed: {ex}")
            info = self.parse_fallback()

        categories = self.categorize_strings(info.strings)
        info.level_files = categories["level_files"]
        info.bitmap_files = categories["bitmap_files"]
        info.key_items = categories["key_items"]
        info.game_text = categories["game_text"] + categories["menu_text"]
        info.warnings = self.warnings
        return info

    def parse_structured(self) -> ScriptInfo:
        if len(self.data) < 4 + DESCRIPTION_LENGTH + 2:
            raise ParseError("file is too small for a TOMBPC.DAT header")

        reader = ByteReader(self.data)
        self.reader = reader

        version = reader.u32("version")
        if version not in (2, 3):
            raise ParseError(f"unsupported version value 0x{version:08X}")

        description = decode_text(reader.read_bytes(DESCRIPTION_LENGTH, "description"))
        gameflow_size = reader.u16("gameflow size")
        if gameflow_size not in EXPECTED_GAMEFLOW_SIZES:
            expected_sizes = ", ".join(str(size) for size in sorted(EXPECTED_GAMEFLOW_SIZES))
            self.warn(f"Gameflow size is {gameflow_size}, expected one of: {expected_sizes}")

        config = {
            "first_option": reader.i32("first option"),
            "title_replace": reader.i32("title replace"),
            "on_death_demo_mode": reader.i32("on death demo mode"),
            "on_death_in_game": reader.i32("on death in game"),
            "demo_time": reader.u32("demo time"),
            "on_demo_interrupt": reader.i32("on demo interrupt"),
            "on_demo_end": reader.i32("on demo end"),
        }
        reader.skip(UNKNOWN1_LENGTH, "unknown1")

        num_levels = self.read_count("num levels")
        num_chapter_screens = self.read_count("num chapter screens")
        num_titles = self.read_count("num titles")
        num_fmvs = self.read_count("num FMVs")
        num_cutscenes = self.read_count("num cutscenes")
        num_demo_levels = self.read_count("num demo levels")
        title_sound_id = reader.u16("title sound id")
        single_level = reader.u16("single level")

        reader.skip(UNKNOWN2_LENGTH, "unknown2")
        flags = reader.u16("flags")
        reader.skip(UNKNOWN3_LENGTH, "unknown3")
        xor_key = reader.u8("xor key")
        language_id = reader.u8("language id")
        secret_sound_id = reader.u16("secret sound id")
        reader.skip(UNKNOWN4_LENGTH, "unknown4")

        self.uses_xor = bool(flags & FLAG_XOR_ENCRYPTION)
        self.xor_key = xor_key

        self.log("\n--- DETECTED STRUCTURED TOMBPC.DAT ---")
        self.log(f"Version: TR{version}")
        self.log(f"Description: {description}")
        self.log(f"Flags: 0x{flags:04X}, XOR: {self.uses_xor}, key: 0x{xor_key:02X}")
        self.log(f"Language: {LANGUAGES.get(language_id, f'Unknown ({language_id})')}")

        arrays: Dict[str, TpcStringArray] = {}
        for name, count in (
            ("level_names", num_levels),
            ("chapter_screens", num_chapter_screens),
            ("titles", num_titles),
            ("fmvs", num_fmvs),
            ("level_paths", num_levels),
            ("cutscene_paths", num_cutscenes),
        ):
            arrays[name] = self.read_tpc_string_array(name, count)

        sequences = self.try_read_sequences(num_levels)
        demo_level_ids = self.try_read_demo_level_ids(num_demo_levels)

        num_game_strings = self.try_read_u16("num game strings")
        if num_game_strings is not None:
            arrays["game_strings"] = self.read_tpc_string_array("game_strings", num_game_strings)
        arrays["pc_strings"] = self.read_tpc_string_array("pc_strings", NUM_PC_STRINGS)

        for idx in range(NUM_PUZZLE_TYPES):
            arrays[f"puzzle_strings_{idx + 1}"] = self.read_tpc_string_array(
                f"puzzle_strings_{idx + 1}", num_levels
            )
        for idx in range(NUM_PICKUP_TYPES):
            arrays[f"pickup_strings_{idx + 1}"] = self.read_tpc_string_array(
                f"pickup_strings_{idx + 1}", num_levels
            )
        for idx in range(NUM_KEY_TYPES):
            arrays[f"key_strings_{idx + 1}"] = self.read_tpc_string_array(
                f"key_strings_{idx + 1}", num_levels
            )

        array_text = {
            name: [entry.text for entry in array.strings]
            for name, array in arrays.items()
        }
        all_strings = unique_preserve_order(
            text for values in array_text.values() for text in values if text
        )

        counts = {
            "levels": num_levels,
            "chapter_screens": num_chapter_screens,
            "titles": num_titles,
            "fmvs": num_fmvs,
            "cutscenes": num_cutscenes,
            "demo_levels": num_demo_levels,
            "game_strings": num_game_strings or 0,
            "title_sound_id": title_sound_id,
            "single_level": single_level,
            "secret_sound_id": secret_sound_id,
            **config,
        }

        return ScriptInfo(
            file_size=len(self.data),
            version=version,
            description=description,
            gameflow_size=gameflow_size,
            language=LANGUAGES.get(language_id, f"Unknown ({language_id})"),
            flags=flags,
            xor_key=xor_key,
            uses_xor=self.uses_xor,
            counts=counts,
            arrays=array_text,
            sequences=sequences,
            demo_level_ids=demo_level_ids,
            strings=all_strings,
        )

    def read_count(self, name: str) -> int:
        assert self.reader is not None
        value = self.reader.u16(name)
        if value > MAX_REASONABLE_COUNT:
            raise ParseError(f"{name} looks invalid: {value}")
        return value

    def read_tpc_string_array(self, name: str, count: int) -> TpcStringArray:
        assert self.reader is not None
        array = TpcStringArray(name=name, count=count)

        if count < 0:
            raise ParseError(f"{name} count is negative: {count}")
        if count > MAX_REASONABLE_COUNT:
            raise ParseError(f"{name} count is too large: {count}")

        start_pos = self.reader.tell()
        self.log(f"[{name}] count={count} at 0x{start_pos:X}")

        array.offsets = [self.reader.u16(f"{name} offset {i}") for i in range(count)]
        array.total_size = self.reader.u16(f"{name} total size")

        if count == 0 and array.total_size == 0:
            return array

        if self.has_impossible_offsets(array):
            array.warning = "impossible offsets; skipped data block"
            self.warn(f"{name}: {array.warning}")
            self.reader.skip(min(array.total_size, self.reader.remaining), f"{name} corrupt data")
            return array

        if array.total_size == 0:
            return array
        if array.total_size > self.reader.remaining:
            array.warning = (
                f"total size {array.total_size} exceeds remaining bytes {self.reader.remaining}"
            )
            self.warn(f"{name}: {array.warning}")
            self.reader.skip(self.reader.remaining, f"{name} truncated data")
            return array

        array.data_offset = self.reader.tell()
        raw_data = self.reader.read_bytes(array.total_size, f"{name} data")
        data = bytes(byte ^ self.xor_key for byte in raw_data) if self.uses_xor else raw_data
        array.strings = self.extract_strings_from_offsets(data, array)
        self.log(f"  strings decoded: {len(array.strings)}")
        return array

    @staticmethod
    def has_impossible_offsets(array: TpcStringArray) -> bool:
        return (
            bool(array.offsets)
            and all(offset >= MAX_OFFSET_THRESHOLD for offset in array.offsets)
            and array.total_size < MIN_TOTAL_SIZE_FOR_LARGE_OFFSETS
        )

    def extract_strings_from_offsets(self, data: bytes, array: TpcStringArray) -> List[StringEntry]:
        entries: List[StringEntry] = []

        for index, offset in enumerate(array.offsets):
            if offset >= len(data):
                self.warn(f"{array.name}: offset {offset} is outside data block ({len(data)} bytes)")
                continue

            end = data.find(b"\x00", offset)
            if end < 0:
                end = len(data)
            if end == offset:
                continue

            text = decode_text(data[offset:end])
            if text:
                entries.append(
                    StringEntry(
                        index=index,
                        offset=array.data_offset + offset,
                        length=end - offset + (1 if end < len(data) else 0),
                        text=text,
                    )
                )

        return entries

    def try_read_sequences(self, num_levels: int) -> List[SequenceEntry]:
        assert self.reader is not None
        sequences: List[SequenceEntry] = []
        start = self.reader.tell()

        try:
            number_of_levels = num_levels + 1
            offsets = [self.reader.u16(f"sequence offset {i}") for i in range(number_of_levels)]
            sequence_num_bytes = self.reader.u16("sequence byte count")
            if sequence_num_bytes > self.reader.remaining:
                raise ParseError(
                    f"sequence block size {sequence_num_bytes} exceeds remaining {self.reader.remaining}"
                )

            sequence_start = self.reader.tell()
            bytes_read = 0
            while bytes_read + 2 <= sequence_num_bytes:
                opcode = self.reader.u16("sequence opcode")
                bytes_read += 2
                sequences.append(SequenceEntry(0, opcode, None))

            if bytes_read != sequence_num_bytes:
                self.warn(
                    f"sequence byte count mismatch: expected {sequence_num_bytes}, read {bytes_read}"
                )
                self.reader.pos = sequence_start + sequence_num_bytes
            self.log(f"[sequences] offsets={len(offsets)}, words={len(sequences)}")
        except ParseError as ex:
            self.warn(f"could not read sequences at 0x{start:X}: {ex}")

        return sequences

    def try_read_demo_level_ids(self, num_demo_levels: int) -> List[int]:
        values: List[int] = []
        for idx in range(num_demo_levels):
            value = self.try_read_u16(f"demo level id {idx}")
            if value is None:
                break
            values.append(value)
        return values

    def try_read_u16(self, context: str) -> Optional[int]:
        assert self.reader is not None
        if self.reader.remaining < 2:
            self.warn(f"not enough data to read {context}")
            return None
        return self.reader.u16(context)

    def parse_fallback(self) -> ScriptInfo:
        strings = self.extract_ascii_runs(self.data)
        self.log(f"Fallback ASCII extraction found {len(strings)} strings")
        return ScriptInfo(file_size=len(self.data), strings=strings)

    @staticmethod
    def extract_ascii_runs(data: bytes) -> List[str]:
        strings: List[str] = []
        i = 0
        while i < len(data):
            if 32 <= data[i] <= 126:
                start = i
                while i < len(data) and 32 <= data[i] <= 126:
                    i += 1
                if i < len(data) and data[i] == 0 and i - start >= 3:
                    strings.append(decode_text(data[start:i]))
                i += 1
            else:
                i += 1
        return unique_preserve_order(strings)

    @staticmethod
    def categorize_strings(all_strings: List[str]) -> Dict[str, List[str]]:
        categories = {
            "level_files": [],
            "bitmap_files": [],
            "key_items": [],
            "weapons": [],
            "items": [],
            "game_text": [],
            "menu_text": [],
            "other": [],
        }

        for text in all_strings:
            lower = text.lower()
            if any(token in lower for token in (".tr2", ".phd", "data\\", "data/")):
                categories["level_files"].append(text)
            elif any(token in lower for token in (".bmp", "pix\\", "pix/")):
                categories["bitmap_files"].append(text)
            elif any(token in lower for token in ("key", "chiave", "access", "card", "code")):
                categories["key_items"].append(text)
            elif any(token in lower for token in ("pistol", "shotgun", "uzi", "magnum", "grenade", "harpoon", "mp5")):
                categories["weapons"].append(text)
            elif any(token in lower for token in ("medipack", "medkit", "ammo", "crystal", "stone", "gem")):
                categories["items"].append(text)
            elif any(token in lower for token in ("game", "load", "save", "options", "inventory", "level", "demo")):
                categories["menu_text"].append(text)
            elif len(text) > 25:
                categories["game_text"].append(text)
            else:
                categories["other"].append(text)

        return categories

    def print_results(self, info: ScriptInfo) -> None:
        print("\n" + "=" * 80)
        print("TOMB RAIDER SCRIPT ANALYSIS - RESULTS")
        print("=" * 80)
        print(f"\nFILE INFORMATION:")
        print(f"  File: {os.path.basename(self.filepath)}")
        print(f"  Size: {info.file_size:,} bytes")
        if info.version:
            print(f"  Version: TR{info.version}")
            print(f"  Description: {info.description}")
            print(f"  Gameflow size: {info.gameflow_size}")
            print(f"  Language: {info.language}")
            print(f"  Flags: 0x{info.flags:04X}")
            print(f"  XOR: {'yes' if info.uses_xor else 'no'} (key 0x{info.xor_key:02X})")
        print(f"  Total strings found: {len(info.strings)}")

        if info.counts:
            print("\nCOUNTS:")
            for key in ("levels", "chapter_screens", "titles", "fmvs", "cutscenes", "demo_levels", "game_strings"):
                print(f"  {key}: {info.counts.get(key, 0)}")

        for title, key in (
            ("LEVEL NAMES", "level_names"),
            ("LEVEL FILES", "level_paths"),
            ("CHAPTER SCREENS", "chapter_screens"),
            ("TITLES", "titles"),
            ("FMVS", "fmvs"),
            ("CUTSCENES", "cutscene_paths"),
            ("GAME STRINGS", "game_strings"),
            ("PC STRINGS", "pc_strings"),
        ):
            self.print_section(title, info.arrays.get(key, []))

        item_sections = [
            key for key in sorted(info.arrays)
            if key.startswith(("puzzle_strings_", "pickup_strings_", "key_strings_"))
        ]
        for key in item_sections:
            self.print_section(key.upper(), info.arrays[key])

        if info.demo_level_ids:
            print(f"\nDEMO LEVEL IDS: {', '.join(str(value) for value in info.demo_level_ids)}")
        if info.sequences:
            print(f"\nSEQUENCES: {len(info.sequences)} opcode entries")

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

    @staticmethod
    def print_section(title: str, values: List[str], limit: int = 40) -> None:
        if not values:
            return
        print(f"\n{title} ({len(values)}):")
        for i, value in enumerate(values[:limit], 1):
            display = value[:100] + "..." if len(value) > 100 else value
            print(f"  {i:2d}. {display}")
        if len(values) > limit:
            print(f"      ... and {len(values) - limit} more")


def decode_text(data: bytes) -> str:
    data = data.split(b"\x00", 1)[0]
    for encoding in ("ascii", "cp1252", "latin1"):
        try:
            return data.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    return data.decode("latin1", errors="replace").strip()


def unique_preserve_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def to_jsonable(info: ScriptInfo) -> Dict[str, Any]:
    return asdict(info)


def main(argv: Optional[List[str]] = None) -> int:
    arg_parser = argparse.ArgumentParser(
        prog="tombpc-viewer",
        description="Parse Tomb Raider 2/3 TOMBPC.DAT script files."
    )
    arg_parser.add_argument("file", help="Path to TOMBPC.DAT")
    arg_parser.add_argument("--json", action="store_true", help="Print parsed data as JSON")
    arg_parser.add_argument("--quiet", action="store_true", help="Suppress parser progress output")
    args = arg_parser.parse_args(argv)

    if not os.path.exists(args.file):
        print(f"File not found: {args.file}", file=sys.stderr)
        return 1

    parser = TombPCDATParser(args.file, verbose=not args.quiet and not args.json)
    info = parser.parse()
    if args.json:
        print(json.dumps(to_jsonable(info), indent=2, ensure_ascii=False))
    else:
        parser.print_results(info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
