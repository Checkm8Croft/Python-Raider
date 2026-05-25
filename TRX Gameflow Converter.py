#!/usr/bin/env python3
"""
Convert Tomb Raider 2/3 TOMBPC.DAT scripts to TRX gameflow JSON5.

The parser is a Python port of trx-update-tool/client/src/converter/tombpc.ts
plus the TOMBPC.DAT branch from gameflow.ts. It writes gameflow.json5 and
strings.json5 next to the input DAT.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class GFE:
    PICTURE = 0x0000
    LIST_START = 0x0001
    LIST_END = 0x0002
    PLAY_FMV = 0x0003
    START_LEVEL = 0x0004
    CUTSCENE = 0x0005
    LEVEL_COMPLETE = 0x0006
    DEMO_PLAY = 0x0007
    JUMP_TO_SEQ = 0x0008
    END_SEQ = 0x0009
    SET_TRACK = 0x000A
    SUNSET = 0x000B
    LOADING_PIC = 0x000C
    DEADLY_WATER = 0x000D
    REMOVE_WEAPONS = 0x000E
    GAME_COMPLETE = 0x000F
    CUT_ANGLE = 0x0010
    NO_FLOOR = 0x0011
    ADD_TO_INV = 0x0012
    START_ANIM = 0x0013
    NUM_SECRETS = 0x0014
    KILL_TO_COMPLETE = 0x0015
    REMOVE_AMMO = 0x0016


GFE_HAS_ARG = {
    GFE.PICTURE,
    GFE.PLAY_FMV,
    GFE.START_LEVEL,
    GFE.CUTSCENE,
    GFE.DEMO_PLAY,
    GFE.JUMP_TO_SEQ,
    GFE.SET_TRACK,
    GFE.LOADING_PIC,
    GFE.CUT_ANGLE,
    GFE.NO_FLOOR,
    GFE.ADD_TO_INV,
    GFE.START_ANIM,
    GFE.NUM_SECRETS,
}

TR2_INV_KEYS = [
    "pistols",
    "autos",
    "uzis",
    "shotgun",
    "harpoon_gun",
    "m16",
    "grenade_launcher",
    "pistols_ammo",
    "autos_ammo",
    "uzis_ammo",
    "shotgun_ammo",
    "harpoon_gun_ammo",
    "m16_ammo",
    "grenade_launcher_ammo",
    "flare",
    "small_medipack",
    "large_medipack",
    "pickup_1",
    "pickup_2",
    "puzzle_1",
    "puzzle_2",
    "puzzle_3",
    "puzzle_4",
    "key_1",
    "key_2",
    "key_3",
    "key_4",
]


@dataclass
class Opcode:
    op: int
    arg: int = -1


@dataclass
class ScriptInfo:
    filenames: list[str]
    level_titles: list[str]
    music_tracks: list[int]
    sequences: list[list[dict[str, Any]] | None]
    title_sound_id: int
    cd_offset: int


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_string_block(
    data: bytes,
    pos: int,
    count: int,
    cypher: int,
) -> tuple[list[str], int]:
    offsets = [u16(data, pos + i * 2) for i in range(count)]
    pos += count * 2
    dlen = u16(data, pos)
    pos += 2

    strings: list[str] = []
    for offset in offsets:
        j = pos + offset
        chars: list[str] = []
        while j < pos + dlen:
            ch = data[j] ^ cypher
            j += 1
            if ch == 0:
                break
            chars.append(chr(ch))
        strings.append("".join(chars))

    return strings, pos + dlen


def parse_tombpc_dat(raw_data: bytes) -> ScriptInfo | None:
    try:
        if len(raw_data) < 384:
            return None

        opt_size = u16(raw_data, 260)
        opt_start = 262

        num_levels = u16(raw_data, opt_start + 64)
        num_cutscenes = u16(raw_data, opt_start + 72)
        title_sound_id = u16(raw_data, opt_start + 76)
        cypher = raw_data[opt_start + 120]

        if num_levels < 2 or num_levels > 100:
            return None

        pos = opt_start + opt_size
        level_titles, title_end = read_string_block(raw_data, pos, num_levels, cypher)

        filenames: list[str] | None = None
        filenames_end = 0
        scan_limit = len(raw_data) - num_levels * 2 - 4
        for sp in range(title_end, max(title_end, scan_limit)):
            if u16(raw_data, sp) != 0:
                continue

            ok = True
            for k in range(1, num_levels):
                if u16(raw_data, sp + k * 2) <= u16(raw_data, sp + (k - 1) * 2):
                    ok = False
                    break
            if not ok:
                continue

            try:
                block, end_pos = read_string_block(raw_data, sp, num_levels, cypher)
            except (IndexError, struct.error):
                continue

            all_valid = True
            for s in block:
                sl = s.lower()
                if not any(ext in sl for ext in (".tr2", ".phd", ".tub", ".psx")):
                    all_valid = False
                    break
                if any(ord(ch) < 32 or ord(ch) > 126 for ch in s):
                    all_valid = False
                    break

            if all_valid:
                filenames = block
                filenames_end = end_pos
                break

        if not filenames:
            return None

        script_pos = filenames_end
        if num_cutscenes > 0:
            try:
                _, script_pos = read_string_block(raw_data, script_pos, num_cutscenes, cypher)
            except (IndexError, struct.error):
                pass

        script_offsets = [u16(raw_data, script_pos + i * 2) for i in range(num_levels + 1)]
        script_pos += (num_levels + 1) * 2
        script_size = u16(raw_data, script_pos)
        script_pos += 2
        script_base = script_pos

        def read_opcodes(seq_idx: int) -> list[Opcode]:
            start = script_base + script_offsets[seq_idx]
            end = (
                script_base + script_offsets[seq_idx + 1]
                if seq_idx + 1 < len(script_offsets)
                else script_base + script_size
            )
            ops: list[Opcode] = []
            p = start
            while p + 1 < end:
                op = u16(raw_data, p)
                p += 2
                if op == GFE.END_SEQ:
                    break
                arg = -1
                if op in GFE_HAS_ARG:
                    arg = u16(raw_data, p) if p + 1 < end else -1
                    p += 2
                ops.append(Opcode(op, arg))
            return ops

        def translate_sequence(ops: list[Opcode]) -> tuple[list[dict[str, Any]], int]:
            pre: list[dict[str, Any]] = []
            post: list[dict[str, Any]] = []
            music_track = -1
            seen_level = False
            is_game_complete = False

            for opcode in ops:
                target = post if seen_level else pre

                if opcode.op == GFE.SET_TRACK:
                    music_track = opcode.arg
                elif opcode.op == GFE.START_LEVEL:
                    seen_level = True
                elif opcode.op == GFE.PLAY_FMV:
                    target.append({"type": "play_fmv", "fmv_id": opcode.arg})
                elif opcode.op == GFE.CUTSCENE:
                    target.append({"type": "play_cutscene", "cutscene_id": opcode.arg})
                elif opcode.op == GFE.LEVEL_COMPLETE:
                    post.append({"type": "play_music", "music_track": 41})
                    post.append({"type": "level_stats"})
                    post.append({"type": "level_complete"})
                elif opcode.op == GFE.GAME_COMPLETE:
                    is_game_complete = True
                    post.append({"type": "total_stats"})
                elif opcode.op == GFE.SUNSET:
                    target.append({"type": "enable_sunset"})
                elif opcode.op == GFE.REMOVE_WEAPONS:
                    target.append({"type": "remove_weapons"})
                elif opcode.op == GFE.REMOVE_AMMO:
                    target.append({"type": "remove_ammo"})
                elif opcode.op == GFE.NO_FLOOR:
                    target.append({"type": "disable_floor", "height": opcode.arg})
                elif opcode.op == GFE.START_ANIM:
                    target.append({"type": "set_lara_start_anim", "anim": opcode.arg})
                elif opcode.op == GFE.ADD_TO_INV and opcode.arg >= 0:
                    item_idx = opcode.arg - 1000 if opcode.arg >= 1000 else opcode.arg
                    inv_type = "give_item" if opcode.arg >= 1000 else "add_secret_reward"
                    if 0 <= item_idx < len(TR2_INV_KEYS):
                        target.append({"type": inv_type, "object_id": TR2_INV_KEYS[item_idx]})

            sequence = [*pre, {"type": "loop_game"}, *post]
            if not is_game_complete and not any(item.get("type") == "level_complete" for item in post):
                sequence.append({"type": "level_stats"})
                sequence.append({"type": "level_complete"})

            return sequence, music_track

        music_tracks = [-1 for _ in range(num_levels)]
        sequences: list[list[dict[str, Any]] | None] = [None for _ in range(num_levels)]

        for seq in range(num_levels + 1):
            if seq == num_levels and script_offsets[num_levels] >= script_size:
                continue

            ops = read_opcodes(seq)
            sequence, music_track = translate_sequence(ops)
            level_target = next((op.arg for op in ops if op.op == GFE.START_LEVEL), -1)
            idx = level_target if 0 <= level_target < num_levels else seq
            if idx >= num_levels:
                continue
            music_tracks[idx] = music_track
            sequences[idx] = sequence

        cd_offset = title_sound_id - 60 if title_sound_id > 0 else 4
        return ScriptInfo(
            filenames=filenames,
            level_titles=level_titles,
            music_tracks=music_tracks,
            sequences=sequences,
            title_sound_id=title_sound_id,
            cd_offset=cd_offset,
        )
    except (IndexError, struct.error):
        return None


def template_gameflow(game_version: int) -> dict[str, Any]:
    if game_version == 3:
        return {
            "engine": 3,
            "main_menu_picture": "todo.webp",
            "savegame_file_fmt": "save_tr3_custom_%02d.dat",
            "demo_version": False,
            "enable_tr2_item_drops": True,
            "convert_dropped_guns": True,
            "sfx_path": "main.sfx",
            "injections": [
                "font.bin",
                "lara_animations.bin",
                "pda_model.bin",
                "lara_extra.bin",
                "misc_sprites.bin",
                "lara_outfits.bin",
            ],
            "levels": [
                {
                    "path": "PLACEHOLDER",
                    "music_track": -1,
                    "lara_outfit": "tr3_classic",
                    "sequence": [{"type": "loop_game"}, {"type": "level_stats"}],
                }
            ],
        }

    return {
        "engine": 2,
        "main_menu_picture": "title_eu.webp",
        "savegame_file_fmt": "save_tr2_custom_%02d.dat",
        "demo_version": False,
        "enable_tr2_item_drops": True,
        "convert_dropped_guns": True,
        "sfx_path": "main.sfx",
        "injections": [
            "font.bin",
            "lara_animations.bin",
            "lara_guns.bin",
            "pda_model.bin",
            "pickup_aid.bin",
            "winston_model.bin",
            "purple_crystal.bin",
            "lara_extra.bin",
            "lara_rifle_sfx.bin",
            "secret_models_og.bin",
            "misc_sprites.bin",
            "lara_outfits.bin",
        ],
        "levels": [
            {
                "path": "PLACEHOLDER",
                "music_track": -1,
                "lara_outfit": "tr2_classic",
                "sequence": [{"type": "loop_game"}, {"type": "level_stats"}],
            }
        ],
    }


def basename_from_script_path(value: str) -> str:
    return value.replace("\\", "/").split("/")[-1].lower()


def strip_extension(value: str) -> str:
    return re.sub(r"\.[^.]+$", "", value)


def build_gameflow(
    script_info: ScriptInfo,
    game_version: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    gameflow = template_gameflow(game_version)
    template_level = gameflow["levels"][0]
    default_outfit = f"tr{game_version}_classic"

    script_title = basename_from_script_path(script_info.filenames[0])
    gameflow["title"] = {
        "path": script_title,
        "music_track": script_info.title_sound_id,
        "sequence": [{"type": "exit_to_title"}],
    }

    gameflow["levels"] = []
    title_entries: list[dict[str, str]] = []

    for i in range(1, len(script_info.filenames)):
        base = basename_from_script_path(script_info.filenames[i])
        entry = copy.deepcopy(template_level)
        entry["path"] = base
        entry["lara_outfit"] = default_outfit
        entry["music_track"] = script_info.music_tracks[i]
        if script_info.sequences[i]:
            entry["sequence"] = script_info.sequences[i]
        gameflow["levels"].append(entry)

        title = (
            script_info.level_titles[i]
            if i < len(script_info.level_titles) and script_info.level_titles[i]
            else strip_extension(base)
        )
        title_entries.append({"title": title})

    if gameflow["levels"]:
        first_sequence = gameflow["levels"][0].get("sequence", [])
        has_give_item = any(item.get("type") == "give_item" for item in first_sequence)
        has_remove_weapons = any(item.get("type") == "remove_weapons" for item in first_sequence)
        if not has_give_item and not has_remove_weapons:
            defaults = (
                [
                    {"type": "give_item", "object_id": "small_medipack"},
                    {"type": "give_item", "object_id": "large_medipack"},
                    {"type": "give_item", "object_id": "flare", "quantity": 2},
                ]
                if game_version == 3
                else [
                    {"type": "give_item", "object_id": "shotgun"},
                    {"type": "give_item", "object_id": "small_medipack"},
                    {"type": "give_item", "object_id": "large_medipack"},
                    {"type": "give_item", "object_id": "flare", "quantity": 2},
                ]
            )
            loop_idx = next(
                (idx for idx, item in enumerate(first_sequence) if item.get("type") == "loop_game"),
                -1,
            )
            if loop_idx >= 0:
                first_sequence[loop_idx:loop_idx] = defaults
            else:
                first_sequence[:0] = defaults
            gameflow["levels"][0]["sequence"] = first_sequence

    gameflow["engine"] = game_version
    gameflow["extends"] = f"tr{game_version}"

    strings = {"levels": title_entries}
    return gameflow, strings


def dump_json5_compatible(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=4, ensure_ascii=False) + "\n"


def convert_file(args: argparse.Namespace) -> int:
    script_path = Path(args.input)
    out_path = script_path.with_name("gameflow.json5")
    strings_path = script_path.with_name("strings.json5")

    raw_data = script_path.read_bytes()
    script_info = parse_tombpc_dat(raw_data)
    if script_info is None:
        print(f"Error: {script_path} does not look like a valid TR2/TR3 TOMBPC.DAT.", file=sys.stderr)
        return 1

    gameflow, strings = build_gameflow(script_info=script_info, game_version=args.game)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(dump_json5_compatible(gameflow), encoding="utf-8")

    strings_path.parent.mkdir(parents=True, exist_ok=True)
    strings_path.write_text(dump_json5_compatible(strings), encoding="utf-8")

    print(f"Wrote: {out_path}")
    print(f"Wrote: {strings_path}")
    print(f"Game version: TR{args.game}")
    print(f"Converted levels: {len(gameflow['levels'])}")
    print(f"Title: {gameflow['title']['path']} / music_track {gameflow['title']['music_track']}")
    print(f"Original CD offset: {script_info.cd_offset}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert a Tomb Raider 2/3 TOMBPC.DAT to gameflow.json5 and strings.json5."
    )
    parser.add_argument("input", help="Path to the TOMBPC.DAT file to convert.")
    parser.add_argument(
        "-game",
        type=int,
        choices=(2, 3),
        required=True,
        help="Target game version: 2 for TR2, 3 for TR3.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return convert_file(parse_args(argv or sys.argv[1:]))


if __name__ == "__main__":
    raise SystemExit(main())

