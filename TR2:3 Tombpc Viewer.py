#!/usr/bin/env python3
"""
Tomb Raider 2/3 TOMBPC.DAT Script Parser
Reads and analyzes TOMBPC.DAT script files from TR2 and TR3

Based on TRosettaStone 3.0 documentation
"""

import struct
import os
import sys
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass

@dataclass
class ScriptInfo:
    """Information extracted from script file"""
    file_size: int
    strings: List[str]
    level_files: List[str]
    bitmap_files: List[str]
    key_items: List[str]
    game_text: List[str]

class TombPCDATParser:
    """Robust parser for TOMBPC.DAT files from TR2/3"""
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        
    def load_file(self) -> bool:
        """Load DAT file into memory"""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            print(f"File loaded: {len(self.data)} bytes")
            return True
        except Exception as e:
            print(f"Error reading file: {e}")
            return False
    
    def hex_dump(self, start: int = 0, length: int = 128) -> None:
        """Show hexadecimal dump of first bytes for debugging"""
        print(f"\nHEX DUMP (offset {start}, {length} bytes):")
        print("-" * 60)
        
        for i in range(start, min(start + length, len(self.data)), 16):
            hex_part = " ".join(f"{b:02X}" for b in self.data[i:i+16])
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in self.data[i:i+16])
            print(f"{i:08X}: {hex_part:<48} {ascii_part}")
    
    def find_best_xor_key(self, data: bytes) -> int:
        """Find the best XOR key by testing against common English words"""
        english_words = [
            b'Pistols', b'Shotgun', b'Uzi', b'Magnums', b'Lara', b'Home',
            b'Jungle', b'Temple', b'Ruins', b'Level', b'Large', b'Small',
            b'Access', b'Secret', b'Treasure', b'Medipack', b'Key'
        ]
        
        best_key = 0
        best_score = 0
        
        for key in range(256):
            decrypted = bytes(b ^ key for b in data)
            score = 0
            
            # Count how many English words we find
            for word in english_words:
                if word in decrypted or word.lower() in decrypted:
                    score += len(word)
            
            # Count valid ASCII characters
            ascii_count = sum(1 for b in decrypted if 32 <= b <= 126)
            score += ascii_count * 0.1
            
            if score > best_score:
                best_score = score
                best_key = key
        
        return best_key
    
    def analyze_tr_structure(self) -> Dict[str, Any]:
        """Analyze TR2/3 structure with optimized XOR decoding"""
        result = {
            'version': 2,
            'description': '',
            'strings': [],
            'level_info': [],
            'game_strings': []
        }
        
        if len(self.data) < 100:
            return result
        
        # Read header
        version = struct.unpack('<I', self.data[0:4])[0]
        result['version'] = version
        
        # Description starts at offset 4
        desc_start = 4
        desc_end = desc_start
        while desc_end < len(self.data) and self.data[desc_end] != 0:
            desc_end += 1
        
        if desc_end < len(self.data):
            result['description'] = self.data[desc_start:desc_end].decode('ascii', errors='ignore')
        
        # Find start of data
        search_start = desc_end + 1
        while search_start < len(self.data) and self.data[search_start] == 0:
            search_start += 1
        
        print(f"\nStarting string search at offset: 0x{search_start:08X}")
        
        # First pass: find most likely XOR key by analyzing a large block
        test_block_size = min(2048, len(self.data) - search_start)
        if test_block_size > 100:
            test_data = self.data[search_start:search_start + test_block_size]
            best_key = self.find_best_xor_key(test_data)
            print(f"Best XOR key detected: 0x{best_key:02X} ({best_key})")
        else:
            best_key = 0x20  # Default
        
        # Second pass: decode all strings with the found key
        strings_found = []
        i = search_start
        decoded_count = 0
        
        while i < len(self.data):
            if self.data[i] != 0:
                start = i
                while i < len(self.data) and self.data[i] != 0:
                    i += 1
                
                if i < len(self.data) and (i - start) > 1:
                    string_data = self.data[start:i]
                    
                    # Try the best key first
                    try:
                        decrypted = bytes(b ^ best_key for b in string_data)
                        decoded = decrypted.decode('latin1', errors='ignore')
                        if len(decoded.strip()) > 1:
                            ascii_count = sum(1 for c in decoded if 32 <= ord(c) <= 126)
                            if ascii_count > len(decoded) * 0.7:  # 70% ASCII
                                clean_string = decoded.strip()
                                if clean_string and clean_string not in strings_found:
                                    strings_found.append(clean_string)
                                    decoded_count += 1
                                    if decoded_count <= 15:  # Show first 15 for progress
                                        print(f"  [{decoded_count:2d}] {clean_string[:50]}{'...' if len(clean_string) > 50 else ''}")
                    except:
                        pass
                    
                    # Also try without XOR for already plain text
                    try:
                        decoded = string_data.decode('latin1', errors='ignore')
                        if len(decoded.strip()) > 1:
                            ascii_count = sum(1 for c in decoded if 32 <= ord(c) <= 126)
                            if ascii_count > len(decoded) * 0.8:
                                clean_string = decoded.strip()
                                if clean_string and clean_string not in strings_found:
                                    strings_found.append(clean_string)
                    except:
                        pass
            i += 1
        
        # Remove duplicates and sort
        result['strings'] = sorted(list(set(strings_found)))
        print(f"\nTotal unique decoded strings: {len(result['strings'])}")
        
        return result
    
    def categorize_strings(self, all_strings: List[str]) -> Dict[str, List[str]]:
        """Categorize the found strings by type"""
        categories = {
            'level_files': [],
            'bitmap_files': [],
            'key_items': [],
            'weapons': [],
            'items': [],
            'game_text': [],
            'menu_text': [],
            'other': []
        }
        
        for string in all_strings:
            string_upper = string.upper()
            string_lower = string.lower()
            
            # Level files
            if '.tr2' in string_lower or '.phd' in string_lower or 'data\\' in string_lower:
                categories['level_files'].append(string)
            # Bitmap files
            elif '.bmp' in string_lower or 'pix\\' in string_lower:
                categories['bitmap_files'].append(string)
            # Key items (usually contain "key" or similar)
            elif any(word in string_lower for word in ['key', 'chiave', 'access', 'card', 'code']):
                categories['key_items'].append(string)
            # Weapons
            elif any(word in string_lower for word in ['pistol', 'shotgun', 'uzi', 'magnum', 'grenade', 'harpoon', 'mp5']):
                categories['weapons'].append(string)
            # Items
            elif any(word in string_lower for word in ['medipack', 'medkit', 'ammo', 'crystal', 'stone', 'gem']):
                categories['items'].append(string)
            # Menu text (common UI words)
            elif any(word in string_lower for word in ['game', 'load', 'save', 'options', 'inventory', 'level', 'demo']):
                categories['menu_text'].append(string)
            # Long text (descriptions, etc.)
            elif len(string) > 25:
                categories['game_text'].append(string)
            else:
                categories['other'].append(string)
        
        return categories
    
    def parse(self) -> ScriptInfo:
        """Complete file parsing with language-agnostic approach"""
        if not self.load_file():
            return ScriptInfo(0, [], [], [], [], [])
        
        print(f"\nAnalyzing file: {os.path.basename(self.filepath)}")
        print(f"Size: {len(self.data)} bytes")
        
        # Show hex dump for debugging
        self.hex_dump(0, 128)
        
        # Detect if it's TR2/3 and use specialized parser
        if len(self.data) >= 4:
            version_bytes = self.data[0:4]
            if version_bytes in [b'\x02\x00\x00\x00', b'\x03\x00\x00\x00']:
                version_num = struct.unpack('<I', version_bytes)[0]
                print(f"\n--- DETECTED TR{version_num} - Using specialized parser ---")
                tr_result = self.analyze_tr_structure()
                
                # Categorize the strings
                categories = self.categorize_strings(tr_result['strings'])
                
                return ScriptInfo(
                    file_size=len(self.data),
                    strings=tr_result['strings'],
                    level_files=categories['level_files'],
                    bitmap_files=categories['bitmap_files'],
                    key_items=categories['key_items'],
                    game_text=categories['game_text'] + categories['menu_text']
                )
        
        print("\n--- Unknown format - Using generic parser ---")
        return ScriptInfo(len(self.data), [], [], [], [], [])
    
    def print_results(self, info: ScriptInfo) -> None:
        """Print results in a clean, readable format"""
        print("\n" + "=" * 80)
        print("TOMB RAIDER SCRIPT ANALYSIS - RESULTS")
        print("=" * 80)
        
        print(f"\nFILE INFORMATION:")
        print(f"  File: {os.path.basename(self.filepath)}")
        print(f"  Size: {info.file_size:,} bytes")
        print(f"  Total strings found: {len(info.strings)}")
        
        # Level files
        if info.level_files:
            print(f"\nLEVEL FILES ({len(info.level_files)}):")
            for i, filename in enumerate(sorted(info.level_files), 1):
                print(f"  {i:2d}. {filename}")
        
        # Bitmap files
        if info.bitmap_files:
            print(f"\nBITMAP FILES ({len(info.bitmap_files)}):")
            for i, filename in enumerate(sorted(info.bitmap_files), 1):
                print(f"  {i:2d}. {filename}")
        
        # Key items
        if info.key_items:
            print(f"\nKEY ITEMS ({len(info.key_items)}):")
            for i, item in enumerate(sorted(info.key_items), 1):
                print(f"  {i:2d}. {item}")
        
        # Game text (limit to first 20 for readability)
        if info.game_text:
            print(f"\nGAME TEXT ({len(info.game_text)} total, showing first 20):")
            for i, text in enumerate(sorted(info.game_text)[:20], 1):
                # Truncate very long strings
                display_text = text[:70] + "..." if len(text) > 70 else text
                print(f"  {i:2d}. {display_text}")
            
            if len(info.game_text) > 20:
                print(f"       ... and {len(info.game_text) - 20} more entries")
        
        # All strings section (organized)
        print(f"\nALL STRINGS ALPHABETICALLY ({len(info.strings)}):")
        print("-" * 80)
        
        for i, string in enumerate(sorted(info.strings), 1):
            # Format: number, length, content
            display_text = string[:65] + "..." if len(string) > 65 else string
            print(f"{i:3d}. ({len(string):2d} chars) {display_text}")
        
        print("\n" + "=" * 80)

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python tr_dat_parser.py <path_to_TOMBPC.DAT>")
        print("Example: python tr_dat_parser.py TOMBPC.DAT")
        return
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"File {filepath} not found")
        return
    
    parser = TombPCDATParser(filepath)
    results = parser.parse()
    parser.print_results(results)

if __name__ == "__main__":
    main()
