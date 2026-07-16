#!/usr/bin/env python3
"""
analyze.py — PS2/Xbox 360 Unified Analysis
=============================================
Entry point that detects platform and runs appropriate analysis.

Usage:
  PYTHONPATH="/path/to/IDA/idalib/python:$PYTHONPATH" \
    python3 analyze.py game.xex|game.elf /output/dir

PS2 flow:
  Phase 1: IDA analysis → DB + Knowledge Base + JSON exports
  Phase 2: PS2Recomp export → CSV + TOML

Xbox 360 flow:
  IDA analysis → DB + Knowledge Base + JSON exports
"""
import idapro
import os
import sys
import json
import sqlite3
import hashlib
import struct
import re
import subprocess
import tempfile
from pathlib import Path
from collections import Counter, defaultdict

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__))) if '__file__' in dir() else Path.cwd()
XEXTOOL = "/mnt/Datos/Herramientas/XexTool_v6/xextool.exe"

# ═══════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ═══════════════════════════════════════════════════════════════

def detect_platform(file_path):
    """Detect if binary is PS2 (ELF/MIPS) or Xbox 360 (XEX/PE/PPC)."""
    with open(file_path, 'rb') as f:
        magic = f.read(4)

    if magic == b'\x7fELF':
        # Check ELF header for architecture
        with open(file_path, 'rb') as f:
            f.seek(18)  # e_machine offset
            machine = struct.unpack('<H', f.read(2))[0]
            if machine == 0x0008:  # EM_MIPS
                return "ps2"
    elif magic == b'XEX2':
        return "xbox360"
    elif magic[:2] == b'MZ':  # PE file (extracted from XEX)
        return "xbox360"
    elif file_path.endswith('.xex') or file_path.endswith('.XEX'):
        return "xbox360"
    elif file_path.endswith('.elf') or file_path.endswith('.ELF'):
        return "ps2"
    elif file_path.endswith('.bin') or file_path.endswith('.exe'):
        # Could be extracted PE - check for PPC code patterns
        with open(file_path, 'rb') as f:
            header = f.read(256)
        if b'MIPS' in header:
            return "ps2"
        return "xbox360"  # Default to Xbox 360 for .bin/.exe

    # Try to detect from file content
    with open(file_path, 'rb') as f:
        header = f.read(256)
    if b'MIPS' in header or b'R5900' in header:
        return "ps2"
    if b'PowerPC' in header or b'XEX' in header:
        return "xbox360"

    return "unknown"

# ═══════════════════════════════════════════════════════════════
# XEX → PE EXTRACTION (Xbox 360)
# ═══════════════════════════════════════════════════════════════

def extract_pe_from_xex(xex_path, output_dir):
    """Extract base PE from XEX using xextool. Returns PE path or None."""
    pe_path = os.path.join(output_dir, "basefile.exe")
    if not os.path.exists(XEXTOOL):
        log(f"  WARNING: xextool not found at {XEXTOOL}, trying to load XEX directly")
        return None
    cmd = ['wine', XEXTOOL, '-b', pe_path, xex_path]
    log(f"  Extracting PE from XEX via xextool...")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if os.path.exists(pe_path) and os.path.getsize(pe_path) > 0:
            log(f"  PE extracted: {os.path.getsize(pe_path)} bytes")
            return pe_path
        else:
            log(f"  WARNING: xextool extraction failed, trying to load XEX directly")
            return None
    except Exception as e:
        log(f"  WARNING: xextool error: {e}, trying to load XEX directly")
        return None

# ═══════════════════════════════════════════════════════════════
# SDK IMPORTS (Xbox 360)
# ═══════════════════════════════════════════════════════════════

def extract_imports(pe_path=None):
    """Extract PE import table entries. Tries IDA API first, falls back to manual PE parsing."""
    import ida_nalt

    # Try IDA API first
    imports = []
    num_modules = ida_nalt.get_import_module_qty()
    if num_modules > 0:
        for i in range(num_modules):
            mod_name = ida_nalt.get_import_module_name(i)
            if not mod_name:
                mod_name = f"module_{i}"
            def callback(ea, ord_val, name, param):
                func_name = name if name else f"ord_{ord_val}" if ord_val else f"unknown_{ea:08X}"
                imports.append({"address": ea, "module": mod_name, "name": func_name, "ordinal": ord_val or 0})
                return True
            ida_nalt.enum_import_names(i, callback)
        return imports

    # Fallback: manual PE parsing with SDK ordinal matching (Xbox 360)
    if pe_path and os.path.exists(pe_path):
        imports = _parse_xbox360_imports(pe_path)
    return imports


def _parse_xbox360_imports(pe_path):
    """Parse Xbox 360 PE imports using big-endian IAT ordinals + x360_imports.idc database."""
    # Load SDK ordinal database from x360_imports.idc
    sdk_db = _load_xbox360_sdk_db()

    imports = []
    with open(pe_path, 'rb') as f:
        # Read PE header to find IAT location
        f.seek(0x3C)
        pe_offset = struct.unpack('<I', f.read(4))[0]
        f.seek(pe_offset + 4)
        num_sections = struct.unpack('<H', f.read(2))[0]
        opt_start = pe_offset + 24
        f.seek(opt_start)
        opt_magic = struct.unpack('<H', f.read(2))[0]
        is_pe32plus = (opt_magic == 0x20B)
        opt_size = 240 if is_pe32plus else 224

        f.seek(opt_start + 16)
        image_base = struct.unpack('<Q' if is_pe32plus else '<I', f.read(8 if is_pe32plus else 4))[0]

        # Read section headers
        f.seek(opt_start + opt_size)
        sections = []
        for _ in range(num_sections):
            raw = f.read(40)
            name = raw[0:8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', raw[8:12])[0]
            vaddr = struct.unpack('<I', raw[12:16])[0]
            raw_size = struct.unpack('<I', raw[16:20])[0]
            raw_ptr = struct.unpack('<I', raw[20:24])[0]
            sections.append((name, vaddr, vsize, raw_ptr, raw_size))

        # Get IAT from data directory (index 12)
        dd_offset = opt_start + (112 if is_pe32plus else 96)
        f.seek(dd_offset + 12 * 8)  # skip to IAT entry (12th * 8 bytes each)
        iat_rva = struct.unpack('<I', f.read(4))[0]
        iat_size = struct.unpack('<I', f.read(4))[0]

        if iat_rva == 0 or iat_size == 0:
            return imports

        # Convert RVA to file offset
        def rva_to_offset(rva):
            for s_name, vaddr, vsize, raw_ptr, raw_size in sections:
                if vaddr <= rva < vaddr + vsize:
                    return raw_ptr + (rva - vaddr)
            return None

        iat_offset = rva_to_offset(iat_rva)
        if iat_offset is None:
            return imports

        # Read IAT entries (big-endian for Xbox 360 PPC)
        f.seek(iat_offset)
        iat_data = f.read(iat_size)
        iat_pos = 0

        for i in range(0, len(iat_data), 4):
            if i + 4 > len(iat_data):
                break
            ordinal = struct.unpack('>I', iat_data[i:i+4])[0]
            if ordinal == 0:
                break

            iat_addr = image_base + iat_rva + i
            if ordinal in sdk_db:
                lib, name = sdk_db[ordinal]
                imports.append({
                    "address": iat_addr,
                    "module": lib,
                    "name": name,
                    "ordinal": ordinal
                })
            else:
                imports.append({
                    "address": iat_addr,
                    "module": "unknown",
                    "name": f"ord_{ordinal}",
                    "ordinal": ordinal
                })

    return imports


def _load_xbox360_sdk_db():
    """Load Xbox 360 SDK function database from x360_imports.idc."""
    import re
    idc_path = "/mnt/Datos/Herramientas/XexTool_v6/x360_imports.idc"
    sdk_db = {}
    if not os.path.exists(idc_path):
        return sdk_db

    current_lib = None
    with open(idc_path) as f:
        for line in f:
            m = re.match(r'static\s+(\w+)NameGen', line)
            if m:
                current_lib = m.group(1)
            m = re.match(r'.*id == 0x([0-9A-Fa-f]+)\)\s*funcName = "([^"]+)"', line)
            if m and current_lib:
                ordinal = int(m.group(1), 16)
                name = m.group(2)
                # Normalize library names
                lib_map = {"xam": "xam.xex", "xboxkrnl": "xboxkrnl.exe",
                           "xapi": "xapi.exe", "xbdm": "xbdm.xex",
                           "connectx": "connectx.dll", "syscall": "syscall.exe",
                           "createprofile": "createprofile.dll", "vk": "vk.dll"}
                lib = lib_map.get(current_lib, current_lib)
                sdk_db[ordinal] = (lib, name)
    return sdk_db

# ═══════════════════════════════════════════════════════════════
# SWITCH TABLES (PPC jump tables for ReXGlue)
# ═══════════════════════════════════════════════════════════════

def detect_switch_tables(text_start, text_end):
    """Detect PPC switch/jump tables in .rdata/.data sections.

    Scans .text for bctr instructions, then looks backward to find
    the mtctr that loads a table pointer from .rdata/.data.
    Each table is an array of code pointers used for indirect branch.
    """
    import ida_bytes, ida_segment, idautils

    tables = []
    seen = set()

    # Find .rdata segment only (vtables/switch tables live here, not in .data)
    # Limit scan to first 2MB for performance
    data_segs = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        name = ida_segment.get_segm_name(seg)
        if name == '.rdata':
            end = min(seg.end_ea, seg.start_ea + 2 * 1024 * 1024)  # cap at 2MB
            data_segs.append((seg.start_ea, end))
            break

    # Scan .rdata for contiguous arrays of code pointers (switch tables / vtables)
    for ds_start, ds_end in data_segs:
        ds_ea = ds_start
        while ds_ea < ds_end - 4:
            if not ida_bytes.is_mapped(ds_ea):
                ds_ea = ida_bytes.next_head(ds_ea, ds_end)
                continue
            ptr = ida_bytes.get_dword(ds_ea)
            if text_start <= ptr < text_end:
                # Candidate start - count contiguous code pointers
                entries = []
                scan_ptr = ds_ea
                while scan_ptr < ds_end:
                    if not ida_bytes.is_mapped(scan_ptr):
                        break
                    val = ida_bytes.get_dword(scan_ptr)
                    if text_start <= val < text_end:
                        entries.append(val)
                        scan_ptr += 4
                    else:
                        break
                if len(entries) >= 3 and ds_ea not in seen:
                    tables.append({
                        "address": ds_ea,
                        "register": 9,  # CTR is default
                        "num_labels": len(entries),
                        "labels": entries
                    })
                    seen.add(ds_ea)
                    ds_ea = scan_ptr  # skip past this table
                else:
                    ds_ea += 4
            else:
                ds_ea += 4

    # Deduplicate and limit
    unique = []
    seen_addrs = set()
    for t in tables:
        if t["address"] not in seen_addrs:
            seen_addrs.add(t["address"])
            unique.append(t)
    return unique[:2000]  # cap at 2000 tables

# ═══════════════════════════════════════════════════════════════
# XEX HEADER PARSING (Xbox 360 metadata)
# ═══════════════════════════════════════════════════════════════

def parse_xex_header(xex_path):
    """Extract metadata from XEX2 header: Title ID, etc."""
    info = {}
    try:
        with open(xex_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'XEX2':
                return info
            # XEX2 header is big-endian
            default_xex_size = struct.unpack('>I', f.read(4))[0]
            xex_headers_size = struct.unpack('>I', f.read(4))[0]
            security_info_offset = struct.unpack('>I', f.read(4))[0]
            # Seek to security info to get Title ID
            f.seek(security_info_offset)
            header_hash = f.read(32)
            # Title ID is at offset 0xA0 from security info start (varies)
            # Try to find it by scanning for patterns
            f.seek(0)
            data = f.read(min(0x200, os.path.getsize(xex_path)))
            # Title ID is typically a 4-byte value after certain headers
            # For now, extract from the PE we already have
    except Exception:
        pass
    return info


# ═══════════════════════════════════════════════════════════════
# CHECKS & VALIDATIONS (Xbox 360 error patterns)
# ═══════════════════════════════════════════════════════════════

CHECK_CATEGORIES = {
    "Error_General": re.compile(r"(error|fail|assert|panic|abort)", re.IGNORECASE),
    "Version_Check": re.compile(r"(version|title.?update|TU\d|system.?version)", re.IGNORECASE),
    "File_Error": re.compile(r"(file|open|read|write|stfs|io.?error|disk)", re.IGNORECASE),
    "Assert_Fatal": re.compile(r"(fatal|abort|crash|deadlock|unreachable)", re.IGNORECASE),
    "GPU_Render": re.compile(r"(D3D|render|shader|texture|gpu|vertex|pixel|draw)", re.IGNORECASE),
    "Memory_Error": re.compile(r"(alloc|free|heap|overflow|corrupt|oom|leak)", re.IGNORECASE),
    "Kinect_Validation": re.compile(r"(nui|kinect|skeleton|body|tracking|gesture)", re.IGNORECASE),
    "Audio_System": re.compile(r"(audio|xma|sound|voice|music|sfx|adpcm)", re.IGNORECASE),
    "Save_Data": re.compile(r"(save|profile|storage|mount|unmount|container)", re.IGNORECASE),
    "Avatar_System": re.compile(r"(avatar|manifest|asset|animation)", re.IGNORECASE),
    "Network_Error": re.compile(r"(network|socket|connect|timeout|disconnect|packet)", re.IGNORECASE),
    "Online_Auth": re.compile(r"(auth|login|credential|token|session|xuid)", re.IGNORECASE),
    "DRM_Security": re.compile(r"(drm|security|encrypt|license|protect|console)", re.IGNORECASE),
    "Debug_Output": re.compile(r"(debug|trace|log|printf|output|print)", re.IGNORECASE),
    "Region_Lock": re.compile(r"(region|locale|language|territory|country)", re.IGNORECASE),
    "Game_Logic": re.compile(r"(game|level|stage|mission|objective|player)", re.IGNORECASE),
}

def detect_checks(func_list, decompiled, strings):
    """Classify functions that contain error/validation patterns."""
    checks = []
    # Build string text set for quick lookup
    string_texts = set()
    for s in strings:
        string_texts.add(s["text"].lower())

    for func in func_list:
        ea = func["address"]
        code = decompiled.get(ea, "")
        code_lower = code.lower()
        matched = False
        for cat, pattern in CHECK_CATEGORIES.items():
            if pattern.search(code_lower):
                checks.append({"address": ea, "category": cat, "description": func["name"]})
                matched = True
                break
        # Also check if function references error strings
        if not matched:
            for s_text in string_texts:
                if any(kw in s_text for kw in ["error", "fail", "assert", "panic"]):
                    # Check if this function has xrefs to that string
                    # (simplified: just check function name/size patterns)
                    pass
    return checks


# ═══════════════════════════════════════════════════════════════
# SUBSYSTEM CLASSIFICATION (Xbox 360)
# ═══════════════════════════════════════════════════════════════

SUBSYSTEM_PATTERNS = {
    "NETWORKING": re.compile(r"(XNet|NetDll|WSA|socket|connect|send|recv|XOnline)", re.IGNORECASE),
    "GRAPHICS": re.compile(r"(D3D|Xe|Rw|Hedgehog|render|shader|texture|vertex|pixel|draw|material|mesh)", re.IGNORECASE),
    "MEMORY": re.compile(r"(ExAllocate|XMem|alloc|free|heap|memcpy|memset|RtlAllocate)", re.IGNORECASE),
    "KINECT": re.compile(r"(Nui|NUI_|skeleton|body|tracking|gesture|kinect)", re.IGNORECASE),
    "AUDIO": re.compile(r"(XMA|XAudio|sound|audio|voice|music|sfx|adpcm)", re.IGNORECASE),
}

def classify_subsystems(func_list, decompiled):
    """Classify functions by subsystem based on pseudocode patterns."""
    results = []
    for func in func_list:
        ea = func["address"]
        code = decompiled.get(ea, "")
        subsystem = "UNCATEGORIZED"
        for sub, pattern in SUBSYSTEM_PATTERNS.items():
            if pattern.search(code):
                subsystem = sub
                break
        results.append({
            "subsystem": subsystem,
            "address": ea,
            "name": func["name"],
            "size": func["size"]
        })
    return results


# ═══════════════════════════════════════════════════════════════
# STRING CATEGORIZATION
# ═══════════════════════════════════════════════════════════════

STRING_PATTERNS = {
    "PS2_SDK": re.compile(r"^(sce|Sif|Gs|Pad|Mc|Cd|Dma|Vif|Gif|Mpeg|Spu|Iop|Vpu)", re.IGNORECASE),
    "XBOX_SDK": re.compile(r"^(XNet|Xam|XAudio|XInput|XContent|XLive|XUI|XShow)", re.IGNORECASE),
    "CDVD": re.compile(r"(disc|cdrom|dvd|sector|toc|track|disc.?error)", re.IGNORECASE),
    "ERROR": re.compile(r"(error|fail|assert|panic|abort|exception|crash)", re.IGNORECASE),
    "DEBUG": re.compile(r"(debug|trace|log|printf|print|dump|hex)", re.IGNORECASE),
    "AUDIO": re.compile(r"(audio|sound|sfx|music|voice|spu|adpcm|vag|xma)", re.IGNORECASE),
    "FILE_PATH": re.compile(r"^(/[a-z]|cdrom|mc[01]:|host0:|mass:|game:|device:)", re.IGNORECASE),
}

def categorize_string(text):
    for cat, pattern in STRING_PATTERNS.items():
        if pattern and pattern.search(text):
            return cat
    return "OTHER"

# ═══════════════════════════════════════════════════════════════
# SCE SHA-1 MATCHING (PS2)
# ═══════════════════════════════════════════════════════════════

PS2RECOMP_HEADER = "/mnt/Datos/Proyectos/PS2Recomp/ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h"
DEFAULT_SCE_DB = SCRIPT_DIR / "sce_symbols.json"

def extract_sce_database():
    if not os.path.exists(PS2RECOMP_HEADER):
        return {}
    with open(PS2RECOMP_HEADER, 'r') as f:
        content = f.read()
    chunks = re.findall(r'R"PS2SDB\((.*?)\)PS2SDB"', content, re.DOTALL)
    json_str = ''.join(chunks)
    tree_marker = json_str.find('{"skip"')
    data = json.loads(json_str[:tree_marker] if tree_marker > 0 else json_str)
    with open(DEFAULT_SCE_DB, 'w') as f:
        json.dump(data, f)
    return data

def load_sce_database(symbols_path=None):
    if symbols_path is None:
        symbols_path = str(DEFAULT_SCE_DB)
    if not os.path.exists(symbols_path):
        data = extract_sce_database()
        if not data: return {}
    else:
        with open(symbols_path, 'r') as f:
            data = json.load(f)
    h = {}
    for lib, funcs in data.items():
        for name, hashes in funcs.items():
            for sha1, variants in hashes.items():
                for vh, info in variants.items():
                    if info.get('type') != 'FUNCTION': continue
                    h.setdefault(sha1, []).append({'library': lib, 'name': name, 'size': info.get('size', 0), 'variant': vh})
    return h

def match_sce(func_ea, hl):
    import ida_funcs, ida_bytes
    f = ida_funcs.get_func(func_ea)
    if not f: return None
    sz = f.end_ea - f.start_ea
    if sz < 8 or sz > 2048: return None
    d = ida_bytes.get_bytes(f.start_ea, sz)
    if not d: return None
    h = hashlib.sha1(d).hexdigest()
    if h in hl:
        for c in hl[h]:
            if abs(c['size']-sz)<=16: return c
    m = bytearray(d)
    for i in range(0,len(m)-3,4):
        w=struct.unpack('<I',m[i:i+4])[0]
        if (w>>26)==0x03: struct.pack_into('<I',m,i,w&0xFC000000)
        elif (w>>26)==0x0F: struct.pack_into('<I',m,i,w&0xFFFF0000)
    h=hashlib.sha1(bytes(m)).hexdigest()
    if h in hl:
        for c in hl[h]:
            if abs(c['size']-sz)<=16: return c
    return None

# ═══════════════════════════════════════════════════════════════
# PS2RECOMP EXPORT (Phase 2 for PS2)
# ═══════════════════════════════════════════════════════════════

PS2_SYSCALL = {
    1:"ResetEE",10:"EnableIntc",11:"DisableIntc",12:"EnableDmac",13:"DisableDmac",
    20:"CreateThread",22:"StartThread",24:"ExitThread",41:"GetThreadId",
    44:"SleepThread",45:"WakeupThread",50:"CreateSema",52:"SignalSema",
    54:"WaitSema",64:"CreateEventFlag",66:"SetEventFlag",68:"ClearEventFlag",
    76:"EnableCache",77:"DisableCache",78:"FlushCache",82:"InitTLB",
    130:"SifInitRpc",131:"SifBindRpc",132:"SifCallRpc",140:"SifInitIopHeap",
    141:"SifAllocIopHeap",200:"PadInit",214:"PadRead",220:"McInit",227:"McSync",
    250:"GsPutIMR",260:"GsSwapDBuff",261:"GsSyncV",265:"GsResetGraph",
    320:"SifAddCmdHandler",322:"SifSendCmd",330:"SifSetDma",
    -26:"iTerminateThread",-43:"iSignalSema",-53:"iSetEventFlag",
    -70:"iEnableIntc",-71:"iDisableIntc",-79:"iFlushCache",
}

MMIO_RANGES = [(0x10000000,0x1000FFFF),(0x10004000,0x10004FFF),(0x11800000,0x1180FFFF)]

def detect_syscall(func_ea):
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj: return None
    ea = fobj.start_ea
    while ea < fobj.end_ea:
        if not ida_bytes.is_mapped(ea):
            ea = ida_bytes.next_head(ea, fobj.end_ea); continue
        w = ida_bytes.get_dword(ea)
        if (w >> 26) == 0x0F and ((w >> 16) & 0x1F) == 2:
            li = (w & 0xFFFF) << 16
            nxt = ea + 4
            if nxt < fobj.end_ea and ida_bytes.is_mapped(nxt):
                nw = ida_bytes.get_dword(nxt)
                if (nw >> 26) == 0x0D and ((nw >> 21) & 0x1F) == 2 and ((nw >> 16) & 0x1F) == 2:
                    val = li | (nw & 0xFFFF)
                    for off in [8, 12, 16]:
                        ce = ea + off
                        if ce < fobj.end_ea and ida_bytes.is_mapped(ce):
                            if ida_bytes.get_dword(ce) == 0x0000000C:
                                if val >= 0x80000000: val -= 0x100000000
                                return val
        ea = ida_bytes.next_head(ea, fobj.end_ea)
    return None

def detect_mmio(func_ea):
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj: return False
    ea = fobj.start_ea; lui_regs = {}
    while ea < fobj.end_ea:
        if not ida_bytes.is_mapped(ea):
            ea = ida_bytes.next_head(ea, fobj.end_ea); continue
        w = ida_bytes.get_dword(ea)
        if (w >> 26) == 0x0F: lui_regs[(w >> 16) & 0x1F] = (w & 0xFFFF) << 16
        if (w >> 26) in (0x23, 0x2B):
            rs = (w >> 21) & 0x1F
            if rs in lui_regs:
                off = w & 0xFFFF
                if off & 0x8000: off -= 0x10000
                addr = lui_regs[rs] + off
                for s, e in MMIO_RANGES:
                    if s <= addr <= e: return True
        ea = ida_bytes.next_head(ea, fobj.end_ea)
    return False

def detect_thunk(func_ea):
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj: return False
    if fobj.end_ea - fobj.start_ea > 16: return False
    ea = fobj.start_ea
    while ea < fobj.end_ea:
        if not ida_bytes.is_mapped(ea): ea += 4; continue
        w = ida_bytes.get_dword(ea)
        if w == 0x03E00008 or (w >> 26) == 0x02: return True
        ea += 4
    return False

def ps2recomp_export(func_list, sce_matches, elf_name, output_dir):
    """Phase 2: Generate CSV + TOML for PS2Recomp."""
    records = []
    classifications = {}
    for func in func_list:
        ea = func["address"]
        sce = sce_matches.get(ea)
        if sce:
            name = sce['name']
            cat = "stub"
        elif detect_thunk(ea):
            name = func["name"]
            cat = "stub"
        elif detect_syscall(ea) is not None:
            sc = detect_syscall(ea)
            name = PS2_SYSCALL.get(sc, f"syscall_{sc}")
            cat = "stub"
        elif detect_mmio(ea):
            name = func["name"]
            cat = "untracked_stub"
        else:
            name = func["name"]
            cat = "game"
        records.append({"address": ea, "name": name, "start": func["start"], "end": func["end"], "cat": cat})

    records.sort(key=lambda r: r["start"])

    # CSV
    base = os.path.splitext(elf_name)[0]
    csv_path = os.path.join(output_dir, "functions.csv")
    with open(csv_path, "w") as f:
        f.write("Name,Start,End,Size\n")
        for r in records:
            sz = r["end"] - r["start"]
            f.write(f"{r['name']},0x{r['start']:08X},0x{r['end']:08X},{sz}\n")

    # TOML
    stubs = [f"{r['name']}@0x{r['address']:08X}" for r in records if r["cat"] == "stub"]
    untracked = [f"{r['name']}@0x{r['address']:08X}" for r in records if r["cat"] == "untracked_stub"]

    toml_path = os.path.join(output_dir, "config.toml")
    with open(toml_path, "w") as f:
        f.write(f"# PS2Recomp - {elf_name}\n# Generated by IDA Pro\n\n")
        f.write("[general]\n")
        f.write(f'input = "{elf_name}"\n')
        f.write('ghidra_output = ""\n')
        f.write('output = "./output/"\n')
        f.write("single_file_output = false\n")
        f.write("patch_syscalls = false\n")
        f.write("patch_cop0 = true\n")
        f.write("patch_cache = true\n\n")
        f.write("stubs = [\n")
        for s in sorted(stubs): f.write(f'  "{s}",\n')
        f.write("]\n\n")
        f.write("untracked_stubs = [\n")
        for u in sorted(untracked): f.write(f'  "{u}",\n')
        f.write("]\n\n")
        f.write("skip = []\n")

    return {"csv": csv_path, "toml": toml_path, "stubs": len(stubs), "untracked": len(untracked)}

# ═══════════════════════════════════════════════════════════════
# FULL ANALYSIS (Phase 1 / Xbox 360 only)
# ═══════════════════════════════════════════════════════════════

def full_analysis(elf_path, output_dir, sce_db=None, platform=None):
    """Phase 1: IDA analysis → DB + Knowledge Base + JSON exports."""
    import idaapi, ida_funcs, ida_hexrays, ida_bytes
    import idautils, ida_segment, ida_nalt, ida_entry

    os.makedirs(output_dir, exist_ok=True)
    elf_name = os.path.basename(elf_path)
    base = os.path.splitext(elf_name)[0]
    db_path = os.path.join(output_dir, f"{base}.db")
    kb_path = os.path.join(output_dir, f"{base.upper()}_KNOWLEDGE_BASE.md")
    export_dir = os.path.join(output_dir, "export")
    os.makedirs(export_dir, exist_ok=True)

    log(f"[Phase 1] Opening {elf_name}...")

    text_start = None
    text_end = None
    imports = []
    switch_tables = []

    if platform == "xbox360":
        import struct

        # ═══════════════════════════════════════════════════════════
        # Xbox 360: Extract PE from XEX → load in IDA → PPC → scan
        # XEX2 files must be extracted to PE first via xextool.
        # The PE is loaded into IDA, processor changed to PPC, and
        # function prologues scanned to create function entries.
        # ═══════════════════════════════════════════════════════════

        log("  Xbox 360 mode: XEX→PE extraction + PPC prologue scanning")

        # Check if input is XEX (needs extraction) or already PE
        with open(elf_path, 'rb') as f:
            magic = f.read(4)

        if magic == b'XEX2':
            # XEX: extract PE first
            pe_path = extract_pe_from_xex(elf_path, output_dir)
            if pe_path:
                load_path = pe_path
            else:
                # Fallback: try loading XEX directly
                load_path = elf_path
        else:
            # Already PE (extracted binary)
            load_path = elf_path

        # Load PE (creates segments at correct addresses)
        log(f"  Loading: {load_path}")
        idapro.open_database(load_path, run_auto_analysis=False)

        # Change processor to PPC
        log("  Setting processor to PPC...")
        idaapi.set_processor_type('ppc', 0)

        # Find .text section
        text_start = None
        text_end = None
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            name = ida_segment.get_segm_name(seg)
            if name == '.text':
                text_start = seg.start_ea
                text_end = seg.end_ea
                break

        if text_start is None:
            log("  WARNING: .text section not found, using first code section")
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                name = ida_segment.get_segm_name(seg)
                if 'text' in name.lower() or 'code' in name.lower():
                    text_start = seg.start_ea
                    text_end = seg.end_ea
                    break

        if text_start:
            log(f"  Scanning .text: 0x{text_start:08X}-0x{text_end:08X}")

            # Scan for PPC function prologues:
            # stwu r1, -X(r1) => opcode=0x25, rs=1, rt=1
            created = 0
            ea = text_start
            while ea < text_end - 4:
                if not ida_bytes.is_mapped(ea):
                    ea = ida_bytes.next_head(ea, text_end)
                    continue
                word = ida_bytes.get_dword(ea)
                # PPC stwu r1, -X(r1): opcode=0x25, rs=1, rt=1
                if (word >> 26) == 0x25 and ((word >> 21) & 0x1F) == 1 and ((word >> 16) & 0x1F) == 1:
                    if not ida_funcs.get_func(ea):
                        ok = ida_funcs.add_func(ea)
                        if ok:
                            created += 1
                ea += 4

            log(f"  Created {created} functions from prologue scanning")

        # Run auto-analysis
        log("  Running auto-analysis...")
        idaapi.auto_wait()

    else:
        idapro.open_database(elf_path, run_auto_analysis=True)

    # Load SCE database (auto-load if PS2 and not provided)
    sce_db_data = {}
    if sce_db:
        sce_db_data = load_sce_database(sce_db)
    else:
        sce_db_data = load_sce_database()  # Try default path

    # Functions Census
    log("Extracting functions...")
    func_list = []
    sce_matches = {}
    for func_ea in idautils.Functions():
        fname = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:08X}"
        fobj = ida_funcs.get_func(func_ea)
        if not fobj: continue
        fsize = fobj.size()
        is_named = fname and not fname.startswith("sub_") and not fname.startswith("loc_")
        start = fobj.start_ea
        end = fobj.end_ea
        func_list.append({"address": func_ea, "name": fname, "size": fsize, "is_named": is_named, "start": start, "end": end})
        if sce_db_data:
            m = match_sce(func_ea, sce_db_data)
            if m: sce_matches[func_ea] = m
    log(f"Functions: {len(func_list)}, SCE matches: {len(sce_matches)}")

    # Decompile
    decompiled = {}
    decompile_errors = 0
    log("Decompiling functions...")
    for i, func in enumerate(func_list):
        try:
            cfunc = ida_hexrays.decompile(func["address"])
            if cfunc: decompiled[func["address"]] = str(cfunc)
        except: decompile_errors += 1
        if (i + 1) % 1000 == 0: log(f"  Decompiled {i+1}/{len(func_list)}...")
    log(f"Decompiled: {len(decompiled)} OK, {decompile_errors} errors")

    # Strings
    log("Extracting strings...")
    strings = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        ea = seg.start_ea
        while ea < seg.end_ea:
            flags = ida_bytes.get_flags(ea)
            if flags & ida_bytes.FF_STRLIT:
                s = ida_bytes.get_strlit_contents(ea, -1, -1)
                if s and len(s) > 2:
                    try:
                        text = s.decode('utf-8', errors='replace')
                        strings.append({"address": ea, "text": text, "category": categorize_string(text)})
                    except: pass
                    ea = ida_bytes.get_item_end(ea)
                    continue
            ea = ida_bytes.next_head(ea, seg.end_ea)
    log(f"Strings: {len(strings)}")

    # Xrefs
    log("Extracting xrefs...")
    xrefs = []
    for func in func_list:
        for cref in idautils.CodeRefsFrom(func["address"], 0):
            xrefs.append({"from": func["address"], "to": cref, "type": "jal"})
    log(f"Xrefs: {len(xrefs)}")

    # Xbox 360 specific: imports + switch tables
    if platform == "xbox360":
        log("Extracting imports...")
        imports = extract_imports(pe_path=load_path)
        log(f"Imports: {len(imports)}")

        log("Detecting switch tables...")
        if text_start and text_end:
            switch_tables = detect_switch_tables(text_start, text_end)
        log(f"Switch tables: {len(switch_tables)}")

        log("Detecting checks/validations...")
        checks = detect_checks(func_list, decompiled, strings)
        log(f"Checks: {len(checks)}")

        log("Classifying subsystems...")
        subsystem_funcs = classify_subsystems(func_list, decompiled)
        log(f"Subsystem functions: {sum(1 for s in subsystem_funcs if s['subsystem'] != 'UNCATEGORIZED')} classified")
    else:
        checks = []
        subsystem_funcs = []

    # SQLite Database
    log(f"Building database: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.execute('''CREATE TABLE IF NOT EXISTS functions (address INTEGER PRIMARY KEY, name TEXT, size INTEGER, is_named INTEGER, category TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS decompiled (address INTEGER PRIMARY KEY, code TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS strings (address INTEGER PRIMARY KEY, text TEXT, category TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS xrefs (from_address INTEGER, to_address INTEGER, type TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS segments (name TEXT PRIMARY KEY, start_address INTEGER, end_address INTEGER, size INTEGER)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS imports (address INTEGER, module TEXT, name TEXT, ordinal INTEGER, PRIMARY KEY (address, module, name))''')
    conn.execute('''CREATE TABLE IF NOT EXISTS switch_tables (address INTEGER PRIMARY KEY, register INTEGER, num_labels INTEGER, labels TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY AUTOINCREMENT, function_address INTEGER, category TEXT, description TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS subsystem_funcs (subsystem TEXT, address INTEGER, name TEXT, size INTEGER)''')

    for func in func_list:
        m = sce_matches.get(func["address"])
        cat = "sdk" if m else ("named" if func["is_named"] else "unknown")
        conn.execute("INSERT INTO functions VALUES (?,?,?,?,?)", (func["address"], func["name"], func["size"], func["is_named"], cat))
    for addr, code in decompiled.items():
        conn.execute("INSERT INTO decompiled VALUES (?,?)", (addr, code))
    for s in strings:
        conn.execute("INSERT INTO strings VALUES (?,?,?)", (s["address"], s["text"], s["category"]))
    for x in xrefs:
        conn.execute("INSERT INTO xrefs VALUES (?,?,?)", (x["from"], x["to"], x["type"]))
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        conn.execute("INSERT OR REPLACE INTO segments VALUES (?,?,?,?)", (ida_segment.get_segm_name(seg), seg.start_ea, seg.end_ea, seg.end_ea - seg.start_ea))
    for imp in imports:
        conn.execute("INSERT OR IGNORE INTO imports VALUES (?,?,?,?)", (imp["address"], imp["module"], imp["name"], imp["ordinal"]))
    for st in switch_tables:
        conn.execute("INSERT OR REPLACE INTO switch_tables VALUES (?,?,?,?)", (st["address"], st["register"], st["num_labels"], json.dumps(st["labels"])))
    for chk in checks:
        conn.execute("INSERT INTO checks (function_address, category, description) VALUES (?,?,?)", (chk["address"], chk["category"], chk["description"]))
    for sf in subsystem_funcs:
        conn.execute("INSERT INTO subsystem_funcs VALUES (?,?,?,?)", (sf["subsystem"], sf["address"], sf["name"], sf["size"]))
    conn.commit()

    # JSON Exports
    log("Exporting JSONs...")
    segs = [{"name": ida_segment.get_segm_name(ida_segment.getseg(e)), "start_address": ida_segment.getseg(e).start_ea, "end_address": ida_segment.getseg(e).end_ea, "size": ida_segment.getseg(e).end_ea - ida_segment.getseg(e).start_ea} for e in idautils.Segments()]
    with open(os.path.join(export_dir, "segments.json"), "w") as f: json.dump({"count": len(segs), "segments": segs}, f, indent=2)
    by_cat = defaultdict(list)
    for s in strings: by_cat[s["category"]].append({"address": s["address"], "text": s["text"]})
    for cat, items in by_cat.items():
        with open(os.path.join(export_dir, f"strings_{cat}.json"), "w") as f: json.dump(items, f, indent=2, ensure_ascii=False)
    dec_list = [{"address": a, "code": c} for a, c in decompiled.items()]
    with open(os.path.join(export_dir, "decompiled_Unknown.json"), "w") as f: json.dump(dec_list, f, indent=2, ensure_ascii=False)
    unknown = [{"address": fa["address"], "name": fa["name"], "size": fa["size"]} for fa in func_list if fa["address"] not in sce_matches]
    with open(os.path.join(export_dir, "Unknown.json"), "w") as f: json.dump({"category": None, "count": len(unknown), "functions": unknown}, f, indent=2)
    if imports:
        with open(os.path.join(export_dir, "imports.json"), "w") as f: json.dump({"count": len(imports), "imports": imports}, f, indent=2, ensure_ascii=False)
    if switch_tables:
        with open(os.path.join(export_dir, "switch_tables.json"), "w") as f: json.dump(switch_tables, f, indent=2)
    if checks:
        with open(os.path.join(export_dir, "checks.json"), "w") as f: json.dump({"count": len(checks), "checks": checks}, f, indent=2)

    # Knowledge Base
    log("Generating Knowledge Base...")

    # Get segments info
    seg_list = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        seg_list.append({
            "name": ida_segment.get_segm_name(seg),
            "start": seg.start_ea,
            "end": seg.end_ea,
            "size": seg.end_ea - seg.start_ea
        })

    # Function size distribution
    size_ranges = [(0, 50), (50, 200), (200, 500), (500, 1024), (1024, 5120), (5120, 51200)]
    size_dist = {}
    for lo, hi in size_ranges:
        label = f"{lo}-{hi}B" if hi < 1024 else f"{lo//1024}-{hi//1024}KB"
        size_dist[label] = sum(1 for f in func_list if lo <= f["size"] < hi)

    # Top 20 largest functions
    top_funcs = sorted(func_list, key=lambda f: f["size"], reverse=True)[:20]

    # Subsystem classification summary
    sub_counts = Counter(s["subsystem"] for s in subsystem_funcs)
    sub_apis = {
        "NETWORKING": "XNet*, NetDll*, WSA*, socket",
        "GRAPHICS": "D3D*, Xe*, Rw*, Hedgehog",
        "MEMORY": "ExAllocatePool, XMemAlloc",
        "KINECT": "Nui*, NUI_*",
        "AUDIO": "XMA, XAudio2",
    }

    # Checks summary
    check_counts = Counter(c["category"] for c in checks)

    kb = []
    kb.append(f"# {base} — Knowledge Base")
    kb.append("")
    kb.append(f"**Binary**: {elf_name}")
    if platform == "xbox360":
        kb.append(f"**Platform**: Xbox 360")
    elif platform == "ps2":
        kb.append(f"**Platform**: PS2")
    kb.append("")
    kb.append("---")
    kb.append("")

    # 1. Executive Summary
    kb.append("## 1. Executive Summary")
    kb.append("")
    kb.append("| Metric | Value |")
    kb.append("|--------|-------|")
    kb.append(f"| Total functions | {len(func_list)} |")
    kb.append(f"| Named functions | {sum(1 for f in func_list if f['is_named'])} |")
    kb.append(f"| Decompiled | {len(decompiled)} ({100*len(decompiled)//max(len(func_list),1)}%) |")
    kb.append(f"| Decompilation errors | {decompile_errors} |")
    kb.append(f"| Strings | {len(strings)} |")
    kb.append(f"| Xrefs | {len(xrefs)} |")
    kb.append(f"| Segments | {len(seg_list)} |")
    if checks:
        kb.append(f"| Check functions | {len(checks)} |")
    if imports:
        kb.append(f"| Imports | {len(imports)} |")
    if switch_tables:
        kb.append(f"| Switch tables | {len(switch_tables)} |")
    kb.append("")

    # 2. Binary Layout
    kb.append("## 2. Binary Layout")
    kb.append("")
    kb.append("| Section | Start | End | Size |")
    kb.append("|---------|-------|-----|------|")
    for seg in seg_list:
        kb.append(f"| `{seg['name']}` | 0x{seg['start']:08x} | 0x{seg['end']:08x} | 0x{seg['size']:x} ({seg['size']:,} bytes) |")
    kb.append("")

    # 3. Function Census
    kb.append("## 3. Function Census")
    kb.append("")
    kb.append("### Size Distribution")
    kb.append("")
    kb.append("| Range | Count |")
    kb.append("|-------|-------|")
    for label, count in size_dist.items():
        kb.append(f"| {label} | {count} |")
    kb.append("")
    kb.append("### Top 20 Largest Functions")
    kb.append("")
    kb.append("| Address | Name | Size |")
    kb.append("|---------|------|------|")
    for f in top_funcs:
        kb.append(f"| 0x{f['address']:08x} | {f['name']} | {f['size']:,}B |")
    kb.append("")

    # 4. Subsystem Classification
    if subsystem_funcs:
        classified = sum(1 for s in subsystem_funcs if s["subsystem"] != "UNCATEGORIZED")
        if classified > 0:
            kb.append("## 4. Subsystem Classification")
            kb.append("")
            kb.append("*Based on pseudocode pattern matching (SDK API calls + string references)*")
            kb.append("")
            kb.append("| Subsystem | Functions | Key APIs |")
            kb.append("|-----------|----------|----------|")
            for sub in ["NETWORKING", "GRAPHICS", "MEMORY", "KINECT", "AUDIO", "UNCATEGORIZED"]:
                cnt = sub_counts.get(sub, 0)
                if cnt > 0:
                    apis = sub_apis.get(sub, "")
                    kb.append(f"| {sub} | {cnt} | {apis} |")
            kb.append("")

    # 5. Checks & Validations Catalog
    if checks:
        kb.append("## 5. Checks & Validations Catalog")
        kb.append("")
        kb.append("| Category | Count |")
        kb.append("|----------|-------|")
        for cat, cnt in check_counts.most_common():
            kb.append(f"| {cat} | {cnt} |")
        kb.append("")
        kb.append("### Detailed Check Functions")
        kb.append("")
        # Group by category
        checks_by_cat = defaultdict(list)
        for c in checks:
            checks_by_cat[c["category"]].append(c)
        for cat in sorted(checks_by_cat.keys()):
            kb.append(f"#### {cat}")
            kb.append("")
            kb.append("| Address | Function |")
            kb.append("|---------|----------|")
            for c in checks_by_cat[cat][:25]:  # limit per category
                kb.append(f"| 0x{c['address']:08x} | {c['description']} |")
            if len(checks_by_cat[cat]) > 25:
                kb.append(f"| ... | +{len(checks_by_cat[cat])-25} more |")
            kb.append("")

    # 6. Imports
    if imports:
        imp_mods = Counter(i['module'] for i in imports)
        kb.append("## 6. Imports")
        kb.append("")
        kb.append("| Module | Count |")
        kb.append("|--------|-------|")
        for mod, count in imp_mods.most_common(20):
            kb.append(f"| {mod} | {count} |")
        kb.append("")

    # 7. Switch Tables
    if switch_tables:
        kb.append("## 7. Switch Tables")
        kb.append("")
        kb.append(f"Detected {len(switch_tables)} jump tables in .rdata")
        kb.append("")

    # 8. String Categories
    kb.append("## 8. String Categories")
    kb.append("")
    kb.append("| Category | Count |")
    kb.append("|----------|-------|")
    for cat, items in sorted(by_cat.items()):
        kb.append(f"| {cat} | {len(items)} |")
    kb.append("")

    with open(kb_path, "w") as f: f.write("\n".join(kb))

    conn.close()
    log(f"[Phase 1] Done! DB: {db_path}, KB: {kb_path}")
    return {"functions": len(func_list), "decompiled": len(decompiled), "errors": decompile_errors,
            "strings": len(strings), "xrefs": len(xrefs), "sdk": len(sce_matches),
            "imports": len(imports), "switch_tables": len(switch_tables),
            "checks": len(checks), "subsystem_funcs": len(subsystem_funcs),
            "func_list": func_list, "sce_matches": sce_matches, "elf_name": elf_name}

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def log(msg):
    print(msg)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 analyze.py <game.xex|game.elf> <output_dir>")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_dir = sys.argv[2]

    platform = detect_platform(binary_path)
    log(f"Platform detected: {platform.upper()}")
    log(f"Input: {binary_path}")
    log(f"Output: {output_dir}")
    log("")

    if platform == "ps2":
        # PS2: Phase 1 (IDA analysis) + Phase 2 (PS2Recomp export)
        log("=" * 60)
        log("PS2 DETECTED — Running Phase 1 + Phase 2")
        log("=" * 60)

        result = full_analysis(binary_path, output_dir)

        log("")
        log("=" * 60)
        log("Phase 2: PS2Recomp Export")
        log("=" * 60)
        ps2_result = ps2recomp_export(result["func_list"], result["sce_matches"], result["elf_name"], output_dir)
        log(f"CSV: {ps2_result['csv']}")
        log(f"TOML: {ps2_result['toml']}")
        log(f"Stubs: {ps2_result['stubs']}, Untracked: {ps2_result['untracked']}")

        log("")
        log("=" * 60)
        log("ALL PHASES COMPLETE")
        log("=" * 60)
        log(f"  DB: {output_dir}/{os.path.splitext(result['elf_name'])[0]}.db")
        log(f"  KB: {output_dir}/{os.path.splitext(result['elf_name'])[0].upper()}_KNOWLEDGE_BASE.md")
        log(f"  CSV: {ps2_result['csv']}")
        log(f"  TOML: {ps2_result['toml']}")

    elif platform == "xbox360":
        # Xbox 360: Phase 1 (IDA analysis) + Phase 2 (ReXGlue export)
        log("=" * 60)
        log("XBOX 360 DETECTED — Running Phase 1 + Phase 2")
        log("=" * 60)

        result = full_analysis(binary_path, output_dir, platform="xbox360")

        log("")
        log("=" * 60)
        log("Phase 2: ReXGlue Export")
        log("=" * 60)

        # Run xbox360_recomp_export.py using the DB from Phase 1
        db_path = os.path.join(output_dir, f"{os.path.splitext(result['elf_name'])[0]}.db")
        toml_path = os.path.join(output_dir, "config.toml")
        elf_name = result["elf_name"]

        try:
            import subprocess
            export_script = str(SCRIPT_DIR / "xbox360_recomp_export.py")
            cmd = [
                sys.executable, export_script,
                "--db", db_path,
                "--file-path", elf_name,
                "--project-name", os.path.splitext(elf_name)[0],
                "--out-directory", "generated",
                "--output", toml_path,
                "--all-functions",
            ]
            # Pass switch tables if detected
            st_json = os.path.join(output_dir, "export", "switch_tables.json")
            if os.path.exists(st_json):
                cmd += ["--switch-tables", st_json]
            log(f"Running: {' '.join(cmd)}")
            proc = subprocess.run(cmd, capture_output=True, text=True)
            if proc.returncode == 0:
                log(proc.stdout)
                log(f"TOML: {toml_path}")
            else:
                log(f"Export warning: {proc.stderr}")
                log(f"TOML: {toml_path} (partial)")
        except Exception as e:
            log(f"Export error: {e}")
            log(f"DB available at: {db_path}")

        log("")
        log("=" * 60)
        log("ALL PHASES COMPLETE")
        log("=" * 60)
        log(f"  DB: {db_path}")
        log(f"  KB: {output_dir}/{os.path.splitext(result['elf_name'])[0].upper()}_KNOWLEDGE_BASE.md")
        log(f"  TOML: {toml_path}")

    else:
        log(f"ERROR: Unknown platform for {binary_path}")
        sys.exit(1)
