#!/usr/bin/env python3
"""
PS2Recomp Export Tool — Unified IDA Pro Script
================================================
Generates CSV function map + TOML config for ps2xRecomp from PS2 ELF files.

Features:
- SCE SHA-1 signature matching (52 SDK libraries, 5,323 function names)
- Code-based detection (syscalls, MMIO, thunks)
- Negative syscalls (IOP mode)
- String-based SDK detection
- Cross-reference propagation

Usage (idalib):
  import idapro
  idapro.open_database("game.elf", run_auto_analysis=True)
  exec(open("ps2_recomp_export.py").read())

Usage (batch mode):
  python3 ps2_recomp_export.py --batch /path/to/isos/ /output/dir

Output:
  <name>_functions.csv  — CSV with Name,Start,End,Size
  <name>.toml           — TOML config for ps2xRecomp
"""
import idapro
import os
import sys
import json
import hashlib
import struct
import re
from collections import Counter
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# SCE SYMBOL DATABASE
# ═══════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__))) if '__file__' in dir() else Path.cwd()
DEFAULT_SCE_DB = SCRIPT_DIR / "sce_symbols.json"
PS2RECOMP_HEADER = "/mnt/Datos/Proyectos/PS2Recomp/ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h"

RELOC_MASKS = {
    "MIPS_NONE": 0xFFFFFFFF, "MIPS_26": 0xFC000000,
    "MIPS_HI16": 0xFFFF0000, "MIPS_LO16": 0xFFFF0000,
    "MIPS_GPREL16": 0xFFFF0000, "MIPS_LITERAL": 0xFFFF0000,
    "MIPS_32": 0x00000000,
}

def extract_sce_database():
    """Auto-extract SCE database from PS2Recomp C++ header."""
    if not os.path.exists(PS2RECOMP_HEADER):
        print(f"WARNING: PS2Recomp header not found at {PS2RECOMP_HEADER}")
        print("SCE matching will be disabled.")
        return {}
    with open(PS2RECOMP_HEADER, 'r') as f:
        content = f.read()
    chunks = re.findall(r'R"PS2SDB\((.*?)\)PS2SDB"', content, re.DOTALL)
    json_str = ''.join(chunks)
    tree_marker = json_str.find('{"skip"')
    data = json.loads(json_str[:tree_marker] if tree_marker > 0 else json_str)
    # Cache for next run
    with open(DEFAULT_SCE_DB, 'w') as f:
        json.dump(data, f)
    return data

def load_sce_database(symbols_path=None):
    """Load SCE symbol database from JSON file."""
    if symbols_path is None:
        symbols_path = str(DEFAULT_SCE_DB)
    if not os.path.exists(symbols_path):
        print(f"SCE database not found at {symbols_path}, extracting...")
        data = extract_sce_database()
        if not data:
            return {}
    else:
        with open(symbols_path, 'r') as f:
            data = json.load(f)
    hash_lookup = {}
    for library, functions in data.items():
        for name, hashes in functions.items():
            for sha1_hash, variants in hashes.items():
                for variant_hash, info in variants.items():
                    if info.get('type') != 'FUNCTION':
                        continue
                    entry = {
                        'library': library, 'name': name,
                        'size': info.get('size', 0),
                        'relocations': info.get('relocations', {}),
                        'variant': variant_hash,
                        'sdk': info.get('sdk', []),
                    }
                    hash_lookup.setdefault(sha1_hash, []).append(entry)
    return hash_lookup

def match_sce_function(func_ea, hash_lookup):
    """Match a function against SCE database by SHA-1 hash."""
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj:
        return None
    size = fobj.end_ea - fobj.start_ea
    if size < 8 or size > 2048:
        return None
    data = ida_bytes.get_bytes(fobj.start_ea, size)
    if not data:
        return None

    # Strategy 1: No relocation masking
    h = hashlib.sha1(data).hexdigest()
    if h in hash_lookup:
        for c in hash_lookup[h]:
            if abs(c['size'] - size) <= 16:
                return c

    # Strategy 2: Mask JAL + LUI
    masked = bytearray(data)
    for i in range(0, len(masked) - 3, 4):
        w = struct.unpack('<I', masked[i:i+4])[0]
        if (w >> 26) == 0x03:  # JAL
            struct.pack_into('<I', masked, i, w & 0xFC000000)
        elif (w >> 26) == 0x0F:  # LUI
            struct.pack_into('<I', masked, i, w & 0xFFFF0000)
    h = hashlib.sha1(bytes(masked)).hexdigest()
    if h in hash_lookup:
        for c in hash_lookup[h]:
            if abs(c['size'] - size) <= 16:
                return c

    # Strategy 3: Mask all branches
    masked = bytearray(data)
    for i in range(0, len(masked) - 3, 4):
        w = struct.unpack('<I', masked[i:i+4])[0]
        if (w >> 26) in (0x04, 0x05, 0x06, 0x07, 0x01):
            struct.pack_into('<I', masked, i, w & 0xFFFF0000)
    h = hashlib.sha1(bytes(masked)).hexdigest()
    if h in hash_lookup:
        for c in hash_lookup[h]:
            if abs(c['size'] - size) <= 16:
                return c

    return None

# ═══════════════════════════════════════════════════════════════
# SYSCALL TABLE
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

# ═══════════════════════════════════════════════════════════════
# CODE-BASED DETECTION
# ═══════════════════════════════════════════════════════════════

def detect_syscall(func_ea):
    """Detect PS2 syscall (positive and negative)."""
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj:
        return None
    ea = fobj.start_ea
    while ea < fobj.end_ea:
        if not ida_bytes.is_mapped(ea):
            ea = ida_bytes.next_head(ea, fobj.end_ea)
            continue
        w = ida_bytes.get_dword(ea)
        if (w >> 26) == 0x0F and ((w >> 16) & 0x1F) == 2:  # lui $v0
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
                                if val >= 0x80000000:
                                    val -= 0x100000000
                                return val
        ea = ida_bytes.next_head(ea, fobj.end_ea)
    return None

def detect_mmio(func_ea):
    """Detect MMIO register access."""
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj:
        return False
    ea = fobj.start_ea
    lui_regs = {}
    while ea < fobj.end_ea:
        if not ida_bytes.is_mapped(ea):
            ea = ida_bytes.next_head(ea, fobj.end_ea)
            continue
        w = ida_bytes.get_dword(ea)
        if (w >> 26) == 0x0F:
            lui_regs[(w >> 16) & 0x1F] = (w & 0xFFFF) << 16
        if (w >> 26) in (0x23, 0x2B):
            rs = (w >> 21) & 0x1F
            if rs in lui_regs:
                off = w & 0xFFFF
                if off & 0x8000:
                    off -= 0x10000
                addr = lui_regs[rs] + off
                for s, e in MMIO_RANGES:
                    if s <= addr <= e:
                        return True
        ea = ida_bytes.next_head(ea, fobj.end_ea)
    return False

def detect_thunk(func_ea):
    """Detect tiny thunk functions (jr $ra or j <target>)."""
    import ida_funcs, ida_bytes
    fobj = ida_funcs.get_func(func_ea)
    if not fobj:
        return False
    if fobj.end_ea - fobj.start_ea > 16:
        return False
    ea = fobj.start_ea
    while ea < fobj.end_ea:
        if not ida_bytes.is_mapped(ea):
            ea += 4
            continue
        w = ida_bytes.get_dword(ea)
        if w == 0x03E00008 or (w >> 26) == 0x02:  # jr $ra or j <target>
            return True
        ea += 4
    return False

# ═══════════════════════════════════════════════════════════════
# MAIN CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

def classify_function(func_ea, sce_match):
    """Classify a function: SCE match > syscall > thunk > IO > game."""
    if sce_match:
        return "stub", f"{sce_match['library']}::{sce_match['name']}"
    if detect_thunk(func_ea):
        return "stub", "thunk"
    sc = detect_syscall(func_ea)
    if sc is not None:
        return "stub", f"{PS2_SYSCALL.get(sc, f'syscall_{sc}')}@syscall_{sc}"
    if detect_mmio(func_ea):
        return "untracked_stub", "io_access"
    return "game", ""

# ═══════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════

def export_elf(elf_path, output_dir, sce_db, log_fn=print):
    """Analyze a PS2 ELF and generate CSV + TOML."""
    import idaapi, ida_funcs, idautils, ida_bytes

    elf_name = os.path.basename(elf_path)
    base = os.path.splitext(elf_name)[0]
    os.makedirs(output_dir, exist_ok=True)

    log_fn(f"Opening {elf_name}...")
    idapro.open_database(elf_path, run_auto_analysis=True)

    # SCE matching
    sce_matches = {}
    for func_ea in idautils.Functions():
        r = match_sce_function(func_ea, sce_db)
        if r:
            sce_matches[func_ea] = r

    log_fn(f"SCE matches: {len(sce_matches)}")

    # Classify all functions
    records = []
    classifications = {}
    for func_ea in idautils.Functions():
        fname = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:08X}"
        fobj = ida_funcs.get_func(func_ea)
        if not fobj:
            continue

        sce = sce_matches.get(func_ea)
        cat, info = classify_function(func_ea, sce)

        name = sce['name'] if sce else fname
        records.append({"address": func_ea, "name": name, "start": func_ea, "end": fobj.end_ea})
        classifications[func_ea] = (cat, info)

    records.sort(key=lambda r: r["address"])

    # Generate CSV
    csv_path = os.path.join(output_dir, "functions.csv")
    with open(csv_path, "w") as f:
        f.write("Name,Start,End,Size\n")
        for rec in records:
            sz = rec["end"] - rec["start"]
            f.write(f"{rec['name']},0x{rec['start']:08X},0x{rec['end']:08X},{sz}\n")

    # Generate TOML
    stubs = []
    untracked = []
    for rec in records:
        cat, info = classifications.get(rec["address"], ("game", ""))
        sel = f"{rec['name']}@0x{rec['address']:08X}"
        if cat == "stub":
            stubs.append(sel)
        elif cat == "untracked_stub":
            untracked.append(sel)

    toml_path = os.path.join(output_dir, "config.toml")
    with open(toml_path, "w") as f:
        f.write(f"# PS2Recomp - {elf_name}\n")
        f.write(f"# Generated by IDA Pro + SCE SHA-1 matching\n\n")
        f.write("[general]\n")
        f.write(f'input = "{elf_name}"\n')
        f.write('ghidra_output = ""\n')
        f.write('output = "./output/"\n')
        f.write("single_file_output = false\n")
        f.write("patch_syscalls = false\n")
        f.write("patch_cop0 = true\n")
        f.write("patch_cache = true\n\n")
        f.write("stubs = [\n")
        for s in sorted(stubs):
            f.write(f'  "{s}",\n')
        f.write("]\n\n")
        f.write("untracked_stubs = [\n")
        for u in sorted(untracked):
            f.write(f'  "{u}",\n')
        f.write("]\n\n")
        f.write("skip = []\n")

    idapro.close_database()

    # Stats
    libs = Counter(m['library'] for m in sce_matches.values())
    sce_count = len([r for r in records if classifications.get(r["address"], ("", ""))[0] == "stub" and "::" in classifications.get(r["address"], ("", ""))[1]])
    thunk_count = len([r for r in records if classifications.get(r["address"], ("", "")) == ("stub", "thunk")])
    io_count = len(untracked)

    return {
        "total": len(records),
        "sce": sce_count,
        "thunks": thunk_count,
        "io": io_count,
        "game": len(records) - sce_count - thunk_count - io_count,
        "libs": dict(libs.most_common(15)),
        "csv": csv_path,
        "toml": toml_path,
    }

# ═══════════════════════════════════════════════════════════════
# BATCH MODE
# ═══════════════════════════════════════════════════════════════

def run_batch(iso_dir, output_dir, sce_db_path):
    """Process all PS2 ISOs in a directory."""
    import subprocess

    sce_db = load_sce_database(sce_db_path)
    log_path = os.path.join(output_dir, "batch_log.txt")
    os.makedirs(output_dir, exist_ok=True)

    def log(msg):
        print(msg)
        with open(log_path, "a") as f:
            f.write(msg + "\n")

    with open(log_path, "w") as f:
        f.write("")

    # Find ISOs
    isos = []
    for f in sorted(Path(iso_dir).glob("*.iso")):
        isos.append(f)
    for f in sorted(Path(iso_dir).glob("*.ISO")):
        if f not in isos:
            isos.append(f)

    log(f"Found {len(isos)} ISOs in {iso_dir}")
    results = []

    for iso_path in isos:
        game_name = iso_path.stem
        log(f"\n{'='*60}")
        log(f"Processing: {game_name}")

        # Extract SYSTEM.CNF
        tmp_dir = f"/tmp/ps2_batch_{game_name.replace(' ', '_')}"
        os.makedirs(tmp_dir, exist_ok=True)
        subprocess.run(["7z", "e", f"-o{tmp_dir}", str(iso_path), "SYSTEM.CNF", "-y"],
                       capture_output=True)

        cnf_path = os.path.join(tmp_dir, "SYSTEM.CNF")
        if not os.path.exists(cnf_path):
            log(f"  SKIP: SYSTEM.CNF not found")
            continue

        with open(cnf_path) as f:
            cnf = f.read()

        elf_name = None
        for line in cnf.split("\n"):
            if "BOOT2" in line:
                elf_name = line.split(":\\")[-1].split(";")[0].strip()
                break

        if not elf_name:
            log(f"  SKIP: Could not parse ELF name")
            continue

        # Extract ELF
        subprocess.run(["7z", "e", f"-o{tmp_dir}", str(iso_path), elf_name, "-y"],
                       capture_output=True)

        elf_path = os.path.join(tmp_dir, elf_name)
        if not os.path.exists(elf_path):
            log(f"  SKIP: ELF not found")
            continue

        # Output dir
        safe_name = game_name.replace(" ", "_").replace("'", "")
        game_output = os.path.join(output_dir, safe_name)
        os.makedirs(game_output, exist_ok=True)

        try:
            stats = export_elf(elf_path, game_output, sce_db, log_fn=log)
            results.append({"name": game_name, "ok": True, "stats": stats})
            log(f"  OK: {stats['total']} funcs, {stats['sce']} SDK, {stats['thunks']} thunks")
        except Exception as e:
            log(f"  ERROR: {e}")
            import traceback
            traceback.print_exc(file=open(log_path, "a"))
            results.append({"name": game_name, "ok": False})

    # Summary
    log(f"\n{'='*60}")
    log("BATCH COMPLETE")
    log(f"{'='*60}")
    for r in results:
        status = "OK" if r["ok"] else "FAIL"
        s = r.get("stats", {})
        log(f"  [{status}] {r['name']}: {s.get('total',0)} funcs, {s.get('sce',0)} SDK")

    return results

# ═══════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    if "--batch" in sys.argv:
        idx = sys.argv.index("--batch")
        iso_dir = sys.argv[idx + 1]
        output_dir = sys.argv[idx + 2]
        sce_db = sys.argv[idx + 3] if len(sys.argv) > idx + 3 else None
        run_batch(iso_dir, output_dir, sce_db)
    elif len(sys.argv) >= 3:
        # Single file mode (requires idalib context)
        elf_path = sys.argv[1]
        output_dir = sys.argv[2]
        sce_db = sys.argv[3] if len(sys.argv) > 3 else None
        db = load_sce_database(sce_db)
        stats = export_elf(elf_path, output_dir, db)
        print(f"Done: {stats}")
    else:
        print("Usage:")
        print("  Single:  idat -A -OIDAPython:ps2_recomp_export.py <elf> <output>")
        print("  Batch:   python3 ps2_recomp_export.py --batch <iso_dir> <output_dir>")
