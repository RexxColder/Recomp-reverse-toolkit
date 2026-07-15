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
from pathlib import Path
from collections import Counter, defaultdict

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__))) if '__file__' in dir() else Path.cwd()

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

def full_analysis(elf_path, output_dir, sce_db=None):
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
    log("Decompiling functions...")
    decompiled = {}
    decompile_errors = 0
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

    # SQLite Database
    log(f"Building database: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.execute('''CREATE TABLE IF NOT EXISTS functions (address INTEGER PRIMARY KEY, name TEXT, size INTEGER, is_named INTEGER, category TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS decompiled (address INTEGER PRIMARY KEY, code TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS strings (address INTEGER PRIMARY KEY, text TEXT, category TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS xrefs (from_address INTEGER, to_address INTEGER, type TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS segments (name TEXT PRIMARY KEY, start_address INTEGER, end_address INTEGER, size INTEGER)''')

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
    conn.commit()

    # JSON Exports
    log("Exporting JSONs...")
    segs = [{"name": ida_segment.get_segm_name(ida_segment.getseg(e)), "start": ida_segment.getseg(e).start_ea, "end": ida_segment.getseg(e).end_ea, "size": ida_segment.getseg(e).end_ea - ida_segment.getseg(e).start_ea} for e in idautils.Segments()]
    with open(os.path.join(export_dir, "segments.json"), "w") as f: json.dump(segs, f, indent=2)
    by_cat = defaultdict(list)
    for s in strings: by_cat[s["category"]].append({"address": s["address"], "text": s["text"]})
    for cat, items in by_cat.items():
        with open(os.path.join(export_dir, f"strings_{cat}.json"), "w") as f: json.dump(items, f, indent=2, ensure_ascii=False)
    dec_list = [{"address": a, "code": c} for a, c in decompiled.items()]
    with open(os.path.join(export_dir, "decompiled_Unknown.json"), "w") as f: json.dump(dec_list, f, indent=2, ensure_ascii=False)
    unknown = [{"address": fa["address"], "name": fa["name"], "size": fa["size"]} for fa in func_list if fa["address"] not in sce_matches]
    with open(os.path.join(export_dir, "Unknown.json"), "w") as f: json.dump(unknown, f, indent=2)

    # Knowledge Base
    log("Generating Knowledge Base...")
    libs = Counter(m['library'] for m in sce_matches.values())
    kb = [f"# {base} — Knowledge Base", "", f"**Binary**: {elf_name}", "", "---", "",
          "## Executive Summary", "", "| Metric | Value |", "|--------|-------|",
          f"| Total functions | {len(func_list)} |", f"| Named functions | {sum(1 for f in func_list if f['is_named'])} |",
          f"| SDK functions (SCE) | {len(sce_matches)} |", f"| Decompiled | {len(decompiled)} ({100*len(decompiled)//max(len(func_list),1)}%) |",
          f"| Decompilation errors | {decompile_errors} |", f"| Xrefs | {len(xrefs)} |", f"| Strings | {len(strings)} |",
          "", "## SDK Libraries", "", "| Library | Functions |", "|---------|-----------|"]
    for lib, count in libs.most_common(20): kb.append(f"| {lib} | {count} |")
    kb.extend(["", "## String Categories", "", "| Category | Count |", "|----------|-------|"])
    for cat, items in sorted(by_cat.items()): kb.append(f"| {cat} | {len(items)} |")
    with open(kb_path, "w") as f: f.write("\n".join(kb))

    conn.close()
    log(f"[Phase 1] Done! DB: {db_path}, KB: {kb_path}")
    return {"functions": len(func_list), "decompiled": len(decompiled), "errors": decompile_errors,
            "strings": len(strings), "xrefs": len(xrefs), "sdk": len(sce_matches),
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

        result = full_analysis(binary_path, output_dir)

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
