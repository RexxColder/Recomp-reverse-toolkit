#!/usr/bin/env python3
"""
PS2 Full Analysis — IDA Pro Headless
======================================
Generates SQLite database + Knowledge Base markdown + JSON exports.

Usage:
  PYTHONPATH="/path/to/IDA/idalib/python:$PYTHONPATH" \
    python3 ps2_full_analysis.py game.elf /output/dir
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

def log(msg):
    print(msg)

STRING_PATTERNS = {
    "PS2_SDK": re.compile(r"^(sce|Sif|Gs|Pad|Mc|Cd|Dma|Vif|Gif|Mpeg|Spu|Iop|Vpu)", re.IGNORECASE),
    "CDVD": re.compile(r"(disc|cdrom|dvd|sector|toc|track|disc.?error)", re.IGNORECASE),
    "ERROR": re.compile(r"(error|fail|assert|panic|abort|exception|crash)", re.IGNORECASE),
    "DEBUG": re.compile(r"(debug|trace|log|printf|print|dump|hex)", re.IGNORECASE),
    "AUDIO": re.compile(r"(audio|sound|sfx|music|voice|spu|adpcm|vag)", re.IGNORECASE),
    "FILE_PATH": re.compile(r"^(/[a-z]|cdrom|mc[01]:|host0:|mass:)", re.IGNORECASE),
}

def categorize_string(text):
    for cat, pattern in STRING_PATTERNS.items():
        if pattern and pattern.search(text):
            return cat
    return "OTHER"

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__))) if '__file__' in dir() else Path.cwd()
DEFAULT_SCE_DB = SCRIPT_DIR / "sce_symbols.json"
PS2RECOMP_HEADER = "/mnt/Datos/Proyectos/PS2Recomp/ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h"

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

def run_analysis(elf_path, output_dir, sce_db_path=None):
    import idaapi, ida_funcs, ida_hexrays, ida_bytes
    import idautils, ida_segment, ida_nalt, ida_entry

    os.makedirs(output_dir, exist_ok=True)
    elf_name = os.path.basename(elf_path)
    base = os.path.splitext(elf_name)[0]
    db_path = os.path.join(output_dir, f"{base}.db")
    kb_path = os.path.join(output_dir, f"{base.upper()}_KNOWLEDGE_BASE.md")
    export_dir = os.path.join(output_dir, "export")
    os.makedirs(export_dir, exist_ok=True)

    log(f"Opening {elf_name}...")
    idapro.open_database(elf_path, run_auto_analysis=True)
    sce_db = load_sce_database(sce_db_path)

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
        func_list.append({"address": func_ea, "name": fname, "size": fsize, "is_named": is_named})
        m = match_sce(func_ea, sce_db)
        if m: sce_matches[func_ea] = m
    log(f"Functions: {len(func_list)}, SCE matches: {len(sce_matches)}")

    # Decompile
    log("Decompiling functions...")
    decompiled = {}
    decompile_errors = 0
    for i, func in enumerate(func_list):
        try:
            cfunc = ida_hexrays.decompile(func["address"])
            if cfunc:
                decompiled[func["address"]] = str(cfunc)
        except:
            decompile_errors += 1
        if (i + 1) % 1000 == 0:
            log(f"  Decompiled {i+1}/{len(func_list)}...")
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
    conn.execute('''CREATE TABLE IF NOT EXISTS analysis_docs (name TEXT PRIMARY KEY, content TEXT)''')

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
    kb = [f"# {base} — Knowledge Base", "", f"**Binary**: {elf_name}", f"**Architecture**: MIPS R5900 (Emotion Engine)", "", "---", "",
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
    idapro.close_database()
    log(f"\nDone! DB: {db_path}, KB: {kb_path}")
    return {"functions": len(func_list), "decompiled": len(decompiled), "errors": decompile_errors,
            "strings": len(strings), "xrefs": len(xrefs), "sdk": len(sce_matches)}

if __name__ == "__main__":
    if len(sys.argv) >= 3:
        sce_db = sys.argv[3] if len(sys.argv) > 3 else None
        stats = run_analysis(sys.argv[1], sys.argv[2], sce_db)
        print(f"Done: {stats}")
    else:
        print("Usage: python3 ps2_full_analysis.py game.elf /output/dir [sce_symbols.json]")
