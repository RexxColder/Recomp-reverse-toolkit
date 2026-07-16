#!/usr/bin/env python3
"""
xbox360_recomp_export.py
-------------------------------------------------------------------------
Exporta un config.toml compatible con ReXGlue SDK (rexglue codegen) a
partir de la SQLite DB que genera analyze.py para un binario Xbox 360.

Simétrico a ps2_recomp_export.py, pero apunta al schema de ReXGlue en vez
de PS2Recomp. Referencia del formato de salida:
  https://github.com/rexglue/rexglue-sdk/wiki/rexglue-CLI-Configuration-File

IMPORTANTE - ASUNCIONES DE SCHEMA:
Este script asume que la DB de analyze.py tiene (al menos) una tabla de
funciones con columnas equivalentes a start/end/name, y opcionalmente una
tabla de imports. Los nombres de tabla/columna reales de tu DB pueden
diferir -- ajustá las listas CANDIDATE_* de abajo si el auto-detect no
encuentra tu schema (corré con --list-schema para ver qué hay).

Switch tables e invalid_instructions NO se asume que estén en la DB
(el pipeline actual de PS2 no las exporta), así que se cargan desde
JSONs externos opcionales -- ver --switch-tables / --invalid-instructions.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Grupos de funciones con implementación nativa en el runtime de ReXGlue.
# Fuente: rexglue-sdk wiki, sección "ReXCRT". El grupo Heap es todo-o-nada:
# si mapeás una función de Heap, tenés que mapear las 4.
# ---------------------------------------------------------------------------
REXCRT_GROUPS = {
    "Heap": ["RtlAllocateHeap", "RtlFreeHeap", "RtlSizeHeap", "RtlReAllocateHeap"],
    "File I/O": [
        "CreateFileA", "ReadFile", "WriteFile", "SetFilePointer", "GetFileSize",
        "GetFileSizeEx", "SetEndOfFile", "FlushFileBuffers", "DeleteFileA",
        "CloseHandle", "FindFirstFileA", "FindNextFileA", "FindClose",
        "CreateDirectoryA", "MoveFileA", "SetFileAttributesA", "GetFileAttributesA",
        "GetFileAttributesExA", "SetFilePointerEx", "SetFileTime", "CompareFileTime",
        "CopyFileA", "RemoveDirectoryA", "GetFileType",
        # Xbox 360 STFS / Nt file I/O
        "StfsCreateDevice", "StfsControlDevice", "StfsDeviceErrorEvent",
        "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
        "NtClose", "NtQueryInformationFile", "NtSetInformationFile",
        "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
        "NtAllocateEncryptedMemory", "NtFreeEncryptedMemory",
    ],
    "Memory": [
        "memcpy", "memmove", "memset", "memchr", "XMemCpy", "XMemSet",
        "XMemSet128", "memset_vmx", "memcpy_s", "memmove_s",
        "RtlCopyMemory", "RtlMoveMemory", "RtlFillMemory", "RtlZeroMemory",
        "RtlImageNtHeader",
    ],
    "String": [
        "strncmp", "strncpy", "strchr", "strstr", "strrchr", "strtok",
        "_stricmp", "strcpy_s", "lstrlenA", "lstrcpyA", "lstrcpynA",
        "lstrcatA", "lstrcmpiA",
        "RtlCompareString", "RtlInitAnsiString", "RtlInitUnicodeString",
        "RtlCopyString", "RtlUpperString",
    ],
    "Xbox Audio": [
        "XAudioGetVoiceCategoryVolume", "XAudioGetVoiceCategoryVolumeChangeMask",
        "XAudioSetDuckerReleaseTime", "XAudioRenderDriverLock",
        "XAudioSubmitDigitalPacket", "XAudioUnregisterRenderDriverClient",
    ],
    "Xbox Input": [
        "XInputdFFGetDeviceInfo", "XInputdGetDevicePid", "XInputdGetDeviceStats",
    ],
    "Xbox Kernel": [
        "KeGetVidInfo", "KeInitializeEvent", "KeSetEvent", "KeResetEvent",
        "KeWaitForSingleObject", "KeWaitForMultipleObjects",
        "KeReleaseMutex", "KeReleaseSemaphore", "KeRaiseIrqlToDpcLevel",
        "KeLowerIrql", "KeAcquireSpinLockRaiseToSynch", "KeReleaseSpinLock",
        "HalFsbInterruptCount", "HalGetNotedArgonErrors",
        "HalNotifyBackgroundModeTransitionComplete",
        "IoReleaseCancelSpinLock",
        "ExExpansionCall",
        "PsCamDeviceRequest", "McaDeviceRequest", "DetroitDeviceRequest",
    ],
    "Xbox Crypto": [
        "XeCryptSha", "XeCryptShaUpdate", "XeCryptShaFinal", "XeCryptSha384Final",
        "HvxKeysExecute", "HvxKeysDes2Cbc", "HvxKeysRsaPrvCrypt",
        "HvxEncryptedEncryptAllocation", "HvxEncryptedReleaseAllocation",
        "HvxStartupProcessors", "HvxFlushEntireTb", "HvxFlushSingleTb",
        "HvxGetSpecialPurposeRegister", "HvxSetSpecialPurposeRegister",
        "HvxLoadImageData", "HvxFinishImageLoad", "HvxZeroPage",
        "HvxSetRevocationList", "HvxHdcpCalculateBKsvSignature",
    ],
    "Xbox AV": [
        "VdEnableHDCP", "VdEnumerateVideoModes", "VdRetrainEDRAM",
        "VdSendClosedCaptionData", "XGetVideoMode", "XGetAVPack",
        "XGetGameRegion", "XGetLanguage",
    ],
    "Xbox Kinect": [
        "XamNuiCameraElevationGetAngle", "XamNuiCameraElevationSetAngle",
        "XamNuiCameraElevationStopMovement", "XamNuiCameraRememberFloor",
        "XamNuiCameraTiltGetStatus", "XamNuiCameraTiltReportStatus",
        "XamNuiCameraTiltSetCallback", "XamNuiGetDeviceSerialNumber",
        "XamNuiGetDeviceStatus", "XamNuiIdentityGetSessionId",
        "XUsbcamCreate",
    ],
    "Xbox Avatar": [
        "XamAvatarInitialize", "XamAvatarShutdown",
        "XamAvatarGetAssets", "XamAvatarGetAssetsResultSize",
        "XamAvatarGenerateMipMaps", "XamAvatarLoadAnimation",
        "XamAvatarGetManifestLocalUser", "XamAvatarGetMetadataRandom",
        "XamAvatarManifestGetBodyType",
    ],
    "Xbox UI": [
        "XamShowNuiSigninUI", "XamShowNuiControllerRequiredUI",
        "XamShowNuiFriendsUI", "XamShowNuiGamerCardUIForXUID",
        "XamShowNuiPartyUI", "XamShowNuiDeviceSelectorUI",
        "XamShowNuiMessageBoxUI", "XamShowNuiTroubleshooterUI",
    ],
    "Xbox Voice": [
        "XamVoiceGetMicArrayAudioEx", "XamVoiceGetMicArrayUnderrunStatus",
        "XVoicedSendVPort",
    ],
    "Xbox System": [
        "XexLoadExecutable", "XamXStudioRequest",
        "XamXlfsInitializeUploadQueue", "XamXlfsMountUploadQueueInstance",
        "XamXlfsUninitializeUploadQueue", "XamXlfsUnmountUploadQueueInstance",
        "XeKeysExSaveKeyVault", "XeKeysSaveSystemUpdate",
        "XeKeysSaveBootLoaderEx", "XeKeysLockSystemUpdate",
        "XMAIsInputBuffer1Valid", "XMASetInputBuffer0",
        "XamReadBiometricData", "XamWriteBiometricData",
        "XamUserNuiEnableBiometric", "XamUserNuiGetEnrollmentIndex",
        "XamUserNuiGetUserIndex",
    ],
    "Xbox Network": [
        "NicGetOpt", "NicGetLinkState",
        "MtpdBeginTransaction", "MtpdEndTransaction",
        "MtpdCancelTransaction", "MtpdVerifyProximity",
    ],
}
REXCRT_KNOWN_NAMES = {n for group in REXCRT_GROUPS.values() for n in group}
HEAP_GROUP = set(REXCRT_GROUPS["Heap"])

# Nombres de tabla/columna candidatos a probar contra la DB de analyze.py.
CANDIDATE_FUNC_TABLES = ["functions", "funcs", "function", "Functions"]
CANDIDATE_START_COLS = ["start", "start_ea", "Start", "address", "addr", "ea"]
CANDIDATE_END_COLS = ["end", "end_ea", "End"]
CANDIDATE_SIZE_COLS = ["size", "Size", "length"]
CANDIDATE_NAME_COLS = ["name", "Name", "func_name", "symbol"]

CANDIDATE_IMPORT_TABLES = ["imports", "import", "Imports"]
CANDIDATE_IMPORT_NAME_COLS = ["name", "Name", "func_name", "symbol"]
CANDIDATE_IMPORT_ADDR_COLS = ["address", "addr", "ea", "start"]

# Nombres auto-generados que consideramos "no informativos" y por lo tanto
# no vale la pena volcar a [functions] a menos que se pase --all-functions
# (ReXGlue ya los va a nombrar sub_XXXXXXXX por su cuenta).
AUTO_NAME_PREFIXES = ("sub_", "SUB_", "FUN_", "loc_", "LOC_")


class SchemaError(RuntimeError):
    pass


def list_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return [r[0] for r in rows]


def list_columns(conn: sqlite3.Connection, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [r[1] for r in rows]


def find_table(conn: sqlite3.Connection, candidates: list[str]) -> str | None:
    tables = {t.lower(): t for t in list_tables(conn)}
    for c in candidates:
        if c.lower() in tables:
            return tables[c.lower()]
    return None


def find_column(columns: list[str], candidates: list[str]) -> str | None:
    cols = {c.lower(): c for c in columns}
    for c in candidates:
        if c.lower() in cols:
            return cols[c.lower()]
    return None


def load_functions(conn: sqlite3.Connection) -> list[dict]:
    """Devuelve [{start, end, size, name}, ...] leídos de la DB de analyze.py."""
    table = find_table(conn, CANDIDATE_FUNC_TABLES)
    if not table:
        raise SchemaError(
            f"No encontré una tabla de funciones (probé {CANDIDATE_FUNC_TABLES}). "
            f"Tablas disponibles: {list_tables(conn)}. "
            f"Ajustá CANDIDATE_FUNC_TABLES o corré con --list-schema."
        )
    cols = list_columns(conn, table)
    start_col = find_column(cols, CANDIDATE_START_COLS)
    if not start_col:
        raise SchemaError(f"No encontré columna de dirección de inicio en '{table}'. Columnas: {cols}")
    end_col = find_column(cols, CANDIDATE_END_COLS)
    size_col = find_column(cols, CANDIDATE_SIZE_COLS)
    name_col = find_column(cols, CANDIDATE_NAME_COLS)
    if not end_col and not size_col:
        raise SchemaError(f"Necesito columna 'end' o 'size' en '{table}'. Columnas: {cols}")

    select_cols = [start_col]
    select_cols += [c for c in (end_col, size_col, name_col) if c]
    query = f"SELECT {', '.join(select_cols)} FROM {table}"

    out = []
    for row in conn.execute(query):
        row = dict(zip(select_cols, row))
        start = int(row[start_col])
        end = int(row[end_col]) if end_col else start + int(row[size_col])
        size = int(row[size_col]) if size_col else end - start
        name = row.get(name_col) if name_col else None
        out.append({"start": start, "end": end, "size": size, "name": name})
    return out


def load_imports(conn: sqlite3.Connection) -> dict[str, int]:
    """Devuelve {nombre_import: direccion}. Vacío si no hay tabla de imports."""
    table = find_table(conn, CANDIDATE_IMPORT_TABLES)
    if not table:
        return {}
    cols = list_columns(conn, table)
    name_col = find_column(cols, CANDIDATE_IMPORT_NAME_COLS)
    addr_col = find_column(cols, CANDIDATE_IMPORT_ADDR_COLS)
    if not name_col or not addr_col:
        return {}
    out = {}
    for name, addr in conn.execute(f"SELECT {name_col}, {addr_col} FROM {table}"):
        if name:
            out[name] = int(addr)
    return out


def build_rexcrt(functions: list[dict], imports: dict[str, int]) -> dict[str, int]:
    """Cruza nombres conocidos de imports/funciones contra REXCRT_KNOWN_NAMES."""
    rexcrt: dict[str, int] = {}

    # 1) prioridad: import table del XEX (nombres reales de xboxkrnl/xam)
    for name, addr in imports.items():
        if name in REXCRT_KNOWN_NAMES:
            rexcrt[name] = addr

    # 2) fallback: funciones ya nombradas por IDA (firmas FLIRT, etc.)
    for f in functions:
        name = f.get("name")
        if name in REXCRT_KNOWN_NAMES and name not in rexcrt:
            rexcrt[name] = f["start"]

    # Regla all-or-nothing del grupo Heap.
    present_heap = HEAP_GROUP & rexcrt.keys()
    if present_heap and present_heap != HEAP_GROUP:
        missing = HEAP_GROUP - present_heap
        print(
            f"[!] Grupo Heap incompleto: encontré {sorted(present_heap)} pero falta "
            f"{sorted(missing)}. ReXGlue exige las 4 juntas o ninguna -> "
            f"las excluyo del [rexcrt] generado.",
            file=sys.stderr,
        )
        for n in present_heap:
            del rexcrt[n]

    unaligned = {n: hex(a) for n, a in rexcrt.items() if a % 4 != 0}
    if unaligned:
        print(f"[!] Direcciones no alineadas a 4 bytes (se excluyen): {unaligned}", file=sys.stderr)
        for n in unaligned:
            del rexcrt[n]

    return rexcrt


def select_functions_for_overrides(functions: list[dict], all_functions: bool) -> list[dict]:
    """Filtra qué funciones vale la pena volcar en [functions].

    Por default solo las que tienen un nombre "informativo" (no sub_/FUN_/etc.),
    porque ReXGlue ya auto-detecta límites razonablemente bien; el valor que
    aporta tu análisis de IDA acá es el naming, no repetir el boundary detection.
    Con --all-functions se incluyen todas (más ruido, pero permite overridear
    boundaries puntuales a mano después).
    """
    if all_functions:
        return functions
    out = []
    for f in functions:
        name = f.get("name")
        if name and not name.startswith(AUTO_NAME_PREFIXES):
            out.append(f)
    return out


def fmt_hex(n: int) -> str:
    return f"0x{n:08X}"


def toml_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def write_toml(
    path: Path,
    project_name: str,
    file_path: str,
    out_directory_path: str,
    rexcrt: dict[str, int],
    functions: list[dict],
    switch_tables: list[dict],
    invalid_instructions: list[dict],
    setjmp_address: int | None,
    longjmp_address: int | None,
) -> None:
    lines: list[str] = []
    lines.append(f'project_name = "{toml_escape(project_name)}"')
    lines.append(f'file_path = "{toml_escape(file_path)}"')
    lines.append(f'out_directory_path = "{toml_escape(out_directory_path)}"')
    lines.append("")

    if setjmp_address is not None:
        lines.append(f"setjmp_address = {fmt_hex(setjmp_address)}")
    if longjmp_address is not None:
        lines.append(f"longjmp_address = {fmt_hex(longjmp_address)}")
    if setjmp_address is not None or longjmp_address is not None:
        lines.append("")

    if rexcrt:
        lines.append("[rexcrt]")
        for name in sorted(rexcrt, key=lambda n: rexcrt[n]):
            lines.append(f"{name} = {fmt_hex(rexcrt[name])}")
        lines.append("")

    if functions:
        lines.append("[functions]")
        for f in sorted(functions, key=lambda x: x["start"]):
            fields = []
            if f.get("name"):
                fields.append(f'name = "{toml_escape(f["name"])}"')
            fields.append(f'end = {fmt_hex(f["end"])}')
            lines.append(f"{fmt_hex(f['start'])} = {{ {', '.join(fields)} }}")
        lines.append("")

    for st in switch_tables:
        lines.append("[[switch_tables]]")
        lines.append(f"address = {fmt_hex(st['address'])}")
        lines.append(f"register = {st['register']}")
        labels = ", ".join(fmt_hex(l) for l in st["labels"])
        lines.append(f"labels = [{labels}]")
        lines.append("")

    for inv in invalid_instructions:
        lines.append("[[invalid_instructions]]")
        lines.append(f"data = {fmt_hex(inv['data'])}")
        lines.append(f"size = {inv['size']}")
        lines.append("")

    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", required=True, type=Path, help="SQLite DB generada por analyze.py")
    ap.add_argument("--file-path", required=True, help="Path al XEX/ELF que va en file_path=")
    ap.add_argument("--project-name", required=True)
    ap.add_argument("--out-directory", default="generated")
    ap.add_argument("--output", type=Path, default=None, help="Default: <project-name>_config.toml")
    ap.add_argument("--switch-tables", type=Path, default=None,
                     help='JSON: [{"address":int,"register":int,"labels":[int,...]}, ...]')
    ap.add_argument("--invalid-instructions", type=Path, default=None,
                     help='JSON: [{"data":int,"size":int}, ...]')
    ap.add_argument("--setjmp-address", default=None, help="Hex, ej. 0x82001000")
    ap.add_argument("--longjmp-address", default=None, help="Hex, ej. 0x82002000")
    ap.add_argument("--all-functions", action="store_true",
                     help="Volcar TODAS las funciones a [functions], no solo las nombradas")
    ap.add_argument("--list-schema", action="store_true",
                     help="Imprime tablas/columnas de la DB y sale, para debug de schema")
    args = ap.parse_args()

    conn = sqlite3.connect(str(args.db))

    if args.list_schema:
        for t in list_tables(conn):
            print(f"{t}: {list_columns(conn, t)}")
        return 0

    try:
        functions = load_functions(conn)
    except SchemaError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        return 1
    imports = load_imports(conn)

    rexcrt = build_rexcrt(functions, imports)
    func_overrides = select_functions_for_overrides(functions, args.all_functions)

    switch_tables = json.loads(args.switch_tables.read_text()) if args.switch_tables else []
    invalid_instructions = json.loads(args.invalid_instructions.read_text()) if args.invalid_instructions else []

    setjmp_addr = int(args.setjmp_address, 16) if args.setjmp_address else None
    longjmp_addr = int(args.longjmp_address, 16) if args.longjmp_address else None

    out_path = args.output or Path(f"{args.project_name}_config.toml")
    write_toml(
        out_path,
        project_name=args.project_name,
        file_path=args.file_path,
        out_directory_path=args.out_directory,
        rexcrt=rexcrt,
        functions=func_overrides,
        switch_tables=switch_tables,
        invalid_instructions=invalid_instructions,
        setjmp_address=setjmp_addr,
        longjmp_address=longjmp_addr,
    )

    print(f"[+] {out_path}")
    print(f"    funciones totales en DB: {len(functions)}")
    print(f"    funciones volcadas a [functions]: {len(func_overrides)}")
    print(f"    [rexcrt] resueltos: {len(rexcrt)} / {len(REXCRT_KNOWN_NAMES)} conocidos")
    print(f"    switch_tables: {len(switch_tables)}  invalid_instructions: {len(invalid_instructions)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
