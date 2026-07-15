# IDA Pro Reverse Engineering Skill

Skill para análisis exhaustivo de binarios usando IDA Pro. Soporta Xbox 360 (PowerPC) y PlayStation 2 (MIPS R5900).

## Qué incluye

- `SKILL.md` — Documentación completa (hardware, formatos, workflows, exploits)
- `ps2_recomp_export.py` — Script para generar CSV + TOML para PS2Recomp
- `sce_symbols.json` — Base de datos de firmas SDK PS2 (auto-generada, 8MB)

## PS2Recomp Export Tool

Genera CSV function map y TOML config para ps2xRecomp desde ELF PS2.

### Uso

```bash
# Single file
PYTHONPATH="/path/to/IDA/idalib/python:$PYTHONPATH" \
  python3 ps2_recomp_export.py game.elf /output/dir

# Batch (todos los ISOs en un directorio)
PYTHONPATH="/path/to/IDA/idalib/python:$PYTHONPATH" \
  python3 ps2_recomp_export.py --batch /path/to/isos/ /output/dir
```

### Características

- SCE SHA-1 signature matching (52 SDK libraries, 5,323 function names)
- Detección de código (syscalls positivos/negativos, MMIO, thunks)
- Batch mode para procesar múltiples juegos
- Auto-extracción de la base de datos desde PS2Recomp source

### Resultados probados

| Juego | Funciones | SDK Matches | Librerías |
|-------|-----------|-------------|-----------|
| Sonic Riders ZG | 17,745 | 1,295 | 15+ |
| Tony Hawk Downhill Jam | 11,626 | 1,471 | 15+ |
| DBZ Budokai Tenkaichi 3 | 8,126 | 604 | 15+ |
| Biohazard Outbreak | 4,775 | 575 | 15 |
| Biohazard Outbreak File 2 | 4,835 | 589 | 15 |

## Análisis completados (Xbox 360)

| Juego | Platform | Functions | Decompiled | Xrefs | DB |
|-------|----------|-----------|------------|-------|-----|
| Skate 3 TU4 | Xbox 360 | 40,518 | 40,285 | 2,877 | 39 MB |
| Sonic Free Riders | Xbox 360 | 23,341 | 23,242 | 2,450 | 31 MB |

## Dependencias

- IDA Pro 9.0+ con Hex-Rays decompiler
- Python 3.10+ con módulo `idapro`
- xextool (para Xbox 360)
- PS2Recomp source (para auto-extraction de SCE DB)
