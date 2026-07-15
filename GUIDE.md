# Guía de Usuario — Recomp Reverse Toolkit

Guía paso a paso para analizar binarios de PS2 y Xbox 360 con IDA Pro.

---

## 1. Instalación

### Paso 1: Instalar IDA Pro

1. Descargar IDA Pro 9.0+ desde https://hex-rays.com/ida-pro/
2. Instalar con licencia válida
3. Verificar:
```bash
/path/to/IDA/idat --version
```

### Paso 2: Verificar Python y idalib

```bash
# Python 3.10+
python3 --version

# idalib (viene con IDA)
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" python3 -c "import idapro; print('idalib OK')"
```

Si `idapro` no se encuentra:
```bash
export PYTHONPATH="/path/to/IDA Pro:/path/to/IDA Pro/python:$PYTHONPATH"
```

### Paso 3: Clonar PS2Recomp (para SCE database)

```bash
git clone https://github.com/ran-j/PS2Recomp.git /path/to/PS2Recomp
```

La base de datos SCE se auto-extrae de:
`ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h`

### Paso 4: Instalar xextool (solo Xbox 360)

```bash
# Compilar desde source o descargar binario
# Requerido para extraer PE de archivos XEX
```

---

## 2. Analizar un juego PS2

### Requisitos
- Archivo ELF del juego (extraído de ISO/backup)
- IDA Pro con Hex-Rays
- PS2Recomp source (para SCE database)

### Paso 1: Extraer ELF del ISO

```bash
# Usando 7z
7z e -o/tmp/game game.iso SYSTEM.CNF
cat /tmp/game/SYSTEM.CNF  # Buscar BOOT2 = cdrom0:\SLUS_XXX.XX;1

7z e -o/tmp/game game.iso SLUS_XXX.XX
file /tmp/game/SLUS_XXX.XX  # Debe decir "ELF 32-bit LSB executable, MIPS"
```

### Paso 2: Ejecutar análisis

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py /tmp/game/SLUS_XXX.XX /output/game_PS2
```

### Paso 3: Verificar output

```bash
ls /output/game_PS2/
# game.db              → SQLite database
# GAME_KNOWLEDGE_BASE.md → Knowledge Base
# config.toml          → PS2Recomp config
# functions.csv        → Function map
# export/              → JSON exports
```

### Paso 4: Usar con PS2Recomp

```bash
# Copiar output al runtime
cp /output/game_PS2/config.toml ps2xRuntime/
cp /output/game_PS2/functions.csv ps2xRuntime/

# Recompilar
ps2_recomp /output/game_PS2/config.toml
```

---

## 3. Analizar un juego Xbox 360

### Requisitos
- Archivo XEX del juego
- IDA Pro con Hex-Rays
- xextool

### Paso 1: Extraer PE del XEX

```bash
xextool -b /tmp/game_pe.bin game.xex
```

**NOTA:** El PE extraído NO es un PE válido. Cargarlo como **Binary file** con procesador **PowerPC** en IDA.

### Paso 2: Ejecutar análisis

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py /tmp/game_pe.bin /output/game_Xbox360
```

### Paso 3: Verificar output

```bash
ls /output/game_Xbox360/
# game_pe.db              → SQLite database
# GAME_PE_KNOWLEDGE_BASE.md → Knowledge Base
# export/                 → JSON exports
```

---

## 4. Batch processing (múltiples PS2 ISOs)

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py --batch /path/to/PS2_ISOs/ /output/dir
```

Procesa todos los `.iso` del directorio, extrae ELFs automáticamente.

---

## 5. Troubleshooting

### "idalib not found"
```bash
export PYTHONPATH="/path/to/IDA Pro:/path/to/IDA Pro/python:$PYTHONPATH"
```

### "Hex-Rays not available"
- Verificar que IDA tiene licencia de decompiler
- Sin decompiler, la decompilación falla (pero el análisis básico funciona)

### "SCE database not found"
- Verificar que PS2Recomp está clonado
- El path está hardcodeado en el script: `/mnt/Datos/Proyectos/PS2Recomp/...`
- Cambiar `PS2RECOMP_HEADER` en el script si es necesario

### "xextool not found" (Xbox 360)
- Compilar desde source o descargar binario pre-compilado
- Sin xextool, no se puede extraer PE de XEX

### "Functions: 0" (PS2)
- IDA no auto-analizó el ELF correctamente
- Verificar que el ELF es MIPS (no ARM, no x86)
- Intentar con `readelf -h game.elf` para verificar arquitectura

### "UNIQUE constraint failed" (SQLite)
- Ocurrió cuando hay segmentos duplicados
- Ya corregido en el script con `INSERT OR REPLACE`

---

## 6. Formatos de output

### SQLite Database (.tab习近平总)
```sql
-- Funciones
SELECT * FROM functions WHERE category = 'sdk';

-- Código decompilado
SELECT code FROM decompiled WHERE address = 0x100000;

-- Strings por categoría
SELECT * FROM strings WHERE category = 'PS2_SDK';

-- Cross-references
SELECT * FROM xrefs WHERE from_address = 0x100000;
```

### Knowledge Base (markdown)
- Executive Summary (stats)
- SDK Libraries (nombre + count)
- String Categories (categorías + count)

### CSV (PS2Recomp)
```
Name,Start,End,Size
sceGsSyncV,0x00102F68,0x00102F68,148
sceDmaSend,0x00103E08,0x00103E08,104
```

### TOML (PS2Recomp)
```toml
[general]
input = "SLUS_216.42"
stubs = ["libgraph::sceGsSyncV@0x00102F68", ...]
```

---

## 7. Ejemplo completo (Sonic Riders ZG)

```bash
# 1. Extraer ELF
7z e -o/tmp/sonic "Sonic Riders - Zero Gravity.iso" SYSTEM.CNF
7z e -o/tmp/sonic "Sonic Riders - Zero Gravity.iso" SLUS_216.42

# 2. Analizar
PYTHONPATH="/mnt/Datos/Herramientas/IDA Pro:/mnt/Datos/Herramientas/IDA Pro/python:$PYTHONPATH" \
  python3 analyze.py /tmp/sonic/SLUS_216.42 /output/Sonic_Riders_ZG

# 3. Verificar
ls /output/Sonic_Riders_ZG/
# SLUS_216.db
# SLUS_216_KNOWLEDGE_BASE.md
# config.toml
# functions.csv
# export/

# 4. Usar con PS2Recomp
ps2_recomp /output/Sonic_Riders_ZG/config.toml
```
