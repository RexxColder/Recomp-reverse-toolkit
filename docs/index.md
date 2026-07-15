# Recomp Reverse Toolkit

Herramientas de análisis y recompilación de binarios para **PS2** (MIPS R5900) y **Xbox 360** (PowerPC) usando IDA Pro.

## Qué hace

Analiza binarios de consolas y genera:
- **SQLite database** con funciones, código decompilado, strings y xrefs
- **Knowledge Base** markdown con executive summary
- **JSON exports** categorizados por tipo
- **CSV + TOML** para PS2Recomp (recompilación estática de PS2)

## Instalación

### 1. IDA Pro 9.0+

```bash
# Verificar instalación
/path/to/IDA/idat --version

# Verificar idalib (Python module)
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" python3 -c "import idapro; print('OK')"
```

**Requisitos:**
- IDA Pro 9.0+ con licencia válida
- Hex-Rays decompiler (para decompilación)
- Módulo `idapro` (viene con IDA)

### 2. Python 3.10+

```bash
python3 --version  # Debe ser 3.10+
```

### 3. PS2Recomp Source (para SCE symbol database)

```bash
git clone https://github.com/ran-j/PS2Recomp.git
# La base de datos se auto-extrae de:
# ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h
```

### 4. xextool (solo para Xbox 360)

```bash
# Compilar desde source o descargar binario
# Requerido para extraer PE de XEX
xextool -b output.bin game.xex
```

### 5. gh CLI (para push a GitHub)

```bash
# Linux
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt update && sudo apt install gh

# macOS
brew install gh

# Autenticar
gh auth login
```

## Uso rápido

### PS2 (ELF)

```bash
# Análisis completo: DB + Knowledge Base + JSON + CSV + TOML
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py game.elf /output/dir

# Output:
#   /output/dir/game.db              (SQLite)
#   /output/dir/GAME_KNOWLEDGE_BASE.md
#   /output/dir/export/              (JSONs)
#   /output/dir/functions.csv        (PS2Recomp)
#   /output/dir/config.toml          (PS2Recomp)
```

### Xbox 360 (XEX)

```bash
# Primero extraer PE
xextool -b game_pe.bin game.xex

# Análisis completo: DB + Knowledge Base + JSON
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py game_pe.bin /output/dir

# Output:
#   /output/dir/game_pe.db          (SQLite)
#   /output/dir/GAME_PE_KNOWLEDGE_BASE.md
#   /output/dir/export/             (JSONs)
```

### Batch (múltiples PS2 ISOs)

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py --batch /path/to/isos/ /output/dir
```

## Estructura del repo

```
Recomp-reverse-toolkit/
├── analyze.py              # Entry point unificado (PS2 + Xbox 360)
├── ps2_recomp_export.py    # Export CSV + TOML para PS2Recomp
├── ps2_full_analysis.py    # Análisis IDA completo (DB + KB + JSON)
├── sce_symbols.json        # Base de datos SCE (auto-generada, 8MB)
├── SKILL.md                # Documentación completa (MCP skill)
├── README.md               # Este archivo
├── GUIDE.md                # Guía de usuario paso a paso
└── .gitignore
```

## Output por plataforma

### PS2
```
<nombre>_PS2/
├── <nombre>.db                    # SQLite (functions, decompiled, strings, xrefs)
├── <NOMBRE>_KNOWLEDGE_BASE.md     # Executive summary + SDK libs + strings
├── config.toml                    # PS2Recomp config (stubs, patches)
├── functions.csv                  # Function map (Name,Start,End,Size)
└── export/
    ├── decompiled_Unknown.json
    ├── segments.json
    ├── strings_PS2_SDK.json
    ├── strings_ERROR.json
    └── Unknown.json
```

### Xbox 360
```
<nombre>_Xbox360/
├── <nombre>.db                    # SQLite (functions, decompiled, strings, xrefs)
├── <NOMBRE>_KNOWLEDGE_BASE.md     # Executive summary + imports + strings
└── export/
    ├── decompiled_Unknown.json
    ├── segments.json
    ├── strings_XBOX_SDK.json
    └── Unknown.json
```

## Resultados probados

### PS2
| Juego | Funciones | SDK | Decompiled | Strings |
|-------|-----------|-----|------------|---------|
| Sonic Riders ZG | 17,778 | 1,296 | 17,778 | 8,470 |
| Tony Hawk Downhill Jam | 11,626 | 1,471 | 11,626 | 7,234 |
| DBZ Budokai Tenkaichi 3 | 8,126 | 604 | 8,126 | 2,023 |
| Biohazard Outbreak | 4,775 | 575 | 4,775 | 2,602 |
| Biohazard Outbreak File 2 | 4,835 | 589 | 4,835 | 2,903 |

### Xbox 360
| Juego | Funciones | Decompiled | Strings |
|-------|-----------|------------|---------|
| Skate 3 TU4 | 40,518 | 40,285 | 4,661 |
| Sonic Free Riders | 23,341 | 23,242 | 8,635 |

## Licencia

MIT
