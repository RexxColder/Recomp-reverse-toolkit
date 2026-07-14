# Reverse Engineering Toolkit + Recomp

Skill para análisis exhaustivo de binarios usando IDA Pro. Soporta Xbox 360 (PowerPC) y PlayStation 2 (MIPS R5900). Produce bases de datos SQLite + Knowledge Base markdown.

## Qué hace

Esta skill permite:

1. Abrir binarios en IDA headless (idalib)
2. Extraer y decompilar todas las funciones
3. Extraer strings, imports, cross-references
4. Clasificar funciones por subsistemas
5. Renombrar funciones automáticamente
6. Generar SQLite database queryable
7. Generar Knowledge Base markdown para Claude

## Plataformas soportadas

| Plataforma | CPU | Formato | Procesador IDA |
|------------|-----|---------|----------------|
| Xbox 360 | PowerPC (Big-endian) | XEX → PE | `ppc` |
| PlayStation 2 | MIPS R5900 (Little-endian) | ELF | `mips` |

## Dependencias

- IDA Pro 9.0+ con Hex-Rays decompiler
- Python 3.10+ con módulo `idapro`
- xextool (para Xbox 360)
- Plugins PS2: `ida-emotionengine.py`, `ps2_ida_vu_micro.py`

## Estructura del skill

El archivo `SKILL.md` contiene:

- Referencia de hardware (Xbox 360, PS2)
- Formatos de archivo (XEX, ELF, STFS)
- Arquitectura de seguridad
- Referencia PPC y MIPS
- Workflow completo de análisis (sección 22)
- Batch analysis para múltiples juegos (sección 23)
- Análisis completados con estadísticas (sección 24)

## Análisis completados

| Juego | Platform | Functions | Decompiled | Xrefs | DB |
|-------|----------|-----------|------------|-------|-----|
| Skate 3 TU4 | Xbox 360 | 40,518 | 40,285 | 2,877 | 39 MB |
| Sonic Free Riders | Xbox 360 | 23,341 | 23,242 | 2,450 | 31 MB |
| Sonic Riders ZG | PS2 | 17,745 | 17,742 | 62,274 | 27 MB |
| Tony Hawk Downhill Jam | PS2 | 12,923 | 11,756 | 43,272 | 18 MB |
| Biohazard Outbreak | PS2 | 4,875 | 4,849 | 12,836 | 5 MB |
| Biohazard Outbreak 2 | PS2 | 4,936 | 4,897 | 13,136 | 5 MB |

## Uso

El archivo `SKILL.md` se carga automáticamente cuando se invoca la skill `ida-pro` desde un agente. Contiene todo el conocimiento necesario para realizar análisis de binarios Xbox 360 y PS2.
