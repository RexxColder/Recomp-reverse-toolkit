---
name: ida-pro
description: Reverse engineering and binary analysis using IDA Pro. Supports Xbox 360 (PowerPC) and PS2 (MIPS R5900) architectures. Produces SQLite databases + Knowledge Base markdown for Claude consumption.
---

# IDA Pro — Multi-Architecture Reverse Engineering Skill

## Overview
Comprehensive binary analysis using IDA Pro headless (idalib). Supports:
- **Xbox 360** (PowerPC, XEX/PE format)
- **PS2** (MIPS R5900 Emotion Engine, ELF format)

**Primary Product**: SQLite database (`game.db`) + Knowledge Base markdown (`GAME_KNOWLEDGE_BASE.md`)

---

## DEPENDENCIES

### Required Software

| Dependency | Version | Purpose | Platform |
|------------|---------|---------|----------|
| **IDA Pro** | 9.0+ | Binary analysis + decompilation | Both |
| **idapro** Python module | - | Headless IDA API | Both |
| **Python** | 3.10+ | Script execution | Both |
| **xextool** | 6.3+ | XEX extraction/decryption | Xbox 360 only |
| **readelf** | - | ELF verification | PS2 only |

### IDA Plugins (Recommended)

| Plugin | Purpose | Platform | Install |
|--------|---------|----------|---------|
| **hexx64.so / hexmips.so** | Hex-Rays decompiler | Both | Comes with IDA |
| **ida-emotionengine.py** | COP2/VU0 disassembly | PS2 | Copy to `plugins/` |
| **ps2_ida_vu_micro.py** | VU microcode analysis | PS2 | Copy to `plugins/` |

### Python Module Verification

```bash
# Verify idapro module is available
python3 -c "import idapro; print(idapro.get_ida_install_dir())"

# If not found, add IDA to PYTHONPATH
export PYTHONPATH="/path/to/IDA Pro:$PYTHONPATH"

# Verify idaapi works after open_database
python3 -c "
import idapro
idapro.open_database('/tmp/test.bin', run_auto_analysis=True)
import idaapi, ida_funcs, ida_hexrays
print('IDA modules loaded OK')
"
```

### IDA License

- **idalib** (headless) requires a valid IDA license
- For batch analysis, use `idapro.open_database()` not interactive IDA
- Hex-Rays decompiler license required for pseudocode generation

### Disk Space

| Analysis Type | Xbox 360 | PS2 |
|---------------|----------|-----|
| Binary extraction | 30-50 MB | N/A (ELF direct) |
| IDA database | 50-200 MB | 50-200 MB |
| SQLite output | 30-50 MB | 20-30 MB |
| Knowledge Base | 10-70 KB | 10-70 KB |
| **Total per game** | **~300 MB** | **~250 MB** |

---

## ARCHITECTURE COMPARISON

| Aspect | Xbox 360 | PS2 |
|--------|----------|-----|
| CPU | PowerPC Xenon (Big-endian) | MIPS R5900 Emotion Engine (Little-endian) |
| File Format | XEX → PE (raw binary) | ELF (direct load) |
| IDA Processor | `ppc` | `mips` |
| Entry Point | 0x82000000 (PE base) | 0x100008 (ELF entry) |
| Calling Convention | PPC ABI (r3-r10 params) | MIPS O32/N32 ($a0-$a3 params) |
| Decompiler | hexx64.so (PPC) | hexmips.so (MIPS) |
| Special Plugins | ppc_altivec.py (VMX128) | ida-emotionengine.py (COP2/VU0) |
| SDK Functions | XNet*, NetDll*, D3D* | sceGs*, sceGif*, scePad* |
| Syscalls | XAPI ordinals (xboxkrnl) | PS2 kernel calls |
| GPU | Xenos (unified shaders) | GS Graphics Synthesizer |
| Audio | XMA hardware decoder | SPU2 |
| I/O | STFS packages | IOP modules (.irx) |
| String Encoding | ASCII/UTF-8 | ASCII (sometimes Shift-JIS) |
| Typical Binary Size | 10-50 MB | 2-10 MB |
| Typical Functions | 20,000-50,000 | 10,000-25,000 |

---

## 1. HARDWARE REFERENCE

### CPU - Xenon (IBM PowerPC)

| Specification | Value |
|---------------|-------|
| Cores | 3 |
| Threads per core | 2 (SMT) |
| Total threads | 6 |
| Clock | 3.2 GHz |
| Architecture | PowerPC (Big-endian) |
| L1 cache | 32KB I + 32KB D per core |
| L2 cache | 1MB shared (lockable by GPU) |
| L2 bandwidth | 51.2 GB/s (256-bit @ 1.6 GHz) |
| VMX128 | 128 registers × 128 bits per thread |
| Execution | In-order, 2-issue per cycle |
| Transistors | 165 million |
| Process | 90nm (initial), 65nm, 45nm, 32nm |
| FSB bandwidth | 21.6 GB/s |
| Dot product | 9.6 billion/second |
| SMT | Yes (first game console with SMT) |

**CPU Core Details:**
- 64-bit PowerPC ISA
- Complete PowerPC ISA available
- VMX128 extension (customized for graphics)
- Two-per-cycle in-order instruction issuance
- Vector/scalar issue queue (VIQ) decouples issuance
- Extensive clock gating for power reduction
- Procedural geometry support (CPU generates triangles for GPU)

**VMX128 Registers:**
- 128 registers × 128 bits per thread
- 256 physical vector registers (128 × 2 threads)
- Much larger than standard VMX/Altivec (32 registers)
- Vec4 + scalar operations per cycle

### GPU - Xenos (ATI)

| Specification | Value |
|---------------|-------|
| Shader cores | 48 unified |
| Clock | 500 MHz |
| EDRAM | 10MB (256 GB/s) |
| Memory controllers | 2 × 1024-bit |
| GDDR3 bandwidth | 22.4 GB/s |
| FSB bandwidth | 10.8 GB/s bidirectional |
| Pixel fill rate | 4 billion pixels/sec |
| Geometry rate | 500 million triangles/sec |
| Features | Tessellator, HDR, Address tiling |
| Shader ops | 240 billion/second |
| GFLOPS | 240 peak |
| ALU width | 32-bit IEEE 754 |
| Texture fetch | 16 units |
| Vertex fetch | 16 units |
| First unified shader GPU | Yes (revolutionary) |

**GPU Architecture:**
```
Unified Shader (48 ALUs)
├── 3 SIMDs × 16 shaders
├── Vec4 + scalar operations
├── Dynamic allocation (vertex/pixel)
│
├── Texture Fetch (16 units)
│   ├── LOD computation
│   ├── Linear/Trilinear filtering
│   └── Unified texture cache
│
├── Vertex Fetch (16 units)
│   └── Vertex-style data cache
│
└── Output Buffer
    ├── EDRAM (10MB, 256 GB/s)
    ├── Color/Z/Stencil
    └── MSAA (4x lossless)
```

**Unified Shader Benefits:**
- GPU-based vertex and pixel load balancing
- Better resource usage (union of features)
- Control flow, indexable constants
- DX9 Shader Model 3.0+ compatible
- First GPU to process 10 billion vertex shader instructions/second

**EDRAM Daughter Die:**
- Separate 90nm chip (NEC)
- 10MB embedded DRAM
- 256 GB/s bandwidth
- Color, Z, stencil operations
- MSAA logic (4x lossless)
- Lossless Z compression

### Memory Map

| Address | Size | Description |
|---------|------|-------------|
| 0x00000000 | - | Reserved (System) |
| 0x20000000 | 512MB | Physical RAM start (GDDR3) |
| 0x7FFFFFFF | - | Physical RAM end |
| 0xC0000000 | - | Aliased memory (physical mirrors) |
| 0xE0000000 | - | Memory Mapped I/O (GPU, Southbridge) |

**Virtual Memory Map (Detailed):**

| Region | Range | Page Size | Purpose |
|--------|-------|-----------|---------|
| User Virtual | 0x00000000-0x3FFFFFFF | 4KB | General allocations |
| User Virtual | 0x40000000-0x7FFFFFFF | 64KB | Large allocations |
| XEX Code | 0x80000000-0x8BFFFFFF | 64KB | Game code |
| XEX Encrypted | 0x8C000000-0x8FFFFFFF | 64KB | Encrypted sections |
| XEX Data | 0x90000000-0x9FFFFFFF | 4KB | Game data |
| Physical | 0xA0000000-0xBFFFFFFF | 64KB | Physical memory |
| Physical | 0xC0000000-0xDFFFFFFF | 16MB | Large physical |
| Physical | 0xE0000000-0xFFFFFFFF | 4KB | MMIO/Devices |

**Page Table Entry Bits:**
- Present, Read/Write, Execute, Cacheable
- Guard pages, copy-on-write
- Protection levels (user/kernel)
- Hypervisor-managed encryption

**Memory Regions:**
- **Kernel Space**: Encrypted, Hashed by Hypervisor
- **User Space**: Game code, data, heap, stack
- **HRMO Register**: Controls memory aliasing
- **L2 Cache**: Lockable by GPU for procedural geometry

### Motherboard Revisions

| Name | Process | GPU | Notes |
|------|---------|-----|-------|
| Xenon | 90nm | Y1 | First gen, RROD prone |
| Zephyr | 90nm | Y1 | HDMI added |
| Falcon | 65nm CPU, 90nm GPU | Y2 | Better thermals |
| Jasper | 65nm CPU+GPU | Zeus | Most reliable phat |
| Tonasket | Jasper revision | Zeus | |
| Trinity | 65nm XCGPU | Vejle | Slim, most common |
| Corona | 45nm XCGPU | Vejle | Slim, cost-reduced |
| Waitsburg | Corona revision | Vejle | |
| Stingray | Waitsburg revision | Vejle | |
| Winchester | 32nm | Oban | Final revision, single die |

**SoC Evolution:**
- 2005: 90nm CPU + GPU (separate dies)
- 2007: 65nm CPU + 90nm GPU
- 2008: 65nm CPU + GPU
- 2009: 45nm XCGPU (single die)
- 2011: 32nm Oban (final)

### Bus Bandwidth Summary

| Connection | Bandwidth | Type |
|------------|-----------|------|
| CPU → L2 Cache | 51.2 GB/s | 256-bit @ 1.6 GHz |
| FSB (CPU ↔ GPU) | 10.8 GB/s | Bidirectional |
| GPU → GDDR3 | 22.4 GB/s | 2× 1024-bit @ 700 MHz |
| GPU → EDRAM | 256 GB/s | Embedded |
| GPU → Daughter Die | 32 GB/s | 128-byte interleaved |
| USB 2.0 | 480 Mbps | Per port |
| SATA | 1.5 Gbps | HDD/DVD |

**FSB Design:**
- Source synchronous architecture
- Non-coded data (low latency)
- CPU PHY: 90nm SOI (IBM)
- GPU PHY: 90nm bulk (TSMC)
- 70mm short path
- Phase rotators for clock alignment

---

## 2. FILE FORMATS

### XEX2 Header Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | Magic | "XEX2" (0x58455832) |
| 0x04 | 4 | Module flags | See flag table below |
| 0x08 | 4 | PE data offset | Offset to PE inside XEX |
| 0x0C | 4 | Reserved | |
| 0x10 | 4 | Security info offset | |
| 0x14 | 4 | Optional header count | |
| 0x18 | varies | Optional headers[] | |

**Module Flags:**
- Bit 0: Title Module
- Bit 1: Exports To Title
- Bit 2: System Debugger
- Bit 3: DLL Module
- Bit 4: Module Patch
- Bit 5: Full Patch
- Bit 6: Delta Patch
- Bit 7: User Mode

### Optional Headers

| ID | Name | Description |
|----|------|-------------|
| 0x2FF | Resource Information | |
| 0x3FF | Basefile Format | Encryption, compression |
| 0x405 | Base Reference | |
| 0x5FF | Delta Patch Descriptor | XEXP patch data |
| 0x80FF | Bounding Path | |
| 0x8105 | Device ID | |
| 0x10001 | Original Base Address | |
| 0x10100 | Entry Point | |
| 0x10201 | Image Base Address | |
| 0x103FF | Import Libraries | |
| 0x18002 | Checksum Timestamp | |
| 0x183FF | Original PE Name | |
| 0x200FF | Static Libraries | |
| 0x20104 | TLS Info | |
| 0x20200 | Default Stack Size | |
| 0x20401 | Default Heap Size | |
| 0x30000 | System Flags | |
| 0x40006 | Execution ID | Title ID, Media ID |
| 0x405FF | Xbox 360 Logo | |
| 0x406FF | Multidisc Media IDs | |
| 0x407FF | Alternate Title IDs | |

### Security Info Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x000 | 4 | Header size | |
| 0x004 | 4 | Image size | |
| 0x008 | 160 | RSA signature | Microsoft signature |
| 0x108 | 4 | Resulting image size | |
| 0x10C | 4 | Load address | |
| 0x140 | 16 | Media ID | Unique per disc |
| 0x150 | 16 | AES key seed | For section encryption |
| 0x164 | 20 | SHA hash | |
| 0x178 | 4 | Region code | |
| 0x17C | 20 | SHA hash | |
| 0x180 | 4 | Image data count | |
| 0x184+ | 24 each | Image data entries | Section descriptors |

### XEXP Delta Patch Descriptor (0x5FF)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | Size | Descriptor size |
| 0x04 | 4 | Target Version | Target dashboard version |
| 0x08 | 4 | Source Version | Original dashboard version |
| 0x0C | 20 | Source Hash | SHA-1 of original XEX |
| 0x20 | 16 | Encryption Seed | AES seed |
| 0x30 | 4 | Target Headers Length | |
| 0x34 | 4 | Delta Headers Source Location | |
| 0x38 | 4 | Delta Headers Source Size | |
| 0x3C | 4 | Delta Headers Target Location | |
| 0x40 | 4 | Delta Image Source Location | |
| 0x44 | 4 | Delta Image Source Size | |
| 0x48 | 4 | Delta Image Target Location | |
| 0x4C | variable | Patch Data | Binary diff data |

### XEX Encryption

- **Algorithm**: AES-128-CBC per section
- **Key derivation**: Per-title keys from media ID
- **Compression**: LDIC (Microsoft proprietary, same as Xbox 1)
- **Debug XEX**: Can be unencrypted/unpacked
- **Section encryption**: Different key per file

### STFS Package Types

| Type | Magic | Description |
|------|-------|-------------|
| CON | - | Console-created (local) |
| LIVE | "LIVE" | Xbox Live downloaded |
| PIRS | "PIRS" | Pre-installed content |

**STFS Details:**
- Block size: 0x1000 (4096 bytes)
- Hash tables every 170 blocks (0xAA)
- Master hash table at 0x3000
- SHA-1 hashes (truncated to 0x18 bytes)
- RSA signature in header
- Supports DLC, Title Updates, Saves, Profiles

---

## 3. SECURITY ARCHITECTURE

### Bootloader Chain

```
1BL (CPU ROM, 32KB)
  │
  └→ CB (2BL, NAND)
        │
        └→ CB_A → CB_B (split 2BL, newer kernels)
              │
              └→ CD (4BL)
                    │
                    └→ CE (5BL) - Base kernel + hypervisor
                          │
                          └→ CF (6BL) - Patch loader
                                │
                                └→ CG (7BL) - Delta patches
                                      │
                                      └→ Patched kernel boots
```

**Boot Sequence Details:**
1. **1BL** (First Boot Loader): ROM inside CPU, 32KB
   - Sets up hardware registers
   - Loads, decrypts, verifies CB
   - 1BL Key: Same for ALL consoles

2. **CB** (2nd Boot Loader): NAND
   - **Old kernels**: Single CB
   - **New kernels**: Split into CB_A + CB_B
   - CB_A: Relocates, reads CPU Key, decrypts CB_B
   - CB_B: Hash verification, loads CD
   - **RGH2 exploit**: Timing attack during CB_B hash comparison

3. **CD** (4BL): NAND
   - Decompresses CE (base kernel + hypervisor)
   - Checks for delta patches in patch slots

4. **CE** (5BL): NAND
   - Contains LZX compressed base hypervisor + kernel
   - Base version: 2.0.1888

5. **CF/CG** (6BL/7BL): Patch slots
   - CF loads CG (delta patch)
   - Applies patches in memory
   - Boots patched kernel

### Hypervisor

**Responsibilities:**
- Memory encryption/decryption (AES-128 CBC)
- Memory access restrictions
- Cryptographic signatures
- System calls

**Execution Mode:**
- Real-Mode with highest privileges
- Memory paging disabled
- Can access any memory space
- User-mode cannot read/write HV space

**System Calls:**

| Number | Function | Purpose |
|--------|----------|---------|
| 0 | HvxGetImagePageTableEntry | Read page table |
| 16 | HvxSetImagePageTableEntry | Write page table |
| 20 | HvxLoadImageData | Load XEX sections |
| 24 | HvxFinishImageLoad | Complete XEX load |
| 75 | HvxKeysExCreateKeyVault | Create keyvault |
| 76 | HvxKeysExLoadKeyVault | Load keyvault |
| 94 | HvxImageTransformImageKey | Decrypt image key |
| 95 | HvxImageXexHeader | Parse XEX header |
| 96 | HvxRevokeLoad | Load revocation data |
| 100 | HvxKeysLoadKeyVault | Load encrypted keys |
| 101 | HvxXexActivationGetNonce | Activation nonce |
| 102 | HvxXexActivationSetLicense | Set license |
| 103 | HvxXexActivationVerifyOwnership | Verify ownership |

**Interrupt Vectors:**
- System Reset
- Machine Check
- Data Storage
- Instruction Storage
- External Interrupt
- Alignment
- Program
- Floating Point
- Decrementer
- System Call
- Trace

### Encryption

| Algorithm | Use |
|-----------|-----|
| AES-128 | XEX encryption, content protection |
| HMAC-SHA1 | Package integrity verification |
| RSA-2048 | Signature verification (bootloaders, XEX) |
| XeKeys | Hardware security keys |
| LDIC | Compression (Microsoft proprietary) |

**Key Hierarchy:**
```
1BL Key (CPU ROM, same for all)
  │
  └→ CB Key = 1BL Key + Salt
        │
        └→ CB_B Key = CB Key + CPU Key + Salt (retail)
        │            CB Key + Salt (MFG - no CPU key)
        │
        └→ CE Key = derived from CB
              │
              └→ Kernel/HV keys
```

### eFuse Security

**Fusesets:**
- 12 fusesets × 256 bits each
- One-time programmable
- Located inside CPU

**Key Derivation:**
- Fuseset #03 + #05 (or #04 + #06) = CPU Key
- CPU Key: Unique per console
- Used to encrypt keyvault

**Lockdown Counter:**
- Prevents downgrade
- Must match fuse value
- If counter < fuse value → boot refused

### Keyvault Contents

- Serial number
- Manufacture date
- DVD key
- Console certificates
- Online credentials
- Encrypted by CPU Key

---

## 4. PPC REFERENCE

### Register Map

**General Purpose Registers (GPR):**

| Register | Name | Usage |
|----------|------|-------|
| r0 | | Volatile, used in prologs |
| r1 | SP | Stack pointer |
| r2 | TOC | Table of Contents pointer |
| r3-r10 | | Volatile, function parameters/return |
| r11 | | Volatile, environment pointer |
| r12 | | Volatile, exception handling |
| r13 | TLS | Thread-local storage |
| r14-r31 | | Non-volatile, local variables |

**Floating Point Registers (FPR):**

| Register | Usage |
|----------|-------|
| f0-f13 | Volatile |
| f14-f31 | Non-volatile |

**VMX128 Registers:**

| Register | Usage |
|----------|-------|
| v0-v1 | Volatile |
| v2-v13 | Volatile, vector parameters |
| v14-v19 | Volatile scratch |
| v20-v31 | Non-volatile |

**Special Registers:**

| Register | Name | Usage |
|----------|------|-------|
| CTR | Count Register | Loop counter |
| LR | Link Register | Return address |
| CR | Condition Register | 8 × 4-bit fields |
| MSR | Machine State Register | |
| XER | Integer Exception Register | |
| VRSAVE | VMX Save Register | |

### VMX128 Instructions

**Load/Store:**
- `lvewx128` - Load Vector128 Element Word Indexed
- `stvewx128` - Store Vector128 Element Word Indexed
- `lvxl128` - Load Vector128 Indexed Last
- `stvxl128` - Store Vector128 Indexed Last

**Arithmetic:**
- `vaddfp128` - Vector128 Add Floating Point
- `vsubfp128` - Vector128 Subtract Floating Point
- `vmaddcfp128` - Vector128 Multiply Add Floating Point
- `vmulfp128` - Vector128 Multiply Floating Point
- `vrefp128` - Vector128 Reciprocal Estimate Floating Point
- `vrsqrtefp128` - Vector128 Reciprocal Square Root Estimate

**Comparison:**
- `vcmpgtfp128` - Vector128 Compare Greater Than FP
- `vcmpeqfp128` - Vector128 Compare Equal FP
- `vmaxfp128` - Vector128 Maximum FP
- `vminfp128` - Vector128 Minimum FP

**Permutation:**
- `vperm128` - Vector128 Permutation
- `vpermwi128` - Vector128 Permutate Word Immediate
- `vspltw128` - Vector128 Splat Word
- `vspltisw128` - Vector128 Splat Immediate Signed Word
- `vsldoi128` - Vector128 Shift Left Double by Octet Immediate
- `vrlw128` - Vector128 Rotate Left Word
- `vrlimi128` - Vector128 Rotate Left Immediate and Mask Insert

**Conversion:**
- `vcfpsxws128` - Vector128 Convert From FP to Signed Fixed-Point Word Saturate
- `vcsxwfp128` - Vector128 Convert From Signed Fixed-Point Word to FP
- `vcfpuxws128` - Vector128 Convert From FP to Unsigned Fixed-Point Word Saturate
- `vcuxwfp128` - Vector128 Convert From Unsigned Fixed-Point Word to FP

**Logical:**
- `vand128` - Vector128 Logical AND
- `vandc128` - Vector128 Logical AND with Complement
- `vor128` - Vector128 Logical OR
- `vxor128` - Vector128 Logical XOR
- `vnor128` - Vector128 Logical NOR

**D3D Pack/Unpack:**
- `vpkd3d128` - Vector128 Pack D3Dtype
- `vupkd3d128` - Vector128 Unpack D3Dtype

### Function Prologue Pattern

```asm
stwu r1, -frame_size(r1)  # Create stack frame
mflr r0                   # Save LR
stw r0, frame_size+4(r1)  # Store return address
stfd f14, ...             # Save non-volatile FPRs (if used)
stvx v20, ...             # Save non-volatile VMX (if used)
stw r14, ...              # Save non-volatile GPRs
```

### Function Epilogue Pattern

```asm
lwz r0, frame_size+4(r1)  # Restore LR
mtlr r0                   # Move to LR
lwz r14, ...              # Restore non-volatile GPRs
lfd f14, ...              # Restore non-volatile FPRs
lvx v20, ...              # Restore non-volatile VMX
addi r1, r1, frame_size   # Destroy stack frame
blr                       # Return
```

### Calling Convention

- Parameters in r3-r10
- Return value in r3
- Volatile: r0-r12, f0-f13, v0-v19
- Non-volatile: r14-r31, f14-f31, v20-v31

---

## 5. TOOLS REFERENCE

### xextool (via Wine)

```bash
# Info
xextool -l <file.xex>

# Extract PE
xextool -b <basefile.exe> <file.xex>

# Extract IDC script
xextool -i <script.idc> <file.xex>

# Apply XEXP patch
xextool -p <patch.xexp> -o <output.xex> <input.xex>

# Merge TU (no separate file)
xextool -u -p <patch.xexp> -o <output.xex> <input.xex>

# Decrypt
xextool -e u -o <output.xex> <input.xex>

# Decompress
xextool -c u -o <output.xex> <input.xex>

# Decrypt + Decompress
xextool -e u -c u -o <output.xex> <input.xex>

# Encrypt
xextool -e e -o <output.xex> <input.xex>

# Compress
xextool -c c -o <output.xex> <input.xex>

# Remove all limits
xextool -r a -o <output.xex> <input.xex>

# Remove media limits
xextool -r m -o <output.xex> <input.xex>

# Remove region limits
xextool -r r -o <output.xex> <input.xex>

# Force devkit
xextool -m d -o <output.xex> <input.xex>

# Force retail
xextool -m r -o <output.xex> <input.xex>

# Extract XML
xextool -x a <file.xex>
```

### xex1tool (via Wine)

```bash
# Info
xex1tool -l <file.xex>

# Extract PE
xex1tool -b <file.xex>

# Extract resources
xex1tool -d <output_dir> <file.xex>

# List imports
xex1tool -i <file.xex>

# VA to offset
xex1tool -a <address> <file.xex>
```

### xexp-apply

```bash
# Apply patch
xexp-apply <original.xex> <patch.xexp> <output.xex>

# Get info
xexp-apply --info <patch.xexp>
```

### 360tools Scripts

```bash
# Extract from STFS
xbox-extract-stfs <package> <output_dir>

# Extract from ISO
xbox-extract-iso <game.iso> <output_dir>

# XEX info
xbox-xex-info <file.xex>

# Parse imports
xbox-parse-imports <file.xex>

# Extract PE
xbox-extract-pe <file.xex> <output.bin>
```

### IDA Pro Setup

**Plugins:**
- `idaxex.dll` - XEX/XBE loader
- `ppc_altivec.py` - VMX128/AltiVec instructions

**Type Libraries:**
- `x360.til` - Xbox 360 types
- `xkelib.til` - Xbox kernel types

**MCP Tools:**
- `get_database_info` - Architecture, bits, filename
- `get_functions` - List all functions
- `get_function_pseudocode` - Decompiled C code
- `get_function_disassembly` - Assembly view
- `get_function_xrefs` - Cross-references
- `rename_function` - Rename functions
- `rename_local_variable` - Rename variables
- `set_variable_type` - Change variable types
- `add_function_comment` - Add comments
- `search_strings` - Find strings
- `get_imports` - List imports
- `get_exports` - List exports
- `int_convert` - Convert number bases (NEVER do this manually!)

---

## 6. RECOMPILATION GLOSSARY

### XenonRecomp

**Purpose:** Converts Xbox 360 executables into C++ code for native recompilation.

**Input:**
- TOML config file
- ppc_context.h file
- XEX file (or extracted PE)

**Output:**
- C++ source files

**Config Format:**
```toml
[main]
file_path = "game.xex"
patch_file_path = "titleupdate.xexp"
patched_file_path = "patched.xex"
out_directory_path = "ppc/"
switch_table_file_path = "jump_tables.toml"

restgprlr_14_address = 0x82BAFEA0
savegprlr_14_address = 0x82BAFE50
restfpr_14_address = 0x82BB0B3C
savefpr_14_address = 0x82BB0AF0
restvmx_14_address = 0x82BB1D58
savevmx_14_address = 0x82BB1AC0
```

**Requirements:**
- CMake 3.20+
- Clang 18+
- LLVM

**Optimizations:**
- Local variable optimization (r14-r31 as locals)
- Register restore/save elimination
- CTR/XER as local variables
- Skip LR for leaf functions
- Reserved registers as local variables

**Jump Table Detection:**
- Pattern-based static analysis
- Game-specific patterns (Sonic Unleashed defaults)
- Manual adjustment needed for other games
- XenonAnalyse extracts switch tables

### XenosRecomp

**Purpose:** Converts Xbox 360 shader binaries to HLSL.

**Output:**
- HLSL → DXIL/SPIR-V via DirectX Shader Compiler (DXC)

**Features:**
- D3D12 and Vulkan support
- Boolean register handling (16 per shader, packed uint32)
- Constant buffer mapping (root constants D3D12, push constants Vulkan)
- Vertex declaration conversion
- Async shader compilation

**Shader Translation Pipeline:**
```
Xbox 360 Microcode (Adreno A200-based)
  │
  └→ ShaderTranslator
       │
       ├→ DxbcShaderTranslator → HLSL → DXBC (D3D12)
       │
       └→ SpirvShaderTranslator → SPIR-V (Vulkan)
```

### ReXGlue SDK

**Purpose:** Runtime for recompiled Xbox 360 games.

**Architecture:**
```
Runtime
├── Memory              - 4GB guest virtual address space + physical memory
├── ExportResolver      - Ordinal-to-name mapping + variable exports
├── FunctionDispatcher  - Guest-to-host function dispatch table
├── VirtualFileSystem   - Guest path → host path mapping
├── KernelState         - Xbox 360 kernel objects (threads, events, modules)
├── IGraphicsSystem*    - GPU backend (D3D12/Vulkan)
├── IAudioSystem*       - Audio backend (XMA2)
└── IInputSystem*       - Input backend (SDL GameController)
```

**Features:**
- Kernel emulation (syscalls, memory, threads)
- D3D12/Vulkan GPU backend (from Xenia)
- XMA audio
- Input handling (SDL GameController → XInput)
- Threading
- No JIT - all code pre-compiled

**Requirements:**
- Clang 18+
- CMake 3.25+
- C++23

**Target Platforms:**
| Platform | Backend | Status |
|----------|---------|--------|
| Windows x64 | D3D12 | ✅ Supported |
| Linux x64 | Vulkan | ✅ Supported |
| macOS ARM64 | Metal | ❌ Not supported |

### 360tools Pipeline

```
XBLA Package (STFS) ─┬─ extract_stfs.py ─→ files
                      │
Xbox 360 ISO ────────┴─ extract_iso.py ─→ files
                            │
                    extract_pe.py ─→ raw PE (AES decrypt + LZX decompress)
                            │
                    find_abi_addrs.py ─→ ABI addresses (GPR/VMX save/restore)
                            │
                    extract_switch_tables.py ─→ jump tables TOML
                            │
                    find_missing_vtable_funcs.py ─→ vtable functions
                            │
                    XenonRecomp ─→ C++ source
                            │
                    ReXGlue SDK ─→ runtime
                            │
                    Clang/CMake ─→ native x86-64 .exe
```

### Recompilation Projects

**Released:**
| Game | Tool | Status |
|------|------|--------|
| Sonic Unleashed | XenonRecomp | ✅ Released |

**In Development (ReXGlue SDK):**
| Game | Status |
|------|--------|
| Blue Dragon | 🟡 Bootable |
| Lost Odyssey | 🟡 In-game |
| Ninja Gaiden 2 | 🟡 Early |
| Banjo Kazooie: Nuts & Bolts | 🟡 Early |
| Halo 3 (beta) | 🟡 Early |
| Crackdown 2 | 🟡 In-game |
| Viva Pinata | 🟡 Early |
| Dragon Ball Z: Budokai HD | 🟡 Early |
| Dragon Ball Z: Raging Blast 2 | 🟡 Early |
| Ace Combat 6 | 🟡 Hybrid backend fixes |

**360tools Projects:**
| Game | Status |
|------|--------|
| The Simpsons Arcade | ✅ Playable |
| Vigilante 8 Arcade | ✅ Playable (90 FPS) |
| Guitar Hero II | ✅ Playable |
| Crazy Taxi | ✅ Playable |
| Comix Zone | 🟡 Analysis |
| Virtual On | 🔴 Foundation |
| Saints Row | 🔴 Planning |

**Other:**
| Game | Status |
|------|--------|
| GoldenEye 007 | 🟡 Active |
| Sonic 06 | 🟡 Active |
| Skate 3 | 🟡 Early |

### Game-Specific Recompilation Details

**The Simpsons Arcade (sp00nznet/simpsonsarcade):**
- 58 C++ source files (~45 MB)
- Kernel stubs for Xbox 360 API
- Speed fixes:
  - VdSwap frame limiter: Windows `Sleep(16)` duerme 31ms → `QueryPerformanceCounter` a 16.667ms
  - Timebase scaling: `__rdtsc()` TSC host 3-4GHz vs Xbox 360 49.875MHz → scaled guest timebase
- Full speed, playable

**Daytona USA (XBLA 2011):**
- XenonRecomp + ReXGlue
- Native PC port available
- Community effort

**Ace Combat 6 (sal063/AC6_recomp):**
- Hybrid backend fixes
- Experimental replay renderer
- AC6-specific diagnostics
- D3D12 hooks for rendering

---

## 7. RENDERING ARCHITECTURE

### Xenos GPU Pipeline

```
Vertex Fetch (16 units)
    │
    └→ Unified Shader (48 ALUs)
        ├── 3 SIMDs × 16 shaders
        ├── Vec4 + scalar operations
        └── Dynamic allocation (vertex/pixel)
            │
            ├── Texture Fetch (16 units)
            │   ├── LOD computation
            │   ├── Linear/Trilinear filtering
            │   └── Unified texture cache
            │
            └── Output Buffer
                ├── EDRAM (10MB, 256 GB/s)
                ├── Color/Z/Stencil
                └── MSAA (4x lossless)
```

**Memory Export:**
- Shader writes to computed addresses
- Enables GPGPU (ray tracing, physics)
- Virtualizes shader resources
- Supports scatter writes

**HDR Format:**
- 32-bit: 7e3 7e3 7e3 2
- Range: 0-16
- Full blending support

**Displaced Subdivision Surfaces:**
- Tessellator generates 64 vertices per patch
- Vertex shader reads one-ring, computes Stam's method
- Adds displacement map
- Pixel shader adds bump mapping and surface color

### Rendering in Recompilation

**IGraphicsSystem Interface:**
```cpp
class IGraphicsSystem {
    virtual X_STATUS Setup(FunctionDispatcher*, KernelState*, WindowedAppContext*, bool) = 0;
    virtual void Shutdown() = 0;
};
```

**Implementations:**
- `D3D12GraphicsSystem` - Windows (Direct3D 12)
- `VulkanGraphicsSystem` - Linux/macOS (Vulkan)

**Command Processing:**
- Xbox 360 GPU commands arrive at `CommandProcessor`
- Translated to backend operations (D3D12/Vulkan)

**Shader Translation:**
- Xbox 360 microcode → HLSL/SPIR-V
- Boolean registers: 16 per shader (packed uint32)
- Constant buffers: Root constants (D3D12) / Push constants (Vulkan)
- Vertex declarations: Native input declarations

**EDRAM Emulation:**
- Path 1: Fragment Shader Interlock (pixel-perfect, software)
- Path 2: Host Render Targets (native, better performance)

**Resource Management:**
| Resource | Implementation | Purpose |
|----------|----------------|---------|
| Textures | TextureCache | Format conversion, tiling |
| Constant Buffers | Root constants (D3D12) / Push constants (Vulkan) | Shader inputs |
| Vertex Buffers | Input declarations | Vertex data |
| Render Targets | EDRAM emulation | Framebuffer |

**Game-Specific Rendering:**
- **The Simpsons Arcade**: Xenia-based D3D12 backend
- **Daytona USA**: Xenia-based D3D12 backend
- **Ace Combat 6**: Hybrid backend with D3D12 hooks
- **Sonic Unleashed**: XenosRecomp shaders + ReXGlue

---

## 8. CODE LEAKS & SDKS

### Public Leaks

| Leak | Year | Contents |
|------|------|----------|
| Xenon SDK Collection | 2019 | Alpha/beta SDKs (2004-2005) |
| XDK 5445 CHK | 2020 | xboxkrnl.exe symbols |
| XDK 8955 | 2015 | Retail recovery ISOs |
| Titan Board Dump | 2015 | CPU programming tool |
| XeLL (Xeon Linux Loader) | 2007 | Linux boot exploit |
| King Kong Shader Exploit | 2006 | First homebrew |

### Internal Tools Leaked

- GianoSimulator (hardware emulator)
- XDK Launcher (development environment)
- Remote Recovery (network flash tool)
- ISO Recovery (bootable disc)

### Reverse Engineering Resources

- Free60 Wiki: Complete boot chain documentation
- ivc wiki: Kernel internals, keyvault structure
- Xenia: Full emulator (open source)
- Xbox-Reversing: Pseudocode for bootloaders

---

## 9. TRAINER/MODDING REFERENCE

### Trainer Types

| Type | Method | Requirements |
|------|--------|--------------|
| Aurora Trainers | XEX loader | Aurora Dashboard |
| XBDM Trainers | Real-time memory editing | xbdm.xex plugin |
| JRPC2 Trainers | RPC calls to kernel | JRPC2.xex plugin |

### Memory Patching

**Base Address:** 0x82000000 (typical XEX load)

**Operations:**
- **Peek**: Read 4 bytes from address
- **Poke**: Write 4 bytes to address
- **Freeze Loop**: Continuously poke value

**Example:**
```cpp
uint32_t base = 0x82000000;
uint32_t health_offset = 0x1A3F8;
*(uint32_t*)(base + health_offset) = 9999;  // Infinite health
```

### RTM Tools

| Tool | Use |
|------|-----|
| Peek Poker v8 | Memory dumps for analysis |
| Cheat Engine | Analyze dumps, find offsets |
| XeCLI | `rgh mem peek/poke` |
| Xbox 360 Neighborhood | Direct console connection |

### Common Offset Patterns

Offsets vary per game. Use Cheat Engine or XeCLI to find:
- Health value
- Ammo count
- Money/currency
- Player coordinates
- Game speed

---

## 10. STRING/PATTERN SIGNATURES

### AES S-Box Constants
```
63 7C 77 7B F2 6B 6F C5
```

### Network API Patterns
```
Winsock: socket, connect, send, recv, bind, listen
WinHTTP: WinHttpOpen, WinHttpConnect, WinHttpSendRequest
Xbox: XNetStartup, XNetSocket, XNetConnect, XNetSendTo
```

### File Operation Patterns
```
Kernel: NtCreateFile, NtReadFile, NtWriteFile, NtClose
Filesystem: NtQueryDirectoryFile, NtSetInformationFile
```

### Crypto Function Patterns
```
AES: AesSetKey, AesEncrypt, AesDecrypt
RSA: RsaOpen, RsaCreateSessionKey, RsaEncrypt
Hash: Sha1Create, HmacSha1Create
```

### Xbox 360 Specific Patterns
```
Threading: ExCreateThread, KeTerminateThread, KeWaitForSingleObject
Memory: ExAllocatePool, ExFreePool, MmMapIoSpace
XAM: XamUserGetXUID, XamInputGetState, XamNetworkCreateSocket
```

---

## 11. MCP TOOL REFERENCE

Use these tools for analysis:
- `get_database_info` - Architecture, bits, filename
- `get_functions` - List all functions
- `get_function_pseudocode` - Decompiled C code
- `get_function_disassembly` - Assembly view
- `get_function_xrefs` - Cross-references
- `rename_function` - Rename functions
- `rename_local_variable` - Rename variables
- `set_variable_type` - Change variable types
- `add_function_comment` - Add comments
- `search_strings` - Find strings
- `get_imports` - List imports
- `get_exports` - List exports
- `int_convert` - Convert number bases (NEVER do this manually!)

---

## 12. OUTPUT FORMATS

### Xbox 360 Binary Analysis Report

```markdown
# Xbox 360 Binary Analysis Report

## Overview
- Filename: [name.xex/name.xbe]
- Title ID: [8-digit hex]
- Media ID: [8-digit hex]
- Kernel Version: [version]
- Region: [region code]

## XEX Information
- Encryption: [Retail/Devkit/None]
- Compression: [None/Basic Block/LZX]
- Title Name: [game title]
- Publisher: [publisher]

## Key Findings
### [Finding Title]
- Description
- Evidence (function names, addresses)

## Network Indicators
- URLs: [list]
- IP Addresses: [list]
- Ports: [list]

## File Operations
- Save paths: [list]
- Asset paths: [list]

## Crypto Usage
- Encryption algorithms: [list]
- Key locations: [list]

## Functionality Summary
[Description of what the game/application does]

## Recommendations
[Next steps for analysis]
```

---

## 13. SECURITY EXPLOITS & HACKS

### King Kong Shader Exploit (2006)

**CVE:** CVE-2007-1220
**Affected:** Kernel 4532 and 4548 only
**Fixed:** Kernel 4552 (January 9, 2007)

**Technical Details:**
- Exploits hypervisor syscall dispatcher bug
- `cmplwi` checks lower 32 bits only
- `rldicr` examines full 64 bits
- Setting MSB overrides HRMOR (Hypervisor Real Mode Offset)
- Aliases syscall handler to unencrypted memory
- Modifies handler table to jump anywhere in HV space

**Exploit Flow:**
```
1. Setup context switch to controlled stack
2. Setup stack frame with syscall info
3. Force context switch to exploit stack
4. Syscall dispatcher uses aliased (unencrypted) table
5. Jump to attacker-controlled code in HV space
6. Run unsigned code with full privileges
```

**Proof of Concept:**
```asm
# Output '!' to serial port
li %r3, '!'
bl putc

putc:
  lis %r4, 0x8000
  ori %r4, %r4, 0x200
  rldicr %r4, %r4, 32, 31
  oris %r4, %r4, 0xea00
  slwi %r3, %r3, 24
  stw %r3, 0x1014(%r4)
  lwz %r3, 0x1018(%r4)
  rlwinm. %r3, %r3, 0, 6, 6
  beq putc+8
  blr
```

### Reset Glitch Hack (RGH) - 2011

**Purpose:** Bypass hash verification in bootloader chain

**Technical Concept:**
- CPU runs at 200MHz (normal: 3.2GHz)
- Send tiny reset pulse (3-10ns) during `memcmp`
- `memcmp` returns 0 (match) regardless of data
- Custom bootloader passes hash check
- Run unsigned code

**Hardware Required:**
- Xilinx CoolRunner II CPLD (xc2c64a)
- I2C bus connection to HANA chip
- POST bus monitor (8-bit)
- CPU_RESET line access

**Phat Console Flow:**
```
1. Assert CPU_PLL_BYPASS at POST 0x36
2. Wait for POST 0x39 (memcmp start)
3. Start counter
4. At ~62% of memcmp duration
5. Send 100ns pulse on CPU_RESET
6. Deassert CPU_PLL_BYPASS
7. CPU resumes, memcmp returns 0
8. Custom CD loads
```

**Slim Console Flow:**
```
1. Wait for POST 0xD8
2. Send I2C: 0xCD,0x04,0x4E,0x08,0x80,0x03 (slow down)
3. Start counter
4. At POST 0xDA, wait 180,840ns
5. Send 10ns LOW/HIGH pulse on RESET
6. Send I2C: 0xCD,0x04,0x4E,0x80,0x0C,0x02 (restore speed)
7. CB_B loads custom CD
```

**CB_B Patches (Slim):**
- Activate zero-paired mode
- Expect plaintext CD in NAND
- Skip CD hash verification

### Timing Attack (Downgrade)

**Purpose:** Find correct HMAC hash for base kernel 1888

**Technical Concept:**
- `memcmp` compares 16-byte HMAC hash byte-by-byte
- True byte takes longer than false byte
- Measure timing for each byte position
- Brute-force correct hash values

**Attack Flow:**
```
1. Patch CB lockdown counter with LDV from NAND
2. Connect timing hardware (Infectus USB)
3. Flash new CB hash guess every ~2 seconds
4. Measure memcmp timing for each guess
5. Repeat for all 16 bytes
6. Find correct hash (~1 hour 10 minutes)
```

**Requirements:**
- Kernel 4552 or higher (to downgrade)
- Infectus chip for NAND flashing
- Timing hardware (serial port + power)
- Old kernel dump (4532/4548)

### SMC Hack (JTAG)

**Method:** Bridge 3 points on motherboard

**Requirements:**
- JTAG access
- Soldering to 3 test points
- Modified SMC image

**Use Case:**
- Earlier consoles only
- Pre-RGH method
- Limited functionality

### Bad Update Exploit (2025)

**Purpose:** Software-only unsigned code execution

**Stages:**
1. Initial entry via game vulnerability
2. Chain of exploits for privilege escalation
3. Memory corruption for code injection
4. Execute unsigned code

**Status:** Active development

### Security Mitigations (Post-Exploits)

| Kernel | Mitigation |
|--------|------------|
| 4552 | Fixed HV privilege escalation |
| 4548+ | Split 2BL (CB_A/CB_B) |
| 4548+ | CPU Key encryption |
| 4548+ | Lockdown counter |
| 6723+ | Updated base kernel |

---

## 14. AUDIO SYSTEM

### XMA Hardware Decoder

**Location:** Southbridge chip (hidden)
**Codec:** Xbox Media Audio (XMA) - variant of WMA
**Purpose:** Hardware-accelerated audio decoding

**Capabilities:**
- On-the-fly decoding of compressed audio streams
- Multiple simultaneous streams
- Seamless looping support
- 8-10x compression vs PCM

**XMA2 Format:**
- Sample rates: 24, 32, 44.1, 48 kHz
- Channels: 1-6 (stereo streams)
- Block size: 2048 bytes
- Frame: 512 mono samples
- Packet: 2KB (32-bit header + frames)

### Audio Pipeline

```
Game Audio Data (XMA)
    │
    └→ XMA Hardware Decoder
         │
         └→ Audio Processing
              │
              ├── VP (Voice Processor)
              │   └── 32 channel mono output
              │
              ├── GP (General Purpose DSP)
              │   └── Programmable effects
              │
              └── EP (Encoding DSP)
                  └── 5.1 AC3 encoding
                       │
                       └→ AC97 Output
```

### Audio APIs

| API | Purpose |
|-----|---------|
| XAudio2 | High-level audio API (cross-platform) |
| XACT | Audio creation tool (cross-platform) |
| DirectSound | Legacy audio API |
| XMA*() | Low-level decoder access |

### Audio Memory

- XMA contexts: 64 bytes each (in physical memory)
- Context array: Multiple contexts for streams
- Mix buffer: 1024 samples (32 channels × 32 samples)
- Frame duration: 0.6ms (48kHz, 32 samples)

---

## 15. I/O SYSTEM

### Southbridge (MCPX)

**Functions:**
- Audio processing (APU)
- USB controllers
- Network interface
- SATA controllers
- System management

### I/O Components

| Component | Interface | Purpose |
|-----------|-----------|---------|
| HDD | SATA | Game saves, updates |
| DVD | SATA | Game discs |
| USB | USB 2.0 | Controllers, accessories |
| Network | Ethernet/WiFi | Xbox Live |
| Memory Units | Proprietary | Portable storage |

### Storage Formats

| Format | Use |
|--------|-----|
| FATX | Xbox 360 filesystem |
| STFS | Package format (DLC, saves) |
| XTAF | Extended filesystem |

### Network Stack

**Protocols:**
- TCP/UDP over IPv4
- Xbox networking (XNet)
- Xbox Live services

**APIs:**
- XNetStartup, XNetSocket, XNetConnect
- XLiveSignIn, XLiveCreateSession

---

## 16. MEMORY MANAGEMENT DETAILED

### Page Table Structure

**Entry Format:**
```c
PAGE_TABLE_ENTRY {
    DWORD ReadOnly : 1;        // Page is read-only
    DWORD Data : 1;            // Data page
    DWORD NoExecute : 1;       // Page is executable
    DWORD Valid : 1;           // Page is valid
    DWORD ImageStart : 1;      // Start of image
    DWORD ImageEnd : 1;        // End of image
    DWORD RealPageNumber : 14; // Physical page
    DWORD WhiteningBits : 10;  // Encryption whitening
    DWORD Pathway : 2;         // MMU pathway
};
```

**Whitening:**
- 10 bits for encryption entropy
- Cycles through 1024 values per page
- Randomizes after all values used
- Prevents identical ciphertext

### Kernel Memory APIs

| API | Ordinal | Purpose |
|-----|---------|---------|
| NtAllocateVirtualMemory | 204 | Virtual memory allocation |
| NtFreeVirtualMemory | 220 | Virtual memory deallocation |
| NtProtectVirtualMemory | 208 | Change memory protection |
| MmAllocatePhysicalMemory | 186 | Physical memory allocation |
| MmFreePhysicalMemory | 189 | Physical memory deallocation |
| MmQueryStatistics | 190 | Memory statistics |

### Memory Protection Flags

| Flag | Value | Description |
|------|-------|-------------|
| PAGE_NOACCESS | 0x01 | No access |
| PAGE_READONLY | 0x02 | Read only |
| PAGE_READWRITE | 0x04 | Read/Write |
| PAGE_WRITECOPY | 0x08 | Copy-on-write |
| PAGE_EXECUTE | 0x10 | Execute only |
| PAGE_EXECUTE_READ | 0x12 | Execute/Read |
| PAGE_EXECUTE_READWRITE | 0x14 | Full access |
| PAGE_NOCACHE | 0x200 | Disable caching |

### Heap Types

| Type | Page Size | Purpose |
|------|-----------|---------|
| User Virtual | 4KB/64KB | Game allocations |
| XEX Code | 64KB | Executable code |
| Physical | 4KB/64KB | Physical memory |
| System | 4KB | Kernel structures |

---

## 17. STFS FILESYSTEM DETAILED

### Block Structure

| Property | Value |
|----------|-------|
| Block size | 0x1000 (4096 bytes) |
| First block | 0xC000 |
| Hash table interval | 0xAA (170) blocks |
| Master hash interval | 0x70E4 (28900) blocks |

### Hash Table Format

**Hash Entry (24 bytes):**
```
Offset  Size  Field
0x00    20    SHA-1 hash
0x14    1     Status byte
0x15    3     Next block (24-bit)
```

**Status Byte Values:**
| Value | State |
|-------|-------|
| 0x00 | Free |
| 0x80 | Allocated |
| 0xE0 | Directory |

### Volume Descriptor

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 1 | Size (0x24) |
| 0x01 | 1 | Reserved |
| 0x02 | 1 | Block separation |
| 0x03 | 2 | File table block count |
| 0x05 | 3 | File table block number |
| 0x08 | 20 | Top hash table hash |
| 0x1C | 4 | Total allocated blocks |
| 0x20 | 4 | Total unallocated blocks |

### Directory Entry (64 bytes)

| Offset | Size | Field |
|--------|------|-------|
| 0x00 | 40 | Filename |
| 0x28 | 1 | Flags |
| 0x29 | 3 | Valid data blocks |
| 0x2C | 3 | Allocated data blocks |
| 0x2F | 3 | Start block number |
| 0x32 | 2 | Directory index |
| 0x34 | 4 | File size |
| 0x38 | 4 | Last updated timestamp |
| 0x3C | 4 | Last accessed timestamp |

### File Table Entry Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | Contiguous | File is contiguous |
| 1 | Directory | Entry is directory |

### Block Offset Calculation

```c
uint64_t blockIndexToOffset(uint64_t baseOffset, uint64_t blockIndex) {
    uint64_t block = blockIndex;
    for (int i = 0; i < 3; i++) {
        uint32_t levelBase = blocksPerHashLevel[i];
        block += ((blockIndex + levelBase) / levelBase);
        if (blockIndex < levelBase) break;
    }
    return baseOffset + (block << 12);
}
```

### Package Types

| Type | Magic | Description |
|------|-------|-------------|
| CON | - | Console-created (local) |
| LIVE | "LIVE" | Xbox Live downloaded |
| PIRS | "PIRS" | Pre-installed content |

### Package Integrity

- SHA-1 hashes for all blocks
- RSA signature in header
- Hash table verification
- HMAC-SHA1 for content

---

## 18. KERNEL FUNCTIONS & SYSTEM CALLS

### xboxkrnl.exe Export Ordinals

**Memory Management:**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 186 | MmAllocatePhysicalMemory | Allocate physical memory |
| 189 | MmFreePhysicalMemory | Free physical memory |
| 190 | MmQueryStatistics | Memory statistics |
| 204 | NtAllocateVirtualMemory | Virtual memory allocation |
| 208 | NtProtectVirtualMemory | Change memory protection |
| 220 | NtFreeVirtualMemory | Virtual memory deallocation |

**Threading:**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 92 | KeAlertResumeThread | Resume alerted thread |
| 93 | KeAlertThread | Alert thread |
| 98 | KeBoostPriorityThread | Boost thread priority |
| 100 | KeInitializeApc | Initialize APC |
| 114 | KeInsertQueueApc | Insert APC into queue |
| 151 | KeStallExecutionProcessor | Stall execution |
| 152 | KeSuspendThread | Suspend thread |
| 158 | KeWaitForMultipleObjects | Wait for objects |
| 159 | KeWaitForSingleObject | Wait for single object |
| 254 | PsCreateSystemThread | Create system thread |
| 255 | PsCreateSystemThreadEx | Create extended thread |
| 258 | PsTerminateSystemThread | Terminate thread |

**I/O Operations:**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 1 | AvGetSavedDataAddress | Get saved data |
| 126 | KeQueryPerformanceCounter | Query performance |
| 127 | KeQueryPerformanceFrequency | Query frequency |
| 128 | KeQuerySystemTime | Query system time |
| 154 | KeSystemTime | System time |

**String/Memory Operations:**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 260 | RtlAnsiStringToUnicodeString | ANSI to Unicode |
| 261 | RtlAppendStringToString | Append strings |
| 262 | RtlAppendUnicodeStringToString | Append Unicode strings |
| 263 | RtlAssert | Assertion handler |
| 278 | RtlFillMemory | Fill memory |
| 279 | RtlMoveMemory | Move memory |
| 280 | RtlZeroMemory | Zero memory |

**Crypto Functions (Ordinals 345-402):**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 345 | XeCryptAesSetup | AES setup |
| 346 | XeCryptAesEncrypt | AES encrypt |
| 347 | XeCryptAesDecrypt | AES decrypt |
| 358 | XeCryptSha1Init | SHA-1 init |
| 359 | XeCryptSha1Update | SHA-1 update |
| 360 | XeCryptSha1Final | SHA-1 final |
| 361 | XeCryptHmacSha1Init | HMAC-SHA-1 init |
| 362 | XeCryptHmacSha1Update | HMAC-SHA-1 update |
| 363 | XeCryptHmacSha1Final | HMAC-SHA-1 final |

**XAM (Xbox Application Manager):**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 200 | XamFeatureEnabled | Check feature |
| 208 | XamUserGetDeviceContext | Get device context |
| 209 | XamUserLookupDevice | Lookup device |
| 210 | XamUserGetXUID | Get XUID |
| 211 | XamUserLogon | User logon |
| 212 | XamUserGetGamerTag | Get gamertag |
| 213 | XamUserGetUserIndexMask | Get user index mask |
| 214 | XamUserGetName | Get user name |
| 218 | XamUserGetState | Get user state |

**XInput (Input):**
| Ordinal | Function | Purpose |
|---------|----------|---------|
| 500 | XInputdGetCapabilities | Get capabilities |
| 501 | XInputdGetState | Get state |
| 502 | XInputdSetState | Set state (vibration) |

### System Call Mechanism

**Entry Point:**
```asm
sc              # System call instruction
mfspr r3, SRR0  # Save return address
mfspr r4, SRR1  # Save MSR
```

**Dispatch:**
```
1. Read syscall number from r0
2. Validate syscall number < 0x61
3. Calculate table offset: rldicr r1, r0, 2, 61
4. Load handler from syscall_table(r1)
5. Jump to handler
```

### Module System

**Modules:**
| Module | Purpose |
|--------|---------|
| xboxkrnl.exe | Kernel functions |
| xam.xex | Application manager |
| xbdm.xex | Debug manager |
| xaudio2.dll | Audio API |
| d3d9.dll | Direct3D 9 |
| xgraphics.dll | Graphics utilities |

**Import Mechanism:**
- Imports by ordinal (not name)
- Ordinal table in XEX header
- Trampoline to actual function

### Kernel Objects

| Object Type | Purpose |
|-------------|---------|
| Thread | Execution threads |
| Process | Process management |
| Event | Synchronization events |
| Mutex | Mutual exclusion |
| Semaphore | Counting semaphore |
| Timer | Kernel timers |
| File | File objects |
| Device | Device objects |
| Section | Memory sections |
| Key | Registry keys |

---

## 19. IMPORTANT RULES

1. **NEVER convert number bases manually** - Always use `int_convert` tool
2. **Be specific with addresses** - Use hex format (0x401000)
3. **Document everything** - Add comments as you analyze
4. **Verify assumptions** - Check cross-references before concluding
5. **Consider context** - What is the binary's purpose?
6. **Look for patterns** - Similar functions often have similar behavior
7. **Security awareness** - Understand the boot chain for exploit research
8. **Memory is encrypted** - Hypervisor encrypts all memory
9. **XMA is hardware** - Audio decoding done in Southbridge
10. **Page tables are software** - HV manages, not MMU
11. **Imports by ordinal** - Xbox 360 uses ordinals, not names
12. **Single module** - Only xboxkrnl.exe is dynamically linked

---

## 20. FUNCTION-LEVEL MODDING

### Overview

Function-level modding in recompilation projects uses ReXGlue's hook system to modify game behavior at the code level. Unlike texture packs or configuration changes, these mods directly alter game logic.

### How It Works

**Weak/Strong Symbol System:**
- Each recompiled function = weak alias to `__imp__` strong implementation
- Mods override by defining strong symbol with same name
- Linker prefers strong definition over weak alias
- `__imp__` always refers to generated code

**PPC Register Conventions:**
- r3-r10: Integer/pointer arguments (first 8 args)
- f1-f13: Floating-point arguments
- r3: Integer return value
- f1: Float return value
- r1: Stack pointer
- r13: TLS base

### Hook Types

**1. REX_HOOK (Typed Override)**
```cpp
#include <rex/hook.h>

uint32_t MyAdd(uint32_t a, uint32_t b) {
    return a + b;
}

// Maps recompiled function to native C++ function
// r3 -> a, r4 -> b, return value -> r3
REX_HOOK(sub_82003A40, MyAdd)
```

**2. REX_HOOK_RAW (Raw Override with Context Access)**
```cpp
#include <rex/hook.h>

REX_EXTERN(__imp__sub_82003A40);

REX_HOOK_RAW(sub_82003A40) {
    // Pre-hook: modify state before original runs
    ctx.r3.u64 = 42;

    // Call original generated implementation
    __imp__sub_82003A40(ctx, base);

    // Post-hook: inspect/modify state after
}
```

**3. Mid-ASM Hooks (Instruction-Level Injection)**
```toml
# retip_config.toml
[[midasm_hook]]
address = 0x8229B0C8
name = "fps_hook"
registers = []
after_instruction = true
```

```cpp
// hooks.cpp
void fps_hook() {
    // Called at specific instruction address
    // Can modify registers, control flow
}
```

### Mid-ASM Hook Options

| Option | Description |
|--------|-------------|
| `address` | PPC instruction address to hook |
| `name` | C++ hook function name |
| `registers` | Registers passed as PPCRegister& args |
| `after_instruction` | Hook fires after instruction executes |
| `return` | Unconditionally return after hook |
| `jump_address` | Jump to address after hook |
| `return_on_true` | Return if hook returns true |
| `jump_address_on_true` | Jump if hook returns true |
| `jump_address_on_false` | Jump if hook returns false |

### Common Mod Patterns

**1. FPS Unlock (TiP-Recomp)**
```cpp
// Modify frame limiter
void fps_hook() {
    REXCVAR_SET(lock_fps, false);
}

// Skip vsync
void vsync_hook(PPCRegister& r10) {
    r10.u32 = 0; // Disable vsync
}
```

**2. Infinite Health/Lives (Conceptual)**
```cpp
// Hook health function, return max value
REX_HOOK_RAW(sub_82003A40) {
    // Call original
    __imp__sub_82003A40(ctx, base);
    
    // Modify return value (health)
    ctx.r3.u64 = 999;
}
```

**3. Skip Game Logic (TiP-Recomp)**
```toml
# Skip entity avatar pinata seed check
[[midasm_hook]]
address = 0x8235DEDC
name = "skip_entityAvatarPinataSeedBigBrotherSaysYes_hook"
registers = []
after_instruction = false
jump_address_on_true = 0x8235DEEC
```

```cpp
bool skip_entityAvatarPinataSeedBigBrotherSaysYes_hook() {
    return true; // Always skip
}
```

**4. Modify Game Parameters (TiP-Recomp)**
```cpp
// Modify occupancy limits
bool meUpdateOccupancyLevels_hook(PPCRegister& fp0) {
    uint32_t& limit1 = *reinterpret_cast<uint32_t*>(0x100000000 + 0x83A5A8A8 + 64);
    uint32_t& limit2 = *reinterpret_cast<uint32_t*>(0x100000000 + 0x83A5A8A8 + 96);
    
    limit1 = _byteswap_ulong(999999);
    limit2 = _byteswap_ulong(999999);
    
    return true;
}
```

**5. Aspect Ratio Override (TiP-Recomp)**
```cpp
float camMainGetAspectRatio_821F0730_Hook() {
    if (REXCVAR_GET(UseAspectRatioFromConfig)) {
        return static_cast<float>(REXCVAR_GET(AspectRatio));
    }
    // Call original
    return rex::GuestToHostFunction<float>(__imp__rex_camMainGetAspectRatio_821F0730);
}
```

**6. Disable Visual Effects (UnleashedRecomp)**
```toml
# Disable boost filter
[[midasm_hook]]
name = "DisableBoostFilterMidAsmHook"
address = 0x82B48CA0
jump_address_on_true = 0x82B48D10
```

```cpp
bool DisableBoostFilterMidAsmHook() {
    return Config::DisableBoostFilter;
}
```

**7. Object Behavior Fixes (UnleashedRecomp)**
```cpp
// Fix barrel stuck at slope
PPC_FUNC_IMPL(__imp__sub_8271AA30);
PPC_FUNC(sub_8271AA30) {
    auto objBigBarrelEx = reinterpret_cast<ObjBigBarrelEx*>(base + ctx.r3.u32 + OBJ_BIG_BARREL_SIZE);
    objBigBarrelEx->interpolate = ctx.f1.f64 < (1.0 / 30.0);
    objBigBarrelEx->elapsedTime += ctx.f1.f64;

    if (!objBigBarrelEx->interpolate || objBigBarrelEx->elapsedTime >= (1.0f / 30.0f)) {
        ctx.f1.f64 = objBigBarrelEx->elapsedTime;
        __imp__sub_8271AA30(ctx, base);
        objBigBarrelEx->elapsedTime = 0.0f;
    }
}
```

### Project-Specific Examples

**UnleashedRecomp:**
- Mid-ASM hooks for FPS, shadow, boost filter
- Object patches (barrel, grind dash panel)
- Camera fixes (HFR, rotation deadzone)
- Gameplay tweaks (draw distance, physics)

**TiP-Recomp (Viva Piñata):**
- Cursor hooks for RGB cursor
- Budget/limit modifications
- Render state skipping
- Aspect ratio overrides

**reblue (Blue Dragon):**
- Early development stage
- Function hooks planned for modding

---

## 21. LESSONS LEARNED: Skate 3 TU4 Headless RE via idalib

This section documents every patch, workaround, bug, and re-implementation needed to perform a complete headless reverse engineering of Skate 3 Title Update 4 (TU4) PE binary on **Linux without idaxex.dll**. These are not hypothetical — they were all encountered and solved in a single 6-hour session analyzing 40,518 functions.

### 21.1 Core Infrastructure Decisions

| Problem | Solution |
|---------|----------|
| `idat -S` exits code 1 silently (no error, no output) | Use **standalone Python + `idapro` module** — no timeout, no silent failures |
| No Windows IDA for `idaxex.dll` (XEX loader) | Extract PE binary via `xextool -e u -c u`, then load as raw PPC binary at base 0x82000000 |
| IDA can't auto-analyze PPC without PE headers | Use `ida_auto.auto_wait()` after loading, then `add_func(0x82000000)` + `create_imports()` manually |
| `save_database()` corrupts on large DB | Save after every batch of renames; use backups via `.i64.backup` files |
| IDA console/syscall/text I/O unusable | Use `idaapi.msg()` for logging + Python `print()` redirected to `sys.stdout` |
| MCP server unreliable for batch analysis | Use pure `idapython` scripts — no MCP, no socket, no timeout issues |

### 21.2 The THUNK Rename Bug (SN_FORCE = 0x800)

**Symptoms:**
- `idaapi.set_name(ea, "name", SN_FORCE)` returns `True` for FUNC_THUNK functions
- But the name is **not actually applied** — the function keeps its `sub_XXXXXX` name
- The function's `get_name()` returns the old name despite successful API call

**Bug:**
```python
# THIS DOES NOT WORK for FUNC_THUNK:
idaapi.set_name(ea, "newname", idaapi.SN_FORCE)  # Returns True, name NOT set
```

**Workaround:**
```python
# THIS WORKS:
ida_funcs.del_func(ea)                     # Remove the thunk function
idaapi.set_name(ea, "newname", SN_FORCE)   # Now name sticks
ida_funcs.add_func(ea)                     # Re-create the function entry
```

**Affects:** All 133 FUNC_THUNK entries in the XAPI import trampoline area.

### 21.3 The XAPI Ordinal-to-Name Table

**Problem:** Xbox 360 imports by ordinal, not name. Xenia's `xboxkrnl_table.inc` only covers kernel exports (~270 entries). The XAPI system call table (102 entries, ordinals ~0x100-0x1FF) is **not documented anywhere public**.

**Solution:** Manually reconstructed 102-entry table from:
1. Xenia source code (kernel dispatch)
2. Xbox 360 kernel symbol leaks (XDK 5445 CHK)
3. Cross-referencing ordinal ranges with known function behavior
4. Deduction from TU4 function call patterns (e.g., ordinal 0x132 = `XamInputGetState` based on context)

**Result:** 97/102 XAPI ordinals mapped. 5 unfixable (no known mapping).

### 21.4 Unmapped Import Ranges

| Range | Count | Status |
|-------|-------|--------|
| xam.xex ordinals 0x548-0x5D4 | 22 | **Blocked** — not in Xenia's tables (mainline or netplay fork) |
| xboxkrnl.exe ordinals 0x211C-0x281C | 70 | **Blocked** — extended range, possibly kernel internals or GPU microcode |
| xboxkrnl.exe ordinals < 0x100 | 5 | **Blocked** — pre-standard range, no public mapping |

**Total unmapped:** 97 out of 292 imports (32%). All remain as `ordinal_XXXX` placeholders.

### 21.5 TU4 Code Shift Discovery

**Observation:** Every base function address shifted by exactly **+0x3C00** (15,360 bytes) in TU4.

**Cause:** The XEXP delta patch inserted code at the beginning of the `.text` section (likely the XEX signature check patch), pushing all existing code forward by a uniform amount.

**Verification:**
```python
# All 215 shifted functions were confirmed:
shift = tu4_addr - base_addr  # Always 0x3C00 (for shifted functions)
```

**Exception:** 63 functions at the **original base address** (0x8242B1E8, 0x82443D80, etc.) — these were modified in-place by the patch.

### 21.6 The 0x3C00 Gap

After shifting, a 15,360-byte gap exists at the **end** of the shifted code region. This gap contains:
- The 16 new TU4 functions (total ~3,436 bytes)
- The dispatch table entries (`unk_82F2B0XX`)
- Padding/filler (NOP slides)

**Modding implication:** This gap can be repurposed for custom code injection.

### 21.7 XEXP Patch SHA Mismatch

**Problem:** The extracted XEXP delta patch has SHA1 hash `2f1e63fb`, but the XEXP header declares target SHA `24fb36e9`.

**Meaning:** The patch targets a **different retail build** than the one analyzed. The TU4 delta was compiled against XEX revision A, but we have revision B (same title update, different compile).

**Consequence:** Cannot apply the XEXP patch to the v1.0 binary. Must use the pre-patched PE binary from a real Xbox 360.

### 21.8 The "VTable" Correction

**Initial assumption:** 9 addresses at 0x82xxxxxx were vtables (function pointer arrays in `.rdata`).

**Correction:** All 9 are actually **`.text` code functions**, not data structures. They were misidentified because:
- They contain multiple embedded function pointers (tables in code)
- IDA auto-analysis creates `unk_` entries for inline data
- The addresses have zero code xrefs (only data xrefs from vtables in `.rdata`)

**Fix:** Renamed from `vtable_XXXX` back to `sub_XXXX` — they are jump tables, not C++ vtables.

### 21.9 Auth Function Rename Corrections

**Two misnamed functions corrected:**

| Old Name | Correction | Reason |
|----------|-----------|--------|
| `sub_829A7830` → `AuthDispatcher_preAuth_postAuth_validateSessionKey_0` | Vector insert function (548B) | Was called "preAuth" but actually performs `DS_vec_insert_6byte` — not auth validation |
| `Auth_error_string_0` → `AuthDispatcher_postAuth` | Post-auth dispatcher (9920B) | Was named after the error string table (which is embedded) but the function wraps post-authentication flows |

### 21.10 Batch Decompilation Pipeline

Used idalib's decompiler to process all 40,518 functions:

```
1. IDA auto-analysis → 40,518 functions created
2. Batch decompile all → 40,285 OK, 233 failed (99.4% success)
3. Extract 305 base names from v1.0 map → apply to TU4
4. Fix all 133 THUNK renames (del_func → force_name → add_func)
5. Apply 98 Xenia xam.xex names, 97 XAPI names
6. Verify: 638 total user-assigned names (1.6% of 40K)
```

**Scripts created (all in `/tmp/opencode/skate3_work/`):**

| Script | Purpose |
|--------|---------|
| `decompile_complete.py` | Full 40K function decompilation |
| `batch_decompile.py` | Resume batch after crash |
| `fix_thunk_renames.py` | Fix all 133 FUNC_THUNK renames |
| `name_imports_v3.py` | Apply XAPI ordinal→name mapping |
| `auth_analysis5.py` | Auth subsystem decompilation |
| `blaze_callgraph.py` | Blaze call graph reconstruction |
| `ds_analysis2.py` | DirtySock subsystem analysis |
| `pool_analysis2.py` | Buddy-system pool allocator analysis |
| `find_inits.py` | Init chain discovery (21 functions) |
| `extract_subsystems.py` | Per-subsystem function extraction |
| `regen_all.py` | Regenerate all analysis documents with corrected counts |

### 21.11 Data Structures Discovered

**MemoryManager singleton:**
- Address: `unk_830284D4`
- Type: Buddy-system pool allocator
- Callbacks: CB_ALLOC (`vtable+8`), CB_GET (`vtable+12`), CB_FREE (`vtable+16`)
- Debug fill: `0xFEEEFEEE` pattern on free
- Used by: Redirector, ConnectionManager, Auth, all Blaze components

**Dispatch Table:**
- Address: `unk_82F2B094` through `unk_82F2B0CC`
- Type: Function pointer table (6+ entries)
- All modified TU4 functions call through this table
- Purpose: Abstraction layer for SDK refactoring — enables server backend selection (prod/test/dev)

**BlazeHub Context Structure:**
```
Offset  Size  Field
+0      4     vtable/type magic
+4      4     state
+1220   1     idle_running flag
+1224   ?     Auth_list_manager instance
+1228   4     callback_start
+1232   4     callback_end
+1284   4     nested_count
+1288   4     processor_start
+1292   4     processor_end
```

**ConnectionManager Connection Structure:**
```
Offset  Size  Field  Notes
+0      4     type   1=XNet, 2=BLaze, 3=XLSP, 4=Secure, 5=Peach
+4      4     connection_state  0=idle, 1=resolving, 2=connecting, 3=connected, 4=disconnecting, 5=failed, 6=reconnecting
+8      4     service_id
+12     4     server_selector  used by QosManager for ranking
```

### 21.12 TU4 Analysis Summary Statistics

| Metric | Value |
|--------|-------|
| Total functions | 40,518 |
| User-named | 638 (1.6%) |
| Decompiled OK | 40,285 (99.4%) |
| Failed | 233 |
| Base→TU4 mapped | 305 |
| NEW functions (v1.0 not exist) | 16 |
| PATCHED (resized at same addr) | 38 |
| SHIFTED (+0x3C00, body intact) | 215 |
| UNCHANGED (same addr+size) | 25 |
| Net code change | -8,860 bytes (-2,215 PPC instructions) |

### 21.13 Key Patch Points for Modders

| Patch Target | TU4 Address | Type | Notes |
|-------------|-------------|------|-------|
| Telemetry upload stub | 0x8242B1E8 | Read-only | Already disabled by TU4 |
| Game network check stub | 0x82969620 | Read-only | Network validation bypassed |
| ConnectionManager service update | 0x829E7448 | Read-only | Service config update disabled |
| DS_manager init | 0x82A09C60 | Hook point | Init is now JUMPOUT, replace for custom init |
| XNet startup handler | 0x82EB7430 | Patch | Add version check bypass for LAN play |
| Dispatch table entry | 0x82F2B0C4 | Patch | Replace with custom handler for offline auth |
| MemoryManager | 0x830284D4 | Data | Change allocator callbacks for custom memory mgmt |
| BlazeHub init | 0x829712C0 | Hook point | First function in Blaze init chain |
| OnlineSignIn check_live | 0x82712F88 | Patch | Always return "online" for LAN mode |
| KernelEntry | 0x82EB4F30 | Patch | Override XEX signature check |

### 21.14 Tooling Recommendations for Future Sessions

1. **Always use idalib directly** — never rely on `idat -S` for headless analysis
2. **Save DB after every rename batch** — `idaapi.save_database(path)` is reliable
3. **Use `ida_funcs.del_func/add_func` for thunks** — `SN_FORCE` is bugged on FUNC_THUNK
4. **Build import tables manually** — Xenia's tables are incomplete; expand from SDK leaks
5. **Check TU4/patched binaries for code shift** — compare with original base to find the offset
6. **Expect XEXP SHA mismatches** — retail builds vary; work from pre-patched binaries
7. **Run scripts in standalone mode** — MCP is convenient for interactive work but unreliable for batch
8. **Use function addresses, not names** — names from v1.0 may not match TU4 after code shift
9. **Document every assumption** — what you think is a vtable may be a jump table in code
10. **Verify all renames by checking callers** — cross-references catch name errors

---

## Session Knowledge: Skate 3 TU4 DirtySock Analysis

### DirtySock (DS) Subsystem — EA Custom Network Layer

**69 named functions** across two layers:

- **DS_manager_*** (core framework): thread pool, timers, buffer pool, handler registration, state machine dispatching on 4-char message IDs (FourCC: "conn", "migr", "rest", "sock", "bind")
- **DirtySock_*** (network adapter): socket lifecycle, connection state machine, async I/O, DNS resolution

**Direct XNet import calls found:**
- `XNetGetTitleXnAddr(thunk, 0x62696E64, 0, &addr, 16)` — address binding ("bind") in `DS_manager_config_update` and `DS_manager_buffer_alloc`
- `XNet_delete_handle()` — handle cleanup in `DirtySock_conn_state`
- `XNet_sleep_ms(1)` — async wait loop in `DirtySock_conn_state`

**Call chain:** `BlazeHub → DS_manager_thread_fn → DirtySock_callback_[5-7] → DirtySock_socket_connect → XNet thunks`

**DNS resolution:** `DNS_abort_helper` called from `DS_manager_timer_create_0`, returns 2=abort, 3=complete.

**Error handling:** WSA codes: 10035=WSAEWOULDBLOCK, 997=ERROR_IO_PENDING, 10051=WSAENETUNREACH, 10065=WSAEHOSTUNREACH.

**638 total user-assigned names** in the .text section (98 Xapi, 51 XNet, 45 Blaze, 18 NetDll, 14 Telemetry, 9 NT Kernel, 403 base+special).

### Tools for Creating Mods

1. **IDA Pro + MCP** - Analyze functions to hook
2. **XenonRecomp** - Generate C++ from PPC
3. **ReXGlue SDK** - Runtime and hook system
4. **Hedge Mod Manager** - Distribute mods

### Finding Functions to Hook

1. Use IDA Pro MCP to analyze XEX
2. Search for function names or patterns
3. Check cross-references
4. Identify parameters/return values
5. Look for similar functions in other games

---

## 22. EXHAUSTIVE BINARY ANALYSIS WORKFLOW (MULTI-ARCH)

Supports **Xbox 360** (PowerPC) and **PS2** (MIPS R5900). Final product: **SQLite database** + **Knowledge Base markdown**.

### Step 0: Prepare Binary

#### Xbox 360 (XEX → PE)
```bash
xextool -b /tmp/game_pe.bin /path/to/game.xex
```
**CRITICAL**: PE from `xextool -b` is NOT valid PE. Load as **Binary file** with processor **PowerPC: ppc** at `0x82000000`.

#### PS2 (ELF direct)
```bash
readelf -h game.elf  # Verify MIPS, entry point
```
Load ELF directly in IDA — processor **MIPS: mips** is auto-detected.

### Step 1: Open in IDA Headless + Auto-Analysis

```python
import idapro
result = idapro.open_database("/tmp/game.bin", run_auto_analysis=True)
# Xbox 360: ~5-10 min | PS2: ~10-15 min (auto-analysis)
```

**After open_database**, import modules:
```python
import idaapi, ida_funcs, ida_hexrays, ida_bytes
import idautils, ida_name, ida_segment, ida_nalt, ida_entry
```

### Step 2: Extract Functions Census

```python
func_list = []
for func_ea in idautils.Functions():
    fname = ida_funcs.get_func_name(func_ea)
    fobj = ida_funcs.get_func(func_ea)
    fsize = fobj.size() if fobj else 0
    is_named = fname and not fname.startswith("sub_") and not fname.startswith("loc_")
    func_list.append({
        "address": func_ea,
        "name": fname or f"sub_{func_ea:X}",
        "size": fsize,
        "is_named": is_named
    })
```

### Step 3: Decompile All Functions

```python
for func in func_list:
    cfunc = ida_hexrays.decompile(func["address"])
    if cfunc:
        pseudocode = str(cfunc)
```

**Performance**:
| Platform | Functions | Decomp Time | Rate |
|----------|-----------|-------------|------|
| Xbox 360 | 40,518 | 22 min | ~30/s |
| Xbox 360 | 23,341 | 22 min | ~18/s |
| PS2 | 17,745 | 22 min | ~13/s |

### Step 4: Extract Strings (Binary Scan)

**Do NOT use `ida_strlist`** — scan manually with `FF_STRLIT` flag:

```python
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    ea = seg.start_ea
    while ea < seg.end_ea:
        flags = ida_bytes.get_flags(ea)
        if flags & ida_bytes.FF_STRLIT:
            s = ida_bytes.get_strlit_contents(ea, -1, -1)
            if s and len(s) > 2:
                text = s.decode('utf-8', errors='replace')
                # Categorize and save
                ea = ida_bytes.get_item_end(ea)
                continue
        ea = ida_bytes.next_head(ea, seg.end_ea)
```

### Step 5: Build SQLite Database

```python
import sqlite3
conn = sqlite3.connect("game.db")

# Functions
conn.execute('''CREATE TABLE functions (
    address INTEGER PRIMARY KEY, name TEXT, size INTEGER,
    is_named INTEGER, category TEXT
)''')

# Decompiled pseudocode
conn.execute('''CREATE TABLE decompiled (
    address INTEGER PRIMARY KEY, code TEXT
)''')

# Strings
conn.execute('''CREATE TABLE strings (
    address INTEGER PRIMARY KEY, text TEXT, category TEXT
)''')

# Checks/validations
conn.execute('''CREATE TABLE checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    function_address INTEGER, category TEXT, description TEXT
)''')

# Imports (Xbox 360) or SDK functions (PS2)
conn.execute('''CREATE TABLE imports (
    address INTEGER, module TEXT, name TEXT, ordinal INTEGER
)''')

# Segments
conn.execute('''CREATE TABLE segments (
    name TEXT PRIMARY KEY, start_address INTEGER,
    end_address INTEGER, size INTEGER
)''')

# Analysis documents
conn.execute('''CREATE TABLE analysis_docs (
    name TEXT PRIMARY KEY, content TEXT
)''')

# Cross-references (caller → callee)
conn.execute('''CREATE TABLE xrefs (
    from_address INTEGER, to_address INTEGER, type TEXT
)''')

# Indexes
conn.execute("CREATE INDEX idx_functions_name ON functions(name)")
conn.execute("CREATE INDEX idx_functions_category ON functions(category)")
conn.execute("CREATE INDEX idx_strings_category ON strings(category)")
conn.execute("CREATE INDEX idx_decompiled_address ON decompiled(address)")
```

### Step 5.5: Extract Cross-References (Xrefs)

**Default step** — extracts caller→callee relationships for all functions.

```python
# For PS2: Scan JAL/J instructions directly
# MIPS JAL (0x0C000000) = function call
# MIPS J (0x08000000) = tail jump

for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    if seg_name in ["seg000", ".text", ".code"]:
        ea = seg.start_ea
        while ea < seg.end_ea - 4:
            word = ida_bytes.get_dword(ea)
            if (word >> 26) == 0x03:  # JAL
                target = (word & 0x03FFFFFF) << 2
                if target in db_func_addrs:
                    conn.execute("INSERT INTO xrefs VALUES (?, ?, ?)",
                              (ea, target, "jal"))
            elif (word >> 26) == 0x02:  # J
                target = (word & 0x03FFFFFF) << 2
                if target in db_func_addrs:
                    conn.execute("INSERT INTO xrefs VALUES (?, ?, ?)",
                              (ea, target, "j"))
            ea += 4
```

**For Xbox 360**: Use `idautils.XrefsFrom()` after creating functions in IDA.

**Expected xrefs**: 10,000-45,000 per game depending on binary size.

### Step 5.6: Rename Functions by String Xrefs

**Default step** — renames `sub_XXXXXX` functions based on strings in their decompiled code.

```python
# For each unnamed function, find strings in its pseudocode
cur.execute("SELECT address, name FROM functions WHERE name LIKE 'sub_%'")
for func_addr, _ in cur.fetchall():
    cur.execute("SELECT code FROM decompiled WHERE address = ?", (func_addr,))
    row = cur.fetchone()
    if row and row[0]:
        strings_found = re.findall(r'"([^"]{3,50})"', row[0])
        if strings_found:
            best_string = max(strings_found, key=len)
            clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', best_string)[:60]
            if clean_name:
                cur.execute("UPDATE functions SET name = ? WHERE address = ?",
                          (f"str_{clean_name}", func_addr))
```

### Step 5.7: Subsystem Classification

**Default step** — classifies functions by what SDK APIs they call.

```python
# Platform-specific SDK patterns
PS2_PATTERNS = {
    "GRAPHICS": r"sceGs|sceGif|sceVif|sceVu0",
    "AUDIO": r"sceSd|sceSpk|sceSpu|sceAudio",
    "INPUT": r"scePad|sceMtap",
    "CDVD": r"sceCd|sceCdv",
    "IOP": r"sceSif|sceIop",
}

XBOX_PATTERNS = {
    "GRAPHICS": r"D3D|XeTexture|XeDraw|RwRaster",
    "NETWORK": r"XNet|NetDll|WSA|socket",
    "AUDIO": r"XAudio|XACT|RwAudio",
    "KINECT": r"Nui|Kinect|skeleton",
}

# Scan decompiled code for each pattern
for category, pattern in patterns.items():
    cur.execute("SELECT d.address, d.code FROM decompiled d "
                "JOIN functions f ON f.address = d.address")
    for addr, code in cur.fetchall():
        if code and re.search(pattern, code, re.IGNORECASE):
            cur.execute("UPDATE functions SET category = ? WHERE address = ?",
                      (category, addr))
```

### Step 6: Build Knowledge Base Markdown

Generate curated markdown (~500KB max for Claude context):

**Sections:**
1. Executive Summary (stats table)
2. Binary Layout (segments)
3. Function Census (size distribution, top 20)
4. Subsystem Classification
5. Checks & Validations Catalog
6. Named Functions with pseudocode (full)
7. Key Strings by Category (top 50 per category)
8. Patch Points & Hook Opportunities
9. SDK/Import Functions
10. Query Guide (SQL examples)

### Step 7: Checks/Validations Catalog

#### Xbox 360 Patterns
```python
xbox_patterns = {
    'DRM_Security': r'xex.*check|license|tamper|anti.*tamper',
    'Online_Auth': r'auth.*check|signin|privilege|profile.*check',
    'Kinect_Validate': r'kinect|nui|skeleton|gesture|tracking',
    'Network_Check': r'socket.*error|WSAE|dns.*fail|connection.*fail',
    'GPU_Hang': r'GPU.*hung|device.*lost|device.*removed',
    'Xbox_Live': r'xbox.*live|xlive|gold.*require',
}
```

#### PS2 Patterns
```python
ps2_patterns = {
    'CDVD_Check': r'sceCd|sceCdv|disc.*error|read.*error',
    'IOP_Check': r'sceSif|sceIop|iop.*reset|iop.*load',
    'GS_Error': r'gs.*error|graph.*error|display.*error',
    'Pad_Check': r'scePad|controller.*error|pad.*not.*found',
    'Memory_Card': r'mc[01]:|memory.*card|save.*error',
    'SPU2_Error': r'spu|audio.*error|sound.*error',
}
```

### Output Structure

```
Game Name Analysis/
├── game.db                        # PRIMARY: SQLite database
├── GAME_KNOWLEDGE_BASE.md         # Claude-readable summary
├── export/                        # JSON exports by category
│   ├── GRAPHICS.json
│   ├── AUDIO.json
│   ├── strings_*.json
│   └── ...
└── original_analysis_files/       # Source data (optional)
```

### Real Performance Numbers

| Game | Platform | Functions | Named | Decompiled | Xrefs | DB Size | Strings | Time |
|------|----------|-----------|-------|------------|-------|---------|---------|------|
| Skate 3 TU4 | Xbox 360 | 40,518 | 534 | 40,285 (99.4%) | TBD | 40 MB | 4,661 | 22 min |
| Sonic Free Riders | Xbox 360 | 23,341 | 353 | 23,242 (99.6%) | TBD | 31 MB | 8,635 | 22 min |
| Sonic Riders ZG | PS2 | 17,745 | 578 | 17,742 (100%) | TBD | 25 MB | 8,470 | 22 min |
| Biohazard Outbreak | PS2 | 4,775 | 163 | 4,775 (100%) | 12,836 | 4.4 MB | 2,602 | 7 min |
| Biohazard Outbreak 2 | PS2 | 4,835 | 170 | 4,835 (100%) | 13,136 | 4.4 MB | 2,903 | 7 min |
| Tony Hawk Downhill Jam | PS2 | 10,312 | 240 | 5,002 (48.5%) | 43,272 | 7.5 MB | 7,233 | 7 min |

### Common Pitfalls & Fixes

| Problem | Solution |
|---------|----------|
| `idaapi` import fails before `open_database` | Import AFTER `idapro.open_database()` |
| `ida_hexrays.hexrays_available()` not found | Use `ida_hexrays.decompile()` directly |
| `ida_segment.Segments()` not found | Use `ida_segment.get_first_seg()` + `get_next_seg()` |
| `ida_bytes.get_str_type()` not found | Use `ida_bytes.get_flags(ea) & FF_STRLIT` |
| Functions show as `sub_XXXXXX` | Normal — <5% of functions have names in retail binaries |
| Hex regex fails on lowercase | Use `[0-9a-fA-F]` not `[0-9A-F]` |
| Decompiled count < function count | Some functions are data, not code — decompiler returns None |
| Strings count low | Scan with FF_STRLIT flag, don't use ida_strlist |
| PS2: COP2/VU0 instructions show as `???` | Install `ida-emotionengine.py` plugin |
| PS2: ELF not loading | Verify with `readelf -h`, check endianness |
| Xbox 360: Import table empty | Loaded as raw binary — scan .idata manually |
| Stripped binary: few functions | Use MIPS prologue scanning (0x27BD pattern) |
| Category column missing | DB uses 'subsystem' instead — export handles both |

### Querying the Database

```sql
-- Find function by address
SELECT * FROM functions WHERE address = 0x82780748;  -- Xbox 360
SELECT * FROM functions WHERE address = 0x100008;    -- PS2

-- Get decompiled code
SELECT code FROM decompiled WHERE address = 0x82780748;

-- Find functions by name pattern
SELECT * FROM functions WHERE name LIKE '%Blaze%';   -- Xbox 360
SELECT * FROM functions WHERE name LIKE 'sce%';      -- PS2 SDK

-- List strings by category
SELECT * FROM strings WHERE category = 'KINECT';     -- Xbox 360
SELECT * FROM strings WHERE category = 'PS2_SDK';    -- PS2

-- Count by category
SELECT category, COUNT(*) FROM functions GROUP BY category;

-- Get named functions with pseudocode
SELECT f.name, d.code FROM functions f
JOIN decompiled d ON f.address = d.address
WHERE f.is_named=1;
```

---

## 23. BATCH ANALYSIS (MULTI-GAME)

Process multiple games sequentially with a single script. Each game gets its own SQLite DB + Knowledge Base.

### Batch Script Pattern

```python
GAMES = [
    {"elf": "/path/to/game1.elf", "out": "/output/dir1/", "db_name": "game1.db", ...},
    {"elf": "/path/to/game2.elf", "out": "/output/dir2/", "db_name": "game2.db", ...},
]

for game in GAMES:
    # Must close previous database before opening new one
    idapro.close_database()
    result = idapro.open_database(game["elf"], run_auto_analysis=True)
    # ... extract functions, decompile, strings, build DB ...
```

**CRITICAL**: Call `idapro.close_database()` between games. Without it, IDA reuses the previous database and you get duplicate data.

### PS2 ISO Extraction Workflow

```bash
# 1. Extract SYSTEM.CNF to find ELF path
7z e -o/tmp/game "/path/to/game.iso" SYSTEM.CNF -y
cat /tmp/game/SYSTEM.CNF  # Shows: BOOT2 = cdrom0:\SLUS_XXX.XX;1

# 2. Extract the ELF
7z e -o/tmp/game "/path/to/game.iso" SLUS_XXX.XX -y
file /tmp/game/SLUS_XXX.XX  # Verify: ELF 32-bit LSB executable, MIPS

# 3. Analyze with IDA
python3 analyze.py  # Uses idapro.open_database()
```

### Common PS2 ELF Naming

| Code | Region | Example |
|------|--------|---------|
| SLUS | USA | SLUS_216.42 (Sonic Riders) |
| SCES | Europe | SCES_524.56 |
| SLPM | Japan | SLPM_654.28 (Biohazard Outbreak) |
| SCPS | Japan | SCPS_150.01 |

### Stripped Binary Handling

When ELF is stripped (no symbols), IDA auto-analysis finds fewer functions:

| Binary Type | Typical Functions Found | Workaround |
|-------------|------------------------|------------|
| Not stripped | 5,000-20,000 | Full analysis |
| Stripped | 10-100 | Use pattern matching, string xrefs |

**Detection**: `file game.elf | grep "stripped"`

**Workaround for stripped binaries**:
1. Strings are still extractable (7,000+ typical)
2. Use string xrefs to find key functions
3. Manual function creation via `ida_funcs.add_func(ea)`

### MIPS Prologue Scanning (PS2 Stripped Binaries)

For stripped PS2 ELFs, scan `.text` for MIPS function prologues:

```python
# MIPS addiu sp, sp, -imm (opcode: 0x27BDxxxx)
ea = code_seg.start_ea
while ea < code_seg.end_ea - 4:
    word = ida_bytes.get_dword(ea)
    if (word >> 16) == 0x27BD:  # addiu sp, sp, imm
        imm = word & 0xFFFF
        if imm > 0x8000:  # Negative = stack allocation
            if not ida_funcs.get_func(ea):
                ida_funcs.add_func(ea)
    ea += 4
```

**Results**: Tony Hawk's Downhill Jam went from 10 → 10,312 functions using this technique.

### Enhanced MIPS Analysis (Comprehensive)

Complete workflow for maximum function detection in stripped PS2 binaries.

#### Step 1: Prologue Scanning (Extended)

```python
PROLOGUE_PATTERNS = [0x27BD, 0x27BC]  # addiu sp, sp, imm
ea = code_seg.start_ea
while ea < code_seg.end_ea - 4:
    word = ida_bytes.get_dword(ea)
    if (word >> 16) in PROLOGUE_PATTERNS:
        if (word & 0xFFFF) > 0x8000:  # Negative = stack alloc
            if not ida_funcs.get_func(ea):
                ida_funcs.add_func(ea)
    ea += 4
```

#### Step 2: JAL Target Following

```python
for func_ea in list(idautils.Functions()):
    fobj = ida_funcs.get_func(func_ea)
    if not fobj: continue
    for head in idautils.Heads(fobj.start_ea, fobj.end_ea):
        word = ida_bytes.get_dword(head)
        if (word >> 26) == 0x03:  # JAL
            target = (word & 0x03FFFFFF) << 2
            if not ida_funcs.get_func(target):
                ida_funcs.add_func(target)
```

#### Step 3: Data Pointer Scanning

```python
for seg_ea in idautils.Segments():
    seg = ida_segment.getseg(seg_ea)
    if ida_segment.get_segm_name(seg) in [".text", "seg000"]:
        continue  # Skip code
    ea = seg.start_ea
    while ea < seg.end_ea - 4:
        val = ida_bytes.get_dword(ea)
        if code_seg.start_ea <= val < code_seg.end_ea:
            if not ida_funcs.get_func(val):
                ida_funcs.add_func(val)
        ea += 4
```

#### Step 4: Recursive Decompilation

```python
new_functions = True
while new_functions:
    new_functions = False
    for func_ea in list(idautils.Functions()):
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                for match in re.finditer(r'0x([0-9A-Fa-f]{8})', str(cfunc)):
                    addr = int(match.group(1), 16)
                    if code_seg.start_ea <= addr < code_seg.end_ea:
                        if not ida_funcs.get_func(addr):
                            ida_funcs.add_func(addr)
                            new_functions = True
        except: pass
```

**Expected**: +20-50% more functions vs basic prologue scanning.

### Xbox 360

| Game | Functions | Named | Decompiled | Xrefs | DB | Location |
|------|-----------|-------|------------|-------|-----|----------|
| Skate 3 TU4 | 40,518 | 534 | 40,285 (99.4%) | 2,877 | 39.2 MB | `analisis/Skate3_TU4_Xbox360/` |
| Sonic Free Riders | 23,341 | 353 | 23,242 (99.6%) | 2,450 | 30.6 MB | `analisis/Sonic_Free_Riders_Xbox360/` |

### PS2

| Game | Functions | Named | Decompiled | Xrefs | DB | Location |
|------|-----------|-------|------------|-------|-----|----------|
| Sonic Riders ZG | 17,745 | 1,167 | 17,742 (100%) | 62,274 | 26.9 MB | `analisis/Sonic_Riders_ZG_PS2/` |
| Biohazard Outbreak | 4,875 | 322 | 4,849 (99.5%) | 12,836 | 5.0 MB | `analisis/Biohazard_Outbreak_PS2/` |
| Biohazard Outbreak File 2 | 4,936 | 331 | 4,897 (99.2%) | 13,136 | 5.1 MB | `analisis/Biohazard_Outbreak_File2_PS2/` |
| Tony Hawk's Downhill Jam | 12,923 | 1,631 | 11,756 (91.0%) | 43,272 | 18.0 MB | `analisis/Tony_Hawk_Downhill_Jam_PS2/` |

**Total**: 6 games, 104,338 functions, 102,771 decompiled, 136,845 xrefs, 124.9 MB

### Performance Summary

| Platform | Avg Functions | Avg Xrefs | Avg Decomp Time | Avg DB Size |
|----------|---------------|-----------|-----------------|-------------|
| Xbox 360 | 31,930 | 2,664 | 22 min | 35 MB |
| PS2 | 8,644 | 32,880 | 15 min | 14 MB |

---

## 24. UNIFIED ANALYSIS TOOL (PS2 + Xbox 360)

Entry point: `analyze.py` — detects platform and runs appropriate analysis.

### Flow

```
analyze.py game.xex|game.elf /output/
├── Detect platform: PS2 (ELF/MIPS) or Xbox 360 (XEX/PPC)
├── Xbox 360 → IDA analysis → DB + Knowledge Base + JSON
└── PS2 → Phase 1: IDA analysis → DB + Knowledge Base + JSON
          → Phase 2: PS2Recomp export → CSV + TOML
```

### Usage

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 analyze.py game.elf /output/dir
```

### Output (PS2)

```
<game>_PS2/
├── <game>.db              (SQLite: functions, decompiled, strings, xrefs)
├── <GAME>_KNOWLEDGE_BASE.md
├── config.toml            (PS2Recomp config)
├── functions.csv          (Name,Start,End,Size)
└── export/ (JSONs)
```

### Output (Xbox 360)

```
<game>_Xbox360/
├── <game>.db              (SQLite)
├── <GAME>_KNOWLEDGE_BASE.md
└── export/ (JSONs)
```

---

## 25. PS2RECOMP EXPORT (PS2 only)

Script: `ps2_recomp_export.py` — generates CSV + TOML for ps2xRecomp.

### Features

- SCE SHA-1 signature matching (52 SDK libraries, 5,323 function names)
- Code-based detection (syscalls, MMIO, thunks)
- Batch mode: `python3 ps2_recomp_export.py --batch /path/to/isos/ /output/`
- Auto-extraction of SCE database from PS2Recomp source

### Usage

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 ps2_recomp_export.py game.elf /output/dir
```

### Libraries Detected

libkernl (926), libhttps (107), libhig (45), libc (40), libmpeg (33), libnet (33), libgraph (28), libgcc (27), libdma (5), libvu0 (3), libpad (2), libmc (2)

---

## 26. XBOX 360 RECOMP EXPORT (Xbox 360 only)

Script: `xbox360_recomp_export.py` — generates TOML for ReXGlue SDK from SQLite DB.

### Features

- Reads DB generated by `analyze.py` (Phase 1)
- Maps function names to ReXGlue runtime handlers (REXCRT)
- Generates TOML config for ReXGlue codegen
- Supports switch tables and invalid instructions (optional JSONs)

### Usage

```bash
python3 xbox360_recomp_export.py \
  --db game.db \
  --file-path game.xex \
  --project-name my_game \
  --output config.toml
```

### ReXGlue Runtime Groups

| Group | Functions | Description |
|-------|-----------|-------------|
| Heap | RtlAllocateHeap, RtlFreeHeap, RtlSizeHeap, RtlReAllocateHeap | Memory allocation (all-or-nothing) |
| File I/O | CreateFileA, ReadFile, WriteFile, ... | File operations |
| Memory | memcpy, memmove, memset, XMemCpy, XMemSet | Memory operations |
| String | strncmp, strncpy, strchr, strstr, ... | String operations |

---

## 26. FULL IDA ANALYSIS (PS2 + Xbox 360)

Script: `ps2_full_analysis.py` — generates SQLite DB + Knowledge Base + JSON exports.

### Features

- Hex-Rays decompilation of all functions
- SCE SHA-1 signature matching (PS2)
- String extraction and categorization
- Cross-reference extraction
- SQLite database with functions, decompiled code, strings, xrefs
- Knowledge Base markdown with executive summary
- JSON exports by category

### Usage

```bash
PYTHONPATH="/path/to/IDA:/path/to/IDA/python" \
  python3 ps2_full_analysis.py game.elf /output/dir
```

### Output

```
<game>/
├── <game>.db              (SQLite)
├── <GAME>_KNOWLEDGE_BASE.md
└── export/
    ├── decompiled_Unknown.json
    ├── segments.json
    ├── strings_*.json
    └── Unknown.json
```

---

## 27. IDA vs GHIDRA for PS2Recomp

| Aspect | IDA Pro | Ghidra |
|--------|---------|--------|
| Decompiler MIPS | hexmips (mejor en algunos casos) | Integrado |
| Headless | idat -A -OIDAPython | analyzeHeadless |
| License | Comercial | Gratis |
| Speed | Más rápido | Más lento |
| Scripts | Python | Java/Python |
| Recommended for | Análisis rápido, decompiling | Games strippados (workflow oficial) |
    "realloc", "sin", "snprintf", "sprintf", "sqrt", "srand", "stat",
    "strcasecmp", "strcat", "strchr", "strcmp", "strcpy", "strlen", "strncat",
    "strncmp", "strncpy", "strrchr", "strstr", "tan", "vfprintf", "vsprintf",
    "write", "__divdi3",
    # SCE IOP / DBC / MC / CD / Pad / DMA / GS / VIF / SIF / Synth / VU
    "sceCdSync", "sceCdSyncS", "sceCdInit", "sceCdGetDiskType", "sceCdMmode",
    "sceCdRead", "sceCdSeek", "sceCdPause", "sceCdStandby", "sceCdStop",
    "sceCdBreak", "sceCdDiskReady", "sceCdStatus", "sceCdGetError",
    "sceCdCallback", "sceCdSearchFile", "sceCdGetToc", "sceCdStInit",
    "sceCdStRead", "sceCdStStart", "sceCdStStop", "sceCdStStat",
    "sceCdStSeek", "sceCdStSeekF", "sceCdStPause", "sceCdStResume",
    "sceCdReadClock", "sceCdReadChain", "sceCdIntToPos", "sceCdPosToInt",
    "sceCdTrayReq", "sceCdApplyNCmd", "sceCdNcmdDiskReady", "sceCdGetReadPos",
    "sceCdReadIOPm", "sceCdLayerSearchFile", "sceCdPowerOff",
    "sceCdGetDiskType2", "sceCdDelayThread",
    "sceDmaReset", "sceDmaPutEnv", "sceDmaGetChan", "sceDmaSend",
    "sceDmaRecv", "sceDmaSync", "sceDmaSendN", "sceDmaRecvN",
    "sceDmaSendI", "sceDmaRecvI", "sceDmaCallback", "sceDmaDebug",
    "sceDmaGetEnv", "sceDmaPause", "sceDmaRestart", "sceDmaWatch",
    "sceDmaLastSyncTime", "sceDmaSyncN", "sceDmaSendM", "sceDmaPutStallAddr",
    "sceSdRemoteInit", "sceSdRemote", "sceSdRemoteInit",
    "sceSifInitCmd", "sceSifExitCmd", "sceSifAddCmdHandler",
    "sceSifRemoveCmdHandler", "sceSifSendCmd", "sceSifWriteBackDCache",
    "sceSifInitRpc", "sceSifBindRpc", "sceSifCallRpc", "sceSifCheckStatRpc",
    "sceSifInitIopHeap", "sceSifAllocIopHeap", "sceSifFreeIopHeap",
    "sceSifLoadIopHeap", "sceSifResetIop", "sceSifSyncIop", "sceSifRebootIop",
    "sceSifLoadFileReset", "sceSifSetDma", "sceSifSetDChain",
    "sceSifStopDma", "sceSifDmaStat", "sceSifGetDataTable",
    "sceSifSetRpcQueue", "sceSifRemoveRpcQueue", "sceSifRemoveRpc",
    "sceSifRegisterRpc", "sceSifRpcLoop", "sceSifGetNextRequest",
    "sceSifExecRequest", "sceSifIsAliveIop", "sceSifGetIopAddr",
    "sceSifSetIopAddr", "sceSifGetReg", "sceSifSetReg", "sceSifGetSreg",
    "sceSifSetSreg", "sceSifSetCmdBuffer", "sceSifSetSysCmdBuffer",
    "sceSifAllocSysMemory", "sceSifFreeSysMemory", "sceSifGetOtherData",
    "sceSifLoadModuleBuffer", "sceSifLoadModule", "sceSifStopModule",
    "sceSifAddCmdHandler", "sceSifRemoveCmdHandler",
    "isceSifSendCmd", "isceSifSetDChain", "isceSifSetDma",
    "sceFsInit", "sceFsReset", "sceOpen", "sceClose", "sceLseek",
    "sceRead", "sceWrite", "sceDevctl",
    "sceFsSemInit", "sceFsSemExit", "sceFsSigSema", "sceFsIntrSigSema",
    "sceFsDbChk", "sceFsIobSemaMK",
    "sceDeci2Open", "sceDeci2Close", "sceDeci2ReqSend", "sceDeci2Poll",
    "sceDeci2ExRecv", "sceDeci2ExSend", "sceDeci2ExReqSend", "sceDeci2ExLock",
    "sceDeci2ExUnLock",
    "sceTtyHandler", "sceTtyWrite", "sceTtyInit", "sceTtyRead",
    "scePadInit", "scePadInit2", "scePadEnd", "scePadOpen", "scePadClose",
    "scePadRead", "scePadGetState", "scePadGetReqState", "scePadSetReqState",
    "scePadGetButtonMask", "scePadInfoAct", "scePadInfoComb", "scePadInfoMode",
    "scePadSetActAlign", "scePadSetActDirect", "scePadSetButtonInfo",
    "scePadSetMainMode", "scePadPortOpen", "scePadPortClose",
    "scePadGetModVersion", "scePadGetPortMax", "scePadGetSlotMax",
    "scePadGetFrameCount", "scePadGetDmaStr", "scePadSetVrefParam",
    "scePadSetWarningLevel", "scePadStateIntToStr", "scePadReqIntToStr",
    "scePadEnterPressMode", "scePadExitPressMode",
    "sceMcInit", "sceMcEnd", "sceMcFormat", "sceMcUnformat", "sceMcOpen",
    "sceMcClose", "sceMcRead", "sceMcWrite", "sceMcDelete", "sceMcSeek",
    "sceMcMkdir", "sceMcChdir", "sceMcRmdir", "sceMcGetDir", "sceMcSync",
    "sceMcGetInfo", "sceMcFlush", "sceMcSetFileInfo", "sceMcRename",
    "sceMcGetSlotMax", "sceMcGetEntSpace", "sceMcChangeThreadPriority",
    "sceGsResetGraph", "sceGsSyncV", "sceGsSyncPath", "sceGsSetDefLoadImage",
    "sceGsExecLoadImage", "sceGsSetDefStoreImage", "sceGsExecStoreImage",
    "sceGsSetDefDispEnv", "sceGsPutDispEnv", "sceGsSetDefDrawEnv",
    "sceGsPutDrawEnv", "sceGsSetDefClear", "sceGsSetDefDBuff",
    "sceGsSetDefDBuffDc", "sceGsSwapDBuff", "sceGsSwapDBuffDc",
    "sceGsSyncVCallback", "sceGsGetGParam", "sceGsResetPath",
    "sceGsSetDefDrawEnv2", "sceGszbufaddr",
    "sceGifPkInit", "sceGifPkReset", "sceGifPkOpenGifTag",
    "sceGifPkCloseGifTag", "sceGifPkAddGsAD", "sceGifPkAddGsData",
    "sceGifPkRef", "sceGifPkRefLoadImage", "sceGifPkTerminate",
    "sceGifPkReserve", "sceGifPkEnd", "sceGifPkCnt",
    "sceVif1PkInit", "sceVif1PkReset", "sceVif1PkOpenGifTag",
    "sceVif1PkCloseGifTag", "sceVif1PkOpenDirectCode",
    "sceVif1PkCloseDirectCode", "sceVif1PkAddGsAD", "sceVif1PkCall",
    "sceVif1PkTerminate", "sceVif1PkReserve", "sceVif1PkEnd", "sceVif1PkCnt",
    "sceVif1PkAlign",
    "sceVu0AddVector", "sceVu0SubVector", "sceVu0MulVector", "sceVu0DivVector",
    "sceVu0CopyVector", "sceVu0CopyVectorXYZ", "sceVu0ScaleVector",
    "sceVu0ScaleVectorXYZ", "sceVu0DivVectorXYZ", "sceVu0InterVector",
    "sceVu0InterVectorXYZ", "sceVu0Normalize", "sceVu0InnerProduct",
    "sceVu0OuterProduct", "sceVu0ApplyMatrix", "sceVu0MulMatrix",
    "sceVu0CopyMatrix", "sceVu0TransposeMatrix", "sceVu0UnitMatrix",
    "sceVu0InversMatrix", "sceVu0RotMatrix", "sceVu0RotMatrixX",
    "sceVu0RotMatrixY", "sceVu0RotMatrixZ", "sceVu0TransMatrix",
    "sceVu0CameraMatrix", "sceVu0ViewScreenMatrix", "sceVu0RotTransPers",
    "sceVu0RotTransPersN", "sceVu0LightColorMatrix", "sceVu0NormalLightMatrix",
    "sceVu0FTOI0Vector", "sceVu0FTOI4Vector", "sceVu0ITOF0Vector",
    "sceVu0ITOF4Vector", "sceVu0ITOF12Vector", "sceVu0ClampVector",
    "sceVu0DropShadowMatrix", "sceVu0ClipAll", "sceVu0ClipScreen",
    "sceVu0ClipScreen3",
    "sceSSyn_SetOutputAssign", "sceSSyn_SetOutputMode", "sceSSyn_SetMasterVolume",
    "sceSSyn_SetOutPortVolume", "sceSSyn_SetPortVolume", "sceSSyn_SetPortMaxPoly",
    "sceSSyn_SetChPriority", "sceSSyn_SetTvaEnvMode", "sceSSyn_SendShortMsg",
    "sceSSyn_SendNrpnMsg", "sceSSyn_SendRpnMsg", "sceSSyn_SendExcMsg",
    "sceSSyn_BreakAtick", "sceSSyn_ClearBreakAtick",
    "sceSynthesizerAssignNoteOn", "sceSynthesizerAssignNoteOff",
    "sceSynthesizerAssignAllNoteOff", "sceSynthesizerAssignAllSoundOff",
    "sceSynthesizerAssignHoldChange", "sceSynthesizerCalcEnv",
    "sceSynthesizerCalcPortamentPitch", "sceSynthesizerCalcTvfCoefAll",
    "sceSynthesizerCalcTvfCoefF0", "sceSynthesizerCent2PhaseInc",
    "sceSynthesizerChangeEffectSend", "sceSynthesizerChangeHsPanpot",
    "sceSynthesizerChangeNrpnCutOff", "sceSynthesizerChangeNrpnLfoDepth",
    "sceSynthesizerChangeNrpnLfoRate", "sceSynthesizerChangeOutAttrib",
    "sceSynthesizerChangeOutVol", "sceSynthesizerChangePanpot",
    "sceSynthesizerChangePartBendSens", "sceSynthesizerChangePartExpression",
    "sceSynthesizerChangePartHsExpression", "sceSynthesizerChangePartHsPitchBend",
    "sceSynthesizerChangePartModuration", "sceSynthesizerChangePartPitchBend",
    "sceSynthesizerChangePartVolume", "sceSynthesizerChangePortamento",
    "sceSynthesizerChangePortamentoTime", "sceSynthesizerClearKeyMap",
    "sceSynthesizerClearSpr", "sceSynthesizerCopyOutput",
    "sceSynthesizerDmaFromSPR", "sceSynthesizerDmaSpr",
    "sceSynthesizerDmaToSPR", "sceSynthesizerGetPartOutLevel",
    "sceSynthesizerGetPartial", "sceSynthesizerGetSampleParam",
    "sceSynthesizerHsMessage", "sceSynthesizerLfoNone", "sceSynthesizerLfoProc",
    "sceSynthesizerLfoSawDown", "sceSynthesizerLfoSawUp",
    "sceSynthesizerLfoSquare", "sceSynthesizerReadNoise",
    "sceSynthesizerReadNoiseAdd", "sceSynthesizerReadSample16",
    "sceSynthesizerReadSample16Add", "sceSynthesizerReadSample8",
    "sceSynthesizerReadSample8Add", "sceSynthesizerResetPart",
    "sceSynthesizerRestorDma", "sceSynthesizerSelectPatch",
    "sceSynthesizerSendShortMessage", "sceSynthesizerSetMasterVolume",
    "sceSynthesizerSetRVoice", "sceSynthesizerSetupDma",
    "sceSynthesizerSetupLfo", "sceSynthesizerSetupMidiModuration",
    "sceSynthesizerSetupMidiPanpot", "sceSynthesizerSetupNewNoise",
    "sceSynthesizerSetupReleaseEnv", "sceSynthesizerSetupTruncateTvaEnv",
    "sceSynthesizerSetupTruncateTvfPitchEnv", "sceSynthesizerSetuptEnv",
    "sceSynthesizerTonegenerator", "sceSynthesizerTransposeMatrix",
    "sceSynthesizerTvfProcI", "sceSynthesizerTvfProcNI",
    "sceSynthesizerWaitDmaFromSPR", "sceSynthesizerWaitDmaToSPR",
    "sceSynthsizerGetDrumPatch", "sceSynthsizerGetMeloPatch",
    "sceSynthsizerLfoNoise", "sceSdCallBack",
    "sceVu0Reset", "sceVpu0Reset", "sceDevVu0Reset", "sceDevVif0Reset",
    "sceDevVu1Pause", "sceDevVu1PutDBit", "sceDevVu1Sync",
    "InitTLB", "sceSetBrokenLink", "sceSetPtm",
    "sceDbcInit", "sceDbcGetConnection", "sceDbcSendData2",
    "sceDbcGetModVersion", "sceDbcSetWorkAddr",
}

PS2_API_PREFIXES = {
    "sce", "Sce", "SCE", "sif", "Sif", "SIF", "gs", "Gs", "GS",
    "dma", "Dma", "DMA", "iop", "Iop", "IOP", "vif", "Vif", "VIF",
    "spu", "Spu", "SPU", "mc", "Mc", "MC", "libc", "Libc", "LIBC",
}

KNOWN_STDLIB = {
    "printf", "sprintf", "snprintf", "fprintf", "vprintf", "vfprintf",
    "vsprintf", "vsnprintf", "puts", "putchar", "getchar", "gets", "fgets",
    "__mcmp", "__sbprintf", "__sprint", "__sprint_r",
    "malloc", "free", "calloc", "realloc", "memalign", "memclr",
    "aligned_alloc", "posix_memalign",
    "memcpy", "memset", "memmove", "memcmp", "memchr", "bcopy", "bzero",
    "strcpy", "strncpy", "strcat", "strncat", "strcmp", "strncmp", "strlen",
    "strstr", "strchr", "strrchr", "strdup", "strtok", "strtok_r", "strerror",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind", "fflush",
    "fgetc", "feof", "ferror", "clearerr", "fileno", "tmpfile", "remove", "rename",
    "open", "close", "read", "write", "lseek", "stat", "fstat",
    "atoi", "atol", "atoll", "atof", "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strtof", "rand", "srand", "random", "srandom", "drand48",
    "sqrt", "pow", "exp", "log", "log10", "sin", "cos", "tan", "asin", "acos",
    "atan", "atan2", "sinh", "cosh", "tanh", "floor", "ceil", "fabs", "fmod",
    "frexp", "ldexp", "modf", "time", "ctime", "clock", "difftime", "mktime",
    "localtime", "gmtime", "asctime", "strftime", "gettimeofday", "nanosleep",
    "usleep", "atexit", "system", "getpid", "fork", "waitpid", "qsort", "bsearch",
    "abs", "div", "labs", "ldiv", "llabs", "lldiv", "isalnum", "isalpha",
    "isdigit", "islower", "isupper", "isspace", "tolower", "toupper",
    "setjmp", "longjmp", "getenv", "setenv", "unsetenv", "perror", "fputc",
    "getc", "ungetc", "freopen", "setvbuf", "setbuf", "strnlen", "strspn",
    "strcspn", "strcasecmp", "strncasecmp",
}

KERNEL_RUNTIME_RE = re.compile(
    r"^(?:"
    r"(?:Create|Delete|Start|ExitDelete|Exit|Terminate|Suspend|Resume|Sleep|Wakeup|"
    r"CancelWakeup|Change|Rotate|Release|Setup|Register|Query|Get|Set|Refer|Poll|Wait|"
    r"Signal|Enable|Disable|Flush|Reset|Add|Init)"
    r"(?:Thread|Sema|EventFlag|Alarm|Intc|IntcHandler2|Dmac|DmacHandler2|"
    r"OsdConfigParam|MemorySize|VSyncFlag|Heap|TLS|Status|Cache|Syscall|TLB|TLBEntry|GsCrt)"
    r"|EndOfHeap|GsGetIMR|GsPutIMR|Deci2Call|Sif[A-Za-z0-9_]+"
    r"|i(?:SignalSema|PollSema|ReferSemaStatus|SetEventFlag|ClearEventFlag|"
    r"PollEventFlag|ReferEventFlagStatus|WakeupThread|CancelWakeupThread|"
    r"ReleaseWaitThread|SetAlarm|CancelAlarm|FlushCache|sceSifSetDma|sceSifSetDChain)"
    r")$"
)

C_LIB_RE = re.compile(
    r"^_*(mem|str|time|f?printf|f?scanf|malloc|free|calloc|realloc|atoi|itoa|"
    r"rand|srand|abort|exit|atexit|getenv|system|bsearch|qsort|abs|labs|div|ldiv|"
    r"mblen|mbtowc|wctomb|mbstowcs|wcstombs).*"
)

# ─── CLASSIFICATION ───────────────────────────────────────────────

def normalize_name(name):
    """Strip optional leading underscore."""
    if name and name.startswith("_") and len(name) > 1:
        return name[1:]
    return name


def resolve_runtime_handler(name):
    """Return the runtime handler name if the function has one, else ''."""
    if not name:
        return ""
    if name in RUNTIME_HANDLERS:
        return name
    norm = normalize_name(name)
    if norm != name and norm in RUNTIME_HANDLERS:
        return norm
    underscored = "_" + name
    if not name.startswith("_") and underscored in RUNTIME_HANDLERS:
        return underscored
    return ""


def has_reliable_name(name):
    """Return False for auto-generated names like sub_XXXX, FUN_XXXX, etc."""
    if not name:
        return False
    for prefix in ("sub_", "FUN_", "func_", "entry_", "function_", "LAB_"):
        if name.startswith(prefix):
            return False
    has_alpha = any(c.isalpha() for c in name)
    all_hex = all(c in "0123456789abcdefABCDEFxX_" for c in name)
    if not has_alpha:
        return False
    if (name.startswith("0x") or name.startswith("0X")) and all_hex:
        return False
    return True


def has_ps2_api_prefix(name):
    if not name:
        return False
    base = normalize_name(name)
    for prefix in PS2_API_PREFIXES:
        if not base.startswith(prefix):
            continue
        if len(base) == len(prefix):
            return True
        if not base[len(prefix)].islower():
            return True
    return False


def is_library_function(name):
    if not name or not has_reliable_name(name):
        return False
    if resolve_runtime_handler(name):
        return True
    norm = normalize_name(name)
    if resolve_runtime_handler(norm):
        return True
    if KERNEL_RUNTIME_RE.match(norm):
        return True
    if norm in KNOWN_STDLIB or name in KNOWN_STDLIB:
        return True
    if has_ps2_api_prefix(name):
        return True
    return bool(C_LIB_RE.match(norm))


def classify_function(func_ea, func_name):
    """Returns (category, handler_name) tuple."""
    handler = resolve_runtime_handler(func_name)
    if handler:
        return ("stub", handler)
    norm = normalize_name(func_name)
    handler = resolve_runtime_handler(norm)
    if handler:
        return ("stub", handler)
    if is_library_function(func_name):
        return ("untracked_stub", func_name)
    return ("game", func_name)


# ─── ENTRY POINT DETECTION ────────────────────────────────────────

def get_entry_address():
    """Get ELF entry point address."""
    for i in range(ida_entry.get_entry_qty()):
        ord = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ord)
        if ea and ea != idaapi.BADADDR:
            return ea
    # Fallback: check first code segment
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg.type == idaapi.SEG_CODE:
            return seg.start_ea
    return None


# ─── SIMD / PERFORMANCE DETECTION ─────────────────────────────────

def has_simd_instructions(func_ea):
    """Check if function uses MIPS MMI/COP2 (VU0) instructions."""
    fobj = ida_funcs.get_func(func_ea)
    if not fobj:
        return False
    ea = fobj.start_ea
    while ea < fobj.end_ea:
        word = ida_bytes.get_dword(ea) if ida_bytes.is_mapped(ea) else 0
        # COP2 (VU0 macro mode): opcode field = 0x4A
        if (word >> 26) == 0x4A:
            return True
        # MMI opcode field = 0x1C
        if (word >> 26) == 0x1C:
            return True
        ea = ida_bytes.next_head(ea, fobj.end_ea)
    return False


def has_heavy_loops(func_ea):
    """Detect functions with many backward branches (loops)."""
    fobj = ida_funcs.get_func(func_ea)
    if not fobj:
        return False
    loop_count = 0
    ea = fobj.start_ea
    while ea < fobj.end_ea:
        word = ida_bytes.get_dword(ea) if ida_bytes.is_mapped(ea) else 0
        # BEQ, BNE, BGTZ, BLEZ, BGEZ, BLTZ (I-type branches)
        opcode = (word >> 26) & 0x3F
        if opcode in (0x04, 0x05, 0x07, 0x06, 0x01):
            imm = (word & 0xFFFF)
            if imm & 0x8000:  # Sign-extend: negative offset = backward branch
                loop_count += 1
        ea = ida_bytes.next_head(ea, fobj.end_ea)
    return loop_count > 5


# ─── OUTPUT GENERATION ────────────────────────────────────────────

def generate_csv(records, output_path):
    """Generate CSV function map: Name,Start,End,Size."""
    with open(output_path, "w") as f:
        f.write("Name,Start,End,Size\n")
        for rec in records:
            size = rec["end"] - rec["start"]
            f.write(f"{rec['name']},0x{rec['start']:08X},0x{rec['end']:08X},{size}\n")
    print(f"[PS2Recomp] CSV written: {output_path} ({len(records)} functions)")


def generate_toml(records, classifications, entry_ea, output_path, elf_path):
    """Generate TOML config for ps2xRecomp."""
    stubs = []
    untracked = []
    perf_critical = []

    for rec in records:
        cat, handler = classifications.get(rec["address"], ("game", rec["name"]))
        selector = f"{rec['name']}@0x{rec['address']:08X}"
        if cat == "stub":
            stubs.append(selector)
        elif cat == "untracked_stub":
            untracked.append(selector)

        if has_simd_instructions(rec["address"]):
            perf_critical.append((rec["name"], "Uses SIMD instructions"))
        elif has_heavy_loops(rec["address"]):
            perf_critical.append((rec["name"], "Contains heavy loops"))

    with open(output_path, "w") as f:
        f.write(f"# PS2Recomp configuration (generated by IDA Pro)\n")
        f.write(f"# Input: {elf_path}\n\n")
        f.write("[general]\n")
        f.write(f'input = "{elf_path}"\n')
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

        f.write("skip = []\n\n")

        if perf_critical:
            f.write("[performance]\n")
            f.write("critical = [\n")
            for name, reason in perf_critical:
                f.write(f'  "{name}", # {reason}\n')
            f.write("]\n")

    print(f"[PS2Recomp] TOML written: {output_path}")
    print(f"  Stubs: {len(stubs)}")
    f"  Untracked: {len(untracked)}"
    f"  Performance: {len(perf_critical)}")


def main():
    # Determine output directory
    output_dir = "/tmp/ps2recomp_output"
    if len(idaapi.get_plugin_options("ps2_ida_recomp_export.py")) > 0:
        output_dir = idaapi.get_plugin_options("ps2_ida_recomp_export.py")

    # Also accept from sys.argv when running standalone
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        output_dir = sys.argv[1]

    os.makedirs(output_dir, exist_ok=True)

    # Get input file name
    input_file = idaapi.get_input_file_path()
    elf_name = os.path.basename(input_file)

    print(f"[PS2Recomp] Input: {elf_name}")
    print(f"[PS2Recomp] Output: {output_dir}")

    # Collect all functions
    records = []
    classifications = {}

    for func_ea in idautils.Functions():
        fname = ida_funcs.get_func_name(func_ea) or f"sub_{func_ea:08X}"
        fobj = ida_funcs.get_func(func_ea)
        if not fobj:
            continue

        end_ea = fobj.end_ea
        records.append({
            "address": func_ea,
            "name": fname,
            "start": func_ea,
            "end": end_ea,
        })
        classifications[func_ea] = classify_function(func_ea, fname)

    # Sort by address
    records.sort(key=lambda r: r["address"])

    # Detect entry point
    entry_ea = get_entry_address()
    if entry_ea:
        print(f"[PS2Recomp] Entry point: 0x{entry_ea:08X}")

    # Generate outputs
    base_name = os.path.splitext(elf_name)[0]
    csv_path = os.path.join(output_dir, f"{base_name}_functions.csv")
    toml_path = os.path.join(output_dir, f"{base_name}.toml")

    generate_csv(records, csv_path)
    generate_toml(records, classifications, entry_ea, toml_path, elf_name)

    print(f"\n[PS2Recomp] Done! {len(records)} functions analyzed.")
    print(f"  CSV: {csv_path}")
    print(f"  TOML: {toml_path}")


# Run when loaded by IDA
if __name__ == "__main__" or "idaapi" in dir():
    main()
```

### Headless Execution

```bash
# Linux/macOS
idat64 -A -S"ps2_ida_recomp_export.py /output/dir" /path/to/game.elf

# Windows
ida64.exe -A -S"ps2_ida_recomp_export.py C:\output\dir" C:\path\to\game.elf
```

### Standalone (idalib)

```python
import idapro
idapro.open_database("/path/to/game.elf", run_auto_analysis=True)

# Option 1: exec the script
exec(open("/path/to/ps2_ida_recomp_export.py").read())

# Option 2: import and call
import ps2_ida_recomp_export as ps2
ps2.main()

idapro.close_database()
```

### Output Files

| File | Description |
|------|-------------|
| `<game>_functions.csv` | CSV with `Name,Start,End,Size` — compatible with `ghidra_output` TOML field |
| `<game>.toml` | TOML config with stubs, untracked_stubs, performance critical |

### Generated CSV Format

```
Name,Start,End,Size
entry_00100000,0x00100000,0x00100008,8
sceCdInit,0x0039E030,0x0039E3B0,944
sceCdSync,0x0039DDC8,0x0039DE68,160
sub_0018B580,0x0018B580,0x0018B5DC,92
sub_0018B5E0,0x0018B5E0,0x0018B63C,92
...
```

### Classification Logic

Each function is classified into one of three categories:

| Category | Meaning | TOML Entry |
|----------|---------|------------|
| `stub` | Has runtime handler in ps2xRuntime | `[general].stubs` |
| `untracked_stub` | SDK/library function, no runtime handler | `[general].untracked_stubs` |
| `game` | Game-specific code, recompiled normally | (none) |

### Usage with PS2Recomp

```bash
# 1. Generate CSV + TOML from IDA
idat64 -A -S"ps2_ida_recomp_export.py ./output" game.elf

# 2. Point TOML to the CSV (auto-set in generated TOML, or manually):
#    ghidra_output = "output/game_functions.csv"

# 3. Run recompiler
ps2_recomp output/game.toml

# 4. Copy output to runtime
cp output/*.cpp ps2xRuntime/src/runner/
cp output/register_functions.cpp ps2xRuntime/src/runner/

# 5. Build and run
cmake --build out/build --target ps2EntryRunner
./ps2EntryRunner game.elf
```

---

## 25. PS2RECOMP WORKFLOW — Ghidra

Generate CSV function map + TOML config for PS2Recomp using Ghidra headless. This is the **officially recommended** workflow for retail/stripped PS2 games.

### Overview

Ghidra's auto-analysis is generally more accurate for stripped binaries than IDA's, and PS2Recomp's analyzer was designed around Ghidra's output format. Use this workflow when:
- The game is retail/stripped (no symbols)
- You want the most accurate function boundaries
- You need internal callable entry points (mid-function labels)

### Script: `ps2_ghidra_recomp_export.py`

```python
# Ghidra Python script for PS2Recomp export
# Run headless:
#   analyzeHeadless /tmp/ghidra_project project_name \
#     -import game.elf \
#     -postScript ps2_ghidra_recomp_export.py /output/dir

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import RefType
from ghidra.app.script import GhidraScript
from java.io import File, PrintWriter
import re

OUTPUT_DIR = getScriptArgs()[0] if len(getScriptArgs()) > 0 else "/tmp/ps2recomp_output"

# Runtime handlers (same set as IDA script)
RUNTIME_HANDLERS = {
    "FlushCache", "iFlushCache", "ResetEE", "SetMemoryMode",
    "InitThread", "CreateThread", "DeleteThread", "StartThread",
    "ExitThread", "ExitDeleteThread", "TerminateThread", "SuspendThread",
    "ResumeThread", "GetThreadId", "ReferThreadStatus", "iReferThreadStatus",
    "SleepThread", "WakeupThread", "iWakeupThread", "CancelWakeupThread",
    "iCancelWakeupThread", "ChangeThreadPriority", "iChangeThreadPriority",
    "RotateThreadReadyQueue", "iRotateThreadReadyQueue", "ReleaseWaitThread",
    "iReleaseWaitThread", "CreateSema", "DeleteSema", "SignalSema",
    "iSignalSema", "WaitSema", "PollSema", "iPollSema", "ReferSemaStatus",
    "iReferSemaStatus", "CreateEventFlag", "DeleteEventFlag", "SetEventFlag",
    "iSetEventFlag", "ClearEventFlag", "iClearEventFlag", "WaitEventFlag",
    "PollEventFlag", "iPollEventFlag", "ReferEventFlagStatus",
    "iReferEventFlagStatus", "InitAlarm", "SetAlarm", "iSetAlarm",
    "CancelAlarm", "iCancelAlarm", "ReleaseAlarm", "iReleaseAlarm",
    "AddIntcHandler", "AddIntcHandler2", "RemoveIntcHandler",
    "AddDmacHandler", "AddDmacHandler2", "RemoveDmacHandler",
    "EnableIntc", "iEnableIntc", "DisableIntc", "iDisableIntc",
    "EnableDmac", "iEnableDmac", "DisableDmac", "iDisableDmac",
    "SifStopModule", "SifLoadModule", "SifInitRpc", "SifBindRpc",
    "SifCallRpc", "SifRegisterRpc", "SifCheckStatRpc", "SifSetRpcQueue",
    "SifRemoveRpcQueue", "SifRemoveRpc", "sceSifCallRpc", "sceSifSendCmd",
    "sceRpcGetPacket",
    "fioOpen", "fioClose", "fioRead", "fioWrite", "fioLseek", "fioMkdir",
    "fioChdir", "fioRmdir", "fioGetstat", "fioRemove",
    "SetGsCrt", "GsSetCrt", "GsGetIMR", "iGsGetIMR", "GsPutIMR", "iGsPutIMR",
    "SetVSyncFlag", "SetSyscall", "GsSetVideoMode", "GetOsdConfigParam",
    "SetOsdConfigParam", "EnableCache", "DisableCache", "GetRomName",
    "SifLoadElfPart", "sceSifLoadElf", "sceSifLoadElfPart",
    "sceSifLoadModule", "sceSifLoadModuleBuffer", "SetupThread",
    "EndOfHeap", "GetMemorySize", "Deci2Call", "QueryBootMode",
    "GetThreadTLS", "Copy", "GetEntryAddress", "RegisterExitHandler",
    "ret0", "ret1", "reta0",
    # ... (full list — same as IDA script, see above)
}

PS2_API_PREFIXES = {"sce", "Sce", "SCE", "sif", "Sif", "SIF", "gs", "Gs", "GS",
    "dma", "Dma", "DMA", "iop", "Iop", "IOP", "vif", "Vif", "VIF",
    "spu", "Spu", "SPU", "mc", "Mc", "MC", "libc", "Libc", "LIBC"}


def classify_function(func):
    name = func.getName()
    if not name:
        return "game", name

    # Check runtime handler
    if name in RUNTIME_HANDLERS:
        return "stub", name
    norm = name[1:] if name.startswith("_") and len(name) > 1 else name
    if norm in RUNTIME_HANDLERS:
        return "stub", norm

    # Check thunk
    if func.isThunk():
        target = func.getThunkedFunction(True)
        if target:
            tname = target.getName()
            if tname in RUNTIME_HANDLERS:
                return "stub", tname
            norm_t = tname[1:] if tname.startswith("_") and len(tname) > 1 else tname
            if norm_t in RUNTIME_HANDLERS:
                return "stub", norm_t

    # Check API prefix
    base = norm
    for prefix in PS2_API_PREFIXES:
        if base.startswith(prefix) and (len(base) == len(prefix) or not base[len(prefix)].islower()):
            return "untracked_stub", name

    return "game", name


# Main
fm = currentProgram.getFunctionManager()
csv_records = []
classifications = {}

for func in fm.getFunctions(True):
    body = func.getBody()
    if body is None or body.getNumAddresses() == 0:
        continue

    name = func.getName()
    start = func.getEntryPoint().getOffset()
    end = body.getMaxAddress().getOffset() + 1
    cat, handler = classify_function(func)

    csv_records.append((name, start, end))
    classifications[start] = (cat, handler)

# Sort by address
csv_records.sort(key=lambda r: r[1])

# Write CSV
csv_path = File(OUTPUT_DIR, currentProgram.getName() + "_functions.csv")
pw = PrintWriter(csv_path)
pw.println("Name,Start,End,Size")
for name, start, end in csv_records:
    size = end - start
    pw.printf("%s,0x%08X,0x%08X,%d\n", name, start, end, size)
pw.close()
println("CSV written: " + csv_path.getAbsolutePath())

# Write TOML
toml_path = File(OUTPUT_DIR, currentProgram.getName() + ".toml")
pw = PrintWriter(toml_path)
pw.println("# PS2Recomp configuration (generated by Ghidra)")
pw.println()
pw.println("[general]")
pw.println('input = "' + currentProgram.getExecutablePath() + '"')
pw.println('ghidra_output = "' + csv_path.getAbsolutePath() + '"')
pw.println('output = "./output/"')
pw.println("single_file_output = false")
pw.println("patch_syscalls = false")
pw.println("patch_cop0 = true")
pw.println("patch_cache = true")
pw.println()

pw.println("stubs = [")
for name, start, end in csv_records:
    cat, handler = classifications.get(start, ("game", name))
    if cat == "stub":
        pw.printf('  "%s@0x%08X",\n', name, start)
pw.println("]")
pw.println()

pw.println("untracked_stubs = [")
for name, start, end in csv_records:
    cat, handler = classifications.get(start, ("game", name))
    if cat == "untracked_stub":
        pw.printf('  "%s@0x%08X",\n', name, start)
pw.println("]")
pw.println()

pw.println("skip = []")
pw.close()
println("TOML written: " + toml_path.getAbsolutePath())
```

### Headless Execution

```bash
# Linux/macOS
analyzeHeadless /tmp/ghidra_project ps2_analysis \
  -import /path/to/game.elf \
  -postScript ps2_ghidra_recomp_export.py /output/dir \
  -scriptPath /path/to/scripts

# With pre-analysis (recommended for accuracy)
analyzeHeadless /tmp/ghidra_project ps2_analysis \
  -import /path/to/game.elf \
  -preScript ExportPS2Functions.java /output/dir \
  -postScript ps2_ghidra_recomp_export.py /output/dir \
  -scriptPath /path/to/ps2xRecomp/tools/ghidra
```

### Using ExportPS2Functions.java (Official Script)

PS2Recomp ships with an official Ghidra script at `ps2xRecomp/tools/ghidra/ExportPS2Functions.java`:

```bash
# Headless with official script
analyzeHeadless /tmp/ghidra_project ps2_analysis \
  -import game.elf \
  -postScript ExportPS2Functions.java \
  -scriptPath /path/to/ps2xRecomp/tools/ghidra
```

This script:
1. Exports all functions to a CSV
2. Classifies stubs vs game functions
3. Generates TOML with the same structure as the IDA script
4. Detects executable labels (callable entry points)
5. Handles thunks and indirect calls

### Output Files

| File | Description |
|------|-------------|
| `<game>_functions.csv` | CSV with `Name,Start,End,Size` |
| `<game>.toml` | TOML config for ps2xRecomp |

### Generated CSV Format

Same as IDA output — compatible with `ghidra_output` TOML field:
```
Name,Start,End,Size
sceCdInit,0x0039E030,0x0039E3B0,944
entry_00100000,0x00100000,0x00100008,8
sub_0018B580,0x0018B580,0x0018B5DC,92
```

---

## 26. IDA vs GHIDRA for PS2Recomp

| Aspect | IDA Pro | Ghidra |
|--------|---------|--------|
| **Decompiler MIPS** | hexmips.so (commercial, often more accurate) | Built-in (free, good quality) |
| **Headless mode** | `idat64 -A` or idalib Python | `analyzeHeadless` + Java/Python |
| **License** | Commercial (required) | Free (GPL) |
| **Speed** | Faster analysis | Slower analysis |
| **Script language** | Python (idapython) | Java or Python (Jython) |
| **Function detection** | Good with prologue scanning | Better auto-analysis for stripped |
| **CSV export** | Custom script (Section 24) | Official `ExportPS2Functions.java` |
| **Recommended for** | Quick analysis, decompilation, known games | Retail/stripped games (official workflow) |
| **PS2Recomp support** | Via custom script | Officially supported |

### When to Use Which

| Scenario | Recommendation |
|----------|---------------|
| Retail game, stripped symbols | **Ghidra** — better auto-analysis |
| Homebrew / debug build with symbols | **Either** — both work well |
| Quick analysis before full RE | **IDA** — faster, better decompiler |
| Batch analysis of many games | **Ghidra** — free, scriptable |
| Maximum function detection | **Ghidra** — better for stripped binaries |
| Need decompiled pseudocode | **IDA** — hexmips is often more accurate |
| First time with PS2Recomp | **Ghidra** — officially documented workflow |

### Workflow Comparison

**IDA Pro:**
```bash
# 1. Export
idat64 -A -S"ps2_ida_recomp_export.py /output" game.elf
# 2. Use output
ps2_recomp /output/game.toml
```

**Ghidra:**
```bash
# 1. Export
analyzeHeadless /tmp/ghidra_project p \
  -import game.elf \
  -postScript ExportPS2Functions.java \
  -scriptPath ps2xRecomp/tools/ghidra
# 2. Use output
ps2_recomp /output/game.toml
```

Both produce identical CSV + TOML output formats. The TOML is interchangeable.
