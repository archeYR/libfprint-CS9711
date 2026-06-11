# Reverse Engineering Windows Drivers: Techniques and Lessons Learned

This document describes the techniques used to reverse engineer the ChipSailing CS9711 Windows fingerprint driver to extract hardware specifications and USB protocol details for Linux driver development.

## Overview

**Goal:** Extract hardware specifications (resolution, image dimensions) and USB protocol from Windows driver DLLs without source code.

**Files Analyzed:**
- `WudfBioUsb.dll` - UMDF USB driver (main driver)
- `EngineAdapter.dll` - Biometric engine adapter
- `CSAlgDll.dll` - ChipSailing algorithm library
- `WudfBioUsb.inf` - Driver installation file

**Tools Used:**
- `radare2` (r2) - Primary disassembly and analysis tool
- `objdump` - Secondary disassembly for specific searches
- `strings` - Extract readable strings from binaries
- `file` - Identify file types
- `iconv` - Convert text encodings (INF file was UTF-16)
- `xxd` - Hex dump for binary pattern searching
- Python + pyusb - Verify findings on actual hardware

## What Worked Well

### 1. Start with the INF File

The `.inf` file is plain text (though may be UTF-16 encoded) and contains valuable metadata:

```bash
iconv -f UTF-16LE -t UTF-8 WudfBioUsb.inf
```

**Found:**
- USB VID/PID: `USB\VID_2541&PID_0236`
- Manufacturer: ChipSailing Electronics
- DLL relationships and dependencies
- Registry keys and configuration

**Lesson:** Always start here - it's the easiest source of structured information.

### 2. String Extraction and Searching

Debug strings in the DLLs were extremely valuable:

```bash
strings -n 6 WudfBioUsb.dll | grep -iE 'width|height|size|image|chip'
```

**Key strings found:**
- `"ChipBioUsb | pDevice->ChipID = %x"` - Revealed chip ID mechanism
- `"ChipBioUsb |DeviceContext->ImageBufferSize is %d"` - Led to buffer size code
- `"ChipEngine | Incorrect raw image size: %d"` - Revealed size validation logic

**Lesson:** Debug/logging strings are goldmines. They often name variables and describe what code is doing.

### 3. Cross-Reference Analysis with radare2

Once you find an interesting string, trace back to the code that uses it:

```bash
# Find string address
r2 -q -c 'iz~ChipID' WudfBioUsb.dll

# Find code that references it
r2 -q -c 'aaa; axt 0x18001d7c0' WudfBioUsb.dll

# Disassemble the function
r2 -q -c 'aaa; s fcn.1800033c0; pdf' WudfBioUsb.dll
```

**Lesson:** The `axt` (cross-references to) command is essential for tracing data flow.

### 4. Pattern Matching for Constants

Search for known constant patterns in disassembly:

```bash
# Search for specific hex values (e.g., 500 DPI = 0x1f4)
r2 -q -c '/x f4010000' WudfBioUsb.dll

# Search for mov instructions with specific values
objdump -D -M intel WudfBioUsb.dll | grep -E 'mov.*(0x1f4|0xea00)'
```

**Found:** Image buffer sizes (0xea00 = 59904) and resolution (0x1f4 = 500) as immediate values.

### 5. Function List and Export Analysis

```bash
# List all exports
r2 -q -c 'rabin2 -E CSAlgDll.dll'

# List all functions
r2 -q -c 'aaa; afl' WudfBioUsb.dll
```

**Found:** Algorithm function names like `ChipSailing_CreateTemplate`, `ChipSailing_MatchScore` which revealed the library's purpose.

### 6. Data Section Analysis

For finding embedded constants and lookup tables:

```bash
# Dump specific memory regions
r2 -q -c 's 0x1800589d0; px 128' CSAlgDll.dll
```

**Found:** Version string `CSAlg_C_V04.07.1` and chip identifiers.

### 7. Hardware Verification

After forming hypotheses, verify on actual hardware:

```python
# Send command, read response
ep_out.write(bytes([0xEA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xEA]))
data = ep_in.read(8)
chip_id = (data[2] << 8) | data[3]  # Confirmed 0x62A0
```

**Lesson:** Always verify findings on real hardware when possible.

## What Didn't Work Well

### 1. Automated Analysis Often Incomplete

radare2's `aaa` (analyze all) sometimes misses functions or misidentifies code:

```bash
r2 -q -c 'aaa; afl~init'  # Often returns empty or incomplete
```

**Workaround:** Manually navigate to addresses found via string cross-references.

### 2. Complex Call Graphs Are Hard to Follow

The `agC` (call graph) command produced unreadable ASCII art for complex drivers.

**Workaround:** Focus on specific functions rather than trying to understand entire call graph.

### 3. Indirect Calls Through vtables

Windows drivers use COM-like interfaces with function pointer tables:

```asm
mov rax, qword [rax + 0x6e8]  ; Load function pointer from vtable
call qword [0x1800142b0]       ; Call through dispatcher
```

**Challenge:** Can't easily determine which function is being called.

**Workaround:** Focus on the data being passed (arguments) rather than trying to resolve every call.

### 4. pyusb Backend Issues on NixOS

The nix-installed pyusb didn't automatically find libusb:

```
usb.core.NoBackendError: No backend available
```

**Workaround:** Explicitly set `LD_LIBRARY_PATH`:
```bash
sudo LD_LIBRARY_PATH=/nix/store/.../libusb-1.0.28/lib python3 script.py
```

### 5. Initial Protocol Guesses Were Wrong

First attempts at USB communication timed out - the device needed a specific command format.

**What helped:** Finding the command-building function in disassembly and reverse engineering the packet structure.

## Step-by-Step Methodology

### Phase 1: Reconnaissance
1. Identify all files (DLLs, INF, CAT)
2. Check file types with `file` command
3. Parse INF file for metadata (VID/PID, manufacturer, dependencies)
4. Extract all strings from each DLL

### Phase 2: String-Guided Analysis
1. Search strings for keywords: `width`, `height`, `size`, `resolution`, `dpi`, `image`, `chip`, `init`
2. For each interesting string, find its address
3. Find cross-references to that address
4. Disassemble the referencing function

### Phase 3: Code Analysis
1. Identify key functions (initialization, configuration, capture)
2. Look for constants being assigned to structures
3. Trace switch statements - they often map chip IDs to configurations
4. Look for debug print statements that reveal variable names

### Phase 4: Protocol Extraction
1. Find USB read/write functions
2. Identify command buffer construction
3. Note packet sizes and formats
4. Map command codes to operations

### Phase 5: Verification
1. Write test script to communicate with device
2. Send discovered commands
3. Verify responses match expected format
4. Iterate if needed

## Key Insights

### Switch Statements Reveal Configuration Tables

The driver used switch statements on Chip ID to set dimensions:

```asm
cmp edi, 0x1f58    ; 8024 bytes
je  set_small_config
cmp edi, 0x4800    ; 18432 bytes
je  set_medium_config
cmp edi, 0xea00    ; 59904 bytes
je  set_large_config
```

**Lesson:** Switch statements are often configuration lookups - analyze all branches.

### Debug Builds Are Your Friend

The driver had extensive debug logging which made analysis much easier. Production drivers with stripped symbols are significantly harder.

### Protocol Framing Is Common

The `[0xEA, cmd, data..., checksum, 0xEA]` format with start/end markers is common in embedded protocols. Look for repeated byte values at fixed offsets.

### Retry Logic Reveals Reliability Issues

The Windows driver retried commands up to 3 times. This told us the device might need multiple attempts to respond (which we confirmed).

## Tools Cheat Sheet

```bash
# Basic info
file *.dll
strings -n 8 driver.dll | grep -i keyword

# INF file (often UTF-16)
iconv -f UTF-16LE -t UTF-8 driver.inf

# radare2 essentials
r2 -q -c 'iz' driver.dll                    # List strings
r2 -q -c 'izz~pattern' driver.dll           # Search all strings
r2 -q -c 'aaa; afl' driver.dll              # List functions
r2 -q -c 'aaa; axt 0xADDRESS' driver.dll    # Cross-references
r2 -q -c 'aaa; s FUNC; pdf' driver.dll      # Disassemble function
r2 -q -c 's ADDR; px 64' driver.dll         # Hex dump
r2 -q -c '/x HEXPATTERN' driver.dll         # Search hex bytes

# objdump for grep-friendly output
objdump -D -M intel driver.dll | grep -E 'pattern'

# Exports
rabin2 -E driver.dll
```

## Conclusion

The most effective approach was **string-guided reverse engineering**: find debug strings, trace them to code, analyze the surrounding logic. This is much more efficient than trying to understand the entire binary.

For USB device drivers specifically, focus on:
1. Device initialization (VID/PID handling, configuration)
2. Endpoint setup (bulk, interrupt, control)
3. Command/response packet formats
4. Image buffer allocation (reveals dimensions)

Always verify findings on real hardware when possible - it catches misinterpretations quickly.
