# FP100-LK Fingerprint Sensor Hardware Specifications

Reverse-engineered from the ChipSailing Windows driver.

**✓ VERIFIED**: Chip ID 0x62A0 confirmed via USB query on actual hardware.

## Device Identification

| Property | Value |
|----------|-------|
| **Manufacturer** | ChipSailing Electronics (ShenZhen) Co., Ltd |
| **Chip Model** | CS9711 (USB product string) / CS62A0 (Chip ID) |
| **Chip ID** | **0x62A0** (verified) |
| **Algorithm Version** | CSAlg_C_V04.07.1 |
| **USB Vendor ID** | 0x2541 |
| **USB Product ID** | 0x0236 |
| **Interface** | USB (WBDI - Windows Biometric Driver Interface) |

## Sensor Resolution

| Property | Value |
|----------|-------|
| **Resolution** | **500 DPI** (verified from driver disassembly) |
| **Type** | Capacitive fingerprint sensor |

### DPI Determination

The DPI value was confirmed by reverse engineering CSAlgDll.dll:
- The algorithm library uses a sensor type parameter passed to `ChipSailing_Init()`
- Different sensor types have different DPI values configured
- The FP100-LK (Chip ID 0x62A0/0x62A1) maps to sensor type 5, which sets DPI = 0x1f4 (500)
- Note: 508 DPI (0x1fc) does NOT appear in the driver - this was a false lead

| Sensor Type | DPI | Notes |
|-------------|-----|-------|
| 1 | 500 | |
| 2 | 500 | CS3106/CS4102 |
| 3 | 407 | CS4101 (118×68) |
| 4 | 259 | |
| 5 | 500 | CS62A0/CS62A1 (288×208) **← FP100-LK** |
| 6 | 340 | |

## Sensor Detection Mechanism

**The driver determines the sensor configuration by reading the Chip ID from the device during initialization**, NOT by the size of image data returned. The USB driver:

1. Sends a read command to the device during `VendorDeviceChipConfigure()`
2. Reads an 8-byte response containing the Chip ID at bytes 2-3
3. Uses a switch statement based on Chip ID to set width, height, and buffer size

## Chip ID to Configuration Mapping

| Chip ID | Width | Height | Image Size (bytes) | Notes |
|---------|-------|--------|-------------------|-------|
| **0x62A0, 0x62A1** | **288** (0x120) | **208** (0xD0) | **59904** (0xEA00) | FP100-LK (primary) |
| 0x3106 | 56 (0x38) | 180 (0xB4) | 20160 (0x4EC0) | Alternative sensor |
| 0x4101 | 118 (0x76) | 68 (0x44) | 8024 (0x1F58) | Small sensor |
| 0x4102 (0x4101+1) | 56 (0x38) | 180 (0xB4) | 20160 (0x4EC0) | Similar to 0x3106 |
| (default/0x3106 case) | 96 (0x60) | 96 (0x60) | 18432 (0x4800) | Square sensor |

**FP100-LK Sensor (Chip ID 0x62A0/0x62A1):**
- **Width: 288 pixels**
- **Height: 208 pixels** 
- **Resolution: 500 DPI**
- **Raw image size: 59,904 bytes (8-bit grayscale)**

Note: The width/height in the driver are stored as (height, width) internally at offsets 0x68 and 0x6C.

## USB Communication

- Uses WinUSB as the lower filter driver
- Bulk transfer mode for image data
- Full Speed USB (12 Mbps)
- Max packet size: 64 bytes

### Endpoints

| Endpoint | Direction | Type | Description |
|----------|-----------|------|-------------|
| 0x01 | OUT | Bulk | Command/data output |
| 0x81 | IN | Bulk | Response/image input |

## USB Protocol

### Command Packet Format

All commands use an 8-byte packet structure:

```
Offset  Size  Description
------  ----  -----------
0       1     Start marker: 0xEA
1       1     Command code
2-5     4     Command parameters (usually 0x00)
6       1     Checksum: XOR of bytes 1-5
7       1     End marker: 0xEA
```

Example command to read chip info (cmd=0x01):
```
[0xEA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xEA]
```

### Response Packet Format

Responses also use 8-byte packets:

```
Offset  Size  Description
------  ----  -----------
0       1     Echo: 0xEA
1       1     Command code echo
2-3     2     Response data (big-endian)
4-5     2     Additional data
6       1     Checksum
7       1     End marker: 0xEA
```

### Command Codes

| Code | Name | Description |
|------|------|-------------|
| 0x01 | READ_CHIP_ID | Read chip identification. Response bytes 2-3 contain Chip ID |
| 0x02 | SLEEP/WAKE | Power state control (used in D0Exit) |
| 0x03 | CAPTURE_START | Start fingerprint capture (when byte[0xD2]=4) |
| 0x04 | CAPTURE_START_ALT | Alternative capture start command |
| 0x07 | RESET | Device reset (used in D0Entry with WdfPowerDeviceD3Final) |

### Initialization Sequence

1. **Device Attach**
   - Enumerate USB endpoints (EP 0x01 OUT, EP 0x81 IN)
   - Configure bulk continuous reader

2. **Read Chip ID** (VendorDeviceChipConfigure)
   ```
   WRITE: [0xEA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xEA]
   READ:  [0xEA, 0x01, ChipID_Hi, ChipID_Lo, 0x00, 0x00, checksum, 0xEA]
   ```
   - May require 2-3 retries (device needs wake-up time)
   - Chip ID determines image dimensions (see table above)

3. **Allocate Image Buffers**
   - Based on Chip ID, allocate `width × height` byte buffer
   - For CS62A0: 288 × 208 = 59,904 bytes

4. **Configure Power Management**
   - Enable idle detection
   - Set 3000ms idle timeout

### Image Capture Sequence

1. **Wait for Finger**
   - Device uses continuous reader on bulk IN endpoint
   - Interrupt/notification when finger detected

2. **Capture Image**
   ```
   WRITE: [0xEA, 0x03, 0x00, 0x00, 0x00, 0x00, 0x03, 0xEA]  (or 0x04)
   READ:  <image data, 59904 bytes for CS62A0>
   ```
   - Image data arrives in 64-byte bulk transfers
   - Total transfers: 59904 / 64 = 936 packets (+ remainder)

3. **Background Image Acquisition** (calibration)
   - IOCTL code: 0x44001C (0x1fe8 offset from base)
   - Used for sensor calibration/baseline

### Power State Commands

| State Transition | Command |
|-----------------|---------|
| Enter D0 (active) | cmd=0x07 (if from D3Final), else cmd=0x02 |
| Exit D0 (sleep) | cmd=0x02 (retry up to 3 times) |

### Error Handling

- Commands may timeout if device is in sleep state
- Retry up to 3 times with short delays
- Status 0xC0000120 indicates device needs re-initialization

## Driver Architecture

```
┌─────────────────────────────────────────────────────┐
│                    WinBio Service                   │
├─────────────────────────────────────────────────────┤
│  WinBioSensorAdapter.DLL   (Windows built-in)       │
├─────────────────────────────────────────────────────┤
│  EngineAdapter.dll (ChipEngine) - Template matching │
├─────────────────────────────────────────────────────┤
│  CSAlgDll.dll - ChipSailing algorithm library       │
│    - ChipSailing_Init()                             │
│    - ChipSailing_CreateTemplate()                   │
│    - ChipSailing_MatchScore()                       │
│    - ChipSailing_AutoGain()                         │
│    - ChipSailing_Enhance16to8()                     │
├─────────────────────────────────────────────────────┤
│  WudfBioUsb.dll - UMDF USB driver                   │
├─────────────────────────────────────────────────────┤
│  WinUSB.sys (Kernel)                                │
└─────────────────────────────────────────────────────┘
```

## Key Constants for Linux Driver Development

```c
#define FP100_VENDOR_ID     0x2541
#define FP100_PRODUCT_ID    0x0236

#define FP100_RESOLUTION_DPI 500

/* Chip IDs - read from device during initialization */
#define CHIPID_CS62A0       0x62A0  /* FP100-LK primary */
#define CHIPID_CS62A1       0x62A1  /* FP100-LK variant */
#define CHIPID_CS3106       0x3106
#define CHIPID_CS4101       0x4101
#define CHIPID_CS4102       0x4102

/* FP100-LK sensor dimensions (Chip ID 0x62A0/0x62A1) */
#define FP100_IMAGE_WIDTH   288
#define FP100_IMAGE_HEIGHT  208
#define FP100_IMAGE_SIZE    (288 * 208)  /* 59904 bytes */

/* Other sensor configurations by Chip ID */
/* CS3106: 56x180 = 10080 raw, 20160 with padding? */
/* CS4101: 118x68 = 8024 */
/* Default: 96x96 = 9216 raw, 18432 bytes */
```

## Algorithm Functions (from CSAlgDll.dll exports)

| Function | Purpose |
|----------|---------|
| `ChipSailing_Init` | Initialize algorithm engine |
| `ChipSailing_AutoGain` | Auto-calibrate sensor gain (8-bit) |
| `ChipSailing_AutoGain16` | Auto-calibrate sensor gain (16-bit) |
| `ChipSailing_CreateTemplate` | Create fingerprint template |
| `ChipSailing_CreateTemplate16` | Create template from 16-bit image |
| `ChipSailing_MatchScore` | Compare fingerprint templates |
| `ChipSailing_MergeFeature` | Merge multiple captures |
| `ChipSailing_RenewFeature` | Update existing template |
| `ChipSailing_DetectFinger` | Detect finger presence |
| `ChipSailing_SignalStrength` | Get signal quality |
| `ChipSailing_Enhance16to8` | Convert 16-bit to 8-bit image |
| `ChipSailing_CutBlankImage` | Crop blank regions |
| `ChipSailing_GetImage` | Retrieve processed image |
| `ChipSailing_IsBlankImage` | Check for blank/empty scan |
| `ChipSailing_GetAlgVersion` | Get algorithm version |

## Resolution Mismatch Investigation

### Problem Statement

Some devices with Chip ID 0x62A0 report the correct chip ID but output only 8024 bytes (68×118) instead of the expected 59904 bytes (288×208). This section documents the investigation into whether the Windows driver sends a resolution configuration command.

### Analysis Results

**Finding: The Windows driver does NOT send any resolution configuration command.**

The driver determines resolution purely from the Chip ID via a switch statement:

```
ChipID 0x62A0/0x62A1 → 288×208 (59904 bytes)
ChipID 0x4101        → 68×118  (8024 bytes)
ChipID 0x3106        → 56×180  (20160 bytes)
ChipID 0x4102        → 56×180  (20160 bytes)
Default              → 96×96   (18432 bytes)
```

### Command Analysis

All discovered commands use the 8-byte packet format with **zero data bytes**:

| Code | Function | Data Bytes | Purpose |
|------|----------|------------|---------|
| 0x01 | Read Chip ID | 0,0,0,0 | Returns chip ID in response |
| 0x02 | Sleep/Wake | 0,0,0,0 | Power state control |
| 0x03 | Capture | 0,0,0,0 | Start capture (mode=4) |
| 0x04 | Capture Alt | 0,0,0,0 | Alternative capture |
| 0x07 | Reset | 0,0,0,0 | Device reset |

**No register write or configuration commands were found** that could change resolution.

### Possible Explanations

1. **Firmware Variant**: The device has different firmware that outputs smaller images regardless of chip ID
2. **Hardware Limitation**: The specific sensor module is physically smaller
3. **Missing Initialization**: There may be undiscovered vendor-specific USB control transfers (not bulk commands)
4. **EEPROM Configuration**: Resolution may be burned into device EEPROM at manufacturing

### Recommended Next Steps

To definitively determine if a configuration command exists:

1. **Capture USB Traffic on Windows**:
   ```
   - Install USBPcap or Wireshark with USBPcap
   - Capture all USB traffic during Windows driver initialization
   - Look for any control transfers or additional bulk commands
   - Compare command sequence between working 288×208 device and 68×118 device
   ```

2. **Check for Control Transfers**:
   The analyzed bulk commands may not be the complete picture. USB control transfers (bmRequestType vendor-specific) could configure the sensor.

3. **Compare Device Descriptors**:
   Check if the 68×118 variant has different USB descriptors or firmware version strings.

---

## USB Traffic Capture Analysis (January 2026)

Captured live USB traffic from device initialization and fingerprint capture.

### Initialization Sequence Observed

| Frame | Direction | Data | Description |
|-------|-----------|------|-------------|
| 489-500 | Control | - | Standard USB enumeration (GET DESCRIPTOR, SET CONFIGURATION) |
| 501 | Host→Device | `EA 01 00 00 00 00 01 EA` | **Read Chip ID command** |
| 504 | Device→Host | `EA 01 62 A0 00 00 C3 EA` | **Chip ID response: 0x62A0** ✓ |

### Fingerprint Capture Sequence

| Frame | Direction | Data | Description |
|-------|-----------|------|-------------|
| 1582 | Host→Device | `EA 04 00 00 00 00 04 EA` | **Capture command (0x04)** |
| 1584 | Device→Host | 8000 bytes | Image data (first chunk) |
| 1586 | Device→Host | 24 bytes | Image data (final chunk) |
| **Total** | | **8024 bytes** | **118×68 pixels** (not 288×208!) |

### Key Finding: Resolution Mismatch Confirmed

**The device reports Chip ID 0x62A0 but outputs only 8024 bytes (118×68) instead of 59904 bytes (288×208).**

This confirms the "Resolution Mismatch" section above - this specific device variant has different firmware or hardware that outputs a smaller image despite having the same Chip ID.

### Commands Observed

| Code | Hex Packet | Purpose |
|------|------------|---------|
| 0x01 | `EA 01 00 00 00 00 01 EA` | Read Chip ID |
| 0x02 | `EA 02 00 00 00 00 02 EA` | Sleep/Wake (sent after capture) |
| 0x04 | `EA 04 00 00 00 00 04 EA` | Capture image |

**No configuration commands were observed** - the driver does not send any resolution configuration to the device.

### Conclusions

1. ✅ Chip ID 0x62A0 confirmed via live capture
2. ✅ Command protocol matches reverse-engineered specs
3. ⚠️ **This device outputs 8024 bytes (118×68) not 59904 (288×208)**
4. ❌ No resolution configuration command exists - this is a hardware/firmware variant

For Linux driver: Must detect actual image size from response, not just rely on Chip ID.

---

## Notes for Linux Driver

1. The sensor outputs raw 8-bit grayscale images
2. The 500 DPI resolution is standard for fingerprint sensors
3. Image processing and template creation can use libfprint's algorithms
4. USB bulk transfers are used for image capture
5. **The Chip ID must be read during device initialization** to determine the correct image dimensions
6. The FP100-LK uses Chip ID 0x62A0 or 0x62A1 with 288x208 resolution
7. The EngineAdapter validates received image size against expected size based on Chip ID
8. **Device needs 2-3 command cycles to "wake up"** from idle state - implement retry logic
9. All commands use the `[0xEA, cmd, params..., checksum, 0xEA]` packet format

## Sample Code

### Building a Command Packet (Python)

```python
def build_command(cmd, params=None):
    """Build an 8-byte command packet for the CS9711 sensor."""
    if params is None:
        params = [0x00, 0x00, 0x00, 0x00]
    
    # Checksum is XOR of bytes 1-5 (cmd + 4 param bytes)
    checksum = cmd
    for p in params:
        checksum ^= p
    
    return bytes([0xEA, cmd] + params + [checksum, 0xEA])

# Examples
CMD_READ_CHIP_ID = build_command(0x01)  # [0xEA, 0x01, 0, 0, 0, 0, 0x01, 0xEA]
CMD_SLEEP_WAKE   = build_command(0x02)  # [0xEA, 0x02, 0, 0, 0, 0, 0x02, 0xEA]
CMD_CAPTURE      = build_command(0x03)  # [0xEA, 0x03, 0, 0, 0, 0, 0x03, 0xEA]
CMD_RESET        = build_command(0x07)  # [0xEA, 0x07, 0, 0, 0, 0, 0x07, 0xEA]
```

### Parsing a Response Packet (Python)

```python
def parse_response(data):
    """Parse an 8-byte response packet."""
    if len(data) != 8 or data[0] != 0xEA or data[7] != 0xEA:
        return None
    
    return {
        'cmd': data[1],
        'data': (data[2] << 8) | data[3],  # Big-endian 16-bit
        'extra': (data[4] << 8) | data[5],
        'checksum': data[6],
    }

# Example: Parse chip ID response
# Response: [0xEA, 0x01, 0x62, 0xA0, 0x00, 0x00, 0xC3, 0xEA]
# Result: {'cmd': 1, 'data': 0x62A0, 'extra': 0, 'checksum': 0xC3}
```
