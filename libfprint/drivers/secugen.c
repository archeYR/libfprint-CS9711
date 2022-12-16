/*
 * SecuGen Hamster Pro 20 (FDU05) driver for libfprint
 * Copyright (C) 2026
 *
 * Protocol reverse-engineered from USB packet captures.
 *
 * SIDO020A sensor configured via I2C-over-USB control transfers.
 * Raw sensor output: 956x688 grayscale via USB bulk (657KB).
 * Downsampled to 300x400 at 500 DPI for libfprint.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FP_COMPONENT "secugen"

#include <string.h>

#include "drivers_api.h"

/* ---- Device constants ---- */

/* Final output image (what libfprint sees) */
#define SECUGEN_IMG_WIDTH 300
#define SECUGEN_IMG_HEIGHT 400
#define SECUGEN_IMG_SIZE (SECUGEN_IMG_WIDTH * SECUGEN_IMG_HEIGHT)      /* 120000 */

/* Raw sensor array (full SIDO020A readout) */
#define SECUGEN_RAW_WIDTH 956
#define SECUGEN_RAW_HEIGHT 688
#define SECUGEN_RAW_SIZE (SECUGEN_RAW_WIDTH * SECUGEN_RAW_HEIGHT)      /* 657728 */
#define SECUGEN_BULK_BUF_SIZE 657920  /* Actual USB stream: 688*956 + 192 trailing */
/* Per-URB read size for the frame stream. Kept below the usbmon capture cap
 * (ring_size/5 ~= 245KB) and a multiple of the 512-byte bulk max-packet size,
 * so the full frame is recorded by the standard pcap-based test capture as a
 * sequence of complete URBs rather than one truncated transfer. 128 * 512. */
#define SECUGEN_BULK_CHUNK 65536
#define SECUGEN_DPI 500
#define SECUGEN_PPMM 19.685           /* 500 DPI / 25.4 mm/in */
#define SECUGEN_EP_DATA 0x82          /* Bulk IN endpoint */

/* ---- Vendor control transfer bRequest codes ---- */

#define SECUGEN_REQ_START_STREAM 1
#define SECUGEN_REQ_STOP_STREAM 2
#define SECUGEN_REQ_START_CAPTURE 5
#define SECUGEN_REQ_READ_FW_DATA 8
#define SECUGEN_REQ_LED_CONTROL 17
#define SECUGEN_REQ_GET_STATUS 22
#define SECUGEN_REQ_I2C_REG 34
#define SECUGEN_REQ_GET_DEVICE_ID 37
#define SECUGEN_REQ_SET_EXPOSURE 64

/* ---- I2C / SIDO020A sensor ---- */

#define SECUGEN_I2C_ADDR 0x0037        /* wValue for I2C transfers */

/* ---- Exposure values ---- */

#define SECUGEN_EXPOSURE_INIT 1000      /* Initial calibration exposure */
#define SECUGEN_EXPOSURE_NORMAL 1116    /* Normal capture exposure */

/* ---- Calibration / FW data ---- */

#define SECUGEN_FW_DATA_START 0x2000
#define SECUGEN_FW_DATA_CHUNK 4096
#define SECUGEN_FW_DATA_CHUNKS 6
#define SECUGEN_FW_DATA_LAST_LEN 2462  /* Last chunk is partial */
#define SECUGEN_FW_DATA_SIZE 22942     /* Total FW data: 4*4096 + 2*3072 ... */

/* Flat-field reference image stored in FW data at struct offset 0x1df8 */
#define SECUGEN_REF_WIDTH 150
#define SECUGEN_REF_HEIGHT 100
#define SECUGEN_REF_SIZE (SECUGEN_REF_WIDTH * SECUGEN_REF_HEIGHT)         /* 15000 */
#define SECUGEN_REF_OFFSET 0x1df8        /* Offset of ref image in FW data */
#define SECUGEN_BLEND_CAL_VAL 240        /* Target uniform brightness */

/* FW data offsets for image processing parameters */
#define SECUGEN_BLC_OFFSETS_FW 0x0e       /* 16 × int16 BLC region offsets */
#define SECUGEN_CAL_VALUE_FW 0x5892       /* uint16 blend target (usually 240) */
#define SECUGEN_SHARPEN_THRESH_FW 0x599C  /* uint8 sharpening threshold */
#define SECUGEN_SHARPEN_AMOUNT_FW 0x599D  /* uint8 sharpening amount */

/* ---- Timeouts (ms) ---- */

#define SECUGEN_CTRL_TIMEOUT 2000
#define SECUGEN_BULK_TIMEOUT 10000      /* Longer timeout for 657KB bulk read */
#define SECUGEN_FW_READ_TIMEOUT 5000
#define SECUGEN_FINGER_POLL_MS 200      /* Finger detection polling interval */
#define SECUGEN_FINGER_THRESHOLD 25    /* Mean brightness above this = finger present */

/* ---- I2C register init table entry ---- */

struct secugen_reg_entry
{
  guint8 reg;
  guint8 val;
};

/* ---- Driver instance ---- */

struct _FpiDeviceSecugen
{
  FpImageDevice parent;

  /* Initialization tracking */
  int    init_reg_idx;             /* Current I2C register being written */
  int    fw_read_idx;              /* Current calibration data chunk */
  guint8 iface_num;                /* Claimed USB interface number */

  /* Finger detection */
  GSource *finger_poll_source;      /* Detection/finger-off timeout source */

  /* Calibration / flat-field correction */
  guint8  *cal_raw;                /* Background frame at raw sensor res (956x688) */
  guint8  *fw_data;                /* Accumulated FW data from device (22942 bytes) */
  gsize    fw_data_len;            /* Bytes accumulated so far */
  guint8  *ref_image;              /* Resized 300x400 flat-field reference image */
  gboolean has_ref_image;          /* Whether ref_image was successfully extracted */

  /* BLC band compensation */
  gint16   blc_offsets[16];        /* Factory-calibrated region offsets from FW */
  gboolean has_blc_offsets;        /* Whether BLC offsets were extracted */

  /* Image processing params from FW */
  guint16  cal_value;              /* Blend target brightness (from FW, default 240) */
  guint8   sharpen_threshold;      /* Min gradient for sharpening */
  guint8   sharpen_amount;         /* Max gradient contribution */
  guint8   sharpen_limit;          /* Overall scaling factor (/10) */
  gboolean sharpen_enabled;        /* Whether post-resize sharpening is active */

  /* Bulk read buffer for capture/detect frames */
  guint8 *bulk_buffer;             /* Reusable buffer for 657KB bulk reads */

  /* Chunked frame-read state (see secugen_read_frame) */
  guint8 *bulk_dest;               /* Destination of the in-progress frame read */
  gsize   bulk_offset;             /* Bytes accumulated into bulk_dest so far */

  /* Activation / teardown state */
  gboolean deactivating;           /* Deactivate requested while an SSM runs */
  int      ssm_count;              /* Number of init/detect/capture SSMs in flight.
                                    * A counter (not a flag): the detect->capture
                                    * handoff is synchronous, so a capture SSM is
                                    * started before the detect SSM's completion
                                    * handler runs - both must be tracked. */

  /* Capture state */
  guint16 exposure;                /* Current exposure value */

  /* Device info */
  guint8 device_id[30];

  /* Last register readback */
  guint8 last_reg_rd;

  /* Last status */
  guint8 last_status[4];
};

G_DECLARE_FINAL_TYPE (FpiDeviceSecugen,
                      fpi_device_secugen,
                      FPI,
                      DEVICE_SECUGEN,
                      FpImageDevice);

G_DEFINE_TYPE (FpiDeviceSecugen,
               fpi_device_secugen,
               FP_TYPE_IMAGE_DEVICE);

/* ---- Blend curve LUT (256 bytes) ----
 *
 * Brightness-dependent correction weight for flat-field correction.
 * Dark pixels (<16) get zero correction, bright pixels (>191) get full
 * correction, middle range scales linearly.  Identical to the table
 * stored in the device's firmware data block.
 */
static const guint8 SECUGEN_BLEND_CURVE[256] = {
  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,
  16,  17,  19,  21,  23,  25,  27,  29,  31,  32,  34,  36,  38,  40,  42,  44,
  46,  47,  49,  51,  53,  55,  57,  59,  61,  62,  64,  66,  68,  70,  72,  74,
  76,  77,  79,  81,  83,  85,  87,  89,  91,  92,  94,  96,  98, 100, 102, 104,
  106, 107, 109, 111, 113, 115, 117, 119, 121, 122, 124, 126, 128, 130, 132, 134,
  136, 137, 138, 139, 141, 142, 143, 144, 146, 147, 148, 149, 151, 152, 153, 154,
  156, 157, 158, 159, 161, 162, 163, 164, 166, 167, 168, 169, 171, 172, 173, 174,
  176, 177, 178, 179, 181, 182, 183, 184, 186, 187, 188, 189, 191, 192, 193, 194,
  196, 197, 198, 199, 201, 202, 203, 204, 206, 207, 208, 209, 211, 212, 213, 214,
  216, 217, 218, 219, 221, 222, 223, 224, 226, 227, 228, 229, 231, 232, 233, 234,
  236, 237, 238, 239, 240, 241, 243, 244, 245, 246, 247, 249, 250, 251, 252, 253,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
};

static void secugen_resize_bilinear (const guint8 *src,
                                     int           src_w,
                                     int           src_h,
                                     guint8       *dst,
                                     int           dst_w,
                                     int           dst_h);

/* ---- Bilinear resize 150x100 → 300x400 ----
 *
 * The FW stores a low-res (150x100) flat-field reference image captured
 * during factory calibration.  It is resized to 300x400 before being
 * used for the blend correction.
 */
static void
secugen_resize_ref_image (const guint8 *src, guint8 *dst)
{
  secugen_resize_bilinear (src, SECUGEN_REF_WIDTH, SECUGEN_REF_HEIGHT,
                           dst, SECUGEN_IMG_WIDTH, SECUGEN_IMG_HEIGHT);
}

/* ---- SIDO020A I2C register init table ---- */

/*
 * Phase 1: Main init registers (54 regs).
 * Written first during init. 0xa5-0xa8 are NOT included here -- they are
 * written later (after a 0x03 rewrite to enable the sensor).
 * 0xb7-0xb9 come BEFORE 0xa5-0xa8, matching the captured init sequence.
 */
static const struct secugen_reg_entry sido020a_init_regs[] = {
  { 0x03, 0x02 },  /* Power/reset control - hold in reset */
  { 0x04, 0x81 },
  { 0x05, 0x0a },
  { 0x08, 0x00 },
  { 0x09, 0x11 },
  { 0x0a, 0x11 },
  { 0x10, 0x11 },
  { 0x11, 0x23 },
  { 0x12, 0x85 },
  { 0x13, 0x00 },
  { 0x14, 0x27 },
  { 0x16, 0xb6 },
  { 0x30, 0x01 },
  { 0x31, 0xc0 },
  { 0x32, 0x08 },
  { 0x41, 0x00 },
  { 0x42, 0x00 },
  { 0x43, 0x06 },
  { 0x44, 0x43 },
  { 0x45, 0x00 },
  { 0x46, 0x00 },
  { 0x47, 0x04 },
  { 0x48, 0xb3 },
  { 0x49, 0x00 },
  { 0x4a, 0x20 },
  { 0x4b, 0x00 },
  { 0x4c, 0x00 },
  { 0x4d, 0x00 },
  { 0x4e, 0x00 },
  { 0x60, 0x0b },
  { 0x61, 0x16 },
  { 0x62, 0x32 },
  { 0x63, 0x80 },
  { 0x71, 0x08 },
  { 0x80, 0xf8 },
  { 0x81, 0x06 },
  { 0x90, 0xaa },
  { 0x91, 0x08 },
  { 0x92, 0x10 },
  { 0x93, 0x40 },
  { 0x94, 0x04 },
  { 0x95, 0x01 },
  { 0x96, 0x02 },
  { 0x97, 0x08 },
  { 0x98, 0x10 },
  { 0x99, 0x08 },
  { 0x9a, 0x03 },
  { 0x9b, 0xb0 },
  { 0x9c, 0x08 },
  { 0x9d, 0x24 },
  { 0x9e, 0x30 },
  { 0xb7, 0x15 },
  { 0xb8, 0x28 },
  { 0xb9, 0x04 },
};

#define N_INIT_REGS G_N_ELEMENTS (sido020a_init_regs)

/*
 * Phase 2 late init: written AFTER 0x03 is rewritten to 0x05 (sensor enable),
 * following the power-on transition.
 */
static const struct secugen_reg_entry late_init_regs[] = {
  { 0xa5, 0x00 },
  { 0xa6, 0x00 },
  { 0xa7, 0x00 },
  { 0xa8, 0x00 },
};

#define N_LATE_INIT_REGS G_N_ELEMENTS (late_init_regs)

/* Capture window config (written after late init, before FW reads) */
static const struct secugen_reg_entry capture_window_regs[] = {
  { 0x41, 0x00 }, { 0x42, 0xfa }, { 0x43, 0x04 }, { 0x44, 0x4f },
  { 0x45, 0x00 }, { 0x46, 0x28 }, { 0x47, 0x03 }, { 0x48, 0x23 },
};

/* Frame window config (written after calibration capture) */
static const struct secugen_reg_entry frame_window_regs[] = {
  { 0x41, 0x01 }, { 0x42, 0x48 }, { 0x43, 0x03 }, { 0x44, 0xbf },
  { 0x45, 0x00 }, { 0x46, 0xcc }, { 0x47, 0x02 }, { 0x48, 0xb3 },
};

#define N_CAPTURE_WINDOW_REGS G_N_ELEMENTS (capture_window_regs)
#define N_FRAME_WINDOW_REGS G_N_ELEMENTS (frame_window_regs)

/* ================================================================
 * USB Transfer Helpers
 * ================================================================ */

/* Send a vendor control OUT transfer (no data) and advance SSM */
static void
secugen_ctrl_out (FpiSsm        *ssm,
                  FpImageDevice *dev,
                  guint8         request,
                  guint16        value,
                  guint16        idx)
{
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (FP_DEVICE (dev));

  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 request, value, idx, 0);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_CTRL_TIMEOUT,
                           fpi_device_get_cancellable (FP_DEVICE (dev)),
                           fpi_ssm_usb_transfer_cb, NULL);
}

/* Send a vendor control OUT transfer with data payload and advance SSM */
static void
secugen_ctrl_out_data (FpiSsm        *ssm,
                       FpImageDevice *dev,
                       guint8         request,
                       guint16        value,
                       guint16        idx,
                       const guint8  *data,
                       gsize          len)
{
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (FP_DEVICE (dev));

  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 request, value, idx, len);
  memcpy (transfer->buffer, data, len);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_CTRL_TIMEOUT,
                           fpi_device_get_cancellable (FP_DEVICE (dev)),
                           fpi_ssm_usb_transfer_cb, NULL);
}

/* Read via vendor control IN transfer, callback receives data */
static void
secugen_ctrl_in (FpiSsm                *ssm,
                 FpImageDevice         *dev,
                 guint8                 request,
                 guint16                value,
                 guint16                idx,
                 gsize                  len,
                 FpiUsbTransferCallback callback)
{
  g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (FP_DEVICE (dev));

  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 request, value, idx, len);
  transfer->ssm = ssm;
  fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_CTRL_TIMEOUT,
                           fpi_device_get_cancellable (FP_DEVICE (dev)),
                           callback, NULL);
}

/* Write a single I2C register on the SIDO020A sensor */
static void
secugen_i2c_write (FpiSsm        *ssm,
                   FpImageDevice *dev,
                   guint8         reg,
                   guint8         val)
{
  secugen_ctrl_out_data (ssm, dev, SECUGEN_REQ_I2C_REG,
                         SECUGEN_I2C_ADDR, reg, &val, 1);
}

/* Read back a single I2C register (1 byte) */
static void
secugen_i2c_read (FpiSsm                *ssm,
                  FpImageDevice         *dev,
                  guint8                 reg,
                  FpiUsbTransferCallback callback)
{
  secugen_ctrl_in (ssm, dev, SECUGEN_REQ_I2C_REG,
                   SECUGEN_I2C_ADDR, reg, 1, callback);
}

/* Set exposure value (big-endian 16-bit + 2 zero bytes) */
static void
secugen_set_exposure (FpiSsm        *ssm,
                      FpImageDevice *dev,
                      guint16        exposure)
{
  guint8 data[4] = {
    (exposure >> 8) & 0xff,
    exposure & 0xff,
    0x00,
    0x00
  };

  secugen_ctrl_out_data (ssm, dev, SECUGEN_REQ_SET_EXPOSURE,
                         0x0000, 0, data, 4);
}

/* ================================================================
 * Init State Machine
 *
 * Matches the init sequence observed in USB captures:
 *   1. GET_DEVICE_ID
 *   2. 54 main I2C regs (with readback)
 *   3. Rewrite 0x03 = 0x05 (enable sensor)
 *   4. 4 late I2C regs: 0xa5-0xa8 (with readback)
 *   5. 8 capture window regs: 0x41-0x48 (with readback)
 *   6. START_CAPTURE (activates sensor subsystem)
 *   7. 6 FW/calibration data reads
 *   8. 0x32=0x00, SET_EXPOSURE(1000), START_CAPTURE, START_STREAM,
 *      bulk read 120KB calibration image, STOP_STREAM
 *   9. 8 frame window regs: 0x41-0x48 (with readback)
 *  10. Post-calibration tuning: 0x32/0x30/0x31 writes + SET_EXPOSURE(1116)
 * ================================================================ */

enum init_states {
  INIT_GET_DEVICE_ID = 0,
  /* Phase 1: Main I2C register init (54 regs) */
  INIT_I2C_WRITE,
  INIT_I2C_READBACK,
  /* Phase 2: Power enable + late regs */
  INIT_POWER_ENABLE,
  INIT_LATE_I2C_WRITE,
  INIT_LATE_I2C_READBACK,
  /* Phase 3: Capture window config */
  INIT_WINDOW_I2C_WRITE,
  INIT_WINDOW_I2C_READBACK,
  /* Phase 4: START_CAPTURE + FW data reads */
  INIT_PRE_FW_CAPTURE,
  INIT_FW_READ,
  /* Phase 5: Calibration capture */
  INIT_CAL_REG32,
  INIT_CAL_EXPOSURE,
  INIT_CAL_START_CAPTURE,
  INIT_CAL_START_STREAM,
  INIT_CAL_BULK_READ,
  INIT_CAL_STOP_STREAM,
  /* Phase 6: Frame window config */
  INIT_FRAME_I2C_WRITE,
  INIT_FRAME_I2C_READBACK,
  /* Phase 7: Post-calibration tuning */
  INIT_POST_REG32_CLEAR,
  INIT_POST_EXPOSURE,
  INIT_POST_REG32_CLEAR2,
  INIT_POST_REG30,
  INIT_POST_REG31,
  INIT_POST_REG32_CLEAR3,
  INIT_POST_REG32_SET,
  INIT_POST_EXPOSURE2,
  /* Phase 8: Final calibration capture (operational settings) */
  INIT_FINAL_REG32,
  INIT_FINAL_START_CAPTURE,
  INIT_FINAL_START_STREAM,
  INIT_FINAL_BULK_READ,
  INIT_FINAL_STOP_STREAM,
  INIT_NUM_STATES,
};

static void
init_device_id_cb (FpiUsbTransfer *transfer,
                   FpDevice       *dev,
                   gpointer        user_data,
                   GError         *error)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  memcpy (self->device_id, transfer->buffer, MIN (transfer->actual_length, 30));
  fp_dbg ("Device ID: %02x %02x %02x %02x ...",
          self->device_id[0], self->device_id[1],
          self->device_id[2], self->device_id[3]);
  fpi_ssm_next_state (transfer->ssm);
}

/* Readback callback for main init regs (54 entries) */
static void
init_i2c_readback_cb (FpiUsbTransfer *transfer,
                      FpDevice       *dev,
                      gpointer        user_data,
                      GError         *error)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length < 1)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  self->last_reg_rd = transfer->buffer[0];
  self->init_reg_idx++;

  if (self->init_reg_idx < (int) N_INIT_REGS)
    {
      fpi_ssm_jump_to_state (transfer->ssm, INIT_I2C_WRITE);
    }
  else
    {
      self->init_reg_idx = 0;
      fpi_ssm_next_state (transfer->ssm);
    }
}

/* Readback callback for late init regs (4 entries: 0xa5-0xa8) */
static void
init_late_readback_cb (FpiUsbTransfer *transfer,
                       FpDevice       *dev,
                       gpointer        user_data,
                       GError         *error)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length < 1)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  self->last_reg_rd = transfer->buffer[0];
  self->init_reg_idx++;

  if (self->init_reg_idx < (int) N_LATE_INIT_REGS)
    {
      fpi_ssm_jump_to_state (transfer->ssm, INIT_LATE_I2C_WRITE);
    }
  else
    {
      self->init_reg_idx = 0;
      fpi_ssm_next_state (transfer->ssm);
    }
}

/* Readback callback for capture window regs (8 entries) */
static void
init_window_readback_cb (FpiUsbTransfer *transfer,
                         FpDevice       *dev,
                         gpointer        user_data,
                         GError         *error)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length < 1)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  self->last_reg_rd = transfer->buffer[0];
  self->init_reg_idx++;

  if (self->init_reg_idx < (int) N_CAPTURE_WINDOW_REGS)
    {
      fpi_ssm_jump_to_state (transfer->ssm, INIT_WINDOW_I2C_WRITE);
    }
  else
    {
      self->init_reg_idx = 0;
      fpi_ssm_next_state (transfer->ssm);
    }
}

/* FW data read callback - accumulate data and extract reference image */
static void
init_fw_read_cb (FpiUsbTransfer *transfer,
                 FpDevice       *dev,
                 gpointer        user_data,
                 GError         *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (local_error)
    {
      fp_warn ("FW data read failed (non-fatal): %s", local_error->message);
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  /* Accumulate FW data into contiguous buffer */
  {
    gsize to_copy = transfer->actual_length;

    if (self->fw_data_len + to_copy > SECUGEN_FW_DATA_SIZE)
      to_copy = SECUGEN_FW_DATA_SIZE - self->fw_data_len;
    if (to_copy > 0 && self->fw_data)
      {
        memcpy (self->fw_data + self->fw_data_len, transfer->buffer, to_copy);
        self->fw_data_len += to_copy;
      }
  }

  self->fw_read_idx++;
  if (self->fw_read_idx < SECUGEN_FW_DATA_CHUNKS)
    {
      fpi_ssm_jump_to_state (transfer->ssm, INIT_FW_READ);
    }
  else
    {
      /* All FW data received - extract image processing parameters */
      if (!self->fw_data)
        {
          fp_warn ("FW data buffer missing; skipping calibration extraction");
          fpi_ssm_next_state (transfer->ssm);
          return;
        }

      /* BLC region offsets: 16 × int16 at fw_data[0x0e] */
      if (self->fw_data_len >= SECUGEN_BLC_OFFSETS_FW + 32)
        {
          int i;

          for (i = 0; i < 16; i++)
            {
              guint16 raw_val;

              memcpy (&raw_val,
                      self->fw_data + SECUGEN_BLC_OFFSETS_FW + i * 2, 2);
              self->blc_offsets[i] = (gint16) GUINT16_FROM_LE (raw_val);
            }
          self->has_blc_offsets = TRUE;
          fp_dbg ("BLC offsets: %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
                  self->blc_offsets[0], self->blc_offsets[1],
                  self->blc_offsets[2], self->blc_offsets[3],
                  self->blc_offsets[4], self->blc_offsets[5],
                  self->blc_offsets[6], self->blc_offsets[7],
                  self->blc_offsets[8], self->blc_offsets[9],
                  self->blc_offsets[10], self->blc_offsets[11],
                  self->blc_offsets[12], self->blc_offsets[13],
                  self->blc_offsets[14], self->blc_offsets[15]);
        }

      /* Reference image: 150×100 at fw_data[0x1df8] */
      if (self->fw_data_len >= SECUGEN_REF_OFFSET + SECUGEN_REF_SIZE)
        {
          const guint8 *ref_src = self->fw_data + SECUGEN_REF_OFFSET;

          if (!self->ref_image)
            self->ref_image = g_malloc (SECUGEN_IMG_SIZE);

          secugen_resize_ref_image (ref_src, self->ref_image);
          self->has_ref_image = TRUE;
          fp_dbg ("Flat-field reference image extracted and resized to %dx%d",
                  SECUGEN_IMG_WIDTH, SECUGEN_IMG_HEIGHT);
        }
      else
        {
          fp_warn ("FW data too short for reference image: %zu < %d",
                   self->fw_data_len,
                   SECUGEN_REF_OFFSET + SECUGEN_REF_SIZE);
        }

      /* Blend cal_value: uint16 at fw_data[0x5892] */
      if (self->fw_data_len >= SECUGEN_CAL_VALUE_FW + 2)
        {
          guint16 raw_val;

          memcpy (&raw_val, self->fw_data + SECUGEN_CAL_VALUE_FW, 2);
          self->cal_value = GUINT16_FROM_LE (raw_val);
          fp_dbg ("Blend cal_value from FW: %u", self->cal_value);
        }

      /* Sharpen parameters */
      if (self->fw_data_len >= SECUGEN_SHARPEN_AMOUNT_FW + 1)
        {
          self->sharpen_threshold = self->fw_data[SECUGEN_SHARPEN_THRESH_FW];
          self->sharpen_amount = self->fw_data[SECUGEN_SHARPEN_AMOUNT_FW];
          self->sharpen_limit = 10;  /* Default; exact FW offset is past our read */
          self->sharpen_enabled = (self->sharpen_threshold > 0 &&
                                   self->sharpen_amount > 0);
          fp_dbg ("Sharpen: threshold=%u amount=%u limit=%u enabled=%d",
                  self->sharpen_threshold, self->sharpen_amount,
                  self->sharpen_limit, self->sharpen_enabled);
        }

      /* The pipeline degrades gracefully when calibration data could not
       * be extracted, but image quality suffers - say so once. */
      if (!self->has_blc_offsets || !self->has_ref_image)
        {
          fp_warn ("Missing FW calibration data (BLC offsets: %s, reference "
                   "image: %s); captured images will have reduced quality",
                   self->has_blc_offsets ? "ok" : "missing",
                   self->has_ref_image ? "ok" : "missing");
        }

      fpi_ssm_next_state (transfer->ssm);
    }
}

/* Readback callback for frame window regs (8 entries) */
static void
init_frame_readback_cb (FpiUsbTransfer *transfer,
                        FpDevice       *dev,
                        gpointer        user_data,
                        GError         *error)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  if (transfer->actual_length < 1)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  self->last_reg_rd = transfer->buffer[0];
  self->init_reg_idx++;

  if (self->init_reg_idx < (int) N_FRAME_WINDOW_REGS)
    {
      fpi_ssm_jump_to_state (transfer->ssm, INIT_FRAME_I2C_WRITE);
    }
  else
    {
      self->init_reg_idx = 0;
      fpi_ssm_next_state (transfer->ssm);
    }
}

/*
 * Chunked frame read.
 *
 * The SIDO020A streams a full ~657KB sensor frame over the bulk-IN endpoint.
 * Reading it as a single USB transfer makes the frame impossible to record
 * with the standard usbmon/pcap-based test capture: the kernel usbmon ring
 * buffer caps per-URB payload at ring_size/5 (~245KB), so one 657KB URB is
 * truncated on capture and the replay cannot reconstruct the frame.
 *
 * Instead the frame is read in SECUGEN_BULK_CHUNK-sized pieces (a multiple of
 * the 512-byte bulk max-packet size, below the usbmon cap), accumulating into
 * a caller-supplied destination buffer. Every URB is then small enough to be
 * captured intact and the test capture works with the standard tooling. Once
 * the whole frame is read the owning SSM advances to its next state.
 */
static void
secugen_frame_chunk_cb (FpiUsbTransfer *transfer,
                        FpDevice       *dev,
                        gpointer        user_data,
                        GError         *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  gsize remaining;
  gsize copied;

  if (local_error)
    {
      /* A deactivate may have cancelled the transfer; unwind quietly. */
      if (self->deactivating)
        fpi_ssm_mark_completed (transfer->ssm);
      else
        fpi_ssm_mark_failed (transfer->ssm, g_steal_pointer (&local_error));
      return;
    }

  /* Abandon the read if a deactivate arrived mid-frame. */
  if (self->deactivating)
    {
      fpi_ssm_mark_completed (transfer->ssm);
      return;
    }

  /* Append this chunk to the frame buffer, guarding against overrun. */
  copied = MIN ((gsize) transfer->actual_length,
                SECUGEN_BULK_BUF_SIZE - self->bulk_offset);
  memcpy (self->bulk_dest + self->bulk_offset, transfer->buffer, copied);
  self->bulk_offset += copied;

  remaining = SECUGEN_BULK_BUF_SIZE - self->bulk_offset;

  /* A full-length chunk means the device may still have more frame data;
   * a short read means the stream has ended. */
  if (remaining > 0 && transfer->actual_length == transfer->length)
    {
      g_autoptr(FpiUsbTransfer) next = fpi_usb_transfer_new (dev);

      next->ssm = transfer->ssm;
      fpi_usb_transfer_fill_bulk (next, SECUGEN_EP_DATA,
                                  MIN ((gsize) SECUGEN_BULK_CHUNK, remaining));
      fpi_usb_transfer_submit (g_steal_pointer (&next), SECUGEN_BULK_TIMEOUT,
                               fpi_device_get_cancellable (dev),
                               secugen_frame_chunk_cb, NULL);
      return;
    }

  /* Zero any unread tail so a short frame never leaves stale data from a
   * previous capture in the destination buffer. */
  if (remaining > 0)
    memset (self->bulk_dest + self->bulk_offset, 0, remaining);

  if (self->bulk_offset < SECUGEN_RAW_SIZE)
    {
      fp_warn ("Short image data: got %" G_GSIZE_FORMAT ", expected %d",
               self->bulk_offset, SECUGEN_RAW_SIZE);
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new (FP_DEVICE_ERROR_PROTO));
      return;
    }

  fp_dbg ("Read %" G_GSIZE_FORMAT " byte frame in chunks", self->bulk_offset);
  fpi_ssm_next_state (transfer->ssm);
}

/* Begin a chunked read of a full sensor frame into dest. */
static void
secugen_read_frame (FpiSsm   *ssm,
                    FpDevice *dev,
                    guint8   *dest)
{
  g_autoptr(FpiUsbTransfer) transfer = NULL;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  self->bulk_dest = dest;
  self->bulk_offset = 0;

  transfer = fpi_usb_transfer_new (dev);
  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, SECUGEN_EP_DATA,
                              MIN ((gsize) SECUGEN_BULK_CHUNK,
                                   (gsize) SECUGEN_BULK_BUF_SIZE));
  fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_BULK_TIMEOUT,
                           fpi_device_get_cancellable (dev),
                           secugen_frame_chunk_cb, NULL);
}

static void
init_run_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (_dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case INIT_GET_DEVICE_ID:
      secugen_ctrl_in (ssm, dev, SECUGEN_REQ_GET_DEVICE_ID,
                       0x0000, 0, 30, init_device_id_cb);
      break;

    /* ---- Phase 1: Main I2C init (54 regs) ---- */

    case INIT_I2C_WRITE:
      {
        const struct secugen_reg_entry *entry =
          &sido020a_init_regs[self->init_reg_idx];
        secugen_i2c_write (ssm, dev, entry->reg, entry->val);
      }
      break;

    case INIT_I2C_READBACK:
      {
        const struct secugen_reg_entry *entry =
          &sido020a_init_regs[self->init_reg_idx];
        secugen_i2c_read (ssm, dev, entry->reg, init_i2c_readback_cb);
      }
      break;

    /* ---- Phase 2: Power enable + late regs ---- */

    case INIT_POWER_ENABLE:
      /* Rewrite reg 0x03 from 0x02 (reset) to 0x05 (enable) */
      secugen_i2c_write (ssm, dev, 0x03, 0x05);
      break;

    case INIT_LATE_I2C_WRITE:
      {
        const struct secugen_reg_entry *entry;

        entry = &late_init_regs[self->init_reg_idx];
        secugen_i2c_write (ssm, dev, entry->reg, entry->val);
      }
      break;

    case INIT_LATE_I2C_READBACK:
      {
        const struct secugen_reg_entry *entry =
          &late_init_regs[self->init_reg_idx];
        secugen_i2c_read (ssm, dev, entry->reg, init_late_readback_cb);
      }
      break;

    /* ---- Phase 3: Capture window config ---- */

    case INIT_WINDOW_I2C_WRITE:
      {
        const struct secugen_reg_entry *entry;

        entry = &capture_window_regs[self->init_reg_idx];
        secugen_i2c_write (ssm, dev, entry->reg, entry->val);
      }
      break;

    case INIT_WINDOW_I2C_READBACK:
      {
        const struct secugen_reg_entry *entry =
          &capture_window_regs[self->init_reg_idx];
        secugen_i2c_read (ssm, dev, entry->reg, init_window_readback_cb);
      }
      break;

    /* ---- Phase 4: START_CAPTURE + FW data reads ---- */

    case INIT_PRE_FW_CAPTURE:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_CAPTURE, 0x0001, 0);
      break;

    case INIT_FW_READ:
      {
        guint16 offset = SECUGEN_FW_DATA_START +
                         (self->fw_read_idx * SECUGEN_FW_DATA_CHUNK);
        gsize len = (self->fw_read_idx == SECUGEN_FW_DATA_CHUNKS - 1) ?
                    SECUGEN_FW_DATA_LAST_LEN :
                    SECUGEN_FW_DATA_CHUNK;

        {
          g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (FP_DEVICE (dev));

          fpi_usb_transfer_fill_control (transfer,
                                         G_USB_DEVICE_DIRECTION_DEVICE_TO_HOST,
                                         G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                         G_USB_DEVICE_RECIPIENT_DEVICE,
                                         SECUGEN_REQ_READ_FW_DATA,
                                         0x0000, offset, len);
          transfer->ssm = ssm;
          fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_FW_READ_TIMEOUT,
                                   fpi_device_get_cancellable (FP_DEVICE (dev)),
                                   init_fw_read_cb, NULL);
        }
      }
      break;

    /* ---- Phase 5: Calibration capture ---- */

    case INIT_CAL_REG32:
      /* Must clear reg 0x32 before each image capture */
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case INIT_CAL_EXPOSURE:
      self->exposure = SECUGEN_EXPOSURE_INIT;
      secugen_set_exposure (ssm, dev, SECUGEN_EXPOSURE_INIT);
      break;

    case INIT_CAL_START_CAPTURE:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_CAPTURE, 0x0001, 0);
      break;

    case INIT_CAL_START_STREAM:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_STREAM, 0x0000, 0);
      break;

    case INIT_CAL_BULK_READ:
      secugen_read_frame (ssm, _dev, self->cal_raw);
      break;

    case INIT_CAL_STOP_STREAM:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_STOP_STREAM, 0x0000, 0);
      break;

    /* ---- Phase 6: Frame window config ---- */

    case INIT_FRAME_I2C_WRITE:
      {
        const struct secugen_reg_entry *entry;

        entry = &frame_window_regs[self->init_reg_idx];
        secugen_i2c_write (ssm, dev, entry->reg, entry->val);
      }
      break;

    case INIT_FRAME_I2C_READBACK:
      {
        const struct secugen_reg_entry *entry =
          &frame_window_regs[self->init_reg_idx];
        secugen_i2c_read (ssm, dev, entry->reg, init_frame_readback_cb);
      }
      break;

    /* ---- Phase 7: Post-calibration tuning ---- */

    case INIT_POST_REG32_CLEAR:
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case INIT_POST_EXPOSURE:
      self->exposure = SECUGEN_EXPOSURE_NORMAL;
      secugen_set_exposure (ssm, dev, SECUGEN_EXPOSURE_NORMAL);
      break;

    case INIT_POST_REG32_CLEAR2:
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case INIT_POST_REG30:
      /* Frame control transitions from init value 0x01 to 0x04 */
      secugen_i2c_write (ssm, dev, 0x30, 0x04);
      break;

    case INIT_POST_REG31:
      /* Frame size transitions from init value 0xc0 to 0x5c */
      secugen_i2c_write (ssm, dev, 0x31, 0x5c);
      break;

    case INIT_POST_REG32_CLEAR3:
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case INIT_POST_REG32_SET:
      /* Final 0x32 value for operational mode */
      secugen_i2c_write (ssm, dev, 0x32, 0x24);
      break;

    case INIT_POST_EXPOSURE2:
      secugen_set_exposure (ssm, dev, SECUGEN_EXPOSURE_NORMAL);
      break;

    /* ---- Phase 8: Final calibration capture (operational settings) ---- */

    case INIT_FINAL_REG32:
      /* Clear reg 0x32 before capture (same as every capture) */
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case INIT_FINAL_START_CAPTURE:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_CAPTURE, 0x0001, 0);
      break;

    case INIT_FINAL_START_STREAM:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_STREAM, 0x0000, 0);
      break;

    case INIT_FINAL_BULK_READ:
      secugen_read_frame (ssm, _dev, self->cal_raw);
      break;

    case INIT_FINAL_STOP_STREAM:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_STOP_STREAM, 0x0000, 0);
      break;
    }
}

/* ================================================================
 * Image Processing Pipeline
 *
 *   1. Band compensation at 956x688
 *   2. Edge-aware unsharp mask at 956x688
 *   3. Bilinear downsample to 300x400
 *   4. Flat-field (blend) correction at 300x400
 *   5. 6-directional sharpening at 300x400
 *   6. Invert - bitwise NOT (~pixel)
 *
 * The raw SIDO020A readout has strong fixed-pattern noise (per-region
 * brightness bands, optical vignetting) that NBIS minutiae detection
 * does not compensate for; stages 1-5 replicate the capture processing
 * the sensor needs to produce a usable ridge image. Stages 1, 4 and 5
 * are driven by per-device factory calibration data read from the FW
 * (see init_fw_read_cb) and degrade gracefully when it is unavailable.
 * ================================================================ */

/* Brightness-dependent offset scaling for band compensation.
 * Correction strength steps down at pixel values 200, 160, 100, 70, 26. */
static inline int
secugen_blc_scale_offset (int pixel, int offset)
{
  if (pixel > 200)
    return offset;
  else if (pixel > 160)
    return (offset * 3) >> 2;
  else if (pixel > 100)
    return offset >> 1;
  else if (pixel > 70)
    return offset >> 2;
  else if (pixel >= 26)
    return offset >> 3;
  else
    return 0;
}

/* Per-region band compensation.
 * Region layout: 2 rows × 8 columns (16 regions).
 * Processes every other row with 3-phase dithering pattern. */
static void
secugen_blc_compensate (guint8       *image,
                        int           width,
                        int           height,
                        const gint16 *offsets)
{
  static const int phase_table[12] = {
    7, 11, 13, 14, 5, 3, 6, 9, 4, 8, 2, 1
  };
  int half_h = height / 2;
  int eighth_w = width / 8;
  int region;

  for (region = 0; region < 16; region++)
    {
      int rc = region % 8;
      int rr = region / 8;
      int x0 = rc * eighth_w;
      int x1 = (rc == 7) ? width - 1 : (rc + 1) * eighth_w - 1;
      int y0 = rr * half_h;
      int y1 = (rr == 1) ? height - 1 : half_h - 1;
      int offset = offsets[region];
      int phase_counter = -1;
      int row, col;

      for (row = y0 + 1; row <= y1; row += 2)
        {
          phase_counter++;
          if (phase_counter > 2)
            phase_counter = 0;

          for (col = x0; col <= x1; col++)
            {
              int idx = row * width + col;
              int pixel = image[idx];
              int scaled = secugen_blc_scale_offset (pixel, offset);
              int quot = scaled / 100;
              int remainder = scaled - quot * 100;
              int abs_rem = remainder < 0 ? -remainder : remainder;
              int extra = 0;
              int bit_idx = (col - x0) & 3;
              int result;

              if (abs_rem > 74)
                extra = (phase_table[phase_counter] >> bit_idx) & 1;
              else if (abs_rem > 49)
                extra = (phase_table[phase_counter + 4] >> bit_idx) & 1;
              else if (abs_rem > 24)
                extra = (phase_table[phase_counter + 8] >> bit_idx) & 1;

              if (scaled >= 0)
                result = pixel - (quot + extra);
              else
                result = pixel - (quot - extra);

              if (result < 0)
                result = 0;
              else if (result > 255)
                result = 255;
              image[idx] = (guint8) result;
            }
        }
    }
}

/* Edge-aware unsharp mask.
 * 3×3 box filter, threshold = pixel/8 + 2.
 * Only sharpens pixels where any neighbor differs by more than threshold.
 * Boost = (center - averaged) / 2, only for bright-side edges. */
static void
secugen_unsharp_mask (guint8 *image, int width, int height)
{
  int total = width * height;
  g_autofree guint8 *original = NULL;
  g_autofree guint8 *averaged = NULL;
  int r, c;

  original = g_malloc (total);
  memcpy (original, image, total);
  averaged = g_malloc (total);
  memcpy (averaged, original, total);

  /* 3×3 box filter (AverageFilter with radius=1) */
  for (r = 1; r < height - 1; r++)
    for (c = 1; c < width - 1; c++)
      {
        int sum = original[(r - 1) * width + c - 1]
                  + original[(r - 1) * width + c]
                  + original[(r - 1) * width + c + 1]
                  + original[r * width + c - 1]
                  + original[r * width + c]
                  + original[r * width + c + 1]
                  + original[(r + 1) * width + c - 1]
                  + original[(r + 1) * width + c]
                  + original[(r + 1) * width + c + 1];

        averaged[r * width + c] = (guint8) (sum / 9);
      }

  /* Edge-aware sharpening (skips top 2 rows, bottom 1 row,
   * left/right 1 column) */
  for (r = 2; r < height - 1; r++)
    for (c = 1; c < width - 1; c++)
      {
        int idx = r * width + c;
        int center = original[idx];
        int threshold = (center >> 3) + 2;

        if (abs (center - original[idx - 1]) > threshold ||
            abs (center - original[idx + 1]) > threshold ||
            abs (center - original[idx - width]) > threshold ||
            abs (center - original[idx + width]) > threshold)
          {
            int avg = averaged[idx];

            if (center > avg + 1)
              {
                int boost = (center - avg) / 2;
                int result = center + boost;

                if (result > 255)
                  result = 255;
                image[idx] = (guint8) result;
              }
            /* else: keep original (already in image) */
          }
        /* else: keep original */
      }

}

/*
 * Bilinear downsample from raw sensor to output dimensions.
 *
 * Uses 8-bit fixed-point weights rather than floating point so the decoded
 * image is bit-identical across compilers and architectures: the umockdev
 * test compares the output against a committed reference image pixel-for-pixel
 * (with no tolerance), and float rounding would diverge between build
 * environments. Interpolation weights sum to FRAC*FRAC, so the weighted sum is
 * rounded back down by that factor with round-to-nearest.
 */
#define SECUGEN_RESIZE_FRAC_BITS 8
#define SECUGEN_RESIZE_FRAC (1 << SECUGEN_RESIZE_FRAC_BITS)

static void
secugen_resize_bilinear (const guint8 *src, int src_w, int src_h,
                         guint8 *dst, int dst_w, int dst_h)
{
  int r, c;

  for (r = 0; r < dst_h; r++)
    {
      /* Source row position in fixed point (scaled by SECUGEN_RESIZE_FRAC). */
      int src_r = (int) ((gint64) r * (src_h - 1) * SECUGEN_RESIZE_FRAC /
                         (dst_h - 1));
      int r0 = src_r >> SECUGEN_RESIZE_FRAC_BITS;
      int r1 = r0 + 1;
      int wr1 = src_r & (SECUGEN_RESIZE_FRAC - 1);
      int wr0 = SECUGEN_RESIZE_FRAC - wr1;

      if (r1 >= src_h)
        r1 = src_h - 1;

      for (c = 0; c < dst_w; c++)
        {
          int src_c = (int) ((gint64) c * (src_w - 1) * SECUGEN_RESIZE_FRAC /
                             (dst_w - 1));
          int c0 = src_c >> SECUGEN_RESIZE_FRAC_BITS;
          int c1 = c0 + 1;
          int wc1 = src_c & (SECUGEN_RESIZE_FRAC - 1);
          int wc0 = SECUGEN_RESIZE_FRAC - wc1;
          guint32 acc;
          int pixel;

          if (c1 >= src_w)
            c1 = src_w - 1;

          acc = (guint32) wr0 * wc0 * src[r0 * src_w + c0]
                + (guint32) wr0 * wc1 * src[r0 * src_w + c1]
                + (guint32) wr1 * wc0 * src[r1 * src_w + c0]
                + (guint32) wr1 * wc1 * src[r1 * src_w + c1];

          pixel = (int) ((acc + (SECUGEN_RESIZE_FRAC * SECUGEN_RESIZE_FRAC) / 2)
                         >> (2 * SECUGEN_RESIZE_FRAC_BITS));
          if (pixel > 255)
            pixel = 255;
          dst[r * dst_w + c] = (guint8) pixel;
        }
    }
}

/* Flat-field (blend) correction.
 * Formula: result = pixel + ((cal_val - ref[i]) * curve[pixel]) >> 8
 * The curve is an S-curve that protects dark pixels and applies
 * full correction to bright pixels. */
static void
secugen_blend (guint8       *image,
               int           width,
               int           height,
               const guint8 *ref_image,
               int           cal_val,
               const guint8 *curve)
{
  int r, c;

  for (r = 0; r < height; r++)
    for (c = 0; c < width; c++)
      {
        int idx = r * width + c;
        int pixel = image[idx];
        int ref_val = ref_image[idx];
        int curve_val = curve[pixel];
        int correction = ((cal_val - ref_val) * curve_val) >> 8;
        int result = pixel + correction;

        if (result > 255)
          result = 255;
        else if (result < 0)
          result = 0;
        image[idx] = (guint8) result;
      }
}

/* 6-directional gradient sharpening.
 * Only enhances pixels where ALL 6 gradients agree on edge direction.
 * Case 1: all gradients > threshold (peak) → positive boost.
 * Case 2: all gradients < -threshold (valley) → negative boost. */
static void
secugen_sharpen (const guint8 *src,
                 guint8       *dst,
                 int           width,
                 int           height,
                 int           threshold,
                 int           amount,
                 int           limit)
{
  int neg_threshold = -threshold;
  int neg_amount = -amount;
  int r, c;

  for (r = 0; r < height; r++)
    for (c = 0; c < width; c++)
      {
        int idx = r * width + c;

        if (r == 0 || r == height - 1 || c == 0 || c == width - 1)
          {
            dst[idx] = src[idx];
            continue;
          }

        {
          int center  = src[idx];
          int d_up    = center - src[(r - 1) * width + c];
          int d_down  = center - src[(r + 1) * width + c];
          int d_left  = center - src[r * width + c - 1];
          int d_right = center - src[r * width + c + 1];
          int d_ul    = src[r * width + c - 1] -
                        src[(r - 1) * width + c - 1];
          int d_dr    = src[r * width + c + 1] -
                        src[(r + 1) * width + c + 1];

          if (d_up > threshold && d_down > threshold &&
              d_left > threshold && d_right > threshold &&
              d_ul > threshold && d_dr > threshold)
            {
              int g1 = MIN (MIN (d_up, d_left), amount);
              int g2 = MIN (MIN (d_down, d_right), amount);
              int g3 = MIN (MIN (d_ul, d_dr), amount);
              int avg = (g1 + g2 + g3) / 3;
              int boost = (avg - threshold) * limit / 10;
              int result = center + boost;

              if (result > 255)
                result = 255;
              else if (result < 0)
                result = 0;
              dst[idx] = (guint8) result;
            }
          else if (d_up < neg_threshold && d_down < neg_threshold &&
                   d_left < neg_threshold && d_right < neg_threshold &&
                   d_ul < neg_threshold && d_dr < neg_threshold)
            {
              int g1 = MAX (MAX (d_up, d_left), neg_amount);
              int g2 = MAX (MAX (d_down, d_right), neg_amount);
              int g3 = MAX (MAX (d_ul, d_dr), neg_amount);
              int avg = (g1 + g2 + g3) / 3;
              int boost = (avg + threshold) * limit / 10;
              int result = center + boost;

              if (result > 255)
                result = 255;
              else if (result < 0)
                result = 0;
              dst[idx] = (guint8) result;
            }
          else
            {
              dst[idx] = src[idx];
            }
        }
      }
}

typedef struct
{
  guint8  *raw_frame;
  gboolean has_blc_offsets;
  gint16   blc_offsets[16];
  gboolean has_ref_image;
  guint8  *ref_image;
  guint16  cal_value;
  gboolean sharpen_enabled;
  guint8   sharpen_threshold;
  guint8   sharpen_amount;
  guint8   sharpen_limit;
} SecugenCaptureTaskData;

typedef struct
{
  guint8 *frame;
  guint8 *cal_raw;
} SecugenDetectTaskData;

typedef struct
{
  guint    mean;
  gboolean finger_present;
  gboolean update_calibration;
  guint8  *new_cal_raw;
} SecugenDetectTaskResult;

static void
secugen_capture_task_data_free (SecugenCaptureTaskData *data)
{
  g_clear_pointer (&data->raw_frame, g_free);
  g_clear_pointer (&data->ref_image, g_free);
  g_free (data);
}

static void
secugen_detect_task_data_free (SecugenDetectTaskData *data)
{
  g_clear_pointer (&data->frame, g_free);
  g_clear_pointer (&data->cal_raw, g_free);
  g_free (data);
}

static void
secugen_detect_task_result_free (SecugenDetectTaskResult *result)
{
  g_clear_pointer (&result->new_cal_raw, g_free);
  g_free (result);
}

G_DEFINE_AUTOPTR_CLEANUP_FUNC (SecugenCaptureTaskData, secugen_capture_task_data_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SecugenDetectTaskData, secugen_detect_task_data_free)
G_DEFINE_AUTOPTR_CLEANUP_FUNC (SecugenDetectTaskResult, secugen_detect_task_result_free)

static void
secugen_capture_process_thread (GTask                    *task,
                                gpointer source_object    G_GNUC_UNUSED,
                                gpointer                  task_data,
                                GCancellable *cancellable G_GNUC_UNUSED)
{
  SecugenCaptureTaskData *data = task_data;
  g_autofree guint8 *image = g_malloc (SECUGEN_IMG_SIZE);

  if (g_task_return_error_if_cancelled (task))
    return;

  /*
   * Image processing pipeline:
   *   1. Band compensation at 956x688
   *   2. Edge-aware unsharp mask at 956x688
   *   3. Bilinear downsample 956x688 → 300x400
   *   4. Flat-field blend at 300x400
   *   5. Directional sharpening at 300x400 (conditional)
   *   6. Bitwise NOT invert
   */

  /* Step 1: BLC band compensation */
  if (data->has_blc_offsets)
    secugen_blc_compensate (data->raw_frame, SECUGEN_RAW_WIDTH,
                            SECUGEN_RAW_HEIGHT, data->blc_offsets);

  /* Step 2: Edge-aware unsharp mask */
  secugen_unsharp_mask (data->raw_frame, SECUGEN_RAW_WIDTH, SECUGEN_RAW_HEIGHT);

  /* Step 3: Bilinear downsample to 300x400 */
  secugen_resize_bilinear (data->raw_frame,
                           SECUGEN_RAW_WIDTH, SECUGEN_RAW_HEIGHT,
                           image,
                           SECUGEN_IMG_WIDTH, SECUGEN_IMG_HEIGHT);

  if (g_task_return_error_if_cancelled (task))
    return;

  /* Step 4: Blend flat-field correction */
  if (data->has_ref_image)
    {
      secugen_blend (image,
                     SECUGEN_IMG_WIDTH, SECUGEN_IMG_HEIGHT,
                     data->ref_image,
                     data->cal_value,
                     SECUGEN_BLEND_CURVE);
    }

  if (g_task_return_error_if_cancelled (task))
    return;

  /* Step 5: Directional sharpening (conditional) */
  if (data->sharpen_enabled)
    {
      g_autofree guint8 *sharpened = g_malloc (SECUGEN_IMG_SIZE);

      secugen_sharpen (image, sharpened,
                       SECUGEN_IMG_WIDTH, SECUGEN_IMG_HEIGHT,
                       data->sharpen_threshold,
                       data->sharpen_amount,
                       data->sharpen_limit);
      memcpy (image, sharpened, SECUGEN_IMG_SIZE);
    }

  /* Step 6: Invert (bitwise NOT) */
  for (int i = 0; i < SECUGEN_IMG_SIZE; i++)
    image[i] = ~image[i];

  if (g_task_return_error_if_cancelled (task))
    return;

  g_task_return_pointer (task, g_steal_pointer (&image), g_free);
}

static void
secugen_detect_analyze_thread (GTask                 *task,
                               gpointer source_object G_GNUC_UNUSED,
                               gpointer               task_data,
                               GCancellable          *cancellable)
{
  SecugenDetectTaskData *data = task_data;

  g_autoptr(SecugenDetectTaskResult) result = g_new0 (SecugenDetectTaskResult, 1);
  guint64 sum = 0;
  int count = 0;
  int start_row = SECUGEN_RAW_HEIGHT / 4;
  int end_row = 3 * SECUGEN_RAW_HEIGHT / 4;
  int start_col = SECUGEN_RAW_WIDTH / 4;
  int end_col = 3 * SECUGEN_RAW_WIDTH / 4;

  if (g_task_return_error_if_cancelled (task))
    return;

  /* Compute mean brightness of central 50% region */
  for (int y = start_row; y < end_row; y++)
    {
      for (int x = start_col; x < end_col; x++)
        {
          int idx = y * SECUGEN_RAW_WIDTH + x;
          int val = (int) data->frame[idx] - (int) data->cal_raw[idx];

          if (val < 0)
            val = 0;
          sum += val;
          count++;
        }

      if (g_task_return_error_if_cancelled (task))
        return;
    }

  result->mean = count > 0 ? (guint) (sum / count) : 0;
  result->finger_present = (result->mean >= SECUGEN_FINGER_THRESHOLD);
  result->update_calibration = (!result->finger_present && result->mean <= 5);
  if (result->update_calibration)
    result->new_cal_raw = g_memdup2 (data->frame, SECUGEN_BULK_BUF_SIZE);

  g_task_return_pointer (task,
                         g_steal_pointer (&result),
                         (GDestroyNotify) secugen_detect_task_result_free);
}

/* ================================================================
 * Capture State Machine
 *
 * Capture sequence observed in USB captures:
 *   I2C 0x32 = 0x00 -> SET_EXPOSURE -> START_CAPTURE ->
 *   START_STREAM -> bulk read 657KB -> STOP_STREAM -> GET_STATUS
 * ================================================================ */

enum capture_states {
  CAPTURE_REG32_CLEAR = 0,
  CAPTURE_LED_ON,
  CAPTURE_SET_EXPOSURE,
  CAPTURE_START,
  CAPTURE_STREAM_ON,
  CAPTURE_BULK_READ,
  CAPTURE_STREAM_OFF,
  CAPTURE_GET_STATUS,
  CAPTURE_DONE,
  CAPTURE_NUM_STATES,
};

static void
capture_process_done (GObject      *source_object,
                      GAsyncResult *result,
                      gpointer      user_data)
{
  g_autoptr(FpImage) img = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *processed = NULL;
  FpDevice *dev = FP_DEVICE (source_object);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  FpiSsm *ssm = user_data;

  processed = g_task_propagate_pointer (G_TASK (result), &error);
  if (error)
    {
      if (self->deactivating &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }

      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  img = fp_image_new (SECUGEN_IMG_WIDTH, SECUGEN_IMG_HEIGHT);
  img->ppmm = SECUGEN_PPMM;
  img->flags = FPI_IMAGE_V_FLIPPED | FPI_IMAGE_H_FLIPPED;
  memcpy (img->data, processed, SECUGEN_IMG_SIZE);

  fpi_image_device_image_captured (FP_IMAGE_DEVICE (dev), g_steal_pointer (&img));
  fpi_ssm_mark_completed (ssm);
}

static void
capture_status_cb (FpiUsbTransfer *transfer,
                   FpDevice       *dev,
                   gpointer        user_data,
                   GError         *error)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  memcpy (self->last_status, transfer->buffer,
          MIN (transfer->actual_length, 4));
  fpi_ssm_next_state (transfer->ssm);
}

static void
capture_run_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (_dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAPTURE_REG32_CLEAR:
      /* Must clear reg 0x32 before each capture */
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case CAPTURE_LED_ON:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_LED_CONTROL, 0x0001, 0);
      break;

    case CAPTURE_SET_EXPOSURE:
      secugen_set_exposure (ssm, dev, self->exposure);
      break;

    case CAPTURE_START:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_CAPTURE, 0x0001, 0);
      break;

    case CAPTURE_STREAM_ON:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_STREAM, 0x0000, 0);
      break;

    case CAPTURE_BULK_READ:
      secugen_read_frame (ssm, _dev, self->bulk_buffer);
      break;

    case CAPTURE_STREAM_OFF:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_STOP_STREAM, 0x0000, 0);
      break;

    case CAPTURE_GET_STATUS:
      secugen_ctrl_in (ssm, dev, SECUGEN_REQ_GET_STATUS,
                       0x0000, 0, 4, capture_status_cb);
      break;

    case CAPTURE_DONE:
      {
        g_autoptr(GTask) task = NULL;
        g_autoptr(SecugenCaptureTaskData) task_data = NULL;

        /* Snapshot frame + calibration parameters for worker-thread processing.
         * The shared driver buffers remain owned by the main thread. */
        task_data = g_new0 (SecugenCaptureTaskData, 1);
        task_data->raw_frame = g_memdup2 (self->bulk_buffer, SECUGEN_RAW_SIZE);
        task_data->has_blc_offsets = self->has_blc_offsets;
        memcpy (task_data->blc_offsets, self->blc_offsets, sizeof (task_data->blc_offsets));
        task_data->has_ref_image = self->has_ref_image;

        if (self->has_ref_image)
          task_data->ref_image = g_memdup2 (self->ref_image, SECUGEN_IMG_SIZE);

        task_data->cal_value = self->cal_value;
        task_data->sharpen_enabled = self->sharpen_enabled;
        task_data->sharpen_threshold = self->sharpen_threshold;
        task_data->sharpen_amount = self->sharpen_amount;
        task_data->sharpen_limit = self->sharpen_limit;

        task = g_task_new (FP_DEVICE (dev),
                           fpi_device_get_cancellable (FP_DEVICE (dev)),
                           capture_process_done,
                           ssm);
        g_task_set_source_tag (task, secugen_capture_process_thread);
        g_task_set_check_cancellable (task, TRUE);
        g_task_set_task_data (task, g_steal_pointer (&task_data),
                              (GDestroyNotify) secugen_capture_task_data_free);
        g_task_run_in_thread (task, secugen_capture_process_thread);
        break;
      }
    }
}

static void secugen_finish_deactivate (FpImageDevice *dev);

static void
capture_ssm_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  FpImageDevice *imgdev = FP_IMAGE_DEVICE (dev);

  self->ssm_count--;

  if (self->deactivating)
    {
      if (self->ssm_count == 0)
        secugen_finish_deactivate (imgdev);
      return;
    }

  if (local_error)
    {
      fp_warn ("Capture failed: %s", local_error->message);
      fpi_image_device_session_error (imgdev, g_steal_pointer (&local_error));
    }
}

/* No-op callback for fire-and-forget USB transfers (e.g. LED control) */
static void
secugen_noop_cb (FpiUsbTransfer *transfer,
                 FpDevice       *dev,
                 gpointer        user_data,
                 GError         *error)
{
  g_autoptr(GError) local_error = error;

  if (local_error)
    fp_warn ("Fire-and-forget transfer failed: %s", local_error->message);
}

/* ================================================================
 * Finger Detection (Image-Based)
 *
 * The SIDO020A has no touch/proximity chip. GET_STATUS always returns
 * zeros. Finger presence is instead detected by capturing preview
 * frames and checking mean brightness:
 *   - No finger: dark image (mean ~20)
 *   - Finger present: reflected LED light (mean ~70+)
 *
 * We implement this as a detect SSM that captures a frame, computes
 * mean brightness of the central region, and reports finger status.
 * If no finger, we schedule another poll after SECUGEN_FINGER_POLL_MS.
 * ================================================================ */

enum detect_states {
  DETECT_REG32_CLEAR = 0,
  DETECT_SET_EXPOSURE,
  DETECT_START_CAPTURE,
  DETECT_START_STREAM,
  DETECT_BULK_READ,
  DETECT_STOP_STREAM,
  DETECT_ANALYZE,
  DETECT_NUM_STATES,
};

static void detect_start (FpImageDevice *dev);
static void detect_retry_timeout (FpDevice          *dev,
                                  gpointer user_data G_GNUC_UNUSED);
static void detect_analyze_done (GObject      *source_object,
                                 GAsyncResult *result,
                                 gpointer      user_data);

static void
detect_analyze_done (GObject      *source_object,
                     GAsyncResult *result,
                     gpointer      user_data)
{
  FpDevice *dev = FP_DEVICE (source_object);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  FpiSsm *ssm = user_data;

  g_autoptr(GError) error = NULL;
  g_autoptr(SecugenDetectTaskResult) analysis = NULL;

  analysis = g_task_propagate_pointer (G_TASK (result), &error);
  if (error)
    {
      if (self->deactivating &&
          g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }
      fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
      return;
    }

  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  fp_dbg ("Finger detect: mean brightness = %u (threshold %d)",
          analysis->mean, SECUGEN_FINGER_THRESHOLD);

  if (analysis->finger_present)
    {
      fp_dbg ("Finger detected!");
      fpi_image_device_report_finger_status (FP_IMAGE_DEVICE (dev), TRUE);
    }
  else
    {
      if (analysis->update_calibration && analysis->new_cal_raw)
        memcpy (self->cal_raw, analysis->new_cal_raw, SECUGEN_BULK_BUF_SIZE);

      self->finger_poll_source =
        fpi_device_add_timeout (FP_DEVICE (dev),
                                SECUGEN_FINGER_POLL_MS,
                                detect_retry_timeout,
                                NULL,
                                NULL);
    }

  fpi_ssm_mark_completed (ssm);
}

static void
detect_run_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *dev = FP_IMAGE_DEVICE (_dev);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (_dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case DETECT_REG32_CLEAR:
      secugen_i2c_write (ssm, dev, 0x32, 0x00);
      break;

    case DETECT_SET_EXPOSURE:
      secugen_set_exposure (ssm, dev, self->exposure);
      break;

    case DETECT_START_CAPTURE:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_CAPTURE, 0x0001, 0);
      break;

    case DETECT_START_STREAM:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_START_STREAM, 0x0000, 0);
      break;

    case DETECT_BULK_READ:
      secugen_read_frame (ssm, _dev, self->bulk_buffer);
      break;

    case DETECT_STOP_STREAM:
      secugen_ctrl_out (ssm, dev, SECUGEN_REQ_STOP_STREAM, 0x0000, 0);
      break;

    case DETECT_ANALYZE:
      {
        g_autoptr(GTask) task = NULL;
        g_autoptr(SecugenDetectTaskData) task_data = NULL;

        /* If a deactivate arrived while this detect cycle ran, do not report
         * finger state or arm another poll - just unwind the SSM so the
         * deferred deactivation can complete. */
        if (self->deactivating)
          {
            fpi_ssm_mark_completed (ssm);
            break;
          }

        /* Snapshot current frame/calibration for worker-thread analysis. */
        task_data = g_new0 (SecugenDetectTaskData, 1);
        task_data->frame = g_memdup2 (self->bulk_buffer, SECUGEN_BULK_BUF_SIZE);
        task_data->cal_raw = g_memdup2 (self->cal_raw, SECUGEN_BULK_BUF_SIZE);

        task = g_task_new (FP_DEVICE (dev),
                           fpi_device_get_cancellable (FP_DEVICE (dev)),
                           detect_analyze_done,
                           ssm);
        g_task_set_source_tag (task, secugen_detect_analyze_thread);
        g_task_set_check_cancellable (task, TRUE);
        g_task_set_task_data (task, g_steal_pointer (&task_data),
                              (GDestroyNotify) secugen_detect_task_data_free);
        g_task_run_in_thread (task, secugen_detect_analyze_thread);
      }
      break;
    }
}

static void
detect_retry_timeout (FpDevice *dev, gpointer user_data G_GNUC_UNUSED)
{
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (img_dev);

  self->finger_poll_source = NULL;
  detect_start (img_dev);
}

static void
detect_ssm_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  self->ssm_count--;

  if (self->deactivating)
    {
      if (self->ssm_count == 0)
        secugen_finish_deactivate (FP_IMAGE_DEVICE (dev));
      return;
    }

  if (local_error)
    {
      fp_warn ("Finger detect failed: %s", local_error->message);
      fpi_image_device_session_error (FP_IMAGE_DEVICE (dev),
                                      g_steal_pointer (&local_error));
    }
}

static void
detect_start (FpImageDevice *dev)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  FpiSsm *ssm;

  self->ssm_count++;
  ssm = fpi_ssm_new (FP_DEVICE (dev), detect_run_state, DETECT_NUM_STATES);
  fpi_ssm_start (ssm, detect_ssm_complete);
}

static void
finger_off_timeout (FpDevice *dev, gpointer user_data G_GNUC_UNUSED)
{
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (img_dev);

  self->finger_poll_source = NULL;
  fpi_image_device_report_finger_status (img_dev, FALSE);
}

/* ================================================================
 * Device Lifecycle
 * ================================================================ */

static void
dev_init (FpImageDevice *dev)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GPtrArray) interfaces = NULL;
  GUsbInterface *iface = NULL;
  int i;

  interfaces = g_usb_device_get_interfaces (
    fpi_device_get_usb_device (FP_DEVICE (dev)), &error);
  if (error)
    {
      fpi_image_device_open_complete (dev, g_steal_pointer (&error));
      return;
    }

  /* Find our vendor-specific interface (0xFF/0xFF/0xFF) */
  for (i = 0; i < (int) interfaces->len; i++)
    {
      GUsbInterface *cur = g_ptr_array_index (interfaces, i);

      if (g_usb_interface_get_class (cur) == 0xFF &&
          g_usb_interface_get_subclass (cur) == 0xFF &&
          g_usb_interface_get_protocol (cur) == 0xFF)
        {
          iface = cur;
          break;
        }
    }

  if (!iface)
    {
      fpi_image_device_open_complete (dev,
                                      fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                "Could not find fingerprint interface"));
      return;
    }

  {
    FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

    self->iface_num = g_usb_interface_get_number (iface);

    if (!g_usb_device_claim_interface (
          fpi_device_get_usb_device (FP_DEVICE (dev)),
          self->iface_num, 0, &error))
      {
        fpi_image_device_open_complete (dev, g_steal_pointer (&error));
        return;
      }

    /* Allocate buffers */
    self->cal_raw = g_malloc0 (SECUGEN_BULK_BUF_SIZE);
    self->bulk_buffer = g_malloc0 (SECUGEN_BULK_BUF_SIZE);
    self->fw_data = g_malloc0 (SECUGEN_FW_DATA_SIZE);
    self->fw_data_len = 0;
    self->ref_image = NULL;
    self->has_ref_image = FALSE;
    self->has_blc_offsets = FALSE;
    self->cal_value = SECUGEN_BLEND_CAL_VAL;  /* Default 240, overridden by FW */
    self->sharpen_enabled = FALSE;
  }

  fpi_image_device_open_complete (dev, NULL);
}

static void
dev_deinit (FpImageDevice *dev)
{
  g_autoptr(GError) error = NULL;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  g_clear_pointer (&self->finger_poll_source, g_source_destroy);

  g_clear_pointer (&self->cal_raw, g_free);
  g_clear_pointer (&self->bulk_buffer, g_free);
  g_clear_pointer (&self->fw_data, g_free);
  g_clear_pointer (&self->ref_image, g_free);
  self->has_ref_image = FALSE;

  g_usb_device_release_interface (
    fpi_device_get_usb_device (FP_DEVICE (dev)),
    self->iface_num, 0, &error);

  fpi_image_device_close_complete (dev, g_steal_pointer (&error));
}

static void
activate_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  g_autoptr(GError) local_error = error;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  FpImageDevice *imgdev = FP_IMAGE_DEVICE (dev);

  self->ssm_count--;

  if (self->deactivating)
    {
      if (self->ssm_count == 0)
        secugen_finish_deactivate (imgdev);
      return;
    }

  if (local_error)
    fp_warn ("Activation failed: %s", local_error->message);

  fpi_image_device_activate_complete (imgdev, g_steal_pointer (&local_error));
}

static void
dev_activate (FpImageDevice *dev)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);
  FpiSsm *ssm;

  /* Reset init counters */
  self->init_reg_idx = 0;
  self->fw_read_idx = 0;
  self->exposure = SECUGEN_EXPOSURE_NORMAL;
  self->deactivating = FALSE;
  self->ssm_count++;

  ssm = fpi_ssm_new (FP_DEVICE (dev), init_run_state, INIT_NUM_STATES);
  fpi_ssm_start (ssm, activate_complete);
}

/* Turn the LED off and report deactivation complete. Called either directly
 * from dev_deactivate (nothing in flight) or, when a deactivate arrives while
 * an SSM is still running, from that SSM's completion handler once it unwinds. */
static void
secugen_finish_deactivate (FpImageDevice *dev)
{
  g_autoptr(FpiUsbTransfer) transfer = NULL;
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  self->deactivating = FALSE;

  /* Turn off LED (fire and forget) */
  transfer = fpi_usb_transfer_new (FP_DEVICE (dev));
  fpi_usb_transfer_fill_control (transfer,
                                 G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                 G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                 G_USB_DEVICE_RECIPIENT_DEVICE,
                                 SECUGEN_REQ_LED_CONTROL,
                                 0x0000, 0, 0);
  fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_CTRL_TIMEOUT, NULL,
                           secugen_noop_cb, NULL);

  fpi_image_device_deactivate_complete (dev, NULL);
}

static void
dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  /* Cancel any pending timeout */
  g_clear_pointer (&self->finger_poll_source, g_source_destroy);

  /* If an init/detect/capture SSM is still in flight, defer completion until
   * it unwinds - its completion handler calls secugen_finish_deactivate(). This
   * guarantees no bulk transfer is in flight (and no chunk callback can run
   * against a reset buffer) by the time we report deactivation complete. */
  if (self->ssm_count > 0)
    {
      self->deactivating = TRUE;
      return;
    }

  secugen_finish_deactivate (dev);
}

static void
dev_change_state (FpImageDevice      *dev,
                  FpiImageDeviceState state)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (dev);

  switch (state)
    {
    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON:
      fp_dbg ("Awaiting finger (image-based detection)");

      /* Under fpi_device_emulation (set by the umockdev test harness so
       * drivers can adapt to replay; see tests/meson.build) skip the
       * timer-driven detect poll: each poll consumes a full ~658KB frame,
       * so exercising it in replay would require recording an unbounded
       * number of extra frames in the test fixture. The recorded capture
       * starts with the finger already present, so report it directly -
       * the same approach other drivers use for replay-incompatible
       * hardware behavior (e.g. elanspi's HID reset skip). */
      if (fpi_device_emulation_mode_enabled (FP_DEVICE (self)))
        {
          fpi_image_device_report_finger_status (dev, TRUE);
          break;
        }

      /* Turn on LED */
      {
        g_autoptr(FpiUsbTransfer) transfer = fpi_usb_transfer_new (FP_DEVICE (dev));

        fpi_usb_transfer_fill_control (transfer,
                                       G_USB_DEVICE_DIRECTION_HOST_TO_DEVICE,
                                       G_USB_DEVICE_REQUEST_TYPE_VENDOR,
                                       G_USB_DEVICE_RECIPIENT_DEVICE,
                                       SECUGEN_REQ_LED_CONTROL,
                                       0x0001, 0, 0);
        fpi_usb_transfer_submit (g_steal_pointer (&transfer), SECUGEN_CTRL_TIMEOUT, NULL,
                                 secugen_noop_cb, NULL);
      }

      /* Start image-based finger detection polling */
      detect_start (dev);
      break;

    case FPI_IMAGE_DEVICE_STATE_CAPTURE:
      {
        FpiSsm *ssm;

        fp_dbg ("Starting image capture");

        /* Cancel timeout if still running */
        g_clear_pointer (&self->finger_poll_source, g_source_destroy);

        self->ssm_count++;
        ssm = fpi_ssm_new (FP_DEVICE (dev), capture_run_state,
                           CAPTURE_NUM_STATES);
        fpi_ssm_start (ssm, capture_ssm_complete);
      }
      break;

    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF:
      fp_dbg ("Waiting for finger off");
      self->finger_poll_source = fpi_device_add_timeout (FP_DEVICE (dev),
                                                         500,
                                                         finger_off_timeout,
                                                         NULL,
                                                         NULL);
      break;

    case FPI_IMAGE_DEVICE_STATE_IDLE:
    case FPI_IMAGE_DEVICE_STATE_INACTIVE:
    case FPI_IMAGE_DEVICE_STATE_ACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_DEACTIVATING:
      break;
    }
}

/* ================================================================
 * Driver Registration
 * ================================================================ */

static const FpIdEntry id_table[] = {
  { .vid = 0x1162, .pid = 0x2200, },  /* SecuGen Hamster Pro 20 (FDU05) */
  { .vid = 0,      .pid = 0,      },  /* terminator */
};

static void
fpi_device_secugen_init (FpiDeviceSecugen *self)
{
  self->init_reg_idx = 0;
  self->fw_read_idx = 0;
  self->finger_poll_source = NULL;
  self->exposure = SECUGEN_EXPOSURE_NORMAL;
  self->deactivating = FALSE;
  self->ssm_count = 0;
}

static void
fpi_device_secugen_finalize (GObject *object)
{
  FpiDeviceSecugen *self = FPI_DEVICE_SECUGEN (object);

  g_clear_pointer (&self->finger_poll_source, g_source_destroy);

  /* Safety net: free heap buffers even if img_close never ran (e.g. an
   * activation failure tore the device down before dev_deinit). */
  g_clear_pointer (&self->cal_raw, g_free);
  g_clear_pointer (&self->bulk_buffer, g_free);
  g_clear_pointer (&self->fw_data, g_free);
  g_clear_pointer (&self->ref_image, g_free);

  G_OBJECT_CLASS (fpi_device_secugen_parent_class)->finalize (object);
}

static void
fpi_device_secugen_class_init (FpiDeviceSecugenClass *klass)
{
  GObjectClass *obj_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  obj_class->finalize = fpi_device_secugen_finalize;

  dev_class->id = "secugen";
  dev_class->full_name = "SecuGen Hamster Pro 20";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  img_class->img_open = dev_init;
  img_class->img_close = dev_deinit;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;
  img_class->change_state = dev_change_state;

  img_class->score_threshold = 24;

  img_class->img_width = SECUGEN_IMG_WIDTH;
  img_class->img_height = SECUGEN_IMG_HEIGHT;
}
