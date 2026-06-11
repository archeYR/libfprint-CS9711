/*
 * Chipsailing CS9711Fingprint driver
 *
 * Modified based on driver vfs301* so keeping original notice:
 *
 * Copyright (c) 2011-2012 Andrej Krutak <dev@andree.sk>
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

#define FP_COMPONENT "cs9711"

#include "drivers_api.h"
#include "cs9711.h"

G_DEFINE_TYPE (FpDeviceCs9711, fpi_device_cs9711, FP_TYPE_IMAGE_DEVICE)

#define CS9711_SENSOR_WIDTH 34
#define CS9711_SENSOR_HEIGHT 236

#define CS9711_DEFAULT_WAIT_TIMEOUT 500
#define CS9711_DEFAULT_RESET_SLEEP  250

#define CS9711_SEND_ENDPOINT    0x01
#define CS9711_RECEIVE_ENDPOINT 0x81

#define CS9711_FP_CMD_LEN_1    8
/* 
 * Image data size: 8024 bytes total
 * With cmd 0x04: arrives as 8000 + 24 bytes
 * With cmd 0x03: arrives as 8024 bytes in one transfer
 */
#define CS9711_FP_RECV_LEN_1   8024
#define CS9711_FP_RECV_LEN_2   0
/* Safety buffer size - prevents overflow if device returns unexpected data */
#define CS9711_FP_RECV_LEN_MAX 65536

/*
 * Command codes (from HARDWARE_SPECS.md USB traffic capture):
 * 0x01 = READ_CHIP_ID - read chip identification
 * 0x02 = SLEEP_WAKE   - power state control
 * 0x03 = CAPTURE      - start capture (alternative)
 * 0x04 = CAPTURE_ALT  - start capture (Windows driver uses this)
 * 0x07 = RESET        - device reset
 */
#define CS9711_CMD_READ_CHIP_ID  0x01
#define CS9711_CMD_SLEEP_WAKE    0x02
#define CS9711_CMD_CAPTURE       0x04  /* Windows driver uses 0x04 for capture */
#define CS9711_CMD_RESET         0x07

/* Legacy aliases for compatibility */
#define CS9711_FP_CMD_TYPE_INIT  CS9711_CMD_READ_CHIP_ID
#define CS9711_FP_CMD_TYPE_SLEEP CS9711_CMD_SLEEP_WAKE
#define CS9711_FP_CMD_TYPE_SCAN  CS9711_CMD_CAPTURE
#define CS9711_FP_CMD_TYPE_RESET CS9711_CMD_RESET

#define CS9711_FP_CMD_STATE_RESULT_EXPECTED { 0xea, 0x01, 0x62, 0xa0, 0x00, 0x00, 0xc3, 0xea }


/************************** GENERIC STUFF *************************************/
#define CS9711_HANDLE_USB_DISCONNECT 1 // Enable USB disconnect handling by default
/*
 * KVM/USB disconnect handling - disabled by default.
 * Enable with -DCS9711_HANDLE_USB_DISCONNECT to detect USB disconnects
 * (e.g., from KVM switches) and mark the device as removed.
 */
#ifdef CS9711_HANDLE_USB_DISCONNECT

static gboolean
is_disconnect_error (GError *error)
{
  if (!error)
    return FALSE;

  if (error->domain == G_USB_DEVICE_ERROR)
    {
      if (error->code == G_USB_DEVICE_ERROR_IO)
        return TRUE;
      if (error->code == G_USB_DEVICE_ERROR_NO_DEVICE)
        return TRUE;
    }

  if (error->domain == G_IO_ERROR)
    {
      if (error->code == G_IO_ERROR_HOST_UNREACHABLE ||
          error->code == G_IO_ERROR_CONNECTION_CLOSED)
        return TRUE;
    }

  if (error->message)
    {
      if (g_strstr_len (error->message, -1, "disconnected") ||
          g_strstr_len (error->message, -1, "no device") ||
          g_strstr_len (error->message, -1, "No such device") ||
          g_strstr_len (error->message, -1, "transfer failed"))
        return TRUE;
    }

  return FALSE;
}

static gboolean
handle_disconnect_error (FpDevice *dev, FpiSsm *ssm, GError *error)
{
  gboolean is_removed = FALSE;

  if (!is_disconnect_error (error))
    return FALSE;

  fp_warn ("Device appears to be disconnected: %s", error->message);

  g_object_get (dev, "removed", &is_removed, NULL);
  if (!is_removed)
    fpi_device_remove (dev);

  g_clear_error (&error);
  GError *removed_error = fpi_device_error_new (FP_DEVICE_ERROR_REMOVED);
  fpi_ssm_mark_failed (ssm, removed_error);

  return TRUE;
}

#endif /* CS9711_HANDLE_USB_DISCONNECT */

/** If error isn't NULL then fail the ssm or move it to the next state */
static void
m_util_fail_if_error_or_next (FpiSsm *ssm, GError *error)
{
  if (error)
    fpi_ssm_mark_failed (ssm, error);
  else
    fpi_ssm_next_state (ssm);
}

/** Synchroneous USB bulk write OUT helper*/
static void
usb_send_out_sync (FpDevice *dev, guint8 type, GError **error)
{
  GError *err = NULL;

  guint8 *data = g_malloc0(CS9711_FP_CMD_LEN_1);

  data[0] = data[CS9711_FP_CMD_LEN_1 - 1] = 0xEA;
  data[1] = data[CS9711_FP_CMD_LEN_1 - 2] = type;

  g_autoptr(FpiUsbTransfer) transfer = NULL;

  transfer = fpi_usb_transfer_new (FP_DEVICE (dev));
  transfer->short_is_error = FALSE;
  fpi_usb_transfer_fill_bulk_full (transfer, CS9711_SEND_ENDPOINT, (guint8 *) data, CS9711_FP_CMD_LEN_1, g_free);
  fpi_usb_transfer_submit_sync (transfer, CS9711_DEFAULT_WAIT_TIMEOUT, &err);
  if (err)
    {
      g_warning ("Error while sending command 0x%X, continuing anyway: %s", type, err->message);
      g_propagate_error (error, err);
    }
  else
    fp_dbg("Sent command 0x%X", type);
}

/** Asynchroneous USB bulk write IN helper */
static void
usb_read_in (FpDevice *dev,
             FpiSsm *ssm,
             gsize length,
             gboolean short_is_error,
             guint timeout_in_ms,
             FpiUsbTransferCallback callback,
             gpointer user_data)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
  FpiUsbTransfer *transfer = NULL;

  fp_dbg("Reading %lu bytes", length);
  // If the response is larger than the buffer, then the usb helpers
  // error before. The reader doesn't seem to care about requestend
  // length, and occasionally answers out of sequence with an invalid
  // data size. So just request the max expected, and deal with errors
  // in the callback. For the same reason, cannot use short_is_error
  // facility
  length = CS9711_FP_RECV_LEN_MAX;
  short_is_error = FALSE;
  transfer = fpi_usb_transfer_new (FP_DEVICE (dev));
  transfer->short_is_error = short_is_error;
  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, CS9711_RECEIVE_ENDPOINT, length);
  fpi_usb_transfer_submit (transfer, timeout_in_ms,
                           self->interrupt_cancellable,
                           callback, user_data);
}

/************************** INIT SSM *************************************/

/* Forward declaration of init states for use in callbacks */
enum {
  M_INIT_STATE_SEND_INI_QUERY = 0,
  M_INIT_STATE_RECOVER_READ_IGNORED,
  M_INIT_STATE_RECOVER_SEND_RESET,
  M_INIT_STATE_RECOVER_READ_IGNORED_RESET,
  M_INIT_STATE_RECOVER_SEND_INIT,
  M_INIT_STATE_RECEIVE_STATUS,
  M_INIT_STATE_COUNT,
};

static void
m_init_read_cb_check_expected (FpiUsbTransfer *transfer,
                               FpDevice       *dev,
                               gpointer        user_data_is_ignore_mismatch_if_non_null,
                               GError         *error)
{
  const guint8 expected[] = CS9711_FP_CMD_STATE_RESULT_EXPECTED;

  g_assert(CS9711_FP_CMD_LEN_1 == sizeof(expected));
  g_assert(transfer->ssm != NULL);

  if (error)
    {
#ifdef CS9711_HANDLE_USB_DISCONNECT
      if (handle_disconnect_error (dev, transfer->ssm, error))
        return;
#endif
      fp_err ("Read failed: %s, aborting", error->message);
      fpi_ssm_mark_failed(transfer->ssm, error);
    }
  else
    {
      fp_dbg ("Read %lu of requested %lu", transfer->length, transfer->actual_length);
      if (transfer->actual_length != CS9711_FP_CMD_LEN_1)
        {
          /* Got unexpected data size - likely stale data from previous session.
           * Don't fail - just warn and complete init. The device is present
           * and captures may still work fine. */
          fp_warn ("Got %lu bytes instead of expected %lu - completing init anyway",
                   transfer->actual_length, (gsize)CS9711_FP_CMD_LEN_1);
          fpi_ssm_mark_completed (transfer->ssm);
        }
      else if (memcmp (transfer->buffer, expected, CS9711_FP_CMD_LEN_1)) {
        fp_info ("Detected ChipID: 0x%04X (expected 0x62A0)", (guint16)((transfer->buffer[2] << 8) | transfer->buffer[3]));
        if (!user_data_is_ignore_mismatch_if_non_null) {
          fp_warn ("Error; got different state response than expected, but don't understand it anyway, continuing");
        }
        fpi_ssm_next_state(transfer->ssm);
      }
      else
        {
          fp_dbg ("Init response valid");
          fpi_ssm_next_state(transfer->ssm);
        }
    }
}

/* Callback to drain stale USB data - we don't care about errors or content */
static void
m_init_drain_stale_cb (FpiUsbTransfer *transfer,
                       FpDevice       *dev,
                       gpointer        user_data,
                       GError         *error)
{
  g_assert (transfer->ssm != NULL);

  if (error)
    {
      /* Timeout is expected if no stale data - that's fine */
      fp_dbg ("Drain read: %s (continuing anyway)", error->message);
      g_clear_error (&error);
    }
  else if (transfer->actual_length > 0)
    {
      fp_info ("Drained %lu bytes of stale data", transfer->actual_length);
    }

  fpi_ssm_next_state (transfer->ssm);
}

/* Exec init sequential state machine */
static void
m_init_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (_dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case M_INIT_STATE_SEND_INI_QUERY:
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_INIT, &error);
      if (error)
        {
          fp_dbg("Error details: '%s', quark: %u code: %d", error->message, error->domain, error->code);
          // if (g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT))
          if (error->code == G_USB_DEVICE_ERROR_TIMED_OUT && error->domain == G_USB_DEVICE_ERROR)
            fpi_ssm_next_state (ssm);
          else
            fpi_ssm_mark_failed (ssm, error);
        }
      else
        fpi_ssm_jump_to_state (ssm, M_INIT_STATE_RECEIVE_STATUS);
      break;

    case M_INIT_STATE_RECOVER_READ_IGNORED:
      /* Drain any stale data - use max buffer size and a short timeout.
       * We don't care about the result, just need to clear the USB buffer. */
      fp_warn("Draining stale USB data before reset...");
      usb_read_in (_dev, ssm, CS9711_FP_RECV_LEN_MAX, FALSE, 100, m_init_drain_stale_cb, NULL);
      break;

    case M_INIT_STATE_RECOVER_SEND_RESET:
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_RESET, &error);
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_INIT_STATE_RECOVER_READ_IGNORED_RESET:
      fp_warn("Draining any response after reset...");
      usb_read_in (_dev, ssm, CS9711_FP_RECV_LEN_MAX, FALSE, 500, m_init_drain_stale_cb, NULL);
      break;

    case M_INIT_STATE_RECOVER_SEND_INIT:
      fp_info("Recovery: sending init command...");
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_INIT, &error);
      if (error)
        {
          /* If init send fails during recovery, just complete anyway -
           * the device is present and may work for captures */
          fp_warn ("Recovery init send failed: %s - completing init anyway", error->message);
          g_clear_error (&error);
          fpi_ssm_mark_completed (ssm);
        }
      else
        fpi_ssm_next_state (ssm);
      break;

    case M_INIT_STATE_RECEIVE_STATUS:
      fp_info("Reading init status response...");
      usb_read_in (_dev, ssm, CS9711_FP_CMD_LEN_1, FALSE, CS9711_DEFAULT_WAIT_TIMEOUT, m_init_read_cb_check_expected, NULL);
      break;

    default:
      g_assert_not_reached ();
    }
  // cs9711_proto_init (self);

  // fpi_ssm_mark_completed (ssm);
}

/* Complete init sequential state machine */
static void
m_init_complete (FpiSsm *ssm, FpDevice *dev, GError *error) //TODO: done
{
  fpi_image_device_activate_complete (FP_IMAGE_DEVICE (dev), error);
}

/************************** SCAN SSM *************************************/

enum {
  M_SCAN_INIT_SLEEP = 0,
  M_SCAN_INIT_READ,
  M_SCAN_WAIT_FOR_READ_TO_COMPLETE,
  M_SCAN_GET_IMAGE_TAIL,
  M_SCAN_SEND_POST_SCAN,
  M_SCAN_IMAGE_COMPLETE,
  M_SCAN_STATE_COUNT,
};

static const gpointer M_SCAN_READ_CB_BULK_UD_FIRST_BLOCK = (gpointer)1;
static const gpointer M_SCAN_READ_CB_BULK_UD_SECOND_BLOCK = (gpointer)2;

/* Read into FpDeviceCs9711->image_buffer if one of the two expected chunk sizes */
static void
m_scan_read_cb_bulk (FpiUsbTransfer *transfer,
                     FpDevice       *dev,
                     gpointer        user_data,
                     GError         *error)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);

  g_assert (transfer->ssm != NULL);

  gsize expected_size = 0;
  gpointer offset = NULL;

  g_assert (FALSE
    || user_data == M_SCAN_READ_CB_BULK_UD_FIRST_BLOCK
    || user_data == M_SCAN_READ_CB_BULK_UD_SECOND_BLOCK
  );

  if (user_data == M_SCAN_READ_CB_BULK_UD_FIRST_BLOCK)
    {
      expected_size = CS9711_FP_RECV_LEN_1;
      offset = self->image_buffer;
    }
  else if (user_data == M_SCAN_READ_CB_BULK_UD_SECOND_BLOCK)
    {
      expected_size = CS9711_FP_RECV_LEN_2;
      offset = self->image_buffer + CS9711_FP_RECV_LEN_1;
    }
  else
    g_assert_not_reached ();

  if (error)
    {
#ifdef CS9711_HANDLE_USB_DISCONNECT
      if (handle_disconnect_error (dev, transfer->ssm, error))
        return;
#endif
      fp_err ("Read failed: %s, aborting", error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
    }
  else
    {
      if (transfer->actual_length != expected_size)
        {
          fp_dbg("\tSkipping buffer print - got %lu bytes, expected %lu", transfer->actual_length, expected_size);
          error = g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID, "expected %lu bytes but got %lu, can't continue", expected_size, transfer->actual_length);
          fpi_ssm_mark_failed (transfer->ssm, error);
        }
      else {
        memcpy (offset, transfer->buffer, expected_size);
        fpi_ssm_next_state (transfer->ssm);
      }
    }
}

/*
 * Per-frame image normalization.
 *
 * The Windows driver preprocesses every frame before matching
 * (EngineAdapter `_AdapterPreprocessImageData`, CSAlgDll
 * `ChipSailing_AutoGain` / `ChipSailing_Enhance16to8`). The raw frames
 * from this capacitive sensor sit on a baseline that drifts with
 * temperature, humidity and skin-oil residue, so feeding them straight
 * into SIGFM/SIFT makes match scores decay as conditions drift away
 * from those at enrollment time.
 *
 * We approximate that preprocessing in two steps:
 *  1. Background flattening: subtract a local box mean (integral image),
 *     removing the slowly-varying baseline while keeping ridge detail.
 *     At 500 DPI the ridge period is ~9 px; a 17x17 window is well above
 *     that, so ridges survive.
 *  2. Robust contrast stretch: map the 2nd..98th percentile of the
 *     flattened values to 0..255 so gain drift doesn't change the
 *     image statistics SIFT sees.
 *
 * Returns FALSE if the flattened frame has so little contrast that it
 * cannot contain a fingerprint (blank/baseline frame, ~stddev 2 vs ~35
 * for a real finger), in which case the caller should ask for a retry
 * instead of submitting garbage to the matcher.
 */
#define CS9711_NORM_RADIUS 8
#define CS9711_MIN_CONTRAST_VARIANCE 64 /* stddev 8, between blank ~2 and finger ~35 */

static gboolean
m_scan_normalize_image (guint8 *data, gint width, gint height)
{
  gint n = width * height;
  gint iw = width + 1;
  g_autofree guint32 *integral = g_new (guint32, iw * (height + 1));
  g_autofree gint16 *flat = g_new (gint16, n);
  guint hist[511] = { 0 };
  gint64 sum = 0, sum_sq = 0;

  /* Integral image */
  memset (integral, 0, iw * sizeof (guint32));
  for (gint y = 1; y <= height; y++)
    {
      guint32 row = 0;
      integral[y * iw] = 0;
      for (gint x = 1; x <= width; x++)
        {
          row += data[(y - 1) * width + (x - 1)];
          integral[y * iw + x] = integral[(y - 1) * iw + x] + row;
        }
    }

  /* Flatten: subtract local box mean */
  for (gint y = 0; y < height; y++)
    {
      gint y0 = MAX (y - CS9711_NORM_RADIUS, 0);
      gint y1 = MIN (y + CS9711_NORM_RADIUS + 1, height);
      for (gint x = 0; x < width; x++)
        {
          gint x0 = MAX (x - CS9711_NORM_RADIUS, 0);
          gint x1 = MIN (x + CS9711_NORM_RADIUS + 1, width);
          guint32 box = integral[y1 * iw + x1] - integral[y0 * iw + x1] -
                        integral[y1 * iw + x0] + integral[y0 * iw + x0];
          gint mean = box / ((y1 - y0) * (x1 - x0));
          gint v = data[y * width + x] - mean;

          flat[y * width + x] = v;
          hist[v + 255]++;
          sum += v;
          sum_sq += (gint64) v * v;
        }
    }

  /* Blank-frame gate (Windows: ChipSailing_IsBlankImage) */
  gint64 variance = (sum_sq - sum * sum / n) / n;
  if (variance < CS9711_MIN_CONTRAST_VARIANCE)
    {
      fp_dbg ("Frame variance %" G_GINT64_FORMAT " below threshold %d - blank frame",
              variance, CS9711_MIN_CONTRAST_VARIANCE);
      return FALSE;
    }

  /* Robust contrast stretch on 2nd..98th percentiles */
  gint lo = -255, hi = 255;
  guint acc = 0, lo_count = n * 2 / 100, hi_count = n * 98 / 100;
  for (gint i = 0; i < 511; i++)
    {
      acc += hist[i];
      if (acc <= lo_count)
        lo = i - 255;
      if (acc < hi_count)
        hi = i - 254;
    }
  if (hi <= lo)
    return FALSE;

  for (gint i = 0; i < n; i++)
    {
      gint v = (flat[i] - lo) * 255 / (hi - lo);
      data[i] = CLAMP (v, 0, 255);
    }

  return TRUE;
}

static int
m_scan_submit_image (FpiSsm        *ssm,
                     FpImageDevice *dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
  FpImage *img;

  img = fp_image_new (CS9711_WIDTH, CS9711_HEIGHT);
  if (img == NULL)
    return 1;

  for (gsize y = 0; y < CS9711_SENSOR_HEIGHT; y++)
    for (gsize x = 0; x < CS9711_SENSOR_WIDTH; x++) {
      gsize dy = y / 2;
      gsize dx = x * 2 + y % 2;
      img->data[dy * CS9711_WIDTH + dx] = self->image_buffer[y * CS9711_SENSOR_WIDTH + x];
    }

  if (!m_scan_normalize_image (img->data, CS9711_WIDTH, CS9711_HEIGHT))
    {
      g_object_unref (img);
      return 1;
    }

  img->flags = FPI_IMAGE_PARTIAL;

  fpi_image_device_image_captured (dev, img);

  return 0;
}

/* Exec scan sequential state machine */
static void
m_scan_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpImageDevice *image_device = FP_IMAGE_DEVICE (_dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case M_SCAN_INIT_SLEEP:
      fpi_ssm_next_state_delayed (ssm, CS9711_DEFAULT_RESET_SLEEP);
      break;

    case M_SCAN_INIT_READ:
      usb_read_in (_dev, ssm, CS9711_FP_RECV_LEN_1, FALSE, 0, m_scan_read_cb_bulk, M_SCAN_READ_CB_BULK_UD_FIRST_BLOCK);
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_SCAN, &error);
      fpi_image_device_report_finger_status (image_device, TRUE);
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_SCAN_WAIT_FOR_READ_TO_COMPLETE:
      /* Wait for usb_read_in's callback m_scan_read_cb_bulk to advance the state */
      break;

    case M_SCAN_GET_IMAGE_TAIL:
      /* All data arrives in first transfer with cmd 0x04 */
      fpi_ssm_next_state (ssm);
      break;

    case M_SCAN_SEND_POST_SCAN:
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_SLEEP, &error);
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_SCAN_IMAGE_COMPLETE:
      if (m_scan_submit_image (ssm, image_device))
        {
          /* Blank or low-contrast frame - ask the user to retry rather
           * than letting the matcher fail on a garbage image. */
          fp_warn ("Discarding low-quality frame, requesting retry");
          fpi_image_device_retry_scan (image_device, FP_DEVICE_RETRY_CENTER_FINGER);
        }
      fpi_image_device_report_finger_status (image_device, FALSE);
      fpi_ssm_mark_completed (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

/************************** ImageDevice impl. *************************************/

/* Activate device */
static void
dev_activate (FpImageDevice *dev)
{
  FpiSsm *ssm;

  /* Start init ssm */
  ssm = fpi_ssm_new (FP_DEVICE (dev), m_init_state, M_INIT_STATE_COUNT);
  fpi_ssm_start (ssm, m_init_complete);
}

/* Deactivate device */
static void
dev_deactivate (FpImageDevice *dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);

  /* Cancel any in-flight read (e.g. a capture read still waiting for a
   * finger). Leaving it pending would let it swallow the next session's
   * init response, which is what the "drain stale data" recovery used to
   * fight after the fact. */
  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);
  self->interrupt_cancellable = g_cancellable_new ();

  fpi_image_device_deactivate_complete (dev, NULL);
}

static void
dev_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
  FpiSsm *ssm_loop;

  if (state != FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON)
    return;

  /* Start a capture operation. */
  ssm_loop = fpi_ssm_new (FP_DEVICE (dev), m_scan_state, M_SCAN_STATE_COUNT);
  fpi_ssm_start (ssm_loop, NULL);
}

static void
dev_open (FpImageDevice *dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
  GError *error = NULL;

  /* Claim usb interface */
  g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)), 0, 0, &error);

  /* Initialize private structure */
  memset(self->image_buffer, 0, CS9711_FRAME_SIZE);
  self->interrupt_cancellable = g_cancellable_new ();

  /* Notify open complete */
  fpi_image_device_open_complete (dev, error);
}

static void
dev_close (FpImageDevice *dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
  GError *error = NULL;

  g_cancellable_cancel (self->interrupt_cancellable);
  g_clear_object (&self->interrupt_cancellable);

  /* Release usb interface */
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                  0, 0, &error);

  /* Notify close complete */
  fpi_image_device_close_complete (dev, error);
}

/* Usb id table of device */
static const FpIdEntry id_table[] = {
  { .vid = 0x2541,  .pid = 0x0236, },
  { .vid = 0x2541,  .pid = 0x9711, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_cs9711_init (FpDeviceCs9711 *self)
{
}

static void
fpi_device_cs9711_class_init (FpDeviceCs9711Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  g_assert ((CS9711_FRAME_SIZE) == CS9711_FP_RECV_LEN_1);

  dev_class->id = "cs9711";
  dev_class->full_name = "Chipsailing CS9711Fingprint";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 15;

  /* Disable software thermal throttling - this is a simple capacitive sensor
   * without thermal concerns, and the default 3-minute limit causes spurious
   * "Device disabled to prevent overheating" errors */
  dev_class->temp_hot_seconds = -1;

  img_class->algorithm = FPI_PRINT_SIGFM;
  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;
  img_class->change_state = dev_change_state;

  /* The default threshold (40) is BOZORTH3_DEFAULT_THRESHOLD, tuned for
   * NBIS minutiae matching - not for SIGFM scores. Use the same value as
   * elan, the other SIGFM driver in tree. SIGFM scores collapse
   * quadratically as keypoint overlap shrinks, so an overly high
   * threshold causes false rejections on this small (68x118) sensor. */
  img_class->score_threshold = 24;

  img_class->img_width = CS9711_WIDTH;
  img_class->img_height = CS9711_HEIGHT;
}
