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

#define CS9711_DEFAULT_WAIT_TIMEOUT 300
#define CS9711_DEFAULT_RESET_SLEEP  1500

#define CS9711_SEND_ENDPOINT    0x01
#define CS9711_RECEIVE_ENDPOINT 0x81

#define CS9711_FP_CMD_LEN_1    8
#define CS9711_FP_RECV_LEN_1   8000
#define CS9711_FP_RECV_LEN_2   24
#define CS9711_FP_RECV_LEN_MAX CS9711_FP_RECV_LEN_1

/* 2541:2549 (USB FingPintAcl16) answers the same commands but returns one
 * 8192-byte bulk frame: 112x73 grayscale pixels and 16 bytes of padding.
 * The 68x118 deinterleave used by the other ids scrambles this image.
 */
#define CS9711_ACL16_DRIVER_DATA 1
#define CS9711_ACL16_FRAME       8192
#define CS9711_ACL16_SCAN_TIMEOUT 180000
#define CS9711_ACL16_DRAIN_TIMEOUT 80

#define CS9711_FP_CMD_TYPE_INIT  1
#define CS9711_FP_CMD_TYPE_RESET 2
#define CS9711_FP_CMD_TYPE_SCAN  4

#define CS9711_FP_CMD_STATE_RESULT_EXPECTED { 0xea, 0x01, 0x62, 0xa0, 0x00, 0x00, 0xc3, 0xea }


/************************** GENERIC STUFF *************************************/

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
  fpi_usb_transfer_submit (transfer, timeout_in_ms, NULL, callback, user_data);
}

/* Same as usb_read_in, but honour the requested length. usb_read_in always
 * asks for CS9711_FP_RECV_LEN_MAX, which is wrong for the 8192-byte frame.
 */
static void
usb_read_exact (FpDevice *dev,
                FpiSsm *ssm,
                gsize length,
                guint timeout_in_ms,
                FpiUsbTransferCallback callback,
                gpointer user_data)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (FP_DEVICE (dev));

  transfer->short_is_error = FALSE;
  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, CS9711_RECEIVE_ENDPOINT, length);
  fpi_usb_transfer_submit (transfer, timeout_in_ms, NULL, callback, user_data);
}

static gboolean
is_acl16 (FpDevice *dev)
{
  return fpi_device_get_driver_data (dev) == CS9711_ACL16_DRIVER_DATA;
}

/* Read until the bulk pipe is quiet, then jump to acl16_after_drain.
 * A timeout means there is nothing left queued.
 */
static void
m_acl16_drain_cb (FpiUsbTransfer *transfer,
                  FpDevice       *dev,
                  gpointer        user_data,
                  GError         *error)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);

  (void) user_data;

  if (error)
    {
      if (error->code == G_USB_DEVICE_ERROR_TIMED_OUT && error->domain == G_USB_DEVICE_ERROR)
        {
          g_error_free (error);
          fpi_ssm_jump_to_state (transfer->ssm, self->acl16_after_drain);
          return;
        }
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  fp_dbg ("Acl16 drained %lu leftover bytes", transfer->actual_length);
  if (self->acl16_drain_budget == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, self->acl16_after_drain);
      return;
    }
  self->acl16_drain_budget--;
  usb_read_exact (dev, transfer->ssm, CS9711_ACL16_FRAME, CS9711_ACL16_DRAIN_TIMEOUT, m_acl16_drain_cb, NULL);
}

/************************** INIT SSM *************************************/

enum {
  M_INIT_STATE_DRAIN = 0,
  M_INIT_STATE_SEND_INI_QUERY,
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
      fp_err ("Read failed: %s, aborting", error->message);
      fpi_ssm_mark_failed(transfer->ssm, error);
    }
  else
    {
      fp_dbg ("Read %lu of requested %lu", transfer->length, transfer->actual_length);
      if (transfer->actual_length != CS9711_FP_CMD_LEN_1)
        {
          FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
          /* Acl16 often still has the tail of the previous image queued. */
          if (is_acl16 (dev) && self->acl16_init_retries < 2)
            {
              self->acl16_init_retries++;
              fp_warn ("Acl16 init got %lu bytes, draining and retrying", transfer->actual_length);
              fpi_ssm_jump_to_state (transfer->ssm, M_INIT_STATE_DRAIN);
            }
          else
            {
              fp_err ("Error; expected %lu bytes but got %lu, failing", (gsize)CS9711_FP_CMD_LEN_1, transfer->actual_length);
              error = g_error_new (FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO,
                                   "Init: expected %lu bytes but got %lu",
                                   (gsize)CS9711_FP_CMD_LEN_1, transfer->actual_length);
              fpi_ssm_mark_failed (transfer->ssm, error);
            }
        }
      else if (memcmp (transfer->buffer, expected, CS9711_FP_CMD_LEN_1)) {
        FPI_DEVICE_CS9711 (dev)->acl16_init_retries = 0;
        if (!user_data_is_ignore_mismatch_if_non_null) {
          fp_warn ("Error; got different state response than expected, but don't understand it anyway, continuing");
        }
        fpi_ssm_next_state(transfer->ssm);
      }
      else
        {
          FPI_DEVICE_CS9711 (dev)->acl16_init_retries = 0;
          fp_dbg ("Init response valid");
          fpi_ssm_next_state(transfer->ssm);
        }
    }
}

/* Exec init sequential state machine */
static void
m_init_state (FpiSsm *ssm, FpDevice *_dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (_dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case M_INIT_STATE_DRAIN:
      if (!is_acl16 (_dev))
        {
          fpi_ssm_next_state (ssm);
          break;
        }
      self->acl16_drain_budget = 6;
      self->acl16_after_drain = M_INIT_STATE_SEND_INI_QUERY;
      usb_read_exact (_dev, ssm, CS9711_ACL16_FRAME, CS9711_ACL16_DRAIN_TIMEOUT, m_acl16_drain_cb, NULL);
      break;

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
      fp_warn("Send operation had a timeout. Switching to reset procedure. Ignore next message about the result not matching the expected data.");
      usb_read_in (_dev, ssm, CS9711_FP_CMD_LEN_1, FALSE, CS9711_DEFAULT_WAIT_TIMEOUT, m_init_read_cb_check_expected, NULL);
      break;

    case M_INIT_STATE_RECOVER_SEND_RESET:
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_RESET, &error);
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_INIT_STATE_RECOVER_READ_IGNORED_RESET:
      fp_warn("Send operation had a timeout. Switching to reset procedure.");
      usb_read_in (_dev, ssm, CS9711_FP_CMD_LEN_1, FALSE, CS9711_DEFAULT_WAIT_TIMEOUT, m_init_read_cb_check_expected, self);
      break;

    case M_INIT_STATE_RECOVER_SEND_INIT:
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_INIT, &error); // Do not reuse state to only try reset once
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_INIT_STATE_RECEIVE_STATUS:
      usb_read_in (_dev, ssm, CS9711_FP_CMD_LEN_1, TRUE, CS9711_DEFAULT_WAIT_TIMEOUT, m_init_read_cb_check_expected, NULL);
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
  M_SCAN_ACL16_DRAIN,
  M_SCAN_SEND_POST_SCAN,
  M_SCAN_IMAGE_COMPLETE,
  M_SCAN_STATE_COUNT,
};

static const gpointer M_SCAN_READ_CB_BULK_UD_FIRST_BLOCK = (gpointer)1;
static const gpointer M_SCAN_READ_CB_BULK_UD_SECOND_BLOCK = (gpointer)2;

static void
m_scan_read_cb_acl16 (FpiUsbTransfer *transfer,
                      FpDevice       *dev,
                      gpointer        user_data,
                      GError         *error)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
  const guint8 *pixels;
  gsize n;

  (void) user_data;
  g_assert (transfer->ssm != NULL);

  if (error)
    {
      fp_err ("Read failed: %s, aborting", error->message);
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  pixels = transfer->buffer;
  n = transfer->actual_length;
  /* Echo of the scan command: ea <type> 00 00 00 00 <type> ea */
  if (n >= 8 && pixels[0] == 0xea && pixels[7] == 0xea && pixels[1] == pixels[6])
    {
      pixels += 8;
      n -= 8;
    }

  if (n < CS9711_ACL16_IMAGE)
    {
      fp_dbg ("Acl16 short frame (%lu bytes), discarding and waiting again", (unsigned long) n);
      self->acl16_after_drain = M_SCAN_INIT_READ;
      fpi_ssm_jump_to_state (transfer->ssm, M_SCAN_ACL16_DRAIN);
      return;
    }

  memcpy (self->image_buffer, pixels, CS9711_ACL16_IMAGE);
  self->acl16_after_drain = M_SCAN_SEND_POST_SCAN;
  fpi_ssm_jump_to_state (transfer->ssm, M_SCAN_ACL16_DRAIN);
}

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

static int
m_scan_submit_image (FpiSsm        *ssm,
                     FpImageDevice *dev)
{
  FpDeviceCs9711 *self = FPI_DEVICE_CS9711 (dev);
  FpImage *img;

  if (is_acl16 (FP_DEVICE (dev)))
    {
      img = fp_image_new (CS9711_ACL16_WIDTH, CS9711_ACL16_HEIGHT);
      if (img == NULL)
        return 1;
      memcpy (img->data, self->image_buffer, CS9711_ACL16_IMAGE);
    }
  else
    {
      img = fp_image_new (CS9711_WIDTH, CS9711_HEIGHT);
      if (img == NULL)
        return 1;

      for (gsize y = 0; y < CS9711_SENSOR_HEIGHT; y++)
        for (gsize x = 0; x < CS9711_SENSOR_WIDTH; x++) {
          gsize dy = y / 2;
          gsize dx = x * 2 + y % 2;
          img->data[dy * CS9711_WIDTH + dx] = self->image_buffer[y * CS9711_SENSOR_WIDTH + x];
        }
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
      if (is_acl16 (_dev))
        usb_read_exact (_dev, ssm, CS9711_ACL16_FRAME, CS9711_ACL16_SCAN_TIMEOUT, m_scan_read_cb_acl16, NULL);
      else
        usb_read_in (_dev, ssm, CS9711_FP_RECV_LEN_1, FALSE, 0, m_scan_read_cb_bulk, M_SCAN_READ_CB_BULK_UD_FIRST_BLOCK);
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_SCAN, &error);
      fpi_image_device_report_finger_status (image_device, TRUE);
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_SCAN_WAIT_FOR_READ_TO_COMPLETE:
      /* Wait for usb_read_in's callback m_scan_read_cb_bulk to advance the state */
      break;

    case M_SCAN_GET_IMAGE_TAIL:
      usb_read_in (_dev, ssm, CS9711_FP_RECV_LEN_2, TRUE, CS9711_DEFAULT_WAIT_TIMEOUT, m_scan_read_cb_bulk, M_SCAN_READ_CB_BULK_UD_SECOND_BLOCK);
      break;

    case M_SCAN_ACL16_DRAIN:
      FPI_DEVICE_CS9711 (_dev)->acl16_drain_budget = 6;
      usb_read_exact (_dev, ssm, CS9711_ACL16_FRAME, CS9711_ACL16_DRAIN_TIMEOUT, m_acl16_drain_cb, NULL);
      break;

    case M_SCAN_SEND_POST_SCAN:
      usb_send_out_sync (_dev, CS9711_FP_CMD_TYPE_RESET, &error);
      m_util_fail_if_error_or_next (ssm, error);
      break;

    case M_SCAN_IMAGE_COMPLETE:
      m_scan_submit_image (ssm, image_device);
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

  /* Claim usb interface. The Acl16 (2541:2549) puts the fingerprint
   * endpoints on interface 1; the other ids use interface 0. */
  g_usb_device_claim_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                is_acl16 (FP_DEVICE (dev)) ? 1 : 0, 0, &error);

  /* Initialize private structure */
  memset(self->image_buffer, 0, sizeof (self->image_buffer));

  /* Notify open complete */
  fpi_image_device_open_complete (dev, error);
}

static void
dev_close (FpImageDevice *dev)
{
  GError *error = NULL;

  /* Release usb interface */
  g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (dev)),
                                  is_acl16 (FP_DEVICE (dev)) ? 1 : 0, 0, &error);

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

  g_assert ((CS9711_FRAME_SIZE) == (CS9711_FP_RECV_LEN_1 + CS9711_FP_RECV_LEN_2));

  dev_class->id = "cs9711";
  dev_class->full_name = "Chipsailing CS9711Fingprint";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = 15;

  img_class->algorithm = FPI_PRINT_SIGFM;
  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;
  img_class->change_state = dev_change_state;

  //TODO: Makes very marginal improvement, stick with default in case
  //      it changes with a better implementation in the future
  // img_class->bz3_threshold = 24;

  img_class->img_width = CS9711_WIDTH;
  img_class->img_height = CS9711_HEIGHT;
}

/* Temperature settings are copied from the class during construction. Keep
 * Acl16's exception in its own class so the original readers retain their
 * default temperature model. The driver id stays the same for stored prints.
 */
typedef struct
{
  FpDeviceCs9711 parent;
} FpDeviceCs9711Acl16;

typedef FpDeviceCs9711Class FpDeviceCs9711Acl16Class;

GType fpi_device_cs9711_acl16_get_type (void);
G_DEFINE_TYPE (FpDeviceCs9711Acl16, fpi_device_cs9711_acl16, fpi_device_cs9711_get_type ())

static const FpIdEntry acl16_id_table[] = {
  { .vid = 0x2541, .pid = 0x2549, .driver_data = CS9711_ACL16_DRIVER_DATA },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

static void
fpi_device_cs9711_acl16_init (FpDeviceCs9711Acl16 *self)
{
}

static void
fpi_device_cs9711_acl16_class_init (FpDeviceCs9711Acl16Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id_table = acl16_id_table;
  /* The default 3-minute estimate aborts a 15-stage Acl16 enroll. */
  dev_class->temp_hot_seconds = -1;
  fpi_device_class_auto_initialize_features (dev_class);
}
