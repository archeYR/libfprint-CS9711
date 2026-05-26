/*
 * validity-commands.c — wire-byte framers + handshake/identify builders.
 *
 * Mirrors handoff/python/verimark_proto.py.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "validity.h"

#include <openssl/rand.h>
#include <time.h>

/* ===========================================================================
 * Wire-byte framer
 *
 * The 0088 driver's outer envelope is exactly one byte (the opcode).
 * FUN_180083670(opcode, len) allocates a buffer with buf[0] = opcode;
 * the wrapper then memcpys the payload to buf[1..].
 * ========================================================================= */

guint8 *
validity_wrap_wire_frame (guint8        opcode,
                          const guint8 *payload,
                          gsize         payload_len,
                          gsize        *out_len)
{
  guint8 *buf = g_malloc (1 + payload_len);
  buf[0] = opcode;
  if (payload_len > 0)
    memcpy (buf + 1, payload, payload_len);
  *out_len = 1 + payload_len;
  return buf;
}

/* ===========================================================================
 * Client random
 *
 * Per FUN_180076050 (ClientHello builder):
 *   bytes 0..3:  gmt_unix_time (big-endian seconds since epoch)
 *   bytes 4..31: 28 random bytes from a CSPRNG
 * ========================================================================= */

static void
make_client_random (guint8 out[32])
{
  guint32 now = (guint32) time (NULL);
  out[0] = (now >> 24) & 0xff;
  out[1] = (now >> 16) & 0xff;
  out[2] = (now >>  8) & 0xff;
  out[3] =  now        & 0xff;
  RAND_bytes (out + 4, 28);
}

/* ===========================================================================
 * ClientHello builder
 *
 * Wire format:
 *   44 00 00 00                   client direction prefix (handshake only)
 *   16 03 03 LL LL                 TLS record header (handshake / TLS 1.2 / length)
 *     01 00 00 LL                  handshake msg: ClientHello + 3-byte length
 *       03 03                      client_version
 *       <32 B client_random>
 *       <1 B session_id_len> <session_id>
 *       <2 B suites_len> <suites...>
 *       <1 B compression_len> <compression methods...>
 *       <2 B extensions_len> <extensions...>
 *
 * Cipher suites offered:
 *   0xc005 (TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA — selected by device)
 *   0x003d (TLS_RSA_WITH_AES_256_CBC_SHA256)
 *   0x008d (TLS_PSK_WITH_AES_256_CBC_SHA)
 * ========================================================================= */

guint8 *
validity_build_client_hello (ValiditySession *session, gsize *out_len)
{
  /* 1. Populate session client_random. */
  make_client_random (session->client_random);

  /* 2. ClientHello body. Four Synaptics deviations from RFC 5246 §7.4.1.2
   *    (a generic ClientHello triggers a fatal `illegal_parameter` alert
   *    from the device):
   *      (a) session_id = 7 zero bytes, NOT empty.
   *      (b) compression_methods_length = 0 with no method bytes
   *          (RFC requires ≥ 1).
   *      (c) declared extensions_length = sizeof(extensions) - 2.
   *      (d) the only "interesting" extension is type 0x0004 (truncated_hmac)
   *          carrying value 0x0017 — Synaptics overloads it to advertise
   *          P-256; standard supported_groups (0x000a) is NOT used. */
  static const guint8 extensions[] = {
    /* ext type 0x0004 (truncated_hmac), length 2, value 0x0017 — Synaptics */
    0x00, 0x04, 0x00, 0x02, 0x00, 0x17,
    /* ext type 0x000b (ec_point_formats), length 2, value 01 00 (uncompressed) */
    0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
  };
  static const guint8 session_id[] = { 0, 0, 0, 0, 0, 0, 0 };
  static const guint16 suites[] = { 0xc005, 0x003d, 0x008d };
  guint16 suites_len = sizeof (suites);  /* = 6 */
  guint16 declared_ext_len = sizeof (extensions) - 2;  /* Synaptics: -2 */

  gsize body_len =
      2                                    /* client_version */
    + 32                                   /* client_random */
    + 1 + sizeof (session_id)              /* session_id_length + session_id */
    + 2 + suites_len                       /* suites */
    + 1                                    /* comp_methods_length=0, no methods */
    + 2 + sizeof (extensions);             /* declared ext_len + (-2-undercount) data */

  /* Handshake header: type + 3-byte length */
  gsize handshake_len = 4 + body_len;

  /* Record header: type + version + 2-byte length */
  gsize record_len = 5 + handshake_len;
  gsize wire_len   = 4 + record_len;       /* with client prefix */

  guint8 *wire = g_malloc (wire_len);
  guint8 *p    = wire;

  memcpy (p, validity_client_handshake_prefix, 4);  p += 4;

  /* Record header */
  *p++ = VALIDITY_CT_HANDSHAKE;
  *p++ = (VALIDITY_TLS_VERSION >> 8) & 0xff;
  *p++ = VALIDITY_TLS_VERSION & 0xff;
  *p++ = (handshake_len >> 8) & 0xff;
  *p++ = handshake_len & 0xff;

  /* Handshake header */
  *p++ = VALIDITY_HS_CLIENT_HELLO;
  *p++ = (body_len >> 16) & 0xff;
  *p++ = (body_len >>  8) & 0xff;
  *p++ = body_len & 0xff;

  /* Body */
  *p++ = (VALIDITY_TLS_VERSION >> 8) & 0xff;
  *p++ = VALIDITY_TLS_VERSION & 0xff;
  memcpy (p, session->client_random, 32);  p += 32;
  *p++ = sizeof (session_id);
  memcpy (p, session_id, sizeof (session_id));  p += sizeof (session_id);
  *p++ = (suites_len >> 8) & 0xff;
  *p++ = suites_len & 0xff;
  for (gsize i = 0; i < G_N_ELEMENTS (suites); ++i) {
    *p++ = (suites[i] >> 8) & 0xff;
    *p++ = suites[i] & 0xff;
  }
  *p++ = 0;  /* compression_methods length = 0 (deviation b) */
  *p++ = (declared_ext_len >> 8) & 0xff;   /* deviation c: -2 */
  *p++ =  declared_ext_len & 0xff;
  memcpy (p, extensions, sizeof (extensions));  p += sizeof (extensions);

  g_assert (p == wire + wire_len);

  *out_len = wire_len;
  return wire;
}

/* ===========================================================================
 * identify/match command
 *
 * Wire format (after the leading 0x5e opcode byte):
 *   +0x00 (1 B)  flag1
 *   +0x01 (1 B)  flag2
 *   +0x02 (2 B)  field_a (LE uint16)
 *   +0x04 (2 B)  field_b
 *   +0x06 (2 B)  field_c
 *   +0x08 (4 B)  payload_length (LE uint32)
 *   +0x0c        payload (= the encrypted template push)
 *
 * Total wire frame = 1 (opcode) + 12 (header) + payload_len.
 * ========================================================================= */

guint8 *
validity_build_identify_command (guint8        flag1,
                                 guint8        flag2,
                                 guint16       field_a,
                                 guint16       field_b,
                                 guint16       field_c,
                                 const guint8 *payload,
                                 guint32       payload_len,
                                 gsize        *out_len)
{
  gsize body_len = 12 + payload_len;
  guint8 *body = g_malloc (body_len);
  guint8 *p = body;

  *p++ = flag1;
  *p++ = flag2;
  /* uint16/uint32 fields are little-endian per FUN_180080df0 */
  *p++ = field_a & 0xff;
  *p++ = (field_a >> 8) & 0xff;
  *p++ = field_b & 0xff;
  *p++ = (field_b >> 8) & 0xff;
  *p++ = field_c & 0xff;
  *p++ = (field_c >> 8) & 0xff;
  *p++ = payload_len & 0xff;
  *p++ = (payload_len >> 8) & 0xff;
  *p++ = (payload_len >> 16) & 0xff;
  *p++ = (payload_len >> 24) & 0xff;
  if (payload_len > 0)
    memcpy (p, payload, payload_len);

  guint8 *wire = validity_wrap_wire_frame (
      VALIDITY_OP_IDENTIFY_MATCH, body, body_len, out_len);
  g_free (body);
  return wire;
}

/* Build the enroll-begin command (wire byte 0x50). Per user RE doc
 * FUN_1800507f0, this is a 1-byte wire command with no payload —
 * literally just [0x50]. The device responds with a 2-byte status
 * word (read by the caller). */
guint8 *
validity_build_enroll_begin_command (gsize *out_len)
{
  return validity_wrap_wire_frame (VALIDITY_OP_ENROLL_BEGIN, NULL, 0, out_len);
}

/* Build the enroll-session-start command (wire byte 0x1A). Per
 * and the live capture-03 trace, sent BEFORE 0x50 when
 * starting an enrollment flow. 1-byte wire, like 0x50. */
guint8 *
validity_build_enroll_session_command (gsize *out_len)
{
  return validity_wrap_wire_frame (VALIDITY_OP_ENROLL_SESSION, NULL, 0, out_len);
}

guint8 *
validity_build_enroll_read_image_command (guint32 mode,
                                          gsize  *out_len)
{
  guint8 payload[4];

  payload[0] = mode & 0xff;
  payload[1] = (mode >> 8) & 0xff;
  payload[2] = (mode >> 16) & 0xff;
  payload[3] = (mode >> 24) & 0xff;

  return validity_wrap_wire_frame (VALIDITY_OP_ENROLL_READ_IMAGE,
                                   payload, sizeof (payload), out_len);
}

/* ===========================================================================
 * SPI flash commands (Phase 7 / FINISH_PAIRING.md)
 *
 * Decompiled references:
 *   FUN_18004e650 + FUN_18007f890: 0x3f partition erase
 *   FUN_18004ead0 + FUN_18007faf0: 0x41 partition write
 *   FUN_18004edd0 + FUN_18007fc70: 0x42 partition signature attach
 *
 * python-validity sanity check:
 *   erase_flash(partition)  -> pack('<BB', 0x3f, partition)
 *   write_flash(part, off)  -> pack('<BBBHLL', 0x41, part, 1, 0, off, len) + data
 *   write_fw_signature(...) -> pack('<BBxH', 0x42, part, len(sig)) + sig
 * ========================================================================= */

guint8 *
validity_build_flash_erase_command (guint8  partition_id,
                                    gsize  *out_len)
{
  guint8 payload[1] = { partition_id };

  return validity_wrap_wire_frame (VALIDITY_OP_FLASH_ERASE,
                                   payload, sizeof (payload), out_len);
}

guint8 *
validity_build_flash_write_command (guint8        partition_id,
                                    guint32       offset,
                                    const guint8 *data,
                                    gsize         len,
                                    gsize        *out_len)
{
  guint8 *buf;

  g_return_val_if_fail (data != NULL || len == 0, NULL);
  g_return_val_if_fail (len <= G_MAXUINT32, NULL);

  buf = g_malloc0 (13 + len);
  buf[0] = VALIDITY_OP_FLASH_WRITE;
  buf[1] = partition_id;
  buf[2] = 0x01;  /* python-validity uses mode/access byte 1 */
  /* buf[3..4] intentionally zero: u16 padding field */
  buf[5] = (guint8) (offset & 0xff);
  buf[6] = (guint8) ((offset >> 8) & 0xff);
  buf[7] = (guint8) ((offset >> 16) & 0xff);
  buf[8] = (guint8) ((offset >> 24) & 0xff);
  buf[9] = (guint8) (len & 0xff);
  buf[10] = (guint8) ((len >> 8) & 0xff);
  buf[11] = (guint8) ((len >> 16) & 0xff);
  buf[12] = (guint8) ((len >> 24) & 0xff);

  if (len > 0)
    memcpy (buf + 13, data, len);

  *out_len = 13 + len;
  return buf;
}

guint8 *
validity_build_flash_sign_command (guint8        partition_id,
                                   const guint8 *signature,
                                   gsize         signature_len,
                                   gsize        *out_len)
{
  guint8 *buf;

  g_return_val_if_fail (signature != NULL || signature_len == 0, NULL);
  g_return_val_if_fail (signature_len <= G_MAXUINT16, NULL);

  buf = g_malloc0 (5 + signature_len);
  buf[0] = VALIDITY_OP_FLASH_SIGN;
  buf[1] = partition_id;
  /* buf[2] intentionally zero: python-validity's '<BBxH' pad byte */
  buf[3] = (guint8) (signature_len & 0xff);
  buf[4] = (guint8) ((signature_len >> 8) & 0xff);

  if (signature_len > 0)
    memcpy (buf + 5, signature, signature_len);

  *out_len = 5 + signature_len;
  return buf;
}

/* Load a replayed encrypted-session command payload from a file path
 * supplied via the named env var. Returns NULL with `error` set if the
 * env var is unset or the file fails to satisfy the expected shape. */
static guint8 *
load_reference_command (const gchar *env_name,
                        guint8       expected_opcode,
                        gsize        expected_len,
                        gsize       *out_len,
                        GError     **error)
{
  const gchar *path = g_getenv (env_name);
  gchar *contents = NULL;
  gsize len = 0;

  if (path == NULL || path[0] == '\0')
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "set %s to the path of the captured payload "
                   "(expected len=%zu opcode=0x%02x)",
                   env_name, expected_len, expected_opcode);
      return NULL;
    }

  if (!g_file_get_contents (path, &contents, &len, error))
    return NULL;

  if (len != expected_len || (guint8) contents[0] != expected_opcode)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s has invalid shape: len=%zu opcode=0x%02x "
                   "(expected len=%zu opcode=0x%02x)",
                   path, len, (guint8) contents[0],
                   expected_len, expected_opcode);
      g_free (contents);
      return NULL;
    }

  *out_len = len;
  return (guint8 *) contents;
}

guint8 *
validity_build_enroll_hostpart_command (gsize   *out_len,
                                        GError **error)
{
  g_autoptr(GError) cache_error = NULL;
  g_autofree guint8 *blob = NULL;
  gsize blob_len = 0;

  /* 1. Explicit env-var override - for per-device experimentation or
   *    bisecting against a captured payload. */
  if (g_getenv ("VALIDITY0088_ENROLL_HOSTPART_CMD") != NULL)
    return load_reference_command (
        "VALIDITY0088_ENROLL_HOSTPART_CMD",
        VALIDITY_OP_INIT_MSG4, 10501, out_len, error);

  /* 2. Disk cache - populated by a future per-device pairing extension
   *    that records the hostpart variant the device negotiated. Absent
   *    in the common case; not-found is benign and falls through to the
   *    embedded blob. Only a present-but-corrupt cache is a hard error. */
  if (validity_pairing_has_enroll_hostpart_blob ())
    {
      blob = validity_pairing_load_enroll_hostpart_blob (&blob_len, &cache_error);
      if (blob != NULL)
        return validity_wrap_wire_frame (VALIDITY_OP_INIT_MSG4,
                                         blob, blob_len, out_len);
      g_propagate_error (error, g_steal_pointer (&cache_error));
      return NULL;
    }

  /* 3. Default - the embedded per-device-family hostpart blob (10500 B).
   *    Bytes come from validity-enroll-data.c; */
  return validity_wrap_wire_frame (VALIDITY_OP_INIT_MSG4,
                                   validity_enroll_hostpart_blob,
                                   VALIDITY_ENROLL_HOSTPART_BLOB_LEN,
                                   out_len);
}

guint8 *
validity_build_enroll_scan_setup_command (gsize   *out_len,
                                          GError **error)
{
  (void) error;

  return validity_build_led_glow_command (0x00, 0x00, 0xff,
                                          LED_VARIANT_BLUE, 0, out_len);
}

guint8 *
validity_build_enroll_capture_command (FpDevice            *dev,
                                       ValidityCaptureMode  mode,
                                       gsize               *out_len,
                                       GError             **error)
{
  ValiditySession *session = dev != NULL ? validity_device_get_session (dev) : NULL;

  if (g_getenv ("VALIDITY0088_ENROLL_CAPTURE_CMD") != NULL)
    return load_reference_command (
        "VALIDITY0088_ENROLL_CAPTURE_CMD",
        VALIDITY_OP_CAPTURE_PROGRAM, 18869, out_len, error);

  return validity_capture_build (session != NULL ? &session->rom_info : NULL,
                                 mode, out_len, error);
}

/* ===========================================================================
 * LED glow command (wire byte 0x39 = internal opcode 0x33).
 *
 * Same wire opcode as the cached "enroll-scan-setup" payload — that payload
 * is actually a blue-pulse LED command (the device shows its blue glow on
 * every receive of `OUT_024_app.bin`).
 *
 * Wire format (per user RE notes on FUN_18007d270 + FUN_180082860,
 * refined by live tests):
 *   byte 0     : 0x39 (opcode)
 *   bytes 1..4 : u32 LE mode/header
 *   bytes 5..124 : 6 × 20-byte slots (stride 20 = 0x14)
 *
 * Per-slot offsets (absolute, for slot 0; add `slot_idx * 20` for others):
 *   +5..+6  : u16 LE timing (on-time / dwell)
 *   +7..+8  : u16 LE ? (often used by python-validity's blue payload)
 *   +9      : R (0-255)
 *   +10     : G
 *   +11     : B
 *   +12     : ?
 *   +13..+18: 3 × [byte,byte] sub-fields
 *   +19..+24: padding/unknown (slot stride is 20)
 *
 * Reference (OUT_024_app.bin / python-validity glow_start_scan):
 *   3920bf0200 ffff000001bf0020...
 *
 * That known-good variant is selected with mode=LED_VARIANT_BLUE. The simple
 * R/G/B-at-slot-0 path remains available for experiments, but live testing
 * showed real red/success color selection is controlled by specific mode
 * values and device state, so the driver replays decrypted raw payloads for
 * post-verify feedback.
 * ------------------------------------------------------------------------- */

#define LED_SLOT_SIZE          20U
#define LED_NUM_SLOTS          6U
#define LED_PAYLOAD_LEN        (1 + 4 + LED_NUM_SLOTS * LED_SLOT_SIZE)  /* = 125 */
/* LED_MODE_STEADY / LED_MODE_SOLID / LED_MODE_REPEAT are defined in validity.h */

static const guint8 led_blue_scan_setup_template[LED_PAYLOAD_LEN] = {
  0x39, 0x20, 0xbf, 0x02, 0x00, 0xff, 0xff, 0x00,
  0x00, 0x01, 0xbf, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0xbf, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00,
  0x00, 0x00, 0xbf, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00
};

/* Build a 125-byte LED glow payload (opcode 0x39).
 *
 * LED_VARIANT_BLUE is the ready-for-tap scan setup command (matches
 * python-validity glow_start_scan). Other modes use the simple
 * single-active-slot builder useful for experiments; the live
 * red/success indicators in validity.c use raw payloads instead because
 * color is controlled by mode-specific firmware state.
 */
guint8 *
validity_build_led_glow_command (guint8  r,
                                 guint8  g,
                                 guint8  b,
                                 guint32 mode,
                                 guint16 timing_ms,
                                 gsize  *out_len)
{
  if (mode == LED_VARIANT_BLUE)
    {
      *out_len = LED_PAYLOAD_LEN;
      return g_memdup2 (led_blue_scan_setup_template,
                        sizeof (led_blue_scan_setup_template));
    }

  /* Minimal hand-built payload per the user's latest RE notes
   * (FUN_18007d270 struct builder, byte mapping clarified):
   *
   *   buf[0]      = 0x39 (opcode)
   *   buf[1..4]   = u32 LE mode (0=off, 1=solid, 2=flash)
   *   buf[5..6]   = slot 0 timing u16 LE (on-time in ms-ish)
   *   buf[7..8]   = slot 0 secondary timing u16 LE
   *   buf[9]      = slot 0 type (0=off, 1=active, 2=flash)
   *   buf[10]     = slot 0 R
   *   buf[11]     = slot 0 G
   *   buf[12]     = slot 0 B
   *   buf[13..24] = slot 0 padding/sub-fields (zeroed)
   *   buf[25..]   = slots 1..5 (zeroed)
   *
   * This is the "send exactly what the struct builder would produce
   * for the simplest single-active-slot solid color" payload. It is kept
   * for controlled experiments; no production path depends on it producing
   * a visible non-blue color.
   */
  guint8 *buf = g_malloc0 (LED_PAYLOAD_LEN);
  buf[0] = VALIDITY_OP_ENROLL_SCAN_SETUP;       /* 0x39 */

  /* mode u32 LE at +1..+4 */
  buf[1] = (guint8) (mode & 0xff);
  buf[2] = (guint8) ((mode >> 8) & 0xff);
  buf[3] = (guint8) ((mode >> 16) & 0xff);
  buf[4] = (guint8) ((mode >> 24) & 0xff);

  /* slot 0 */
  buf[5]  = (guint8) (timing_ms & 0xff);
  buf[6]  = (guint8) ((timing_ms >> 8) & 0xff);
  /* buf[7..8] secondary timing — leave zero for solid color */
  buf[9]  = 0x01;   /* type = active */
  buf[10] = r;
  buf[11] = g;
  buf[12] = b;

  *out_len = LED_PAYLOAD_LEN;
  return buf;
}

/* Raw-payload override: parse a hex string into a 125-byte payload.
 * Used by VALIDITY0088_LED_RAW_PAYLOAD env var for live experimentation.
 * Returns NULL if the hex is malformed or doesn't decode to exactly 125 bytes.
 */
guint8 *
validity_parse_led_raw_payload (const gchar *hex_str,
                                gsize       *out_len)
{
  gsize hex_len = strlen (hex_str);
  if (hex_len != LED_PAYLOAD_LEN * 2)
    return NULL;

  guint8 *buf = g_malloc (LED_PAYLOAD_LEN);
  for (gsize i = 0; i < LED_PAYLOAD_LEN; i++)
    {
      gint hi = g_ascii_xdigit_value (hex_str[i * 2]);
      gint lo = g_ascii_xdigit_value (hex_str[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        {
          g_free (buf);
          return NULL;
        }
      buf[i] = (guint8) ((hi << 4) | lo);
    }

  *out_len = LED_PAYLOAD_LEN;
  return buf;
}
