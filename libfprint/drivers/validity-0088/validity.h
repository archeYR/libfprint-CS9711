/*
 * validity.h — Kensington VeriMark (06CB:0088) libfprint driver.
 * Modified TLS-1.2 over USB bulk transfers.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"

G_DECLARE_FINAL_TYPE (FpiDeviceValidity0088, fpi_device_validity_0088, FPI, DEVICE_VALIDITY_0088, FpDevice)

/* ===========================================================================
 * USB transport
 * ========================================================================= */

/* USB endpoints (from device descriptor) */
#define VALIDITY_EP_CMD_OUT       (0x01 | FPI_USB_ENDPOINT_OUT)
#define VALIDITY_EP_CMD_IN        (0x81 | FPI_USB_ENDPOINT_IN)
#define VALIDITY_EP_BULK_IN_ALT   (0x82 | FPI_USB_ENDPOINT_IN)
#define VALIDITY_EP_INT_IN        (0x83 | FPI_USB_ENDPOINT_IN)
#define VALIDITY_EP_INT_IN_ALT    (0x84 | FPI_USB_ENDPOINT_IN)

#define VALIDITY_USB_SEND_TIMEOUT       5000
#define VALIDITY_USB_RECV_TIMEOUT       5000
#define VALIDITY_USB_INTERRUPT_TIMEOUT 60000

#define VALIDITY_MAX_RECV_LEN          24576  /* > 18960 to fit per-attempt records */
#define VALIDITY_MAX_ENROLL_STAGES        10

/* ===========================================================================
 * Protocol constants
 * ========================================================================= */

#define VALIDITY_TLS_VERSION    0x0303u   /* TLS 1.2 */

/* Cipher suite offered + selected by the device */
#define VALIDITY_CIPHER_SUITE   0xC005u   /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */

/* Modified-TLS-1.2 parameters: SHA-256 MAC (32 B) instead of SHA-1 (20 B) */
#define VALIDITY_MAC_KEY_LEN        32
#define VALIDITY_ENC_KEY_LEN        32    /* AES-256 */
#define VALIDITY_FIXED_IV_LEN        0    /* CBC explicit IV */
#define VALIDITY_MAC_OUTPUT_LEN     32    /* HMAC-SHA-256 */
#define VALIDITY_AES_BLOCK_SIZE     16
#define VALIDITY_MASTER_SECRET_LEN  48
#define VALIDITY_KEY_BLOCK_LEN     128    /* = 2*MAC + 2*ENC */
#define VALIDITY_VERIFY_DATA_LEN    12
#define VALIDITY_HANDSHAKE_HASH_LEN 32    /* SHA-256(handshake_messages) */

/* TLS content types */
#define VALIDITY_CT_CHANGE_CIPHER_SPEC  0x14
#define VALIDITY_CT_ALERT               0x15
#define VALIDITY_CT_HANDSHAKE           0x16
#define VALIDITY_CT_APPLICATION_DATA    0x17

/* TLS handshake types */
#define VALIDITY_HS_CLIENT_HELLO          0x01
#define VALIDITY_HS_SERVER_HELLO          0x02
#define VALIDITY_HS_CERTIFICATE           0x0B
#define VALIDITY_HS_CERTIFICATE_REQUEST   0x0D
#define VALIDITY_HS_SERVER_HELLO_DONE     0x0E
#define VALIDITY_HS_CERTIFICATE_VERIFY    0x0F
#define VALIDITY_HS_CLIENT_KEY_EXCHANGE   0x10
#define VALIDITY_HS_FINISHED              0x14

/* Wire opcodes — just the most-used here. */
#define VALIDITY_OP_INIT_MSG1          0x01  /* RomInfo.get */
#define VALIDITY_OP_INIT_MSG2          0x19
#define VALIDITY_OP_INIT_MSG4          0x06  /* big static identity blob */
#define VALIDITY_OP_ENROLL_SESSION     0x1A
#define VALIDITY_OP_UNKNOWN_5B         0x5B  /* not in dispatch table; provenance TBD */
#define VALIDITY_OP_ENROLL_BEGIN       0x50
#define VALIDITY_OP_ENROLL_READ_IMAGE  0x51
#define VALIDITY_OP_IDENTIFY_MATCH     0x5E
#define VALIDITY_OP_CAPTURE_PROGRAM    0x02
#define VALIDITY_OP_ENROLL_SCAN_SETUP  0x39
#define VALIDITY_OP_UNKNOWN_75         0x75
#define VALIDITY_OP_FLASH_ERASE        0x3F
#define VALIDITY_OP_FLASH_WRITE        0x41
#define VALIDITY_OP_FLASH_SIGN         0x42
#define VALIDITY_OP_GET_FW_INFO        0x43  /* + 1-byte partition: 0x02 = fwext */

/* Client-direction prefix on TLS handshake records (NOT on app_data) */
extern const guint8 validity_client_handshake_prefix[4];  /* = { 0x44, 0x00, 0x00, 0x00 } */

/* Low-level USB bulk transfer wrappers — defined in validity.c, used from
 * other driver source files including validity-pretls-pair.c. */
gboolean validity_usb_write (FpDevice     *dev,
                             const guint8 *data,
                             gsize         len,
                             GError      **error);
gboolean validity_usb_read  (FpDevice  *dev,
                             guint8    *buf,
                             gsize      max_len,
                             gsize     *out_len,
                             GError   **error);

/* INIT_MSG4 cached identity payload (660 B). See validity-init-data.c. */
#define VALIDITY_INIT_MSG4_PAYLOAD_LEN  660
extern const guint8 validity_init_msg4_payload[VALIDITY_INIT_MSG4_PAYLOAD_LEN];

/* Clean-slate INIT_MSG4 variant (5796 B). Sent as `0x06 + payload` during
 * the pre-TLS fresh-pair ceremony to put the device into "will accept a
 * fresh CSR via 0x4f" state. Static blob — same for every 0088 device. */
#define VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN  5796
extern const guint8 validity_init_msg4_clean_slate_payload[VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN];

/* Pre-TLS fresh-pair ceremony. Generates a fresh host keypair, signs CSR
 * with hs_key, runs the 0x06+clean_slate / 0x4f+CSR / 0x50 exchange, and
 * persists cert + priv + device ECDH pubkey to the on-disk pairing dir.
 * Returns TRUE on success. See validity-pretls-pair.c. */
gboolean validity_pairing_run_pretls_fresh_pair_ceremony (FpDevice *dev,
                                                          GError  **error);

/* Enroll-time HOSTPART payload (10500 B). See validity-enroll-data.c.
 * The clean-slate variant is shipped but not auto-selected; the
 * 0x4302 probe in validity_send_plaintext_init would be the trigger
 * if a future 0088 ever returns non-zero from it. */
#define VALIDITY_ENROLL_HOSTPART_BLOB_LEN  10500
extern const guint8 validity_enroll_hostpart_blob[VALIDITY_ENROLL_HOSTPART_BLOB_LEN];
extern const guint8 validity_enroll_hostpart_blob_clean_slate[VALIDITY_ENROLL_HOSTPART_BLOB_LEN];

/* ===========================================================================
 * Pinned attestation keys (embedded; raw bytes in validity-pubkeys.c).
 * Family-wide constants, same on every 0088 device.
 * ========================================================================= */

/* RSA-2048: F4 exponent. Modulus is in validity_rsa_modulus_a / _b. */
#define VALIDITY_RSA_EXPONENT     0x10001u
#define VALIDITY_RSA_MODULUS_LEN  256

extern const guint8 validity_rsa_modulus_a[VALIDITY_RSA_MODULUS_LEN];
extern const guint8 validity_rsa_modulus_b[VALIDITY_RSA_MODULUS_LEN];
extern const guint8 validity_rsa_modulus_a_sha256[32];
extern const guint8 validity_rsa_modulus_b_sha256[32];

/* ECC P-256 attestation key (the only entry in the default table). */
#define VALIDITY_ECC_COORD_LEN  32
extern const guint8 validity_ecc_pubkey_x[VALIDITY_ECC_COORD_LEN];
extern const guint8 validity_ecc_pubkey_y[VALIDITY_ECC_COORD_LEN];

/* Maps a device-ID 3-byte prefix to a pinned key. Currently:
 *   prefix 06 03 01           -> Key B
 *   all other 06 xx xx        -> Key A
 *   06 07 00 (default table)  -> ECC key
 */
const guint8 *validity_pick_rsa_modulus_for_device_id (const guint8 device_prefix[3]);

/* ===========================================================================
 * Image record (device → host, inside an encrypted TLS app_data record)
 *
 * Format: 18-byte header + 56×144 8-bit greyscale pixels = 8082 bytes
 * total plaintext per image (8128 B of ciphertext on the wire after
 * AES-CBC + padding + HMAC-SHA-256).
 * ========================================================================= */

#define VALIDITY_IMAGE_WIDTH        56
#define VALIDITY_IMAGE_HEIGHT      144
#define VALIDITY_IMAGE_HEADER_LEN   18
#define VALIDITY_IMAGE_DATA_LEN    (VALIDITY_IMAGE_WIDTH * VALIDITY_IMAGE_HEIGHT)  /* 8064 */
#define VALIDITY_IMAGE_RECORD_LEN  (VALIDITY_IMAGE_HEADER_LEN + VALIDITY_IMAGE_DATA_LEN)  /* 8082 */

typedef struct __attribute__((packed)) {
  guint16 type;        /* = 0 */
  guint16 payload_len; /* = 0x1f8c = 8076 (LE) */
  guint16 flags;       /* = 0 */
  guint16 width;       /* = 56 (LE) */
  guint16 height;      /* = 144 (LE) */
  guint16 fw_const;    /* = 0x014d — constant across sessions; meaning TBD */
  guint16 bpp;         /* = 8 (8-bit greyscale) */
  guint16 reserved;
  guint8  pixels[VALIDITY_IMAGE_DATA_LEN];
} ValidityImageRecord;

/* Parse and validate an image plaintext. Returns TRUE if valid. */
static inline gboolean
validity_image_record_validate (const ValidityImageRecord *img)
{
  return (img->type == 0
          && img->payload_len == 0x1f8c
          && img->width  == VALIDITY_IMAGE_WIDTH
          && img->height == VALIDITY_IMAGE_HEIGHT
          && img->bpp    == 8);
}

/* ===========================================================================
 * Match-response record (device → host)
 *
 * 2154-byte plaintext inside an 8128-byte ciphertext record. Field layout
 * confirmed via cross-session validation. Each per-touch
 * interaction produces TWO of these — a "probe" response followed by a
 * "result" response. The result record contains the actual match score
 * and outcome.
 * ========================================================================= */

#define VALIDITY_MATCH_RESPONSE_LEN  2154

/* IMPORTANT: reinterpretation (v10 capture analysis), this
 * device runs in EOH-MOH-StgOnHost mode — feature-extraction happens
 * on the device, but MATCHING happens on the HOST. The "match_result"
 * field below is really an "image-features-extracted-OK" status; the
 * actual match decision is made by libfprint's NBIS matcher against
 * its template database, NOT by the device. */
#define VALIDITY_MATCH_RESULT_INIT          0x00000000u  /* uninit / first response */
#define VALIDITY_MATCH_RESULT_PROBE         0x00000080u  /* touch detected, capture in progress */
#define VALIDITY_MATCH_RESULT_FEATURES_OK   0x00000085u  /* image captured + features extracted */

/* Compat aliases */
#define VALIDITY_MATCH_RESULT_SUCCESS  VALIDITY_MATCH_RESULT_FEATURES_OK

typedef struct __attribute__((packed)) {
  guint8  header[10];     /* constant 00 00 88 02 00 30 86 00 00 00 */
  guint8  session_nonce[6]; /* varies per session, constant within */
  /* Bytes 0x0010..0x0353 — session-static "enrolled-finger record"
   * (0x344 = 836 bytes — opaque to driver) */
  guint8  static_state[0x344];
  guint8  flags_a;        /* +0x0354: typically 0x02 for normal */
  guint8  pad1;
  guint32 timestamp_us;   /* +0x0356: u32 LE, monotonically increasing */
  /* Variable-length payload from +0x035a..+0x0579 — image quality data */
  guint8  acq_data[0x220];
  guint32 score;          /* +0x057a: matcher score (>>threshold = pass) */
  guint32 minutia_count;  /* +0x057e: minutiae found by matcher */
  guint32 threshold;      /* +0x0582: 42 for match attempts, 2-3 for probes */
  guint8  probe_flag;     /* +0x0586: 0x80 during probe, 0x00 in result */
  guint8  pad2[39];
  /* +0x05ae..+0x05b1: the MATCH-RESULT field */
  guint32 match_result;   /* +0x05ae: see VALIDITY_MATCH_RESULT_* constants */
  /* Remaining bytes: device-internal state mirror, opaque */
  guint8  trailing[VALIDITY_MATCH_RESPONSE_LEN - 0x05b2];
} ValidityMatchResponse;

static inline gboolean
validity_match_response_is_success (const ValidityMatchResponse *r)
{
  return r->match_result == VALIDITY_MATCH_RESULT_SUCCESS;
}

static inline gboolean
validity_match_response_is_probe (const ValidityMatchResponse *r)
{
  return r->probe_flag == 0x80;
}

/* ===========================================================================
 * ROM info + capture-program construction
 * ========================================================================= */

#define VALIDITY_ROM_INFO_RAW_MAX 64

typedef struct {
  gboolean valid;
  guint32  timestamp;
  guint32  build;
  guint8   major;
  guint8   minor;
  guint8   product;
  guint8   u1;
  guint8   raw[VALIDITY_ROM_INFO_RAW_MAX];
  gsize    raw_len;
} ValidityRomInfo;

typedef enum {
  VALIDITY_CAPTURE_MODE_IDENTIFY = 0x02,
  VALIDITY_CAPTURE_MODE_ENROLL   = 0x23,
} ValidityCaptureMode;

/* ===========================================================================
 * Session state
 * ========================================================================= */

typedef struct {
  /* Negotiated during handshake */
  guint8 client_random[32];      /* 4 B gmt_unix_time + 28 B random */
  guint8 server_random[32];      /* from ServerHello */
  guint8 master_secret[VALIDITY_MASTER_SECRET_LEN];
  guint8 client_write_mac_key[VALIDITY_MAC_KEY_LEN];
  guint8 server_write_mac_key[VALIDITY_MAC_KEY_LEN];
  guint8 client_write_key[VALIDITY_ENC_KEY_LEN];
  guint8 server_write_key[VALIDITY_ENC_KEY_LEN];

  /* TLS-1.2 record-layer sequence numbers (one per direction) */
  guint64 client_seq_num;
  guint64 server_seq_num;

  /* Cipher activation flag: TRUE after ChangeCipherSpec */
  gboolean cipher_active;

  /* Per-session ephemeral keypair (for ECDH) */
  guint8 ephemeral_priv[32];   /* P-256 private scalar */
  guint8 ephemeral_pub_x[32];
  guint8 ephemeral_pub_y[32];

  /* Running SHA-256 over the handshake messages (for Finished's verify_data) */
  void *handshake_hash_ctx;    /* opaque EVP_MD_CTX* */

  /* Device identity (3-byte prefix) — picked up early in the init phase */
  guint8 device_prefix[3];

  /* Parsed opcode 0x01 RomInfo response. */
  ValidityRomInfo rom_info;

  /* Fresh-pair handshake material extracted from the device's Server
   * Certificate TLV envelope. On a paired device these stay NULL/0
   * and the driver falls back to the cached cert / cached host key.
   * On a never-paired (fresh) device the Server Certificate carries
   * the placeholder cert (tag 3, 292 B) and an RSA key blob (tag 4,
   * 1184 B) the host should use for the Client Certificate + the
   * RSA-SHA256 CertificateVerify signing. See , */
  guint8  *fresh_pair_cert_body;   /* 292-B blob, owned */
  gsize    fresh_pair_cert_body_len;
  guint8  *fresh_pair_rsa_blob;    /* 1184-B blob, owned */
  gsize    fresh_pair_rsa_blob_len;
  void    *fresh_pair_rsa_key;     /* opaque EVP_PKEY*, owned */
} ValiditySession;

/* ===========================================================================
 * Crypto API (validity-crypto.c)
 * Modelled on the Python reference at handoff/python/verimark_proto.py.
 * Defaults to OpenSSL EVP; swap for GnuTLS / libgcrypt if preferred.
 * ========================================================================= */

/* TLS-1.2 PRF over SHA-256. RFC 5246 §5. */
gboolean validity_tls12_prf (
    const guint8 *secret, gsize secret_len,
    const guint8 *label,  gsize label_len,
    const guint8 *seed,   gsize seed_len,
    guint8       *out,    gsize out_len);

/* Derive master_secret + key_block + split into 4 keys.
 * Stores the result into `session`. See for the deviation
 * from RFC 5246 §6.3 seed ordering. */
gboolean validity_derive_session_keys (
    ValiditySession *session,
    const guint8    *pre_master_secret,
    gsize            pre_master_secret_len);

/* Encrypt one outgoing TLS-1.2 record body. Returns malloc'd buffer
 * (caller frees) and its length via *out_len. */
guint8 *validity_encrypt_record (
    ValiditySession *session,
    guint8           content_type,
    const guint8    *plaintext, gsize plaintext_len,
    gsize           *out_len);

/* Decrypt one incoming TLS-1.2 record body. Returns malloc'd
 * plaintext buffer (caller frees) and its length via *out_len.
 * Returns NULL on MAC failure. */
guint8 *validity_decrypt_record (
    ValiditySession *session,
    guint8           content_type,
    const guint8    *record_body, gsize record_body_len,
    gsize           *out_len);

/* ECDH on NIST P-256. Returns malloc'd 32-byte shared secret. */
guint8 *validity_ecdh_p256 (
    const guint8 *our_priv,        /* 32 B */
    const guint8 *peer_pub_x,      /* 32 B */
    const guint8 *peer_pub_y,      /* 32 B */
    gsize        *out_len);

/* Generate a random P-256 keypair into the session struct. */
gboolean validity_generate_ephemeral_keypair (ValiditySession *session);

/* Free heap-owned fresh-pair material (cert body, RSA blob, EVP_PKEY)
 * attached to a session. Safe on sessions that never received the
 * tags. Call before zeroing the session struct. */
void validity_session_clear_fresh_pair (ValiditySession *session);

/* SHA-256 update: feed handshake_messages into the running hash for
 * later Finished verify_data computation. */
void validity_handshake_hash_init   (ValiditySession *session);
void validity_handshake_hash_update (ValiditySession *session, const guint8 *data, gsize len);
void validity_handshake_hash_finish (ValiditySession *session, guint8 out[32]);

/* ===========================================================================
 * Command builders (validity-commands.c)
 * Modelled on handoff/python/verimark_proto.py.
 * ========================================================================= */

/* Wire-byte framer: prepend the 1-byte opcode to the payload.
 * Returns malloc'd buffer of size payload_len + 1. */
guint8 *validity_wrap_wire_frame (
    guint8        opcode,
    const guint8 *payload, gsize payload_len,
    gsize        *out_len);

/* Build a ClientHello, including the 4-byte client-direction prefix.
 * Returns malloc'd buffer. */
guint8 *validity_build_client_hello (
    ValiditySession *session,
    gsize           *out_len);

/* Build the identify/match command payload (wire byte 0x5e). The
 * "payload" arg is the encrypted template push (~18851 B). */
guint8 *validity_build_identify_command (
    guint8        flag1,
    guint8        flag2,
    guint16       field_a,
    guint16       field_b,
    guint16       field_c,
    const guint8 *payload, guint32 payload_len,
    gsize        *out_len);

/* Single-byte wire commands. Both produce malloc'd 1-byte buffers
 * `[0x50]` and `[0x1A]` respectively; caller g_frees. */
guint8 *validity_build_enroll_begin_command (gsize *out_len);
guint8 *validity_build_enroll_session_command (gsize *out_len);
guint8 *validity_build_enroll_read_image_command (guint32 mode,
                                                  gsize  *out_len);
guint8 *validity_build_flash_erase_command (guint8 partition_id,
                                            gsize  *out_len);
guint8 *validity_build_flash_write_command (guint8        partition_id,
                                            guint32       offset,
                                            const guint8 *data,
                                            gsize         len,
                                            gsize        *out_len);
guint8 *validity_build_flash_sign_command  (guint8        partition_id,
                                            const guint8 *signature,
                                            gsize         signature_len,
                                            gsize        *out_len);

/* Enrollment program builders. HostPart uses an embedded default with
 * optional override/cache fallback; capture is constructed from the
 * validated 0088 materialized template unless the debug env override is
 * set. Scan setup is constructed from the known-good LED blue-ready
 * variant. */
guint8 *validity_build_enroll_hostpart_command (gsize   *out_len,
                                                GError **error);
guint8 *validity_build_enroll_scan_setup_command (gsize   *out_len,
                                                  GError **error);
gboolean validity_parse_rom_info_response (ValidityRomInfo *rom_info,
                                           const guint8    *plain,
                                           gsize            plain_len,
                                           GError         **error);
guint8 *validity_capture_build (const ValidityRomInfo *rom_info,
                                ValidityCaptureMode    mode,
                                gsize                 *out_len,
                                GError               **error);
guint8 *validity_build_enroll_capture_command (FpDevice            *dev,
                                               ValidityCaptureMode  mode,
                                               gsize               *out_len,
                                               GError             **error);

/* HostPart read/write commands (P5 / PAIRING.md). */
guint8  *validity_build_host_part_write (gsize *out_len);
guint8  *validity_build_host_part_read  (guint8  tag1,
                                          guint8  tag2,
                                          guint32 val1,
                                          guint32 val2,
                                          gsize  *out_len);
gboolean validity_send_host_part_write (FpDevice *dev, GError **error);
gboolean validity_send_host_part_read  (FpDevice  *dev,
                                         guint8     tag1,
                                         guint8     tag2,
                                         guint32    val1,
                                         guint32    val2,
                                         guint8   **out_data,
                                         gsize     *out_data_len,
                                         GError   **error);

/* Cert blob acquisition via wire 0x4f (P1 / PAIRING.md).
 *
 * If @out_status is non-NULL, the device's 2-byte response status word
 * is always written there (big-endian as logged), regardless of whether
 * the function returns TRUE or FALSE. Callers use this to distinguish
 * "device rejected because already paired" (status 0x0104) from generic
 * I/O failures. */
gboolean validity_send_cert_acquisition (FpDevice  *dev,
                                         guint8    out_cert_blob[0xb8],
                                         guint16  *out_status,
                                         GError  **error);

/* Status meanings observed live on 06cb:0088. Add new entries as they're
 * encountered. */
#define VALIDITY_STATUS_OK                       0x0000u
#define VALIDITY_STATUS_CERT_ALREADY_ISSUED      0x0104u  /* 0x4f rejection: device has an existing cert context */
#define VALIDITY_STATUS_FLASH_ERASE_NOT_ALLOWED  0x04afu  /* 0x3f rejection: partition cannot be erased in current state */

/* Internal encrypted app-data exchange helpers (validity.c). These route
 * through validity_usb_write(), which enforces the 06cb:0088 defensive
 * write guard before any USB OUT transfer. */
ValiditySession *validity_device_get_session (FpDevice *dev);
gboolean validity_exchange_app_plaintext (FpDevice     *dev,
                                          const guint8 *plain,
                                          gsize         plain_len,
                                          guint8      **out_rsp,
                                          gsize        *out_rsp_len,
                                          GError      **error);
/* LED mode flags written to u32 LE at payload+1 of the 0x39 glow command. */
#define LED_MODE_STEADY   0u   /* solid, no animation */
#define LED_MODE_SOLID    1u   /* single ramp/pulse */
#define LED_MODE_REPEAT   2u   /* repeating flash */
#define LED_VARIANT_BLUE  0x0002bf20u  /* ready-for-tap blue glow */

/* ---------------------------------------------------------------------------
 * LED glow command (opcode 0x39 — shared with enroll-scan-setup).
 *
 * Builds a 125-byte payload. Passing mode=LED_VARIANT_BLUE returns the
 * ready-for-tap scan-setup payload (blue pulse). Other modes use the simple
 * single-slot R/G/B form preserved for experiments. Returns g_malloc'd
 * buffer; caller g_frees.
 *
 *   r, g, b   : 0-255
 *   mode      : LED_VARIANT_BLUE, or LED_MODE_STEADY/SOLID/REPEAT for the
 *               experimental single-slot builder
 *   timing_ms : u16 LE on-time / dwell duration
 * ------------------------------------------------------------------------- */
guint8 *validity_build_led_glow_command (guint8  r,
                                         guint8  g,
                                         guint8  b,
                                         guint32 mode,
                                         guint16 timing_ms,
                                         gsize  *out_len);

/* Parse a hex string into a 125-byte raw LED payload (for env-var override).
 * Returns g_malloc'd buffer or NULL on malformed input. */
guint8 *validity_parse_led_raw_payload (const gchar *hex_str,
                                        gsize       *out_len);

/* ===========================================================================
 * Pairing / host identity (validity-pairing.c)
 * Storage: $XDG_DATA_HOME/libfprint/verimark-06cb-0088/{host-uuid,host-key.pem}
 * See 
 * ========================================================================= */

#define VALIDITY_HOST_UUID_LEN          16
#define VALIDITY_CLIENT_CERT_LEN       192   /* Synaptics custom Certificate body */
#define VALIDITY_CLIENT_CERT_SIG_LEN    32   /* trailing opaque signature */

extern const guint8 validity_cached_client_cert_body[VALIDITY_CLIENT_CERT_LEN];
extern const guint8 validity_cached_host_private_key[VALIDITY_ECC_COORD_LEN];
extern const guint8 validity_cached_device_ecdh_pubkey_x[VALIDITY_ECC_COORD_LEN];
extern const guint8 validity_cached_device_ecdh_pubkey_y[VALIDITY_ECC_COORD_LEN];

/* Storage path management. Returned string is g_free'd by caller. */
gchar *  validity_pairing_get_storage_dir   (void);
gboolean validity_pairing_ensure_storage_dir (GError **error);

/* Host UUID: 16 random bytes presented as the Machine-GUID equivalent. */
gboolean validity_pairing_generate_host_uuid (guint8 out[VALIDITY_HOST_UUID_LEN],
                                              GError **error);
gboolean validity_pairing_save_host_uuid     (const guint8 uuid[VALIDITY_HOST_UUID_LEN],
                                              GError **error);
gboolean validity_pairing_load_host_uuid     (guint8 out[VALIDITY_HOST_UUID_LEN],
                                              GError **error);

/* Persistent host ECDSA P-256 keypair. EVP_PKEY * must be EVP_PKEY_free'd. */
struct evp_pkey_st; /* forward decl; <openssl/evp.h> provides the real one */
typedef struct evp_pkey_st EVP_PKEY;
EVP_PKEY *validity_pairing_generate_host_keypair (GError **error);
gboolean  validity_pairing_save_host_keypair     (EVP_PKEY *pkey, GError **error);
EVP_PKEY *validity_pairing_load_host_keypair     (GError **error);

gboolean  validity_pairing_get_pubkey_xy (EVP_PKEY *pkey,
                                          guint8    x_be[VALIDITY_ECC_COORD_LEN],
                                          guint8    y_be[VALIDITY_ECC_COORD_LEN],
                                          GError  **error);

/* Build the Synaptics 192-byte client Certificate body. Caller g_free's. */
guint8 *validity_pairing_build_client_certificate (
    const guint8 host_pubkey_x_be[VALIDITY_ECC_COORD_LEN],
    const guint8 host_pubkey_y_be[VALIDITY_ECC_COORD_LEN],
    const guint8 signature_trailer[VALIDITY_CLIENT_CERT_SIG_LEN],
    const guint8 session_random[4]);

/* Machine GUID continuity check (CeivMode::ValidateDatabase equivalent).
 * Checks whether the host UUID matches the one recorded during the
 * last pairing ceremony. See and PAIRING.md NTH. */
gboolean validity_pairing_ensure_host_uuid (GError **error);
gboolean validity_pairing_check_guid_continuity (gboolean *needs_re_pair,
                                                  GError  **error);
gboolean validity_pairing_record_pairing_uuid (GError **error);
gboolean validity_pairing_was_database_wiped (void);

/* SPI flash write (gated on encrypted session; dry-run via
 * VALIDITY0088_FLASH_DRY_RUN=1). */
gboolean validity_pairing_flash_write (FpDevice        *dev,
                                       ValiditySession *session,
                                       guint8           partition_id,
                                       guint32          offset,
                                       const guint8    *data,
                                       gsize            len,
                                       GError         **error);

/* HostPart persistence (P4). */
gboolean validity_pairing_generate_host_part (guint8 out[16], GError **error);
gboolean validity_pairing_save_host_part (const guint8 host_part[16], GError **error);
gboolean validity_pairing_load_host_part (guint8 out[16], GError **error);
gboolean validity_pairing_has_host_part (void);

/* Cert blob persistence (cache full 0xb8-byte blob from 0x4f for handshake replay). */
gboolean validity_pairing_save_cert_blob (const guint8 blob[0xb8], GError **error);

/* One-time migration: copy baked-in cert + host private scalar from
 * validity-pubkeys.c into the on-disk pairing storage so the driver
 * can be rebuilt with the baked-in arrays zeroed. Idempotent and safe
 * to call on every open(): no-op if disk already has both, no-op if
 * baked-in values are zero, copies otherwise. See validity-pairing.c. */
gboolean validity_pairing_bootstrap_from_hardcoded (GError **error);

gboolean validity_pairing_load_cert_blob (guint8 out[0xb8], GError **error);
gboolean validity_pairing_has_cert_blob (void);
gboolean validity_pairing_have_per_pairing_material (void);

/* P6 — High-level pairing ceremony orchestrator.
 * Runs the full fresh-pair flow: acquire cert trailer via 0x4f,
 * derive shared secret, write OSB to device, cache everything locally.
 * Returns FALSE on any failure with error set. */
gboolean validity_pairing_run_ceremony (FpDevice *dev, GError **error);

/* P2 — Shared-secret derivation (GWK / GWK_SIGN / OSB). */
gboolean validity_pairing_derive_shared_keys (const guint8  host_part[16],
                                                guint8        out_gwk[32],
                                                guint8        out_gwk_sign[32]);
gboolean validity_pairing_derive_osb   (const guint8  host_part[16],
                                         const guint8 *tag4_data,
                                         gsize         tag4_len,
                                         guint8       *out_osb);
gboolean validity_pairing_save_osb     (const guint8 osb[32], GError **error);
gboolean validity_pairing_load_osb     (guint8 out[32], GError **error);
gboolean validity_pairing_has_osb      (void);

/* Enroll bootstrap wire-0x06 body cache.
 * Stores the 10500-byte body without the outer opcode byte; command builders
 * wrap it as 0x06 + body. See */
gboolean validity_pairing_save_enroll_hostpart_blob (const guint8 *blob,
                                                     gsize         len,
                                                     GError      **error);
guint8 * validity_pairing_load_enroll_hostpart_blob (gsize   *out_len,
                                                     GError **error);
gboolean validity_pairing_has_enroll_hostpart_blob  (void);

/* Phase 9 - first-pair trigger helpers.
 *   _state_complete: TRUE iff (host_part && cert_blob && osb cached) OR
 *                    the device-already-paired sentinel exists.
 *   _wipe_state: delete every file in the pairing storage dir (used by
 *                VALIDITY0088_FORCE_REPAIR=1 to trigger a fresh ceremony).
 *   _has_/_save_already_paired_marker: sentinel written when wire 0x4f
 *                returns VALIDITY_STATUS_CERT_ALREADY_ISSUED, used by
 *                state_complete to short-circuit the ceremony retry on
 *                subsequent opens of an already-paired device. */
gboolean validity_pairing_state_complete                (void);
gboolean validity_pairing_wipe_state                    (GError **error);
gboolean validity_pairing_has_already_paired_marker     (void);
gboolean validity_pairing_save_already_paired_marker    (GError **error);

/* ===========================================================================
 * TLS handshake (validity-handshake.c)
 * ========================================================================= */

/* Run the full mutual-TLS handshake on `dev`. Assumes the plaintext
 * init phase has completed and the device is awaiting ClientHello.
 * On success: session->cipher_active = TRUE and all four keys derived. */
gboolean validity_run_tls_handshake (FpDevice        *dev,
                                     ValiditySession *session,
                                     GError         **error);

/* ===========================================================================
 * Driver state machine (validity.c)
 * ========================================================================= */

typedef enum {
  VALIDITY_PHASE_PLAINTEXT_INIT,  /* Send INIT_MSG4, 5b, 01, 19 */
  VALIDITY_PHASE_TLS_HANDSHAKE,   /* ClientHello → ... → Finished */
  VALIDITY_PHASE_APP_DATA,        /* Encrypted session active */
} ValidityPhase;
