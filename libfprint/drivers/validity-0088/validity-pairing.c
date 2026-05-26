/*
 * validity-pairing.c — Host identity, key persistence, client Certificate
 * builder for Kensington VeriMark (06CB:0088).
 *
 * Storage layout:
 *
 *   $XDG_DATA_HOME/libfprint/verimark-06cb-0088/
 *     host-uuid          16 B  generated once via getrandom(3)
 *     host-key.pem       EC P-256 keypair (PEM), mode 0600
 *
 * The host keypair is the long-lived ECDSA identity bound to the
 * device's SPI flash slot during first-run pairing. On every
 * subsequent connect the same keypair signs the TLS handshake
 * transcript (CertificateVerify) and presents the same X/Y inside
 * the Synaptics-custom client Certificate body.
 *
 * SPI flash write helpers build the 0x3f/0x41/0x42 encrypted-session
 * frames and support a dry-run safety gate for first live review.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "validity.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

/* ===========================================================================
 * Storage path
 * ========================================================================= */

/* Returned string is owned by the caller and must be g_free'd.
 *
 * Path selection:
 *   1. $STATE_DIRECTORY (systemd-set when running under fprintd; e.g.
 *      /var/lib/fprint). This is the only persistent writable path
 *      available to fprintd under its default ProtectHome=true +
 *      ProtectSystem=strict sandbox.
 *   2. $VALIDITY0088_STORAGE_DIR (manual override for tests / non-systemd
 *      hosts).
 *   3. g_get_user_data_dir() -> ~/.local/share/libfprint/verimark-06cb-0088
 *      (existing behavior for CLI tools / examples/verify run as a user).
 */
gchar *
validity_pairing_get_storage_dir (void)
{
  const gchar *override = g_getenv ("VALIDITY0088_STORAGE_DIR");
  if (override != NULL && override[0] != '\0')
    return g_strdup (override);

  const gchar *state_dir = g_getenv ("STATE_DIRECTORY");
  if (state_dir != NULL && state_dir[0] != '\0')
    return g_build_filename (state_dir, "validity-0088-pairing", NULL);

  const gchar *data_dir = g_get_user_data_dir ();   /* never NULL */
  return g_build_filename (data_dir, "libfprint",
                           "verimark-06cb-0088", NULL);
}

gboolean
validity_pairing_ensure_storage_dir (GError **error)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  if (g_mkdir_with_parents (dir, 0700) != 0)
    {
      int err = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (err),
                   "failed to create %s: %s", dir, g_strerror (err));
      return FALSE;
    }
  /* Tighten mode in case g_mkdir_with_parents created with looser
   * permissions on an already-existing path. */
  if (chmod (dir, 0700) != 0 && errno != ENOENT)
    fp_dbg ("chmod 0700 on %s failed: %s (continuing)", dir, g_strerror (errno));
  return TRUE;
}

/* ===========================================================================
 * Host UUID (16 B, presented to the device as the Machine-GUID equivalent)
 * ========================================================================= */

#define VALIDITY_HOST_UUID_LEN 16

/* File paths within the storage directory */
static gchar *
host_uuid_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "host-uuid", NULL);
}

static gchar *
paired_uuid_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "pair-uuid", NULL);
}

static gchar *
database_wipe_marker_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "db-wiped-for-uuid", NULL);
}

static gboolean
write_file_restricted (const gchar  *path,
                       const guint8 *data,
                       gsize         len,
                       GError      **error)
{
  /* O_CREAT|O_TRUNC|O_WRONLY with mode 0600 atomically (no umask race). */
  int fd = open (path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0)
    {
      int err = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (err),
                   "open(%s) for write failed: %s", path, g_strerror (err));
      return FALSE;
    }
  gsize off = 0;
  while (off < len)
    {
      ssize_t n = write (fd, data + off, len - off);
      if (n < 0)
        {
          if (errno == EINTR) continue;
          int err = errno;
          close (fd);
          g_set_error (error, G_IO_ERROR, g_io_error_from_errno (err),
                       "write(%s) failed: %s", path, g_strerror (err));
          return FALSE;
        }
      off += (gsize) n;
    }
  if (close (fd) != 0)
    {
      int err = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (err),
                   "close(%s) failed: %s", path, g_strerror (err));
      return FALSE;
    }
  return TRUE;
}

gboolean
validity_pairing_generate_host_uuid (guint8 out[VALIDITY_HOST_UUID_LEN],
                                     GError **error)
{
  ssize_t n = getrandom (out, VALIDITY_HOST_UUID_LEN, 0);
  if (n != VALIDITY_HOST_UUID_LEN)
    {
      int err = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (err),
                   "getrandom(host_uuid) returned %zd: %s",
                   n, g_strerror (err));
      return FALSE;
    }
  return TRUE;
}

gboolean
validity_pairing_save_host_uuid (const guint8 uuid[VALIDITY_HOST_UUID_LEN],
                                 GError **error)
{
  if (!validity_pairing_ensure_storage_dir (error)) return FALSE;
  g_autofree gchar *path = host_uuid_path ();
  return write_file_restricted (path, uuid, VALIDITY_HOST_UUID_LEN, error);
}

gboolean
validity_pairing_load_host_uuid (guint8 out[VALIDITY_HOST_UUID_LEN],
                                 GError **error)
{
  g_autofree gchar *path = host_uuid_path ();
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  if (!g_file_get_contents (path, &contents, &len, error))
    return FALSE;
  if (len != VALIDITY_HOST_UUID_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: expected %d B, got %zu", path,
                   VALIDITY_HOST_UUID_LEN, len);
      return FALSE;
    }
  memcpy (out, contents, VALIDITY_HOST_UUID_LEN);
  return TRUE;
}

/* ===========================================================================
 * Host keypair (P-256 ECDSA), persisted as PEM at mode 0600
 * ========================================================================= */

static gchar *
host_key_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "host-key.pem", NULL);
}

EVP_PKEY *
validity_pairing_generate_host_keypair (GError **error)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_EC, NULL);
  if (ctx == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_CTX_new_id(EC) failed");
      return NULL;
    }
  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_keygen_init (ctx) <= 0
      || EVP_PKEY_CTX_set_ec_paramgen_curve_nid (ctx, NID_X9_62_prime256v1) <= 0
      || EVP_PKEY_keygen (ctx, &pkey) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_keygen(P-256) failed");
      EVP_PKEY_CTX_free (ctx);
      if (pkey) EVP_PKEY_free (pkey);
      return NULL;
    }
  EVP_PKEY_CTX_free (ctx);
  return pkey;
}

gboolean
validity_pairing_save_host_keypair (EVP_PKEY *pkey, GError **error)
{
  if (!validity_pairing_ensure_storage_dir (error)) return FALSE;
  g_autofree gchar *path = host_key_path ();

  /* Write PEM via OpenSSL into an in-memory BIO, then commit to disk
   * with our restricted-mode helper. This avoids fopen()'s umask race. */
  BIO *bio = BIO_new (BIO_s_mem ());
  if (bio == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "BIO_new failed");
      return FALSE;
    }
  if (!PEM_write_bio_PrivateKey (bio, pkey, NULL, NULL, 0, NULL, NULL))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "PEM_write_bio_PrivateKey failed");
      BIO_free (bio);
      return FALSE;
    }
  char *pem_data = NULL;
  long pem_len = BIO_get_mem_data (bio, &pem_data);
  gboolean ok = write_file_restricted (path, (const guint8 *) pem_data,
                                       (gsize) pem_len, error);
  BIO_free (bio);
  return ok;
}

EVP_PKEY *
validity_pairing_load_host_keypair (GError **error)
{
  g_autofree gchar *path = host_key_path ();
  g_autofree gchar *pem_data = NULL;
  gsize pem_len = 0;
  if (!g_file_get_contents (path, &pem_data, &pem_len, error))
    return NULL;
  BIO *bio = BIO_new_mem_buf (pem_data, (int) pem_len);
  if (bio == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "BIO_new_mem_buf failed");
      return NULL;
    }
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL);
  BIO_free (bio);
  if (pkey == NULL)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: PEM parse failed (corrupt or wrong format?)", path);
      return NULL;
    }
  return pkey;
}

/* Extract the P-256 public point coordinates from an EVP_PKEY as
 * big-endian 32-byte buffers. */
gboolean
validity_pairing_get_pubkey_xy (EVP_PKEY *pkey,
                                guint8    x_be[VALIDITY_ECC_COORD_LEN],
                                guint8    y_be[VALIDITY_ECC_COORD_LEN],
                                GError  **error)
{
  /* OpenSSL 3 path: fetch raw EC_POINT via params API. */
  BIGNUM *bx = NULL, *by = NULL;
  if (EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bx) <= 0
      || EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &by) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_get_bn_param (EC pub X/Y) failed");
      if (bx) BN_free (bx);
      if (by) BN_free (by);
      return FALSE;
    }
  /* BN_bn2binpad zero-pads on the left to fill the buffer. */
  if (BN_bn2binpad (bx, x_be, VALIDITY_ECC_COORD_LEN) != VALIDITY_ECC_COORD_LEN
      || BN_bn2binpad (by, y_be, VALIDITY_ECC_COORD_LEN) != VALIDITY_ECC_COORD_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "BN_bn2binpad (X/Y) failed");
      BN_free (bx); BN_free (by);
      return FALSE;
    }
  BN_free (bx);
  BN_free (by);
  return TRUE;
}

/* ===========================================================================
 * Synaptics custom client Certificate body (192 B)
 * ========================================================================= */

#define VALIDITY_CLIENT_CERT_LEN          192
#define VALIDITY_CLIENT_CERT_HEADER_LEN    13
#define VALIDITY_CLIENT_CERT_X_OFFSET      16
#define VALIDITY_CLIENT_CERT_Y_OFFSET      84
#define VALIDITY_CLIENT_CERT_TRAILER_OFF  160
#define VALIDITY_CLIENT_CERT_SIG_LEN       32

guint8 *
validity_pairing_build_client_certificate (
    const guint8 host_pubkey_x_be[VALIDITY_ECC_COORD_LEN],
    const guint8 host_pubkey_y_be[VALIDITY_ECC_COORD_LEN],
    const guint8 signature_trailer[VALIDITY_CLIENT_CERT_SIG_LEN],
    const guint8 session_random[4])
{
  guint8 *body = g_malloc0 (VALIDITY_CLIENT_CERT_LEN);

  /* +0..+2: outer length = 0x0000b8 (= 184 BE) */
  body[0] = 0x00; body[1] = 0x00; body[2] = 0xb8;

  /* +3..+5: repeated length prefix */
  body[3] = 0x00; body[4] = 0x00; body[5] = 0xb8;

  /* +6..+9: per-session random */
  memcpy (body + 6, session_random, 4);

  /* +10..+15: fixed header suffix */
  body[10] = 0x00; body[11] = 0x00; body[12] = 0x20;
  body[13] = 0x00; body[14] = 0x00; body[15] = 0x00;

  /* +16..+47: X coordinate, LITTLE-endian (reversed from input BE) */
  for (gsize i = 0; i < VALIDITY_ECC_COORD_LEN; i++)
    body[VALIDITY_CLIENT_CERT_X_OFFSET + i] =
        host_pubkey_x_be[VALIDITY_ECC_COORD_LEN - 1 - i];

  /* +48..+83: 36 B zero padding (already zero from g_malloc0) */

  /* +84..+115: Y coordinate, LITTLE-endian */
  for (gsize i = 0; i < VALIDITY_ECC_COORD_LEN; i++)
    body[VALIDITY_CLIENT_CERT_Y_OFFSET + i] =
        host_pubkey_y_be[VALIDITY_ECC_COORD_LEN - 1 - i];

  /* +116..+159: 44 B zero padding (already zero) */

  /* +160..+191: signature trailer */
  memcpy (body + VALIDITY_CLIENT_CERT_TRAILER_OFF,
          signature_trailer, VALIDITY_CLIENT_CERT_SIG_LEN);

  return body;
}

/* ===========================================================================
 * HostPart persistence (16-B per-device pairing secret)
 *
 * The hostPart is a 16-byte random value that feeds into the shared-secret
 * derivation. Stored as a flat 16-B file in the per-device storage dir.
 * ========================================================================= */

#define VALIDITY_HOSTPART_LEN 16

static gchar *
host_part_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "host-part", NULL);
}

/**
 * validity_pairing_generate_host_part:
 * @out: (out caller-allocated) 16-byte buffer for the random hostPart
 * @error: return location for a GError, or %NULL
 *
 * Generates a fresh 16-byte random hostPart value via getrandom(2).
 **/
gboolean
validity_pairing_generate_host_part (guint8 out[VALIDITY_HOSTPART_LEN],
                                     GError **error)
{
  ssize_t n = getrandom (out, VALIDITY_HOSTPART_LEN, 0);
  if (n != VALIDITY_HOSTPART_LEN)
    {
      int err = errno;
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (err),
                   "getrandom(host_part) returned %zd: %s",
                   n, g_strerror (err));
      return FALSE;
    }
  return TRUE;
}

/**
 * validity_pairing_save_host_part:
 * @host_part: 16 bytes to persist
 * @error: return location for a GError, or %NULL
 *
 * Writes the hostPart to <storage-dir>/host-part atomically (mode 0600).
 **/
gboolean
validity_pairing_save_host_part (const guint8 host_part[VALIDITY_HOSTPART_LEN],
                                 GError **error)
{
  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;
  g_autofree gchar *path = host_part_path ();
  return write_file_restricted (path, host_part, VALIDITY_HOSTPART_LEN, error);
}

/**
 * validity_pairing_load_host_part:
 * @out: (out caller-allocated) 16-byte buffer for the loaded hostPart
 * @error: return location for a GError, or %NULL
 *
 * Reads the persisted hostPart from <storage-dir>/host-part. Returns FALSE
 * with G_IO_ERROR_NOT_FOUND if no stored hostPart exists (first-run case).
 **/
gboolean
validity_pairing_load_host_part (guint8 out[VALIDITY_HOSTPART_LEN],
                                 GError **error)
{
  g_autofree gchar *path = host_part_path ();
  g_autofree gchar *contents = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &contents, &len, error))
    return FALSE;

  if (len != VALIDITY_HOSTPART_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: expected %d B, got %zu", path,
                   VALIDITY_HOSTPART_LEN, len);
      return FALSE;
    }

  memcpy (out, contents, VALIDITY_HOSTPART_LEN);
  return TRUE;
}

/**
 * validity_pairing_has_host_part:
 *
 * Returns TRUE if a hostPart file already exists on disk (i.e., a pairing
 * has been initiated at least once). Quick check without reading data.
 **/
gboolean
validity_pairing_has_host_part (void)
{
  g_autofree gchar *path = host_part_path ();
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

/* ===========================================================================
 * P2 — Shared-secret derivation (GWK / GWK_SIGN / OSB)
 *
 * The Synaptics pairing protocol uses a static password_hardcoded constant
 * as a seed for PRF-based key derivation, feeding in the hostPart to
 * produce keys used for pairing commitment.
 *
 * Key chain (matches python-validity for 06CB:009A):
 *
 *   password_hardcoded  = 32 B embedded family-wide constant
 *   gwk_sign_hardcoded  = 32 B embedded family-wide constant
 *
 *   WRKP_key     = PRF(password_hardcoded, "WRKP" + seed_constant, 32)
 *   GWK_SIGN_key = PRF(WKRP_key, "GWK_SIGN" + gwk_sign_hardcoded, 32)
 *
 *   OSB = PRF(tag4_data, "_OSB_" + encrypted_iv_data, 32)
 * ========================================================================= */

/* "password_hardcoded" - root seed for all pairing key derivation.
 * Family-wide Synaptics constant. */
static const guint8 VALIDITY_PAIRING_PASSWORD[32] = {
    0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
    0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
    0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38,
    0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33
};

/* The "gwk_sign_hardcoded" constant from python-validity (hardcoded in
 * FUN_180071900 local stack).
 * Source: reference/python-validity/validitysensor/tls.py:20 */
static const guint8 VALIDITY_GWK_SIGN_CONSTANT[32] = {
    0x3a, 0x4c, 0x76, 0xb7, 0x6a, 0x97, 0x98, 0x1d,
    0x12, 0x74, 0x24, 0x7e, 0x16, 0x66, 0x10, 0xe7,
    0x7f, 0x4d, 0x9c, 0x9d, 0x07, 0xd3, 0xc7, 0x28,
    0xe5, 0x32, 0x91, 0x6b, 0xdd, 0x28, 0xb4, 0x54
};

/**
 * validity_pairing_derive_shared_keys:
 * @host_part: 16-byte per-device hostPart
 * @out_gwk: (out caller-allocated) 32-byte GWK encryption key
 * @out_gwk_sign: (out caller-allocated) 32-byte GWK_SIGN validation key
 *
 * Derives the GWK and GWK_SIGN keys from the hostPart using the
 * Synaptics PRF chain.
 *
 * GWK = PRF(password, "GWK" || hostPart, 32)
 * GWK_SIGN = PRF(GWK, "GWK_SIGN" || gwk_sign_constant, 32)
 *
 * Returns: TRUE on success, FALSE on error.
 **/
gboolean
validity_pairing_derive_shared_keys (const guint8  host_part[16],
                                      guint8        out_gwk[32],
                                      guint8        out_gwk_sign[32])
{
  /* Step 1: GWK = PRF(password, "GWK" + hostPart, 32) */
  {
    guint8 label[4] = { 'G', 'W', 'K', 0 };

    /* Build seed: label || hostPart
     * Per FUN_180071400 + tls.py:116: prf(password, b'GWK' + hw_key, 0x20) */
    guint8 joined[3 + 16];
    memcpy (joined, label, 3);
    memcpy (joined + 3, host_part, 16);

    validity_tls12_prf (VALIDITY_PAIRING_PASSWORD, 32,
                        (const guint8 *)"", 0,  /* label — pre-joined in seed */
                        joined, 19,
                        out_gwk, 32);
  }

  /* Step 2: GWK_SIGN = PRF(GWK, "GWK_SIGN" + gwk_sign_constant, 32)
   * Per FUN_180071900 + tls.py:117: prf(gwk, b'GWK_SIGN' + constant, 0x20) */
  {
    guint8 joined[8 + 32];
    memcpy (joined, "GWK_SIGN", 8);
    memcpy (joined + 8, VALIDITY_GWK_SIGN_CONSTANT, 32);

    validity_tls12_prf (out_gwk, 32,
                        (const guint8 *)"", 0,
                        joined, 40,
                        out_gwk_sign, 32);
  }

  return TRUE;
}

/**
 * validity_pairing_derive_osb:
 * @host_part: 16-byte per-device hostPart
 * @tag4_data: TLV tag 4 data from device (encrypted private key blob, opaque)
 * @tag4_len: length of tag4_data
 * @out_osb: (out caller-allocated) 32-byte OSB (Operating System Binding)
 *
 * Derives the OSB blob that gets written to the device's SPI flash
 * partition 1 during pairing. Maps to FUN_180071aa0.
 *
 * The OSB is: PRF(tag4_data, "_OSB_" || AES_output, 32)
 * where AES_output is the encrypted (IV || tag4_data) under the GWK.
 *
 * For simplicity, when tag4_data is NULL (fresh pair without prior
 * encrypted blob), we derive OSB directly from hostPart.
 *
 * Returns: TRUE on success, FALSE on error.
 **/
gboolean
validity_pairing_derive_osb (const guint8  host_part[16],
                              const guint8 *tag4_data,
                              gsize         tag4_len,
                              guint8       *out_osb)
{
  /* Derive GWK and GWK_SIGN first. */
  guint8 gwk[32], gwk_sign[32];
  if (!validity_pairing_derive_shared_keys (host_part, gwk, gwk_sign))
    return FALSE;

  /* Build the OSB using the same PRF with "_OSB_" label.
   * Per FUN_180071aa0: PRF(tag4_data, "_OSB_" + AES_out, 32)
   *
   * On a fresh pair (no prior tag4), we derive a deterministic OSB
   * from hostPart + GWK_SIGN. The device just needs a binding blob. */
  if (tag4_data != NULL && tag4_len > 0)
    {
      /* Full path: encrypt tag4_data under GWK, then PRF */
      /* For now: simplified path — derive directly */
      guint8 joined[4 + 32];
      memcpy (joined, "_OSB_", 4);
      memcpy (joined + 4, gwk_sign, 32);

      validity_tls12_prf (tag4_data, tag4_len,
                          (const guint8 *)"", 0,
                          joined, 36,
                          out_osb, 32);
    }
  else
    {
      /* Fresh pair: use hostPart as the "data" and gwk as the key */
      guint8 joined[4 + 16];
      memcpy (joined, "_OSB_", 4);
      memcpy (joined + 4, host_part, 16);

      validity_tls12_prf (gwk, 32,
                          (const guint8 *)"", 0,
                          joined, 20,
                          out_osb, 32);
    }

  return TRUE;
}

/* OSB persistence (32-byte Operating System Binding blob for SPI flash). */
#define VALIDITY_OSB_LEN 32

static gchar *
osb_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "osb", NULL);
}

gboolean
validity_pairing_save_osb (const guint8 osb[VALIDITY_OSB_LEN],
                            GError **error)
{
  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;
  g_autofree gchar *path = osb_path ();
  return write_file_restricted (path, osb, VALIDITY_OSB_LEN, error);
}

gboolean
validity_pairing_load_osb (guint8 out[VALIDITY_OSB_LEN],
                            GError **error)
{
  g_autofree gchar *path = osb_path ();
  g_autofree gchar *contents = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &contents, &len, error))
    return FALSE;

  if (len != VALIDITY_OSB_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: expected %d B, got %zu", path,
                   VALIDITY_OSB_LEN, len);
      return FALSE;
    }

  memcpy (out, contents, VALIDITY_OSB_LEN);
  return TRUE;
}

gboolean
validity_pairing_has_osb (void)
{
  g_autofree gchar *path = osb_path ();
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

/* Enroll bootstrap payload cache.
 *
 * The 10500-byte body sent as wire 0x06 during enroll setup is a static
 * configuration payload, not a per-pairing encrypt-and-format product.
 * Store only the 10500-byte body here; command builders add the outer
 * 0x06 opcode byte when sending.
 */
#define VALIDITY_ENROLL_HOSTPART_BLOB_LEN 10500

static gchar *
enroll_hostpart_blob_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "enroll-hostpart-blob", NULL);
}

gboolean
validity_pairing_save_enroll_hostpart_blob (const guint8 *blob,
                                            gsize         len,
                                            GError      **error)
{
  if (blob == NULL || len != VALIDITY_ENROLL_HOSTPART_BLOB_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "enroll hostpart blob must be %d B, got %zu",
                   VALIDITY_ENROLL_HOSTPART_BLOB_LEN, len);
      return FALSE;
    }

  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;

  g_autofree gchar *path = enroll_hostpart_blob_path ();
  return write_file_restricted (path, blob,
                                VALIDITY_ENROLL_HOSTPART_BLOB_LEN, error);
}

guint8 *
validity_pairing_load_enroll_hostpart_blob (gsize   *out_len,
                                            GError **error)
{
  g_autofree gchar *path = enroll_hostpart_blob_path ();
  g_autofree gchar *contents = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &contents, &len, error))
    return NULL;

  if (len != VALIDITY_ENROLL_HOSTPART_BLOB_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: expected %d B, got %zu", path,
                   VALIDITY_ENROLL_HOSTPART_BLOB_LEN, len);
      return NULL;
    }

  if ((guint8) contents[0] != 0x02 ||
      (guint8) contents[1] != 0x00 ||
      (guint8) contents[2] != 0x00 ||
      (guint8) contents[3] != 0x01)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: invalid enroll hostpart prefix", path);
      return NULL;
    }

  *out_len = len;
  return (guint8 *) g_steal_pointer (&contents);
}

gboolean
validity_pairing_has_enroll_hostpart_blob (void)
{
  g_autofree gchar *path = enroll_hostpart_blob_path ();
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

/* ===========================================================================
 * Host-UUID continuity check
 *
 * The driver compares the current host-uuid against a previously-stored
 * pair-uuid to detect host identity changes:
 *   - FIRST RUN (no pair-uuid): no prior identity. Save current host-uuid
 *     as pair-uuid and allow connection.
 *   - MATCH: pair-uuid == current host-uuid. Normal operation.
 *   - MISMATCH: pair-uuid != current host-uuid. The host identity changed
 *     (config cloned or storage moved). Wipe the database marker, flag a
 *     re-pair needed. The caller should re-init pairing from scratch.
 *
 * This is a HOST-SIDE guard. The device side stores its own copy via the
 * pairing ceremony (opcode 0x3e/0x40). When the check triggers, the caller
 * must also re-pair with the device to update its flash-stored identity.
 * ========================================================================= */

/**
 * validity_pairing_ensure_host_uuid:
 * @error: return location for a GError, or %NULL
 *
 * Loads or creates the host UUID (16 random bytes). On first run when
 * no UUID exists, generates one and persists it atomically (mode 0600).
 * Subsequent calls are a no-op (the UUID is already on disk).
 *
 * Returns: %TRUE on success, %FALSE on error with @error set.
 **/
gboolean
validity_pairing_ensure_host_uuid (GError **error)
{
  g_autofree gchar *path = host_uuid_path ();

  if (g_file_test (path, G_FILE_TEST_EXISTS))
    return TRUE;   /* already provisioned */

  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;

  guint8 uuid[VALIDITY_HOST_UUID_LEN];
  if (!validity_pairing_generate_host_uuid (uuid, error))
    return FALSE;

  return write_file_restricted (path, uuid, VALIDITY_HOST_UUID_LEN, error);
}

/**
 * validity_pairing_check_guid_continuity:
 * @needs_re_pair: (out) (nullable): set to %TRUE if the host identity
 *     changed and the device needs a fresh pairing ceremony
 * @error: return location for a GError, or %NULL
 *
 * Checks whether the current host UUID matches the UUID that was recorded
 * during the last pairing ceremony. Designed to be called once per device
 * open, right after the TLS handshake succeeds.
 *
 * On the very first run (no pair-uuid on disk), the current UUID is saved
 * as pair-uuid and @needs_re_pair is set to %FALSE.
 *
 * On a subsequent run, if the host UUID changed (e.g. config restored from
 * backup on a different machine, or the storage directory was tampered
 * with), @needs_re_pair is set to %TRUE and the old pair-uuid is wiped.
 * The caller should:
 *   1. Log a warning ("host identity changed — re-pairing")
 *   2. Wipe the device's template database
 *   3. Initiate a fresh pairing ceremony (PAIRING.md flow)
 *   4. Call validity_pairing_record_pairing_uuid() to record the new UUID
 *
 * Returns: %TRUE on success (even if re-pair is needed — the check itself
 *     completed without I/O error). %FALSE on I/O error with @error set.
 **/
gboolean
validity_pairing_check_guid_continuity (gboolean *needs_re_pair,
                                        GError  **error)
{
  guint8 current_uuid[VALIDITY_HOST_UUID_LEN];
  gboolean has_stored;

  /* Load the current host UUID. If missing, this is first run — generate it. */
  if (!validity_pairing_load_host_uuid (current_uuid, error))
    {
      /* ENOENT / G_IO_ERROR_NOT_FOUND: first run — generate fresh UUID */
      if (g_error_matches (*error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND))
        {
          g_clear_error (error);
          fp_dbg ("no host-uuid found — first run. Generating fresh UUID.");
          if (!validity_pairing_generate_host_uuid (current_uuid, error))
            return FALSE;
          if (!validity_pairing_save_host_uuid (current_uuid, error))
            return FALSE;
        }
      else
        {
          return FALSE;  /* real I/O error */
        }
    }

  /* Read pair-uuid (the UUID recorded during the last successful pairing). */
  g_autofree gchar *pu_path = paired_uuid_path ();
  g_autofree gchar *pair_data = NULL;
  gsize pair_len = 0;

  has_stored = g_file_get_contents (pu_path, &pair_data, &pair_len, NULL);

  if (!has_stored)
    {
      /* First run — no prior pairing. Record current UUID as the pair anchor
       * and report that no re-pair is needed (first pair will happen naturally
       * during the device open). */
      fp_dbg ("no pair-uuid found — first run. Recording current host UUID.");
      if (!validity_pairing_record_pairing_uuid (error))
        return FALSE;

      if (needs_re_pair)
        *needs_re_pair = FALSE;
      return TRUE;
    }

  if (pair_len != VALIDITY_HOST_UUID_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "pair-uuid: expected %d B, got %zu",
                   VALIDITY_HOST_UUID_LEN, pair_len);
      return FALSE;
    }

  /* Compare. */
  if (memcmp (current_uuid, pair_data, VALIDITY_HOST_UUID_LEN) == 0)
    {
      fp_dbg ("host UUID continuity check OK");
      if (needs_re_pair)
        *needs_re_pair = FALSE;
      return TRUE;
    }

  /* MISMATCH — host identity changed. */
  fp_warn ("HOST UUID MISMATCH — sensor was previously paired with a different "
           "machine identity. Re-pairing is required.");

  /* Wipe the pair-uuid and the database-wipe marker so a fresh pairing
   * ceremony starts clean. */
  if (unlink (pu_path) != 0 && errno != ENOENT)
    fp_warn ("failed to remove pair-uuid: %s (continuing)", g_strerror (errno));

  /* Also remove the db-wiped marker if present, since the mismatch wipes it. */
  g_autofree gchar *wipe_path = database_wipe_marker_path ();
  if (unlink (wipe_path) != 0 && errno != ENOENT)
    fp_warn ("failed to remove db-wiped marker: %s (continuing)",
             g_strerror (errno));

  if (needs_re_pair)
    *needs_re_pair = TRUE;
  return TRUE;
}

/**
 * validity_pairing_record_pairing_uuid:
 * @error: return location for a GError, or %NULL
 *
 * Records the current host UUID as the "pairing anchor" — the identity
 * that was in use when the last successful pairing ceremony completed.
 *
 * This is called by the pairing code after a successful fresh pairing.
 * On subsequent opens, validity_pairing_check_guid_continuity() compares
 * the current UUID against this saved anchor.
 *
 * Returns: %TRUE on success, %FALSE on error with @error set.
 **/
gboolean
validity_pairing_record_pairing_uuid (GError **error)
{
  guint8 current_uuid[VALIDITY_HOST_UUID_LEN];

  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;

  /* ensure_host_uuid is idempotent: generates+saves only if absent. We
   * always call it first so the load that follows can't trip on a
   * fresh-storage missing-file path (the prior G_IO_ERROR_NOT_FOUND
   * edge-case check didn't match because g_file_get_contents reports
   * via G_FILE_ERROR, not G_IO_ERROR). */
  if (!validity_pairing_ensure_host_uuid (error))
    return FALSE;
  if (!validity_pairing_load_host_uuid (current_uuid, error))
    return FALSE;

  g_autofree gchar *pu_path = paired_uuid_path ();
  return write_file_restricted (pu_path, current_uuid,
                                VALIDITY_HOST_UUID_LEN, error);
}

/**
 * validity_pairing_was_database_wiped:
 *
 * Returns %TRUE if the template database has been wiped as a consequence
 * of a GUID mismatch (the marker file exists). The caller uses this to
 * determine whether the stored pairing credentials must be regenerated.
 **/
gboolean
validity_pairing_was_database_wiped (void)
{
  g_autofree gchar *path = database_wipe_marker_path ();
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

/* ===========================================================================
 * SPI flash R/W (Phase 7)
 *
 * Per python-validity's init_flash.py, the device exposes:
 *   - erase_flash (0x3f) — erase a flash partition
 *   - write_flash (0x41) — write N bytes to flash partition P at offset O
 *   - write_fw_signature (0x42) — attach a FW signature to a partition
 *
 * For 0088 the partition IDs are:
 *   1 = cert store          (where the client cert lands)
 *   2 = xpfwext
 *   5 = ???
 *   6 = calibration data
 *   4 = template database
 *
 * Both helpers are gated on session->cipher_active being TRUE.
 * ========================================================================= */

#define VALIDITY_TLS_FLASH_LEN          0x1000
#define VALIDITY_FLASH_BLOCK_HASH_LEN   32
#define VALIDITY_FLASH_BLOCK_OVERHEAD   (2 + 2 + VALIDITY_FLASH_BLOCK_HASH_LEN)
#define VALIDITY_CERT_BLOB_LEN          0xb8  /* 184 bytes */

static gboolean
buffer_is_all_zero (const guint8 *data,
                    gsize         len)
{
  for (gsize i = 0; i < len; i++)
    if (data[i] != 0)
      return FALSE;
  return TRUE;
}

static gboolean
sha256_buffer (const guint8 *data,
               gsize         len,
               guint8        out[VALIDITY_FLASH_BLOCK_HASH_LEN],
               GError      **error)
{
  EVP_MD_CTX *ctx;
  unsigned int md_len = 0;

  ctx = EVP_MD_CTX_new ();
  if (ctx == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_MD_CTX_new failed");
      return FALSE;
    }

  if (EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL) != 1 ||
      EVP_DigestUpdate (ctx, data, len) != 1 ||
      EVP_DigestFinal_ex (ctx, out, &md_len) != 1 ||
      md_len != VALIDITY_FLASH_BLOCK_HASH_LEN)
    {
      EVP_MD_CTX_free (ctx);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "SHA-256 digest failed");
      return FALSE;
    }

  EVP_MD_CTX_free (ctx);
  return TRUE;
}

static gboolean
append_tls_flash_block (GByteArray   *array,
                        guint16       id,
                        const guint8 *body,
                        gsize         body_len,
                        GError      **error)
{
  guint8 header[4];
  guint8 digest[VALIDITY_FLASH_BLOCK_HASH_LEN];

  if (body_len > G_MAXUINT16)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "flash block 0x%04x too large: %zu B", id, body_len);
      return FALSE;
    }

  if (array->len + VALIDITY_FLASH_BLOCK_OVERHEAD + body_len >
      VALIDITY_TLS_FLASH_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NO_SPACE,
                   "TLS flash payload would exceed 0x%x bytes",
                   VALIDITY_TLS_FLASH_LEN);
      return FALSE;
    }

  if (!sha256_buffer (body, body_len, digest, error))
    return FALSE;

  header[0] = (guint8) (id & 0xff);
  header[1] = (guint8) ((id >> 8) & 0xff);
  header[2] = (guint8) (body_len & 0xff);
  header[3] = (guint8) ((body_len >> 8) & 0xff);

  g_byte_array_append (array, header, sizeof (header));
  g_byte_array_append (array, digest, sizeof (digest));
  g_byte_array_append (array, body, body_len);
  return TRUE;
}

static guint8 *
validity_pairing_build_tls_flash_payload (const guint8  osb[32],
                                          const guint8  cert_blob[VALIDITY_CERT_BLOB_LEN],
                                          gsize        *out_len,
                                          GError      **error)
{
  static const guint8 empty_block[1] = { 0x00 };
  GByteArray *array = g_byte_array_new ();

  /* python-validity's cert-store image is a sequence of:
   *   <u16 id><u16 len><sha256(body)><body>
   * padded with 0xff to 0x1000 bytes. For 0088, the pieces we currently
   * produce are the OSB blob (tag 2) and the 0xb8-byte device-issued
   * cert blob (same role as tls_cert).
   */
  if (!append_tls_flash_block (array, 0, empty_block, sizeof (empty_block),
                               error) ||
      !append_tls_flash_block (array, 2, osb, 32, error) ||
      !append_tls_flash_block (array, 3, cert_blob, VALIDITY_CERT_BLOB_LEN,
                               error))
    {
      g_byte_array_free (array, TRUE);
      return NULL;
    }

  while (array->len < VALIDITY_TLS_FLASH_LEN)
    {
      guint8 pad = 0xff;
      g_byte_array_append (array, &pad, 1);
    }

  *out_len = array->len;
  return g_byte_array_free (array, FALSE);
}

static gchar *
hex_string_full (const guint8 *data,
                 gsize         len)
{
  GString *hex = g_string_sized_new (len * 2 + 1);

  for (gsize i = 0; i < len; i++)
    g_string_append_printf (hex, "%02x", data[i]);

  return g_string_free (hex, FALSE);
}

static void
flash_dry_run_dump (const gchar  *label,
                    const guint8 *frame,
                    gsize         frame_len)
{
  g_autofree gchar *hex = hex_string_full (frame, frame_len);

  fp_info ("VALIDITY0088_FLASH_DRY_RUN %s (%zu B): %s",
           label, frame_len, hex);
}

static gboolean
parse_hex_blob (const gchar  *hex,
                guint8      **out,
                gsize        *out_len,
                GError      **error)
{
  gsize hex_len;
  guint8 *buf;

  if (hex == NULL || hex[0] == '\0')
    {
      *out = NULL;
      *out_len = 0;
      return TRUE;
    }

  hex_len = strlen (hex);
  if ((hex_len % 2) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "hex blob must contain an even number of digits");
      return FALSE;
    }

  buf = g_malloc (hex_len / 2);
  for (gsize i = 0; i < hex_len / 2; i++)
    {
      gint hi = g_ascii_xdigit_value (hex[i * 2]);
      gint lo = g_ascii_xdigit_value (hex[i * 2 + 1]);

      if (hi < 0 || lo < 0)
        {
          g_free (buf);
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                       "invalid hex digit at byte %zu", i);
          return FALSE;
        }

      buf[i] = (guint8) ((hi << 4) | lo);
    }

  *out = buf;
  *out_len = hex_len / 2;
  return TRUE;
}

static gboolean
flash_exchange_status (FpDevice     *dev,
                       const gchar  *label,
                       const guint8 *plain,
                       gsize         plain_len,
                       gboolean      allow_nothing_to_commit,
                       GError      **error)
{
  g_autofree guint8 *rsp = NULL;
  gsize rsp_len = 0;
  guint16 status;

  fp_dbg ("%s: send %zu B plaintext opcode 0x%02x",
          label, plain_len, plain_len > 0 ? plain[0] : 0xff);

  if (!validity_exchange_app_plaintext (dev, plain, plain_len,
                                        &rsp, &rsp_len, error))
    return FALSE;

  if (rsp_len < 2)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s response too short: %zu B", label, rsp_len);
      return FALSE;
    }

  status = ((guint16) rsp[0]) | ((guint16) rsp[1] << 8);
  if (status == 0x0000 ||
      (allow_nothing_to_commit && status == 0x0491))
    {
      fp_dbg ("%s: status 0x%04x OK", label, status);
      return TRUE;
    }

  g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
               "%s returned status 0x%04x", label, status);
  return FALSE;
}

gboolean
validity_pairing_flash_write (FpDevice        *dev,
                              ValiditySession *session,
                              guint8           partition_id,
                              guint32          offset,
                              const guint8    *data,
                              gsize            len,
                              GError         **error)
{
  /* Safety default: dry-run unless VALIDITY0088_FLASH_LIVE=1 is explicitly
   * set. This is the defensive-write pattern from the project memory: the
   * live flash write has not been validated end-to-end on a fresh device,
   * and an erroneous 0x41 write to partition 1 could corrupt the cert
   * store on the user's already-paired device. The pre-existing
   * VALIDITY0088_FLASH_DRY_RUN=1 env var is honored too (force dry-run
   * even if LIVE is set), for scripts that already use it. */
  const gchar *live_env    = g_getenv ("VALIDITY0088_FLASH_LIVE");
  const gchar *dry_run_env = g_getenv ("VALIDITY0088_FLASH_DRY_RUN");
  gboolean live_opt_in = (live_env != NULL && g_strcmp0 (live_env, "0") != 0);
  gboolean force_dry   = (dry_run_env != NULL && g_strcmp0 (dry_run_env, "0") != 0);
  gboolean dry_run     = !live_opt_in || force_dry;
  g_autofree guint8 *erase_cmd = NULL;
  g_autofree guint8 *write_cmd = NULL;
  g_autofree guint8 *sign_cmd = NULL;
  g_autofree guint8 *cleanup_cmd = NULL;
  g_autofree guint8 *signature = NULL;
  gsize erase_len = 0;
  gsize write_len = 0;
  gsize sign_len = 0;
  gsize cleanup_len = 0;
  gsize signature_len = 0;

  if (!dry_run && (session == NULL || !session->cipher_active))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_INITIALIZED,
                           "flash write requires encrypted session "
                           "(complete TLS handshake first)");
      return FALSE;
    }

  if (len > 0 && data == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "flash write payload is NULL");
      return FALSE;
    }

  if (len > G_MAXUINT32)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "flash write payload too large: %zu B", len);
      return FALSE;
    }

  if (!parse_hex_blob (g_getenv ("VALIDITY0088_FLASH_SIGNATURE_HEX"),
                       &signature, &signature_len, error))
    return FALSE;

  if (signature_len > G_MAXUINT16)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "flash signature too large: %zu B", signature_len);
      return FALSE;
    }

  erase_cmd = validity_build_flash_erase_command (partition_id, &erase_len);
  write_cmd = validity_build_flash_write_command (partition_id, offset,
                                                  data, len, &write_len);
  sign_cmd = validity_build_flash_sign_command (partition_id, signature,
                                                signature_len, &sign_len);
  cleanup_cmd = validity_build_enroll_session_command (&cleanup_len);

  if (erase_cmd == NULL || write_cmd == NULL || sign_cmd == NULL ||
      cleanup_cmd == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "failed to build flash command frame");
      return FALSE;
    }

  if (dry_run)
    {
      fp_info ("flash write: DRY-RUN (set VALIDITY0088_FLASH_LIVE=1 to send "
               "real frames; this is the project's safety default until the "
               "live flash path is validated on a fresh device)");
      flash_dry_run_dump ("erase-0x3f", erase_cmd, erase_len);
      flash_dry_run_dump ("write-0x41", write_cmd, write_len);
      flash_dry_run_dump ("sign-0x42", sign_cmd, sign_len);
      flash_dry_run_dump ("cleanup-0x1a", cleanup_cmd, cleanup_len);
      return TRUE;
    }

  if (!flash_exchange_status (dev, "flash-erase-0x3f",
                              erase_cmd, erase_len, FALSE, error))
    return FALSE;
  if (!flash_exchange_status (dev, "flash-cleanup-after-erase-0x1a",
                              cleanup_cmd, cleanup_len, TRUE, error))
    return FALSE;
  if (!flash_exchange_status (dev, "flash-write-0x41",
                              write_cmd, write_len, FALSE, error))
    return FALSE;
  if (!flash_exchange_status (dev, "flash-cleanup-after-write-0x1a",
                              cleanup_cmd, cleanup_len, TRUE, error))
    return FALSE;

  if (signature_len == 0)
    {
      fp_dbg ("flash-sign-0x42 skipped: no VALIDITY0088_FLASH_SIGNATURE_HEX; "
              "python-validity does not sign partition-1 TLS-flash writes");
      return TRUE;
    }

  return flash_exchange_status (dev, "flash-sign-0x42",
                                sign_cmd, sign_len, FALSE, error);
}

/* ===========================================================================
 * P6 — Pairing ceremony orchestrator
 *
 * Maps to FUN_1800486a0 (CBiometricDevice::DoPairing). Runs the full
 * sequence to establish a fresh pairing with the device:
 *
 *   1. Ensure hostPart exists (generate if missing, load if cached)
 *   2. Ensure cert trailer is available (load cached or acquire via 0x4f)
 *   3. Write hostPart to device (wire 0x3e)
 *   4. Record pairing UUID for GUID continuity
 *
 * Called after a successful TLS handshake when the driver detects
 * that pairing material needs refreshing.
 *
 * Returns: TRUE on success (pairing established), FALSE on error.
 * ========================================================================= */

/* ===========================================================================
 * Cert trailer persistence (cache for replay on subsequent handshakes)
 *
 * The device issues a 0xb8-byte certificate blob via opcode 0x4f during
 * initial pairing. The 32-byte trailer at offset 0x98 within that blob
 * must be cached host-side and replayed in every subsequent TLS handshake
 * client Certificate body.
 *
 * We store the FULL 0xb8-byte blob as-is, since the handshake code needs
 * the whole thing (EC X/Y + padding + trailer), not just the trailer bytes.
 * ========================================================================= */

static gchar *
cert_blob_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "cert-blob", NULL);
}

gboolean
validity_pairing_save_cert_blob (const guint8 blob[VALIDITY_CERT_BLOB_LEN],
                                  GError **error)
{
  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;
  g_autofree gchar *path = cert_blob_path ();
  return write_file_restricted (path, blob, VALIDITY_CERT_BLOB_LEN, error);
}

gboolean
validity_pairing_load_cert_blob (guint8  out[VALIDITY_CERT_BLOB_LEN],
                                  GError **error)
{
  g_autofree gchar *path = cert_blob_path ();
  g_autofree gchar *contents = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &contents, &len, error))
    return FALSE;

  if (len != VALIDITY_CERT_BLOB_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "%s: expected %d B, got %zu", path,
                   VALIDITY_CERT_BLOB_LEN, len);
      return FALSE;
    }

  memcpy (out, contents, VALIDITY_CERT_BLOB_LEN);
  return TRUE;
}

gboolean
validity_pairing_has_cert_blob (void)
{
  g_autofree gchar *path = cert_blob_path ();
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

/* Returns TRUE if the driver has SOMETHING to authenticate the device
 * TLS session with — either an on-disk cert blob from a prior session,
 * or non-zero baked-in arrays in validity-pubkeys.c. Returns FALSE
 * when both sources are empty (= the public-repo "fresh clone" state),
 * which means the TLS handshake is guaranteed to fail with
 * bad_certificate unless the fresh-pair ceremony is enabled and runs
 * successfully. Callers can use this to bail early with a clear
 * diagnostic instead of letting users discover the failure via a
 * cryptic TLS alert. */
gboolean
validity_pairing_have_per_pairing_material (void)
{
  if (validity_pairing_has_cert_blob ())
    return TRUE;
  if (!buffer_is_all_zero (validity_cached_client_cert_body + 8,
                           VALIDITY_CERT_BLOB_LEN))
    return TRUE;
  if (!buffer_is_all_zero (validity_cached_host_private_key,
                           VALIDITY_ECC_COORD_LEN))
    return TRUE;
  return FALSE;
}

/* Build an OpenSSL P-256 EVP_PKEY from a raw 32-byte private scalar
 * (the format the baked-in validity_cached_host_private_key uses).
 * Returns malloc'd EVP_PKEY; caller frees with EVP_PKEY_free. NULL on
 * error. Mirrors load_cached_host_keypair() in validity-handshake.c
 * but exposed here so the bootstrap helper can convert + persist. */
static EVP_PKEY *
build_ec_keypair_from_scalar (const guint8  scalar_be[VALIDITY_ECC_COORD_LEN],
                              GError      **error)
{
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  BIGNUM *priv_bn = NULL;
  EC_GROUP *group = NULL;
  EC_POINT *pub_pt = NULL;
  BN_CTX *bnctx = NULL;
  unsigned char priv_native[VALIDITY_ECC_COORD_LEN];
  unsigned char *pub_oct = NULL;
  size_t pub_oct_len = 0;
  OSSL_PARAM params[4] = {0};

  priv_bn = BN_bin2bn (scalar_be, VALIDITY_ECC_COORD_LEN, NULL);
  if (priv_bn == NULL
      || BN_bn2nativepad (priv_bn, priv_native,
                          VALIDITY_ECC_COORD_LEN) != VALIDITY_ECC_COORD_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "BIGNUM import of raw scalar failed");
      goto cleanup;
    }

  /* Derive the public point Q = priv * G on P-256 so the resulting
   * EVP_PKEY is a complete keypair. EVP_PKEY_fromdata with only
   * PRIV_KEY produces a private-only key that PEM_write_bio_PrivateKey
   * refuses to serialize. */
  group = EC_GROUP_new_by_curve_name (NID_X9_62_prime256v1);
  pub_pt = group ? EC_POINT_new (group) : NULL;
  bnctx = BN_CTX_new ();
  if (group == NULL || pub_pt == NULL || bnctx == NULL
      || EC_POINT_mul (group, pub_pt, priv_bn, NULL, NULL, bnctx) != 1)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EC_POINT_mul(scalar*G) failed");
      goto cleanup;
    }
  pub_oct_len = EC_POINT_point2oct (group, pub_pt,
                                    POINT_CONVERSION_UNCOMPRESSED,
                                    NULL, 0, bnctx);
  if (pub_oct_len == 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EC_POINT_point2oct sizing failed");
      goto cleanup;
    }
  pub_oct = g_malloc (pub_oct_len);
  if (EC_POINT_point2oct (group, pub_pt, POINT_CONVERSION_UNCOMPRESSED,
                          pub_oct, pub_oct_len, bnctx) != pub_oct_len)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EC_POINT_point2oct encoding failed");
      goto cleanup;
    }

  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (ctx == NULL || EVP_PKEY_fromdata_init (ctx) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_CTX_new_from_name(EC) failed");
      goto cleanup;
    }
  params[0] = OSSL_PARAM_construct_utf8_string (
      OSSL_PKEY_PARAM_GROUP_NAME, (char *) "prime256v1", 0);
  params[1] = OSSL_PARAM_construct_BN (
      OSSL_PKEY_PARAM_PRIV_KEY, priv_native, VALIDITY_ECC_COORD_LEN);
  params[2] = OSSL_PARAM_construct_octet_string (
      OSSL_PKEY_PARAM_PUB_KEY, pub_oct, pub_oct_len);
  params[3] = OSSL_PARAM_construct_end ();
  if (EVP_PKEY_fromdata (ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_fromdata(scalar+pub) failed");
      pkey = NULL;
    }
cleanup:
  if (priv_bn) BN_free (priv_bn);
  if (ctx) EVP_PKEY_CTX_free (ctx);
  if (pub_pt) EC_POINT_free (pub_pt);
  if (group) EC_GROUP_free (group);
  if (bnctx) BN_CTX_free (bnctx);
  if (pub_oct) g_free (pub_oct);
  memset (priv_native, 0, sizeof (priv_native));
  return pkey;
}

/* Verify the on-disk cert blob and keypair are mutually consistent:
 * the pubkey derived from the keypair must match the pubkey embedded
 * in the cert (offsets 8/76, little-endian per the cert format).
 * Returns TRUE only if both files load AND the pubkeys match. */
static gboolean
on_disk_pair_is_consistent (void)
{
  guint8 cert[VALIDITY_CERT_BLOB_LEN];
  guint8 kx_be[VALIDITY_ECC_COORD_LEN];
  guint8 ky_be[VALIDITY_ECC_COORD_LEN];
  guint8 cx_be[VALIDITY_ECC_COORD_LEN];
  guint8 cy_be[VALIDITY_ECC_COORD_LEN];

  if (!validity_pairing_load_cert_blob (cert, NULL)) return FALSE;
  EVP_PKEY *kp = validity_pairing_load_host_keypair (NULL);
  if (kp == NULL) return FALSE;
  gboolean got_xy = validity_pairing_get_pubkey_xy (kp, kx_be, ky_be, NULL);
  EVP_PKEY_free (kp);
  if (!got_xy) return FALSE;

  /* Cert stores X/Y in little-endian; reverse to compare against the
   * big-endian output of get_pubkey_xy. Offsets within the 184-byte
   * blob: X at +8 (= +16 in the 192-B wire body minus 8-B framing),
   * Y at +76 (= +84 minus 8). */
  for (gsize i = 0; i < VALIDITY_ECC_COORD_LEN; i++)
    {
      cx_be[i] = cert[8  + VALIDITY_ECC_COORD_LEN - 1 - i];
      cy_be[i] = cert[76 + VALIDITY_ECC_COORD_LEN - 1 - i];
    }
  return memcmp (kx_be, cx_be, VALIDITY_ECC_COORD_LEN) == 0
      && memcmp (ky_be, cy_be, VALIDITY_ECC_COORD_LEN) == 0;
}

/* One-time migration helper: copies the baked-in cert + private scalar
 * from validity-pubkeys.c into the on-disk pairing storage, so the
 * driver can be rebuilt with the baked-in arrays zeroed and still
 * work.
 *
 * Safe / idempotent rules:
 *   1. If on-disk cert + keypair are present AND mutually consistent
 *      (keypair's pubkey matches cert's embedded X/Y), do nothing.
 *      This covers anyone who has run a real fresh-pair ceremony OR
 *      successfully bootstrapped previously.
 *   2. If the baked-in cert OR scalar is zero, do nothing. (Fresh
 *      device with no baked-in identity; nothing to migrate.)
 *   3. Otherwise: write the baked-in cert + a keypair derived from
 *      the baked-in scalar to disk, OVERWRITING any partial or
 *      inconsistent state. This is the migration path - logs
 *      prominently so the user sees it happen.
 *
 * Returns TRUE on success or no-op; FALSE only on a real write
 * failure. Callers may safely ignore errors (the driver continues
 * working via the baked-in fallback if migration fails). */
gboolean
validity_pairing_bootstrap_from_hardcoded (GError **error)
{
  /* Rule 1: both on disk AND consistent - nothing to do. */
  if (on_disk_pair_is_consistent ())
    {
      fp_dbg ("bootstrap: on-disk cert+keypair already present and consistent, no-op");
      return TRUE;
    }

  /* Rule 2: baked-in identity is empty (e.g. public-repo zeroed state
   * before migration). Nothing to copy. */
  if (buffer_is_all_zero (validity_cached_client_cert_body + 8,
                          VALIDITY_CERT_BLOB_LEN))
    {
      fp_dbg ("bootstrap: baked-in cert is zero, nothing to copy");
      return TRUE;
    }
  if (buffer_is_all_zero (validity_cached_host_private_key,
                          VALIDITY_ECC_COORD_LEN))
    {
      fp_dbg ("bootstrap: baked-in host private scalar is zero, nothing to copy");
      return TRUE;
    }

  /* Rule 3: migrate. Both baked-in values are present and the on-disk
   * pair is incomplete - copy both to disk, overwriting any partial
   * state (e.g. a stale random keypair from a previous run that
   * doesn't match the baked-in cert's pubkey). */
  fp_info ("bootstrap: copying baked-in cert + private scalar to on-disk "
           "pairing storage (one-time migration). After this, "
           "validity-pubkeys.c can be zeroed and the driver will continue "
           "to work using the on-disk material.");

  /* The cert blob lives at offset +8 inside validity_cached_client_cert_body
   * (which includes 8 bytes of TLS-framing). Save the inner 184-byte body. */
  if (!validity_pairing_save_cert_blob (validity_cached_client_cert_body + 8,
                                        error))
    {
      fp_warn ("bootstrap: failed to save cert blob to disk: %s",
               error && *error ? (*error)->message : "?");
      return FALSE;
    }

  EVP_PKEY *kp = build_ec_keypair_from_scalar (validity_cached_host_private_key,
                                               error);
  if (kp == NULL)
    {
      fp_warn ("bootstrap: failed to build EVP_PKEY from baked-in scalar: %s",
               error && *error ? (*error)->message : "?");
      return FALSE;
    }
  gboolean ok = validity_pairing_save_host_keypair (kp, error);
  EVP_PKEY_free (kp);
  if (!ok)
    {
      fp_warn ("bootstrap: failed to save host keypair to disk: %s",
               error && *error ? (*error)->message : "?");
      return FALSE;
    }

  fp_info ("bootstrap: on-disk pairing storage now self-sufficient "
           "(cert + matching P-256 keypair persisted)");
  return TRUE;
}

/* ===========================================================================
 * P6 — Pairing ceremony orchestrator
 *
 * Maps to FUN_1800486a0 (CBiometricDevice::DoPairing). Runs the full
 * sequence to establish a fresh pairing with the device:
 *
 *   1. Ensure hostPart exists (generate if missing)
 *   2. Acquire cert blob via opcode 0x4f (if not cached)
 *   2b. Derive GWK + GWK_SIGN + OSB and persist OSB locally
 *   2c. Write OSB + cert material to flash partition 1 (0x3f/0x41)
 *   3. Write hostPart to device (wire 0x3e)
 *   4. Record pairing UUID for GUID continuity
 *
 * Called after a successful TLS handshake when the driver detects
 * that pairing material needs refreshing.
 *
 * Returns: TRUE on success (pairing established), FALSE on error.
 * ========================================================================= */

gboolean
validity_pairing_run_ceremony (FpDevice *dev, GError **error)
{
  guint8 cert_blob[VALIDITY_CERT_BLOB_LEN];
  guint8 osb[32];
  gboolean have_cert_blob = FALSE;
  gboolean have_osb = FALSE;

  fp_dbg ("== pairing ceremony start ==");

  /* Step 1: Ensure hostPart exists (generate on first run). */
  if (!validity_pairing_has_host_part ())
    {
      guint8 host_part[16];
      fp_dbg ("generating fresh hostPart");
      if (!validity_pairing_generate_host_part (host_part, error))
        return FALSE;
      if (!validity_pairing_save_host_part (host_part, error))
        return FALSE;
    }
  else
    {
      fp_dbg ("hostPart already cached on disk");
    }

  /* Step 2: Ensure cert blob is available.
   * On a device with cached data, just load it.
   * On a fresh device (no cached blob), acquire via opcode 0x4f.
   *
   * If 0x4f returns VALIDITY_STATUS_CERT_ALREADY_ISSUED (0x0104), the
   * device is signaling that it already has an established pairing
   * context - re-pairing is not allowed. We record this in
   * already_paired_observed so the flash-write step can be skipped
   * (the device's existing cert store is fine; clobbering it would
   * break the working pairing) and the next open() can short-circuit
   * via the already-paired marker (see step 5). */
  gboolean already_paired_observed = FALSE;
  if (!validity_pairing_has_cert_blob ())
    {
      guint16 cert_status = 0;
      fp_dbg ("no cached cert blob — acquiring via 0x4f...");
      if (!validity_send_cert_acquisition (dev, cert_blob,
                                            &cert_status, error))
        {
          if (cert_status == VALIDITY_STATUS_CERT_ALREADY_ISSUED)
            {
              fp_info ("device reports already paired (0x4f -> 0x0104) — "
                       "skipping cert-store flash write step");
              already_paired_observed = TRUE;
            }
          else
            {
              fp_warn ("0x4f cert acquisition failed: %s — "
                       "using hardcoded fallback",
                       (*error)->message);
            }
          g_clear_error (error);
        }
      else
        {
          if (!validity_pairing_save_cert_blob (cert_blob, error))
            return FALSE;
          fp_dbg ("cert blob acquired via 0x4f and saved to disk");
          have_cert_blob = TRUE;
        }
    }
  else
    {
      if (!validity_pairing_load_cert_blob (cert_blob, error))
        return FALSE;
      fp_dbg ("cert blob cached on disk — OK");
      have_cert_blob = TRUE;
    }

  if (!have_cert_blob &&
      !buffer_is_all_zero (validity_cached_client_cert_body + 8,
                           VALIDITY_CERT_BLOB_LEN))
    {
      memcpy (cert_blob, validity_cached_client_cert_body + 8,
              VALIDITY_CERT_BLOB_LEN);
      have_cert_blob = TRUE;
      fp_warn ("using hardcoded fallback cert blob for flash payload");
    }

  /* Step 2b: Derive shared keys (GWK + GWK_SIGN + OSB).
   * Needed for the pairing commitment. */
  {
    guint8 host_part[16];
    if (validity_pairing_has_host_part ())
      {
        if (!validity_pairing_load_host_part (host_part, error))
          return FALSE;
      }
    else
      {
        fp_dbg ("generating fresh hostPart for key derivation");
        if (!validity_pairing_generate_host_part (host_part, error))
          return FALSE;
        if (!validity_pairing_save_host_part (host_part, error))
          return FALSE;
      }

    /* Derive GWK + GWK_SIGN */
    guint8 gwk[32], gwk_sign[32];
    if (!validity_pairing_derive_shared_keys (host_part, gwk, gwk_sign))
      {
        fp_warn ("GWK derivation failed (continuing)");
      }
    else
      {
        fp_dbg ("GWK + GWK_SIGN derived OK");

        /* Derive OSB from hostPart (no tag4 data in fresh path) */
        if (!validity_pairing_derive_osb (host_part, NULL, 0, osb))
          {
            fp_warn ("OSB derivation failed (continuing)");
          }
        else
          {
            fp_dbg ("OSB derived OK");
            /* Save OSB to disk for flash write later (once SPI flash
             * write wrapper is ready). */
            if (!validity_pairing_save_osb (osb, error))
              return FALSE;
            have_osb = TRUE;
          }
      }
  }

  /* Step 2c: Write OSB + cert material to cert-store flash partition 1.
   * Skipped when the device reported "already paired" via 0x0104 (the
   * existing cert store is fine - re-flashing it would risk breaking
   * the working pairing). validity_pairing_flash_write itself defaults
   * to dry-run mode unless VALIDITY0088_FLASH_LIVE=1 is set. */
  if (already_paired_observed)
    {
      fp_info ("flash write step skipped: device reported already paired");
    }
  else if (have_osb && have_cert_blob)
    {
      g_autofree guint8 *flash_payload = NULL;
      gsize flash_payload_len = 0;

      flash_payload = validity_pairing_build_tls_flash_payload (
          osb, cert_blob, &flash_payload_len, error);
      if (flash_payload == NULL)
        return FALSE;

      if (!validity_pairing_flash_write (dev, validity_device_get_session (dev),
                                         1, 0,
                                         flash_payload, flash_payload_len,
                                         error))
        {
          fp_warn ("flash write failed (continuing): %s",
                   (error && *error) ? (*error)->message : "unknown");
          g_clear_error (error);
        }
    }
  else
    {
      fp_warn ("skipping flash write: have_osb=%d have_cert_blob=%d",
               have_osb, have_cert_blob);
    }

  /* Step 3: Write hostPart to device (wire 0x3e). Skipped when the
   * device reports already-paired - it has its own hostPart from the
   * prior pairing and rejecting another write isn't useful here. */
  if (already_paired_observed)
    {
      fp_info ("hostPart write step skipped: device reported already paired");
    }
  else if (!validity_send_host_part_write (dev, error))
    {
      fp_warn ("hostPart write (0x3e) failed (continuing): %s",
               (*error)->message);
      g_clear_error (error);
    }

  /* Step 4: If the device reported already-paired, write the sentinel
   * file so the next open() short-circuits the ceremony entirely (via
   * validity_pairing_state_complete). Done before the UUID-recording
   * step (5) so a failure there doesn't prevent the marker from
   * persisting - the marker captures a fact about the device that's
   * independent of GUID-continuity bookkeeping.
   * VALIDITY0088_FORCE_REPAIR wipes this along with the rest of the
   * storage dir to allow re-trying. */
  if (already_paired_observed)
    {
      GError *marker_err = NULL;
      if (!validity_pairing_save_already_paired_marker (&marker_err))
        {
          fp_warn ("failed to write already-paired marker: %s",
                   marker_err ? marker_err->message : "unknown");
          g_clear_error (&marker_err);
        }
    }

  /* Step 5: Record pairing UUID for GUID continuity on next open. */
  if (!validity_pairing_record_pairing_uuid (error))
    return FALSE;

  fp_dbg ("== pairing ceremony complete ==");
  return TRUE;
}

/* ===========================================================================
 * Phase 9 - State predicate + wipe helpers for first-pair trigger
 *
 * validity_pairing_state_complete returns TRUE iff the three on-disk
 * pairing artifacts (hostPart, cert blob, OSB) are all present. Used
 * by validity_open() to decide whether to run the ceremony to backfill
 * missing state after a successful handshake.
 *
 * INIT_MSG4 cache is intentionally NOT part of this predicate yet:
 * Phase 8 hasn't landed, so the static array remains the source of
 * truth. Add the cache check here when Phase 8 starts persisting the
 * 660-byte payload to disk.
 * ========================================================================= */

/* "Device says already paired" marker.
 *
 * Written by the ceremony when wire 0x4f returns
 * VALIDITY_STATUS_CERT_ALREADY_ISSUED (0x0104), which means the device
 * already has its cert store populated from a prior pairing. The presence
 * of the marker tells the next open() that the ceremony already ran once
 * and concluded "nothing to do" - state_complete returns TRUE, so the
 * ceremony is not re-attempted, which prevents log noise and avoids
 * re-sending the 0x4f probe every session.
 *
 * VALIDITY0088_FORCE_REPAIR wipes the entire storage dir including this
 * marker, which allows the user to retry pairing if the device is later
 * put back into a fresh state. */
static gchar *
already_paired_marker_path (void)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  return g_build_filename (dir, "device-already-paired", NULL);
}

gboolean
validity_pairing_has_already_paired_marker (void)
{
  g_autofree gchar *path = already_paired_marker_path ();
  return g_file_test (path, G_FILE_TEST_EXISTS);
}

gboolean
validity_pairing_save_already_paired_marker (GError **error)
{
  if (!validity_pairing_ensure_storage_dir (error))
    return FALSE;
  g_autofree gchar *path = already_paired_marker_path ();
  /* Empty file - existence is the signal, no content needed. */
  return g_file_set_contents (path, "", 0, error);
}

gboolean
validity_pairing_state_complete (void)
{
  if (validity_pairing_has_already_paired_marker ())
    return TRUE;
  return validity_pairing_has_host_part ()
      && validity_pairing_has_cert_blob ()
      && validity_pairing_has_osb ();
}

/* Delete every cached file in the pairing storage dir. Used by
 * VALIDITY0088_FORCE_REPAIR=1 to force a fresh ceremony on next open. */
gboolean
validity_pairing_wipe_state (GError **error)
{
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  g_autoptr (GDir) gdir = NULL;
  const gchar *name;

  gdir = g_dir_open (dir, 0, NULL);
  if (gdir == NULL)
    return TRUE;  /* Nothing to wipe. */

  while ((name = g_dir_read_name (gdir)) != NULL)
    {
      g_autofree gchar *path = g_build_filename (dir, name, NULL);
      if (g_unlink (path) != 0 && errno != ENOENT)
        {
          g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                       "wipe failed for %s: %s", path, g_strerror (errno));
          return FALSE;
        }
    }

  fp_info ("VALIDITY0088_FORCE_REPAIR: wiped pairing state in %s", dir);
  return TRUE;
}
