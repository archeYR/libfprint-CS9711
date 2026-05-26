/*
 * validity-pretls-pair.c — Linux-autonomous fresh-pair ceremony for 06CB:0088.
 *
 * Pre-TLS protocol used to obtain a fresh cert+priv from the device:
 *
 *   1. 0x01 (RomInfo) — plaintext
 *   2. 0x19 (INIT_MSG2) — plaintext
 *   3. 0x06 + 5796 B clean-slate INIT_MSG4 — plaintext
 *   4. 0x4f + 453 B CSR request — plaintext, contains:
 *        [5 B virgin header: 4f 00 00 00 00]
 *        [4 B TLV header:    05 00 bc 01      (tag=5, size=0x01bc=444)]
 *        [184 B cert body containing fresh host X/Y at offsets +8 and +0x4c]
 *        [4 B sig length LE]
 *        [70-72 B DER ECDSA-SHA256 signature, signed by hs_key (LE-reversed)]
 *        [zero padding to 444 B total TLV value]
 *   5. Receive 298 B response containing device-signed cert (status+len+184B body)
 *   6. 0x01 — plaintext (protocol-required repeat)
 *   7. 0x50 — plaintext; receive 926 B response containing device ECDH pubkey
 *      at offsets 534 (X) and 602 (Y), both LE
 *   8. 0x1a — plaintext
 *
 * Persists to the on-disk pairing dir:
 *   cert-blob          (184 B, the device-signed cert body)
 *   host-key.pem       (PEM-encoded fresh host EC P-256 keypair)
 *   device-ecdh-pubkey.bin (64 B, X||Y in BE form — extracted from 0x50 response)
 *
 * After this runs successfully, the regular TLS handshake (in
 * validity-handshake.c) uses cert+priv from disk and the device-ECDH-pubkey
 * from disk (falling back to baked-in if the file is missing).
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "validity.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

/* The well-known Synaptics hardcoded password (same as python-validity
 * uses for 06CB:009A). Used to derive hs_key. */
static const guint8 PASSWORD_HARDCODED[32] = {
  0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
  0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
  0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38,
  0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33,
};

/* Synaptics TLS-1.2 PRF: HMAC-SHA256 chain (matches python-validity). */
static gboolean
synaptics_prf (const guint8 *secret, gsize secret_len,
               const guint8 *seed, gsize seed_len,
               guint8 *out, gsize out_len)
{
  guint8 a[32];
  guint a_len = sizeof (a);
  if (HMAC (EVP_sha256 (), secret, (int) secret_len,
            seed, seed_len, a, &a_len) == NULL)
    return FALSE;

  gsize emitted = 0;
  while (emitted < out_len)
    {
      guint8 block_seed[32 + 256];  /* generous; we always have <128 B seed */
      g_assert (seed_len + 32 <= sizeof (block_seed));
      memcpy (block_seed, a, 32);
      memcpy (block_seed + 32, seed, seed_len);

      guint8 block[32];
      guint block_len = sizeof (block);
      if (HMAC (EVP_sha256 (), secret, (int) secret_len,
                block_seed, 32 + seed_len, block, &block_len) == NULL)
        return FALSE;

      gsize take = MIN (out_len - emitted, (gsize) block_len);
      memcpy (out + emitted, block, take);
      emitted += take;

      /* Advance a */
      if (HMAC (EVP_sha256 (), secret, (int) secret_len,
                a, 32, a, &a_len) == NULL)
        return FALSE;
    }
  return TRUE;
}

/* Compute hs_key (32 B, LE storage form per Synaptics convention). */
static gboolean
compute_hs_key (guint8 hs_key_le[32])
{
  guint8 seed[15 + 16 + 2];
  memcpy (seed, "HS_KEY_PAIR_GEN", 15);
  memcpy (seed + 15, PASSWORD_HARDCODED + 16, 16);
  seed[15 + 16 + 0] = 0xaa;
  seed[15 + 16 + 1] = 0xaa;
  return synaptics_prf (PASSWORD_HARDCODED, 16, seed, sizeof (seed),
                        hs_key_le, 32);
}

/* Build an EVP_PKEY from a BE-encoded 32-byte EC P-256 private scalar. */
static EVP_PKEY *
ec_pkey_from_scalar_be (const guint8 scalar_be[32], GError **error)
{
  EC_KEY *ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
  if (!ec) goto fail;

  BIGNUM *d = BN_bin2bn (scalar_be, 32, NULL);
  if (!d) goto fail;

  if (!EC_KEY_set_private_key (ec, d))
    {
      BN_free (d);
      goto fail;
    }

  /* Compute the public point */
  const EC_GROUP *group = EC_KEY_get0_group (ec);
  EC_POINT *pub = EC_POINT_new (group);
  if (!pub) { BN_free (d); goto fail; }
  if (!EC_POINT_mul (group, pub, d, NULL, NULL, NULL))
    {
      EC_POINT_free (pub);
      BN_free (d);
      goto fail;
    }
  if (!EC_KEY_set_public_key (ec, pub))
    {
      EC_POINT_free (pub);
      BN_free (d);
      goto fail;
    }
  EC_POINT_free (pub);
  BN_free (d);

  EVP_PKEY *pkey = EVP_PKEY_new ();
  if (!pkey) { EC_KEY_free (ec); goto fail; }
  if (EVP_PKEY_assign_EC_KEY (pkey, ec) != 1)
    {
      EVP_PKEY_free (pkey);
      EC_KEY_free (ec);
      goto fail;
    }
  /* pkey now owns ec */
  return pkey;

fail:
  if (ec) EC_KEY_free (ec);
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "failed to build EC_KEY from scalar");
  return NULL;
}

/* Sign `data` with `pkey` using ECDSA-SHA256, return DER-encoded sig.
 * Caller frees with g_free. */
static guint8 *
ecdsa_sha256_sign_der (EVP_PKEY     *pkey,
                       const guint8 *data,
                       gsize         data_len,
                       gsize        *out_sig_len,
                       GError      **error)
{
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  if (!ctx) goto fail;

  if (EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, pkey) != 1) goto fail;
  if (EVP_DigestSignUpdate (ctx, data, data_len) != 1) goto fail;

  gsize sig_len = 0;
  if (EVP_DigestSignFinal (ctx, NULL, &sig_len) != 1) goto fail;
  guint8 *sig = g_malloc (sig_len);
  if (EVP_DigestSignFinal (ctx, sig, &sig_len) != 1) { g_free (sig); goto fail; }

  EVP_MD_CTX_free (ctx);
  *out_sig_len = sig_len;
  return sig;

fail:
  if (ctx) EVP_MD_CTX_free (ctx);
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "ECDSA-SHA256 sign failed");
  return NULL;
}

/* Build the 184-byte candidate cert body (matches FUN_1800672e0). */
static void
build_cert_body (const guint8 x_le[32], const guint8 y_le[32], guint8 out[184])
{
  memset (out, 0, 184);
  /* type=0x17 LE u32 at +0, keylen=0x20 LE u32 at +4 */
  out[0] = 0x17;
  out[4] = 0x20;
  memcpy (out + 8, x_le, 32);
  memcpy (out + 76, y_le, 32);
  /* remainder stays zero */
}

/* Build the full 453-byte 0x4f wire request. Returns malloc'd buffer. */
static guint8 *
build_0x4f_request (const guint8 cert_body[184],
                    const guint8 *sig_der, gsize sig_len,
                    gsize *out_len)
{
  gsize total = 5 + 4 + 444;  /* virgin header + TLV header + 444 B value */
  guint8 *req = g_malloc0 (total);
  /* 5-byte virgin header */
  req[0] = 0x4f;
  /* req[1..4] = zeros, already set by g_malloc0 */
  /* TLV header: tag=5 LE u16, size=0x01bc LE u16 */
  req[5] = 0x05; req[6] = 0x00;
  req[7] = 0xbc; req[8] = 0x01;
  /* cert body */
  memcpy (req + 9, cert_body, 184);
  /* sig length LE u32 at offset 9+184 = 193 */
  req[193] = (guint8) (sig_len & 0xff);
  req[194] = (guint8) ((sig_len >> 8) & 0xff);
  req[195] = (guint8) ((sig_len >> 16) & 0xff);
  req[196] = (guint8) ((sig_len >> 24) & 0xff);
  /* signature at offset 197 */
  memcpy (req + 197, sig_der, sig_len);
  /* remainder of TLV value (up to offset 9+444=453) stays zero */
  *out_len = total;
  return req;
}

/* Send wire then read response. Returns malloc'd response buffer. */
static guint8 *
exchange (FpDevice *dev, const guint8 *out, gsize out_len,
          gsize *in_len, GError **error)
{
  if (!validity_usb_write (dev, out, out_len, error))
    return NULL;
  guint8 *buf = g_malloc (24576);  /* generous */
  if (!validity_usb_read (dev, buf, 24576, in_len, error))
    {
      g_free (buf);
      return NULL;
    }
  return buf;
}

/* Save raw bytes to a 0600 file. */
static gboolean
write_file_secret (const gchar *path, const guint8 *data, gsize len, GError **error)
{
  int fd = g_open (path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "open(%s): %s", path, g_strerror (errno));
      return FALSE;
    }
  ssize_t w = write (fd, data, len);
  close (fd);
  if (w != (ssize_t) len)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "short write to %s: %zd != %zu", path, w, len);
      return FALSE;
    }
  return TRUE;
}

/* Save PEM-encoded private key with 0600 perms. */
static gboolean
write_pem_key (const gchar *path, EVP_PKEY *pkey, GError **error)
{
  FILE *fp = fopen (path, "w");
  if (!fp)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "fopen(%s): %s", path, g_strerror (errno));
      return FALSE;
    }
  int ok = PEM_write_PrivateKey (fp, pkey, NULL, NULL, 0, NULL, NULL);
  fclose (fp);
  chmod (path, 0600);
  if (!ok)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "PEM_write_PrivateKey failed");
      return FALSE;
    }
  return TRUE;
}

gboolean
validity_pairing_run_pretls_fresh_pair_ceremony (FpDevice *dev, GError **error)
{
  guint8 *resp = NULL;
  gsize resp_len = 0;
  guint8 *req = NULL;
  guint8 *sig_der = NULL;
  EVP_PKEY *fresh_pkey = NULL;
  EVP_PKEY *hs_pkey = NULL;
  gboolean ok = FALSE;

  fp_info ("=== pre-TLS fresh-pair ceremony starting ===");

  /* Step 1: 0x01 (RomInfo) */
  fp_dbg ("step 1: 0x01 RomInfo");
  guint8 op = 0x01;
  resp = exchange (dev, &op, 1, &resp_len, error);
  if (!resp) goto out;
  g_clear_pointer (&resp, g_free);

  /* Step 2: 0x19 INIT_MSG2 */
  fp_dbg ("step 2: 0x19 INIT_MSG2");
  op = 0x19;
  resp = exchange (dev, &op, 1, &resp_len, error);
  if (!resp) goto out;
  g_clear_pointer (&resp, g_free);

  /* Step 3: 0x06 + clean-slate INIT_MSG4 */
  fp_dbg ("step 3: 0x06 + clean-slate INIT_MSG4 (5797 B total)");
  guint8 *init4 = g_malloc (1 + VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN);
  init4[0] = 0x06;
  memcpy (init4 + 1, validity_init_msg4_clean_slate_payload,
          VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN);
  resp = exchange (dev, init4, 1 + VALIDITY_INIT_MSG4_CLEAN_SLATE_LEN,
                   &resp_len, error);
  g_free (init4);
  if (!resp) goto out;
  if (resp_len < 2 || resp[0] != 0x00 || resp[1] != 0x00)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "clean-slate INIT_MSG4 rejected: status %02x %02x",
                   resp_len > 0 ? resp[0] : 0xff,
                   resp_len > 1 ? resp[1] : 0xff);
      goto out;
    }
  g_clear_pointer (&resp, g_free);

  /* Step 4: generate fresh host EC P-256 keypair */
  fp_dbg ("step 4: generate fresh host EC P-256 keypair");
  EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id (EVP_PKEY_EC, NULL);
  if (!kctx
      || EVP_PKEY_keygen_init (kctx) <= 0
      || EVP_PKEY_CTX_set_ec_paramgen_curve_nid (kctx, NID_X9_62_prime256v1) <= 0
      || EVP_PKEY_keygen (kctx, &fresh_pkey) <= 0)
    {
      if (kctx) EVP_PKEY_CTX_free (kctx);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "fresh keypair generation failed");
      goto out;
    }
  EVP_PKEY_CTX_free (kctx);

  /* Extract X, Y, and the private scalar */
  guint8 x_be[32] = {0}, y_be[32] = {0}, x_le[32], y_le[32];
  guint8 priv_be[32] = {0};
  {
    BIGNUM *x_bn = NULL, *y_bn = NULL, *d_bn = NULL;
    if (EVP_PKEY_get_bn_param (fresh_pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x_bn) <= 0
        || EVP_PKEY_get_bn_param (fresh_pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y_bn) <= 0
        || EVP_PKEY_get_bn_param (fresh_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d_bn) <= 0)
      {
        BN_free (x_bn); BN_free (y_bn); BN_free (d_bn);
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                             "failed to extract keypair components");
        goto out;
      }
    BN_bn2binpad (x_bn, x_be, 32);
    BN_bn2binpad (y_bn, y_be, 32);
    BN_bn2binpad (d_bn, priv_be, 32);
    BN_free (x_bn); BN_free (y_bn); BN_free (d_bn);
    for (int i = 0; i < 32; i++) { x_le[i] = x_be[31 - i]; y_le[i] = y_be[31 - i]; }
  }

  /* Step 5: build cert body + sign with hs_key */
  guint8 cert_body[184];
  build_cert_body (x_le, y_le, cert_body);

  guint8 hs_key_le[32];
  if (!compute_hs_key (hs_key_le))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "hs_key derivation failed");
      goto out;
    }
  guint8 hs_key_be[32];
  for (int i = 0; i < 32; i++) hs_key_be[i] = hs_key_le[31 - i];

  hs_pkey = ec_pkey_from_scalar_be (hs_key_be, error);
  if (!hs_pkey) goto out;

  gsize sig_len = 0;
  sig_der = ecdsa_sha256_sign_der (hs_pkey, cert_body, 184, &sig_len, error);
  if (!sig_der) goto out;
  fp_dbg ("step 5: CSR signed (%zu B DER) with hs_key", sig_len);

  /* Step 6: send 0x4f + CSR, receive signed cert */
  gsize req_len;
  req = build_0x4f_request (cert_body, sig_der, sig_len, &req_len);
  g_assert (req_len == 453);

  fp_dbg ("step 6: send 0x4f request (%zu B)", req_len);
  resp = exchange (dev, req, req_len, &resp_len, error);
  if (!resp) goto out;
  /* Some devices split the cert response across 2 IN packets (256+42).
   * Try one more read to catch the tail. */
  gsize resp_extra = 0;
  guint8 *resp_extra_buf = g_malloc (4096);
  GError *eextra = NULL;
  if (validity_usb_read (dev, resp_extra_buf, 4096, &resp_extra, &eextra))
    {
      guint8 *combined = g_malloc (resp_len + resp_extra);
      memcpy (combined, resp, resp_len);
      memcpy (combined + resp_len, resp_extra_buf, resp_extra);
      g_free (resp);
      resp = combined;
      resp_len += resp_extra;
    }
  g_clear_error (&eextra);
  g_free (resp_extra_buf);

  fp_dbg ("0x4f response: %zu B", resp_len);
  if (resp_len < 6 + 184 || resp[0] != 0x00 || resp[1] != 0x00)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "0x4f returned status %02x %02x (%zu B total)",
                   resp[0], resp[1], resp_len);
      goto out;
    }
  /* layout: status(2) + length LE u32(4) + cert body(184) */
  guint32 cert_len = (guint32) resp[2]
                   | ((guint32) resp[3] << 8)
                   | ((guint32) resp[4] << 16)
                   | ((guint32) resp[5] << 24);
  if (cert_len != 184)
    fp_warn ("unexpected cert length in 0x4f response: %u (continuing anyway)",
             cert_len);

  const guint8 *signed_cert = resp + 6;
  /* Sanity: cert's X/Y should echo what we sent */
  if (memcmp (signed_cert + 8, x_le, 32) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "device returned cert with different X — protocol violation");
      goto out;
    }
  fp_info ("device signed cert; trailer = "
           "%02x%02x%02x%02x%02x%02x%02x%02x...",
           signed_cert[152], signed_cert[153], signed_cert[154], signed_cert[155],
           signed_cert[156], signed_cert[157], signed_cert[158], signed_cert[159]);

  /* Save the cert body separately so we don't lose it during subsequent steps */
  guint8 signed_cert_copy[184];
  memcpy (signed_cert_copy, signed_cert, 184);
  g_clear_pointer (&resp, g_free);

  /* Step 7: 0x01 again (protocol requires this repeat) */
  fp_dbg ("step 7: 0x01 RomInfo (second time)");
  op = 0x01;
  resp = exchange (dev, &op, 1, &resp_len, error);
  if (!resp) goto out;
  g_clear_pointer (&resp, g_free);

  /* Step 8: 0x50 — receive device ECDH pubkey */
  fp_dbg ("step 8: 0x50 (request device state + ECDH pubkey)");
  op = 0x50;
  resp = exchange (dev, &op, 1, &resp_len, error);
  if (!resp) goto out;
  /* Drain any continuation */
  resp_extra_buf = g_malloc (4096);
  eextra = NULL;
  if (validity_usb_read (dev, resp_extra_buf, 4096, &resp_extra, &eextra))
    {
      guint8 *combined = g_malloc (resp_len + resp_extra);
      memcpy (combined, resp, resp_len);
      memcpy (combined + resp_len, resp_extra_buf, resp_extra);
      g_free (resp);
      resp = combined;
      resp_len += resp_extra;
    }
  g_clear_error (&eextra);
  g_free (resp_extra_buf);

  if (resp_len < 634)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "0x50 response too short (%zu B; need >=634 to extract ECDH)",
                   resp_len);
      goto out;
    }
  /* Device ECDH pubkey: X at offset 534, Y at offset 602 (both LE, 32 B) */
  guint8 device_ecdh_x_be[32], device_ecdh_y_be[32];
  for (int i = 0; i < 32; i++)
    {
      device_ecdh_x_be[i] = resp[534 + 31 - i];
      device_ecdh_y_be[i] = resp[602 + 31 - i];
    }
  fp_dbg ("extracted device ECDH X (first 8 BE): "
          "%02x%02x%02x%02x%02x%02x%02x%02x",
          device_ecdh_x_be[0], device_ecdh_x_be[1], device_ecdh_x_be[2],
          device_ecdh_x_be[3], device_ecdh_x_be[4], device_ecdh_x_be[5],
          device_ecdh_x_be[6], device_ecdh_x_be[7]);
  g_clear_pointer (&resp, g_free);

  /* Step 9: 0x1a (enroll session start; protocol setup) */
  fp_dbg ("step 9: 0x1a");
  op = 0x1a;
  resp = exchange (dev, &op, 1, &resp_len, error);
  if (!resp) goto out;
  g_clear_pointer (&resp, g_free);

  /* Step 10: persist cert + priv + ECDH pubkey to disk */
  g_autofree gchar *dir = validity_pairing_get_storage_dir ();
  if (!validity_pairing_ensure_storage_dir (error))
    goto out;

  g_autofree gchar *cert_path = g_build_filename (dir, "cert-blob", NULL);
  g_autofree gchar *key_path  = g_build_filename (dir, "host-key.pem", NULL);
  g_autofree gchar *ecdh_path = g_build_filename (dir, "device-ecdh-pubkey.bin", NULL);

  if (!write_file_secret (cert_path, signed_cert_copy, 184, error))
    goto out;
  fp_info ("wrote %s (184 B device-signed cert)", cert_path);

  if (!write_pem_key (key_path, fresh_pkey, error))
    goto out;
  fp_info ("wrote %s (PEM-encoded fresh host keypair)", key_path);

  guint8 ecdh_xy[64];
  memcpy (ecdh_xy, device_ecdh_x_be, 32);
  memcpy (ecdh_xy + 32, device_ecdh_y_be, 32);
  if (!write_file_secret (ecdh_path, ecdh_xy, 64, error))
    goto out;
  fp_info ("wrote %s (64 B device ECDH pubkey X||Y in BE form)", ecdh_path);

  fp_info ("=== pre-TLS fresh-pair ceremony COMPLETE ===");
  ok = TRUE;

out:
  if (resp) g_free (resp);
  if (req) g_free (req);
  if (sig_der) g_free (sig_der);
  if (fresh_pkey) EVP_PKEY_free (fresh_pkey);
  if (hs_pkey) EVP_PKEY_free (hs_pkey);
  return ok;
}
