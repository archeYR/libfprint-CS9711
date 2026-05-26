/*
 * validity-crypto.c — modified-TLS-1.2 crypto primitives.
 *
 * Uses OpenSSL EVP API. To swap for GnuTLS / libgcrypt, replace the
 * helpers below; the public API (validity.h) stays the same.
 *
 * The Python reference at handoff/python/verimark_proto.py implements
 * the same algorithms; cross-check there if behavior diverges.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "validity.h"

#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef VALIDITY_TRACE_HANDSHAKE
static void
debug_hex (const char   *label,
           const guint8 *data,
           gsize         len)
{
  GString *hex = g_string_sized_new (len * 2);

  for (gsize i = 0; i < len; i++)
    g_string_append_printf (hex, "%02x", data[i]);

  fp_dbg ("%s len=%zu hex=%s", label, len, hex->str);
  g_string_free (hex, TRUE);
}
#else
#define debug_hex(label, data, len) \
  G_STMT_START { } G_STMT_END
#endif

/* ===========================================================================
 * TLS 1.2 PRF (RFC 5246 §5)
 * ========================================================================= */

static void
hmac_sha256 (const guint8 *key,  gsize key_len,
             const guint8 *data, gsize data_len,
             guint8 out[VALIDITY_MAC_OUTPUT_LEN])
{
  unsigned int out_len = VALIDITY_MAC_OUTPUT_LEN;
  HMAC (EVP_sha256 (), key, (int) key_len, data, data_len, out, &out_len);
  g_assert_cmpuint (out_len, ==, VALIDITY_MAC_OUTPUT_LEN);
}

/* P_SHA256 (RFC 5246 §5) — feed-forward HMAC chain. */
static void
p_sha256 (const guint8 *secret, gsize secret_len,
          const guint8 *seed,   gsize seed_len,
          guint8       *out,    gsize out_len)
{
  guint8 A[VALIDITY_MAC_OUTPUT_LEN];
  guint8 block[VALIDITY_MAC_OUTPUT_LEN];
  gsize  written = 0;

  /* A(1) = HMAC_K(seed) */
  hmac_sha256 (secret, secret_len, seed, seed_len, A);

  while (written < out_len)
    {
      /* Compute HMAC_K(A(i) || seed) */
      gsize input_len = VALIDITY_MAC_OUTPUT_LEN + seed_len;
      guint8 *input = g_malloc (input_len);
      memcpy (input, A, VALIDITY_MAC_OUTPUT_LEN);
      memcpy (input + VALIDITY_MAC_OUTPUT_LEN, seed, seed_len);
      hmac_sha256 (secret, secret_len, input, input_len, block);
      g_free (input);

      gsize chunk = MIN (VALIDITY_MAC_OUTPUT_LEN, out_len - written);
      memcpy (out + written, block, chunk);
      written += chunk;

      /* A(i+1) = HMAC_K(A(i)) */
      hmac_sha256 (secret, secret_len, A, VALIDITY_MAC_OUTPUT_LEN, A);
    }
}

gboolean
validity_tls12_prf (const guint8 *secret, gsize secret_len,
                    const guint8 *label,  gsize label_len,
                    const guint8 *seed,   gsize seed_len,
                    guint8       *out,    gsize out_len)
{
  /* PRF(secret, label, seed) = P_SHA256(secret, label || seed) */
  gsize  joined_len = label_len + seed_len;
  guint8 *joined = g_malloc (joined_len);

  memcpy (joined, label, label_len);
  memcpy (joined + label_len, seed, seed_len);
  p_sha256 (secret, secret_len, joined, joined_len, out, out_len);
  g_free (joined);
  return TRUE;
}

/* ===========================================================================
 * Session-key derivation
 *
 * The 0088 driver uses client_random || server_random as the seed for
 * BOTH master_secret and key_block. RFC 5246 §6.3 specifies
 * server_random || client_random for key_block — this driver deviates.
 * ========================================================================= */

gboolean
validity_derive_session_keys (ValiditySession *session,
                              const guint8    *pre_master_secret,
                              gsize            pre_master_secret_len)
{
  guint8 seed[64];
  memcpy (seed,      session->client_random, 32);
  memcpy (seed + 32, session->server_random, 32);

  /* master_secret = PRF(pre_master, "master secret", c_random ‖ s_random)[0..47] */
  validity_tls12_prf (
      pre_master_secret, pre_master_secret_len,
      (const guint8 *) "master secret", 13,
      seed, sizeof (seed),
      session->master_secret, VALIDITY_MASTER_SECRET_LEN);

  /* key_block = PRF(master_secret, "key expansion", SAME seed)[0..127]
   * NB: RFC says s_random || c_random here, but 0088 uses the same buffer. */
  guint8 key_block[VALIDITY_KEY_BLOCK_LEN];
  validity_tls12_prf (
      session->master_secret, VALIDITY_MASTER_SECRET_LEN,
      (const guint8 *) "key expansion", 13,
      seed, sizeof (seed),
      key_block, sizeof (key_block));

  memcpy (session->client_write_mac_key, key_block,            32);
  memcpy (session->server_write_mac_key, key_block + 32,       32);
  memcpy (session->client_write_key,     key_block + 64,       32);
  memcpy (session->server_write_key,     key_block + 96,       32);

  debug_hex ("KDF seed client_random||server_random", seed, sizeof (seed));
  debug_hex ("KDF pre_master_secret", pre_master_secret, pre_master_secret_len);
  debug_hex ("KDF master_secret", session->master_secret,
             VALIDITY_MASTER_SECRET_LEN);
  debug_hex ("KDF key_block", key_block, sizeof (key_block));
  debug_hex ("KDF client_write_mac_key", session->client_write_mac_key,
             VALIDITY_MAC_KEY_LEN);
  debug_hex ("KDF server_write_mac_key", session->server_write_mac_key,
             VALIDITY_MAC_KEY_LEN);
  debug_hex ("KDF client_write_key", session->client_write_key,
             VALIDITY_ENC_KEY_LEN);
  debug_hex ("KDF server_write_key", session->server_write_key,
             VALIDITY_ENC_KEY_LEN);

  /* Zero the seed buffer */
  memset (seed,      0, sizeof (seed));
  memset (key_block, 0, sizeof (key_block));

  /* Reset record-layer sequence numbers — fresh keys = fresh seq */
  session->client_seq_num = 0;
  session->server_seq_num = 0;
  return TRUE;
}

/* ===========================================================================
 * TLS-1.2 record encryption (AES-256-CBC + HMAC-SHA-256 + explicit IV)
 * ========================================================================= */

/* MAC input — Synaptics deviation from RFC 5246 §6.2.3.1.
 *
 * Standard RFC:
 *   seq_num (8 BE) || content_type || version (2 BE) || frag_len (2 BE) || fragment
 *
 * Synaptics / python-validity:
 *   content_type || version (2 BE) || frag_len (2 BE) || fragment
 *
 * NO sequence number. The seq_num parameter is kept in the signature
 * for source-compat with RFC impls and is IGNORED.
 */
static void
compute_record_mac (const guint8 *mac_key,
                    guint64       seq_num G_GNUC_UNUSED,
                    guint8        content_type,
                    const guint8 *fragment,
                    guint16       fragment_len,
                    guint8        out[32])
{
  gsize  input_len = 1 + 2 + 2 + fragment_len;
  guint8 *input = g_malloc (input_len);
  guint8 *p = input;

  *p++ = content_type;
  *p++ = (VALIDITY_TLS_VERSION >> 8) & 0xff;
  *p++ = VALIDITY_TLS_VERSION & 0xff;
  *p++ = (fragment_len >> 8) & 0xff;
  *p++ = fragment_len & 0xff;
  memcpy (p, fragment, fragment_len);

  hmac_sha256 (mac_key, VALIDITY_MAC_KEY_LEN, input, input_len, out);
  g_free (input);
}

guint8 *
validity_encrypt_record (ValiditySession *session,
                         guint8           content_type,
                         const guint8    *plaintext,
                         gsize            plaintext_len,
                         gsize           *out_len)
{
  guint8 iv[VALIDITY_AES_BLOCK_SIZE];
  guint8 mac[VALIDITY_MAC_OUTPUT_LEN];
  EVP_CIPHER_CTX *ctx;

  if (plaintext_len > 0xFFFF)
    return NULL;  /* TLS 1.2 record fragment length max */

  /* 1. MAC over the plaintext (with seq_num prefix). */
  compute_record_mac (session->client_write_mac_key,
                      session->client_seq_num,
                      content_type,
                      plaintext,
                      (guint16) plaintext_len,
                      mac);
  debug_hex ("ENCRYPT plaintext", plaintext, plaintext_len);
  debug_hex ("ENCRYPT mac", mac, sizeof (mac));

  /* 2. CBC padding: pad_len + 1 trailing bytes, each = pad_len. */
  gsize to_pad = plaintext_len + VALIDITY_MAC_OUTPUT_LEN;
  gsize pad_len = (VALIDITY_AES_BLOCK_SIZE - (to_pad + 1) % VALIDITY_AES_BLOCK_SIZE) % VALIDITY_AES_BLOCK_SIZE;
  gsize body_len = plaintext_len + VALIDITY_MAC_OUTPUT_LEN + pad_len + 1;
  g_assert_cmpuint (body_len % VALIDITY_AES_BLOCK_SIZE, ==, 0);

  guint8 *body = g_malloc (body_len);
  memcpy (body, plaintext, plaintext_len);
  memcpy (body + plaintext_len, mac, VALIDITY_MAC_OUTPUT_LEN);
  for (gsize i = 0; i <= pad_len; ++i)
    body[plaintext_len + VALIDITY_MAC_OUTPUT_LEN + i] = (guint8) pad_len;

  /* 3. Random explicit IV. */
  RAND_bytes (iv, VALIDITY_AES_BLOCK_SIZE);
  debug_hex ("ENCRYPT explicit_iv", iv, sizeof (iv));

  /* 4. AES-256-CBC encrypt. */
  ctx = EVP_CIPHER_CTX_new ();
  EVP_EncryptInit_ex (ctx, EVP_aes_256_cbc (), NULL,
                      session->client_write_key, iv);
  EVP_CIPHER_CTX_set_padding (ctx, 0);  /* we did our own padding */

  guint8 *ciphertext = g_malloc (body_len);
  int outl = 0, total = 0;
  EVP_EncryptUpdate (ctx, ciphertext, &outl, body, (int) body_len);
  total = outl;
  EVP_EncryptFinal_ex (ctx, ciphertext + total, &outl);
  total += outl;
  EVP_CIPHER_CTX_free (ctx);
  g_assert_cmpuint ((gsize) total, ==, body_len);

  /* 5. Build the on-wire record. */
  gsize record_len = 5 + VALIDITY_AES_BLOCK_SIZE + body_len;
  guint8 *record = g_malloc (record_len);
  record[0] = content_type;
  record[1] = (VALIDITY_TLS_VERSION >> 8) & 0xff;
  record[2] = VALIDITY_TLS_VERSION & 0xff;
  guint16 fragment_size = VALIDITY_AES_BLOCK_SIZE + body_len;
  record[3] = (fragment_size >> 8) & 0xff;
  record[4] = fragment_size & 0xff;
  memcpy (record + 5, iv, VALIDITY_AES_BLOCK_SIZE);
  memcpy (record + 5 + VALIDITY_AES_BLOCK_SIZE, ciphertext, body_len);
  debug_hex ("ENCRYPT record", record, record_len);

  g_free (body);
  g_free (ciphertext);
  memset (mac, 0, sizeof (mac));

  session->client_seq_num++;
  *out_len = record_len;
  return record;
}

guint8 *
validity_decrypt_record (ValiditySession *session,
                         guint8           content_type,
                         const guint8    *record_body,
                         gsize            record_body_len,
                         gsize           *out_len)
{
  EVP_CIPHER_CTX *ctx;
  guint8 mac_check[VALIDITY_MAC_OUTPUT_LEN];

  if (record_body_len < VALIDITY_AES_BLOCK_SIZE + VALIDITY_AES_BLOCK_SIZE)
    return NULL;  /* needs at least IV + one block */

  const guint8 *iv = record_body;
  const guint8 *ciphertext = record_body + VALIDITY_AES_BLOCK_SIZE;
  gsize ciphertext_len = record_body_len - VALIDITY_AES_BLOCK_SIZE;
  if (ciphertext_len % VALIDITY_AES_BLOCK_SIZE)
    return NULL;  /* not block-aligned */

  ctx = EVP_CIPHER_CTX_new ();
  EVP_DecryptInit_ex (ctx, EVP_aes_256_cbc (), NULL,
                      session->server_write_key, iv);
  EVP_CIPHER_CTX_set_padding (ctx, 0);

  guint8 *body = g_malloc (ciphertext_len);
  int outl = 0, total = 0;
  EVP_DecryptUpdate (ctx, body, &outl, ciphertext, (int) ciphertext_len);
  total = outl;
  EVP_DecryptFinal_ex (ctx, body + total, &outl);
  total += outl;
  EVP_CIPHER_CTX_free (ctx);
  g_assert_cmpuint ((gsize) total, ==, ciphertext_len);

  /* Verify padding */
  guint8 pad_len = body[ciphertext_len - 1];
  if ((gsize) pad_len + 1 > ciphertext_len)
    {
      g_free (body);
      return NULL;
    }
  for (gsize i = 0; i <= pad_len; ++i)
    if (body[ciphertext_len - 1 - i] != pad_len)
      {
        g_free (body);
        return NULL;
      }
  gsize unpadded_len = ciphertext_len - (pad_len + 1);
  if (unpadded_len < VALIDITY_MAC_OUTPUT_LEN)
    {
      g_free (body);
      return NULL;
    }
  gsize plaintext_len = unpadded_len - VALIDITY_MAC_OUTPUT_LEN;

  /* Verify MAC */
  compute_record_mac (session->server_write_mac_key,
                      session->server_seq_num,
                      content_type,
                      body,
                      (guint16) plaintext_len,
                      mac_check);
  if (memcmp (mac_check, body + plaintext_len, VALIDITY_MAC_OUTPUT_LEN) != 0)
    {
      g_free (body);
      memset (mac_check, 0, sizeof (mac_check));
      return NULL;
    }

  guint8 *plaintext = g_malloc (plaintext_len);
  memcpy (plaintext, body, plaintext_len);
  g_free (body);
  memset (mac_check, 0, sizeof (mac_check));

  session->server_seq_num++;
  *out_len = plaintext_len;
  return plaintext;
}

/* ===========================================================================
 * ECDH on NIST P-256
 * ========================================================================= */

gboolean
validity_generate_ephemeral_keypair (ValiditySession *session)
{
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIGNUM *priv = NULL;
  guint8 pub[65];
  gsize pub_len = sizeof (pub);
  gboolean ok = FALSE;

  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (ctx == NULL ||
      EVP_PKEY_keygen_init (ctx) <= 0 ||
      EVP_PKEY_CTX_set_group_name (ctx, "prime256v1") <= 0 ||
      EVP_PKEY_keygen (ctx, &pkey) <= 0)
    {
      fp_dbg ("ephemeral keygen failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
      goto cleanup;
    }

  if (EVP_PKEY_get_bn_param (pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv) != 1 ||
      EVP_PKEY_get_octet_string_param (pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                       pub, sizeof (pub), &pub_len) != 1 ||
      pub_len != sizeof (pub) || pub[0] != 0x04)
    {
      fp_dbg ("ephemeral key export failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
      goto cleanup;
    }

  if (BN_bn2binpad (priv, session->ephemeral_priv, 32) != 32)
    goto cleanup;

  memcpy (session->ephemeral_pub_x, pub + 1, 32);
  memcpy (session->ephemeral_pub_y, pub + 33, 32);
  ok = TRUE;

cleanup:
  BN_clear_free (priv);
  EVP_PKEY_free (pkey);
  EVP_PKEY_CTX_free (ctx);
  return ok;
}

/* ECDH on P-256 via OpenSSL 3 EVP_PKEY API.
 * Takes our 32-byte private scalar (big-endian) and the peer's
 * uncompressed P-256 point as X, Y (big-endian 32 bytes each).
 * Returns 32-byte shared secret (caller g_free's), or NULL on error. */
guint8 *
validity_ecdh_p256 (const guint8 *our_priv,
                    const guint8 *peer_pub_x,
                    const guint8 *peer_pub_y,
                    gsize        *out_len)
{
  EVP_PKEY *our_key = NULL;
  EVP_PKEY *peer_key = NULL;
  EVP_PKEY_CTX *derive_ctx = NULL;
  guint8 *shared = NULL;
  OSSL_PARAM params[3] = {0};
  BIGNUM *priv_bn = NULL;
  guint8 peer_uncompressed[65];

  /* Build our private key from raw scalar via EVP_PKEY_fromdata. */
  EVP_PKEY_CTX *priv_ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (priv_ctx == NULL || EVP_PKEY_fromdata_init (priv_ctx) <= 0)
    {
      fp_dbg ("ECDH: EVP_PKEY_CTX_new_from_name(EC) failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
      goto cleanup;
    }
  priv_bn = BN_bin2bn (our_priv, 32, NULL);
  if (!priv_bn) { fp_dbg ("ECDH: BN_bin2bn(priv) failed"); goto cleanup; }
  params[0] = OSSL_PARAM_construct_utf8_string (
      OSSL_PKEY_PARAM_GROUP_NAME, (char *) "prime256v1", 0);
  params[1] = OSSL_PARAM_construct_BN (
      OSSL_PKEY_PARAM_PRIV_KEY, (unsigned char *) our_priv, 32);
  /* OSSL_PARAM_construct_BN expects native-endian; convert via BN. */
  unsigned char priv_native[32];
  if (BN_bn2nativepad (priv_bn, priv_native, 32) != 32)
    { fp_dbg ("ECDH: BN_bn2nativepad failed"); goto cleanup; }
  params[1] = OSSL_PARAM_construct_BN (
      OSSL_PKEY_PARAM_PRIV_KEY, priv_native, 32);
  params[2] = OSSL_PARAM_construct_end ();
  if (EVP_PKEY_fromdata (priv_ctx, &our_key, EVP_PKEY_KEYPAIR, params) <= 0)
    {
      fp_dbg ("ECDH: EVP_PKEY_fromdata(priv) failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
      goto cleanup;
    }

  /* Build the peer's public key — uncompressed encoding: 0x04 || X || Y. */
  peer_uncompressed[0] = 0x04;
  memcpy (peer_uncompressed + 1,  peer_pub_x, 32);
  memcpy (peer_uncompressed + 33, peer_pub_y, 32);
  EVP_PKEY_CTX *pub_ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  OSSL_PARAM pub_params[3];
  pub_params[0] = OSSL_PARAM_construct_utf8_string (
      OSSL_PKEY_PARAM_GROUP_NAME, (char *) "prime256v1", 0);
  pub_params[1] = OSSL_PARAM_construct_octet_string (
      OSSL_PKEY_PARAM_PUB_KEY, peer_uncompressed, 65);
  pub_params[2] = OSSL_PARAM_construct_end ();
  if (pub_ctx == NULL || EVP_PKEY_fromdata_init (pub_ctx) <= 0
      || EVP_PKEY_fromdata (pub_ctx, &peer_key,
                            EVP_PKEY_PUBLIC_KEY, pub_params) <= 0)
    {
      fp_dbg ("ECDH: EVP_PKEY_fromdata(pub) failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
      EVP_PKEY_CTX_free (pub_ctx);
      goto cleanup;
    }
  EVP_PKEY_CTX_free (pub_ctx);

  /* Derive shared secret. */
  derive_ctx = EVP_PKEY_CTX_new (our_key, NULL);
  if (derive_ctx == NULL
      || EVP_PKEY_derive_init (derive_ctx) <= 0
      || EVP_PKEY_derive_set_peer (derive_ctx, peer_key) <= 0)
    {
      fp_dbg ("ECDH: derive_init/set_peer failed: %s",
              ERR_error_string (ERR_get_error (), NULL));
      goto cleanup;
    }
  size_t sec_len = 32;
  shared = g_malloc (32);
  if (EVP_PKEY_derive (derive_ctx, shared, &sec_len) <= 0 || sec_len != 32)
    {
      fp_dbg ("ECDH: EVP_PKEY_derive failed (len=%zu): %s",
              sec_len, ERR_error_string (ERR_get_error (), NULL));
      g_free (shared);
      shared = NULL;
      goto cleanup;
    }
  *out_len = 32;

cleanup:
  if (priv_bn) BN_free (priv_bn);
  if (our_key) EVP_PKEY_free (our_key);
  if (peer_key) EVP_PKEY_free (peer_key);
  if (derive_ctx) EVP_PKEY_CTX_free (derive_ctx);
  if (priv_ctx) EVP_PKEY_CTX_free (priv_ctx);
  return shared;
}

/* ===========================================================================
 * Handshake-message running hash (for Finished verify_data)
 * ========================================================================= */

void
validity_handshake_hash_init (ValiditySession *session)
{
  if (session->handshake_hash_ctx)
    EVP_MD_CTX_free ((EVP_MD_CTX *) session->handshake_hash_ctx);
  EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
  EVP_DigestInit_ex (ctx, EVP_sha256 (), NULL);
  session->handshake_hash_ctx = ctx;
}

void
validity_handshake_hash_update (ValiditySession *session,
                                const guint8 *data,
                                gsize         len)
{
  if (session->handshake_hash_ctx)
    EVP_DigestUpdate ((EVP_MD_CTX *) session->handshake_hash_ctx, data, len);
}

void
validity_handshake_hash_finish (ValiditySession *session, guint8 out[32])
{
  if (!session->handshake_hash_ctx) {
    memset (out, 0, 32);
    return;
  }
  unsigned int outl = 32;
  /* Use EVP_MD_CTX_copy_ex to allow continued use; final-and-discard otherwise */
  EVP_MD_CTX *snap = EVP_MD_CTX_new ();
  EVP_MD_CTX_copy_ex (snap, (EVP_MD_CTX *) session->handshake_hash_ctx);
  EVP_DigestFinal_ex (snap, out, &outl);
  EVP_MD_CTX_free (snap);
}
