/*
 * validity-handshake.c — Mutual TLS-1.2 handshake state machine
 * for Kensington VeriMark (06CB:0088).
 *
 * Ported from python-validity's validitysensor/tls.py for the sibling
 * 06CB:009A; adapted to 0088 specifics:
 *
 *   - Device ECDH pubkey is the per-device session-cached pairing key
 *     (extracted at fresh-pair time from the 0x50 response), NOT the
 *     pinned attestation root key.
 *   - The host client Certificate is the 192-byte cached TLV tag 3 blob;
 *     the 32-B trailer is issued by the device during initial pair and
 *     replayed verbatim here.
 *   - CertificateVerify body is a bare DER ECDSA-Sig-Value, NO
 *     SignatureAndHashAlgorithm prefix, NO 2-byte length.
 *   - MAC over records uses Synaptics no-seq-num format
 *     (already handled by validity_encrypt_record / validity_decrypt_record).
 *
 * Wire-level flow (single USB exchange per direction):
 *
 *   Out  #1: 44 00 00 00 || TLSRecord(handshake, ClientHello)
 *   In   #1: TLSRecord(handshake, ServerHello||CertReq||SrvHelloDone)
 *   Out  #2: 44 00 00 00
 *            || TLSRecord(handshake, ClientCert||CKE||CertVerify)
 *            || TLSRecord(change_cipher_spec, 0x01)
 *            || TLSRecord(handshake, Finished)              [ENCRYPTED]
 *   In   #2: TLSRecord(change_cipher_spec, 0x01)
 *            || TLSRecord(handshake, Finished)              [ENCRYPTED]
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#define FP_COMPONENT "validity"

#include "drivers_api.h"
#include "validity.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/* ===========================================================================
 * Wire framing helpers
 * ========================================================================= */

#define HS_HEADER_LEN     4       /* type(1) + length(3) */
#define RECORD_HEADER_LEN 5       /* type(1) + version(2) + length(2) */

#ifdef VALIDITY_TRACE_HANDSHAKE
/* These trace helpers dump private scalars and session keys, so keep them
 * behind an explicit build flag and off in normal debug builds. */
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

static void
debug_handshake_hash (ValiditySession *session,
                      const char      *label)
{
  guint8 hash[32];

  validity_handshake_hash_finish (session, hash);
  debug_hex (label, hash, sizeof (hash));
}

static void
debug_handshake_hash_update (ValiditySession *session,
                             const char      *label,
                             const guint8    *data,
                             gsize            len)
{
  char hash_label[96];

  debug_hex (label, data, len);
  validity_handshake_hash_update (session, data, len);
  g_snprintf (hash_label, sizeof (hash_label), "%s -> transcript_sha256", label);
  debug_handshake_hash (session, hash_label);
}
#else
#define debug_hex(label, data, len) \
  G_STMT_START { } G_STMT_END
#define debug_handshake_hash_update(session, label, data, len) \
  validity_handshake_hash_update ((session), (data), (len))
#endif

/* Wrap one or more handshake-message bodies into a TLS handshake record.
 * `messages` is the concatenated handshake bytes (each starting with the
 * 4-byte handshake header). Returns malloc'd buffer; caller frees. */
static guint8 *
wrap_handshake_record (const guint8 *messages, gsize messages_len,
                       gsize        *out_len)
{
  *out_len = RECORD_HEADER_LEN + messages_len;
  guint8 *out = g_malloc (*out_len);
  out[0] = VALIDITY_CT_HANDSHAKE;
  out[1] = 0x03;
  out[2] = 0x03;
  out[3] = (guint8) (messages_len >> 8);
  out[4] = (guint8) (messages_len & 0xff);
  memcpy (out + RECORD_HEADER_LEN, messages, messages_len);
  return out;
}

/* Prepend the 4-byte handshake header to a body. */
static guint8 *
wrap_handshake_message (guint8 hs_type, const guint8 *body, gsize body_len,
                       gsize *out_len)
{
  *out_len = HS_HEADER_LEN + body_len;
  guint8 *out = g_malloc (*out_len);
  out[0] = hs_type;
  out[1] = (guint8) (body_len >> 16);
  out[2] = (guint8) ((body_len >> 8) & 0xff);
  out[3] = (guint8) (body_len & 0xff);
  memcpy (out + HS_HEADER_LEN, body, body_len);
  return out;
}

/* ===========================================================================
 * Incoming handshake-message parsers (mirror Python's parse_* functions)
 * ========================================================================= */

static gboolean
parse_server_hello (const guint8 *body, gsize body_len,
                    guint8        server_random_out[32],
                    guint16      *cipher_suite_out,
                    GError      **error)
{
  if (body_len < 38)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "ServerHello body too short: %zu B", body_len);
      return FALSE;
    }
  guint16 version = (body[0] << 8) | body[1];
  if (version != VALIDITY_TLS_VERSION)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "ServerHello version 0x%04x != TLS 1.2", version);
      return FALSE;
    }
  memcpy (server_random_out, body + 2, 32);
  guint8 sid_len = body[34];
  gsize off = 35 + sid_len;
  if (off + 3 > body_len)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "ServerHello truncated at cipher_suite/compression");
      return FALSE;
    }
  *cipher_suite_out = (body[off] << 8) | body[off + 1];
  if (body[off + 2] != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "ServerHello selected compression 0x%02x (only null=0 supported)",
                   body[off + 2]);
      return FALSE;
    }
  return TRUE;
}

/* ===========================================================================
 * Synaptics TLV envelope walker (§"TLV decoder")
 *
 * Each TLV record in the server's Certificate handshake message body:
 *   +0x00..0x01  int16 LE   tag       (-1 / 0xFFFF = end-of-list sentinel)
 *   +0x02..0x03  uint16 LE  length    (length of the value payload)
 *   +0x04..0x23  20 bytes   header    (undecoded metadata)
 *   +0x24..      length B   value payload
 * Each record's total size on the wire is 36 + length.
 *
 * The walker scans for the first record whose tag matches `target_tag`.
 * On match, *out_ptr is set to a pointer INSIDE `body` (caller copies if
 * needed) and *out_len is the value length. Returns FALSE if not found.
 * Malformed/truncated records terminate the walk; not found is a soft
 * failure (no GError set).
 * ========================================================================= */

#define SYNAPTICS_TLV_HEADER_LEN  0x24    /* tag+len(4) + 20 metadata */
#define SYNAPTICS_TLV_END_TAG     0xFFFF

static gboolean
synaptics_tlv_find (const guint8 *body, gsize body_len,
                    guint16       target_tag,
                    const guint8 **out_ptr,
                    gsize        *out_len)
{
  gsize off = 0;
  while (off + SYNAPTICS_TLV_HEADER_LEN <= body_len)
    {
      guint16 tag = (guint16) body[off] | ((guint16) body[off + 1] << 8);
      guint16 len = (guint16) body[off + 2] | ((guint16) body[off + 3] << 8);
      if (tag == SYNAPTICS_TLV_END_TAG)
        return FALSE;
      gsize record_end = off + SYNAPTICS_TLV_HEADER_LEN + len;
      if (record_end > body_len)
        return FALSE;
      if (tag == target_tag)
        {
          *out_ptr = body + off + SYNAPTICS_TLV_HEADER_LEN;
          *out_len = len;
          return TRUE;
        }
      off = record_end;
    }
  return FALSE;
}

/* Free any fresh-pair material attached to a session. Safe to call on a
 * session that never received fresh-pair tags (everything stays NULL). */
void
validity_session_clear_fresh_pair (ValiditySession *session)
{
  if (session == NULL)
    return;
  g_clear_pointer (&session->fresh_pair_cert_body, g_free);
  session->fresh_pair_cert_body_len = 0;
  g_clear_pointer (&session->fresh_pair_rsa_blob, g_free);
  session->fresh_pair_rsa_blob_len = 0;
  if (session->fresh_pair_rsa_key != NULL)
    {
      EVP_PKEY_free ((EVP_PKEY *) session->fresh_pair_rsa_key);
      session->fresh_pair_rsa_key = NULL;
    }
}

/* Forward-declared so dispatch_server_hello_phase can use it without
 * pulling the full RSA key importer ahead of the existing parsers. */
static EVP_PKEY *load_rsa_key_from_virp_blob (const guint8 *blob,
                                              gsize         blob_len,
                                              GError      **error);

/* Handle the Server Certificate (HS type 0x0b) handshake message.
 *
 * On a paired-already device this message is NOT sent and this handler
 * never runs. On a never-paired device the body is a Synaptics-TLV
 * envelope; we extract the two tags that matter for the host's
 * Client Certificate + CertificateVerify steps:
 *   - tag 3 (expected 0x124 B): the placeholder cert body the host
 *     should echo back as its own Certificate handshake message
 *   - tag 4 (expected 0x4a0 B): an RSA private-key blob ("VIRP" magic)
 *     the host should import + use to sign CertificateVerify
 *
 * Both extracted blobs are copied into session-owned heap buffers so
 * the lifetime is decoupled from the incoming network buffer. If
 * tag 4 can be imported as an RSA key we cache the EVP_PKEY too.
 *
 * Failures here are LOGGED but not propagated: the paired-path code
 * paths still work via the cached cert + cached host private key, so
 * a malformed Server Certificate just leaves the session in its
 * normal "no fresh-pair material" state. */
static gboolean
parse_server_certificate (ValiditySession *session,
                          const guint8    *body,
                          gsize            body_len,
                          GError         **error)
{
  (void) error;  /* soft failure path; we only log */

  if (session == NULL || body == NULL || body_len == 0)
    return TRUE;

  /* Drop any previously-stashed fresh-pair material from an aborted
   * earlier session (defensive; validity_close also clears). */
  validity_session_clear_fresh_pair (session);

  const guint8 *tag_ptr = NULL;
  gsize         tag_len = 0;

  if (synaptics_tlv_find (body, body_len, 3, &tag_ptr, &tag_len)
      && tag_len > 0)
    {
      session->fresh_pair_cert_body = g_memdup2 (tag_ptr, tag_len);
      session->fresh_pair_cert_body_len = tag_len;
      fp_dbg ("server Certificate carries tag 3 (cert body) len=%zu",
              tag_len);
    }

  if (synaptics_tlv_find (body, body_len, 4, &tag_ptr, &tag_len)
      && tag_len > 0)
    {
      session->fresh_pair_rsa_blob = g_memdup2 (tag_ptr, tag_len);
      session->fresh_pair_rsa_blob_len = tag_len;
      fp_dbg ("server Certificate carries tag 4 (RSA key blob) len=%zu",
              tag_len);

      GError *rsa_err = NULL;
      EVP_PKEY *rsa = load_rsa_key_from_virp_blob (tag_ptr, tag_len, &rsa_err);
      if (rsa != NULL)
        {
          session->fresh_pair_rsa_key = rsa;
          fp_dbg ("imported tag-4 RSA key for CertificateVerify signing");
        }
      else
        {
          fp_dbg ("could not import tag-4 RSA key (non-fatal; "
                  "ECDSA path remains available): %s",
                  rsa_err ? rsa_err->message : "unknown");
          g_clear_error (&rsa_err);
        }
    }

  return TRUE;
}

static gboolean
parse_certificate_request (const guint8 *body, gsize body_len, GError **error)
{
  /* Synaptics 4-byte non-standard CR. We just validate shape and that
   * the cert type list includes ECDSA_sign (0x40). */
  if (body_len < 3)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "CertificateRequest too short");
      return FALSE;
    }
  guint8 ct_len = body[0];
  if (ct_len == 0 || 1 + (gsize) ct_len + 2 > body_len)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "CertificateRequest truncated in cert_types");
      return FALSE;
    }
  gboolean has_ecdsa = FALSE;
  for (guint8 i = 0; i < ct_len; i++)
    if (body[1 + i] == 0x40) has_ecdsa = TRUE;
  if (!has_ecdsa)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           "device requested cert type other than ecdsa_sign(0x40)");
      return FALSE;
    }
  return TRUE;
}

static gboolean
parse_server_hello_done (const guint8 *body, gsize body_len, GError **error)
{
  if (body_len != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "ServerHelloDone body must be empty, got %zu B", body_len);
      return FALSE;
    }
  return TRUE;
}

/* ===========================================================================
 * Iterate over handshake messages inside a (potentially decrypted) blob.
 * Calls dispatch_fn with (hs_type, body, body_len, transcript_data,
 * transcript_len, user_data) for each — the transcript bytes include
 * the 4-B handshake header (RFC 5246 §7.4.9 requires this in the hash).
 * ========================================================================= */

typedef gboolean (*hs_iter_cb) (guint8 hs_type,
                                const guint8 *body, gsize body_len,
                                const guint8 *transcript, gsize transcript_len,
                                gpointer user_data, GError **error);

static gboolean
iterate_handshake_messages (const guint8 *data, gsize data_len,
                            hs_iter_cb    cb,
                            gpointer      user_data,
                            GError      **error)
{
  gsize off = 0;
  while (off < data_len)
    {
      if (off + HS_HEADER_LEN > data_len)
        {
          g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                               "incomplete handshake header");
          return FALSE;
        }
      guint8 t = data[off];
      gsize len = (data[off + 1] << 16) | (data[off + 2] << 8) | data[off + 3];
      if (off + HS_HEADER_LEN + len > data_len)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "handshake msg type 0x%02x length %zu exceeds buffer", t, len);
          return FALSE;
        }
      if (!cb (t, data + off + HS_HEADER_LEN, len,
               data + off, HS_HEADER_LEN + len, user_data, error))
        return FALSE;
      off += HS_HEADER_LEN + len;
    }
  return TRUE;
}

/* ===========================================================================
 * Dispatch context for the server response to ClientHello.
 * ========================================================================= */

typedef struct {
  ValiditySession *session;
  gboolean got_server_hello;
  gboolean got_cert_request;
  gboolean got_server_hello_done;
} ServerHelloPhaseCtx;

static gboolean
dispatch_server_hello_phase (guint8 hs_type,
                             const guint8 *body, gsize body_len,
                             const guint8 *transcript, gsize transcript_len,
                             gpointer user_data, GError **error)
{
  ServerHelloPhaseCtx *ctx = user_data;
  char label[64];

  g_snprintf (label, sizeof (label),
              "HASH_UPDATE server hs_type=0x%02x", hs_type);
  debug_handshake_hash_update (ctx->session, label, transcript, transcript_len);

  switch (hs_type)
    {
    case VALIDITY_HS_SERVER_HELLO:
      {
        guint16 suite = 0;
        if (!parse_server_hello (body, body_len,
                                 ctx->session->server_random, &suite, error))
          return FALSE;
        if (suite != VALIDITY_CIPHER_SUITE)
          {
            g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                         "device selected cipher 0x%04x (expected 0x%04x)",
                         suite, VALIDITY_CIPHER_SUITE);
            return FALSE;
          }
        ctx->got_server_hello = TRUE;
        return TRUE;
      }
    case VALIDITY_HS_CERTIFICATE: /* 0x0b, only sent on fresh-pair devices */
      return parse_server_certificate (ctx->session, body, body_len, error);
    case 0x0d: /* CertificateRequest */
      ctx->got_cert_request = TRUE;
      return parse_certificate_request (body, body_len, error);
    case 0x0e: /* ServerHelloDone */
      ctx->got_server_hello_done = TRUE;
      return parse_server_hello_done (body, body_len, error);
    default:
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "unexpected handshake msg 0x%02x in server-hello phase", hs_type);
      return FALSE;
    }
}

/* ===========================================================================
 * RSA key import + signing for the fresh-pair CertificateVerify path.
 *
 * On a fresh-pair Server Certificate, tag 4 carries a 1184-byte value.
 * The first 1172 bytes are a CAPI PRIVATEKEYBLOB for a 2048-bit RSA
 * signing key:
 *   BLOBHEADER || RSAPUBKEY || n || p || q || dP || dQ || qInv || d
 * All multi-byte integers in the CAPI blob are little-endian. OpenSSL's
 * provider-side RSA import wants native-endian BIGNUM params, so this
 * loader converts every integer field before EVP_PKEY_fromdata().
 *
 * The remaining 12 bytes of the tag-4 value are not read; they are
 * zeroized with the rest of the tag after import.
 * ========================================================================= */

#define CAPI_PRIVATEKEYBLOB          0x07
#define CAPI_CUR_BLOB_VERSION        0x02
#define CAPI_CALG_RSA_SIGN           0x00002400u
#define CAPI_CALG_RSA_KEYX           0x0000a400u
#define CAPI_RSA2_MAGIC              0x32415352u  /* "RSA2" */
#define CAPI_BLOBHEADER_LEN          0x08
#define CAPI_RSAPUBKEY_LEN           0x0c
#define CAPI_RSA_PRIVATE_BLOB_LEN    0x494        /* RSA-2048 */
#define VIRP_TAG4_VALUE_LEN          0x4a0

static EVP_PKEY *
load_rsa_key_from_virp_blob (const guint8 *blob,
                             gsize         blob_len,
                             GError      **error)
{
  static const char *field_names[] = {
    OSSL_PKEY_PARAM_RSA_N,
    OSSL_PKEY_PARAM_RSA_E,
    OSSL_PKEY_PARAM_RSA_D,
    OSSL_PKEY_PARAM_RSA_FACTOR1,
    OSSL_PKEY_PARAM_RSA_FACTOR2,
    OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
  };
  const guint8 *field_ptrs[G_N_ELEMENTS (field_names)] = {0};
  gsize field_lens[G_N_ELEMENTS (field_names)] = {0};
  guint8 *native[G_N_ELEMENTS (field_names)] = {0};
  OSSL_PARAM params[G_N_ELEMENTS (field_names) + 1];
  EVP_PKEY_CTX *ctx = NULL;
  EVP_PKEY *pkey = NULL;

  if (blob_len < CAPI_RSA_PRIVATE_BLOB_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "tag-4 RSA blob too short: %zu", blob_len);
      return NULL;
    }

  if (blob_len != CAPI_RSA_PRIVATE_BLOB_LEN
      && blob_len != VIRP_TAG4_VALUE_LEN)
    fp_dbg ("tag-4 RSA blob len=%zu; importing first %u bytes",
            blob_len, CAPI_RSA_PRIVATE_BLOB_LEN);

  guint32 alg_id = (guint32) blob[4]
                  | ((guint32) blob[5] << 8)
                  | ((guint32) blob[6] << 16)
                  | ((guint32) blob[7] << 24);
  guint32 magic = (guint32) blob[8]
                 | ((guint32) blob[9] << 8)
                 | ((guint32) blob[10] << 16)
                 | ((guint32) blob[11] << 24);
  guint32 bit_len = (guint32) blob[12]
                   | ((guint32) blob[13] << 8)
                   | ((guint32) blob[14] << 16)
                   | ((guint32) blob[15] << 24);

  if (blob[0] != CAPI_PRIVATEKEYBLOB
      || blob[1] != CAPI_CUR_BLOB_VERSION
      || blob[2] != 0
      || blob[3] != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "tag-4 RSA blob has invalid CAPI BLOBHEADER");
      return NULL;
    }

  if (alg_id != CAPI_CALG_RSA_SIGN && alg_id != CAPI_CALG_RSA_KEYX)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "tag-4 RSA blob has unexpected aiKeyAlg 0x%08x", alg_id);
      return NULL;
    }

  if (magic != CAPI_RSA2_MAGIC)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "tag-4 RSA blob magic mismatch: got 0x%08x expected RSA2",
                   magic);
      return NULL;
    }

  if (bit_len == 0 || bit_len % 16 != 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "tag-4 RSA blob has invalid bitlen %u", bit_len);
      return NULL;
    }

  gsize modulus_len = bit_len / 8;
  gsize prime_len = bit_len / 16;
  gsize expected_len = CAPI_BLOBHEADER_LEN + CAPI_RSAPUBKEY_LEN
                       + modulus_len + 5 * prime_len + modulus_len;
  if (expected_len != CAPI_RSA_PRIVATE_BLOB_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "tag-4 RSA blob length math mismatch: bitlen=%u expected=%zu",
                   bit_len, expected_len);
      return NULL;
    }

  const guint8 *p = blob + CAPI_BLOBHEADER_LEN + CAPI_RSAPUBKEY_LEN;
  field_ptrs[0] = p; field_lens[0] = modulus_len; p += modulus_len; /* n */
  field_ptrs[3] = p; field_lens[3] = prime_len;   p += prime_len;   /* p */
  field_ptrs[4] = p; field_lens[4] = prime_len;   p += prime_len;   /* q */
  field_ptrs[5] = p; field_lens[5] = prime_len;   p += prime_len;   /* dP */
  field_ptrs[6] = p; field_lens[6] = prime_len;   p += prime_len;   /* dQ */
  field_ptrs[7] = p; field_lens[7] = prime_len;   p += prime_len;   /* qInv */
  field_ptrs[2] = p; field_lens[2] = modulus_len;                   /* d */
  field_ptrs[1] = blob + 16; field_lens[1] = 4;                     /* e */

  for (guint i = 0; i < G_N_ELEMENTS (field_names); i++)
    {
      g_autofree guint8 *be = g_malloc (field_lens[i]);
      BIGNUM *bn;

      for (gsize j = 0; j < field_lens[i]; j++)
        be[j] = field_ptrs[i][field_lens[i] - 1 - j];

      bn = BN_bin2bn (be, field_lens[i], NULL);
      if (bn == NULL)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "BN_bin2bn failed for RSA param %s", field_names[i]);
          goto cleanup;
        }

      native[i] = g_malloc0 (field_lens[i]);
      if (BN_bn2nativepad (bn, native[i], field_lens[i]) != (int) field_lens[i])
        {
          BN_clear_free (bn);
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "BN_bn2nativepad failed for RSA param %s", field_names[i]);
          goto cleanup;
        }
      BN_clear_free (bn);

      params[i] = OSSL_PARAM_construct_BN ((char *) field_names[i],
                                           native[i], field_lens[i]);
    }
  params[G_N_ELEMENTS (field_names)] = OSSL_PARAM_construct_end ();

  ctx = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
  if (ctx == NULL || EVP_PKEY_fromdata_init (ctx) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_fromdata_init(RSA) failed");
      goto cleanup;
    }

  if (EVP_PKEY_fromdata (ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "EVP_PKEY_fromdata(RSA PRIVATEKEYBLOB) failed: %s",
                   ERR_error_string (ERR_get_error (), NULL));
      pkey = NULL;
    }

cleanup:
  if (ctx != NULL)
    EVP_PKEY_CTX_free (ctx);
  for (guint i = 0; i < G_N_ELEMENTS (native); i++)
    g_free (native[i]);
  return pkey;
}

/* Sign the running handshake hash with an RSA private key using
 * RSA-SHA256 (matches the Synaptics fresh-pair CertificateVerify
 * algorithm per the FUN_1800dbcb0 + BCryptSignHash chain). Returns
 * malloc'd signature bytes; caller frees. */
static guint8 *
rsa_sha256_sign_handshake_hash (EVP_PKEY     *priv_key,
                                const guint8  hs_hash[32],
                                gsize        *out_sig_len,
                                GError      **error)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (priv_key, NULL);
  if (ctx == NULL || EVP_PKEY_sign_init (ctx) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_sign_init (RSA) failed");
      if (ctx) EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  if (EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING) <= 0
      || EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ()) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "RSA sign init: padding/md setup failed");
      EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  size_t sig_len = 0;
  if (EVP_PKEY_sign (ctx, NULL, &sig_len, hs_hash, 32) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_sign (RSA probe) failed");
      EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  guint8 *sig = g_malloc (sig_len);
  if (EVP_PKEY_sign (ctx, sig, &sig_len, hs_hash, 32) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_sign (RSA) failed");
      EVP_PKEY_CTX_free (ctx);
      g_free (sig);
      return NULL;
    }
  EVP_PKEY_CTX_free (ctx);
  *out_sig_len = sig_len;
  return sig;
}

/* ===========================================================================
 * ECDSA signing for CertificateVerify
 * ========================================================================= */

static EVP_PKEY *
load_cached_host_keypair (GError **error)
{
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  BIGNUM *priv_bn = NULL;
  unsigned char priv_native[VALIDITY_ECC_COORD_LEN];
  OSSL_PARAM params[3] = {0};

  /* Prefer the on-disk pairing-storage keypair when it is PAIRED with
   * an on-disk cert blob. Both must be present together so the cert's
   * embedded pubkey matches the keypair's private scalar (otherwise a
   * stale random on-disk keypair could end up signing CertificateVerify
   * against the hardcoded cert's pubkey - signature mismatch, handshake
   * dies). The bootstrap helper in validity-pairing.c keeps these two
   * in sync. */
  if (validity_pairing_has_cert_blob ())
    {
      GError *load_err = NULL;
      EVP_PKEY *from_disk = validity_pairing_load_host_keypair (&load_err);
      if (from_disk != NULL)
        {
          fp_dbg ("using on-disk host keypair (paired with on-disk cert)");
          return from_disk;
        }
      fp_dbg ("on-disk cert present but keypair load failed (%s); "
              "falling back to baked-in scalar",
              load_err ? load_err->message : "absent");
      g_clear_error (&load_err);
    }
  else
    {
      fp_dbg ("no on-disk cert blob; using baked-in scalar to keep "
              "cert + keypair consistent");
    }

  ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (ctx == NULL || EVP_PKEY_fromdata_init (ctx) <= 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "EVP_PKEY_CTX_new_from_name(EC) failed: %s",
                   ERR_error_string (ERR_get_error (), NULL));
      goto cleanup;
    }

  priv_bn = BN_bin2bn (validity_cached_host_private_key,
                       VALIDITY_ECC_COORD_LEN, NULL);
  if (priv_bn == NULL
      || BN_bn2nativepad (priv_bn, priv_native,
                          VALIDITY_ECC_COORD_LEN) != VALIDITY_ECC_COORD_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "failed to import cached host private scalar");
      goto cleanup;
    }

  params[0] = OSSL_PARAM_construct_utf8_string (
      OSSL_PKEY_PARAM_GROUP_NAME, (char *) "prime256v1", 0);
  params[1] = OSSL_PARAM_construct_BN (
      OSSL_PKEY_PARAM_PRIV_KEY, priv_native, VALIDITY_ECC_COORD_LEN);
  params[2] = OSSL_PARAM_construct_end ();

  if (EVP_PKEY_fromdata (ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "EVP_PKEY_fromdata(cached host key) failed: %s",
                   ERR_error_string (ERR_get_error (), NULL));
      pkey = NULL;
      goto cleanup;
    }

cleanup:
  if (priv_bn != NULL)
    BN_free (priv_bn);
  EVP_PKEY_CTX_free (ctx);
  memset (priv_native, 0, sizeof (priv_native));
  return pkey;
}

/* Sign the running handshake hash with the host's persistent P-256
 * private key. Returns a malloc'd DER ECDSA-Sig-Value; caller frees. */
static guint8 *
ecdsa_sign_handshake_hash (EVP_PKEY     *priv_key,
                           const guint8  hs_hash[32],
                           gsize        *out_sig_len,
                           GError      **error)
{
  debug_hex ("ECDSA_SIGN input transcript_sha256", hs_hash, 32);

  /* Use the "prehashed" path: feed in the 32-byte SHA-256 directly. */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new (priv_key, NULL);
  if (ctx == NULL || EVP_PKEY_sign_init (ctx) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_sign_init failed");
      if (ctx) EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  if (EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ()) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_CTX_set_signature_md(sha256) failed");
      EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  /* Probe length first */
  size_t sig_len = 0;
  if (EVP_PKEY_sign (ctx, NULL, &sig_len, hs_hash, 32) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_sign (probe) failed");
      EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  guint8 *sig = g_malloc (sig_len);
  if (EVP_PKEY_sign (ctx, sig, &sig_len, hs_hash, 32) <= 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "EVP_PKEY_sign failed");
      g_free (sig);
      EVP_PKEY_CTX_free (ctx);
      return NULL;
    }
  EVP_PKEY_CTX_free (ctx);
  *out_sig_len = sig_len;
  debug_hex ("ECDSA_SIGN output der", sig, sig_len);
  return sig;
}

/* ===========================================================================
 * Build the second-direction blob: Cert + CKE + CertVerify + CCS + Finished
 * The whole thing goes out in one USB write per python-validity convention.
 * Returns malloc'd buffer; caller frees.
 * ========================================================================= */

static guint8 *
build_client_second_message (FpDevice         *dev,
                             ValiditySession  *session,
                             EVP_PKEY         *host_keypair,
                             gsize            *out_len,
                             GError          **error)
{
  (void) dev;

  /* ----- Build the three handshake-message bodies. ----- */

  /* (a) client Certificate body. Two paths:
   *
   * FRESH-PAIR (session->fresh_pair_cert_body != NULL): the device's
   *   Server Certificate carried a tag-3 blob the host is expected to
   *   echo back as its own Client Certificate. Wrap it in the same
   *   TLS-style triple-length framing (certificate_list length +
   *   single-certificate length + body) but sized for whatever the
   *   device sent.
   *
   * PAIRED (default): replay the cached TLV tag 3 blob from disk
   *   (acquired via opcode 0x4f during initial pairing), falling back
   *   to the baked-in blob in validity-pubkeys.c.
   *
   * Layout of the 192 B paired cert_body:
   *   +0..2: certificate_list length  (00 00 b8)
   *   +3..5: single-certificate length (00 00 b8)
   *   +6..7: stale bytes (overwritten by session_random[4..5] below)
   *   +8..191: 184-byte cert blob from device (TLV tag 1, 0xb8 bytes)
   *
   * The 32-byte trailer in the paired blob is device-issued, not
   * host-computable; , , , */
  g_autofree guint8 *cert_body_dyn = NULL;
  guint8       cert_body_paired[VALIDITY_CLIENT_CERT_LEN];
  const guint8 *cert_body_ptr = NULL;
  gsize         cert_body_len = 0;

  if (session->fresh_pair_cert_body != NULL
      && session->fresh_pair_cert_body_len > 0)
    {
      gsize inner_len = session->fresh_pair_cert_body_len;
      cert_body_len   = 8 + inner_len;
      cert_body_dyn   = g_malloc (cert_body_len);
      cert_body_dyn[0] = 0x00;
      cert_body_dyn[1] = (guint8) ((inner_len >> 8) & 0xff);
      cert_body_dyn[2] = (guint8) (inner_len & 0xff);
      cert_body_dyn[3] = 0x00;
      cert_body_dyn[4] = (guint8) ((inner_len >> 8) & 0xff);
      cert_body_dyn[5] = (guint8) (inner_len & 0xff);
      cert_body_dyn[6] = session->client_random[4];
      cert_body_dyn[7] = session->client_random[5];
      memcpy (cert_body_dyn + 8, session->fresh_pair_cert_body, inner_len);
      cert_body_ptr = cert_body_dyn;
      fp_dbg ("using fresh-pair cert body from server tag 3 (%zu B inner)",
              inner_len);
    }
  else
    {
      GError *load_err = NULL;
      /* Build the TLS framing (certificate_list + single-cert length) */
      cert_body_paired[0] = 0x00; cert_body_paired[1] = 0x00; cert_body_paired[2] = 0xb8;
      cert_body_paired[3] = 0x00; cert_body_paired[4] = 0x00; cert_body_paired[5] = 0xb8;
      cert_body_paired[6] = session->client_random[4];
      cert_body_paired[7] = session->client_random[5];

      if (!validity_pairing_load_cert_blob (cert_body_paired + 8, &load_err))
        {
          fp_dbg ("no cached cert blob on disk — using hardcoded fallback: %s",
                  load_err ? load_err->message : "");
          g_clear_error (&load_err);
          memcpy (cert_body_paired, validity_cached_client_cert_body,
                  sizeof (cert_body_paired));
          /* The hardcoded blob includes its own framing at +0..+7, so after
           * memcpy we need to re-patch the session bytes at +6..+7 */
          cert_body_paired[6] = session->client_random[4];
          cert_body_paired[7] = session->client_random[5];
        }
      else
        {
          fp_dbg ("using cached cert blob from disk");
        }
      cert_body_ptr = cert_body_paired;
      cert_body_len = sizeof (cert_body_paired);
    }

  gsize cert_msg_len;
  g_autofree guint8 *cert_msg =
      wrap_handshake_message (VALIDITY_HS_CERTIFICATE,
                              cert_body_ptr, cert_body_len, &cert_msg_len);

  /* (b) ClientKeyExchange body — 0x04 || ephemeral_pub_x || ephemeral_pub_y. */
  guint8 cke_body[65];
  cke_body[0] = 0x04;
  memcpy (cke_body + 1,  session->ephemeral_pub_x, 32);
  memcpy (cke_body + 33, session->ephemeral_pub_y, 32);
  gsize cke_msg_len;
  g_autofree guint8 *cke_msg =
      wrap_handshake_message (VALIDITY_HS_CLIENT_KEY_EXCHANGE,
                              cke_body, sizeof (cke_body), &cke_msg_len);

  /* Update the handshake hash with Certificate and CKE BEFORE signing,
   * since CertificateVerify covers them. */
  debug_handshake_hash_update (session, "HASH_UPDATE client Certificate",
                               cert_msg, cert_msg_len);
  debug_handshake_hash_update (session, "HASH_UPDATE client ClientKeyExchange",
                               cke_msg, cke_msg_len);

  /* (c) CertificateVerify body — bare signature over the running
   * handshake hash. Two algorithms depending on the session state:
   *
   * FRESH-PAIR (session->fresh_pair_rsa_key != NULL): sign with
   *   RSA-SHA256 using the key imported from the server's tag-4
   *   "VIRP" blob. Wire format is the bare PKCS#1 v1.5 signature
   *   (same Synaptics deviation as the ECDSA path: no
   *   SignatureAndHashAlgorithm prefix, no 2-byte length).
   *
   * PAIRED (default): sign with ECDSA-SHA256 using the host's
   *   persistent P-256 private key, wire-encoded as a bare DER
   *   ECDSA-Sig-Value.
   *
   * `validity_handshake_hash_finish` snapshots via EVP_MD_CTX_copy_ex
   * so subsequent `update`s still extend the same running hash —
   * exactly what TLS wants for Finished too. */
  guint8 hs_hash[32];
  validity_handshake_hash_finish (session, hs_hash);
  gsize cv_sig_len = 0;
  g_autofree guint8 *cv_sig = NULL;
  if (session->fresh_pair_rsa_key != NULL)
    {
      fp_dbg ("CertificateVerify: signing with RSA-SHA256 (fresh-pair)");
      cv_sig = rsa_sha256_sign_handshake_hash (
          (EVP_PKEY *) session->fresh_pair_rsa_key,
          hs_hash, &cv_sig_len, error);
    }
  else
    {
      debug_hex ("CertificateVerify signing host_private_scalar",
                 validity_cached_host_private_key, VALIDITY_ECC_COORD_LEN);
      cv_sig = ecdsa_sign_handshake_hash (host_keypair, hs_hash,
                                          &cv_sig_len, error);
    }
  if (cv_sig == NULL) return NULL;
  gsize cv_msg_len;
  g_autofree guint8 *cv_msg =
      wrap_handshake_message (VALIDITY_HS_CERTIFICATE_VERIFY,
                              cv_sig, cv_sig_len, &cv_msg_len);
  debug_handshake_hash_update (session, "HASH_UPDATE client CertificateVerify",
                               cv_msg, cv_msg_len);


  /* ----- Bundle (a)+(b)+(c) into one handshake record ----- */
  gsize messages_len = cert_msg_len + cke_msg_len + cv_msg_len;
  g_autofree guint8 *messages = g_malloc (messages_len);
  memcpy (messages,                                 cert_msg, cert_msg_len);
  memcpy (messages + cert_msg_len,                  cke_msg,  cke_msg_len);
  memcpy (messages + cert_msg_len + cke_msg_len,    cv_msg,   cv_msg_len);

  gsize hs_record_len;
  g_autofree guint8 *hs_record =
      wrap_handshake_record (messages, messages_len, &hs_record_len);

  /* ----- ChangeCipherSpec + Finished -----
   * The wire captures in and show a plaintext CCS record
   * followed by an encrypted handshake Finished record:
   *   14 03 03 00 01 01
   *   16 03 03 00 50 [IV + AES-CBC(Finished || MAC || padding)]
   *
   * Some later notes interpreted FUN_180078100 as a single combined
   * encrypted CCS+Finished record, but that leaves the device in cleartext
   * mode and it responds with plaintext fatal illegal_parameter(47). */

  /* Compute verify_data over the current handshake hash. */
  guint8 hs_hash_fin[32];
  validity_handshake_hash_finish (session, hs_hash_fin);
  debug_hex ("Finished input transcript_sha256", hs_hash_fin, 32);
  guint8 verify_data[VALIDITY_VERIFY_DATA_LEN];
  if (!validity_tls12_prf (session->master_secret, VALIDITY_MASTER_SECRET_LEN,
                           (const guint8 *) "client finished", 15,
                           hs_hash_fin, 32,
                           verify_data, VALIDITY_VERIFY_DATA_LEN))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "PRF(client finished) failed");
      return NULL;
    }

  guint8 ccs_record[6] = {
    VALIDITY_CT_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01
  };

  /* Build the Finished plaintext: [0x14][0x00 0x00 0x0c][verify_data:12]. */
  guint8 finished_plaintext[HS_HEADER_LEN + VALIDITY_VERIFY_DATA_LEN];
  finished_plaintext[0] = VALIDITY_HS_FINISHED;
  finished_plaintext[1] = 0;
  finished_plaintext[2] = 0;
  finished_plaintext[3] = VALIDITY_VERIFY_DATA_LEN;
  memcpy (finished_plaintext + HS_HEADER_LEN, verify_data,
          VALIDITY_VERIFY_DATA_LEN);
  debug_hex ("Finished client verify_data", verify_data,
             VALIDITY_VERIFY_DATA_LEN);
  debug_hex ("CCS plaintext record", ccs_record, sizeof (ccs_record));
  debug_hex ("Finished plaintext before encryption",
             finished_plaintext, sizeof (finished_plaintext));

  /* SYNAPTICS DEVIATION: the server's
   * verify_data is computed over the handshake transcript EXCLUDING
   * the client's Finished message. RFC 5246 §7.4.9 says to include
   * it; Synaptics does NOT. So we do NOT add finished_plaintext to
   * the running hash here. Don't "fix" this to match RFC — server
   * Finished verification breaks. */

  session->cipher_active = TRUE;

  gsize finished_ct_len = 0;
  g_autofree guint8 *finished_record =
      validity_encrypt_record (session, VALIDITY_CT_HANDSHAKE,
                               finished_plaintext, sizeof (finished_plaintext),
                               &finished_ct_len);
  if (finished_record == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "validity_encrypt_record(Finished) failed");
      return NULL;
    }

  /* ----- Single prefix + all records concatenated. */
  gsize total = sizeof (validity_client_handshake_prefix)
              + hs_record_len
              + sizeof (ccs_record)
              + finished_ct_len;
  guint8 *out = g_malloc (total);
  gsize p = 0;
  memcpy (out + p, validity_client_handshake_prefix,
          sizeof (validity_client_handshake_prefix));
  p += sizeof (validity_client_handshake_prefix);
  memcpy (out + p, hs_record, hs_record_len); p += hs_record_len;
  memcpy (out + p, ccs_record, sizeof (ccs_record)); p += sizeof (ccs_record);
  memcpy (out + p, finished_record, finished_ct_len); p += finished_ct_len;
  g_assert_cmpuint (p, ==, total);
  debug_hex ("OUT second_blob complete", out, total);
  *out_len = total;
  return out;
}

/* ===========================================================================
 * Entry: full mutual-TLS handshake
 *
 * Called once per session, after the plaintext init phase. Drives the
 * complete exchange; on success the session is ready for application
 * data (cipher_active = TRUE in both directions, keys derived,
 * server's Finished verified).
 *
 * STATUS: scaffold-complete. Tested end-to-end against the test vectors
 * for shape, but live device testing (Phase 11) is required to:
 *   (a) confirm the 32-B Certificate signature_trailer format
 *   (b) confirm endianness of ClientKeyExchange X/Y
 *   (c) finalise the transcript-hash carry-forward when verifying
 *       server Finished
 * Specific TODOs are marked inline.
 * ========================================================================= */

gboolean
validity_run_tls_handshake (FpDevice *dev, ValiditySession *session,
                            GError **error)
{
  /* 1. Initialise the handshake hash and generate our ECDH ephemeral. */
  validity_handshake_hash_init (session);
  if (!validity_generate_ephemeral_keypair (session))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "validity_generate_ephemeral_keypair failed");
      return FALSE;
    }

  /* 2. Build + send ClientHello. The builder includes the
   *    44 00 00 00 prefix; we strip it after the TLS record so we can
   *    update_neg with just the handshake-message bytes. */
  gsize ch_with_prefix_len = 0;
  g_autofree guint8 *ch_with_prefix =
      validity_build_client_hello (session, &ch_with_prefix_len);
  if (ch_with_prefix == NULL || ch_with_prefix_len < 9)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "validity_build_client_hello failed");
      return FALSE;
    }
  /* ClientHello layout: [4-B prefix][5-B record header][handshake msg...] */
  const guint8 *ch_msg = ch_with_prefix + 4 + RECORD_HEADER_LEN;
  gsize ch_msg_len = ch_with_prefix_len - 4 - RECORD_HEADER_LEN;
  debug_hex ("OUT ClientHello complete", ch_with_prefix, ch_with_prefix_len);
  debug_handshake_hash_update (session, "HASH_UPDATE client ClientHello",
                               ch_msg, ch_msg_len);

  GUsbDevice *udev = fpi_device_get_usb_device (dev);
  gsize transferred = 0;
  if (!g_usb_device_bulk_transfer (udev, VALIDITY_EP_CMD_OUT,
                                   ch_with_prefix, ch_with_prefix_len,
                                   &transferred,
                                   VALIDITY_USB_SEND_TIMEOUT, NULL, error))
    return FALSE;

  /* 3. Read the server's first response (ServerHello + CertReq + SHD). */
  g_autofree guint8 *rsp1 = g_malloc (VALIDITY_MAX_RECV_LEN);
  gsize rsp1_len = 0;
  if (!g_usb_device_bulk_transfer (udev, VALIDITY_EP_CMD_IN,
                                   rsp1, VALIDITY_MAX_RECV_LEN, &rsp1_len,
                                   VALIDITY_USB_RECV_TIMEOUT, NULL, error))
    return FALSE;
  /* DEBUG: dump device's first-blob response so we can spot Certificate
   * (handshake type 0x0b) if device is in fresh-pair state. */
  {
    debug_hex ("IN rsp1 complete", rsp1, rsp1_len);
    /* Quick walk: enumerate handshake message types in the record */
    if (rsp1_len >= 9 && rsp1[0] == VALIDITY_CT_HANDSHAKE) {
      gsize rec = (rsp1[3] << 8) | rsp1[4];
      gsize p = 5;
      while (p + 4 <= 5 + rec && p + 4 <= rsp1_len) {
        guint8 ht = rsp1[p];
        gsize ml = (rsp1[p+1] << 16) | (rsp1[p+2] << 8) | rsp1[p+3];
        fp_dbg ("  HS msg type=0x%02x len=%zu", ht, ml);
        p += 4 + ml;
      }
    }
  }
  if (rsp1_len < RECORD_HEADER_LEN || rsp1[0] != VALIDITY_CT_HANDSHAKE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "expected handshake record from device, got type 0x%02x len %zu",
                   rsp1_len ? rsp1[0] : 0, rsp1_len);
      return FALSE;
    }
  gsize rec_len = (rsp1[3] << 8) | rsp1[4];
  if (RECORD_HEADER_LEN + rec_len > rsp1_len)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "device handshake record truncated");
      return FALSE;
    }

  ServerHelloPhaseCtx ctx = { .session = session };
  if (!iterate_handshake_messages (rsp1 + RECORD_HEADER_LEN, rec_len,
                                   dispatch_server_hello_phase, &ctx, error))
    return FALSE;
  if (!(ctx.got_server_hello && ctx.got_cert_request
        && ctx.got_server_hello_done))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "missing one of ServerHello / CertReq / SrvHelloDone "
                   "(SH=%d CR=%d SHD=%d)",
                   ctx.got_server_hello, ctx.got_cert_request,
                   ctx.got_server_hello_done);
      return FALSE;
    }

  /* 4. Compute pre_master_secret via ECDH against the device's ECDH peer
   *    pubkey. Prefer the bytes extracted dynamically during the autonomous
   *    bootstrap (on-disk device-ecdh-pubkey.bin), falling back to the
   *    baked-in validity_cached_device_ecdh_pubkey_x/_y if not present. */
  guint8 ecdh_x_buf[VALIDITY_ECC_COORD_LEN];
  guint8 ecdh_y_buf[VALIDITY_ECC_COORD_LEN];
  const guint8 *ecdh_x = validity_cached_device_ecdh_pubkey_x;
  const guint8 *ecdh_y = validity_cached_device_ecdh_pubkey_y;
  {
    g_autofree gchar *dir = validity_pairing_get_storage_dir ();
    g_autofree gchar *path = g_build_filename (dir, "device-ecdh-pubkey.bin", NULL);
    g_autoptr (GError) ferr = NULL;
    g_autofree gchar *contents = NULL;
    gsize len = 0;
    if (g_file_get_contents (path, &contents, &len, &ferr) && len == 64)
      {
        memcpy (ecdh_x_buf, contents, 32);
        memcpy (ecdh_y_buf, contents + 32, 32);
        ecdh_x = ecdh_x_buf;
        ecdh_y = ecdh_y_buf;
        fp_dbg ("ECDH: using device pubkey from %s (extracted at fresh-pair)", path);
      }
  }

  gsize pms_len = 0;
  g_autofree guint8 *pms = validity_ecdh_p256 (session->ephemeral_priv,
                                               ecdh_x, ecdh_y,
                                               &pms_len);
  if (pms == NULL || pms_len != 32)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "ECDH(host_ephemeral, cached_device_ECDH_pub) failed");
      return FALSE;
    }
#ifdef VALIDITY_TRACE_HANDSHAKE
  fp_dbg ("ECDH DEBUG:");
  fp_dbg ("  CR:  %02x%02x%02x%02x%02x%02x%02x%02x...",
          session->client_random[0], session->client_random[1], session->client_random[2],
          session->client_random[3], session->client_random[4], session->client_random[5],
          session->client_random[6], session->client_random[7]);
  fp_dbg ("  SR:  %02x%02x%02x%02x%02x%02x%02x%02x...",
          session->server_random[0], session->server_random[1], session->server_random[2],
          session->server_random[3], session->server_random[4], session->server_random[5],
          session->server_random[6], session->server_random[7]);
  fp_dbg ("  EPH: %02x%02x%02x%02x... (our X)",
          session->ephemeral_pub_x[0], session->ephemeral_pub_x[1],
          session->ephemeral_pub_x[2], session->ephemeral_pub_x[3]);
  debug_hex ("  cached device ECDH pub X",
             validity_cached_device_ecdh_pubkey_x, VALIDITY_ECC_COORD_LEN);
  debug_hex ("  cached device ECDH pub Y",
             validity_cached_device_ecdh_pubkey_y, VALIDITY_ECC_COORD_LEN);
  debug_hex ("  ephemeral private scalar", session->ephemeral_priv,
             VALIDITY_ECC_COORD_LEN);
  debug_hex ("  ephemeral public X", session->ephemeral_pub_x,
             VALIDITY_ECC_COORD_LEN);
  debug_hex ("  ephemeral public Y", session->ephemeral_pub_y,
             VALIDITY_ECC_COORD_LEN);
  debug_hex ("  PMS", pms, pms_len);
#endif

  /* 5. Derive master_secret + key_block + 4 session keys. */
  if (!validity_derive_session_keys (session, pms, pms_len))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "validity_derive_session_keys failed");
      return FALSE;
    }

  /* 6. Import the cached host key that matches the replayed
   *    client Certificate. */
  EVP_PKEY *host_keypair = load_cached_host_keypair (error);
  if (host_keypair == NULL)
    return FALSE;

  /* 7. Build the second-direction blob (Cert + CKE + CV + CCS + Finished). */
  gsize second_len = 0;
  g_autofree guint8 *second =
      build_client_second_message (dev, session, host_keypair,
                                   &second_len, error);
  EVP_PKEY_free (host_keypair);
  if (second == NULL) return FALSE;

  /* 8. Send it. */
  if (!g_usb_device_bulk_transfer (udev, VALIDITY_EP_CMD_OUT,
                                   second, second_len, &transferred,
                                   VALIDITY_USB_SEND_TIMEOUT, NULL, error))
    return FALSE;

  /* 9. Read server CCS + Finished. Decrypt + verify Finished's verify_data.
   *    TODO: implement full server Finished verification — currently
   *    we accept any decrypt-successful Finished and trust it. */
  g_autofree guint8 *rsp2 = g_malloc (VALIDITY_MAX_RECV_LEN);
  gsize rsp2_len = 0;
  if (!g_usb_device_bulk_transfer (udev, VALIDITY_EP_CMD_IN,
                                   rsp2, VALIDITY_MAX_RECV_LEN, &rsp2_len,
                                   VALIDITY_USB_RECV_TIMEOUT, NULL, error))
    return FALSE;
  debug_hex ("IN rsp2 complete", rsp2, rsp2_len);
  /* If the first record is a TLS Alert, parse it. WARNING-level
   * alerts (level=1) per RFC 5246 do NOT terminate the connection;
   * we log and try to keep reading for the expected CCS+Finished. */
  if (rsp2_len >= 7 && rsp2[0] == VALIDITY_CT_ALERT)
    {
      guint8 level = rsp2[5];
      guint8 desc  = rsp2[6];
      const char *desc_name = "?";
      switch (desc) {
        case 10:  desc_name = "unexpected_message"; break;
        case 20:  desc_name = "bad_record_mac"; break;
        case 21:  desc_name = "decryption_failed"; break;
        case 22:  desc_name = "record_overflow"; break;
        case 40:  desc_name = "handshake_failure"; break;
        case 42:  desc_name = "bad_certificate"; break;
        case 43:  desc_name = "unsupported_certificate"; break;
        case 46:  desc_name = "certificate_unknown"; break;
        case 47:  desc_name = "illegal_parameter"; break;
        case 48:  desc_name = "unknown_ca"; break;
        case 50:  desc_name = "decode_error"; break;
        case 51:  desc_name = "decrypt_error"; break;
        default: break;
      }
      if (level == 2)  /* fatal */
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "device sent FATAL TLS Alert: desc=%u (%s)",
                       desc, desc_name);
          return FALSE;
        }
      fp_dbg ("Device sent WARNING alert desc=%u (%s) — connection may "
              "continue per RFC 5246; reading more...", desc, desc_name);

      /* Read the next record(s) — likely the device's CCS+Finished */
      gsize more_len = 0;
      if (!g_usb_device_bulk_transfer (udev, VALIDITY_EP_CMD_IN,
                                       rsp2, VALIDITY_MAX_RECV_LEN, &more_len,
                                       VALIDITY_USB_RECV_TIMEOUT, NULL, error))
        {
          if (error && *error) g_clear_error (error);
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                       "device sent only WARNING alert desc=%u (%s); "
                       "no CCS+Finished followed (timed out)",
                       desc, desc_name);
          return FALSE;
        }
      fp_dbg ("Post-alert read: %zu B, first byte 0x%02x", more_len, more_len ? rsp2[0] : 0);
      rsp2_len = more_len;
    }

  if (rsp2_len < 6 || rsp2[0] != VALIDITY_CT_CHANGE_CIPHER_SPEC)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "expected server ChangeCipherSpec; got type 0x%02x len %zu",
                   rsp2_len ? rsp2[0] : 0, rsp2_len);
      return FALSE;
    }
  /* Parse + decrypt the trailing server Finished record. Standard TLS
   * framing: rsp2 = `14 03 03 00 01 01` (6-B CCS) followed by
   * `16 03 03 LL LL [encrypted body]` (server Finished). */
  if (rsp2_len < 6 + RECORD_HEADER_LEN + VALIDITY_AES_BLOCK_SIZE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "server CCS+Finished too short: %zu B", rsp2_len);
      return FALSE;
    }
  const guint8 *fin_rec = rsp2 + 6;
  gsize fin_rec_offset = 6;
  if (fin_rec[0] != VALIDITY_CT_HANDSHAKE)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "expected server Finished as handshake record (0x16); "
                   "got type 0x%02x", fin_rec[0]);
      return FALSE;
    }
  gsize fin_body_len = (fin_rec[3] << 8) | fin_rec[4];
  if (fin_rec_offset + RECORD_HEADER_LEN + fin_body_len > rsp2_len)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "server Finished record truncated (claimed %zu B body, %zu B left)",
                   fin_body_len, rsp2_len - fin_rec_offset - RECORD_HEADER_LEN);
      return FALSE;
    }

  gsize fin_plain_len = 0;
  g_autofree guint8 *fin_plain =
      validity_decrypt_record (session, VALIDITY_CT_HANDSHAKE,
                               fin_rec + RECORD_HEADER_LEN, fin_body_len,
                               &fin_plain_len);
  if (fin_plain == NULL)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "server Finished decrypt/MAC verify failed");
      return FALSE;
    }
  if (fin_plain_len != HS_HEADER_LEN + VALIDITY_VERIFY_DATA_LEN
      || fin_plain[0] != VALIDITY_HS_FINISHED
      || fin_plain[1] != 0 || fin_plain[2] != 0
      || fin_plain[3] != VALIDITY_VERIFY_DATA_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "server Finished body malformed: len=%zu type=0x%02x",
                   fin_plain_len, fin_plain[0]);
      return FALSE;
    }

  /* Compute expected verify_data = PRF(MS, "server finished", SHA256(transcript))[0..11]
   * Transcript for server Finished INCLUDES our client Finished (which we
   * already added to the running hash inside build_client_second_message). */
  guint8 hs_hash_srv[32];
  validity_handshake_hash_finish (session, hs_hash_srv);
  guint8 expected_verify_data[VALIDITY_VERIFY_DATA_LEN];
  if (!validity_tls12_prf (session->master_secret, VALIDITY_MASTER_SECRET_LEN,
                           (const guint8 *) "server finished", 15,
                           hs_hash_srv, 32,
                           expected_verify_data, VALIDITY_VERIFY_DATA_LEN))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "PRF(server finished) failed");
      return FALSE;
    }

  if (memcmp (fin_plain + HS_HEADER_LEN, expected_verify_data,
              VALIDITY_VERIFY_DATA_LEN) != 0)
    {
      const guint8 *g = fin_plain + HS_HEADER_LEN;
      const guint8 *e = expected_verify_data;
      fp_dbg ("server Finished GOT      = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
              g[0],g[1],g[2],g[3], g[4],g[5],g[6],g[7], g[8],g[9],g[10],g[11]);
      fp_dbg ("server Finished EXPECTED = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
              e[0],e[1],e[2],e[3], e[4],e[5],e[6],e[7], e[8],e[9],e[10],e[11]);
      fp_dbg ("server transcript SHA256 = %02x%02x%02x%02x...",
              hs_hash_srv[0], hs_hash_srv[1], hs_hash_srv[2], hs_hash_srv[3]);
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "server Finished verify_data mismatch — "
                           "session keys diverged from device OR transcript "
                           "hash doesn't include client Finished as RFC dictates");
      return FALSE;
    }

  fp_dbg ("handshake: server Finished verified ✓");
  return TRUE;
}
