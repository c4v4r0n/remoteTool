/*
 * NTLMv2 + WS-Man message-sealing implementation.
 *
 * References:
 *   [MS-NLMP] NT LAN Manager (NTLM) Authentication Protocol,
 *             https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp
 *   [MS-WSMV] Web Services Management Protocol Extensions for Windows Vista,
 *             section 2.2.9.1 (multipart/encrypted message body)
 *
 * Scope (matches what default-config Windows accepts):
 *   - NTLMv2 only. No NTLMv1.
 *   - NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY mandatory (we
 *     always set it; key derivation depends on it).
 *   - NTLMSSP_NEGOTIATE_KEY_EXCH always set; we generate a fresh
 *     ExportedSessionKey instead of reusing the SessionBaseKey.
 *   - We do NOT compute the optional MIC field (servers using the
 *     factory `winrm quickconfig` config don't require it). If your
 *     deployment forces MIC, the server will reject Type3 with 401
 *     and the error path surfaces it.
 *   - SPNEGO wrapper is omitted; raw NTLMSSP under "Negotiate"
 *     authorisation header. Windows accepts both.
 *
 * Threading: instances are owned by a single thread (the WinRM
 * worker). No internal locking.
 */

#include "protocols/winrm/winrm_ntlm.h"
#include "protocols/winrm/winrm_crypto.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Negotiate flags                                                    */
/* ------------------------------------------------------------------ */

#define NTLM_NEGOTIATE_56                       0x80000000u
#define NTLM_NEGOTIATE_KEY_EXCH                 0x40000000u
#define NTLM_NEGOTIATE_128                      0x20000000u
#define NTLM_NEGOTIATE_VERSION                  0x02000000u
#define NTLM_NEGOTIATE_TARGET_INFO              0x00800000u
#define NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY 0x00080000u
#define NTLM_NEGOTIATE_ALWAYS_SIGN              0x00008000u
#define NTLM_NEGOTIATE_NTLM                     0x00000200u
#define NTLM_NEGOTIATE_SEAL                     0x00000020u
#define NTLM_NEGOTIATE_SIGN                     0x00000010u
#define NTLM_REQUEST_TARGET                     0x00000004u
#define NTLM_NEGOTIATE_OEM                      0x00000002u
#define NTLM_NEGOTIATE_UNICODE                  0x00000001u

/* What we advertise. Matches the working set used by ntlm-auth /
 * pywinrm against modern Windows (10/11/Server 2016+). */
#define NTLM_FLAGS_TYPE1                                                \
    ( NTLM_NEGOTIATE_56                                                  \
    | NTLM_NEGOTIATE_KEY_EXCH                                            \
    | NTLM_NEGOTIATE_128                                                 \
    | NTLM_NEGOTIATE_VERSION                                             \
    | NTLM_NEGOTIATE_TARGET_INFO                                         \
    | NTLM_NEGOTIATE_EXTENDED_SESSIONSECURITY                            \
    | NTLM_NEGOTIATE_ALWAYS_SIGN                                         \
    | NTLM_NEGOTIATE_NTLM                                                \
    | NTLM_NEGOTIATE_SEAL                                                \
    | NTLM_NEGOTIATE_SIGN                                                \
    | NTLM_REQUEST_TARGET                                                \
    | NTLM_NEGOTIATE_OEM                                                 \
    | NTLM_NEGOTIATE_UNICODE)

/* Static OS version block. Windows 10 build 16299 / NTLMSSP rev 15.
 * Servers don't validate this beyond format. */
static const uint8_t NTLM_VERSION_BLOB[8] = {
    0x0a, 0x00, 0xaa, 0x3f, 0x00, 0x00, 0x00, 0x0f
};

#define NTLMSSP_SIGNATURE "NTLMSSP\0"  /* 8 bytes including the NUL */

/* ------------------------------------------------------------------ */
/* Tiny byte-buffer helper                                            */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
} buf_t;

static int buf_grow(buf_t *b, size_t need)
{
    if (b->len + need <= b->cap) return 0;
    size_t nc = b->cap ? b->cap : 64;
    while (nc < b->len + need) nc *= 2;
    uint8_t *nb = realloc(b->buf, nc);
    if (nb == NULL) return -1;
    b->buf = nb;
    b->cap = nc;
    return 0;
}

static int buf_append(buf_t *b, const void *data, size_t len)
{
    if (buf_grow(b, len) != 0) return -1;
    if (len > 0) memcpy(b->buf + b->len, data, len);
    b->len += len;
    return 0;
}

static int buf_append_u32_le(buf_t *b, uint32_t v)
{
    uint8_t tmp[4] = {
        (uint8_t)(v),       (uint8_t)(v >> 8),
        (uint8_t)(v >> 16), (uint8_t)(v >> 24),
    };
    return buf_append(b, tmp, 4);
}

static int buf_append_u16_le(buf_t *b, uint16_t v)
{
    uint8_t tmp[2] = { (uint8_t)v, (uint8_t)(v >> 8) };
    return buf_append(b, tmp, 2);
}

/* ------------------------------------------------------------------ */
/* Little-endian readers                                              */
/* ------------------------------------------------------------------ */

static uint16_t rd_u16_le(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] <<  8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/* NTLMv2 hashes / response                                           */
/* ------------------------------------------------------------------ */

/* NTOWFv2(passwd, user, domain) =
 *   HMAC_MD5(MD4(unicode(passwd)), unicode(uppercase(user) || domain)) */
static int compute_ntowfv2(const char *user,
                           const char *domain,
                           const char *password,
                           uint8_t     out[16])
{
    /* Step 1: NT hash = MD4(UTF-16LE(password)). */
    size_t pw16_len = 0;
    uint8_t *pw16 = winrm_utf8_to_utf16le(password ? password : "", &pw16_len);
    if (pw16 == NULL) return -1;
    uint8_t nt_hash[16];
    winrm_md4(pw16, pw16_len, nt_hash);
    explicit_bzero(pw16, pw16_len);
    free(pw16);

    /* Step 2: HMAC_MD5 input = UTF-16LE(uppercase(user) || domain). */
    size_t user_len = (user ? strlen(user) : 0);
    char *user_uc = malloc(user_len + 1);
    if (user_uc == NULL) {
        explicit_bzero(nt_hash, 16);
        return -1;
    }
    for (size_t i = 0; i < user_len; i++) {
        unsigned char c = (unsigned char)user[i];
        user_uc[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : (char)c;
    }
    user_uc[user_len] = '\0';

    size_t dom_len = (domain ? strlen(domain) : 0);
    size_t comb_len = user_len + dom_len;
    char *comb = malloc(comb_len + 1);
    if (comb == NULL) {
        free(user_uc);
        explicit_bzero(nt_hash, 16);
        return -1;
    }
    memcpy(comb,            user_uc, user_len);
    if (dom_len > 0) memcpy(comb + user_len, domain,  dom_len);
    comb[comb_len] = '\0';

    size_t comb16_len = 0;
    uint8_t *comb16 = winrm_utf8_to_utf16le(comb, &comb16_len);
    free(comb);
    free(user_uc);
    if (comb16 == NULL) {
        explicit_bzero(nt_hash, 16);
        return -1;
    }

    winrm_hmac_md5(nt_hash, 16, comb16, comb16_len, out);
    explicit_bzero(nt_hash, 16);
    free(comb16);
    return 0;
}

/* Windows file time = 100ns intervals since 1601-01-01 UTC. */
static uint64_t windows_filetime_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* Seconds between 1601-01-01 and 1970-01-01 = 11644473600. */
    uint64_t secs_since_1601 = (uint64_t)ts.tv_sec + 11644473600ULL;
    uint64_t hundred_ns = secs_since_1601 * 10000000ULL +
                          (uint64_t)(ts.tv_nsec / 100);
    return hundred_ns;
}

/* ------------------------------------------------------------------ */
/* Sign/Seal key derivation ([MS-NLMP] 3.4.5)                         */
/* ------------------------------------------------------------------ */

static const char SIGN_C2S[] =
    "session key to client-to-server signing key magic constant";
static const char SIGN_S2C[] =
    "session key to server-to-client signing key magic constant";
static const char SEAL_C2S[] =
    "session key to client-to-server sealing key magic constant";
static const char SEAL_S2C[] =
    "session key to server-to-client sealing key magic constant";

/* Derive a 16-byte sub-key. The trailing NUL of the magic constant
 * IS part of the input, per [MS-NLMP] 3.4.5.2 (sizeof includes it). */
static void derive_subkey(const uint8_t *eskey, const char *konst,
                          uint8_t out[16])
{
    size_t klen = strlen(konst) + 1;  /* include NUL */
    uint8_t *buf = malloc(16 + klen);
    if (buf == NULL) { memset(out, 0, 16); return; }
    memcpy(buf,      eskey, 16);
    memcpy(buf + 16, konst, klen);
    winrm_md5(buf, 16 + klen, out);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* Public init / reset                                                */
/* ------------------------------------------------------------------ */

void winrm_ntlm_init(winrm_ntlm_t *n)
{
    memset(n, 0, sizeof(*n));
    char host[256];
    if (gethostname(host, sizeof(host)) != 0 || host[0] == '\0') {
        snprintf(host, sizeof(host), "WORKSTATION");
    }
    host[sizeof(host) - 1] = '\0';
    /* Uppercase, NetBIOS-friendly. */
    for (char *p = host; *p; ++p) {
        if (*p >= 'a' && *p <= 'z') *p = (char)(*p - 32);
        if (*p == '.') { *p = '\0'; break; }
    }
    n->workstation = strdup(host);
}

void winrm_ntlm_reset(winrm_ntlm_t *n)
{
    if (n == NULL) return;
    char    *ws  = n->workstation;
    uint8_t *t1  = n->type1_bytes;
    size_t   t1l = n->type1_bytes_len;
    explicit_bzero(n, sizeof(*n));
    n->workstation     = ws;
    n->type1_bytes     = t1;
    n->type1_bytes_len = t1l;
}

/* ------------------------------------------------------------------ */
/* Type 1 NEGOTIATE                                                   */
/* ------------------------------------------------------------------ */

int winrm_ntlm_build_type1(winrm_ntlm_t  *n,
                           uint8_t      **out,
                           size_t        *out_len)
{
    (void)n;
    if (out == NULL || out_len == NULL) return -1;

    buf_t b = {0};
    /* Signature + MessageType. */
    if (buf_append    (&b, NTLMSSP_SIGNATURE, 8)        != 0) goto fail;
    if (buf_append_u32_le(&b, 0x00000001)               != 0) goto fail;
    /* NegotiateFlags. */
    if (buf_append_u32_le(&b, NTLM_FLAGS_TYPE1)         != 0) goto fail;
    /* DomainNameFields - empty. (len=0, maxlen=0, offset=0). */
    if (buf_append_u16_le(&b, 0) != 0) goto fail;
    if (buf_append_u16_le(&b, 0) != 0) goto fail;
    if (buf_append_u32_le(&b, 0) != 0) goto fail;
    /* WorkstationFields - empty. */
    if (buf_append_u16_le(&b, 0) != 0) goto fail;
    if (buf_append_u16_le(&b, 0) != 0) goto fail;
    if (buf_append_u32_le(&b, 0) != 0) goto fail;
    /* Version. */
    if (buf_append(&b, NTLM_VERSION_BLOB, 8) != 0) goto fail;

    /* Stash a copy for later MIC computation. Best-effort: if
     * allocation fails we skip MIC and the server may downgrade us. */
    free(n->type1_bytes);
    n->type1_bytes     = malloc(b.len);
    n->type1_bytes_len = 0;
    if (n->type1_bytes != NULL) {
        memcpy(n->type1_bytes, b.buf, b.len);
        n->type1_bytes_len = b.len;
    }

    *out     = b.buf;
    *out_len = b.len;
    return 0;

fail:
    free(b.buf);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Type 2 parsing helpers                                             */
/* ------------------------------------------------------------------ */

/* Read a security buffer (8 bytes: len, maxlen, offset) starting at
 * `hdr_off`. Returns 0 if it fits within `total_len`. */
static int read_secbuf(const uint8_t *msg, size_t total_len,
                       size_t hdr_off,
                       uint16_t *out_len, uint32_t *out_offset)
{
    if (hdr_off + 8 > total_len) return -1;
    uint16_t len    = rd_u16_le(msg + hdr_off);
    /* maxlen at +2 (ignored) */
    uint32_t offset = rd_u32_le(msg + hdr_off + 4);
    if ((size_t)offset + (size_t)len > total_len) return -1;
    if (out_len)    *out_len    = len;
    if (out_offset) *out_offset = offset;
    return 0;
}

/* Walk the AV_PAIR list in `in` (AvId u16le, AvLen u16le, value...,
 * terminated by AvId=MsvAvEOL=0). Produce a copy in `out` that has
 * MsvAvFlags (AvId=6) set to (existing|0x00000002), inserting a new
 * MsvAvFlags AV_PAIR before the EOL if it wasn't there. The 0x02 bit
 * is the [MS-NLMP] indicator that the AUTHENTICATE_MESSAGE includes
 * a MIC field; modern Windows refuses sensitive WSMan operations
 * (with status 500 / wsa:AccessDenied) when the client doesn't both
 * advertise this flag and supply a matching MIC. */
static int target_info_with_mic_flag(const uint8_t  *in,  size_t in_len,
                                     uint8_t       **out, size_t *out_len)
{
    /* First pass: validate framing and detect existing MsvAvFlags. */
    size_t pos       = 0;
    int    has_flags = 0;
    int    has_eol   = 0;
    while (pos + 4 <= in_len) {
        uint16_t av_id  = rd_u16_le(in + pos);
        uint16_t av_len = rd_u16_le(in + pos + 2);
        if (av_id == 0) { has_eol = 1; break; }
        if (pos + 4 + av_len > in_len) return -1;
        if (av_id == 6) has_flags = 1;
        pos += 4 + av_len;
    }
    if (!has_eol) return -1;

    /* Second pass: copy, mutating MsvAvFlags or inserting one. */
    size_t cap = in_len + 8;  /* room for one extra 4+4 AV_PAIR */
    uint8_t *buf = malloc(cap);
    if (buf == NULL) return -1;

    size_t in_p = 0, out_p = 0;
    while (in_p + 4 <= in_len) {
        uint16_t av_id  = rd_u16_le(in + in_p);
        uint16_t av_len = rd_u16_le(in + in_p + 2);

        if (av_id == 0) {
            if (!has_flags) {
                buf[out_p++] = 0x06; buf[out_p++] = 0x00;  /* AvId = 6 */
                buf[out_p++] = 0x04; buf[out_p++] = 0x00;  /* AvLen = 4 */
                buf[out_p++] = 0x02; buf[out_p++] = 0x00;
                buf[out_p++] = 0x00; buf[out_p++] = 0x00;  /* flags = 0x02 */
            }
            memcpy(buf + out_p, in + in_p, 4);  /* the EOL header itself */
            out_p += 4;
            in_p  += 4;
            break;
        }

        if (av_id == 6 && av_len >= 4) {
            memcpy(buf + out_p, in + in_p, 4);
            out_p += 4;
            uint32_t existing = rd_u32_le(in + in_p + 4);
            uint32_t new_v    = existing | 0x00000002u;
            buf[out_p++] = (uint8_t)(new_v      );
            buf[out_p++] = (uint8_t)(new_v >>  8);
            buf[out_p++] = (uint8_t)(new_v >> 16);
            buf[out_p++] = (uint8_t)(new_v >> 24);
            if (av_len > 4) {
                memcpy(buf + out_p, in + in_p + 4 + 4, av_len - 4);
                out_p += av_len - 4;
            }
            in_p += 4 + av_len;
        } else {
            memcpy(buf + out_p, in + in_p, 4 + av_len);
            out_p += 4 + av_len;
            in_p  += 4 + av_len;
        }
    }

    *out     = buf;
    *out_len = out_p;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Type 3 AUTHENTICATE                                                */
/* ------------------------------------------------------------------ */

int winrm_ntlm_build_type3(winrm_ntlm_t  *n,
                           const uint8_t *type2,
                           size_t         type2_len,
                           const char    *user,
                           const char    *domain,
                           const char    *password,
                           uint8_t      **out_type3,
                           size_t        *out_type3_len)
{
    if (n == NULL || type2 == NULL || out_type3 == NULL ||
        out_type3_len == NULL || user == NULL) {
        return -1;
    }
    *out_type3     = NULL;
    *out_type3_len = 0;

    /* Validate Type 2 framing. Layout per [MS-NLMP] 2.2.1.2:
     *   0..7   "NTLMSSP\0"
     *   8..11  MessageType (=0x00000002)
     *   12..19 TargetNameFields (security buffer)
     *   20..23 NegotiateFlags
     *   24..31 ServerChallenge (8 bytes)
     *   32..39 Reserved
     *   40..47 TargetInfoFields (security buffer)
     *   48..55 Version (optional)
     */
    if (type2_len < 48) return -1;
    if (memcmp(type2, NTLMSSP_SIGNATURE, 8) != 0) return -1;
    if (rd_u32_le(type2 + 8) != 0x00000002) return -1;

    const uint8_t *server_challenge = type2 + 24;
    /* Pull TargetInfo blob. We rewrite it to include MsvAvFlags=0x02,
     * which tells the server "I will provide a MIC" - required to
     * unlock the WinRM Shell endpoint on hardened/modern Windows
     * builds. The rewritten blob is the one we put into the NTLMv2
     * temp structure (and therefore into NtChallengeResponse). */
    uint16_t ti_len    = 0;
    uint32_t ti_offset = 0;
    if (read_secbuf(type2, type2_len, 40, &ti_len, &ti_offset) != 0) {
        return -1;
    }
    const uint8_t *raw_target_info = type2 + ti_offset;

    uint8_t *target_info     = NULL;
    size_t   target_info_len = 0;
    if (target_info_with_mic_flag(raw_target_info, ti_len,
                                  &target_info, &target_info_len) != 0) {
        return -1;
    }
    /* From here on `target_info` points at the heap copy; free at exit. */

    /* NTOWFv2. */
    uint8_t ntowfv2[16];
    if (compute_ntowfv2(user, domain, password, ntowfv2) != 0) {
        return -1;
    }

    /* Build the NTLMv2 "temp" blob:
     *   01 01 00 00 00 00 00 00      (signature)
     *   timestamp (8 bytes LE, Windows file time)
     *   client_challenge (8 random bytes)
     *   00 00 00 00                  (reserved2)
     *   target_info (verbatim from Type2)
     *   00 00 00 00                  (terminator)
     */
    uint8_t client_challenge[8];
    if (winrm_random(client_challenge, 8) != 0) {
        explicit_bzero(ntowfv2, 16);
        return -1;
    }

    buf_t temp = {0};
    static const uint8_t TEMP_HDR[8] = { 0x01,0x01,0x00,0x00,
                                          0x00,0x00,0x00,0x00 };
    if (buf_append(&temp, TEMP_HDR, 8) != 0)            goto fail_blob;
    uint64_t ft = windows_filetime_now();
    uint8_t ft_bytes[8];
    for (int i = 0; i < 8; i++) ft_bytes[i] = (uint8_t)(ft >> (i * 8));
    if (buf_append(&temp, ft_bytes,         8)       != 0) goto fail_blob;
    if (buf_append(&temp, client_challenge, 8)       != 0) goto fail_blob;
    if (buf_append_u32_le(&temp, 0x00000000)         != 0) goto fail_blob;
    if (buf_append(&temp, target_info, target_info_len) != 0) goto fail_blob;
    if (buf_append_u32_le(&temp, 0x00000000)            != 0) goto fail_blob;

    /* NtProofStr = HMAC_MD5(NTOWFv2, server_challenge || temp). */
    uint8_t *hash_in = malloc(8 + temp.len);
    if (hash_in == NULL) goto fail_blob;
    memcpy(hash_in,     server_challenge, 8);
    memcpy(hash_in + 8, temp.buf,         temp.len);
    uint8_t nt_proof[16];
    winrm_hmac_md5(ntowfv2, 16, hash_in, 8 + temp.len, nt_proof);
    free(hash_in);

    /* NtChallengeResponse = NtProofStr || temp. */
    buf_t nt_resp = {0};
    if (buf_append(&nt_resp, nt_proof, 16)        != 0) goto fail_resp;
    if (buf_append(&nt_resp, temp.buf, temp.len)  != 0) goto fail_resp;

    /* LmChallengeResponse = HMAC_MD5(NTOWFv2,
     *      server_challenge || lm_client_challenge) || lm_client_challenge.
     * For NTLMv2 + extended session security an all-zero LM response
     * is also commonly accepted; we send the proper computation for
     * maximum compatibility. */
    uint8_t lm_client_chal[8];
    if (winrm_random(lm_client_chal, 8) != 0) goto fail_resp;
    uint8_t lm_in[16];
    memcpy(lm_in,     server_challenge, 8);
    memcpy(lm_in + 8, lm_client_chal,   8);
    uint8_t lm_hmac[16];
    winrm_hmac_md5(ntowfv2, 16, lm_in, 16, lm_hmac);

    uint8_t lm_resp[24];
    memcpy(lm_resp,      lm_hmac,        16);
    memcpy(lm_resp + 16, lm_client_chal, 8);

    /* SessionBaseKey = HMAC_MD5(NTOWFv2, NtProofStr). */
    uint8_t session_base_key[16];
    winrm_hmac_md5(ntowfv2, 16, nt_proof, 16, session_base_key);

    /* KeyExchangeKey == SessionBaseKey for NTLMv2 + extended session. */
    /* ExportedSessionKey: random 16 bytes (since KEY_EXCH set). */
    uint8_t exported[16];
    if (winrm_random(exported, 16) != 0) {
        explicit_bzero(session_base_key, 16);
        goto fail_resp;
    }
    /* EncryptedRandomSessionKey = RC4(KeyExchangeKey)(ExportedSessionKey). */
    uint8_t enc_session_key[16];
    {
        winrm_rc4_t rc4;
        winrm_rc4_init(&rc4, session_base_key, 16);
        winrm_rc4_crypt(&rc4, exported, enc_session_key, 16);
        explicit_bzero(&rc4, sizeof(rc4));
    }

    /* Persist session keys + handles on n. */
    memcpy(n->exported_session_key, exported, 16);
    derive_subkey(exported, SIGN_C2S, n->client_signing_key);
    derive_subkey(exported, SIGN_S2C, n->server_signing_key);
    {
        uint8_t seal_c2s[16], seal_s2c[16];
        derive_subkey(exported, SEAL_C2S, seal_c2s);
        derive_subkey(exported, SEAL_S2C, seal_s2c);
        winrm_rc4_init(&n->client_seal_handle, seal_c2s, 16);
        winrm_rc4_init(&n->server_seal_handle, seal_s2c, 16);
        explicit_bzero(seal_c2s, 16);
        explicit_bzero(seal_s2c, 16);
    }
    n->client_seq = 0;
    n->server_seq = 0;
    n->authenticated = 1;

    /* Done with cleartext-derived material. */
    explicit_bzero(exported,         16);
    explicit_bzero(session_base_key, 16);
    explicit_bzero(ntowfv2,          16);

    /* ------------------------------------------------------
     * Assemble the AUTHENTICATE_MESSAGE.
     *
     * Layout (with VERSION and MIC):
     *   0..7   signature
     *   8..11  MessageType (0x03)
     *   12..19 LmChallengeResponseFields
     *   20..27 NtChallengeResponseFields
     *   28..35 DomainNameFields
     *   36..43 UserNameFields
     *   44..51 WorkstationFields
     *   52..59 EncryptedRandomSessionKeyFields
     *   60..63 NegotiateFlags
     *   64..71 Version
     *   72..87 MIC (16 bytes)  -- patched in after the rest of the
     *                             message and (Type1, Type2) bytes
     *                             are in place
     *   88..   payload
     * ------------------------------------------------------ */

    /* UTF-16LE versions of name fields. */
    size_t dom16_len = 0, user16_len = 0, ws16_len = 0;
    uint8_t *dom16  = winrm_utf8_to_utf16le(domain ? domain : "", &dom16_len);
    uint8_t *user16 = winrm_utf8_to_utf16le(user, &user16_len);
    uint8_t *ws16   = winrm_utf8_to_utf16le(
        n->workstation ? n->workstation : "WORKSTATION", &ws16_len);
    if (dom16 == NULL || user16 == NULL || ws16 == NULL) {
        free(dom16); free(user16); free(ws16);
        goto fail_resp;
    }

    const size_t HEADER = 88;
    size_t payload_off = HEADER;

    size_t off_dom   = payload_off;                payload_off += dom16_len;
    size_t off_user  = payload_off;                payload_off += user16_len;
    size_t off_ws    = payload_off;                payload_off += ws16_len;
    size_t off_lm    = payload_off;                payload_off += 24;
    size_t off_nt    = payload_off;                payload_off += nt_resp.len;
    size_t off_enck  = payload_off;                payload_off += 16;
    size_t total_len = payload_off;

    uint8_t *msg = calloc(total_len, 1);
    if (msg == NULL) {
        free(dom16); free(user16); free(ws16);
        goto fail_resp;
    }

    /* Header. */
    memcpy(msg, NTLMSSP_SIGNATURE, 8);
    msg[8] = 0x03;  /* MessageType */
    /* security buffers (len, maxlen, offset_le) - LE u16, u16, u32 */
#define WRITE_SECBUF(buf, off_in_msg, len, payload_offset)                  \
    do {                                                                    \
        (buf)[(off_in_msg)+0] = (uint8_t)((len)      );                     \
        (buf)[(off_in_msg)+1] = (uint8_t)((len) >> 8 );                     \
        (buf)[(off_in_msg)+2] = (uint8_t)((len)      );                     \
        (buf)[(off_in_msg)+3] = (uint8_t)((len) >> 8 );                     \
        (buf)[(off_in_msg)+4] = (uint8_t)((payload_offset)      );          \
        (buf)[(off_in_msg)+5] = (uint8_t)((payload_offset) >>  8);          \
        (buf)[(off_in_msg)+6] = (uint8_t)((payload_offset) >> 16);          \
        (buf)[(off_in_msg)+7] = (uint8_t)((payload_offset) >> 24);          \
    } while (0)

    WRITE_SECBUF(msg, 12, 24,           off_lm);    /* LM */
    WRITE_SECBUF(msg, 20, nt_resp.len,  off_nt);    /* NT */
    WRITE_SECBUF(msg, 28, dom16_len,    off_dom);
    WRITE_SECBUF(msg, 36, user16_len,   off_user);
    WRITE_SECBUF(msg, 44, ws16_len,     off_ws);
    WRITE_SECBUF(msg, 52, 16,           off_enck);
#undef WRITE_SECBUF

    /* NegotiateFlags. */
    uint32_t flags = NTLM_FLAGS_TYPE1;
    msg[60] = (uint8_t)(flags      );
    msg[61] = (uint8_t)(flags >>  8);
    msg[62] = (uint8_t)(flags >> 16);
    msg[63] = (uint8_t)(flags >> 24);
    /* Version. */
    memcpy(msg + 64, NTLM_VERSION_BLOB, 8);

    /* MIC field (offset 72..87) initially zero - patched at the end. */

    /* Payloads. */
    if (dom16_len  > 0) memcpy(msg + off_dom,   dom16,        dom16_len);
    if (user16_len > 0) memcpy(msg + off_user,  user16,       user16_len);
    if (ws16_len   > 0) memcpy(msg + off_ws,    ws16,         ws16_len);
    memcpy(msg + off_lm,    lm_resp,      24);
    memcpy(msg + off_nt,    nt_resp.buf,  nt_resp.len);
    memcpy(msg + off_enck,  enc_session_key, 16);

    free(dom16); free(user16); free(ws16);

    /* MIC = HMAC_MD5(ExportedSessionKey, Type1 || Type2 || Type3)
     * computed with Type3.MIC == 16 zero bytes. We need the saved
     * Type1 bytes; if they're missing (oom in Type1 build), skip the
     * MIC - some servers will still accept us, others won't, but we
     * have no better option. */
    if (n->type1_bytes != NULL && n->type1_bytes_len > 0) {
        size_t   concat_len = n->type1_bytes_len + type2_len + total_len;
        uint8_t *concat     = malloc(concat_len);
        if (concat != NULL) {
            memcpy(concat,
                   n->type1_bytes, n->type1_bytes_len);
            memcpy(concat + n->type1_bytes_len,
                   type2, type2_len);
            memcpy(concat + n->type1_bytes_len + type2_len,
                   msg, total_len);
            uint8_t mic[16];
            winrm_hmac_md5(n->exported_session_key, 16,
                           concat, concat_len, mic);
            free(concat);
            memcpy(msg + 72, mic, 16);
            explicit_bzero(mic, 16);
        }
    }

    free(target_info);
    free(temp.buf);
    free(nt_resp.buf);
    explicit_bzero(enc_session_key, 16);
    explicit_bzero(nt_proof,        16);
    explicit_bzero(lm_resp,         24);

    *out_type3     = msg;
    *out_type3_len = total_len;
    return 0;

fail_resp:
    free(nt_resp.buf);
    explicit_bzero(nt_proof, 16);
fail_blob:
    free(target_info);
    free(temp.buf);
    explicit_bzero(client_challenge, 8);
    explicit_bzero(ntowfv2, 16);
    return -1;
}

/* ------------------------------------------------------------------ */
/* Sealing / unsealing                                                */
/* ------------------------------------------------------------------ */

#define WSMAN_BOUNDARY     "Encrypted Boundary"
#define WSMAN_PROTOCOL     "application/HTTP-SPNEGO-session-encrypted"
#define WSMAN_OCTETSTREAM  "application/octet-stream"
#define WSMAN_SOAPCONTENT  "application/soap+xml"

/* Build the per-message NTLM signature. The 16-byte signature is
 *   uint32_le(0x00000001) || RC4(seal, HMAC_MD5(SignKey, seq||msg)[:8]) ||
 *   uint32_le(seq)
 * RC4 advances the seal handle by 8 bytes after this call. */
static void ntlm_sign(winrm_ntlm_t  *n,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t        sig[16])
{
    uint8_t buf[4 + 65536];  /* msg_len cap is for the stack version */
    uint8_t hmac[16];

    uint8_t seq_le[4] = {
        (uint8_t)(n->client_seq      ),
        (uint8_t)(n->client_seq >>  8),
        (uint8_t)(n->client_seq >> 16),
        (uint8_t)(n->client_seq >> 24),
    };

    if (msg_len + 4 <= sizeof(buf)) {
        memcpy(buf,     seq_le, 4);
        memcpy(buf + 4, msg,    msg_len);
        winrm_hmac_md5(n->client_signing_key, 16, buf, msg_len + 4, hmac);
    } else {
        /* Heap fallback for big bodies. */
        uint8_t *big = malloc(4 + msg_len);
        if (big == NULL) { memset(sig, 0, 16); return; }
        memcpy(big,     seq_le, 4);
        memcpy(big + 4, msg,    msg_len);
        winrm_hmac_md5(n->client_signing_key, 16, big, msg_len + 4, hmac);
        free(big);
    }

    /* Encrypt HMAC[:8] with the seal handle (continues stream). */
    uint8_t enc_hmac[8];
    winrm_rc4_crypt(&n->client_seal_handle, hmac, enc_hmac, 8);

    sig[0] = 0x01; sig[1] = 0x00; sig[2] = 0x00; sig[3] = 0x00;
    memcpy(sig + 4,  enc_hmac, 8);
    memcpy(sig + 12, seq_le,   4);
}

int winrm_ntlm_seal(winrm_ntlm_t  *n,
                    const char    *plaintext,
                    size_t         plaintext_len,
                    char         **out_body,
                    size_t        *out_len,
                    const char   **out_boundary)
{
    if (n == NULL || !n->authenticated || plaintext == NULL ||
        out_body == NULL || out_len == NULL) {
        return -1;
    }
    if (out_boundary) *out_boundary = WSMAN_BOUNDARY;

    /* 1. Encrypt body with the seal handle (continues stream). */
    uint8_t *sealed = malloc(plaintext_len);
    if (sealed == NULL) return -1;
    winrm_rc4_crypt(&n->client_seal_handle,
                    (const uint8_t *)plaintext, sealed, plaintext_len);

    /* 2. Compute signature; this also advances the seal handle by 8. */
    uint8_t sig[16];
    ntlm_sign(n, (const uint8_t *)plaintext, plaintext_len, sig);
    n->client_seq++;

    /* 3. Build encrypted_message = u32_le(16) || sig(16) || sealed.
     * 4. Build the multipart body. The format is fragile and follows
     *    the exact layout pywinrm/ntlm-auth produce. */
    char *header = NULL;
    int hdr_n = asprintf(&header,
        "--%s\r\n"
        "\tContent-Type: %s\r\n"
        "\tOriginalContent: type=%s;charset=UTF-8;Length=%zu\r\n"
        "--%s\r\n"
        "\tContent-Type: %s\r\n",
        WSMAN_BOUNDARY,
        WSMAN_PROTOCOL,
        WSMAN_SOAPCONTENT,
        plaintext_len,
        WSMAN_BOUNDARY,
        WSMAN_OCTETSTREAM);
    if (hdr_n < 0) { free(sealed); return -1; }

    char *trailer = NULL;
    int tlr_n = asprintf(&trailer, "--%s--\r\n", WSMAN_BOUNDARY);
    if (tlr_n < 0) { free(header); free(sealed); return -1; }

    size_t body_len =
        (size_t)hdr_n + 4 /*sig_len*/ + 16 /*sig*/ + plaintext_len + (size_t)tlr_n;
    char *body = malloc(body_len);
    if (body == NULL) {
        free(header); free(trailer); free(sealed);
        return -1;
    }
    size_t off = 0;
    memcpy(body + off, header, hdr_n); off += (size_t)hdr_n;
    /* signature length = 16, little-endian uint32 */
    body[off++] = 0x10;
    body[off++] = 0x00;
    body[off++] = 0x00;
    body[off++] = 0x00;
    memcpy(body + off, sig,    16);             off += 16;
    memcpy(body + off, sealed, plaintext_len);  off += plaintext_len;
    memcpy(body + off, trailer, tlr_n);         off += (size_t)tlr_n;

    free(header);
    free(trailer);
    free(sealed);

    *out_body = body;
    *out_len  = body_len;
    return 0;
}

/* Verify and decrypt a server signature/body pair. Mirror of
 * ntlm_sign. Returns 0 on success. */
static int unseal_and_verify(winrm_ntlm_t  *n,
                             const uint8_t *sig, size_t sig_len,
                             const uint8_t *sealed, size_t sealed_len,
                             uint8_t       **out, size_t *out_len)
{
    if (sig_len != 16) return -1;
    if (rd_u32_le(sig) != 0x00000001) return -1;

    uint8_t *plain = malloc(sealed_len + 1);
    if (plain == NULL) return -1;
    /* Decrypt body first (RC4 stream order is body, then mac). */
    winrm_rc4_crypt(&n->server_seal_handle, sealed, plain, sealed_len);
    plain[sealed_len] = '\0';

    /* Then "decrypt" the encrypted HMAC[:8]. */
    uint8_t enc_hmac[8];
    memcpy(enc_hmac, sig + 4, 8);
    uint8_t hmac_out[8];
    winrm_rc4_crypt(&n->server_seal_handle, enc_hmac, hmac_out, 8);

    /* Expected HMAC = HMAC_MD5(server_sign_key, seq || plaintext)[:8].
     * The server uses its own per-direction sequence number, which we
     * pull from the signature itself. */
    uint32_t their_seq = rd_u32_le(sig + 12);
    uint8_t seq_le[4] = {
        (uint8_t)(their_seq      ),
        (uint8_t)(their_seq >>  8),
        (uint8_t)(their_seq >> 16),
        (uint8_t)(their_seq >> 24),
    };
    uint8_t *hin = malloc(4 + sealed_len);
    if (hin == NULL) { free(plain); return -1; }
    memcpy(hin,     seq_le, 4);
    memcpy(hin + 4, plain,  sealed_len);
    uint8_t expected[16];
    winrm_hmac_md5(n->server_signing_key, 16, hin, 4 + sealed_len, expected);
    free(hin);

    if (memcmp(hmac_out, expected, 8) != 0) {
        /* Signature mismatch - do NOT release the plaintext. */
        explicit_bzero(plain, sealed_len);
        free(plain);
        return -1;
    }

    n->server_seq = their_seq + 1;
    *out     = plain;
    *out_len = sealed_len;
    return 0;
}

/* Locate the encrypted_message bytes inside a multipart/encrypted
 * response. We anchor on the known header strings instead of doing
 * a full MIME parse - WinRM's wire format is rigid and the cost of
 * a parser library would dwarf the implementation. */
int winrm_ntlm_unseal(winrm_ntlm_t *n,
                      const char   *enc_body,
                      size_t        enc_len,
                      char        **out,
                      size_t       *out_len)
{
    if (n == NULL || !n->authenticated || enc_body == NULL ||
        out == NULL || out_len == NULL) {
        return -1;
    }
    *out = NULL;
    *out_len = 0;

    static const char OS_MARK[] = "Content-Type: " WSMAN_OCTETSTREAM "\r\n";
    const char *os = memmem(enc_body, enc_len, OS_MARK, sizeof(OS_MARK) - 1);
    if (os == NULL) return -1;
    const uint8_t *cursor = (const uint8_t *)os + (sizeof(OS_MARK) - 1);
    size_t remaining = enc_len - (size_t)(cursor - (const uint8_t *)enc_body);

    /* Tail close marker: "--<boundary>--". */
    static const char END_MARK[] = "--" WSMAN_BOUNDARY "--";
    /* rfind from the end of the body. */
    if (remaining < sizeof(END_MARK) - 1 + 4 + 16) return -1;
    const uint8_t *end = NULL;
    for (ssize_t i = (ssize_t)remaining - (ssize_t)(sizeof(END_MARK) - 1);
         i >= 0; i--) {
        if (memcmp(cursor + i, END_MARK, sizeof(END_MARK) - 1) == 0) {
            end = cursor + i;
            break;
        }
    }
    if (end == NULL) return -1;
    size_t enc_msg_len = (size_t)(end - cursor);
    if (enc_msg_len < 4 + 16) return -1;

    uint32_t sig_len = rd_u32_le(cursor);
    if (sig_len != 16) return -1;
    const uint8_t *sig    = cursor + 4;
    const uint8_t *sealed = cursor + 4 + 16;
    size_t  sealed_len    = enc_msg_len - 4 - 16;

    uint8_t *plain    = NULL;
    size_t   plain_len = 0;
    if (unseal_and_verify(n, sig, 16, sealed, sealed_len,
                          &plain, &plain_len) != 0) {
        return -1;
    }
    *out     = (char *)plain;
    *out_len = plain_len;
    return 0;
}
