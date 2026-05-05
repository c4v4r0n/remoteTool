/*
 * Crypto primitives for NTLM. All textbook RFC reference code:
 *   - MD4: RFC 1320
 *   - MD5: RFC 1321
 *   - HMAC-MD5: RFC 2104
 *   - RC4: original reference (formerly RSA Data Security trade secret)
 *
 * No effort is spent on side-channel hardening; NTLMv2 doesn't
 * survive an attacker with timing access anyway, and these are
 * desktop-tool keys with millisecond lifetimes.
 */

#include "protocols/winrm/winrm_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ================================================================== */
/* MD4 (RFC 1320)                                                     */
/* ================================================================== */

static uint32_t md4_F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t md4_G(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (x & z) | (y & z); }
static uint32_t md4_H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }

static uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

void winrm_md4(const void *data_, size_t len, uint8_t out[16])
{
    const uint8_t *data = (const uint8_t *)data_;

    uint32_t a = 0x67452301u, b = 0xefcdab89u,
             c = 0x98badcfeu, d = 0x10325476u;

    uint64_t bit_len = (uint64_t)len * 8u;
    /* padded length: original len + 0x80 + zero pad + 8 length bytes,
     * round up to multiple of 64. */
    size_t   padded  = ((len + 8) / 64 + 1) * 64;
    uint8_t *buf     = calloc(padded, 1);
    if (buf == NULL) { memset(out, 0, 16); return; }

    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) {
        buf[padded - 8 + i] = (uint8_t)(bit_len >> (i * 8));
    }

    for (size_t off = 0; off < padded; off += 64) {
        uint32_t X[16];
        for (int i = 0; i < 16; i++) {
            X[i] = (uint32_t)buf[off + i*4]            |
                   ((uint32_t)buf[off + i*4 + 1] <<  8) |
                   ((uint32_t)buf[off + i*4 + 2] << 16) |
                   ((uint32_t)buf[off + i*4 + 3] << 24);
        }
        uint32_t aa = a, bb = b, cc = c, dd = d;

#define R1(a, b, c, d, k, s) (a) = rotl32((a) + md4_F((b),(c),(d)) + X[k], s)
        R1(a,b,c,d, 0, 3);  R1(d,a,b,c, 1, 7);
        R1(c,d,a,b, 2,11);  R1(b,c,d,a, 3,19);
        R1(a,b,c,d, 4, 3);  R1(d,a,b,c, 5, 7);
        R1(c,d,a,b, 6,11);  R1(b,c,d,a, 7,19);
        R1(a,b,c,d, 8, 3);  R1(d,a,b,c, 9, 7);
        R1(c,d,a,b,10,11);  R1(b,c,d,a,11,19);
        R1(a,b,c,d,12, 3);  R1(d,a,b,c,13, 7);
        R1(c,d,a,b,14,11);  R1(b,c,d,a,15,19);
#undef R1

#define R2(a, b, c, d, k, s) (a) = rotl32((a) + md4_G((b),(c),(d)) + X[k] + 0x5a827999u, s)
        R2(a,b,c,d, 0, 3);  R2(d,a,b,c, 4, 5);
        R2(c,d,a,b, 8, 9);  R2(b,c,d,a,12,13);
        R2(a,b,c,d, 1, 3);  R2(d,a,b,c, 5, 5);
        R2(c,d,a,b, 9, 9);  R2(b,c,d,a,13,13);
        R2(a,b,c,d, 2, 3);  R2(d,a,b,c, 6, 5);
        R2(c,d,a,b,10, 9);  R2(b,c,d,a,14,13);
        R2(a,b,c,d, 3, 3);  R2(d,a,b,c, 7, 5);
        R2(c,d,a,b,11, 9);  R2(b,c,d,a,15,13);
#undef R2

#define R3(a, b, c, d, k, s) (a) = rotl32((a) + md4_H((b),(c),(d)) + X[k] + 0x6ed9eba1u, s)
        R3(a,b,c,d, 0, 3);  R3(d,a,b,c, 8, 9);
        R3(c,d,a,b, 4,11);  R3(b,c,d,a,12,15);
        R3(a,b,c,d, 2, 3);  R3(d,a,b,c,10, 9);
        R3(c,d,a,b, 6,11);  R3(b,c,d,a,14,15);
        R3(a,b,c,d, 1, 3);  R3(d,a,b,c, 9, 9);
        R3(c,d,a,b, 5,11);  R3(b,c,d,a,13,15);
        R3(a,b,c,d, 3, 3);  R3(d,a,b,c,11, 9);
        R3(c,d,a,b, 7,11);  R3(b,c,d,a,15,15);
#undef R3

        a += aa; b += bb; c += cc; d += dd;
    }

    free(buf);

    uint32_t h[4] = { a, b, c, d };
    for (int i = 0; i < 4; i++) {
        out[i*4    ] = (uint8_t)(h[i]      );
        out[i*4 + 1] = (uint8_t)(h[i] >>  8);
        out[i*4 + 2] = (uint8_t)(h[i] >> 16);
        out[i*4 + 3] = (uint8_t)(h[i] >> 24);
    }
}

/* ================================================================== */
/* MD5 (RFC 1321)                                                     */
/* ================================================================== */

static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,
    0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,
    0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,
    0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,
    0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,
    0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,
    0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,
    0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,
    0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};

static const uint32_t MD5_R[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
};

void winrm_md5(const void *data_, size_t len, uint8_t out[16])
{
    const uint8_t *data = (const uint8_t *)data_;

    uint32_t h0 = 0x67452301u, h1 = 0xefcdab89u,
             h2 = 0x98badcfeu, h3 = 0x10325476u;

    uint64_t bit_len = (uint64_t)len * 8u;
    size_t   padded  = ((len + 8) / 64 + 1) * 64;
    uint8_t *buf     = calloc(padded, 1);
    if (buf == NULL) { memset(out, 0, 16); return; }

    memcpy(buf, data, len);
    buf[len] = 0x80;
    for (int i = 0; i < 8; i++) {
        buf[padded - 8 + i] = (uint8_t)(bit_len >> (i * 8));
    }

    for (size_t off = 0; off < padded; off += 64) {
        uint32_t M[16];
        for (int i = 0; i < 16; i++) {
            M[i] = (uint32_t)buf[off + i*4]            |
                   ((uint32_t)buf[off + i*4 + 1] <<  8) |
                   ((uint32_t)buf[off + i*4 + 2] << 16) |
                   ((uint32_t)buf[off + i*4 + 3] << 24);
        }
        uint32_t a = h0, b = h1, c = h2, d = h3;

        for (int i = 0; i < 64; i++) {
            uint32_t f, g;
            if (i < 16)      { f = (b & c) | (~b & d);              g = (uint32_t)i; }
            else if (i < 32) { f = (d & b) | (~d & c);              g = (uint32_t)(5*i + 1) % 16; }
            else if (i < 48) { f = b ^ c ^ d;                       g = (uint32_t)(3*i + 5) % 16; }
            else             { f = c ^ (b | ~d);                    g = (uint32_t)(7*i)     % 16; }

            uint32_t temp = d;
            d = c;
            c = b;
            b = b + rotl32(a + f + MD5_K[i] + M[g], MD5_R[i]);
            a = temp;
        }
        h0 += a; h1 += b; h2 += c; h3 += d;
    }

    free(buf);

    uint32_t h[4] = { h0, h1, h2, h3 };
    for (int i = 0; i < 4; i++) {
        out[i*4    ] = (uint8_t)(h[i]      );
        out[i*4 + 1] = (uint8_t)(h[i] >>  8);
        out[i*4 + 2] = (uint8_t)(h[i] >> 16);
        out[i*4 + 3] = (uint8_t)(h[i] >> 24);
    }
}

/* ================================================================== */
/* HMAC-MD5 (RFC 2104)                                                */
/* ================================================================== */

void winrm_hmac_md5(const uint8_t *key, size_t key_len,
                    const void    *data, size_t data_len,
                    uint8_t        out[16])
{
    uint8_t k_pad[64];
    uint8_t khash[16];

    if (key_len > 64) {
        winrm_md5(key, key_len, khash);
        key     = khash;
        key_len = 16;
    }

    /* inner */
    memset(k_pad, 0x36, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];
    uint8_t *inner = malloc(64 + data_len);
    if (inner == NULL) { memset(out, 0, 16); return; }
    memcpy(inner, k_pad, 64);
    if (data_len > 0) memcpy(inner + 64, data, data_len);
    uint8_t inner_h[16];
    winrm_md5(inner, 64 + data_len, inner_h);
    free(inner);

    /* outer */
    memset(k_pad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) k_pad[i] ^= key[i];
    uint8_t outer[64 + 16];
    memcpy(outer,      k_pad,   64);
    memcpy(outer + 64, inner_h, 16);
    winrm_md5(outer, 80, out);
}

/* ================================================================== */
/* RC4                                                                */
/* ================================================================== */

void winrm_rc4_init(winrm_rc4_t *r, const uint8_t *key, size_t key_len)
{
    for (int i = 0; i < 256; i++) r->s[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        j = (uint8_t)(j + r->s[i] + key[i % key_len]);
        uint8_t t = r->s[i];
        r->s[i] = r->s[j];
        r->s[j] = t;
    }
    r->i = 0;
    r->j = 0;
}

void winrm_rc4_crypt(winrm_rc4_t *r, const uint8_t *in, uint8_t *out, size_t len)
{
    for (size_t k = 0; k < len; k++) {
        r->i = (uint8_t)(r->i + 1);
        r->j = (uint8_t)(r->j + r->s[r->i]);
        uint8_t t = r->s[r->i];
        r->s[r->i] = r->s[r->j];
        r->s[r->j] = t;
        uint8_t ks = r->s[(uint8_t)(r->s[r->i] + r->s[r->j])];
        out[k] = in[k] ^ ks;
    }
}

/* ================================================================== */
/* Base64                                                             */
/* ================================================================== */

static const char B64_TABLE[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *winrm_b64_encode(const uint8_t *data, size_t len)
{
    if (data == NULL && len > 0) return NULL;

    size_t out_len = ((len + 2) / 3) * 4;
    char  *out     = malloc(out_len + 1);
    if (out == NULL) return NULL;

    size_t i, o;
    for (i = 0, o = 0; i + 3 <= len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16) |
                     ((uint32_t)data[i+1] << 8) |
                     ((uint32_t)data[i+2]);
        out[o++] = B64_TABLE[(v >> 18) & 0x3f];
        out[o++] = B64_TABLE[(v >> 12) & 0x3f];
        out[o++] = B64_TABLE[(v >>  6) & 0x3f];
        out[o++] = B64_TABLE[ v        & 0x3f];
    }
    if (i < len) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < len) v |= (uint32_t)data[i+1] << 8;
        out[o++] = B64_TABLE[(v >> 18) & 0x3f];
        out[o++] = B64_TABLE[(v >> 12) & 0x3f];
        out[o++] = (i + 1 < len) ? B64_TABLE[(v >> 6) & 0x3f] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return out;
}

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

uint8_t *winrm_b64_decode(const char *b64, size_t *out_len)
{
    if (b64 == NULL) {
        if (out_len) *out_len = 0;
        return NULL;
    }
    size_t in_len = strlen(b64);
    uint8_t *out = malloc(in_len + 1);
    if (out == NULL) {
        if (out_len) *out_len = 0;
        return NULL;
    }

    int     quad[4];
    int     q = 0;
    size_t  o = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)b64[i];
        if (c == '=' || c == ' ' || c == '\r' || c == '\n' || c == '\t') {
            if (c == '=') break;
            continue;
        }
        int v = b64_val(c);
        if (v < 0) continue;
        quad[q++] = v;
        if (q == 4) {
            out[o++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
            out[o++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
            out[o++] = (uint8_t)((quad[2] << 6) |  quad[3]);
            q = 0;
        }
    }
    if (q == 2) {
        out[o++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
    } else if (q == 3) {
        out[o++] = (uint8_t)((quad[0] << 2) | (quad[1] >> 4));
        out[o++] = (uint8_t)((quad[1] << 4) | (quad[2] >> 2));
    }
    if (out_len) *out_len = o;
    return out;
}

/* ================================================================== */
/* Random                                                             */
/* ================================================================== */

int winrm_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, out + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        got += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ================================================================== */
/* UTF-8 -> UTF-16LE                                                  */
/* ================================================================== */

uint8_t *winrm_utf8_to_utf16le(const char *utf8, size_t *out_byte_len)
{
    if (out_byte_len) *out_byte_len = 0;
    if (utf8 == NULL) return NULL;

    /* Worst-case: each input byte produces a single UTF-16 code unit
     * (2 bytes). Surrogate pairs make some 4-byte UTF-8 expand to
     * 4 bytes UTF-16, still <= 2x input. */
    size_t in_len = strlen(utf8);
    size_t cap    = (in_len + 1) * 2;
    uint8_t *out  = malloc(cap);
    if (out == NULL) return NULL;

    size_t o = 0;
    size_t i = 0;
    while (i < in_len) {
        uint32_t cp;
        unsigned char c = (unsigned char)utf8[i];
        if (c < 0x80) {
            cp = c;
            i += 1;
        } else if ((c & 0xe0) == 0xc0 && i + 1 < in_len) {
            cp = ((uint32_t)(c & 0x1f) << 6) |
                 (uint32_t)((unsigned char)utf8[i+1] & 0x3f);
            i += 2;
        } else if ((c & 0xf0) == 0xe0 && i + 2 < in_len) {
            cp = ((uint32_t)(c & 0x0f) << 12) |
                 ((uint32_t)((unsigned char)utf8[i+1] & 0x3f) << 6) |
                 (uint32_t)((unsigned char)utf8[i+2] & 0x3f);
            i += 3;
        } else if ((c & 0xf8) == 0xf0 && i + 3 < in_len) {
            cp = ((uint32_t)(c & 0x07) << 18) |
                 ((uint32_t)((unsigned char)utf8[i+1] & 0x3f) << 12) |
                 ((uint32_t)((unsigned char)utf8[i+2] & 0x3f) <<  6) |
                 (uint32_t)((unsigned char)utf8[i+3] & 0x3f);
            i += 4;
        } else {
            /* Invalid byte; substitute U+FFFD and skip one. */
            cp = 0xFFFD;
            i += 1;
        }

        if (cp <= 0xFFFF) {
            out[o++] = (uint8_t)(cp      );
            out[o++] = (uint8_t)(cp >> 8 );
        } else {
            cp -= 0x10000;
            uint16_t high = 0xD800u | (uint16_t)((cp >> 10) & 0x3FF);
            uint16_t low  = 0xDC00u | (uint16_t)( cp        & 0x3FF);
            out[o++] = (uint8_t)(high      );
            out[o++] = (uint8_t)(high >> 8 );
            out[o++] = (uint8_t)(low       );
            out[o++] = (uint8_t)(low  >> 8 );
        }
    }

    if (out_byte_len) *out_byte_len = o;
    return out;
}
