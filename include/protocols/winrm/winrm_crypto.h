#ifndef RT_PROTOCOLS_WINRM_CRYPTO_H
#define RT_PROTOCOLS_WINRM_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/*
 * Self-contained crypto primitives needed by the NTLMv2 + SPNEGO
 * message-sealing path. Kept in-tree (rather than calling OpenSSL)
 * so we don't depend on the OpenSSL 3.x legacy provider for MD4 and
 * RC4. Implementations are textbook RFC reference code.
 *
 * Nothing in here is a general-purpose crypto API - the surface is
 * shaped to what NTLM needs.
 */

/* MD4 hash, 16-byte output. RFC 1320. */
void winrm_md4(const void *data, size_t len, uint8_t out[16]);

/* MD5 hash, 16-byte output. RFC 1321. */
void winrm_md5(const void *data, size_t len, uint8_t out[16]);

/* HMAC-MD5, 16-byte output. RFC 2104. */
void winrm_hmac_md5(const uint8_t *key, size_t key_len,
                    const void    *data, size_t data_len,
                    uint8_t        out[16]);

/* RC4 stream cipher state. Reset between independent streams; for
 * NTLM sealing the SAME handle is reused across messages so the
 * keystream advances with each sealed byte. */
typedef struct {
    uint8_t s[256];
    uint8_t i;
    uint8_t j;
} winrm_rc4_t;

void winrm_rc4_init (winrm_rc4_t *r, const uint8_t *key, size_t key_len);
void winrm_rc4_crypt(winrm_rc4_t *r, const uint8_t *in, uint8_t *out, size_t len);

/* Base64 encode/decode. encode returns NUL-terminated heap string;
 * decode returns heap bytes + length (caller frees). On NULL input
 * decode returns NULL. */
char    *winrm_b64_encode(const uint8_t *data, size_t len);
uint8_t *winrm_b64_decode(const char    *b64,  size_t *out_len);

/* Cryptographic random bytes from /dev/urandom. Returns 0 on success. */
int winrm_random(uint8_t *out, size_t len);

/* UTF-8 -> UTF-16LE. Returns heap bytes (no BOM, no terminator),
 * with byte length in *out_byte_len. NULL input -> NULL out, len 0. */
uint8_t *winrm_utf8_to_utf16le(const char *utf8, size_t *out_byte_len);

#endif /* RT_PROTOCOLS_WINRM_CRYPTO_H */
