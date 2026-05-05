#ifndef RT_PROTOCOLS_WINRM_NTLM_H
#define RT_PROTOCOLS_WINRM_NTLM_H

#include <stddef.h>
#include <stdint.h>

#include "protocols/winrm/winrm_crypto.h"

/*
 * NTLMv2 + SPNEGO message-sealing for WinRM.
 *
 * What's implemented:
 *   - NTLMSSP NEGOTIATE / CHALLENGE / AUTHENTICATE messages
 *     (Type 1 / 2 / 3) per [MS-NLMP]
 *   - NTLMv2 response (NTOWFv2 + ntProofStr) per [MS-NLMP] 3.3.2
 *   - Extended session security key derivation (Sign/Seal keys
 *     per [MS-NLMP] 3.4.5)
 *   - Per-message SEAL with 16-byte signature ([MS-NLMP] 3.4.4.2)
 *
 * What's NOT implemented:
 *   - NTLMv1, LM responses
 *   - SPNEGO wrapping (we send raw NTLMSSP under "Negotiate" auth
 *     header anyway - Windows accepts both)
 *
 * Threading: instances are NOT thread-safe. The WinRM worker thread
 * is the sole owner.
 */

typedef struct {
    /* Session state derived after Type3. */
    uint8_t      exported_session_key[16];
    uint8_t      client_signing_key  [16];
    uint8_t      server_signing_key  [16];
    winrm_rc4_t  client_seal_handle;
    winrm_rc4_t  server_seal_handle;
    uint32_t     client_seq;
    uint32_t     server_seq;
    int          authenticated;

    /* Workstation name reported in Type1/Type3. Best-effort: gethostname
     * at construction time. Heap-owned. */
    char        *workstation;

    /* The exact bytes of the NEGOTIATE message we sent. Required so
     * we can compute the MIC over (Type1 || Type2 || Type3) when
     * building Type3. Heap-owned. */
    uint8_t     *type1_bytes;
    size_t       type1_bytes_len;
} winrm_ntlm_t;

void winrm_ntlm_init (winrm_ntlm_t *n);
void winrm_ntlm_reset(winrm_ntlm_t *n);

/* Build the Type 1 NEGOTIATE message. Returns 0 on success and
 * heap-owned bytes via *out / *out_len (caller frees). */
int winrm_ntlm_build_type1(winrm_ntlm_t  *n,
                           uint8_t      **out,
                           size_t        *out_len);

/* Process a Type 2 CHALLENGE message and produce a Type 3
 * AUTHENTICATE message. On success, derives session keys and marks
 * the context authenticated; the caller is then responsible for
 * sending Type 3 over the wire and from then on uses winrm_ntlm_seal
 * and winrm_ntlm_unseal for every body. */
int winrm_ntlm_build_type3(winrm_ntlm_t  *n,
                           const uint8_t *type2,
                           size_t         type2_len,
                           const char    *user,
                           const char    *domain,
                           const char    *password,
                           uint8_t      **out_type3,
                           size_t        *out_type3_len);

/* Seal a plaintext SOAP envelope into a WinRM-style multipart/
 * encrypted body. Returns the body bytes via *out_body / *out_len
 * (caller frees) and the matching boundary string in *out_boundary
 * (static literal, do not free). */
int winrm_ntlm_seal(winrm_ntlm_t  *n,
                    const char    *plaintext,
                    size_t         plaintext_len,
                    char         **out_body,
                    size_t        *out_len,
                    const char   **out_boundary);

/* Unseal a multipart/encrypted response. Returns the recovered
 * plaintext via *out / *out_len (caller frees, NUL-terminated). */
int winrm_ntlm_unseal(winrm_ntlm_t *n,
                      const char   *enc_body,
                      size_t        enc_len,
                      char        **out,
                      size_t       *out_len);

#endif /* RT_PROTOCOLS_WINRM_NTLM_H */
