#ifndef RT_PROTOCOLS_WINRM_PSRP_H
#define RT_PROTOCOLS_WINRM_PSRP_H

#include <stddef.h>
#include <stdint.h>

/*
 * PowerShell Remoting Protocol [MS-PSRP] over WinRM/WSMan.
 *
 * Why this exists
 * ---------------
 * Default Windows ACLs:
 *   - cmd-shell endpoint  (Microsoft.WindowsRemoteShell)  -> Administrators only
 *   - PowerShell endpoint (Microsoft.PowerShell)          -> Administrators
 *                                                            + Remote Mgmt Users
 * evil-winrm and pypsrp both target the PowerShell endpoint, which is
 * why they "just work" for non-admin users while a cmd-shell client
 * bounces off with wsa:AccessDenied. To match that behavior we have
 * to speak PSRP, which wraps PowerShell pipelines in fragmented
 * binary messages carrying CLIXML payloads.
 *
 * What's implemented (MVP)
 * ------------------------
 *  - PSRP fragment encode/decode ([MS-PSRP] 2.2.4)
 *  - PSRP message header build/parse ([MS-PSRP] 2.2.1)
 *  - Hard-coded CLIXML for SESSION_CAPABILITY, INIT_RUNSPACEPOOL,
 *    and CREATE_PIPELINE messages
 *  - PIPELINE_OUTPUT CLIXML scrape: pull <S>...</S> primitive strings
 *    out of object envelopes and concatenate them as text. Good
 *    enough for typical PowerShell formatted output (Get-Process,
 *    Get-Service, Get-ChildItem, etc., all auto-format to strings
 *    server-side before serialization)
 *
 * What's NOT implemented
 * ----------------------
 *  - Host I/O (PIPELINE_HOST_CALL/RESPONSE) - any cmdlet that calls
 *    Read-Host or Write-Host with formatting will look plain
 *  - Full CLIXML object reconstruction (we treat everything as text)
 *  - Multi-runspace pools (we always use Min=Max=1)
 *  - ApplicationArguments
 *
 * Threading: instances are owned by the WinRM worker thread.
 */

/* PSRP message types we care about. Values are from [MS-PSRP] 2.2.2 -
 * earlier drafts of this header had RUNSPACEPOOL_STATE and
 * PIPELINE_OUTPUT shifted by one identifier slot, which silently
 * dropped server messages we needed to dispatch. */
#define PSRP_MSG_SESSION_CAPABILITY       0x00010002u
#define PSRP_MSG_INIT_RUNSPACEPOOL        0x00010004u
#define PSRP_MSG_RUNSPACEPOOL_STATE       0x00021005u
#define PSRP_MSG_CREATE_PIPELINE          0x00021006u
#define PSRP_MSG_APPLICATION_PRIVATE_DATA 0x00021009u
#define PSRP_MSG_PIPELINE_OUTPUT          0x00041004u
#define PSRP_MSG_ERROR_RECORD             0x00041005u
#define PSRP_MSG_PIPELINE_STATE           0x00041006u
#define PSRP_MSG_PIPELINE_HOST_CALL       0x00041100u

/* Destination markers in the PSRP header. */
#define PSRP_DEST_CLIENT  0x00000001u
#define PSRP_DEST_SERVER  0x00000002u

typedef struct {
    uint8_t  rpid[16];        /* Runspace Pool ID, generated on init */
    uint64_t object_counter;  /* PSRP fragment ObjectId, monotonic */

    /* Decoder state for reassembling fragments coming in over the
     * stdout stream. Holds at most one in-flight message at a time;
     * MS-PSRP guarantees fragments are not interleaved. */
    uint64_t decoder_object_id;
    int      decoder_in_progress;
    uint8_t *decoder_buf;
    size_t   decoder_len;
    size_t   decoder_cap;
} winrm_psrp_t;

void winrm_psrp_init (winrm_psrp_t *p);
void winrm_psrp_reset(winrm_psrp_t *p);

/* Build the SESSION_CAPABILITY PSRP message (header + CLIXML) and
 * fragment it. Returns heap bytes the caller frees. PID is all zeros. */
int winrm_psrp_build_session_capability(winrm_psrp_t  *p,
                                        uint8_t      **out, size_t *out_len);

/* Build INIT_RUNSPACEPOOL message + fragments. PID is all zeros. */
int winrm_psrp_build_init_runspacepool(winrm_psrp_t  *p,
                                       uint8_t      **out, size_t *out_len);

/* Build CREATE_PIPELINE message + fragments for `command`. The
 * pipeline ID (PID) is generated and copied to `out_pid` (16 bytes).
 * Caller passes the same UUID to the WinRM Command operation so the
 * server uses it as the WinRM CommandId for Send/Receive. */
int winrm_psrp_build_create_pipeline(winrm_psrp_t  *p,
                                     const char    *command,
                                     uint8_t        out_pid[16],
                                     uint8_t      **out_frags,
                                     size_t        *out_frags_len);

/* Feed bytes from one <rsp:Stream> base64-decoded payload into the
 * decoder. May produce zero, one, or several complete messages.
 * Each completion fires the callback with the message bytes
 * (header+data, header is 21 bytes), the message type, and the
 * caller's `user`. Returns 0 on success, -1 on a framing error. */
typedef void (*winrm_psrp_msg_cb_t)(uint32_t       msg_type,
                                    const uint8_t *msg, size_t msg_len,
                                    void          *user);

int winrm_psrp_decoder_feed(winrm_psrp_t       *p,
                            const uint8_t      *bytes, size_t len,
                            winrm_psrp_msg_cb_t cb, void *user);

/* PIPELINE_OUTPUT, ERROR_RECORD etc. carry CLIXML in the data area
 * that follows the 21-byte PSRP header. This helper pulls every
 * <S>...</S> primitive string out of `clixml` and concatenates them
 * with newlines, which closely mirrors what an interactive PowerShell
 * console would print. Returns heap text (caller frees) or NULL. */
char *winrm_psrp_clixml_to_text(const char *clixml, size_t clixml_len);

/* Convenience: format a 16-byte UUID as
 * "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" (NUL-terminated, 37 bytes).
 * Used by the protocol layer to set the WinRM CommandId option. */
void winrm_psrp_uuid_format(const uint8_t uuid[16], char out[37]);

/* PIPELINE_STATE state values (decoded from the message data). */
#define PSRP_PIPELINE_STATE_RUNNING   2
#define PSRP_PIPELINE_STATE_STOPPED   3
#define PSRP_PIPELINE_STATE_COMPLETED 4
#define PSRP_PIPELINE_STATE_FAILED    6
int winrm_psrp_parse_pipeline_state(const uint8_t *msg, size_t msg_len);

/* RUNSPACEPOOL_STATE state values. */
#define PSRP_RUNSPACE_STATE_OPENED    2
#define PSRP_RUNSPACE_STATE_CLOSED    3
#define PSRP_RUNSPACE_STATE_BROKEN    5
int winrm_psrp_parse_runspace_state(const uint8_t *msg, size_t msg_len);

#endif /* RT_PROTOCOLS_WINRM_PSRP_H */
