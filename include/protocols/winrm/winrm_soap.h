#ifndef RT_PROTOCOLS_WINRM_SOAP_H
#define RT_PROTOCOLS_WINRM_SOAP_H

#include <stddef.h>

/*
 * SOAP / WS-Management envelope helpers for the WinRM back-end.
 *
 * Generation: hand-crafted strings. Each builder returns a heap-
 * allocated UTF-8 envelope; the caller owns it. Inputs that go into
 * element bodies (commands, shell ids) are XML-escaped here.
 *
 * Parsing: thin libxml2 lookups against well-known elements. Stream
 * payloads come back base64-encoded; rt_winrm_soap_parse_receive
 * decodes them and concatenates stdout/stderr in arrival order.
 *
 * No header outside the WinRM module includes this; nothing outside
 * the WinRM module pulls in libxml2 or sees the SOAP wire format.
 */

/* WS-Management resource URIs we target. */
#define RT_WSMAN_RESOURCE_CMD \
    "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
#define RT_WSMAN_RESOURCE_POWERSHELL \
    "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"

/* Build the envelopes we need. All return malloc'd UTF-8 strings.
 * `host_url` is the full endpoint URL ("http://host:5985/wsman" etc).
 * Returns NULL on allocation failure. */

/* Cmd-shell flavour: classic Microsoft.WindowsRemoteShell. */
char *rt_winrm_soap_build_create(const char *host_url);

/* PowerShell-shell flavour: includes <creationXml> with base64-encoded
 * PSRP SESSION_CAPABILITY + INIT_RUNSPACEPOOL fragments. The shell
 * declares "stdin pr" input streams and "stdout" output stream as
 * PSRP requires. `shell_id_uuid` is the client-generated UUID we
 * want the server to use as the WinRM ShellId (= PSRP RPID). */
char *rt_winrm_soap_build_create_powershell(const char *host_url,
                                            const char *shell_id_uuid,
                                            const char *creation_xml_b64);

/* Cmd-shell command (single text command line). */
char *rt_winrm_soap_build_command(const char *host_url,
                                  const char *shell_id,
                                  const char *command);

/* PowerShell-style command: the body of <rsp:Command> is the base64-
 * encoded first PSRP fragment of the CREATE_PIPELINE message. Any
 * subsequent fragments go into <rsp:Arguments> elements (we keep
 * messages within a single fragment for now, so `more_fragments` is
 * usually NULL). The CommandId option is set to `pipeline_id_uuid`
 * so the server uses our generated PID as its WinRM CommandId. */
char *rt_winrm_soap_build_command_psrp(const char *host_url,
                                       const char *shell_id,
                                       const char *pipeline_id_uuid,
                                       const char *first_fragment_b64,
                                       const char *const *more_fragments_b64,
                                       size_t      more_fragments_count);

char *rt_winrm_soap_build_receive(const char *host_url,
                                  const char *shell_id,
                                  const char *command_id);

char *rt_winrm_soap_build_signal_terminate(const char *host_url,
                                           const char *shell_id,
                                           const char *command_id);

char *rt_winrm_soap_build_delete(const char *host_url,
                                 const char *shell_id);

/* Extract a ShellId from a Create response. Heap-owned, NULL on miss. */
char *rt_winrm_soap_parse_shell_id(const char *xml, size_t xml_len);

/* Extract a CommandId from a Command response. Heap-owned, NULL on miss. */
char *rt_winrm_soap_parse_command_id(const char *xml, size_t xml_len);

/* Parse a Receive response. On success:
 *   - *out_data is heap-owned UTF-8 (concatenation of stdout+stderr,
 *     decoded from the base64 streams). May be empty string. Caller
 *     frees with free().
 *   - *out_len is the byte length (excludes the NUL terminator).
 *   - *out_done is 1 iff the CommandState indicates the command has
 *     finished (Done state), 0 otherwise.
 *   - *out_exit is the ExitCode if reported, INT_MIN if unknown.
 * Returns 0 on success, -1 on parse error. */
int rt_winrm_soap_parse_receive(const char  *xml,
                                size_t       xml_len,
                                char       **out_data,
                                size_t      *out_len,
                                int         *out_done,
                                int         *out_exit);

/* Pull a SOAP fault reason out of a fault response. Returns heap
 * string or NULL. Useful for surfacing back to the UI. */
char *rt_winrm_soap_parse_fault_reason(const char *xml, size_t xml_len);

#endif /* RT_PROTOCOLS_WINRM_SOAP_H */
