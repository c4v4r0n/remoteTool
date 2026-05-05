/*
 * SOAP / WS-Management envelope helpers.
 *
 * Generation is plain string assembly: WS-Man envelopes are tightly
 * scoped, the templates are short, and a libxml2 builder would be
 * heavier than the data. Anything that flows from user input into an
 * element body (the command line, shell ids returned from the server,
 * the host url) goes through xml_escape() first to keep operators
 * from being able to break out of the envelope.
 *
 * Parsing uses libxml2 + XPath against the canonical namespaces.
 * Receive responses carry base64-encoded streams that we decode and
 * concatenate (stdout+stderr) in document order so the caller emits
 * a single byte-stream consistent with what an interactive shell
 * would have produced.
 */

#include "protocols/winrm/winrm_soap.h"

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

/* WS-Man / SOAP namespaces we register XPath prefixes against. */
#define NS_S    "http://www.w3.org/2003/05/soap-envelope"
#define NS_A    "http://schemas.xmlsoap.org/ws/2004/08/addressing"
#define NS_W    "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
#define NS_RSP  "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
#define NS_X    "http://schemas.xmlsoap.org/ws/2004/09/transfer"

/* ------------------------------------------------------------------ */
/* String / escape helpers                                            */
/* ------------------------------------------------------------------ */

/* Append text to a dynamically grown buffer. Returns 0 on success. */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} sb_t;

static int sb_append(sb_t *s, const char *str)
{
    size_t n = strlen(str);
    if (s->len + n + 1 > s->cap) {
        size_t nc = s->cap ? s->cap : 1024;
        while (nc < s->len + n + 1) nc *= 2;
        char *nb = realloc(s->buf, nc);
        if (nb == NULL) return -1;
        s->buf = nb;
        s->cap = nc;
    }
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
    return 0;
}

static char *xml_escape(const char *in)
{
    if (in == NULL) {
        return strdup("");
    }
    sb_t s = {0};
    for (const char *p = in; *p; ++p) {
        const char *rep;
        switch (*p) {
        case '<':  rep = "&lt;";   break;
        case '>':  rep = "&gt;";   break;
        case '&':  rep = "&amp;";  break;
        case '"':  rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default: {
            char tmp[2] = { *p, '\0' };
            if (sb_append(&s, tmp) != 0) { free(s.buf); return NULL; }
            continue;
        }
        }
        if (sb_append(&s, rep) != 0) { free(s.buf); return NULL; }
    }
    if (s.buf == NULL) {
        return strdup("");
    }
    return s.buf;
}

/* Generate a UUID-v4-ish identifier. This is for SOAP MessageID only
 * (the WS-Man server only requires uniqueness within the session), so
 * a deterministic-but-unique-enough rand_r-driven generator suffices. */
#define RT_MSGID_LEN 48
static void make_msgid(char out[RT_MSGID_LEN])
{
    static unsigned int g_seed = 0;
    if (g_seed == 0) {
        g_seed = (unsigned int)((uintptr_t)out ^ (unsigned int)time(NULL));
    }
    unsigned int r1 = (unsigned int)rand_r(&g_seed);
    unsigned int r2 = (unsigned int)rand_r(&g_seed);
    unsigned int r3 = (unsigned int)rand_r(&g_seed);
    unsigned int r4 = (unsigned int)rand_r(&g_seed);
    snprintf(out, RT_MSGID_LEN,
             "uuid:%08X-%04X-%04X-%04X-%04X%08X",
             r1,
             (r2 >> 16) & 0xFFFFu,
             ((r2 & 0x0FFFu) | 0x4000u),                 /* v4 */
             ((r3 >> 16) & 0x3FFFu) | 0x8000u,           /* RFC4122 variant */
             r3 & 0xFFFFu,
             r4);
}

/* ------------------------------------------------------------------ */
/* Envelope template                                                   */
/* ------------------------------------------------------------------ */

/* Header common to every envelope, parameterised by Action,
 * ResourceURI, and an optional inner block (selectors, options).
 * `host_url` is already escaped. Caller frees the returned string. */
static char *build_envelope(const char *host_url,
                            const char *action_uri,
                            const char *resource_uri,
                            const char *extra_header,
                            const char *body)
{
    char msgid[RT_MSGID_LEN];
    make_msgid(msgid);

    char *out = NULL;
    int n = asprintf(&out,
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<s:Envelope xmlns:s=\"" NS_S "\""
        " xmlns:a=\"" NS_A "\""
        " xmlns:w=\"" NS_W "\""
        " xmlns:rsp=\"" NS_RSP "\">"
        "<s:Header>"
          "<a:To>%s</a:To>"
          "<w:ResourceURI s:mustUnderstand=\"true\">%s</w:ResourceURI>"
          "<a:ReplyTo>"
            "<a:Address s:mustUnderstand=\"true\">"
              "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
            "</a:Address>"
          "</a:ReplyTo>"
          "<a:Action s:mustUnderstand=\"true\">%s</a:Action>"
          "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
          "<a:MessageID>%s</a:MessageID>"
          "<w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>"
          "<w:OperationTimeout>PT60.000S</w:OperationTimeout>"
          "%s"
        "</s:Header>"
        "<s:Body>%s</s:Body>"
        "</s:Envelope>",
        host_url, resource_uri, action_uri, msgid,
        extra_header ? extra_header : "",
        body ? body : "");
    return (n < 0) ? NULL : out;
}

/* SelectorSet block selecting a ShellId. Caller frees. */
static char *selector_shell(const char *shell_id_escaped)
{
    char *out = NULL;
    int n = asprintf(&out,
        "<w:SelectorSet>"
          "<w:Selector Name=\"ShellId\">%s</w:Selector>"
        "</w:SelectorSet>",
        shell_id_escaped);
    return (n < 0) ? NULL : out;
}

/* ------------------------------------------------------------------ */
/* Builders                                                           */
/* ------------------------------------------------------------------ */

char *rt_winrm_soap_build_create(const char *host_url)
{
    char *url = xml_escape(host_url);
    if (url == NULL) return NULL;

    const char *body =
        "<rsp:Shell>"
          "<rsp:InputStreams>stdin</rsp:InputStreams>"
          "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>"
        "</rsp:Shell>";
    /* OptionSet: WINRS_NOPROFILE=FALSE, WINRS_CODEPAGE=437. Defaults
     * are fine for now; explicit codepage avoids surprises. */
    const char *option_set =
        "<w:OptionSet>"
          "<w:Option Name=\"WINRS_NOPROFILE\">FALSE</w:Option>"
          "<w:Option Name=\"WINRS_CODEPAGE\">437</w:Option>"
        "</w:OptionSet>";
    char *env = build_envelope(
        url,
        NS_X "/Create",
        RT_WSMAN_RESOURCE_CMD,
        option_set,
        body);
    free(url);
    return env;
}

char *rt_winrm_soap_build_create_powershell(const char *host_url,
                                            const char *shell_id_uuid,
                                            const char *creation_xml_b64)
{
    char *url = xml_escape(host_url);
    char *sid = xml_escape(shell_id_uuid);
    if (url == NULL || sid == NULL) {
        free(url); free(sid); return NULL;
    }
    /* `creation_xml_b64` is already pure base64 (no XML chars), but
     * be defensive in case a future caller hands us padding glyphs. */
    char *cxb = xml_escape(creation_xml_b64 ? creation_xml_b64 : "");
    if (cxb == NULL) {
        free(url); free(sid); return NULL;
    }

    char *body = NULL;
    int n = asprintf(&body,
        "<rsp:Shell ShellId=\"%s\" Name=\"remoteTool-Runspace\">"
          "<rsp:InputStreams>stdin pr</rsp:InputStreams>"
          "<rsp:OutputStreams>stdout</rsp:OutputStreams>"
          "<creationXml xmlns=\"http://schemas.microsoft.com/powershell\">"
            "%s"
          "</creationXml>"
        "</rsp:Shell>",
        sid, cxb);
    if (n < 0) {
        free(url); free(sid); free(cxb);
        return NULL;
    }

    /* OptionSet with the protocolversion option is REQUIRED by
     * [MS-PSRP] 3.1.4.5.2 (Rules for the wxf:Create Message).
     * pypsrp's RunspacePool.open() sends this exact form; an earlier
     * iteration of this code dropped the OptionSet entirely after
     * a previous attempt with MustComply="true" got InvalidOptions
     * back - the actual cause then was the missing
     * `s:mustUnderstand="true"` on the OptionSet itself, which the
     * server requires to enforce MustComply on the inner Option. */
    const char *option_set =
        "<w:OptionSet s:mustUnderstand=\"true\">"
          "<w:Option Name=\"protocolversion\" "
                    "MustComply=\"true\">2.3</w:Option>"
        "</w:OptionSet>";
    char *env = build_envelope(
        url,
        NS_X "/Create",
        RT_WSMAN_RESOURCE_POWERSHELL,
        option_set,
        body);
    free(url); free(sid); free(cxb); free(body);
    return env;
}

char *rt_winrm_soap_build_command(const char *host_url,
                                  const char *shell_id,
                                  const char *command)
{
    char *url = xml_escape(host_url);
    char *sid = xml_escape(shell_id);
    char *cmd = xml_escape(command);
    if (url == NULL || sid == NULL || cmd == NULL) {
        free(url); free(sid); free(cmd);
        return NULL;
    }

    char *sel = selector_shell(sid);
    if (sel == NULL) {
        free(url); free(sid); free(cmd);
        return NULL;
    }

    char *body = NULL;
    int n = asprintf(&body,
        "<rsp:CommandLine>"
          "<rsp:Command>%s</rsp:Command>"
        "</rsp:CommandLine>",
        cmd);
    if (n < 0) {
        free(url); free(sid); free(cmd); free(sel);
        return NULL;
    }

    /* WSMAN_CMD_SHELL_OPTIONS: WINRS_CONSOLEMODE_STDIN, WINRS_SKIP_CMD_SHELL=FALSE */
    const char *option_set =
        "<w:OptionSet>"
          "<w:Option Name=\"WINRS_CONSOLEMODE_STDIN\">TRUE</w:Option>"
          "<w:Option Name=\"WINRS_SKIP_CMD_SHELL\">FALSE</w:Option>"
        "</w:OptionSet>";

    char *combined = NULL;
    n = asprintf(&combined, "%s%s", sel, option_set);
    free(sel);
    if (n < 0) {
        free(url); free(sid); free(cmd); free(body);
        return NULL;
    }

    char *env = build_envelope(
        url,
        NS_RSP "/Command",
        RT_WSMAN_RESOURCE_CMD,
        combined,
        body);

    free(url); free(sid); free(cmd); free(body); free(combined);
    return env;
}

char *rt_winrm_soap_build_command_psrp(const char *host_url,
                                       const char *shell_id,
                                       const char *pipeline_id_uuid,
                                       const char *first_fragment_b64,
                                       const char *const *more_fragments_b64,
                                       size_t      more_fragments_count)
{
    char *url = xml_escape(host_url);
    char *sid = xml_escape(shell_id);
    char *pid = xml_escape(pipeline_id_uuid);
    char *frag0 = xml_escape(first_fragment_b64 ? first_fragment_b64 : "");
    if (url == NULL || sid == NULL || pid == NULL || frag0 == NULL) {
        free(url); free(sid); free(pid); free(frag0);
        return NULL;
    }
    char *sel = selector_shell(sid);
    if (sel == NULL) {
        free(url); free(sid); free(pid); free(frag0);
        return NULL;
    }

    /* CommandLine carries the first fragment in <Command> and any
     * remaining fragments in successive <Arguments> elements. The
     * CommandId attribute pins the WinRM CommandId to the same UUID
     * as the PSRP pipeline_id, so server-side correlation is direct. */
    struct {
        size_t cap, len;
        char  *buf;
    } body = {0, 0, NULL};
    /* Inline a small grow-and-cat helper to keep this self-contained. */
    #define APPEND(s) do {                                                  \
        size_t sl = strlen(s);                                              \
        if (body.len + sl + 1 > body.cap) {                                 \
            size_t nc = body.cap ? body.cap : 256;                          \
            while (nc < body.len + sl + 1) nc *= 2;                         \
            char *nb = realloc(body.buf, nc);                               \
            if (nb == NULL) {                                               \
                free(body.buf);                                             \
                free(url); free(sid); free(pid); free(frag0); free(sel);    \
                return NULL;                                                \
            }                                                               \
            body.buf = nb; body.cap = nc;                                   \
        }                                                                   \
        memcpy(body.buf + body.len, s, sl);                                 \
        body.len += sl;                                                     \
        body.buf[body.len] = '\0';                                          \
    } while (0)

    /* PowerShell-shell convention: <rsp:Command> is EMPTY (the command
     * name lives inside the PSRP CREATE_PIPELINE CLIXML payload) and
     * the base64-encoded PSRP fragment goes into <rsp:Arguments>.
     * The cmd-shell convention (fragment-in-Command) makes Windows'
     * WSManPluginCommand fault with "fatal error while processing
     * WSManPluginCommand arguments". Source: pypsrp powershell.py
     *   shell.command("", arguments=[first_frag], command_id=self.id)
     */
    APPEND("<rsp:CommandLine CommandId=\"");
    APPEND(pid);
    APPEND("\"><rsp:Command></rsp:Command>"
           "<rsp:Arguments>");
    APPEND(frag0);
    APPEND("</rsp:Arguments>");
    for (size_t i = 0; i < more_fragments_count; i++) {
        char *more = xml_escape(more_fragments_b64[i]);
        if (more == NULL) {
            free(body.buf);
            free(url); free(sid); free(pid); free(frag0); free(sel);
            return NULL;
        }
        APPEND("<rsp:Arguments>");
        APPEND(more);
        APPEND("</rsp:Arguments>");
        free(more);
    }
    APPEND("</rsp:CommandLine>");
    #undef APPEND

    char *env = build_envelope(
        url,
        NS_RSP "/Command",
        RT_WSMAN_RESOURCE_POWERSHELL,
        sel,
        body.buf);

    free(body.buf);
    free(url); free(sid); free(pid); free(frag0); free(sel);
    return env;
}

char *rt_winrm_soap_build_receive(const char *host_url,
                                  const char *shell_id,
                                  const char *command_id)
{
    char *url = xml_escape(host_url);
    char *sid = xml_escape(shell_id);
    if (url == NULL || sid == NULL) {
        free(url); free(sid);
        return NULL;
    }
    char *sel = selector_shell(sid);
    if (sel == NULL) {
        free(url); free(sid);
        return NULL;
    }

    /* Two body shapes:
     *   - command_id NULL/empty -> runspace-level Receive (drain
     *     SESSION_CAPABILITY response, RUNSPACEPOOL_STATE messages,
     *     etc.). The CommandId attribute MUST be omitted, not set
     *     to "" - some Windows builds reject the empty-string form.
     *   - command_id set       -> per-pipeline Receive.
     *
     * PowerShell shells declare only "stdout" as an output stream,
     * so we don't ask for "stderr" - that produced an InvalidStream
     * fault on the previous cmd-shell-style builder. */
    char *body = NULL;
    int   n;
    if (command_id != NULL && command_id[0] != '\0') {
        char *cid = xml_escape(command_id);
        if (cid == NULL) { free(url); free(sid); free(sel); return NULL; }
        n = asprintf(&body,
            "<rsp:Receive>"
              "<rsp:DesiredStream CommandId=\"%s\">stdout</rsp:DesiredStream>"
            "</rsp:Receive>",
            cid);
        free(cid);
    } else {
        n = asprintf(&body,
            "<rsp:Receive>"
              "<rsp:DesiredStream>stdout</rsp:DesiredStream>"
            "</rsp:Receive>");
    }
    if (n < 0) {
        free(url); free(sid); free(sel);
        return NULL;
    }

    char *env = build_envelope(
        url,
        NS_RSP "/Receive",
        RT_WSMAN_RESOURCE_POWERSHELL,
        sel,
        body);

    free(url); free(sid); free(sel); free(body);
    return env;
}

char *rt_winrm_soap_build_signal_terminate(const char *host_url,
                                           const char *shell_id,
                                           const char *command_id)
{
    char *url = xml_escape(host_url);
    char *sid = xml_escape(shell_id);
    char *cid = xml_escape(command_id);
    if (url == NULL || sid == NULL || cid == NULL) {
        free(url); free(sid); free(cid);
        return NULL;
    }
    char *sel = selector_shell(sid);
    if (sel == NULL) {
        free(url); free(sid); free(cid);
        return NULL;
    }

    char *body = NULL;
    int n = asprintf(&body,
        "<rsp:Signal CommandId=\"%s\">"
          "<rsp:Code>" NS_RSP "/signal/terminate</rsp:Code>"
        "</rsp:Signal>",
        cid);
    if (n < 0) {
        free(url); free(sid); free(cid); free(sel);
        return NULL;
    }

    char *env = build_envelope(
        url,
        NS_RSP "/Signal",
        RT_WSMAN_RESOURCE_POWERSHELL,
        sel,
        body);

    free(url); free(sid); free(cid); free(sel); free(body);
    return env;
}

char *rt_winrm_soap_build_delete(const char *host_url,
                                 const char *shell_id)
{
    char *url = xml_escape(host_url);
    char *sid = xml_escape(shell_id);
    if (url == NULL || sid == NULL) {
        free(url); free(sid);
        return NULL;
    }
    char *sel = selector_shell(sid);
    if (sel == NULL) {
        free(url); free(sid);
        return NULL;
    }
    char *env = build_envelope(
        url,
        NS_X "/Delete",
        RT_WSMAN_RESOURCE_POWERSHELL,
        sel,
        "");
    free(url); free(sid); free(sel);
    return env;
}

/* ------------------------------------------------------------------ */
/* Parsing                                                            */
/* ------------------------------------------------------------------ */

/* Parse buffer into an xmlDocPtr; caller frees with xmlFreeDoc. */
static xmlDocPtr parse_xml(const char *xml, size_t xml_len)
{
    if (xml == NULL || xml_len == 0) {
        return NULL;
    }
    return xmlReadMemory(xml, (int)xml_len, "winrm.xml", NULL,
                         XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
}

/* Register all WS-Man-related namespace prefixes for an XPath context. */
static void register_namespaces(xmlXPathContextPtr xpath)
{
    xmlXPathRegisterNs(xpath, BAD_CAST "s",   BAD_CAST NS_S);
    xmlXPathRegisterNs(xpath, BAD_CAST "a",   BAD_CAST NS_A);
    xmlXPathRegisterNs(xpath, BAD_CAST "w",   BAD_CAST NS_W);
    xmlXPathRegisterNs(xpath, BAD_CAST "rsp", BAD_CAST NS_RSP);
    xmlXPathRegisterNs(xpath, BAD_CAST "x",   BAD_CAST NS_X);
}

/* Run XPath, return text content of first matching node or NULL.
 * Caller frees with free(). */
static char *xpath_first_text(xmlDocPtr doc, const char *expr)
{
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (ctx == NULL) {
        return NULL;
    }
    register_namespaces(ctx);
    xmlXPathObjectPtr obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
    char *out = NULL;
    if (obj != NULL && obj->nodesetval != NULL && obj->nodesetval->nodeNr > 0) {
        xmlChar *t = xmlNodeGetContent(obj->nodesetval->nodeTab[0]);
        if (t != NULL) {
            out = strdup((const char *)t);
            xmlFree(t);
        }
    }
    if (obj != NULL) xmlXPathFreeObject(obj);
    xmlXPathFreeContext(ctx);
    return out;
}

/* ------------------------------------------------------------------ */
/* Base64 decode (single-buffer, in-place safe)                       */
/* ------------------------------------------------------------------ */

static int b64_val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decodes base64 (ignoring whitespace). Returns malloc'd buffer + len.
 * Returns NULL on alloc failure (invalid input is best-effort skipped). */
static char *b64_decode(const char *in, size_t in_len, size_t *out_len)
{
    char *out = malloc(in_len + 1);
    if (out == NULL) {
        return NULL;
    }
    int   quad[4];
    int   q = 0;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isspace(c)) continue;
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) continue;
        quad[q++] = v;
        if (q == 4) {
            out[o++] = (char)((quad[0] << 2) | (quad[1] >> 4));
            out[o++] = (char)((quad[1] << 4) | (quad[2] >> 2));
            out[o++] = (char)((quad[2] << 6) | quad[3]);
            q = 0;
        }
    }
    if (q == 2) {
        out[o++] = (char)((quad[0] << 2) | (quad[1] >> 4));
    } else if (q == 3) {
        out[o++] = (char)((quad[0] << 2) | (quad[1] >> 4));
        out[o++] = (char)((quad[1] << 4) | (quad[2] >> 2));
    }
    out[o] = '\0';
    if (out_len != NULL) {
        *out_len = o;
    }
    return out;
}

/* ------------------------------------------------------------------ */
/* Public parsers                                                     */
/* ------------------------------------------------------------------ */

char *rt_winrm_soap_parse_shell_id(const char *xml, size_t xml_len)
{
    xmlDocPtr doc = parse_xml(xml, xml_len);
    if (doc == NULL) return NULL;
    /* Two response shapes are possible: the Shell element itself
     * carries a ShellId child, or the ResourceCreated reference
     * carries a Selector Name="ShellId". Handle both. */
    char *id = xpath_first_text(doc, "//rsp:Shell/rsp:ShellId");
    if (id == NULL) {
        id = xpath_first_text(doc,
            "//w:Selector[@Name='ShellId']");
    }
    xmlFreeDoc(doc);
    return id;
}

char *rt_winrm_soap_parse_command_id(const char *xml, size_t xml_len)
{
    xmlDocPtr doc = parse_xml(xml, xml_len);
    if (doc == NULL) return NULL;
    char *id = xpath_first_text(doc, "//rsp:CommandResponse/rsp:CommandId");
    xmlFreeDoc(doc);
    return id;
}

int rt_winrm_soap_parse_receive(const char  *xml,
                                size_t       xml_len,
                                char       **out_data,
                                size_t      *out_len,
                                int         *out_done,
                                int         *out_exit)
{
    if (out_data != NULL) *out_data = NULL;
    if (out_len  != NULL) *out_len  = 0;
    if (out_done != NULL) *out_done = 0;
    if (out_exit != NULL) *out_exit = INT_MIN;

    xmlDocPtr doc = parse_xml(xml, xml_len);
    if (doc == NULL) return -1;

    /* Decode and concatenate all <rsp:Stream> elements in document
     * order. Mixing stdout/stderr is intentional: the UI is line-
     * oriented and rendering them separately would invert the
     * relative ordering the server intended. */
    sb_t s = {0};
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    if (ctx == NULL) { xmlFreeDoc(doc); return -1; }
    register_namespaces(ctx);

    xmlXPathObjectPtr obj = xmlXPathEvalExpression(
        BAD_CAST "//rsp:Stream", ctx);
    if (obj != NULL && obj->nodesetval != NULL) {
        for (int i = 0; i < obj->nodesetval->nodeNr; i++) {
            xmlChar *t = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);
            if (t == NULL) continue;
            size_t dec_len = 0;
            char *dec = b64_decode((const char *)t, strlen((const char *)t),
                                   &dec_len);
            xmlFree(t);
            if (dec == NULL) continue;
            /* sb_append takes a NUL-terminated string; for safety
             * append byte-by-byte since decoded streams may carry
             * embedded NULs (unlikely, but defensive). */
            if (s.len + dec_len + 1 > s.cap) {
                size_t nc = s.cap ? s.cap : 1024;
                while (nc < s.len + dec_len + 1) nc *= 2;
                char *nb = realloc(s.buf, nc);
                if (nb == NULL) { free(dec); free(s.buf); s.buf = NULL; break; }
                s.buf = nb; s.cap = nc;
            }
            memcpy(s.buf + s.len, dec, dec_len);
            s.len += dec_len;
            s.buf[s.len] = '\0';
            free(dec);
        }
    }
    if (obj != NULL) xmlXPathFreeObject(obj);

    /* CommandState attribute on <rsp:CommandState> determines done-ness.
     *   .../CommandState/Done  -> finished
     *   .../CommandState/Running -> still running */
    char *state = xpath_first_text(doc,
        "//rsp:CommandState/@State");
    if (state == NULL) {
        /* libxml2 returns attribute text via xmlNodeGetContent on
         * the attribute node. Try a node-based query as a fallback. */
        xmlXPathObjectPtr o2 = xmlXPathEvalExpression(
            BAD_CAST "//rsp:CommandState", ctx);
        if (o2 != NULL && o2->nodesetval != NULL && o2->nodesetval->nodeNr > 0) {
            xmlChar *attr = xmlGetProp(o2->nodesetval->nodeTab[0],
                                       BAD_CAST "State");
            if (attr != NULL) {
                state = strdup((const char *)attr);
                xmlFree(attr);
            }
        }
        if (o2 != NULL) xmlXPathFreeObject(o2);
    }
    if (state != NULL && strstr(state, "Done") != NULL) {
        if (out_done != NULL) *out_done = 1;
    }
    free(state);

    /* ExitCode is reported only with Done. */
    char *exit_str = xpath_first_text(doc, "//rsp:ExitCode");
    if (exit_str != NULL && out_exit != NULL) {
        *out_exit = atoi(exit_str);
    }
    free(exit_str);

    xmlXPathFreeContext(ctx);
    xmlFreeDoc(doc);

    if (out_data != NULL) *out_data = s.buf;
    else                  free(s.buf);
    if (out_len  != NULL) *out_len  = s.len;
    return 0;
}

char *rt_winrm_soap_parse_fault_reason(const char *xml, size_t xml_len)
{
    xmlDocPtr doc = parse_xml(xml, xml_len);
    if (doc == NULL) return NULL;
    /* SOAP 1.2 Fault: //s:Fault/s:Reason/s:Text */
    char *text = xpath_first_text(doc, "//s:Fault/s:Reason/s:Text");
    if (text == NULL) {
        /* WS-Man often nests detail/Message under fault; try that. */
        text = xpath_first_text(doc, "//s:Fault//*[local-name()='Message']");
    }
    xmlFreeDoc(doc);
    return text;
}
