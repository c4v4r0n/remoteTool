/*
 * PSRP wire format and CLIXML helpers. See header for scope.
 *
 * Wire format reminders ([MS-PSRP]):
 *
 *   Fragment header (21 bytes, big-endian):
 *     ObjectId    : u64
 *     FragmentId  : u64
 *     Flags       : u8   (bit 0 = start of message, bit 1 = end)
 *     BlobLength  : u32
 *     Blob        : BlobLength bytes
 *
 *   PSRP message header (21 bytes inside the Blob, mostly little-endian):
 *     Destination : u32 LE       (1 = client, 2 = server)
 *     MessageType : u32 LE
 *     RPID        : 16 bytes     (Runspace Pool UUID, mixed-endian
 *                                  per Windows GUID layout)
 *     PID         : 16 bytes     (Pipeline UUID, all zeros for
 *                                  runspace-scoped messages)
 *     Then the message payload (CLIXML for everything we care about).
 *
 *   The "mixed-endian" Windows GUID layout is the same as
 *   Microsoft's GUID memory layout: u32 LE, u16 LE, u16 LE, u8[8] BE.
 *   We generate UUIDs as 16 random bytes; we do not care about the
 *   "version" bits since the server treats us as a client GUID.
 */

#include "protocols/winrm/winrm_psrp.h"
#include "protocols/winrm/winrm_crypto.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Tiny growable byte buffer                                          */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
} buf_t;

static int buf_reserve(buf_t *b, size_t need)
{
    if (b->len + need <= b->cap) return 0;
    size_t nc = b->cap ? b->cap : 256;
    while (nc < b->len + need) nc *= 2;
    uint8_t *nb = realloc(b->buf, nc);
    if (nb == NULL) return -1;
    b->buf = nb;
    b->cap = nc;
    return 0;
}

static int buf_put(buf_t *b, const void *data, size_t len)
{
    if (buf_reserve(b, len) != 0) return -1;
    if (len > 0) memcpy(b->buf + b->len, data, len);
    b->len += len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Endian helpers                                                     */
/* ------------------------------------------------------------------ */

static void be64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> ((7 - i) * 8));
}

static void be32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> ((3 - i) * 8));
}

static void le32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static uint64_t rd_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static uint32_t rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint32_t rd_le32(const uint8_t *p)
{
    return  (uint32_t)p[0]        | ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/* UUID handling                                                      */
/* ------------------------------------------------------------------ */

void winrm_psrp_uuid_format(const uint8_t uuid[16], char out[37])
{
    /* Microsoft GUID byte order: bytes [0..3] hold Data1 in little-
     * endian, [4..5] Data2 in LE, [6..7] Data3 in LE; [8..15] are
     * raw bytes (no endian). The string form is BE for Data1/2/3,
     * which is why a memory-order hex dump differs from the canonical
     * GUID string. We MUST format the string in Windows convention
     * because the server parses our ShellId attribute that way and
     * compares it to the raw RPID bytes we put in PSRP messages -
     * any mismatch crashes pwrshplugin.dll with STATUS_ACCESS_VIOLATION. */
    static const char H[] = "0123456789ABCDEF";
    static const int  ORDER[16] = {
        3, 2, 1, 0,                  /* Data1 LE -> BE in string */
        5, 4,                        /* Data2 LE -> BE in string */
        7, 6,                        /* Data3 LE -> BE in string */
        8, 9, 10, 11, 12, 13, 14, 15 /* Data4 in raw byte order  */
    };
    int o = 0;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[o++] = '-';
        uint8_t b = uuid[ORDER[i]];
        out[o++] = H[(b >> 4) & 0xF];
        out[o++] = H[b        & 0xF];
    }
    out[o] = '\0';
}

/* ------------------------------------------------------------------ */
/* init/reset                                                         */
/* ------------------------------------------------------------------ */

void winrm_psrp_init(winrm_psrp_t *p)
{
    if (p == NULL) return;
    memset(p, 0, sizeof(*p));
    /* Random RPID. Windows treats it as opaque, so non-RFC4122 layout
     * is fine. */
    if (winrm_random(p->rpid, 16) != 0) {
        /* Last-ditch fallback - never trip in practice. */
        for (int i = 0; i < 16; i++) p->rpid[i] = (uint8_t)i;
    }
}

void winrm_psrp_reset(winrm_psrp_t *p)
{
    if (p == NULL) return;
    free(p->decoder_buf);
    memset(p, 0, sizeof(*p));
}

/* ------------------------------------------------------------------ */
/* PSRP message header + fragmentation                                */
/* ------------------------------------------------------------------ */

/* WinRM Shell input/output streams cap individual <rsp:Stream>
 * payloads; pypsrp uses 153600 bytes per fragment by default for
 * compatibility with Windows' MaxEnvelopeSize. We mirror that. */
#define PSRP_FRAGMENT_MAX_BLOB 153600

/* Build a 21-byte PSRP message header. */
static void psrp_header(uint8_t       hdr[21],
                        uint32_t      destination,
                        uint32_t      msg_type,
                        const uint8_t rpid[16],
                        const uint8_t pid[16])
{
    le32(hdr,      destination);
    le32(hdr +  4, msg_type);
    memcpy(hdr +  8, rpid, 16);
    memcpy(hdr + 24, pid,  16);
}
/* Sanity check: the layout above writes 24 + 16 = 40 bytes, not 21.
 * Re-reading [MS-PSRP] 2.2.1: yes, the header is 40 bytes total
 * (4 + 4 + 16 + 16). The "21-byte header" comment in places refers
 * to a different/older revision; current spec is 40. */
#define PSRP_HEADER_LEN 40

/* Wrap a complete PSRP message (header + payload) into one or more
 * fragments. The fragments are concatenated in `out`. */
static int psrp_fragment(winrm_psrp_t  *p,
                         const uint8_t *msg, size_t msg_len,
                         buf_t         *out)
{
    uint64_t object_id   = ++p->object_counter;
    uint64_t fragment_id = 0;
    size_t   off         = 0;

    while (off < msg_len || fragment_id == 0) {
        size_t chunk = msg_len - off;
        if (chunk > PSRP_FRAGMENT_MAX_BLOB) chunk = PSRP_FRAGMENT_MAX_BLOB;

        uint8_t flags = 0;
        if (fragment_id == 0)            flags |= 0x01;  /* start */
        if (off + chunk == msg_len)      flags |= 0x02;  /* end   */

        uint8_t hdr[21];
        be64(hdr,        object_id);
        be64(hdr + 8,    fragment_id);
        hdr[16] = flags;
        be32(hdr + 17,  (uint32_t)chunk);

        if (buf_put(out, hdr, 21)             != 0) return -1;
        if (chunk > 0 &&
            buf_put(out, msg + off, chunk)    != 0) return -1;

        off         += chunk;
        fragment_id += 1;
        if (msg_len == 0) break;
    }
    return 0;
}

/* Glue: produce header(40) + payload(clixml), fragmented, ready for
 * base64. `clixml` may be a plain ASCII string. */
static int psrp_message_to_fragments(winrm_psrp_t  *p,
                                     uint32_t       msg_type,
                                     const uint8_t *pid_or_null,
                                     const char    *clixml,
                                     uint8_t      **out, size_t *out_len)
{
    static const uint8_t ZERO_PID[16] = {0};
    if (pid_or_null == NULL) pid_or_null = ZERO_PID;

    size_t  payload_len = (clixml != NULL) ? strlen(clixml) : 0;
    size_t  msg_len     = PSRP_HEADER_LEN + payload_len;
    uint8_t *msg = malloc(msg_len);
    if (msg == NULL) return -1;
    psrp_header(msg, PSRP_DEST_SERVER, msg_type, p->rpid, pid_or_null);
    if (payload_len > 0) memcpy(msg + PSRP_HEADER_LEN, clixml, payload_len);

    buf_t b = {0};
    int rc = psrp_fragment(p, msg, msg_len, &b);
    free(msg);
    if (rc != 0) {
        free(b.buf);
        return -1;
    }
    *out     = b.buf;
    *out_len = b.len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLIXML payload templates                                           */
/* ------------------------------------------------------------------ */

/* PSRP message data is a bare CLIXML <Obj>, NOT wrapped in <Objs>.
 * The pwrshplugin.dll deserializer rejects an Objs root with
 * "Objs XML tag is not recognized. Line 1, position 2." The <Objs>
 * wrapper is for top-level CLIXML serialization (e.g. file output);
 * inside a PSRP message we emit just the object. (Source: pypsrp's
 * serializer.serialize() returns a bare <Obj> element. The
 * [MS-PSRP] 2.2.2.2 INIT_RUNSPACEPOOL example also shows no Objs.) */

/* SESSION_CAPABILITY (client -> server). Advertise PSRP 2.3 over
 * PowerShell 2.0 serialization. Older versions are widely accepted;
 * newer features we don't use. */
static const char CLIXML_SESSION_CAPABILITY[] =
    "<Obj RefId=\"0\">"
    "<MS>"
      "<Version N=\"protocolversion\">2.3</Version>"
      "<Version N=\"PSVersion\">2.0</Version>"
      "<Version N=\"SerializationVersion\">1.1.0.1</Version>"
    "</MS>"
    "</Obj>";

/* INIT_RUNSPACEPOOL with Min=Max=1 runspace and a NULL host. Servers
 * accept this minimal form; the host-specific fields would matter
 * only for cmdlets that try to interact with the console.
 *
 * RefIds: Obj and TN share a single counter namespace per [MS-PSRP]
 * 2.2.5.1.4.1. A reused RefId between an Obj and a TN poisons the
 * server's deserializer hash and crashes pwrshplugin.dll with
 * STATUS_ACCESS_VIOLATION - the previous version of this template
 * had that bug. Numbering here is sequential in document order. */
static const char CLIXML_INIT_RUNSPACEPOOL[] =
    "<Obj RefId=\"0\">"
    "<MS>"
      "<I32 N=\"MinRunspaces\">1</I32>"
      "<I32 N=\"MaxRunspaces\">1</I32>"
      "<Obj N=\"PSThreadOptions\" RefId=\"1\">"
        "<TN RefId=\"2\">"
          "<T>System.Management.Automation.Runspaces.PSThreadOptions</T>"
          "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
        "</TN>"
        "<ToString>Default</ToString><I32>0</I32>"
      "</Obj>"
      "<Obj N=\"ApartmentState\" RefId=\"3\">"
        "<TN RefId=\"4\">"
          "<T>System.Threading.ApartmentState</T>"
          "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
        "</TN>"
        "<ToString>Unknown</ToString><I32>2</I32>"
      "</Obj>"
      "<Obj N=\"HostInfo\" RefId=\"5\">"
        "<MS>"
          "<B N=\"_isHostNull\">true</B>"
          "<B N=\"_isHostUINull\">true</B>"
          "<B N=\"_isHostRawUINull\">true</B>"
          "<B N=\"_useRunspaceHost\">true</B>"
        "</MS>"
      "</Obj>"
      "<Nil N=\"ApplicationArguments\"/>"
    "</MS>"
    "</Obj>";

/* CREATE_PIPELINE wraps a PowerShell command. The merge-* fields tell
 * the server "send everything (warnings, verbose, etc.) into the
 * primary output stream" so we don't need to multiplex receivers.
 * Every result that PowerShell would print to a console comes back
 * as PIPELINE_OUTPUT messages with primitive <S> string objects.
 *
 * RefIds are sequential in document order to keep Obj/TN namespaces
 * non-conflicting; reusing a RefId across an Obj and a TN is what
 * crashed pwrshplugin.dll in earlier versions of this template. */
static char *clixml_create_pipeline(const char *escaped_cmd)
{
    char *out = NULL;
    int n = asprintf(&out,
        "<Obj RefId=\"0\">"
        "<MS>"
        "<Obj N=\"PowerShell\" RefId=\"1\"><MS>"
          "<Obj N=\"Cmds\" RefId=\"2\">"
            "<TN RefId=\"3\">"
              "<T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=1.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T>"
              "<T>System.Object</T>"
            "</TN>"
            "<LST>"
              "<Obj RefId=\"4\"><MS>"
                "<S N=\"Cmd\">%s</S>"
                "<B N=\"IsScript\">true</B>"
                "<Nil N=\"UseLocalScope\"/>"
                "<Obj N=\"MergeMyResult\" RefId=\"5\">"
                  "<TN RefId=\"6\">"
                    "<T>System.Management.Automation.Runspaces.PipelineResultTypes</T>"
                    "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
                  "</TN>"
                  "<ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"MergeToResult\" RefId=\"7\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"MergePreviousResults\" RefId=\"8\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                /* PipelineResultTypes per [MS-PSRP] 2.2.3.18:
                 *   None=0, Output=1, Error=2, ...
                 * MergeError/Warning/Verbose/Debug/Information are
                 * RESTRICTED to {None, Output} - other values cause
                 * pwrshplugin to fault with "fatal error while
                 * processing WSManPluginCommand arguments." Earlier
                 * iterations of this template had I32=2 with
                 * ToString=Output, which is both inconsistent (2 is
                 * Error in the enum) and out-of-range for these
                 * fields. We use None (0); stderr-style messages
                 * arrive as their own ERROR_RECORD / WARNING_RECORD
                 * PSRP messages, which the receive loop already
                 * dispatches. */
                "<Obj N=\"MergeError\" RefId=\"9\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"MergeWarning\" RefId=\"10\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"MergeVerbose\" RefId=\"11\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"MergeDebug\" RefId=\"12\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"MergeInformation\" RefId=\"13\">"
                  "<TNRef RefId=\"6\"/><ToString>None</ToString><I32>0</I32>"
                "</Obj>"
                "<Obj N=\"Args\" RefId=\"14\"><TNRef RefId=\"3\"/><LST/></Obj>"
              "</MS></Obj>"
            "</LST>"
          "</Obj>"
          "<B N=\"IsNested\">false</B>"
          "<Nil N=\"History\"/>"
          "<B N=\"RedirectShellErrorOutputPipe\">true</B>"
        "</MS></Obj>"
        "<B N=\"NoInput\">true</B>"
        "<Obj N=\"ApartmentState\" RefId=\"15\">"
          "<TN RefId=\"16\">"
            "<T>System.Threading.ApartmentState</T>"
            "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
          "</TN>"
          "<ToString>Unknown</ToString><I32>2</I32>"
        "</Obj>"
        "<Obj N=\"RemoteStreamOptions\" RefId=\"17\">"
          "<TN RefId=\"18\">"
            "<T>System.Management.Automation.RemoteStreamOptions</T>"
            "<T>System.Enum</T><T>System.ValueType</T><T>System.Object</T>"
          "</TN>"
          "<ToString>0</ToString><I32>0</I32>"
        "</Obj>"
        "<B N=\"AddToHistory\">true</B>"
        "<Obj N=\"HostInfo\" RefId=\"19\"><MS>"
          "<B N=\"_isHostNull\">true</B>"
          "<B N=\"_isHostUINull\">true</B>"
          "<B N=\"_isHostRawUINull\">true</B>"
          "<B N=\"_useRunspaceHost\">true</B>"
        "</MS></Obj>"
        "<B N=\"IsNested\">false</B>"
        "</MS>"
        "</Obj>",
        escaped_cmd);
    return (n < 0) ? NULL : out;
}

/* XML-escape (subset) for command text going into <S>...</S>. */
static char *xml_escape_cmd(const char *in)
{
    if (in == NULL) return strdup("");
    buf_t b = {0};
    for (const char *q = in; *q; ++q) {
        const char *rep;
        switch (*q) {
        case '<':  rep = "&lt;";   break;
        case '>':  rep = "&gt;";   break;
        case '&':  rep = "&amp;";  break;
        case '"':  rep = "&quot;"; break;
        case '\'': rep = "&apos;"; break;
        default: {
            uint8_t c = (uint8_t)*q;
            if (buf_put(&b, &c, 1) != 0) { free(b.buf); return NULL; }
            continue;
        }
        }
        if (buf_put(&b, rep, strlen(rep)) != 0) { free(b.buf); return NULL; }
    }
    /* NUL-terminate. */
    uint8_t z = 0;
    if (buf_put(&b, &z, 1) != 0) { free(b.buf); return NULL; }
    return (char *)b.buf;
}

/* ------------------------------------------------------------------ */
/* Public message builders                                            */
/* ------------------------------------------------------------------ */

int winrm_psrp_build_session_capability(winrm_psrp_t *p,
                                        uint8_t **out, size_t *out_len)
{
    return psrp_message_to_fragments(p,
        PSRP_MSG_SESSION_CAPABILITY,
        NULL,
        CLIXML_SESSION_CAPABILITY,
        out, out_len);
}

int winrm_psrp_build_init_runspacepool(winrm_psrp_t *p,
                                       uint8_t **out, size_t *out_len)
{
    return psrp_message_to_fragments(p,
        PSRP_MSG_INIT_RUNSPACEPOOL,
        NULL,
        CLIXML_INIT_RUNSPACEPOOL,
        out, out_len);
}

int winrm_psrp_build_create_pipeline(winrm_psrp_t  *p,
                                     const char    *command,
                                     uint8_t        out_pid[16],
                                     uint8_t      **out_frags,
                                     size_t        *out_frags_len)
{
    if (winrm_random(out_pid, 16) != 0) return -1;

    /* Wrap the user's command so PowerShell formats objects to text
     * on the server, one line per <S>. Without this, "ls" pipes back
     * raw DirectoryInfo objects whose CLIXML carries one <S> per
     * property (Name, FullName, PSPath, ...) - which our scrape-mode
     * decoder dumps as a flat blob. Out-String -Stream feeds each
     * formatted output line back as its own primitive string.
     *
     * Dot-source (".") rather than call ("&") so that variable
     * assignments inside the user's command leak into the runspace's
     * top-level scope and survive across commands. With "&" the
     * block runs in a child scope and "$x = 5" would be lost the
     * moment the pipeline ends. Set-Location works either way (it
     * mutates the runspace's PSDrive state, not a scoped variable).
     *
     * -Width 200 keeps wide table output (Get-Process, Get-Service)
     * from being truncated; PSRP without a real host defaults to a
     * narrow width otherwise. */
    char *wrapped = NULL;
    if (asprintf(&wrapped,
                 ". { %s } | Out-String -Stream -Width 200",
                 command ? command : "") < 0) {
        return -1;
    }

    char *escaped = xml_escape_cmd(wrapped);
    free(wrapped);
    if (escaped == NULL) return -1;

    char *clixml = clixml_create_pipeline(escaped);
    free(escaped);
    if (clixml == NULL) return -1;

    int rc = psrp_message_to_fragments(p,
        PSRP_MSG_CREATE_PIPELINE,
        out_pid,
        clixml,
        out_frags, out_frags_len);
    free(clixml);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Decoder: bytes -> messages                                         */
/* ------------------------------------------------------------------ */

int winrm_psrp_decoder_feed(winrm_psrp_t       *p,
                            const uint8_t      *bytes, size_t len,
                            winrm_psrp_msg_cb_t cb, void *user)
{
    size_t off = 0;
    while (off + 21 <= len) {
        uint64_t object_id   = rd_be64(bytes + off);
        uint64_t fragment_id = rd_be64(bytes + off + 8);
        uint8_t  flags       = bytes[off + 16];
        uint32_t blob_len    = rd_be32(bytes + off + 17);
        if (off + 21 + blob_len > len) return -1;

        const uint8_t *blob = bytes + off + 21;

        if ((flags & 0x01) != 0) {
            /* Start of new message - reset accumulator. */
            p->decoder_object_id   = object_id;
            p->decoder_in_progress = 1;
            p->decoder_len         = 0;
        } else if (!p->decoder_in_progress ||
                   p->decoder_object_id != object_id) {
            /* Stray middle/end fragment without start. Skip. */
            off += 21 + blob_len;
            continue;
        }
        (void)fragment_id;  /* sequence not enforced; servers send in order */

        if (p->decoder_len + blob_len > p->decoder_cap) {
            size_t nc = p->decoder_cap ? p->decoder_cap : 4096;
            while (nc < p->decoder_len + blob_len) nc *= 2;
            uint8_t *nb = realloc(p->decoder_buf, nc);
            if (nb == NULL) return -1;
            p->decoder_buf = nb;
            p->decoder_cap = nc;
        }
        memcpy(p->decoder_buf + p->decoder_len, blob, blob_len);
        p->decoder_len += blob_len;

        if ((flags & 0x02) != 0) {
            /* Message complete. */
            if (p->decoder_len >= PSRP_HEADER_LEN) {
                uint32_t msg_type = rd_le32(p->decoder_buf + 4);
                if (cb != NULL) {
                    cb(msg_type, p->decoder_buf, p->decoder_len, user);
                }
            }
            p->decoder_in_progress = 0;
            p->decoder_len         = 0;
        }

        off += 21 + blob_len;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* CLIXML scrape: <S> string extraction                               */
/* ------------------------------------------------------------------ */

/* Decode the small XML entity set we can see inside <S>...</S>:
 * &lt; &gt; &amp; &quot; &apos; and decimal &#NNNN;. Anything we
 * don't recognise is passed through verbatim. */
static void xml_unescape_into(buf_t *out, const char *in, size_t len)
{
    size_t i = 0;
    while (i < len) {
        if (in[i] != '&') {
            uint8_t c = (uint8_t)in[i++];
            buf_put(out, &c, 1);
            continue;
        }
        /* Find the ';' terminator within a sane window. */
        size_t end = i + 1;
        while (end < len && end - i < 8 && in[end] != ';') end++;
        if (end >= len || in[end] != ';') {
            uint8_t amp = '&';
            buf_put(out, &amp, 1);
            i++;
            continue;
        }
        size_t  ent_len = end - i - 1;
        const char *ent = in + i + 1;
        char repl       = 0;
        if (ent_len == 2 && memcmp(ent, "lt", 2) == 0)        repl = '<';
        else if (ent_len == 2 && memcmp(ent, "gt", 2) == 0)   repl = '>';
        else if (ent_len == 3 && memcmp(ent, "amp", 3) == 0)  repl = '&';
        else if (ent_len == 4 && memcmp(ent, "quot", 4) == 0) repl = '"';
        else if (ent_len == 4 && memcmp(ent, "apos", 4) == 0) repl = '\'';
        else if (ent_len > 1 && ent[0] == '#') {
            int v = atoi(ent + 1);
            if (v >= 0 && v < 128) repl = (char)v;
        }
        if (repl != 0) {
            uint8_t c = (uint8_t)repl;
            buf_put(out, &c, 1);
            i = end + 1;
        } else {
            /* Unknown entity - emit verbatim. */
            buf_put(out, in + i, end - i + 1);
            i = end + 1;
        }
    }
}

char *winrm_psrp_clixml_to_text(const char *clixml, size_t clixml_len)
{
    if (clixml == NULL || clixml_len == 0) return strdup("");

    buf_t out = {0};
    /* Walk the CLIXML and pull out:
     *   <S>...</S>            primitive strings
     *   <ToString>...</ToString>  for typed objects (ErrorRecord etc.)
     * We append each find followed by '\n' so the caller's terminal
     * sees PowerShell-console-style output. */
    static const struct {
        const char *open;    size_t open_len;
        const char *close;   size_t close_len;
    } TAGS[] = {
        { "<S>",         3, "</S>",         4 },
        { "<S ",         3, "</S>",         4 },  /* <S N="..."> form */
        { "<ToString>",  10,"</ToString>", 11 },
    };
    const size_t NTAGS = sizeof(TAGS) / sizeof(TAGS[0]);

    size_t pos = 0;
    while (pos < clixml_len) {
        size_t      best_off = clixml_len;
        size_t      best_idx = NTAGS;
        for (size_t i = 0; i < NTAGS; i++) {
            void *p = memmem(clixml + pos, clixml_len - pos,
                             TAGS[i].open, TAGS[i].open_len);
            if (p != NULL) {
                size_t o = (size_t)((const char *)p - clixml);
                if (o < best_off) { best_off = o; best_idx = i; }
            }
        }
        if (best_idx == NTAGS) break;

        /* For <S the tag may be either <S> or <S N="..."> - skip to
         * first '>' to find the content start. */
        size_t content_start = best_off + TAGS[best_idx].open_len;
        if (TAGS[best_idx].open[2] == ' ') {
            const char *gt = memchr(clixml + content_start, '>',
                                    clixml_len - content_start);
            if (gt == NULL) break;
            content_start = (size_t)(gt - clixml) + 1;
        }
        const char *end = memmem(clixml + content_start,
                                 clixml_len - content_start,
                                 TAGS[best_idx].close,
                                 TAGS[best_idx].close_len);
        if (end == NULL) break;

        size_t content_len = (size_t)(end - (clixml + content_start));
        xml_unescape_into(&out, clixml + content_start, content_len);
        uint8_t nl = '\n';
        buf_put(&out, &nl, 1);

        pos = (size_t)(end - clixml) + TAGS[best_idx].close_len;
    }

    /* NUL-terminate. */
    uint8_t z = 0;
    buf_put(&out, &z, 1);
    return (char *)out.buf;
}

/* ------------------------------------------------------------------ */
/* PIPELINE_STATE / RUNSPACEPOOL_STATE                                */
/* ------------------------------------------------------------------ */

/* Both messages are CLIXML objects. Look for an <I32 N="PipelineState">
 * (or RunspaceState) integer. */
static int parse_state_int(const uint8_t *msg, size_t msg_len,
                           const char *attr_name)
{
    if (msg_len <= PSRP_HEADER_LEN) return -1;
    const char *xml = (const char *)(msg + PSRP_HEADER_LEN);
    size_t      len = msg_len - PSRP_HEADER_LEN;
    /* Look for "I32 N=\"<attr_name>\">N</I32>" - simple substring find. */
    char  needle[64];
    int n = snprintf(needle, sizeof(needle), "<I32 N=\"%s\">", attr_name);
    if (n <= 0 || n >= (int)sizeof(needle)) return -1;
    const char *p = memmem(xml, len, needle, (size_t)n);
    if (p == NULL) return -1;
    p += n;
    int v = atoi(p);
    return v;
}

int winrm_psrp_parse_pipeline_state(const uint8_t *msg, size_t msg_len)
{
    return parse_state_int(msg, msg_len, "PipelineState");
}

int winrm_psrp_parse_runspace_state(const uint8_t *msg, size_t msg_len)
{
    return parse_state_int(msg, msg_len, "RunspaceState");
}
