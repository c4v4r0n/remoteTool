/*
 * WinRM terminal view: a VteTerminal with client-side line editing.
 *
 * PSRP-over-WinRM is request/response, not a real PTY: each Enter
 * submits one command line that the protocol layer runs as a single
 * pipeline. So this widget wears the visual costume of a terminal
 * (full VTE rendering of ANSI from PowerShell) but does its own line
 * editing in C, because the server does no echo, no readline, no
 * nothing. Up-arrow history, Ctrl+A/E/U/K/W, Home/End, etc. are all
 * implemented locally.
 *
 * Output (server -> screen) flows straight through vte_terminal_feed.
 * Input (keys -> us) hits the "commit" signal, where we run a small
 * state machine over the byte stream:
 *
 *   - Printable / UTF-8 bytes  -> insert at cursor, redraw tail
 *   - Backspace / Delete       -> remove, redraw tail
 *   - Left/Right arrows        -> move cursor
 *   - Home/End / Ctrl+A/E      -> jump
 *   - Ctrl+U/K/W               -> kill region
 *   - Ctrl+L                   -> clear screen, repaint prompt+line
 *   - Ctrl+C                   -> abort current line, fresh prompt
 *   - Up/Down arrows / Ctrl+P/N -> history navigation
 *   - Enter (CR or LF)         -> submit "<line>\n", clear, no prompt
 *                                 (we wait for on_idle to repaint)
 *
 * Clipboard: Ctrl+Shift+C / V / A and the right-click menu wrap VTE's
 * own clipboard helpers. Copy/paste are intercepted in key-press-event
 * so they don't reach VTE's commit signal as ^C / ^V control bytes.
 *
 * The "redraw" primitive uses VT100 sequences:
 *
 *   \r\x1b[K<prompt><line>\x1b[<n>D
 *
 * which clears the row, repaints prompt+full line, and (if the cursor
 * isn't at end) walks back n cells. This assumes the editable line
 * fits on one row of the terminal. Long lines that wrap will redraw
 * with minor visual smearing - acceptable for shell-style use.
 *
 * Repainting once per commit batch (rather than per byte) is what
 * makes pasted multibyte UTF-8 land correctly: we never feed VTE a
 * half-codepoint.
 */

#include "ui/winrm_view.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>      /* explicit_bzero */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include <vte/vte.h>
#pragma GCC diagnostic pop

#define RT_WINRM_FONT             "Monospace 11"
#define RT_WINRM_SCROLLBACK_LINES 10000
#define RT_WINRM_HISTORY_MAX      1000

typedef enum {
    ESC_NORMAL = 0,
    ESC_GOT_ESC,    /* saw 0x1b */
    ESC_GOT_CSI,    /* saw 0x1b '['  */
    ESC_GOT_SS3     /* saw 0x1b 'O'  */
} esc_state_t;

struct rt_winrm_view {
    GtkWidget *box;
    GtkWidget *status;
    GtkWidget *vte;

    rt_winrm_view_input_cb_t input_cb;
    void                    *input_user;

    int input_enabled;
    int prompt_visible;          /* a prompt is currently displayed */

    char  *prompt;
    size_t prompt_len;

    /* Editable line buffer (UTF-8). cursor is a byte offset on a
     * codepoint boundary. */
    char  *line;
    size_t line_len;
    size_t line_cap;
    size_t cursor;

    /* CSI / SS3 escape parser. */
    esc_state_t esc_state;
    char        esc_buf[16];
    size_t      esc_len;

    /* Last byte fed to VTE from server output. Used to translate
     * lone \n into \r\n without doubling a CRLF that straddles two
     * feed_output() calls. */
    char last_out_byte;

    /* History (oldest -> newest). */
    GPtrArray *history;
    int        history_pos;      /* -1 = editing fresh line */
    char      *saved_line;       /* in-progress line snapshot during nav */
};

/* ------------------------------------------------------------------ */
/* Low-level terminal output                                          */
/* ------------------------------------------------------------------ */

static void term_write(rt_winrm_view_t *v, const char *s, size_t len)
{
    if (len == 0) return;
    vte_terminal_feed(VTE_TERMINAL(v->vte), s, (gssize)len);
}

static void term_writes(rt_winrm_view_t *v, const char *s)
{
    term_write(v, s, strlen(s));
}

/* ------------------------------------------------------------------ */
/* UTF-8 helpers                                                      */
/* ------------------------------------------------------------------ */

/* Walk one codepoint backward from byte offset pos. */
static size_t utf8_back(const char *s, size_t pos)
{
    if (pos == 0) return 0;
    pos--;
    while (pos > 0 && ((unsigned char)s[pos] & 0xc0) == 0x80) {
        pos--;
    }
    return pos;
}

/* Walk one codepoint forward from byte offset pos (clamped to len). */
static size_t utf8_fwd(const char *s, size_t len, size_t pos)
{
    if (pos >= len) return len;
    pos++;
    while (pos < len && ((unsigned char)s[pos] & 0xc0) == 0x80) {
        pos++;
    }
    return pos;
}

/* ------------------------------------------------------------------ */
/* Line-buffer primitives                                             */
/* ------------------------------------------------------------------ */

static int line_ensure(rt_winrm_view_t *v, size_t need)
{
    if (need <= v->line_cap) return 0;
    size_t nc = v->line_cap ? v->line_cap : 64;
    while (nc < need) nc *= 2;
    char *nb = realloc(v->line, nc);
    if (nb == NULL) return -1;
    /* Zero new region so any stale memory from realloc isn't readable. */
    memset(nb + v->line_cap, 0, nc - v->line_cap);
    v->line     = nb;
    v->line_cap = nc;
    return 0;
}

static void redraw_line(rt_winrm_view_t *v)
{
    if (!v->prompt_visible) return;
    /* \r: column 0; \x1b[K: erase to end of row. */
    term_writes(v, "\r\x1b[K");
    term_write (v, v->prompt, v->prompt_len);
    term_write (v, v->line,   v->line_len);
    if (v->cursor < v->line_len) {
        /* Walk the cursor back over codepoints between cursor and
         * line_len. We approximate cells == codepoints (true for
         * Latin/punctuation; off by one cell per CJK glyph but the
         * worst symptom is a stale visible cursor for one keystroke). */
        size_t cells = 0;
        size_t i = v->cursor;
        while (i < v->line_len) {
            i = utf8_fwd(v->line, v->line_len, i);
            cells++;
        }
        char buf[16];
        snprintf(buf, sizeof(buf), "\x1b[%zuD", cells);
        term_writes(v, buf);
    }
}

/* ------------------------------------------------------------------ */
/* Editing operations (model + redraw)                                */
/* ------------------------------------------------------------------ */

static void op_insert(rt_winrm_view_t *v, const char *bytes, size_t n)
{
    if (n == 0) return;
    if (line_ensure(v, v->line_len + n + 1) != 0) return;
    if (v->cursor < v->line_len) {
        memmove(v->line + v->cursor + n,
                v->line + v->cursor,
                v->line_len - v->cursor);
    }
    memcpy(v->line + v->cursor, bytes, n);
    v->line_len += n;
    v->cursor   += n;
    redraw_line(v);
}

static void op_backspace(rt_winrm_view_t *v)
{
    if (v->cursor == 0) return;
    size_t newpos = utf8_back(v->line, v->cursor);
    size_t n = v->cursor - newpos;
    memmove(v->line + newpos,
            v->line + v->cursor,
            v->line_len - v->cursor);
    v->line_len -= n;
    v->cursor    = newpos;
    redraw_line(v);
}

static void op_delete_fwd(rt_winrm_view_t *v)
{
    if (v->cursor >= v->line_len) return;
    size_t end = utf8_fwd(v->line, v->line_len, v->cursor);
    size_t n   = end - v->cursor;
    memmove(v->line + v->cursor,
            v->line + end,
            v->line_len - end);
    v->line_len -= n;
    redraw_line(v);
}

static void op_left(rt_winrm_view_t *v)
{
    if (v->cursor == 0) return;
    v->cursor = utf8_back(v->line, v->cursor);
    redraw_line(v);
}

static void op_right(rt_winrm_view_t *v)
{
    if (v->cursor >= v->line_len) return;
    v->cursor = utf8_fwd(v->line, v->line_len, v->cursor);
    redraw_line(v);
}

static void op_home(rt_winrm_view_t *v)
{
    if (v->cursor == 0) return;
    v->cursor = 0;
    redraw_line(v);
}

static void op_end(rt_winrm_view_t *v)
{
    if (v->cursor >= v->line_len) return;
    v->cursor = v->line_len;
    redraw_line(v);
}

static void op_kill_to_start(rt_winrm_view_t *v)
{
    if (v->cursor == 0) return;
    memmove(v->line,
            v->line + v->cursor,
            v->line_len - v->cursor);
    v->line_len -= v->cursor;
    v->cursor    = 0;
    redraw_line(v);
}

static void op_kill_to_end(rt_winrm_view_t *v)
{
    if (v->cursor >= v->line_len) return;
    v->line_len = v->cursor;
    redraw_line(v);
}

static void op_kill_word_back(rt_winrm_view_t *v)
{
    if (v->cursor == 0) return;
    size_t pos = v->cursor;
    while (pos > 0 && v->line[pos - 1] == ' ')        pos--;
    while (pos > 0 && v->line[pos - 1] != ' ')        pos--;
    size_t n = v->cursor - pos;
    memmove(v->line + pos,
            v->line + v->cursor,
            v->line_len - v->cursor);
    v->line_len -= n;
    v->cursor    = pos;
    redraw_line(v);
}

static void op_clear_screen(rt_winrm_view_t *v)
{
    /* xterm: home + clear from cursor to end of screen. */
    term_writes(v, "\x1b[H\x1b[2J");
    if (v->prompt_visible) {
        term_write(v, v->prompt, v->prompt_len);
        term_write(v, v->line,   v->line_len);
        if (v->cursor < v->line_len) {
            size_t cells = 0;
            size_t i = v->cursor;
            while (i < v->line_len) {
                i = utf8_fwd(v->line, v->line_len, i);
                cells++;
            }
            char buf[16];
            snprintf(buf, sizeof(buf), "\x1b[%zuD", cells);
            term_writes(v, buf);
        }
    }
}

static void op_abort_line(rt_winrm_view_t *v)
{
    /* Emit "^C" + newline, drop the buffer, fresh prompt right
     * away (we don't go through the protocol on Ctrl+C). */
    term_writes(v, "^C\r\n");
    if (v->line_cap > 0) {
        explicit_bzero(v->line, v->line_cap);
    }
    v->line_len = 0;
    v->cursor   = 0;
    v->history_pos = -1;
    if (v->saved_line != NULL) {
        explicit_bzero(v->saved_line, strlen(v->saved_line));
        free(v->saved_line);
        v->saved_line = NULL;
    }
    /* prompt_visible stays true; just paint a fresh prompt. */
    term_write(v, v->prompt, v->prompt_len);
}

static void op_history_load(rt_winrm_view_t *v, const char *s)
{
    size_t n = strlen(s);
    if (line_ensure(v, n + 1) != 0) return;
    memcpy(v->line, s, n);
    v->line_len = n;
    v->cursor   = n;
    redraw_line(v);
}

static void op_history_up(rt_winrm_view_t *v)
{
    if (v->history->len == 0) return;
    if (v->history_pos == -1) {
        /* First step into history: snapshot whatever the user had typed. */
        if (v->saved_line != NULL) {
            explicit_bzero(v->saved_line, strlen(v->saved_line));
            free(v->saved_line);
        }
        v->saved_line = g_strndup(v->line ? v->line : "", v->line_len);
        v->history_pos = (int)v->history->len - 1;
    } else if (v->history_pos > 0) {
        v->history_pos--;
    } else {
        return; /* already at oldest */
    }
    op_history_load(v, g_ptr_array_index(v->history, v->history_pos));
}

static void op_history_down(rt_winrm_view_t *v)
{
    if (v->history_pos == -1) return;
    v->history_pos++;
    if ((guint)v->history_pos >= v->history->len) {
        v->history_pos = -1;
        const char *s = v->saved_line ? v->saved_line : "";
        op_history_load(v, s);
        if (v->saved_line != NULL) {
            explicit_bzero(v->saved_line, strlen(v->saved_line));
            free(v->saved_line);
            v->saved_line = NULL;
        }
    } else {
        op_history_load(v, g_ptr_array_index(v->history, v->history_pos));
    }
}

/* ------------------------------------------------------------------ */
/* Submit                                                             */
/* ------------------------------------------------------------------ */

static void history_push(rt_winrm_view_t *v, const char *line, size_t len)
{
    if (len == 0) return;
    if (v->history->len > 0) {
        const char *last = g_ptr_array_index(v->history,
                                             v->history->len - 1);
        if (strlen(last) == len && memcmp(last, line, len) == 0) {
            return;
        }
    }
    char *e = g_malloc(len + 1);
    memcpy(e, line, len);
    e[len] = '\0';
    g_ptr_array_add(v->history, e);
    while (v->history->len > RT_WINRM_HISTORY_MAX) {
        /* g_ptr_array_remove_index calls free_func (g_free). */
        g_ptr_array_remove_index(v->history, 0);
    }
}

static void op_submit(rt_winrm_view_t *v)
{
    term_writes(v, "\r\n");

    if (v->line_len > 0) {
        history_push(v, v->line, v->line_len);
    }

    if (v->line_len > 0 && v->input_cb != NULL) {
        size_t n = v->line_len;
        char  *out = malloc(n + 2);
        if (out != NULL) {
            memcpy(out, v->line, n);
            out[n]     = '\n';
            out[n + 1] = '\0';
            v->input_cb(out, n + 1, v->input_user);
            explicit_bzero(out, n + 1);
            free(out);
        }
    }

    if (v->line_cap > 0) {
        explicit_bzero(v->line, v->line_cap);
    }
    v->line_len = 0;
    v->cursor   = 0;
    v->history_pos = -1;
    if (v->saved_line != NULL) {
        explicit_bzero(v->saved_line, strlen(v->saved_line));
        free(v->saved_line);
        v->saved_line = NULL;
    }

    /* Prompt is now stale: we wait for on_idle to redraw it. */
    v->prompt_visible = 0;
}

/* ------------------------------------------------------------------ */
/* Escape parser                                                      */
/* ------------------------------------------------------------------ */

static void process_csi(rt_winrm_view_t *v, const char *seq, size_t n)
{
    if (n == 0) return;
    char term = seq[n - 1];

    if (n == 1) {
        switch (term) {
        case 'A': op_history_up(v);   return;
        case 'B': op_history_down(v); return;
        case 'C': op_right(v);        return;
        case 'D': op_left(v);         return;
        case 'F': op_end(v);          return;
        case 'H': op_home(v);         return;
        }
        return;
    }

    /* Parameterized form: digits then '~'. */
    if (term != '~') return;
    char num[8] = {0};
    size_t i = 0;
    while (i < n - 1 && i < sizeof(num) - 1
           && seq[i] >= '0' && seq[i] <= '9') {
        num[i] = seq[i];
        i++;
    }
    int p = atoi(num);
    switch (p) {
    case 1: case 7: op_home(v);       return;
    case 3:         op_delete_fwd(v); return;
    case 4: case 8: op_end(v);        return;
    /* Unhandled: 2 (Insert), 5 (PgUp), 6 (PgDn). */
    }
}

static void process_ss3(rt_winrm_view_t *v, char term)
{
    /* Application-cursor mode: ESC O <letter>. */
    switch (term) {
    case 'A': op_history_up(v);   return;
    case 'B': op_history_down(v); return;
    case 'C': op_right(v);        return;
    case 'D': op_left(v);         return;
    case 'F': op_end(v);          return;
    case 'H': op_home(v);         return;
    }
}

/* ------------------------------------------------------------------ */
/* Clipboard / context menu                                           */
/* ------------------------------------------------------------------ */

static void copy_selection(rt_winrm_view_t *v)
{
    if (vte_terminal_get_has_selection(VTE_TERMINAL(v->vte))) {
        vte_terminal_copy_clipboard_format(VTE_TERMINAL(v->vte),
                                           VTE_FORMAT_TEXT);
    }
}

/* Paste calls into the GTK clipboard asynchronously; the bytes come
 * back through the VTE "commit" signal, so our line editor handles
 * them like normal typing (newlines submit lines, queued at the
 * protocol level). */
static void paste_clipboard(rt_winrm_view_t *v)
{
    vte_terminal_paste_clipboard(VTE_TERMINAL(v->vte));
}

static void on_menu_copy(GtkMenuItem *m, gpointer user)
{
    (void)m;
    copy_selection((rt_winrm_view_t *)user);
}

static void on_menu_paste(GtkMenuItem *m, gpointer user)
{
    (void)m;
    paste_clipboard((rt_winrm_view_t *)user);
}

static void on_menu_select_all(GtkMenuItem *m, gpointer user)
{
    (void)m;
    rt_winrm_view_t *v = user;
    vte_terminal_select_all(VTE_TERMINAL(v->vte));
}

/* The menu owns a floating ref. We attach it to the VTE widget so
 * GTK takes a real ref, then destroy on selection-done. */
static void show_context_menu(rt_winrm_view_t *v, GdkEvent *trigger)
{
    GtkWidget *menu = gtk_menu_new();
    gtk_menu_attach_to_widget(GTK_MENU(menu), v->vte, NULL);

    GtkWidget *mi;

    mi = gtk_menu_item_new_with_label("Copy");
    gtk_widget_set_sensitive(mi,
        vte_terminal_get_has_selection(VTE_TERMINAL(v->vte)));
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_copy), v);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    mi = gtk_menu_item_new_with_label("Paste");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_paste), v);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    gtk_menu_shell_append(GTK_MENU_SHELL(menu),
                          gtk_separator_menu_item_new());

    mi = gtk_menu_item_new_with_label("Select All");
    g_signal_connect(mi, "activate", G_CALLBACK(on_menu_select_all), v);
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), mi);

    g_signal_connect(menu, "selection-done",
                     G_CALLBACK(gtk_widget_destroy), NULL);

    gtk_widget_show_all(menu);
    gtk_menu_popup_at_pointer(GTK_MENU(menu), trigger);
}

static gboolean on_vte_button_press(GtkWidget       *w,
                                    GdkEventButton  *ev,
                                    gpointer         user)
{
    (void)w;
    if (ev->button != GDK_BUTTON_SECONDARY) {
        return FALSE;     /* let VTE handle left-click selection */
    }
    show_context_menu((rt_winrm_view_t *)user, (GdkEvent *)ev);
    return TRUE;          /* don't let VTE clear the selection */
}

static gboolean on_vte_popup_menu(GtkWidget *w, gpointer user)
{
    /* Keyboard-driven menu request (Shift+F10, Menu key). */
    show_context_menu((rt_winrm_view_t *)user, NULL);
    (void)w;
    return TRUE;
}

static gboolean on_vte_key_press(GtkWidget   *w,
                                 GdkEventKey *ev,
                                 gpointer     user)
{
    (void)w;
    rt_winrm_view_t *v = user;
    guint mods = ev->state & gtk_accelerator_get_default_mod_mask();
    if (mods == (GDK_CONTROL_MASK | GDK_SHIFT_MASK)) {
        switch (ev->keyval) {
        case GDK_KEY_C: case GDK_KEY_c:
            copy_selection(v);
            return TRUE;
        case GDK_KEY_V: case GDK_KEY_v:
            paste_clipboard(v);
            return TRUE;
        case GDK_KEY_A: case GDK_KEY_a:
            vte_terminal_select_all(VTE_TERMINAL(v->vte));
            return TRUE;
        }
    }
    return FALSE;     /* let VTE turn this into a commit / cursor key */
}

/* ------------------------------------------------------------------ */
/* Commit handler (VTE -> us)                                         */
/* ------------------------------------------------------------------ */

static void on_vte_commit(VteTerminal *vte, gchar *text, guint size, gpointer user)
{
    (void)vte;
    rt_winrm_view_t *v = user;
    if (!v->input_enabled || !v->prompt_visible) {
        /* Drop keystrokes until a prompt is visible. This avoids the
         * race where the user types between submit and the next idle
         * callback - we'd otherwise lose track of where the cursor is. */
        return;
    }

    for (guint i = 0; i < size; ) {
        unsigned char b = (unsigned char)text[i];

        if (v->esc_state == ESC_GOT_ESC) {
            if (b == '[') {
                v->esc_state = ESC_GOT_CSI;
                v->esc_len   = 0;
            } else if (b == 'O') {
                v->esc_state = ESC_GOT_SS3;
            } else {
                /* Bare ESC or unsupported intro: drop. */
                v->esc_state = ESC_NORMAL;
            }
            i++;
            continue;
        }

        if (v->esc_state == ESC_GOT_CSI) {
            if (v->esc_len < sizeof(v->esc_buf) - 1) {
                v->esc_buf[v->esc_len++] = (char)b;
            }
            if (b >= 0x40 && b <= 0x7e) {
                process_csi(v, v->esc_buf, v->esc_len);
                v->esc_len   = 0;
                v->esc_state = ESC_NORMAL;
            }
            i++;
            continue;
        }

        if (v->esc_state == ESC_GOT_SS3) {
            process_ss3(v, (char)b);
            v->esc_state = ESC_NORMAL;
            i++;
            continue;
        }

        /* ESC_NORMAL */
        if (b == 0x1b) { v->esc_state = ESC_GOT_ESC; i++; continue; }
        switch (b) {
        case 0x7f: case 0x08: op_backspace(v);    i++; continue;
        case 0x0d: case 0x0a: op_submit(v);       i++; continue;
        case 0x09:            op_insert(v, "\t", 1); i++; continue;
        case 0x01:            op_home(v);         i++; continue;
        case 0x02:            op_left(v);         i++; continue;
        case 0x03:            op_abort_line(v);   i++; continue;
        case 0x05:            op_end(v);          i++; continue;
        case 0x06:            op_right(v);        i++; continue;
        case 0x0b:            op_kill_to_end(v);  i++; continue;
        case 0x0c:            op_clear_screen(v); i++; continue;
        case 0x0e:            op_history_down(v); i++; continue;
        case 0x10:            op_history_up(v);   i++; continue;
        case 0x15:            op_kill_to_start(v);i++; continue;
        case 0x17:            op_kill_word_back(v);i++;continue;
        }
        if (b < 0x20) { i++; continue; }   /* drop unhandled controls */

        /* Run-length printable scan: include UTF-8 continuation bytes
         * (0x80..0xbf) and high-bit-set bytes (0xc0..0xff) so a paste
         * of multibyte text lands in one op_insert. */
        guint j = i;
        while (j < size) {
            unsigned char bb = (unsigned char)text[j];
            if (bb < 0x20 || bb == 0x7f) break;
            j++;
        }
        op_insert(v, text + i, j - i);
        i = j;
    }
}

/* ------------------------------------------------------------------ */
/* Construction / destruction                                         */
/* ------------------------------------------------------------------ */

static void wrapper_destroy(gpointer data)
{
    rt_winrm_view_t *v = data;
    if (v == NULL) return;
    if (v->history != NULL) {
        g_ptr_array_unref(v->history);
    }
    if (v->saved_line != NULL) {
        explicit_bzero(v->saved_line, strlen(v->saved_line));
        free(v->saved_line);
    }
    if (v->line != NULL) {
        if (v->line_cap > 0) explicit_bzero(v->line, v->line_cap);
        free(v->line);
    }
    g_free(v->prompt);
    g_free(v);
}

rt_winrm_view_t *rt_winrm_view_new(void)
{
    rt_winrm_view_t *v = g_new0(rt_winrm_view_t, 1);
    v->prompt        = g_strdup("PS> ");
    v->prompt_len    = strlen(v->prompt);
    v->history       = g_ptr_array_new_with_free_func(g_free);
    v->history_pos   = -1;

    v->box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_margin_top   (v->box, 6);
    gtk_widget_set_margin_bottom(v->box, 6);
    gtk_widget_set_margin_start (v->box, 6);
    gtk_widget_set_margin_end   (v->box, 6);

    /* Status label */
    v->status = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(v->status), 0.0f);
    gtk_label_set_ellipsize(GTK_LABEL(v->status), PANGO_ELLIPSIZE_END);
    gtk_box_pack_start(GTK_BOX(v->box), v->status, FALSE, FALSE, 0);

    /* VTE + scrollbar */
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_vexpand(row, TRUE);
    gtk_widget_set_hexpand(row, TRUE);

    v->vte = vte_terminal_new();
    gtk_widget_set_vexpand(v->vte, TRUE);
    gtk_widget_set_hexpand(v->vte, TRUE);

    vte_terminal_set_scrollback_lines  (VTE_TERMINAL(v->vte),
                                        RT_WINRM_SCROLLBACK_LINES);
    vte_terminal_set_scroll_on_keystroke(VTE_TERMINAL(v->vte), TRUE);
    vte_terminal_set_scroll_on_output  (VTE_TERMINAL(v->vte), FALSE);
    vte_terminal_set_mouse_autohide    (VTE_TERMINAL(v->vte), TRUE);
    vte_terminal_set_cursor_blink_mode (VTE_TERMINAL(v->vte),
                                        VTE_CURSOR_BLINK_ON);

    PangoFontDescription *font = pango_font_description_from_string(RT_WINRM_FONT);
    if (font != NULL) {
        vte_terminal_set_font(VTE_TERMINAL(v->vte), font);
        pango_font_description_free(font);
    }

    GtkWidget *sb = gtk_scrollbar_new(
        GTK_ORIENTATION_VERTICAL,
        gtk_scrollable_get_vadjustment(GTK_SCROLLABLE(v->vte)));

    gtk_box_pack_start(GTK_BOX(row), v->vte, TRUE,  TRUE,  0);
    gtk_box_pack_start(GTK_BOX(row), sb,     FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(v->box), row, TRUE,  TRUE,  0);

    g_signal_connect(v->vte, "commit",
                     G_CALLBACK(on_vte_commit), v);
    g_signal_connect(v->vte, "key-press-event",
                     G_CALLBACK(on_vte_key_press), v);
    g_signal_connect(v->vte, "button-press-event",
                     G_CALLBACK(on_vte_button_press), v);
    g_signal_connect(v->vte, "popup-menu",
                     G_CALLBACK(on_vte_popup_menu), v);

    /* The wrapper struct lives as long as the top-level box. */
    g_object_set_data_full(G_OBJECT(v->box), "rt-winrm-view-wrapper",
                           v, (GDestroyNotify)wrapper_destroy);
    return v;
}

void rt_winrm_view_free(rt_winrm_view_t *v)
{
    /* Lifetime owned by the top-level widget. */
    (void)v;
}

GtkWidget *rt_winrm_view_get_widget(rt_winrm_view_t *v)
{
    return (v != NULL) ? v->box : NULL;
}

/* ------------------------------------------------------------------ */
/* Public ops                                                         */
/* ------------------------------------------------------------------ */

void rt_winrm_view_feed_output(rt_winrm_view_t *v, const char *data, size_t len)
{
    if (v == NULL || data == NULL || len == 0) return;

    /* PSRP <S> payloads use bare LF as the line separator. VTE in
     * its default mode treats LF as line-feed only (no carriage
     * return), so without a CR each line stair-steps further right
     * by however many cells the previous line had. Insert a CR
     * before any LF that isn't already preceded by one - tracking
     * the previous byte across calls so a CRLF split across two
     * chunks isn't seen as a lone LF. */
    GString *buf = g_string_sized_new(len + 16);
    char prev = v->last_out_byte;
    for (size_t i = 0; i < len; i++) {
        char ch = data[i];
        if (ch == '\n' && prev != '\r') {
            g_string_append_c(buf, '\r');
        }
        g_string_append_c(buf, ch);
        prev = ch;
    }
    v->last_out_byte = prev;
    vte_terminal_feed(VTE_TERMINAL(v->vte), buf->str, (gssize)buf->len);
    g_string_free(buf, TRUE);
}

void rt_winrm_view_set_status(rt_winrm_view_t *v, const char *status)
{
    if (v == NULL) return;
    gtk_label_set_text(GTK_LABEL(v->status), status ? status : "");
}

void rt_winrm_view_set_input_enabled(rt_winrm_view_t *v, gboolean enabled)
{
    if (v == NULL) return;
    v->input_enabled = enabled ? 1 : 0;
    if (enabled) {
        gtk_widget_grab_focus(v->vte);
    } else {
        /* Wipe any in-flight line on disconnect so the next session
         * doesn't inherit a stale buffer. */
        if (v->line_cap > 0) explicit_bzero(v->line, v->line_cap);
        v->line_len = 0;
        v->cursor   = 0;
        v->prompt_visible = 0;
    }
}

void rt_winrm_view_show_prompt(rt_winrm_view_t *v)
{
    if (v == NULL) return;
    if (v->prompt_visible) return;
    /* Make sure we start the prompt on its own row even if the last
     * server byte wasn't a newline. */
    term_writes(v, "\r\n");
    term_write (v, v->prompt, v->prompt_len);
    v->prompt_visible = 1;
}

void rt_winrm_view_set_chrome_visible(rt_winrm_view_t *v, gboolean visible)
{
    if (v == NULL) return;
    gtk_widget_set_visible(v->status, visible);
}

void rt_winrm_view_set_input_handler(rt_winrm_view_t          *v,
                                     rt_winrm_view_input_cb_t  cb,
                                     void                     *user)
{
    if (v == NULL) return;
    v->input_cb   = cb;
    v->input_user = user;
}
