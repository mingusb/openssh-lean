/* Streaming value boundaries, not a replacement JSON decoder. Input identity
 * and the complete decoded data remain checked by the archive/Lean consumers. */
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t depth;
    uint32_t started, kind, quoted, escaped;
} core_json_frame;

/* kind: 1 composite, 2 string, 3 scalar. A scalar delimiter is not consumed. */
int core_json_frame_feed(core_json_frame *s, const unsigned char *data,
                         size_t length, size_t *used)
{
    size_t i;
    for (i = 0; i < length; i++) {
        unsigned char c = data[i];
        if (!s->started) {
            if (c == ' ' || c == '\n' || c == '\r' || c == '\t') continue;
            s->started = 1;
            if (c == '{' || c == '[') { s->kind = 1; s->depth = 1; continue; }
            if (c == '"') { s->kind = 2; s->quoted = 1; continue; }
            if (c == ',' || c == ']' || c == '}' || c == ':') { *used = i; return -1; }
            s->kind = 3;
        }
        if (s->quoted) {
            if (s->escaped) { s->escaped = 0; continue; }
            if (c == '\\') { s->escaped = 1; continue; }
            if (c == '"') {
                s->quoted = 0;
                if (s->kind == 2) { *used = i + 1; return 1; }
            }
            if (c < 0x20) { *used = i; return -1; }
            continue;
        }
        if (s->kind == 3) {
            if (c == ',' || c == ']' || c == '}' || c == ' ' ||
                c == '\n' || c == '\r' || c == '\t') { *used = i; return 1; }
            continue;
        }
        if (c == '"') s->quoted = 1;
        else if (c == '{' || c == '[') {
            if (++s->depth == 0) { *used = i; return -1; }
        } else if (c == '}' || c == ']') {
            if (s->depth == 0) { *used = i; return -1; }
            if (--s->depth == 0) { *used = i + 1; return 1; }
        }
    }
    *used = length;
    return 0;
}
