/*
 * Differential oracle: calls the actual pinned OpenSSH libssh.a functions.
 * Compile with upstream generated include paths and -Wl,--wrap=malloc.
 * No OpenSSH function implementation is copied into this file.
 *
 * Input:  op hex wantValue wantLength allocSuccess previous
 * Output: code remaininghex value length
 * Hex is lowercase, '_' is an empty byte sequence, '-' is NULL/absent.
 * A '-' input byte sequence is also accepted as empty for convenience.
 * For integer operations, previous alone determines whether valp is NULL;
 * the value field is decimal and the length field is always '-'.
 * For string operations, previous is ignored. Copied values include the
 * added NUL terminator; direct values consist only of the wire payload.
 */
#include "includes.h"
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sshbuf.h"

static int fail_malloc;
void *__real_malloc(size_t);

void *
__wrap_malloc(size_t n)
{
    if (fail_malloc) {
        errno = ENOMEM;
        return NULL;
    }
    return __real_malloc(n);
}

static int
hex_digit(int ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static unsigned char *
parse_hex(const char *text, size_t *len)
{
    size_t i, nchars;
    unsigned char *bytes;
    if (strcmp(text, "_") == 0 || strcmp(text, "-") == 0) {
        *len = 0;
        return calloc(1, 1);
    }
    nchars = strlen(text);
    if (nchars % 2 != 0 || nchars > 2 * 1024 * 1024)
        return NULL;
    *len = nchars / 2;
    if ((bytes = malloc(*len == 0 ? 1 : *len)) == NULL)
        return NULL;
    for (i = 0; i < *len; i++) {
        int hi = hex_digit((unsigned char)text[2 * i]);
        int lo = hex_digit((unsigned char)text[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(bytes);
            return NULL;
        }
        bytes[i] = (unsigned char)(hi * 16 + lo);
    }
    return bytes;
}

static void
print_hex(const unsigned char *bytes, size_t len)
{
    size_t i;
    if (len == 0) {
        putchar('_');
        return;
    }
    for (i = 0; i < len; i++)
        printf("%02x", bytes[i]);
}

static int
parse_flag(const char *text, int *flag)
{
    if (strcmp(text, "0") != 0 && strcmp(text, "1") != 0)
        return -1;
    *flag = text[0] - '0';
    return 0;
}

static int
parse_previous(const char *text, int *present, uint64_t *value)
{
    char *end;
    unsigned long long parsed;
    *present = strcmp(text, "-") != 0;
    *value = 0;
    if (!*present)
        return 0;
    if (*text < '0' || *text > '9')
        return -1;
    errno = 0;
    parsed = strtoull(text, &end, 10);
    if (errno != 0 || *end != '\0' || parsed > UINT64_MAX)
        return -1;
    *value = (uint64_t)parsed;
    return 0;
}

static int
run_row(char **parts)
{
    const char *op = parts[0];
    unsigned char *input;
    unsigned char sentinel[1] = {0x5a};
    unsigned char *allocated = sentinel;
    const unsigned char *direct = sentinel;
    const unsigned char *output = NULL;
    struct sshbuf *buf;
    size_t input_len, length = 987654321, wire_len = 0, output_len = 0;
    uint64_t previous, numeric = 0;
    int want_value, want_length, alloc_success, has_previous;
    int code, is_integer = 0, is_copied = 0;

    if (parse_flag(parts[2], &want_value) != 0 ||
        parse_flag(parts[3], &want_length) != 0 ||
        parse_flag(parts[4], &alloc_success) != 0 ||
        parse_previous(parts[5], &has_previous, &previous) != 0 ||
        (input = parse_hex(parts[1], &input_len)) == NULL)
        return -1;
    if ((buf = sshbuf_from(input, input_len)) == NULL) {
        free(input);
        return -1;
    }
    if (input_len >= 4)
        wire_len = ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
            ((uint32_t)input[2] << 8) | (uint32_t)input[3];

    if (strcmp(op, "u8") == 0) {
        uint8_t value = (uint8_t)previous;
        if (previous > UINT8_MAX) goto invalid;
        code = sshbuf_get_u8(buf, has_previous ? &value : NULL);
        numeric = value;
        is_integer = 1;
    } else if (strcmp(op, "u16") == 0) {
        uint16_t value = (uint16_t)previous;
        if (previous > UINT16_MAX) goto invalid;
        code = sshbuf_get_u16(buf, has_previous ? &value : NULL);
        numeric = value;
        is_integer = 1;
    } else if (strcmp(op, "u32") == 0) {
        uint32_t value = (uint32_t)previous;
        if (previous > UINT32_MAX) goto invalid;
        code = sshbuf_get_u32(buf, has_previous ? &value : NULL);
        numeric = value;
        is_integer = 1;
    } else if (strcmp(op, "u64") == 0) {
        uint64_t value = previous;
        code = sshbuf_get_u64(buf, has_previous ? &value : NULL);
        numeric = value;
        is_integer = 1;
    } else if (strcmp(op, "peek") == 0) {
        code = sshbuf_peek_string_direct(buf, want_value ? &direct : NULL,
            want_length ? &length : NULL);
        output = want_value ? direct : NULL;
        output_len = wire_len;
    } else if (strcmp(op, "direct") == 0) {
        code = sshbuf_get_string_direct(buf, want_value ? &direct : NULL,
            want_length ? &length : NULL);
        output = want_value ? direct : NULL;
        output_len = wire_len;
    } else if (strcmp(op, "string") == 0) {
        fail_malloc = !alloc_success;
        code = sshbuf_get_string(buf, want_value ? &allocated : NULL,
            want_length ? &length : NULL);
        fail_malloc = 0;
        output = want_value ? allocated : NULL;
        output_len = wire_len + 1;
        is_copied = 1;
    } else if (strcmp(op, "cstring") == 0) {
        char *cstring = (char *)sentinel;
        fail_malloc = !alloc_success;
        code = sshbuf_get_cstring(buf, want_value ? &cstring : NULL,
            want_length ? &length : NULL);
        fail_malloc = 0;
        allocated = (unsigned char *)cstring;
        output = want_value ? allocated : NULL;
        output_len = wire_len + 1;
        is_copied = 1;
    } else {
        goto invalid;
    }

    printf("%d ", code);
    print_hex(sshbuf_ptr(buf), sshbuf_len(buf));
    putchar(' ');
    if (is_integer) {
        if (has_previous) printf("%" PRIu64, numeric);
        else putchar('-');
    } else if (output == NULL) {
        putchar('-');
    } else if (output == sentinel) {
        /* Exposes an unexpected failure to initialize without dereferencing it. */
        fputs("sentinel", stdout);
    } else {
        print_hex(output, output_len);
    }
    putchar(' ');
    if (is_integer || !want_length) putchar('-');
    else printf("%zu", length);
    putchar('\n');

    if (is_copied && allocated != NULL && allocated != sentinel)
        free(allocated);
    sshbuf_free(buf);
    free(input);
    return ferror(stdout) ? -1 : 0;

invalid:
    fail_malloc = 0;
    sshbuf_free(buf);
    free(input);
    return -1;
}

int
main(void)
{
    char *line = NULL, *saveptr, *token, *parts[6];
    size_t capacity = 0, row = 0;
    ssize_t n;
    int count;
    while ((n = getline(&line, &capacity, stdin)) >= 0) {
        (void)n;
        row++;
        count = 0;
        saveptr = NULL;
        for (token = strtok_r(line, " \t\r\n", &saveptr); token != NULL;
             token = strtok_r(NULL, " \t\r\n", &saveptr)) {
            if (count == 6) break;
            parts[count++] = token;
        }
        if (count != 6 || token != NULL || run_row(parts) != 0) {
            fprintf(stderr, "Invalid or failed oracle input at row %zu\n", row);
            free(line);
            return 2;
        }
    }
    free(line);
    if (ferror(stdin)) {
        fputs("Oracle stdin read failed\n", stderr);
        return 2;
    }
    return fflush(stdout) == 0 ? 0 : 2;
}
