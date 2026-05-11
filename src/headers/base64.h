#ifndef BASE64_H
#define BASE64_H

#include <stddef.h>

#define BASE64_INVALID     ((unsigned char)64)
#define BASE64_PLUS_IDX    ((unsigned char)62)
#define BASE64_SLASH_IDX   ((unsigned char)63)
#define DIGIT_OFFSET       ((unsigned char)52)
#define UPPER_OFFSET       ((unsigned char)0)
#define LOWER_OFFSET       ((unsigned char)26)
#define LOWER_OFFSET_INT   26
#define B64_GROUP_SIZE     4
#define ENCODE_TABLE_SIZE  64
#define DECODE_TABLE_SIZE  256
#define PAD_CHAR           '='
#define LOW_2_BITS         0x03u
#define LOW_4_BITS         0x0Fu
#define LOW_6_BITS         0x3Fu
#define SHIFT_2            2
#define SHIFT_4            4
#define SHIFT_6            6

static inline const unsigned char *base64_decode_table(void) {
    static unsigned char table[DECODE_TABLE_SIZE];
    static int           initialized = 0;

    if (!initialized) {
        for (int i = 0; i < DECODE_TABLE_SIZE; i++) {
            table[i] = BASE64_INVALID;
        }
        table['+'] = BASE64_PLUS_IDX;
        table['/'] = BASE64_SLASH_IDX;
        for (int i = 0; i < SHIFT_6 + SHIFT_4; i++) { table['0' + i] = (unsigned char)(DIGIT_OFFSET + i); }
        for (int i = 0; i < LOWER_OFFSET_INT;  i++) { table['A' + i] = (unsigned char)(UPPER_OFFSET + i); }
        for (int i = 0; i < LOWER_OFFSET_INT;  i++) { table['a' + i] = (unsigned char)(LOWER_OFFSET + i); }
        initialized = 1;
    }
    return table;
}

static inline const unsigned char *base64_encode_table(void) {
    static const unsigned char table[ENCODE_TABLE_SIZE + 1] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    return table;
}

size_t base64_encode_len(size_t in_len);
int    base64_encode(const unsigned char *in, size_t in_len, unsigned char *out);
int    base64_decode(const char *in, size_t in_len, unsigned char *out, size_t out_size);
int    is_b64(char c);

#endif /* BASE64_H */


