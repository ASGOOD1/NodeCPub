/*
    * base64.c - Implementare pentru decodarea Base64.
    * Acest fisier nu este creat de mine insa nu mai stiu de unde l-am descarcat.
    * Functii:
    * - base64_encode_len: Calculeaza lungimea necesara pentru a codifica un sir de octeti in Base64.
    * - base64_decode: Decodeaza un sir de caractere Base64 intr-un buffer de octeti, returnand lungimea datelor decodate sau -1 in caz de eroare.
    * - is_b64: Verifica daca un caracter este valid in codarea Base64 (alfanumeric sau '+' sau '/' sau '=').
*/

#include "headers/base64.h"
#include <stddef.h> // Pentru size_t
#include <stdio.h>
#include <ctype.h> // Pentru isalnum

// Consntate pentru shift-ing si masti
#define TOP_6_MASK  0xFCu
#define MID_4_MASK  0xF0u
#define MID_2_MASK  0xC0u

// Formula pentru Base64
size_t base64_encode_len(size_t in_len) {
    return ((in_len + 2) / 3) * B64_GROUP_SIZE + 1;
}



// Functie care decodeaza un string in format Base64. Returneaza lungimea datelor decodate sau -1 in caz de eroare (de exemplu, daca inputul nu este valid sau daca output buffer-ul nu este suficient de mare).
int base64_decode(const char *in, size_t in_len, unsigned char *out, size_t out_size) {
    if (in_len % B64_GROUP_SIZE != 0) return -1;

    const unsigned char *table   = base64_decode_table();
    int                  out_len = 0;

    for (size_t i = 0; i < in_len; i += B64_GROUP_SIZE) {
        unsigned char a = table[(unsigned char)in[i]];
        unsigned char b = table[(unsigned char)in[i + 1]];
        unsigned char c = table[(unsigned char)in[i + 2]];
        unsigned char d = table[(unsigned char)in[i + 3]];

        if (a == BASE64_INVALID || b == BASE64_INVALID) return -1;

        if (i + B64_GROUP_SIZE < in_len && (in[i + 2] == '=' || in[i + 3] == '='))
            return -1;

        if (in[i + 2] == '=' && in[i + 3] != '=') return -1;

        if ((size_t)out_len + 1 > out_size) return -1;
        out[out_len++] = (unsigned char)((a << SHIFT_2) | (b >> SHIFT_4));

        if (in[i + 2] != '=') {
            if (c == BASE64_INVALID) return -1;
            if ((size_t)out_len + 1 > out_size) return -1;
            out[out_len++] = (unsigned char)(((b & LOW_4_BITS) << SHIFT_4) | (c >> SHIFT_2));
        }

        if (in[i + 3] != '=') {
            if (d == BASE64_INVALID) return -1;
            if ((size_t)out_len + 1 > out_size) return -1;
            out[out_len++] = (unsigned char)(((c & LOW_2_BITS) << SHIFT_6) | d);
        }
    }
    return out_len;
}

int is_b64(char c) {
    return (isalnum(c) || c == '+' || c == '/' || c == '=');
}


