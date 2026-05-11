/*
    scanner.c - Implementarea unui scanner de fisiere care utilizeaza expresii regulate pentru a detecta posibile amenintari in continutul fisierelor. 
    Acest modul este responsabil pentru scanea fisierelor folosind libraria pcre2
    Aceasta librarie permite definirea unor pattern-uri si cautarea acestora intr-un singur pass.


    Acest modul se ocupa cu gasirea malware de tip vbs, script, powershell etc

*/




#define PCRE2_CODE_UNIT_WIDTH 8

#include "headers/scanner.h"
#include "headers/base64.h"
#include <pcre2.h> // Necesar pentru a folosi functiile si structurile din libraria PCRE2, care este utilizata pentru a compila si a executa expresii regulate in procesul de scanare a fisierelor, permitand detectarea unor pattern-uri specifice care ar putea indica prezenta unor amenintari sau comportamente malitioase in continutul fisierelor scanate.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

// Consntante necesare
#ifndef SCANNER_LENGTH
#define SCANNER_LENGTH      256
#endif


// cel mult 65535 bytes / chunk
// Permitem overlap-uri in cazuri in care e encoded (si sunt in chunk-uri separate)
#define CHUNK_SIZE          (64  * 1024)
#define OVERLAP_SIZE        (1024)
#define MAX_FULL_LOAD       (10  * 1024 * 1024)
#define B64_DECODED_SIZE(n) (((n) / 4 + 1) * 3)

// MAX 1MB de stringuri, pentru a evita consumul excesiv de memorie in cazuri in care sunt multe stringuri mari in fisierele scanate
#define MAX_STR_LEN         1048576
#define MIN_B64             16

// Functia pentru a scana un buffer de date
static int scan_buffer(Scanner *s, const unsigned char *buf, size_t len,
                       const char *pass_label, int dst) {
    if (!buf || len == 0) return SCAN_NO_MATCH;

    pcre2_match_data *match_data = pcre2_match_data_create(1, NULL);
    if (!match_data) return SCAN_ERROR;

    int found = SCAN_NO_MATCH;

    for (size_t i = 0; i < s->count; i++) { // iteram prin fiecare pattern
        pcre2_code *re = (pcre2_code *)s->patterns[i].compiled;

        // Facem efectiv matching-ul
        int rc = pcre2_match( 
            re,
            (PCRE2_SPTR)buf,
            len,
            0, 0,
            match_data,
            NULL
        );

        if (rc >= 0) { // Daca e gasit il scriem in destinatie
            char msg[SCANNER_LENGTH];
            (void)snprintf(msg, sizeof(msg),
                           "(%s) Possible threat detected: category=%-24s pattern=%-40s\n",
                           pass_label,
                           s->patterns[i].category,
                           s->patterns[i].pattern);
            if(write(dst, msg, strlen(msg)) < 0) {
                perror("[scanner] write");
            }
            found = SCAN_MATCH;
        }
    }

    pcre2_match_data_free(match_data); // Eliberam memoria
    return found;
}
// Scarea chunked
static int scan_fd_chunked(Scanner *s, int fd, const char *pass_label, int dst) {
    size_t         buf_size = CHUNK_SIZE + OVERLAP_SIZE;
    unsigned char *buf      = malloc(buf_size);
    if (!buf) return SCAN_ERROR;

    int    found   = SCAN_NO_MATCH;
    size_t overlap = 0;

    while (1) {
        size_t  to_read = CHUNK_SIZE;
        size_t  total   = overlap;

        while (to_read > 0) {
            ssize_t n = read(fd, buf + total, to_read);
            if (n < 0) {
                perror("[scanner] read");
                free(buf);
                return SCAN_ERROR;
            }
            if (n == 0) goto eof_raw;
            total   += (size_t)n;
            to_read -= (size_t)n;
        }

eof_raw:
        if (total == overlap) break;

        int rc = scan_buffer(s, buf, total, pass_label, dst);
        if (rc == SCAN_MATCH) found = SCAN_MATCH;

        overlap = (total > OVERLAP_SIZE) ? OVERLAP_SIZE : total;
        memmove(buf, buf + total - overlap, overlap);

        if (total < CHUNK_SIZE + overlap) break;
    }

    free(buf);
    return found;
}
static int scan_decoded_chunked(Scanner *s, int fd,
                                const char *pass_label, int dst) {
    int found = SCAN_NO_MATCH;

    // Acumulatorul pentru tokenuri base64
    char   *acc     = malloc(MAX_STR_LEN + 1);
    int     acc_len = 0;

    // Buffer de output pentru decode
    size_t  dec_size = B64_DECODED_SIZE(MAX_STR_LEN);
    unsigned char *decoded = malloc(dec_size);

    if (!acc || !decoded) {
        free(acc); free(decoded);
        return SCAN_ERROR;
    }

    // ── helper: flush acumulatorul curent(macro) ──────────────────────────────────
    #define FLUSH_ACC() do {                                                  \
        if (acc_len >= MIN_B64) {                                             \
            int valid_len = (acc_len / B64_GROUP_SIZE) * B64_GROUP_SIZE;      \
            if (valid_len >= MIN_B64) {                                       \
                /* adauga padding daca lipseste */                            \
                int pad = (4 - (valid_len % 4)) % 4;                         \
                for (int _p = 0; _p < pad; _p++)                             \
                    acc[valid_len + _p] = '=';                               \
                valid_len += pad;                                             \
                                                                              \
                int dec_len = base64_decode(acc, valid_len, decoded, dec_size);\
                if (dec_len > 0) {                                            \
                    int rc = scan_buffer(s, decoded, (size_t)dec_len,        \
                                        pass_label, dst);                    \
                    if (rc == SCAN_MATCH) found = SCAN_MATCH;                \
                }                                                             \
            }                                                                 \
        }                                                                     \
        acc_len = 0;                                                          \
    } while(0)
    // ───────────────────────────────────────────────────────────────────────

    unsigned char buf[CHUNK_SIZE + OVERLAP_SIZE];
    size_t overlap = 0;

    while (1) {
        size_t  to_read = CHUNK_SIZE;
        size_t  total   = overlap;

        // Citeste un chunk complet
        while (to_read > 0) {
            ssize_t n = read(fd, buf + total, to_read);
            if (n < 0) {
                perror("[scanner] read decoded_chunked");
                free(acc); free(decoded);
                return SCAN_ERROR;
            }
            if (n == 0) goto eof_dec;
            total   += (size_t)n;
            to_read -= (size_t)n;
        }

eof_dec:
        if (total == overlap) break;

        // Parcurge byte cu byte, acumuleaza tokenuri base64
        for (size_t i = overlap; i < total; i++) {
            char c = (char)buf[i];

            if (is_b64(c) && c != '=') {
                if (acc_len < MAX_STR_LEN)
                    acc[acc_len++] = c;
            } else {
                FLUSH_ACC();
            }
        }

        // Overlap: pastreaza ultimii OVERLAP_SIZE bytes pentru urmatorul chunk
        // ca sa nu taiem un token base64 la granita dintre chunk-uri
        overlap = (total > OVERLAP_SIZE) ? OVERLAP_SIZE : total;
        memmove(buf, buf + total - overlap, overlap);

        // Reseteaza acumulatorul doar pentru bytes NON-overlap
        // (overlap-ul il vom re-procesa in iteratia urmatoare)

        if (total < CHUNK_SIZE + overlap) break;
    }

    // Flush final pentru ce a ramas in acumulator
    FLUSH_ACC();

    #undef FLUSH_ACC

    free(acc);
    free(decoded);
    return found;
}
// Initializarea si distrugerea unui scanner
Scanner *scanner_create(void) {
    Scanner *s = calloc(1, sizeof(Scanner));
    return s;
}

void scanner_destroy(Scanner *s) {
    if (!s) return;
    for (size_t i = 0; i < s->count; i++) {
        pcre2_code_free((pcre2_code *)s->patterns[i].compiled);
    }
    free(s);
}


// Functie pentru adaugarea unui pattern in scanner
int scanner_add_pattern(Scanner *s, const char *pattern, const char *category) {
    if (!s || !pattern || !category)      return SCAN_ERROR;
    if (s->count >= SCANNER_MAX_PATTERNS) return SCAN_ERROR;

    int        error_code;
    PCRE2_SIZE error_offset;

    pcre2_code *re = pcre2_compile(
        (PCRE2_SPTR)pattern,
        PCRE2_ZERO_TERMINATED,
        PCRE2_CASELESS,
        &error_code,
        &error_offset,
        NULL
    );

    if (!re) {
        PCRE2_UCHAR err_buf[SCANNER_LENGTH];
        pcre2_get_error_message(error_code, err_buf, sizeof(err_buf));
        (void)fprintf(stderr, "[scanner] compile error at offset %zu: %s\n",
                      error_offset, (char *)err_buf);
        return SCAN_ERROR;
    }

    ScanPattern *p = &s->patterns[s->count++];
    strncpy(p->category, category, SCANNER_CATEGORY_LEN - 1);
    strncpy(p->pattern,  pattern,  SCANNER_PATTERN_LEN  - 1);
    p->category[SCANNER_CATEGORY_LEN - 1] = '\0';
    p->pattern[SCANNER_PATTERN_LEN   - 1] = '\0';
    p->compiled = re;

    return SCAN_NO_MATCH;
}


// Functia public pentru a scana un fisier.
int scanner_scan_file_raw(Scanner *s, const char *filepath, int dst) {
    if (!s || !filepath) return SCAN_ERROR;

    int found = SCAN_NO_MATCH;
    int rc;

    int fd = open(filepath, O_RDONLY);
    if (fd >= 0) {
            
        rc = scan_fd_chunked(s, fd, "RAW", dst);
        if (rc == SCAN_MATCH) found = SCAN_MATCH;
        close(fd);
    }

    return found;
}
int scanner_scan_file_decoded(Scanner *s, const char *filepath, int dst) {
    if (!s || !filepath) return SCAN_ERROR;

    int found = SCAN_NO_MATCH;
    int rc;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("[scanner] open pass1");
        return SCAN_ERROR;
    }


    fd = open(filepath, O_RDONLY);
    if (fd >= 0) {
        rc = scan_decoded_chunked(s, fd, "DECODED", dst);
        if (rc == SCAN_MATCH) found = SCAN_MATCH;
        close(fd);
    }

    return found;
}
