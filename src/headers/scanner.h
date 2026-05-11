#ifndef SCANNER_H
#define SCANNER_H

#include <stddef.h>

#define SCANNER_MAX_PATTERNS  256
#define SCANNER_CATEGORY_LEN  64
#define SCANNER_PATTERN_LEN   256

#define SCAN_MATCH            0
#define SCAN_NO_MATCH         1
#define SCAN_ERROR           -1

typedef struct {
    char  category[SCANNER_CATEGORY_LEN];
    char  pattern[SCANNER_PATTERN_LEN];
    void *compiled;   /* pcre2_code* */
} ScanPattern;

typedef struct {
    ScanPattern patterns[SCANNER_MAX_PATTERNS];
    size_t      count;
} Scanner;

Scanner *scanner_create(void);
void     scanner_destroy(Scanner *s);
int      scanner_add_pattern(Scanner *s, const char *pattern, const char *category);
int      scanner_scan_file_raw(Scanner *s, const char *filepath, int dst);
int      scanner_scan_file_decoded(Scanner *s, const char *filepath, int dst);

#endif /* SCANNER_H */


