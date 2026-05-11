#ifndef PE_SCANNER_H
#define PE_SCANNER_H

#include <stdint.h>
#include <stddef.h>

/* ── verdict levels ──────────────────────────────────────────── */

typedef enum {
    SCAN_UNKNOWN_FORMAT = -1,
    SCAN_LOW_RISK       =  0,
    SCAN_MODERATE_RISK  =  1,
    SCAN_HIGH_RISK      =  2,
} ScanVerdict;

/* ── result struct ───────────────────────────────────────────── */

typedef struct {
    ScanVerdict verdict;
    int         score;

    /* flags for what was found */
    int         inject_combo;     /* VirtualAlloc+WriteProcessMemory+CreateRemoteThread */
    int         inject_hits;
    int         antidebug_hits;
    int         network_hits;
    int         wx_sections;      /* writable+executable sections */
    int         ep_outside_text;  /* entry point not in .text */
    int         packer_sections;  /* UPX / .ndata / .aspack */
    int         high_entropy;     /* sections with entropy > 7.2 */

    /* format info */
    int         is_pe;
    int         is_pe32plus;
    const char *machine;          /* "x86", "x86-64", "ARM64", etc. */
    uint64_t    entry_point;
    int         num_sections;
} ScanResult;

/* ── public API ──────────────────────────────────────────────── */

/*
 * Scan a file at the given path.
 * Returns a ScanResult. Check result.verdict:
 *   SCAN_UNKNOWN_FORMAT  — not a PE 
 *   SCAN_LOW_RISK        — score < 4
 *   SCAN_MODERATE_RISK   — score 4-7
 *   SCAN_HIGH_RISK       — score >= 8
 *
 * Does NOT print anything. Use pe_scanner_print() for output.
 */
ScanResult pe_scanner_scan(const char *path);

/*
 * Print a human-readable report to stdout (using write(), no printf).
 */
void pe_scanner_print(const char *path, int dst, const ScanResult *result);

/*
 * Convenience: scan + print in one call.
 * Returns the verdict.
 */
ScanVerdict pe_scan_file(const char *path);

/*
 * Verdict as a string: "LOW RISK", "MODERATE RISK", "HIGH RISK", "UNKNOWN"
 */
const char *pe_scanner_verdict_str(ScanVerdict verdict);

#endif /* PE_SCANNER_H */


