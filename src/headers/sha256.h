#ifndef SHA256_H
#define SHA256_H
#include <openssl/sha.h>

#ifndef HEX_LENGTH
#define HEX_LENGTH 64
#endif
#define SHA256_BUFFSIZE 65535
int sha256_file(const char *path, unsigned char out[HEX_LENGTH/2]);
int sha256_hash_to_byte(const char *source, unsigned char out[HEX_LENGTH/2]);
void sha256_hash(const char *text, char *output_hex);
int compute_signature(const char *filename, char *out_hash);
#endif


