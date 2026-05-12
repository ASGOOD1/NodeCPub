#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <string.h>
#include "headers/sha256.h"


int sha256_file(const char *path, unsigned char out[HEX_LENGTH/2]) {  // NOLINT it cant be pointer to const
    int f = open(path, O_RDONLY);
    if (f < 0) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    unsigned char buf[SHA256_BUFFSIZE];
    size_t n;
    while ((n = read(f, buf, sizeof(buf) - 1)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    unsigned int len;
    EVP_DigestFinal_ex(ctx, out, &len);

    EVP_MD_CTX_free(ctx);
    close(f);
    return 0;
}

int sha256_hash_to_byte(const char *text, unsigned char out[HEX_LENGTH/2]) { // NOLINT it cant be pointer to const
    unsigned int len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, text, strlen(text));
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    return 0;
}
void sha256_hash(const char *text, char *output_hex) {
    unsigned char bytes[HEX_LENGTH / 2];
    sha256_hash_to_byte(text, bytes);
    for (int i = 0; i < HEX_LENGTH / 2; i++) {
        (void)sprintf(output_hex + i * 2, "%02x", bytes[i]);
    }
    output_hex[HEX_LENGTH] = '\0';
}


#define CHUNK_SIZE 4096
int compute_signature(const char *filename, char *out_hash) {
    if (!out_hash) return -1;

    unsigned int len;
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return -1;

    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size < 0) {
        close(fd);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        close(fd);
        return -1;
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    uint64_t size_be = file_size;
    EVP_DigestUpdate(ctx, &size_be, sizeof(size_be));

    unsigned char buffer[CHUNK_SIZE];
    ssize_t bytes_read;

    if (file_size <= 3 * CHUNK_SIZE) {
        lseek(fd, 0, SEEK_SET);
        while ((bytes_read = read(fd, buffer, CHUNK_SIZE)) > 0) {
            EVP_DigestUpdate(ctx, buffer, bytes_read);
        }
        if (bytes_read < 0) goto error;
    } else {
        // start
        lseek(fd, 0, SEEK_SET);
        bytes_read = read(fd, buffer, CHUNK_SIZE);
        if (bytes_read < 0) goto error;
        if (bytes_read > 0) EVP_DigestUpdate(ctx, buffer, bytes_read);

        // middle
        off_t mid = (file_size - CHUNK_SIZE) / 2;
        lseek(fd, mid, SEEK_SET);
        bytes_read = read(fd, buffer, CHUNK_SIZE);
        if (bytes_read < 0) goto error;
        if (bytes_read > 0) EVP_DigestUpdate(ctx, buffer, bytes_read);

        // end
        lseek(fd, file_size - CHUNK_SIZE, SEEK_SET);
        bytes_read = read(fd, buffer, CHUNK_SIZE);
        if (bytes_read < 0) goto error;
        if (bytes_read > 0) EVP_DigestUpdate(ctx, buffer, bytes_read);
    }

    unsigned char final_hash[HEX_LENGTH/2];
    EVP_DigestFinal_ex(ctx, final_hash, &len);

    for (int i = 0; i < HEX_LENGTH/2; i++) {
        (void)snprintf(out_hash + i * 2, 3, "%02x", final_hash[i]);
    }
    out_hash[HEX_LENGTH] = '\0';

    EVP_MD_CTX_free(ctx);
    close(fd);
    return 0;

error:
    EVP_MD_CTX_free(ctx);
    close(fd);
    return -1;
}