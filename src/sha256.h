#ifndef SHA256_H
#define SHA256_H
typedef struct {
    unsigned int       h[8];
    unsigned long long len;
    unsigned char      buf[64];
    unsigned int       fill;
} SHA256_CTX;
void sha256_init(SHA256_CTX *c);
void sha256_update(SHA256_CTX *c, const void *data, unsigned int n);
void sha256_final(SHA256_CTX *c, unsigned char out[32]);
#endif
