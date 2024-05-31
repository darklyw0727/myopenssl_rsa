#include <openssl/evp.h>

#ifndef _MYOPENSSL_H
#define _MYOPENSSL_H

#ifdef _OPENSSL_DEBUG
#define OPENSSL_DEBUG(format, args...) printf("[%s:%s:%d] "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define OPENSSL_DEBUG(args...)
#endif

/**
 * Base on openssl 3.0
 * If your key is a file, use the function with f suffix.
*/

typedef struct myopenssl_key {
    char *pubkey;
    char *privkey;
} myopenssl_k;

void myopenssl_free_k(myopenssl_k *ptr);
void myopenssl_free(unsigned char *in);

/**
 * Create RSA public & private key in PEM format string
 * @returns NULL (error) or myopenssl_k that include PKCS#1 pubkey ,privkey string and their length
*/
myopenssl_k *myopenssl_genkey();
/**
 * Encrypt input, make sure your output buffer is enough and clean
 * @param pubkey <in> pubkey string
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out <out> output data, make sure it is enough and clean
 * @returns 0 (error) or output length
*/
unsigned char *myopenssl_encrypt(char *pubkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len);
/**
 * Decrypt input, make sure your output buffer is enough and clean. Please decode input, if it is base64/base64url encoded
 * @param privkey <in> privkey string
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out <out> output data, make sure it is enough and clean
 * @returns 0 (error) or output length
*/
unsigned char *myopenssl_decrypt(char *pubkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len);

/**
 * Create RSA public & private key in PEM format file
 * @param pubkey_file <in> where to save public key
 * @param privkey_file <in> where to save private key
 * @returns 0 (successes) or -1
*/
int myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file);
/**
 * Encrypt input, make sure your output buffer is enough and clean
 * @param keyfile <in> where is the public key
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out <out> output data, make sure it is enough and clean
 * @returns 0 (error) or output length
*/
unsigned char *myopenssl_encrypt_f(const char *keyfile, unsigned char *in, const size_t in_len, size_t *out_len);
/**
 * Decrypt input, make sure your output buffer is enough and clean. Please decode input, if it is base64/base64url encoded
 * @param keyfile <in> where is the private key
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out <out> output data, make sure it is enough and clean
 * @returns 0 (error) or output length
*/
unsigned char *myopenssl_decrypt_f(const char *keyfile, unsigned char *in, const size_t in_len, size_t *out_len);
#endif