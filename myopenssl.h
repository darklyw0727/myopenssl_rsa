#include <openssl/evp.h>

#ifndef _MYOPENSSL_H
#define _MYOPENSSL_H

#ifdef _OPENSSL_DEBUG
#define OPENSSL_DEBUG(format, args...) printf("[%s:%s:%d] "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define OPENSSL_DEBUG(args...)
#endif

/**
 * Base on openssl 1.1.1
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
 * @returns NULL (error) or myopenssl_k that include pubkey and privkey string
*/
myopenssl_k *myopenssl_genkey();
/**
 * Encrypt input, return the result
 * @param pubkey <in> pubkey string
 * @param key_len <in> pubkey length
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out_len <out> output data length, this is a int pointer
 * @returns NULL (error) or encrypt result
*/
unsigned char *myopenssl_encrypt(char *pubkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len);
/**
 * Decrypt input, return the result
 * @param pubkey <in> privkey string
 * @param key_len <in> privkey length
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out_len <out> output data length, this is a int pointer
 * @returns NULL (error) or decrypt result
*/
unsigned char *myopenssl_decrypt(char *pubkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len);

/**
 * Create RSA public & private key in PEM format file
 * @param pubkey_file <in> where to save public key
 * @param privkey_file <in> where to save private key
 * @returns -1 (error) or 0
*/
int myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file);
/**
 * Encrypt input, return the result
 * @param keyfile <in> where is the private key
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out_len <out> output data length, this is a int pointer
 * @returns NULL (error) or encrypt result
*/
unsigned char *myopenssl_encrypt_f(const char *keyfile, unsigned char *in, const size_t in_len, size_t *out_len);
/**
 * Decrypt input, return the result
 * @param keyfile <in> where is the private key
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out_len <out> output data length, this is a int pointer
 * @returns NULL (error) or decrypt result
*/
unsigned char *myopenssl_decrypt_f(const char *keyfile, unsigned char *in, const size_t in_len, size_t *out_len);
#endif