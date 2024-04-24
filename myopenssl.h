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
    unsigned char *pubkey;
    size_t publen;
    unsigned char *privkey;
    size_t privlen;
} myopenssl_k;

typedef struct myopenssl_data {
    unsigned char *data;
    size_t data_len;
} myopenssl_d;

void myopenssl_k_free(myopenssl_k *ptr);
void myopenssl_d_free(myopenssl_d *ptr);

/**
 * Create RSA public & private key in PEM format file
 * @param pubkey_file <in> where to save public key
 * @param privkey_file <in> where to save private key
 * @returns 1 (successes) or 0
*/
int myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file);
/**
 * Encrypt input
 * @param keyfile <in> where is the public key
 * @param in <in> input string
 * @param in_len <in> input length
 * @returns NULL (error) or myopenssl_d that include output string and length
*/
myopenssl_d *myopenssl_encrypt_f(const char *keyfile, const unsigned char *in, const size_t in_len);
/**
 * Decrypt input. Please decode input, if it is base64/base64url encoded
 * @param keyfile <in> where is the private key
 * @param in <in> input string
 * @param in_len <in> input length
 * @returns NULL (error) or myopenssl_d that include output string and length
*/
myopenssl_d *myopenssl_decrypt_f(const char *keyfile, const unsigned char *in, const size_t in_len);
/**
 * Create a PKCS#8 PEM key form PKCS#1 PEM key
 * @param infile <in> where is the PKCS#1 PEM key file
 * @param public <in> pubkey or privkey, 1 or 0
 * @param outfile <out> where to save the PKCS#8 PEM key
 * @returns 1 (successes) or 0
*/
int myopenssl_pkcs8_f(const char *infile, const int public, const char *outfile);

/**
 * Create RSA public & private key in PEM format string
 * @returns NULL (error) or myopenssl_k that include PKCS#1 pubkey ,privkey string and their length
*/
myopenssl_k *myopenssl_genkey();
/**
 * Encrypt input
 * @param pubkey <in> pubkey string
 * @param in <in> input string
 * @param in_len <in> input length
 * @returns NULL (error) or myopenssl_d that include output string and length
*/
myopenssl_d *myopenssl_encrypt(const unsigned char *pubkey, const unsigned char *in, const size_t in_len);
/**
 * Decrypt input. Please decode input, if it is base64/base64url encoded
 * @param privkey <in> privkey string
 * @param in <in> input string
 * @param in_len <in> input length
 * @returns NULL (error) or myopenssl_d that include output string and length
*/
myopenssl_d *myopenssl_decrypt(const unsigned char *privkey, const unsigned char *in, const size_t in_len);
/**
 * Create a PKCS#8 PEM key string form PKCS#1 PEM key string
 * @param in <in> PKCS#1 PEM key string
 * @param public <in> pubkey or privkey, 1 or 0
 * @returns NULL (error) or myopenssl_k that include PKCS#8 pubkey/privkey string and their length
*/
myopenssl_k *myopenssl_pkcs8(const unsigned char *in, const int public);
#endif