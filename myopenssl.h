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
 * If inpit & output are file format, use the function without suffix.
 * If input & output are string format, use the function with "str" suffix.
*/

/**
 * Make EVP_PKEY to PEM format file
 * @param pkey <in> EVP_PKEY
 * @param f <in> where to save key
 * @param selection <in> EVP_PKEY_PUBLIC_KEY or EVP_PKEY_KEYPAIR
 * @returns 1 (successes) or 0
*/
static int key_encode(EVP_PKEY *pkey, FILE *f, const int selection);
/**
 * Create RSA public & private key in PEM format file
 * @param pubkey_file <in> where to save public key
 * @param privkey_file <in> where to save private key
 * @returns 1 (successes) or 0
*/
int genkey(const char *pubkey_file, const char *privkey_file);
/**
 * Make PEM key file to EVP_PKEY
 * @param libctx <in> OSSL_LIB_CTX
 * @param keyfile <in> where is the key
 * @param public <in> public key or not, 1 or 0
 * @retval EVP_PKEY
*/
static EVP_PKEY *load_key(OSSL_LIB_CTX *libctx, const char *keyfile, const int selection);
/**
 * Encrypt input
 * @param keyfile <in> where is the public key
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out <out> output, binary
 * @param out_len <out> output length
 * @returns 1 (seccedsses) or 0
*/
int do_encrypt(const char *keyfile, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len);
/**
 * Decrypt
 * @param keyfile <in> where is the private key
 * @param in <in> input, binary
 * @param in_len <in> input length
 * @param out <out> output string
 * @param out_len <out> output length
 * @returns 1 (successes) or 0
*/
int do_decrypt(const char *keyfile, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len);
/**
 * Create a PKCS#8 PEM key form PKCS#1 PEM key
 * @param infile <in> where is the PKCS#1 PEM key file
 * @param public <in> pubkey or privkey, 1 or 0
 * @param outfile <out> where to save the PKCS#8 PEM key
 * @returns 1 (successes) or 0
*/
int pkcs8_maker(const char *infile, const int public, const char *outfile);

/**
 * Make EVP_PKEY to PEM format string
 * @param pkey <in> EVP_PKEY
 * @param out <out> string, pubkey or privkey
 * @param out_len <out> output length
 * @param selection <in> EVP_PKEY_PUBLIC_KEY or EVP_PKEY_KEYPAIR
 * @returns 1 (successes) or 0
*/
static int key_encode_str(EVP_PKEY *pkey, unsigned char **out, size_t *out_len, const int selection);
/**
 * Create RSA public & private key in PEM format string
 * @param pubout <out> pubkey string
 * @param pubout_len <out> pubkey length
 * @param privout <out> privkey string
 * @param privout_len <out> privkey length
 * @returns 1 (successes) or 0
*/
int genkey_str(unsigned char **pubout, size_t *pubout_len, unsigned char **privout, size_t *privout_len);
/**
 * Make PEM format string to EVP_PKEY
 * @param libctx <in> OSSL_LIB_CTX
 * @param key <in> the pubkey or privkey you want to use
 * @param ken_len <in> key length
 * @param selection <in> EVP_PKEY_PUBLIC_KEY or EVP_PKEY_KEYPAIR
 * @retval EVP_PKEY
*/
static EVP_PKEY *load_key_str(OSSL_LIB_CTX *libctx, const unsigned char *key, const size_t key_len, const int selection);
/**
 * Encrypt input
 * @param pubkey <in> pubkey string
 * @param in <in> input string
 * @param in_len <in> input length
 * @param out <out> output, binary
 * @param out_len <out> output length
 * @returns 1 (seccedsses) or 0
*/
int do_encrypt_str(const unsigned char *pubkey, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len);
/**
 * Decrypt
 * @param privkey <in> privkey string
 * @param in <in> input ,binary
 * @param in_len <in> input length
 * @param out <out> output string
 * @param out_len <out> output length
 * @returns 1 (successes) or 0
*/
int do_decrypt_str(const unsigned char *privkey, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len);
/**
 * Create a PKCS#8 PEM key string form PKCS#1 PEM key string
 * @param in <in> PKCS#1 PEM key string
 * @param public <in> pubkey or privkey, 1 or 0
 * @param out <out> PKCS#8 PEM key string
 * @param out_len <out> output length
 * @returns 1 (successes) or 0
*/
int pkcs8_maker_str(const unsigned char *in, const int public, unsigned char **out, size_t *out_len);
#endif