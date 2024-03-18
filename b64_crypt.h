#include <stdio.h>

#ifndef _B64_CRYPT_H
#define _B64_CRYPT_H

#ifdef _B64_DEBUG
#define B64_DEBUG(fomat, args...) printf("[%s:%s:%d] "fomat, __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define B64_DEBUG(args...)
#endif

/**
 * Repalce all char A in string to char B
 * @param in <in+out> input string, will be replaced step by step
 * @param ori_char <in> the char you want to replace, use ' ' not " "
 * @param rep_char <in> the char you need in output, use " "
*/
static void replace_char(char *in, int ori_char, char *rep_char);

/**
 * Count the length after base64 encode
 * @param inlen <in> input length
 * @retval The length of input char in base64 fomat
*/
static size_t b64_encoded_size(size_t inlen);
/**
 * Make binary char to base64 fomat
 * @param in <in> input binary char
 * @param len <in> input length
 * @retval Input char in base64 fomat
*/
char *b64_encode(const unsigned char *in, size_t len);
/**
 * Make binary char to base64url fomat
 * @param in <in> input binary char
 * @param len <in> input length
 * @retval Input char in base64url fomat
*/
char *b64url_encode(const unsigned char *in, size_t len);

/**
 * Count the length after base64 decode
 * @param in <in> input length
 * @retval The length of input char in binary fomat
*/
static size_t b64_decoded_size(const char *in);
/**
 * Check the input char is in base64 table or not
 * @param c <in> input char
 * @returns 1 (in table) or 0
*/
static int b64_checkchar(char c);
/**
 * Make base64 input char to binary
 * @param in <in> input char in base64 fomat
 * @param out <out> output char in binary
 * @param outlen <out> output length
 * @returns 1 (successes) or 0
*/
int b64_decode(const char *in, unsigned char **out, size_t *outlen);
/**
 * Check the input char is in base64url table or not
 * @param c <in> input char
 * @returns 1 (in table) or 0
*/
static int b64url_checkchar(char c);
/**
 * Make base64url input char to binary
 * @param in <in> input char in base64 fomat
 * @param out <out> output char in binary
 * @param outlen <out> output length
 * @returns 1 (successes) or 0
*/
int b64url_decode(const char *in, unsigned char **out, size_t *outlen);
#endif