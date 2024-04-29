#include <stdio.h>

#ifndef _B64_CRYPT_H
#define _B64_CRYPT_H

#ifdef _B64_DEBUG
#define B64_DEBUG(format, args...) printf("[%s:%s:%d] "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define B64_DEBUG(args...)
#endif

size_t b64_turn(const int url, const char *in, char *out);

/**
 * Calculate the data length after encode
 * @param inlen <in> your input length
 * @return the data length after encode
*/
size_t b64_encoded_size(size_t inlen);
/**
 * Calculate the data length after decode
 * @param in <in> your input string
 * @return the data length after decode
*/
size_t b64_decoded_size(const char *in);

/**
 * Make input string to base64 format
 * @param in <in> input string
 * @param len <in> input length
 * @param out <out> output string
 * @returns 0 (error) or the data length after base64 encode
*/
size_t b64_encode(const unsigned char *in, size_t len, char *out);
/**
 * Make base64 string to normal (origin) string
 * @param in <in> input string in base64 format
 * @param out <out> output string
 * @returns 0 (error) or the data length after base64 decode
*/
size_t b64_decode(const char *in, unsigned char *out);
#endif