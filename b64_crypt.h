#include <stdio.h>

#ifndef _B64_CRYPT_H
#define _B64_CRYPT_H

#ifdef _B64_DEBUG
#define B64_DEBUG(format, args...) printf("[%s:%s:%d] "format, __FILE__, __FUNCTION__, __LINE__, ##args)
#else
#define B64_DEBUG(args...)
#endif

typedef struct b64{
    unsigned char *data;
    size_t data_len;
} b64_t;

void b64_free(b64_t *ptr);

/**
 * Make input string to base64 format
 * @param in <in> input string
 * @param len <in> input length
 * @returns NULL (error) or b64_t that include output string and length
*/
b64_t *b64_encode(const unsigned char *in, size_t len);
/**
 * Make input string to base64url format
 * @param in <in> input string
 * @param len <in> input length
 * @returns NULL (error) or the b64_t include output string and length
*/
b64_t *b64url_encode(const unsigned char *in, size_t len);

/**
 * Make base64 string to normal (origin) string
 * @param in <in> input string in base64 format
 * @param len <in> input length
 * @returns NULL (error) or the b64_t include output string and length
*/
b64_t *b64_decode(const char *in);
/**
 * Make base64url char string to normal (origin) string
 * @param in <in> input string in base64 format
 * @param len <in> input length
 * @returns NULL (error) or the b64_t include output string and length
*/
b64_t *b64url_decode(const char *in);
#endif