#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64_crypt.h"

static void replace_char(char *in, int ori_char, char *rep_char){
	char *ptr;
	char *buf = malloc(strlen(in)+1);

	while((ptr = strchr(in, ori_char)) != NULL){ //Find the char you want to replace
		B64_DEBUG("Origin string is : %s\n", in);
		B64_DEBUG("find target\n");
		memset(buf, 0, sizeof(buf));

		strncpy(buf, in, ptr - in); //Copy the chars befor target char to buffer
		buf[ptr - in] = '\0';
		B64_DEBUG("buf = %s\n", buf);

		strcat(buf, rep_char); //Cat the char you need buffer
		B64_DEBUG("buf = %s\n", buf);
		strcat(buf, ptr+1); //Skip the target char you find and copy rest chars to buffer
		B64_DEBUG("buf = %s\n", buf);

		strcpy(in, buf);//Replace input by buffer
		B64_DEBUG("buf = %s\n", buf);
		B64_DEBUG("String after repalce is : %s\n", in);
	}

	free(buf);
}

static size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	return ret;
}

//base64 char table
const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const unsigned char *in, size_t len)
{
    B64_DEBUG("---B64 encode---\n");
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	//Check input
	if (in == NULL || len == 0)
		return NULL;

	//Calculate the length after encode
	elen = b64_encoded_size(len);
	out  = malloc(elen+1);
	memset(out, 0, sizeof(out));

	//Encode
	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	out[elen] = '\0';

	return out;
}

char *b64url_encode(const unsigned char *in, size_t len)
{
    char *b64;
	char *out;
	char *ptr;

	//Base64 encode
	b64 = b64_encode(in, len);
	B64_DEBUG("b64url encode step1: %s\n", b64);

	//Delete "="
	if((ptr = strchr(b64, '=')) != NULL){
	    B64_DEBUG("find =\n");
		out = malloc(ptr - b64 + 1);
		memset(out, 0, strlen(out));
		strncpy(out, b64, ptr - b64);
		out[b64-ptr] = '\0';
	}
	B64_DEBUG("b64url encode step2: %s\n", out);

	//Turn to base64url fomat
	replace_char(out, '+', "-");
	replace_char(out, '/', "_");

	return out;
}

static size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
}

/**
 * ASCII table from "+" to "z", number means the location in base64 table,
 * "-1" means base64 doesn't support that char
*/
const int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
	59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
	6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
	29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50, 51 };

static int b64_checkchar(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '+' || c == '/' || c == '=')
		return 1;
	return 0;
}

static int b64url_checkchar(char c)
{
	if (c >= '0' && c <= '9')
		return 1;
	if (c >= 'A' && c <= 'Z')
		return 1;
	if (c >= 'a' && c <= 'z')
		return 1;
	if (c == '-' || c == '_')
		return 1;
	return 0;
}

int b64_decode(const char *in, unsigned char **out, size_t *outlen)
{
    B64_DEBUG("---B64 decode---\n");
	size_t in_len;
    size_t out_len_b64;
    unsigned char *out_b64 = NULL;
	size_t i;
	size_t j;
	int    v;

	//Check input length
	if(in == NULL) return 0;
	in_len = strlen(in);
	if(in_len % 4 != 0) return 0;

	//Check input fomat
	for (i=0; i<in_len; i++) {
		if (!b64_checkchar(in[i])) {
			return 0;
		}
	}

	//Calculate the length after decode
    out_len_b64 = b64_decoded_size(in);
	out_b64 = malloc(out_len_b64+1);
	memset(out_b64, 0, sizeof(out_b64));

	//Decode
	for (i=0, j=0; i<in_len; i+=4, j+=3) {
		v = b64invs[in[i]-43];
		v = (v << 6) | b64invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

		out_b64[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			out_b64[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			out_b64[j+2] = v & 0xFF;
	}

	out_b64[out_len_b64] = '\0';

    *out = out_b64;
    *outlen = out_len_b64;

	return 1;
}

int b64url_decode(const char *in, unsigned char **out, size_t *outlen)
{
	char *ptr;
	char *url;
	int ret = 0;
	size_t in_len;
	unsigned char *b64_out;
	size_t b64_outlen;

	//Check input is base64url fomat
	for(int a = 0; a < strlen(in); a++){
		if(b64url_checkchar(in[a]) <= 0) return ret;
	}

	//Copy input
	url = malloc(strlen(in)+1);
	memset(url, 0, sizeof(url));
	strncpy(url, in, strlen(in));
	url[strlen(in)] = '\0';

	//Turn to base64 fomat
	replace_char(url, '_', "/");
	replace_char(url, '-', "+");

	in_len = strlen(url);
	if((in_len % 4) == 2) strcat(url, "==");
	else if((in_len %4) == 3) strcat(url, "=");

	//Base64 decode
    if(b64_decode(url, &b64_out, &b64_outlen) <= 0) return ret;

	*out = b64_out;
	*outlen = b64_outlen;
	ret = 1;
	free(url);
	return ret;
}