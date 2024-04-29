#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64_codec.h"

static void replace_char(char *in, int ori_char, int rep_char){
	char *ptr;

	while((ptr = strchr(in, ori_char)) != NULL){
		B64_DEBUG("Find Target, start repalce\n");
		in[ptr-in] = rep_char;
		B64_DEBUG("After repalce : \n%s\n", in);
	}
}

size_t b64_turn(const int url, const char *in, char *out){
	B64_DEBUG("--- b64_turn ---\n");
	size_t ret = 0;
	char *buf;
	size_t buf_len;
	size_t buf_size = strlen(in)+1;

	if((buf = malloc(buf_size)) == NULL){
		B64_DEBUG("Malloc failed\n");
		return ret;
	}
	memset(buf, 0, sizeof(buf));
	strncpy(buf, in, strlen(in));

	if(url == 0){ //b64url to b64
		B64_DEBUG("Base64 to base64URL\n");
		replace_char(buf, '-', '+');
		replace_char(buf, '_', '/');

		if((strlen(buf)%4) != 0){
			int a = 4-(strlen(buf)%4);
			while(a > 0){
				B64_DEBUG("Length % 4 != 0, strcat \"=\"\n");
				strcat(buf, "=");
				a--;
			}
		}
	}else{ //b64 to b64url
		B64_DEBUG("Base64URL to base64\n");
		char *ptr;

		replace_char(buf, '+', '-');
		replace_char(buf, '/', '_');

		if((ptr = strchr(buf, '=')) != NULL){
			B64_DEBUG("Find \"=\" remove it\n");
			memset(ptr, 0, buf+strlen(buf)-ptr);
		}
	}
	strncpy(out, buf, strlen(buf));

	free(buf);
	B64_DEBUG("--- b64_turn finish ---\n");
	return strlen(buf);
}

size_t b64_encoded_size(size_t inlen)
{
	size_t ret;

	B64_DEBUG("Input length = %d\n", inlen);
	ret = inlen;
	if (inlen % 3 != 0)
		ret += 3 - (inlen % 3);
	ret /= 3;
	ret *= 4;

	B64_DEBUG("Data length after encode = %d\n", ret);
	return ret;
}

//base64 char table
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encode(const unsigned char *in, size_t len, char *out)
{
    B64_DEBUG("---B64 encode---\n");
	size_t ret = 0;
	size_t  v;
	char *buf;
	size_t  buf_len;

	//Calculate the length after encode
	buf_len = b64_encoded_size(len);

	size_t buf_size = buf_len+1;
	if((buf = malloc(buf_size)) == NULL){
		B64_DEBUG("Malloc failed\n");
		return ret;
	}
	memset(buf, 0, buf_size);
	B64_DEBUG("Malloc %d bytes buffer\n", buf_size);

	//Encode
	for (int  i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		buf[j] = b64chars[(v >> 18) & 0x3F];
		buf[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			buf[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			buf[j+2] = '=';
		}
		if (i+2 < len) {
			buf[j+3] = b64chars[v & 0x3F];
		} else {
			buf[j+3] = '=';
		}
	}
	buf[buf_len] = '\0';
	strncpy(out, buf, buf_len);
	B64_DEBUG("B64 encode data buffer (length = %ld):\n%s\n", strlen(buf), buf);

	free(buf);
	ret = buf_len;
	B64_DEBUG("---B64 encode finish---\n");
	return ret;
}

size_t b64_decoded_size(const char *in)
{
	size_t len;
	size_t ret;

	B64_DEBUG("Input (length = %ld) : \n%s\n", strlen(in), in);
	len = strlen(in);

	ret = len / 4 * 3;

	for (int i=len-1; i >= 0; i--) {
		if (in[i] == '=') {
			B64_DEBUG("input[%d] = %d (=), length -1\n", i, in[i]);
			ret--;
		} else {
			break;
		}
	}

	B64_DEBUG("Data length after decode = %d\n", ret);
	return ret;
}

/**
 * ASCII table from "+" to "z", number means the location in base64 table,
 * "-1" means base64 doesn't support that char
*/
static const int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
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

size_t b64_decode(const char *in, unsigned char *out)
{
    B64_DEBUG("---B64 decode---\n");
	size_t ret = 0;
	int    v;
	size_t len = strlen(in);
	char *buf;
	size_t buf_len;

	//Check input length
	if(len % 4 != 0) return ret;

	//Check input fomat
	for (int i=0; i<len; i++) {
		if (!b64_checkchar(in[i])) {
			B64_DEBUG("b64_checkchar failed (char %d)\n", i);
			return ret;
		}
	}
	
	//Calculate the length after decode
	buf_len = b64_decoded_size(in);
	buf = malloc(buf_len+1);
	if(buf == NULL){
		B64_DEBUG("Malloc failed\n");
		return ret;
	}
	memset(buf, 0, buf_len+1);
	B64_DEBUG("Malloc %ld bytes buffer\n", buf_len+1);

	//Decode
	for (size_t i=0, j=0; i<len; i+=4, j+=3) {
		v = b64invs[in[i]-43];
		v = (v << 6) | b64invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

		buf[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			buf[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			buf[j+2] = v & 0xFF;
	}

	buf[buf_len] = '\0';
	B64_DEBUG("Buffer after decode : \n%s\n", buf);
	memcpy(out, buf, buf_len);
	free(buf);
	ret = buf_len;
	return ret;
}