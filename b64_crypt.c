#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "b64_crypt.h"

void b64_free(b64_t *ptr){
	if(ptr->data) free(ptr->data);
	free(ptr);
}

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
		//B64_DEBUG("buf = %s\n", buf);
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
static const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

b64_t *b64_encode(const unsigned char *in, size_t len)
{
    B64_DEBUG("---B64 encode---\n");
	b64_t *ret;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	//Check input
	if (in == NULL || len == 0)
		return NULL;

	//Calculate the length after encode
	elen = b64_encoded_size(len);

	ret = malloc(sizeof(b64_t));
	if(!ret){
		B64_DEBUG("Malloc failed\n");
		return NULL;
	}
	memset(ret, 0, sizeof(b64_t));
	ret->data = malloc(elen+1);
	if(!ret->data){
		B64_DEBUG("Malloc failed\n");
		b64_free(ret);
		return NULL;
	}
	memset(ret->data, 0, elen+1);

	//Encode
	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		ret->data[j] = b64chars[(v >> 18) & 0x3F];
		ret->data[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			ret->data[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			ret->data[j+2] = '=';
		}
		if (i+2 < len) {
			ret->data[j+3] = b64chars[v & 0x3F];
		} else {
			ret->data[j+3] = '=';
		}
	}
	ret->data[elen] = '\0';
	ret->data_len = strlen(ret->data);
	B64_DEBUG("B64 encode data (length = %ld):\n%s\n", ret->data_len, ret->data);
	B64_DEBUG("---B64 encode finish---\n");

	return ret;
}

b64_t *b64url_encode(const unsigned char *in, size_t len)
{
	b64_t *ret;
    b64_t *b64;
	unsigned char *ptr;
	char *buf;

	//Base64 encode
	ret = b64_encode(in, len);
	B64_DEBUG("b64url encode step1: %s\n", ret->data);

	//Delete "="
	if((ptr = strchr(ret->data, '=')) != NULL){
	    B64_DEBUG("find =\n");
		buf = malloc(ptr-(ret->data)+1);
		if(buf == NULL){
			B64_DEBUG("Malloc failed\n");
			b64_free(ret);
			return NULL;
		}
		memset(buf, 0, ptr-(ret->data)+1);

		strncpy(buf, ret->data, ptr-(ret->data));
		buf[ptr-(ret->data)] = '\0';
		
		free(ret->data);
		ret->data = buf;
		ret->data_len = strlen(ret->data);
	}
	B64_DEBUG("b64url encode step2: %s\n", ret->data);

	//Turn to base64url fomat
	replace_char(ret->data, '+', "-");
	replace_char(ret->data, '/', "_");

	return ret;
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
	B64_DEBUG("Read %s -> failed\n", c);
	return 0;
}

b64_t *b64_decode(const char *in)
{
    B64_DEBUG("---B64 decode---\n");
	b64_t *ret;
	size_t i;
	size_t j;
	int    v;
	size_t len = strlen(in);

	//Check input length
	if(in == NULL) return NULL;
	if(len % 4 != 0) return NULL;

	//Check input fomat
	for (i=0; i<len; i++) {
		if (!b64_checkchar(in[i])) {
			return NULL;
		}
	}

	ret = malloc(sizeof(b64_t));
	if(ret == NULL){
		B64_DEBUG("Malloc failed\n");
		return NULL;
	}
	memset(ret, 0, sizeof(b64_t));
	
	//Calculate the length after decode
	ret->data_len = b64_decoded_size(in);
	ret->data = malloc(ret->data_len+1);
	if(ret->data == NULL){
		B64_DEBUG("Malloc failed\n");
		b64_free(ret);
		return NULL;
	}
	memset(ret->data, 0, ret->data_len+1);

	//Decode
	for (i=0, j=0; i<len; i+=4, j+=3) {
		v = b64invs[in[i]-43];
		v = (v << 6) | b64invs[in[i+1]-43];
		v = in[i+2]=='=' ? v << 6 : (v << 6) | b64invs[in[i+2]-43];
		v = in[i+3]=='=' ? v << 6 : (v << 6) | b64invs[in[i+3]-43];

		ret->data[j] = (v >> 16) & 0xFF;
		if (in[i+2] != '=')
			ret->data[j+1] = (v >> 8) & 0xFF;
		if (in[i+3] != '=')
			ret->data[j+2] = v & 0xFF;
	}

	ret->data[ret->data_len] = '\0';

	return ret;
}

b64_t *b64url_decode(const char *in)
{
	b64_t *ret;
	size_t len;
	char *buf;
	size_t buf_len;

	len = strlen(in);

	//Check input is base64url fomat
	for(int a = 0; a < len; a++){
		if(b64url_checkchar(in[a]) <= 0){
			B64_DEBUG("b64url_checkchar() failed\n");
			return NULL;
		}
	}

	//Copy input
	buf = malloc(len+1);
	memset(buf, 0, len+1);
	strcpy(buf, in);

	//Turn to base64 fomat
	replace_char(buf, '_', "/");
	replace_char(buf, '-', "+");

	buf_len = strlen(buf);
	if((buf_len % 4) == 2) strcat(buf, "==");
	else if((buf_len %4) == 3) strcat(buf, "=");

	//Base64 decode
	ret = b64_decode(buf);
	
	free(buf);
	return ret;
}