#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "myopenssl.h"
#include "b64_codec.h"

//suffix can be .pem / .crt / .cer / .key
#define PUB_PATH "pubkey.key"
#define PRIV_PATH "privkey.key"

static const unsigned char msg[] = "This is the original msg";

int main(int argc, char **argv){
    //you need 256 bytes memory space for encrypt/decrypt output
    unsigned char enc[256];
    unsigned char dec[256];
    size_t enc_len, dec_len;

    printf("Origin msg (sizeof = %ld)(length = %ld):\n%s\n", sizeof(msg), strlen(msg), msg);

    //genkey
    if(myopenssl_genkey_f(PUB_PATH, PRIV_PATH) <= 0){
        printf("myopenssl_genkey_f() failed\n");
        return -1;
    }
    printf("Pubkey save in %s\n", PUB_PATH);
    printf("Privekey save in %s\n", PRIV_PATH);

    //encrypt
    memset(enc, 0, sizeof(enc));
    if((enc_len = myopenssl_encrypt_f(PUB_PATH, msg, strlen(msg), enc)) == 0){
        printf("Encrypt failed\n");
        return -1;
    }
    printf("Encrypted data (length = %ld)(sizeof = %ld):\n%s\n\n", enc_len, sizeof(enc), enc);

    //base64 encode, if you want do this with base64url, use b64url_encode
    size_t b64e_len = b64_encoded_size(enc_len);
    char *b64e = malloc(b64e_len+1);
    if(b64e == NULL){
        printf("Base64 encode malloc failed\n");
        return -1;
    }
    memset(b64e, 0, b64e_len+1);

    if((b64e_len = b64_encode(enc, enc_len, b64e)) == 0){
        printf("B64 encode failed\n");
        free(b64e);
        return -1;
    }
    printf("Encrypted data after base64 (length = %ld) =\n%s\n\n", b64e_len, b64e);

    //base64 decode, if you want do this with base64url, use b64url_decode
    size_t b64d_len = b64_decoded_size(b64e);
    unsigned char *b64d = malloc(b64d_len+1);
    if(b64d == NULL){
        printf("Base64 decode malloc failed\n");
        free(b64e);
        return -1;
    }
    memset(b64d, 0, b64d_len+1);

    if((b64d_len = b64_decode(b64e, b64d)) == 0){
        printf("Base64 decode failed\n");
        free(b64e);
        free(b64d);
        return -1;
    }
    printf("After base64 decode (length = %ld) =\n%s\n", b64d_len, b64d);
    free(b64e);

    //decrypt
    memset(dec, 0, sizeof(dec));
    if((dec_len = myopenssl_decrypt_f(PRIV_PATH, b64d, b64d_len, dec)) == 0){
        printf("Decrypt failed\n");
        free(b64d);
        return -1;
    }
    printf("Decrypted data (length = %ld) (sizeof = %ld) :\n%s\n", dec_len, sizeof(dec), dec);
    free(b64d);

    int a = strcmp(msg, dec);
    printf("Decrypted msg %s Origin msg\n", (a==0)?"==":"!=");
    if(a != 0) return -1;

    //make PKCS#8 format key
    if(myopenssl_pkcs8_f("pubkey.key", 1, "pub8.key") <= 0){
        printf("PKCS8 failed\n");
        return -1;
    }
    if(myopenssl_pkcs8_f("privkey.key", 0, "priv8.key") <= 0){
        printf("PKCS8 failed\n");
        return -1;
    }

    printf("All finish\n");
    return 0;
}