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
#include "b64_crypt.h"

//suffix = .pem / .crt / .cer / .key
#define PUB_PATH "pubkey.key"
#define PRIV_PATH "privkey.key"

static const unsigned char msg[] = "This is the original msg";

int main(int argc, char **argv){
    unsigned char *encrypt_out;
    size_t encrypt_len = 0;
    unsigned char *decrypt_out;
    size_t decrypt_len = 0;
    unsigned char *b64_en;
    unsigned char *b64_de;
    size_t b64_de_len;

    printf("Origin msg (sizeof = %ld)(length = %ld):\n%s\n", sizeof(msg), strlen(msg), msg);

    //genkey
    if(genkey(PUB_PATH, PRIV_PATH) <= 0){
        printf("genkey() failed\n");
        return -1;
    }
    printf("Pubkey save in %s\n", PUB_PATH);
    printf("Privekey save in %s\n", PRIV_PATH);

    //encrypt
    if(do_encrypt(PUB_PATH, msg, strlen(msg), &encrypt_out, &encrypt_len) <= 0){
        printf("Encrypt failed\n");
        return -1;
    }
    printf("Encrypted data (length = %ld)(sizeof = %ld):\n%s\n", encrypt_len, sizeof(encrypt_out), encrypt_out);

    //base64 encode, if you want do this with base64url, use b64url_encode
    b64_en = b64_encode(encrypt_out, encrypt_len);
    printf("Encrypted data after base64 (length = %ld) =\n%s\n", strlen(b64_en), b64_en);

    //base64 decode, if you want do this with base64url, use b64url_decode
    if(b64_decode(b64_en, &b64_de, &b64_de_len) <= 0){
        printf("Base64 decode failed\n");
        free(encrypt_out);
        free(b64_en);
        return -1;
    }
    printf("After base64 decode (length = %ld) =\n%s\n", b64_de_len, b64_de);

    //decrypt
    if(do_decrypt(PRIV_PATH, b64_de, b64_de_len, &decrypt_out, &decrypt_len) <= 0){
        printf("Decrypt failed\n");
        free(encrypt_out);
        free(b64_en);
        free(b64_de);
        return -1;
    }
    printf("Decrypted data:\n%s\n", decrypt_out);

    if(strcmp(msg, decrypt_out) == 0) printf("Original msg = decrypted msg\n");
    else printf("Original msg != decrypted msg\n");

    //make PKCS#8 format key
    if(pkcs8_maker("pubkey.key", 1, "pub8.key") <= 0) printf("PKCS8 failed\n");
    if(pkcs8_maker("privkey.key", 0, "priv8.key") <= 0) printf("PKCS8 failed\n");

    //remember free the encrypt/decrypt output after used
    free(encrypt_out);
    free(decrypt_out);
    free(b64_en);
    free(b64_de);

    printf("All finish\n");
    return 0;
}