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

//suffix can be .pem / .crt / .cer / .key
#define PUB_PATH "pubkey.key"
#define PRIV_PATH "privkey.key"

static const unsigned char msg[] = "This is the original msg";

int main(int argc, char **argv){
    myopenssl_d *mp_enc;
    myopenssl_d *mp_dec;
    b64_t *b64_enc;
    b64_t *b64_dec;

    printf("Origin msg (sizeof = %ld)(length = %ld):\n%s\n", sizeof(msg), strlen(msg), msg);

    //genkey
    if(myopenssl_genkey_f(PUB_PATH, PRIV_PATH) <= 0){
        printf("myopenssl_genkey_f() failed\n");
        return -1;
    }
    printf("Pubkey save in %s\n", PUB_PATH);
    printf("Privekey save in %s\n", PRIV_PATH);

    //encrypt
    if((mp_enc = myopenssl_encrypt_f(PUB_PATH, msg, strlen(msg))) == NULL){
        printf("Encrypt failed\n");
        return -1;
    }
    printf("Encrypted data (length = %ld)(sizeof = %ld):\n%s\n", mp_enc->data_len, sizeof(mp_enc->data), mp_enc->data);

    //base64 encode, if you want do this with base64url, use b64url_encode
    if((b64_enc = b64_encode(mp_enc->data, mp_enc->data_len)) == NULL){
        printf("B64 decode failed\n");
        goto clean1;
    }
    printf("Encrypted data after base64 (length = %ld) =\n%s\n", b64_enc->data_len, b64_enc->data);

    //base64 decode, if you want do this with base64url, use b64url_decode
    if((b64_dec = b64_decode(b64_enc->data, b64_enc->data_len)) == NULL){
        printf("Base64 decode failed\n");
        goto clean2;
    }
    printf("After base64 decode (length = %ld) =\n%s\n", b64_dec->data_len, b64_dec->data);

    //decrypt
    if((mp_dec = myopenssl_decrypt_f(PRIV_PATH, b64_dec->data, b64_dec->data_len)) == NULL){
        printf("Decrypt failed\n");
        goto clean3;
    }
    printf("Decrypted data:\n%s\n", mp_dec->data);

    if(strcmp(msg, mp_dec->data) == 0) printf("Original msg = decrypted msg\n");
    else{
        printf("Original msg != decrypted msg\n");
        goto clean4;
    }

    //make PKCS#8 format key
    if(myopenssl_pkcs8_f("pubkey.key", 1, "pub8.key") <= 0){
        printf("PKCS8 failed\n");
        goto clean4;
    }
    if(myopenssl_pkcs8_f("privkey.key", 0, "priv8.key") <= 0){
        printf("PKCS8 failed\n");
        goto clean4;
    }

    //remember free the encrypt/decrypt output after used
    printf("All finish\n");

    clean4:
    b64_free(b64_dec);
    clean3:
    myopenssl_d_free(mp_dec);
    clean2:
    b64_free(b64_enc);
    clean1:
    myopenssl_d_free(mp_enc);
    return 0;
}