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

//suffix can be .pem / .crt / .cer / .key
#define PUB_PATH "pubkey.key"
#define PRIV_PATH "privkey.key"

static const unsigned char msg[] = "This is the original msg";

int main(int argc, char **argv){
    myopenssl_k *mpk = NULL;
    unsigned char enc[256];
    unsigned char dec[256];
    size_t enc_len, dec_len;

    printf("Original input msg (length = %ld): %s\n\n", strlen((char *)msg), msg);

    //Use kye FILE
    if(myopenssl_genkey_f(PUB_PATH, PRIV_PATH) != 0){
        printf("myopenssl_genkey_f fail\n");
        goto end;
    }
    printf("Create key file done\n");

    if((enc_len = myopenssl_encrypt_f(PUB_PATH, msg, strlen((char *)msg), enc)) == 0){
        printf("enc with file failed\n");
        goto end;
    }
    printf("enc with file (length = %ld): ", enc_len);
    for(int a = 0; a < enc_len; a++){
        printf("%X ", enc[a]);
    }
    printf("\n");

    memset(dec, 0, sizeof(dec));
    if((dec_len = myopenssl_decrypt_f(PRIV_PATH, enc, enc_len, dec)) == 0){
        printf("dec with file failed\n");
        goto end;
    }
    printf("dec with file (lenght = %ld): %s\n\n", dec_len, dec);

    //Use key STRING
    if((mpk = myopenssl_genkey()) == NULL){
        printf("myopenssl_genkey fail\n");
        goto end;
    }
    printf("Create key string done\n");
    printf("Privkey (length = %ld): %s\n", mpk->privlen, mpk->privkey);
    printf("Pubkey (length = %ld): %s\n", mpk->publen, mpk->pubkey);

    memset(enc, 0, sizeof(enc));
    if((enc_len = myopenssl_encrypt(mpk->pubkey, msg, strlen((char *)msg), enc)) == 0){
        printf("enc with string failed\n");
        goto end;
    }
    printf("enc with string (length = %ld): ", enc_len);
    for(int a = 0; a < enc_len; a++){
        printf("%X ", enc[a]);
    }
    printf("\n");

    memset(dec, 0, sizeof(dec));
    if((dec_len = myopenssl_decrypt(mpk->privkey, enc, enc_len, dec)) == 0){
        printf("dec with string failed\n");
        goto end;
    }
    printf("dec with string (lenght = %ld): %s\n", dec_len, dec);

    end:
    if(mpk) myopenssl_k_free(mpk);
    return 0;
}