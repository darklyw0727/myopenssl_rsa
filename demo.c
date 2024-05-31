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

//static const unsigned char msg[] = "This is the original msg";
static unsigned char msg[] = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhc2QiLCJleHAiOjE3MTY5ODExMjksImp0aSI6IjB0NjZvOmdUb04iLCJ0aWUiOiI3WE5kZmJNMGVuN3VlWmdVNDFwV2FmNFdiKzVlTXg3dnVYYkdnb3c3UjJBPSJ9.AjPPtnBFlL1HcYT0Ud44iYD0ctr_poSEPHWTn4j5aHQ";

static int file_demo(){
    size_t enc_len = 0, dec_len = 0;
    unsigned char *enc = NULL, *dec = NULL;

    //Use kye FILE
    if(myopenssl_genkey_f(PUB_PATH, PRIV_PATH) != 0){
        printf("myopenssl_genkey_f fail\n");
        return -1;
    }
    printf("Create key file done\n");

    if(!(enc = myopenssl_encrypt_f(PUB_PATH, msg, strlen((char *)msg), &enc_len))){
        printf("enc with file failed\n");
        return -1;
    }
    printf("enc with file (length = %ld): ", enc_len);
    for(int a = 0; a < enc_len; a++){
        printf("%X ", enc[a]);
    }
    printf("\n");

    if(!(dec = myopenssl_decrypt_f(PRIV_PATH, enc, enc_len, &dec_len))){
        printf("dec with file failed\n");
        myopenssl_free(enc);
        return -1;
    }
    printf("dec with file (lenght = %ld): %s\n\n", dec_len, dec);

    myopenssl_free(dec);
    myopenssl_free(enc);
    return 0;
}

static int str_demo(){
    int ret = -1;
    myopenssl_k *mpk = NULL;
    size_t enc_len = 0;
    size_t dec_len = 0;
    unsigned char *enc = NULL;
    unsigned char *dec = NULL;

    if(!(mpk = myopenssl_genkey())){
        printf("myopenssl_genkey fail\n");
        return -1;
    }
    printf("Create key string done\n");
    printf("Privkey (strlen = %ld): %s\n", strlen(mpk->privkey), mpk->privkey);
    printf("Pubkey (strlen = %ld): %s\n", strlen(mpk->pubkey), mpk->pubkey);

    if(!(enc = myopenssl_encrypt(mpk->pubkey, strlen(mpk->pubkey), msg, strlen((char *)msg), &enc_len))){
        printf("enc with string failed\n");
        goto end;
    }
    printf("enc with string (length = %ld): ", enc_len);
    for(int a = 0; a < enc_len; a++){
        printf("%X ", enc[a]);
    }
    printf("\n");

    if(!(dec = myopenssl_decrypt(mpk->privkey, strlen(mpk->privkey), enc, enc_len, &dec_len))){
        printf("dec with string failed\n");
        myopenssl_free(enc);
        goto end;
    }
    printf("dec with string (lenght = %ld): %s\n", dec_len, dec);
    ret = 0;
    myopenssl_free(dec);
    myopenssl_free(enc);

    end:
    myopenssl_free_k(mpk);
    return ret;
}

int main(int argc, char **argv){
    printf("Original input msg (length = %ld): %s\n\n", strlen((char *)msg), msg);

    if(file_demo() != 0) return -1;
    if(str_demo() != 0) return -1;

    return 0;
}