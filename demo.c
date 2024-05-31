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
static unsigned char k1[] = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDGdDexTdu/pXzg\n\
pUm1g9r+7GHC5T8pAz5rYVFqS6lzxVMmW3O4Ui/tI7fvejwuccIVuOYKvnnoqgEq\n\
DYlPZ8lysdbXnq7HpGg89BGH+RA9aSjyrA99Uu46O36DlfsNCnfYMjTKEy11lflZ\n\
Dpnf/3hHF5kpX15mNDOkXBe1C8rT7fzqvpBXLO5UUI2Pc4I4CB9Ld3sGE/kTTgd8\n\
K9Xwyzw1FTBv3Zti3S3Qq7IjhE91QPYO4oYPkyjavxmWGYD0A7r10QzKO2RS67zE\n\
pVyKZy/cJ9EShYXZz+YWU7fByKxDC6CT/IbZROihQ9EBglLZ/axsjU18U1W8u+ti\n\
Gp87S35FAgMBAAECggEALobuy7XqUEs3NN/roQ/R1zSKUww2O6JUDw7Y7KfiiY74\n\
yKRmRA+Yxus5435v/5+SFk+sN1ai9EZvUXGtAJ3fn/FL4m+EoK/N9IRwW8Wr5gny\n\
nLp0QzifO63ZInaWTl9m65wRvlKytL+9nwCKWPbnNxu0P/vpAOM6PE2PDVY/bmIS\n\
IwnwozQoPzV4cOOXhdBjh2oUyvxZoRl2PuMKH8hBxl+1M2guUc4Jq+zaChv85A2P\n\
kwej8y4dCqX4mO/d+UWDEtMsXcEYSM0WXEEMKP0NswlRgGG6vBSazipujypdEPvY\n\
Wi7ArSAHf/7enblUbNz2a0cFLczVe/GFEHREVyqewQKBgQD9NKNbVQ33s6zuqfoD\n\
ZpJUI+9XSEG4EMuAThZNMwwTXP42Mjgtqkv0Q7ai86wMQ9o7tRDU4Hm/T7WINhBK\n\
Ur9J80asCqG0yV1Pgql3ULX2HG5A9G2bcvhAusHVykXV9XY8/l/l20BClAkhQqZI\n\
Owbtb0F7WHHvRZzrR4zHYNw8MQKBgQDIpOTYyTFiGmM20wNtTOvh+81yai3yelYF\n\
Jl1+bkywAZn98AxmTpREEIF21k6KZwa7aEcJn/YjAN2PuipjLge0mVZbvA9647iG\n\
7VJG7SFcZx6826UAR/ajQx+1MCkcyn6OuEx9mxauromIssfyDx7x5vZ5cE4tQRrz\n\
m7TeAr0iVQKBgQDO5ach5xMdtwx0jCHFi5e/9wkIKfvBWr/eXHAurqqMW+1A/bIX\n\
5lJgCsB+0FtiPkNhjGdveukgoRI1de/Du2+hDo9N3vYZUnzTjnHJFANLUhnpK5Ew\n\
dzZRNglTFxAPb54o4rYbjRcqD+qR6fMTjF/xvXolPrUCjcBWJEXtWME80QKBgE3c\n\
b1IRATDovIeR60qHByJy7I7x1VK7VpY5BR8C/o9uj6uTc7xf0fl3zkWndGMRB/PB\n\
y49Ym9OJinEz9S73tdXHi1Od7wPpSrpRbhRIASIygiMXuTgatQM2ER/myI17pxEL\n\
Q+OaQ3sWEBkUB7NPWtrUneESS8QT97mBOvbMaUjhAoGASdN6ogWOedF6IP/nmTV7\n\
9IyRw9yDpb9QnW3nArMts1iI9Gd4tYi3GX9O7I/GubpQbZoUrNxvD95l7ZZxdQeW\n\
WBXCzYoOTDcJgkmuucyO6zS1bK3p70LNSkNLIfqV9jqhlDyXsBg5Pn/O68ma2Mrb\n\
+EOO9lEPKTmwcMTGfHc5dL8=\n\
-----END PRIVATE KEY-----";
static unsigned char k2[] = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxnQ3sU3bv6V84KVJtYPa\n\
/uxhwuU/KQM+a2FRakupc8VTJltzuFIv7SO373o8LnHCFbjmCr556KoBKg2JT2fJ\n\
crHW156ux6RoPPQRh/kQPWko8qwPfVLuOjt+g5X7DQp32DI0yhMtdZX5WQ6Z3/94\n\
RxeZKV9eZjQzpFwXtQvK0+386r6QVyzuVFCNj3OCOAgfS3d7BhP5E04HfCvV8Ms8\n\
NRUwb92bYt0t0KuyI4RPdUD2DuKGD5Mo2r8ZlhmA9AO69dEMyjtkUuu8xKVcimcv\n\
3CfREoWF2c/mFlO3wcisQwugk/yG2UTooUPRAYJS2f2sbI1NfFNVvLvrYhqfO0t+\n\
RQIDAQAB\n\
-----END PUBLIC KEY-----";

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