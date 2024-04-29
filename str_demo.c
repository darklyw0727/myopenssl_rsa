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

static const unsigned char msg[] = "This is the original msg";

char *to_b64(const unsigned char *in, const size_t in_len){
    size_t b64e_len = b64_encoded_size(in_len);
    char *b64e = malloc(b64e_len+1);
    if(b64e == NULL){
        printf("Base64 encode malloc failed\n");
        return NULL;
    }
    memset(b64e, 0, b64e_len+1);

    if((b64e_len = b64_encode(in, in_len, b64e)) == 0){
        printf("B64 encode failed\n");
        free(b64e);
        return NULL;
    }
    printf("Encrypted data after base64 (length = %ld) =\n%s\n\n", b64e_len, b64e);
    return b64e;
}

char *from_b64(const char* in){
    size_t b64d_len = b64_decoded_size(in);
    unsigned char *b64d = malloc(b64d_len+1);
    if(b64d == NULL){
        printf("Base64 decode malloc failed\n");
        return NULL;
    }
    memset(b64d, 0, b64d_len+1);

    if((b64d_len = b64_decode(in, b64d)) == 0){
        printf("Base64 decode failed\n");
        free(b64d);
        return NULL;
    }
    printf("After base64 decode (length = %ld) =\n%s\n", b64d_len, b64d);
    return b64d;
}

char *b64toURL(char *in){
    char *buf;

    if((buf = malloc(strlen(in)+1)) == NULL){
        printf("b64toURL malloc failed\n");
        return in;
    }
    memset(buf, 0, strlen(in)+1);

    if(b64_turn(1, in, buf) == 0){
        printf("b64_turn failed\n");
        free(buf);
        return in;
    }

    printf("Turn to base64URL : \n%s\n", buf);
    free(in);
    return buf;
}

char *URLto64(char *in){
    char *buf;
    int a = 4-(strlen(in)%4);

    if((buf = malloc(strlen(in)+1+a)) == NULL){
        printf("URLto64 malloc failed\n");
        return in;
    }
    memset(buf, 0, strlen(in)+1+a);

    if(b64_turn(0, in, buf) == 0){
        printf("b64_turn failed\n");
        free(buf);
        return in;
    }

    printf("Turn to base64 : \n%s\n", buf);
    free(in);
    return buf;
}

int main(int argc, char **argv){
    myopenssl_k *mpk;
    myopenssl_k *mp8;
    //you need 256 bytes memory space for encrypt/decrypt output
    unsigned char enc[256];
    unsigned char dec[256];
    size_t enc_len, dec_len;

    printf("Origin msg (sizeof = %ld)(length = %ld):\n%s\n", sizeof(msg), strlen(msg), msg);

    //genkey
    if((mpk = myopenssl_genkey()) == NULL){
        printf("myopenssl_genkey() failed\n");
        return -1;
    }
    printf("Pubkey (length = %ld) =\n%s\n", mpk->publen, mpk->pubkey);
    printf("Privkey (length = %ld) =\n%s\n", mpk->privlen, mpk->privkey);

    //encrypt
    memset(enc, 0, sizeof(enc));
    if((enc_len = myopenssl_encrypt(mpk->pubkey, msg, strlen(msg), enc)) == 0){
        printf("Encrypt failed\n");
        goto clean;
    }
    printf("Encrypted data (length = %ld)(sizeof = %ld):\n%s\n\n", enc_len, sizeof(enc), enc);

    //base64 encode
    char *b64e = to_b64(enc, enc_len);
    if(b64e == NULL) goto clean;

    //base64 decode
    char *b64d = from_b64(b64e);
    if(b64d == NULL) goto clean;

    //decrypt
    memset(dec, 0, sizeof(dec));
    //if((dec_len = myopenssl_decrypt(mpk->privkey, enc, enc_len, dec)) == 0){
    if((dec_len = myopenssl_decrypt(mpk->privkey, enc, enc_len, dec)) == 0){
        printf("Decrypt failed\n");
        //free(b64d);
        goto clean;
    }
    printf("Decrypted data (length = %ld) : \n%s\n", dec_len, dec);
    //free(b64d);

    int a = strcmp(msg, dec);
    printf("Decrypted msg %s Origin msg\n", (a==0)?"==":"!=");
    if(a != 0) goto clean;

    //make PKCS#8 format key
    if((mp8 = myopenssl_pkcs8(mpk->pubkey, 1)) == NULL){
        printf("PKCS8 failed\n");
        goto clean;
    }else printf("PKCS#8 pubkey (length = %ld) =\n%s\n", mp8->publen, mp8->pubkey);
    myopenssl_k_free(mp8);

    if((mp8 = myopenssl_pkcs8(mpk->privkey, 0)) == NULL){
        printf("PKCS8 failed\n");
        goto clean;
    }else printf("PKCS#8 privkey (length = %ld) =\n%s\n", mp8->privlen, mp8->privkey);

    printf("All finish\n");
    //remember free the PKCS#1 and PKCS#8 format pub/privkey after used
    clean:
    if(mp8) myopenssl_k_free(mp8);
    if(mpk) myopenssl_k_free(mpk);
    if(b64e) free(b64e);
    if(b64d) free(b64d);
    
    return 0;
}