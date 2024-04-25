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

static const unsigned char msg[] = "This is the original msg";

int main(int argc, char **argv){
    myopenssl_k *mpk;
    myopenssl_k *mp8;
    myopenssl_d *mp_dec;
    myopenssl_d *mp_enc;
    b64_t *url_enc;
    b64_t *url_dec;

    printf("Origin msg (sizeof = %ld)(length = %ld):\n%s\n", sizeof(msg), strlen(msg), msg);

    //genkey
    if((mpk = myopenssl_genkey()) == NULL){
        printf("myopenssl_genkey() failed\n");
        return -1;
    }
    printf("Pubkey (length = %ld) =\n%s\n", mpk->publen, mpk->pubkey);
    printf("Privkey (length = %ld) =\n%s\n", mpk->privlen, mpk->privkey);

    //encrypt
    if((mp_enc = myopenssl_encrypt(mpk->pubkey, msg, strlen(msg))) == NULL){
        printf("Encrypt failed\n");
        goto clean1;
    }
    printf("Encrypted data (length = %ld)(sizeof = %ld):\n%s\n", mp_enc->data_len, sizeof(mp_enc->data), mp_enc->data);

    //base64url encode, if you want do this with base64url, use b64_encode
    if((url_enc = b64url_encode(mp_enc->data, mp_enc->data_len)) == NULL){
        printf("B64URL encode failed\n");
        goto clean2;
    }
    printf("Encrypted data after base64url (length = %ld) =\n%s\n", url_enc->data_len, url_enc->data);

    //base64url decode, if you want do this with base64url, use b64_decode
    if((url_dec = b64url_decode(url_enc->data)) == NULL){
        printf("Base64 decode failed\n");
        goto clean3;
    }
    printf("After base64url decode (length = %ld) =\n%s\n", url_dec->data_len, url_dec->data);

    //decrypt
    if((mp_dec = myopenssl_decrypt(mpk->privkey, mp_enc->data, mp_enc->data_len)) == NULL){
        printf("Decrypt failed\n");
        goto clean4;
    }
    printf("Decrypted data (length = %ld) : \n%s\n", mp_dec->data_len, mp_dec->data);

    if(strcmp(msg, mp_dec->data) == 0) printf("Original msg = decrypted msg\n");
    else{
        printf("Original msg != decrypted msg\n");
        goto clean5;
    }

    //make PKCS#8 format key
    if((mp8 = myopenssl_pkcs8(mpk->pubkey, 1)) == NULL){
        printf("PKCS8 failed\n");
        goto clean5;
    }else printf("PKCS#8 pubkey (length = %ld) =\n%s\n", mp8->publen, mp8->pubkey);
    myopenssl_k_free(mp8);

    if((mp8 = myopenssl_pkcs8(mpk->privkey, 0)) == NULL){
        printf("PKCS8 failed\n");
        goto clean5;
    }else printf("PKCS#8 privkey (length = %ld) =\n%s\n", mp8->privlen, mp8->privkey);

    printf("All finish\n");

    //remember free the PKCS#1 and PKCS#8 format pub/privkey & encrypt/decrypt output after used
    myopenssl_k_free(mp8);
    clean5:
    myopenssl_d_free(mp_dec);
    clean4:
    b64_free(url_dec);
    clean3:
    b64_free(url_enc);
    clean2:
    myopenssl_d_free(mp_enc);
    clean1:
    myopenssl_k_free(mpk);
    return 0;
}