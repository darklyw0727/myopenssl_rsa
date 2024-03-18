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
    unsigned char *pubkey;
    size_t pubkey_len;
    unsigned char *pub8;
    size_t pub8_len;
    unsigned char *privkey;
    size_t privkey_len;
    unsigned char *priv8;
    size_t priv8_len;
    unsigned char *encrypt_out;
    size_t encrypt_len;
    unsigned char *decrypt_out;
    size_t decrypt_len;
    unsigned char *b64_en;
    unsigned char *b64_de;
    size_t b64_de_len;

    printf("Origin msg (sizeof = %ld)(length = %ld):\n%s\n", sizeof(msg), strlen(msg), msg);

    //genkey
    if(genkey_str(&pubkey, &pubkey_len, &privkey, &privkey_len) <= 0){
        printf("genkey() failed\n");
        return -1;
    }
    printf("Pubkey (length = %ld) =\n%s\n", pubkey_len, pubkey);
    printf("Privkey (length = %ld) =\n%s\n", privkey_len, privkey);

    //encrypt
    if(do_encrypt_str(pubkey, msg, strlen(msg), &encrypt_out, &encrypt_len) <= 0){
        printf("Encrypt failed\n");
        free(pubkey);
        free(privkey);
        return -1;
    }
    printf("Encrypted data (length = %ld)(sizeof = %ld):\n%s\n", encrypt_len, sizeof(encrypt_out), encrypt_out);

    //base64url encode
    b64_en = b64url_encode(encrypt_out, encrypt_len);
    printf("Encrypted data after base64 (length = %ld) =\n%s\n", strlen(b64_en), b64_en);

    //base64url decode
    if(b64url_decode(b64_en, &b64_de, &b64_de_len) <= 0){
        printf("Base64 decode failed\n");
        free(pubkey);
        free(privkey);
        free(encrypt_out);
        free(b64_en);
        return -1;
    }
    printf("After base64 decode (length = %ld) =\n%s\n", b64_de_len, b64_de);

    //decrypt
    if(do_decrypt_str(privkey, encrypt_out, encrypt_len, &decrypt_out, &decrypt_len) <= 0){
        printf("Decrypt failed\n");
        free(pubkey);
        free(privkey);
        free(encrypt_out);
        free(b64_en);
        free(b64_de);
        return -1;
    }
    printf("Decrypted data:\n%s\n", decrypt_out);

    if(strcmp(msg, decrypt_out) == 0) printf("Original msg = decrypted msg\n");
    else printf("Original msg != decrypted msg\n");

    //make PKCS#8 format key
    if(pkcs8_maker_str(pubkey, 1, &pub8, &pub8_len) <= 0) printf("PKCS8 failed\n");
    else printf("PKCS#8 pubkey (length = %ld) =\n%s\n", pub8_len, pub8);

    if(pkcs8_maker_str(privkey, 0, &priv8, &priv8_len) <= 0) printf("PKCS8 failed\n");
    else printf("PKCS#8 pubkey (length = %ld) =\n%s\n", priv8_len, priv8);

    //remember free the PKCS#1 and PKCS#8 format pub/privkey & encrypt/decrypt output after used
    free(pubkey);
    free(privkey);
    free(encrypt_out);
    free(b64_en);
    free(b64_de);
    free(decrypt_out);
    free(pub8);
    free(priv8);

    printf("All finish\n");
    return 0;
}