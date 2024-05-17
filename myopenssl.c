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
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include "myopenssl.h"

void myopenssl_k_free(myopenssl_k *ptr){
    if(ptr->pubkey) free(ptr->pubkey);
    OPENSSL_DEBUG("free 1/3\n");
    if(ptr->privkey) free(ptr->privkey);
    OPENSSL_DEBUG("free 2/3\n");
    free(ptr);
    OPENSSL_DEBUG("free 3/3\n");
}

static size_t key_encode(EVP_PKEY *pkey, char **out, const int public){
    OPENSSL_DEBUG("---Key encode---\n");
    size_t  ret = 0;
    BIO *bio = NULL;
    char *bio_data = NULL;
    long data_len;
    char *buf = NULL;

    if((bio = BIO_new(BIO_s_mem())) == NULL){
        OPENSSL_DEBUG("Fail to create bio\n");
        goto clean;
    }

    if(public == 1){
        OPENSSL_DEBUG("Create pubkey\n");
        if(PEM_write_bio_PUBKEY(bio, pkey) == 0){
            OPENSSL_DEBUG("PEM_write_bio_PUBKEY() failed\n");
            goto clean;
        }
    }else{
        OPENSSL_DEBUG("Create prikey\n");
        if(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) == 0){
            OPENSSL_DEBUG("PEM_write_bio_PrivateKey() failed\n");
            goto clean;
        }
    }

    if((data_len = BIO_get_mem_data(bio, &bio_data)) <= 0){
        OPENSSL_DEBUG("BIO_get_mem_data() failed (retrun val = %ld)\n", data_len);
        goto clean;
    }

    if((buf = (char *)malloc((size_t)data_len + 1)) == NULL){
        OPENSSL_DEBUG("out malloc failed\n");
        goto clean;
    }

    strcpy(buf, bio_data);
    buf[data_len] = '\0';
    *out = buf;

    ret = (size_t)data_len;
    OPENSSL_DEBUG("---Key encode done---\n");

    clean:
    if(bio) BIO_free_all(bio);
    return ret;
}

myopenssl_k *myopenssl_genkey(){
    OPENSSL_DEBUG("---myopenssl_genkey()---\n");
    myopenssl_k *ret = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        goto clean;
    }
    if(EVP_PKEY_keygen_init(ctx) <= 0){
        OPENSSL_DEBUG("Fail to init ctx\n");
        goto clean;
    }

    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
        OPENSSL_DEBUG("Fail to set RSA key length\n");
        goto clean;
    }

    if(EVP_PKEY_keygen(ctx, &pkey) <= 0){
        OPENSSL_DEBUG("Fail to genaration RSA key\n");
        goto clean;
    }

    //Create myopenssl_k struct
    myopenssl_k *mp = malloc(sizeof(myopenssl_k));
    if(!mp){
        OPENSSL_DEBUG("Malloc failed\n");
        goto clean;
    }
    memset(mp, 0, sizeof(myopenssl_k));

    OPENSSL_DEBUG("Ready to write prikey\n");
    if((mp->privlen = key_encode(pkey, &mp->privkey, 0)) == 0){
        OPENSSL_DEBUG("Encode privkey failed\n");
        myopenssl_k_free(mp);
        goto clean;
    }

    OPENSSL_DEBUG("Ready to write pubkey\n");
    if((mp->publen = key_encode(pkey, &mp->pubkey, 1)) == 0){
        OPENSSL_DEBUG("Encode pubkey failed\n");
        myopenssl_k_free(mp);
        goto clean;
    }

    ret = mp;

    clean:
    if(pkey) EVP_PKEY_free(pkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---myopenssl_genkey() finish---\n");
    return ret;
}

static EVP_PKEY *key_decode(const char *in, const int public){
    OPENSSL_DEBUG("---key decode---\n");
    EVP_PKEY *ret = NULL;
    BIO *bio = NULL;
    EVP_PKEY *pkey = NULL;

    if((bio = BIO_new_mem_buf(in, -1)) == NULL){
        OPENSSL_DEBUG("Fail to create bio\n");
        goto clean;
    }

    if(public == 1){
        if((pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == NULL){
            OPENSSL_DEBUG("PEM_read_bio_PUBKEY faild\n");
            goto clean;
        }
    }else{
        if((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL){
            OPENSSL_DEBUG("PEM_read_bio_PrivateKey faild\n");
            goto clean;
        }
    }

    ret = pkey;
    OPENSSL_DEBUG("---key decode done---\n");

    clean:
    if(bio) BIO_free_all(bio);
    return ret;
}

size_t myopenssl_encrypt(const char *pubkey, const unsigned char *in, const size_t in_len, unsigned char *out){
    OPENSSL_DEBUG("---Encrypt---\n");
    size_t ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len;

    //check input
    if(!pubkey || !in || (in_len <= 1)){
        OPENSSL_DEBUG("Input error\n");
        return ret;
    }

    //decode key to EVP_PKEY
    pkey = key_decode(pubkey, 1);
    if(pkey == NULL){
        OPENSSL_DEBUG("Pub EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get pub EVP_PKEY\n");

    //create EVP_PKEY_CTX
    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
        OPENSSL_DEBUG("Fail to create ctx\n");
        goto clean;
    }
    if(EVP_PKEY_encrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Encrypt init failed\n");
        goto clean;
    }

    //encrypt
    if(EVP_PKEY_encrypt(ctx, out, &out_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Encrypt data failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("Encrypted data buffer (length = %ld) :\n%s\n", out_len, out);

    ret = out_len;
    OPENSSL_DEBUG("---Encrypt done---\n");

    clean:
    if(pkey) EVP_PKEY_free(pkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

size_t myopenssl_decrypt(const char *privkey, const unsigned char *in, const size_t in_len, unsigned char *out){
    OPENSSL_DEBUG("---Decrypt---\n");
    size_t ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len;

    //check input
    if(!privkey || !in || (in_len <= 1)){
        OPENSSL_DEBUG("Input error\n");
        return ret;
    }

    //decode key to EVP_PKEY
    pkey = key_decode(privkey, 0);
    if(pkey == NULL){
        OPENSSL_DEBUG("Priv EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get Priv EVP_PKEY\n");

    //create EVP_PKEY_CTX
    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
        OPENSSL_DEBUG("Fail to create ctx\n");
        goto clean;
    }
    if(EVP_PKEY_decrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Decrypt init failed\n");
        goto clean;
    }

    //decrypt
    int decrypt_ret = EVP_PKEY_decrypt(ctx, out, &out_len, in, in_len);
    if(decrypt_ret <= 0){
        OPENSSL_DEBUG("Decrypt data step2 failed (%d)\n", decrypt_ret);
        goto clean;
    }
    OPENSSL_DEBUG("Decrypt data buffer (length = %ld) :\n%s\n", out_len, out);

    ret = out_len;
    OPENSSL_DEBUG("---Decrypt done---\n");

    clean:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file){
    OPENSSL_DEBUG("---myopenssl_genkey_f()---\n");
    int ret = -1;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    //Create EVP_PKEY_CTX for RSA
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        goto clean;
    }
    if(EVP_PKEY_keygen_init(ctx) <= 0){
        OPENSSL_DEBUG("Fail to init ctx\n");
        goto clean;
    }

    //Set RSA key to 2048 bits
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
        OPENSSL_DEBUG("Fail to set RSA key length\n");
        goto clean;
    }

    //Gen RSA key
    if(EVP_PKEY_keygen(ctx, &pkey) <= 0){
        OPENSSL_DEBUG("Fail to genaration RSA key\n");
        goto clean;
    }

    //Write key to PEM key file
    OPENSSL_DEBUG("Ready to write prikey\n");
    FILE *fkey = fopen(privkey_file,"w+");
    if(!fkey){
        OPENSSL_DEBUG("Privkey create failed\n");
        goto clean;
    }
    if(PEM_write_PrivateKey(fkey, pkey, NULL, NULL, 0, NULL, NULL) == 0){
        OPENSSL_DEBUG("PEM_write_PrivateKey() failed\n");
        goto clean;
    }
    fclose(fkey);

    OPENSSL_DEBUG("Ready to write pubkey\n");
    fkey = fopen(pubkey_file,"w+");
    if(!fkey){
        OPENSSL_DEBUG("Pubkey create failed\n");
        goto clean;
    }
    if(PEM_write_PUBKEY(fkey, pkey) == 0){
        OPENSSL_DEBUG("PEM_write_PUBKEY() failed\n");
        goto clean;
    }
    fclose(fkey);

    ret = 0;

    clean:
    if(pkey) EVP_PKEY_free(pkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---myopenssl_genkey_f() finish---\n");
    return ret;
}

static EVP_PKEY *key_decode_f(const char *key_file, const int public){
    OPENSSL_DEBUG("---key decode---\n");
    EVP_PKEY *ret = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;

    if((fp = fopen(key_file, "r")) == NULL){
        OPENSSL_DEBUG("Fail to open %s\n", key_file);
        goto clean;
    }

    if(public == 1){
        if((pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL)) == NULL){
            OPENSSL_DEBUG("PEM_read_bio_PUBKEY faild\n");
            goto clean;
        }
    }else{
        if((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL){
            OPENSSL_DEBUG("PEM_read_bio_PrivateKey faild\n");
            goto clean;
        }
    }
    fclose(fp);

    ret = pkey;
    OPENSSL_DEBUG("---key decode done---\n");

    clean:
    return ret;
}

size_t myopenssl_encrypt_f(const char *pubkey, const unsigned char *in, const size_t in_len, unsigned char *out){
    OPENSSL_DEBUG("---Encrypt---\n");
    size_t ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len;

    //check input
    if(!pubkey || !in || (in_len <= 1)){
        OPENSSL_DEBUG("Input error\n");
        return ret;
    }

    //decode key to EVP_PKEY
    pkey = key_decode_f(pubkey, 1);
    if(pkey == NULL){
        OPENSSL_DEBUG("Pub EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get pub EVP_PKEY\n");

    //create EVP_PKEY_CTX
    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
        OPENSSL_DEBUG("Fail to create ctx\n");
        goto clean;
    }
    if(EVP_PKEY_encrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Encrypt init failed\n");
        goto clean;
    }

    //encrypt
    if(EVP_PKEY_encrypt(ctx, out, &out_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Encrypt data failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("Encrypted data buffer (length = %ld) :\n%s\n", out_len, out);

    ret = out_len;
    OPENSSL_DEBUG("---Encrypt done---\n");

    clean:
    if(pkey) EVP_PKEY_free(pkey);
    if(ctx) EVP_PKEY_CTX_free(ctx);
    return ret;
}

size_t myopenssl_decrypt_f(const char *privkey, const unsigned char *in, const size_t in_len, unsigned char *out){
    OPENSSL_DEBUG("---Decrypt---\n");
    size_t ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len;

    //check input
    if(!privkey || !in || (in_len <= 1)){
        OPENSSL_DEBUG("Input error\n");
        return ret;
    }

    //decode key to EVP_PKEY
    pkey = key_decode_f(privkey, 0);
    if(pkey == NULL){
        OPENSSL_DEBUG("Priv EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get Priv EVP_PKEY\n");

    //create EVP_PKEY_CTX
    if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
        OPENSSL_DEBUG("Fail to create ctx\n");
        goto clean;
    }
    if(EVP_PKEY_decrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Decrypt init failed\n");
        goto clean;
    }

    //decrypt
    int decrypt_ret = EVP_PKEY_decrypt(ctx, out, &out_len, in, in_len);
    if(decrypt_ret <= 0){
        OPENSSL_DEBUG("Decrypt data step2 failed (%d)\n", decrypt_ret);
        goto clean;
    }
    OPENSSL_DEBUG("Decrypt data buffer (length = %ld) :\n%s\n", out_len, out);

    ret = out_len;
    OPENSSL_DEBUG("---Decrypt done---\n");

    clean:
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}
