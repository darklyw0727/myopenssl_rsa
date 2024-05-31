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
#include <openssl/err.h>
#include "myopenssl.h"

void myopenssl_free_k(myopenssl_k *ptr){
    if(ptr->pubkey) free(ptr->pubkey);
    OPENSSL_DEBUG("free 1/3\n");
    if(ptr->privkey) free(ptr->privkey);
    OPENSSL_DEBUG("free 2/3\n");
    free(ptr);
    OPENSSL_DEBUG("free 3/3\n");
}

void myopenssl_free(unsigned char *in){
    if(in) OPENSSL_free(in);
}

// static size_t key_encode(EVP_PKEY *pkey, char **out, const int public){
//     OPENSSL_DEBUG("---Key encode---\n");
//     size_t  ret = 0;
//     BIO *bio = NULL;
//     char *bio_data = NULL;
//     long data_len;
//     char *buf = NULL;

//     if((bio = BIO_new(BIO_s_mem())) == NULL){
//         OPENSSL_DEBUG("Fail to create bio\n");
//         goto clean;
//     }

//     if(public == 1){
//         OPENSSL_DEBUG("Create pubkey\n");
//         if(PEM_write_bio_PUBKEY(bio, pkey) == 0){
//             OPENSSL_DEBUG("PEM_write_bio_PUBKEY() failed\n");
//             goto clean;
//         }
//     }else{
//         OPENSSL_DEBUG("Create prikey\n");
//         if(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) == 0){
//             OPENSSL_DEBUG("PEM_write_bio_PrivateKey() failed\n");
//             goto clean;
//         }
//     }

//     if((data_len = BIO_get_mem_data(bio, &bio_data)) <= 0){
//         OPENSSL_DEBUG("BIO_get_mem_data() failed (retrun val = %ld)\n", data_len);
//         goto clean;
//     }

//     if((buf = (char *)malloc((size_t)data_len + 1)) == NULL){
//         OPENSSL_DEBUG("out malloc failed\n");
//         goto clean;
//     }

//     strcpy(buf, bio_data);
//     buf[data_len] = 0;
//     *out = buf;

//     ret = (size_t)data_len;
    
//     clean:
//     if(bio) BIO_free_all(bio);
//     OPENSSL_DEBUG("---Key encode done---\n");
//     return ret;
// }

// myopenssl_k *myopenssl_genkey(){
//     OPENSSL_DEBUG("---myopenssl_genkey()---\n");
//     myopenssl_k *ret = NULL;
//     EVP_PKEY_CTX *ctx = NULL;
//     EVP_PKEY *pkey = NULL;

//     ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
//     if(!ctx){
//         OPENSSL_DEBUG("Fail to creat ctx\n");
//         goto clean;
//     }
//     if(EVP_PKEY_keygen_init(ctx) <= 0){
//         OPENSSL_DEBUG("Fail to init ctx\n");
//         goto clean;
//     }

//     if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
//         OPENSSL_DEBUG("Fail to set RSA key length\n");
//         goto clean;
//     }

//     if(EVP_PKEY_keygen(ctx, &pkey) <= 0){
//         OPENSSL_DEBUG("Fail to genaration RSA key\n");
//         goto clean;
//     }

//     //Create myopenssl_k struct
//     myopenssl_k *mp = (myopenssl_k *)malloc(sizeof(myopenssl_k));
//     if(!mp){
//         OPENSSL_DEBUG("Malloc failed\n");
//         goto clean;
//     }
//     memset(mp, 0, sizeof(myopenssl_k));

//     OPENSSL_DEBUG("Ready to write prikey\n");
//     if((mp->privlen = key_encode(pkey, &mp->privkey, 0)) <= 0){
//         OPENSSL_DEBUG("Encode privkey failed\n");
//         myopenssl_k_free(mp);
//         goto clean;
//     }

//     OPENSSL_DEBUG("Ready to write pubkey\n");
//     if((mp->publen = key_encode(pkey, &mp->pubkey, 1)) <= 0){
//         OPENSSL_DEBUG("Encode pubkey failed\n");
//         myopenssl_k_free(mp);
//         goto clean;
//     }

//     ret = mp;
//     OPENSSL_DEBUG("ret = mp\n");

//     clean:
//     if(pkey) EVP_PKEY_free(pkey);
//     OPENSSL_DEBUG("if(pkey) EVP_PKEY_free(pkey)\n");
//     if(ctx) EVP_PKEY_CTX_free(ctx);
//     OPENSSL_DEBUG("---myopenssl_genkey() finish---\n");
//     return ret;
// }

// static EVP_PKEY *key_decode(const char *in, const int public){
//     OPENSSL_DEBUG("---key decode---\n");
//     EVP_PKEY *ret = NULL;
//     BIO *bio = NULL;
//     EVP_PKEY *pkey = NULL;
//     char in_buf[2048];

//     memset(in_buf, 0, sizeof(in_buf));
//     strncpy(in_buf, in, strlen(in));
//     OPENSSL_DEBUG("Key will be decode: %s\n", in_buf);

//     // if((bio = BIO_new_mem_buf(in, strlen(in)+1)) == NULL){
//     //     OPENSSL_DEBUG("Fail to create bio\n");
//     //     goto clean;
//     // }
//     if(!(bio = BIO_new(BIO_s_mem()))){
//         OPENSSL_DEBUG("Fail to create bio\n");
//         goto clean;
//     }
//     OPENSSL_DEBUG("key decode 1/3\n");

//     if(BIO_write(bio, in_buf, strlen(in_buf)) <= 0){
//         OPENSSL_DEBUG("Fail to write key into bio\n");
//         goto clean;
//     }
//     OPENSSL_DEBUG("key decode 2/3\n");

//     if(public == 1){
//         if((pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == NULL){
//             OPENSSL_DEBUG("PEM_read_bio_PUBKEY faild\n");
//             goto clean;
//         }
//     }else{
//         if((pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL){
//             OPENSSL_DEBUG("PEM_read_bio_PrivateKey faild\n");
//             goto clean;
//         }
//     }
//     OPENSSL_DEBUG("key decode 3/3\n");

//     ret = pkey;
//     OPENSSL_DEBUG("---key decode done---\n");

//     clean:
//     if(bio) BIO_free_all(bio);
//     return ret;
// }

// size_t myopenssl_encrypt(const char *pubkey, const unsigned char *in, const size_t in_len, unsigned char *out){
//     OPENSSL_DEBUG("---Encrypt---\n");
//     size_t ret = 0;
//     EVP_PKEY *pkey = NULL;
//     EVP_PKEY_CTX *ctx = NULL;
//     size_t out_len;

//     //check input
//     if(!pubkey || !in || (in_len <= 1)){
//         OPENSSL_DEBUG("Input error\n");
//         return ret;
//     }

//     //decode key to EVP_PKEY
//     pkey = key_decode(pubkey, 1);
//     if(pkey == NULL){
//         OPENSSL_DEBUG("Pub EVP_PKEY is NULL\n");
//         goto clean;
//     }else OPENSSL_DEBUG("Get pub EVP_PKEY\n");

//     //create EVP_PKEY_CTX
//     if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
//         OPENSSL_DEBUG("Fail to create ctx\n");
//         goto clean;
//     }
//     if(EVP_PKEY_encrypt_init(ctx) <= 0){
//         OPENSSL_DEBUG("Encrypt init failed\n");
//         goto clean;
//     }

//     //encrypt
//     if(EVP_PKEY_encrypt(ctx, out, &out_len, in, in_len) <= 0){
//         OPENSSL_DEBUG("Encrypt data failed\n");
//         goto clean;
//     }
//     OPENSSL_DEBUG("Encrypted data buffer (length = %ld) :\n%s\n", out_len, out);

//     ret = out_len;
//     OPENSSL_DEBUG("---Encrypt done---\n");

//     clean:
//     if(pkey) EVP_PKEY_free(pkey);
//     if(ctx) EVP_PKEY_CTX_free(ctx);
//     return ret;
// }

// size_t myopenssl_decrypt(const char *privkey, const unsigned char *in, const size_t in_len, unsigned char *out){
//     OPENSSL_DEBUG("---Decrypt---\n");
//     size_t ret = 0;
//     EVP_PKEY *pkey = NULL;
//     EVP_PKEY_CTX *ctx = NULL;
//     size_t out_len;

//     //check input
//     if(!privkey || !in || (in_len <= 1)){
//         OPENSSL_DEBUG("Input error\n");
//         return ret;
//     }

//     //decode key to EVP_PKEY
//     pkey = key_decode(privkey, 0);
//     if(pkey == NULL){
//         OPENSSL_DEBUG("Priv EVP_PKEY is NULL\n");
//         goto clean;
//     }else OPENSSL_DEBUG("Get Priv EVP_PKEY\n");

//     //create EVP_PKEY_CTX
//     if((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL){
//         OPENSSL_DEBUG("Fail to create ctx\n");
//         goto clean;
//     }
//     if(EVP_PKEY_decrypt_init(ctx) <= 0){
//         OPENSSL_DEBUG("Decrypt init failed\n");
//         goto clean;
//     }

//     //decrypt
//     int decrypt_ret = EVP_PKEY_decrypt(ctx, out, &out_len, in, in_len);
//     if(decrypt_ret <= 0){
//         OPENSSL_DEBUG("Decrypt data step2 failed (%d)\n", decrypt_ret);
//         goto clean;
//     }
//     OPENSSL_DEBUG("Decrypt data buffer (length = %ld) :\n%s\n", out_len, out);

//     ret = out_len;
//     OPENSSL_DEBUG("---Decrypt done---\n");

//     clean:
//     EVP_PKEY_free(pkey);
//     EVP_PKEY_CTX_free(ctx);
//     return ret;
// }

static void openssl_err(){
    unsigned long err_code;
    while((err_code = ERR_get_error())){
        char *err_msg = ERR_error_string(err_code, NULL);
        OPENSSL_DEBUG("%s\n", err_msg);
    }
}

static EVP_PKEY *gen_pkey(){
    OPENSSL_DEBUG("---gen_pkey Start---\n");
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *ret = NULL;

    //Create EVP_PKEY_CTX for RSA
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        return NULL;
    }
    OPENSSL_DEBUG("gen_pkey 1/5\n");

    if(EVP_PKEY_keygen_init(ctx) <= 0){
        OPENSSL_DEBUG("Fail to init ctx\n");
        goto clean;
    }
    OPENSSL_DEBUG("gen_pkey 2/5\n");

    //Set RSA key to 2048 bits
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0){
        OPENSSL_DEBUG("Fail to set RSA key length\n");
        goto clean;
    }
    OPENSSL_DEBUG("gen_pkey 3/5\n");

    //Gen RSA key
    if(EVP_PKEY_keygen(ctx, &ret) <= 0){
        OPENSSL_DEBUG("Fail to genaration RSA key\n");
        EVP_PKEY_free(ret);
        goto clean;
    }
    OPENSSL_DEBUG("gen_pkey 4/5\n");

    clean:
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---gen_pkey 5/5---\n");
    return ret;
}

static char *pkey2str(const int pub, EVP_PKEY *pkey){
    OPENSSL_DEBUG("---pkey2str Start---\n");
    BIO *bio = NULL;
    char *mem_buf = NULL;
    long mem_len;
    char *ret = NULL;

    if(!(bio = BIO_new(BIO_s_mem()))){
        OPENSSL_DEBUG("BIO_new failed\n");
        return 0;
    }
    OPENSSL_DEBUG("pkey2str 1/6\n");

    if(pub){
        if(PEM_write_bio_PUBKEY(bio, pkey) <= 0){
            OPENSSL_DEBUG("PEM_write_bio_PUBKEY failed\n");
            goto clean;
        }
        OPENSSL_DEBUG("pkey2str 2/6, pubkey\n");
    }else{
        if(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0){
            OPENSSL_DEBUG("PEM_write_bio_PrivateKey failed\n");
            goto clean;
        }
        OPENSSL_DEBUG("pkey2str 2/6, privkey\n");
    }

    mem_len = BIO_get_mem_data(bio, &mem_buf);
    OPENSSL_DEBUG("pkey2str 3/6\n");

    ret = (char *)malloc(mem_len+1);
    if(!ret){
        OPENSSL_DEBUG("malloc failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("pkey2str 4/6\n");

    memcpy(ret, mem_buf, mem_len);
    ret[mem_len] = 0;
    OPENSSL_DEBUG("pkey2str 5/6, output (length = %ld): %s\n", mem_len, ret);

    clean:
    BIO_free(bio);
    OPENSSL_DEBUG("---pkey2str 6/6---\n");
    return ret;
}

static EVP_PKEY *str2pkey(const char *in, const int pub){
    OPENSSL_DEBUG("---str2pkey Start---\n");
    BIO *bio = NULL;
    EVP_PKEY *ret = NULL;

    bio = BIO_new_mem_buf(in, -1);
    if(!bio){
        OPENSSL_DEBUG("BIO_new_mem_buf failed\n");
        return NULL;
    }
    OPENSSL_DEBUG("str2pkey 1/3\n");

    if(pub){
        if(!(ret = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL))){
            OPENSSL_DEBUG("PEM_read_bio_PrivateKey failed\n");
            goto clean;
        }
        OPENSSL_DEBUG("str2pkey 2/3, pubkey\n");
    }else{
        if(!(ret = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL))){
            OPENSSL_DEBUG("PEM_read_bio_PrivateKey failed\n");
            goto clean;
        }
        OPENSSL_DEBUG("str2pkey 2/3, privkey\n");
    }

    clean:
    BIO_free(bio);
    OPENSSL_DEBUG("---str2pkey 3/3---\n");
    return ret;
}

static int pkey2file(const char *filename, const int pub, EVP_PKEY *pkey){
    OPENSSL_DEBUG("---pkey2file Start---\n");
    int ret = -1;
    FILE *file = fopen(filename, "w");
    if(!file){
        OPENSSL_DEBUG("Can't create %s\n", filename);
        return -1;
    }
    OPENSSL_DEBUG("pkey2file 1/3\n");

    if(pub){
        if(PEM_write_PUBKEY(file, pkey) <= 0){
            OPENSSL_DEBUG("Pubkey conversion failed\n");
            fclose(file);
            return -1;
        }
        OPENSSL_DEBUG("pkey2file 2/3, pubkey\n");
    }else{
        if(PEM_write_PrivateKey(file, pkey, NULL, NULL, 0, NULL, NULL) <= 0){
            OPENSSL_DEBUG("Privkey conversion failed\n");
            fclose(file);
            return -1;
        }
        OPENSSL_DEBUG("pkey2file 2/3, privkey\n");
    }

    fclose(file);
    OPENSSL_DEBUG("---pkey2file 3/3---\n");
    return 0;
}

static EVP_PKEY *file2pkey(const char *filename, const int pub){
    OPENSSL_DEBUG("---file2pkey Start---\n");
    EVP_PKEY *ret = NULL;
    FILE *file = fopen(filename, "r");
    if(!file){
        OPENSSL_DEBUG("Can't open %s\n", filename);
        return NULL;
    }
    OPENSSL_DEBUG("file2pkey 1/3\n");

    if(pub){
        if(!(ret = PEM_read_PUBKEY(file, NULL, NULL, NULL))){
            OPENSSL_DEBUG("Pubkey conversion failed\n");
            fclose(file);
            return NULL;
        }
        OPENSSL_DEBUG("file2pkey 2/3, pubkey\n");
    }else{
        if(!(ret = PEM_read_PrivateKey(file, NULL, NULL, NULL))){
            OPENSSL_DEBUG("Privkey conversion failed\n");
            fclose(file);
            return NULL;
        }
        OPENSSL_DEBUG("file2pkey 2/3, privkey\n");
    }

    fclose(file);
    OPENSSL_DEBUG("---file2pkey 3/3---\n");
    return ret;
}

static unsigned char *pkey_encrypt(EVP_PKEY *pkey, unsigned char *in, const size_t in_len, size_t *out_len){
    OPENSSL_DEBUG("---pkey_encrypt Start---\n");
    unsigned char *ret = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t ret_len = 0;

    //create EVP_PKEY_CTX
    if(!(ctx = EVP_PKEY_CTX_new(pkey, NULL))){
        OPENSSL_DEBUG("Fail to create ctx\n");
        goto clean;
    }
    OPENSSL_DEBUG("pkey_encrypt 1/6\n");

    if(EVP_PKEY_encrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Encrypt init failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("pkey_encrypt 2/6\n");

    //encrypt
    int a = 0;
    if((a = EVP_PKEY_encrypt(ctx, NULL, &ret_len, in, in_len)) <= 0){
        OPENSSL_DEBUG("EVP_PKEY_encrypt failed (error code %d)\n", a);
        openssl_err();
        goto clean;
    }
    OPENSSL_DEBUG("pkey_encrypt 3/6\n");

    if(!(ret = OPENSSL_malloc(ret_len))){
        OPENSSL_DEBUG("OPENSSL_malloc failed\n");
        openssl_err();
        goto clean;
    }
    memset(ret, 0, ret_len);
    OPENSSL_DEBUG("pkey_encrypt 4/6\n");

    if((a = EVP_PKEY_encrypt(ctx, ret, &ret_len, in, in_len)) <= 0){
        OPENSSL_DEBUG("EVP_PKEY_encrypt failed (error code %d)\n", a);
        openssl_err();
        OPENSSL_free(ret);
        ret = NULL;
        goto clean;
    }
    *out_len = ret_len;
    OPENSSL_DEBUG("pkey_encrypt 3/4, encrypted data (length = %ld):\n%s\n", ret_len, ret);

    clean:
    if(ctx) EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---pkey_encrypt 6/6---\n");
    return ret;
}

static unsigned char *pkey_decrypt(EVP_PKEY *pkey, unsigned char *in, const size_t in_len, size_t *out_len){
    OPENSSL_DEBUG("---pkey_decrypt Start---\n");
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ret = NULL;
    size_t ret_len = 0;

    //create EVP_PKEY_CTX
    if(!(ctx = EVP_PKEY_CTX_new(pkey, NULL))){
        OPENSSL_DEBUG("Fail to create ctx\n");
        goto clean;
    }
    OPENSSL_DEBUG("pkey_decrypt 1/6\n");

    if(EVP_PKEY_decrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Encrypt init failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("pkey_decrypt 2/6\n");

    //encrypt
    int a = 0;
    if((a = EVP_PKEY_decrypt(ctx, NULL, &ret_len, in, in_len)) <= 0){
        OPENSSL_DEBUG("Decrypt data failed (error code %d)\n", a);
        openssl_err();
        goto clean;
    }
    OPENSSL_DEBUG("pkey_decrypt 3/6\n");

    if(!(ret = OPENSSL_malloc(ret_len))){
        OPENSSL_DEBUG("OPENSSL_malloc failed\n");
        openssl_err();
        goto clean;
    }
    memset(ret, 0, ret_len);
    OPENSSL_DEBUG("pkey_decrypt 4/6\n");

    if((a = EVP_PKEY_decrypt(ctx, ret, &ret_len, in, in_len)) <= 0){
        OPENSSL_DEBUG("Decrypt data failed (error code %d)\n", a);
        openssl_err();
        OPENSSL_free(ret);
        ret = NULL;
        goto clean;
    }
    *out_len = ret_len;
    OPENSSL_DEBUG("pkey_decrypt 3/4, decrypted data (length = %ld):\n%s\n", ret_len, ret);

    clean:
    if(ctx) EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---pkey_decrypt 6/6---\n");
    return ret;
}

myopenssl_k *myopenssl_genkey(){
    OPENSSL_DEBUG("---myopenssl_genkey Start---\n");
    myopenssl_k *ret = NULL;
    EVP_PKEY *pkey = NULL;
    char *pubkey = NULL, *privkey = NULL;

    if(!(pkey = gen_pkey())){
        OPENSSL_DEBUG("gen_pkey filed\n");
        return NULL;
    }
    OPENSSL_DEBUG("myopenssl_genkey 1/6\n");

    if(!(pubkey = pkey2str(1, pkey))){
        OPENSSL_DEBUG("Pubkey conversion failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("myopenssl_genkey 2/6\n");
    if(!(privkey = pkey2str(0, pkey))){
        OPENSSL_DEBUG("Pubkey conversion failed\n");
        free(pubkey);
        goto clean;
    }
    OPENSSL_DEBUG("myopenssl_genkey 3/6\n");

    if(!(ret = (myopenssl_k *)malloc(sizeof(myopenssl_k)))){
        OPENSSL_DEBUG("malloc failed\n");
        free(pubkey);
        free(privkey);
        goto clean;
    }
    memset(ret, 0, sizeof(myopenssl_k));
    OPENSSL_DEBUG("myopenssl_genkey 4/6\n");

    ret->pubkey = pubkey;
    ret->privkey = privkey;
    OPENSSL_DEBUG("myopenssl_genkey 5/6\n");

    clean:
    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---myopenssl_genkey 6/6---\n");
    return ret;
}

unsigned char *myopenssl_encrypt(char *pubkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len){
    OPENSSL_DEBUG("---myopenssl_encrypt Start---\n");
    EVP_PKEY *pkey = NULL;
    char inkey_buf[key_len+1];
    unsigned char *ret = NULL;

    //check input
    if(!pubkey || (key_len <= 0) || !in || (in_len <= 0)){
        OPENSSL_DEBUG("Input error\n");
        return NULL;
    }

    //decode key to EVP_PKEY
    strncpy(inkey_buf, pubkey, key_len);
    inkey_buf[key_len] = 0;

    pkey = str2pkey(inkey_buf, 1);
    if(!pkey){
        OPENSSL_DEBUG("str2pkey failed\n");
        return NULL;
    }
    OPENSSL_DEBUG("myopenssl_encrypt 1/2\n");

    if(!(ret = pkey_encrypt(pkey, in, in_len, out_len))){
        OPENSSL_DEBUG("pkey_encrypt failed\n");
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---myopenssl_encrypt 2/2---\n");
    return ret;
}

unsigned char *myopenssl_decrypt(char *privkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len){
    OPENSSL_DEBUG("---myopenssl_decrypt Start---\n");
    EVP_PKEY *pkey = NULL;
    unsigned char *ret = NULL;
    char inkey_buf[key_len+1];

    //check input
    if(!privkey || (key_len <= 0) || !in || (in_len <= 0)){
        OPENSSL_DEBUG("Input error\n");
        return 0;
    }

    //decode key to EVP_PKEY
    strncpy(inkey_buf, privkey, key_len);
    inkey_buf[key_len] = 0;

    pkey = str2pkey(inkey_buf, 0);
    if(!pkey){
        OPENSSL_DEBUG("str2pkey failed\n");
        return 0;
    }
    OPENSSL_DEBUG("myopenssl_decrypt 1/2\n");

    if(!(ret = pkey_decrypt(pkey, in, in_len, out_len))){
        OPENSSL_DEBUG("pkey_decrypt failed\n");
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---myopenssl_decrypt 2/2---\n");
    return ret;
}

int myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file){
    OPENSSL_DEBUG("---myopenssl_genkey_f Start---\n");
    int ret = -1;
    EVP_PKEY *pkey = NULL;

    if(!pubkey_file || !privkey_file){
        OPENSSL_DEBUG("Input error\n");
        return -1;
    }

    if(!(pkey = gen_pkey())){
        OPENSSL_DEBUG("gen_pkey filed\n");
        return -1;
    }
    OPENSSL_DEBUG("myopenssl_genkey_f 1/3\n");

    //Write key to PEM key file
    OPENSSL_DEBUG("Ready to write prikey\n");
    if(pkey2file(privkey_file, 0, pkey) != 0){
        OPENSSL_DEBUG("pkey2file filed\n");
        goto clean;
    }
    OPENSSL_DEBUG("Ready to write pubkey\n");
    if(pkey2file(pubkey_file, 1, pkey) != 0){
        OPENSSL_DEBUG("pkey2file filed\n");
        goto clean;
    }
    ret = 0;
    OPENSSL_DEBUG("myopenssl_genkey_f 2/3\n");

    clean:
    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---myopenssl_genkey_f 3/3---\n");
    return ret;
}

unsigned char *myopenssl_encrypt_f(const char *pubkey, unsigned char *in, const size_t in_len, size_t *out_len){
    OPENSSL_DEBUG("---myopenssl_encrypt_f Start---\n");
    EVP_PKEY *pkey = NULL;
    unsigned char *ret = NULL;

    //check input
    if(!pubkey || !in || (in_len <= 0)){
        OPENSSL_DEBUG("Input error\n");
        return 0;
    }

    //decode key to EVP_PKEY
    pkey = file2pkey(pubkey, 1);
    if(!pkey){
        OPENSSL_DEBUG("Can't get PKEY\n");
        return 0;
    }
    OPENSSL_DEBUG("myopenssl_encrypt_f 1/2\n");

    if(!(ret = pkey_encrypt(pkey, in, in_len, out_len))){
        OPENSSL_DEBUG("pkey_encrypt failed\n");
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---myopenssl_encrypt_f 2/2---\n");
    return ret;
}

unsigned char *myopenssl_decrypt_f(const char *privkey, unsigned char *in, const size_t in_len, size_t *out_len){
    OPENSSL_DEBUG("---myopenssl_decrypt_f Start---\n");
    EVP_PKEY *pkey = NULL;
    unsigned char *ret = NULL;

    //check input
    if(!privkey || !in || (in_len <= 0)){
        OPENSSL_DEBUG("Input error\n");
        return 0;
    }

    //decode key to EVP_PKEY
    pkey = file2pkey(privkey, 0);
    if(!pkey){
        OPENSSL_DEBUG("Can't get PKEY\n");
        return 0;
    }
    OPENSSL_DEBUG("myopenssl_decrypt_f 1/2\n");

    if(!(ret = pkey_decrypt(pkey, in, in_len, out_len))){
        OPENSSL_DEBUG("pkey_decrypt failed\n");
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---myopenssl_decrypt_f 2/2---\n");
    return ret;
}