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
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/pem.h>
#include "myopenssl.h"

static int key_encode(EVP_PKEY *pkey, FILE *f, const int selection){
    OPENSSL_DEBUG("---Key encode---\n");
    int ret = 0;

    //create encoder for PEM fomat
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", NULL, NULL);
    if(ectx == NULL){
        printf("Fail to creat encoder\n");
        goto clean;
    }
    OPENSSL_DEBUG("encode step1\n");

    //encode key
    if(OSSL_ENCODER_to_fp(ectx, f) == 0){
        printf("Fail to encode\n");
        goto clean;
    }
    OPENSSL_DEBUG("encode step2\n");
    ret = 1;

    clean:
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_DEBUG("---Encode finish---\n");
    return ret;
}

int genkey(const char *pubkey_file, const char *privkey_file){
    OPENSSL_DEBUG("---genkey()---\n");
    int ret = 0;
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
    OPENSSL_DEBUG("Ready to write pubkey\n");
    FILE *fkey = fopen(pubkey_file,"w+");
    if(fkey != NULL){
        if(key_encode(pkey, fkey, EVP_PKEY_PUBLIC_KEY) == 0){
            fclose(fkey);
            goto clean;
        }
        fclose(fkey);
    }else{
        OPENSSL_DEBUG("Pubkey create failed\n");
        goto clean;
    }

    OPENSSL_DEBUG("Ready to write prikey\n");
    fkey = fopen(privkey_file,"w+");
    if(fkey != NULL){
        if(key_encode(pkey, fkey, EVP_PKEY_KEYPAIR) == 0){
            fclose(fkey);
            goto clean;
        }
        fclose(fkey);
    }else{
        OPENSSL_DEBUG("Privekey create failed\n");
        goto clean;
    }

    ret = 1;

    clean:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---genkey() finish---\n");
    return ret;
}

static EVP_PKEY *load_key(OSSL_LIB_CTX *libctx, const char *keyfile, const int selection){
    OPENSSL_DEBUG("---Load key---\n");
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char keychar[2048];
    ssize_t key_len;
    int fd;
    
    //Read key from PEM key file
    if((fd = open(keyfile, O_RDWR, 0666)) < 0){
        OPENSSL_DEBUG("Open %s failed\n", keyfile);
        goto clean;
    }

    memset(keychar, 0, sizeof(keychar));
    if((key_len = read(fd, keychar, 2048)) < 0){
        OPENSSL_DEBUG("Read %s failed\n", keyfile);
        goto clean;
    }
    OPENSSL_DEBUG("Key length = %ld\n", key_len);

    //Create decoder for RSA PEM key
    OPENSSL_DEBUG("---Key decode---\n");
    dctx = OSSL_DECODER_CTX_new_for_pkey(&key, "PEM", NULL, "RSA", selection, libctx, NULL);
    if(dctx == NULL){
        OPENSSL_DEBUG("Fail to creat decoder\n");
        key = NULL;
        goto clean;
    }
    OPENSSL_DEBUG("Decode step1\n");

    const unsigned char *data;
    data = keychar;

    //Create EVP_PKEY from PEM key
    if(OSSL_DECODER_from_data(dctx, &data, &key_len) <= 0){
        OPENSSL_DEBUG("Fail to decode\n");
        key = NULL;
        goto clean;
    }
    OPENSSL_DEBUG("Decode step2\n");

    clean:
    OSSL_DECODER_CTX_free(dctx);
    OPENSSL_DEBUG("---Decode finish---\n");
    OPENSSL_DEBUG("---Load key finish---\n");
    return key;
}

int do_encrypt(const char *keyfile, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len){
    OPENSSL_DEBUG("---Encrypt---\n");
    int ret = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *encrypt_data = NULL;
    size_t data_len = 0;

    //Load key
    pkey = load_key(libctx, keyfile, EVP_PKEY_PUBLIC_KEY);
    if(pkey == NULL){
        OPENSSL_DEBUG("Pub EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get pub EVP_PKEY\n");

    //Use EVP_PKEY to create EVP_PKEY_CTX for encrypt
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        goto clean;
    }
    if(EVP_PKEY_encrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Encrypt init failed\n");
        goto clean;
    }

    //Get encrypted data length
    if(EVP_PKEY_encrypt(ctx, NULL, &data_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Encrypt data step1 failed\n");
        goto clean;
    }
    encrypt_data = OPENSSL_zalloc(data_len);
    if(encrypt_data == NULL){
        OPENSSL_DEBUG("Malloc failed\n");
        goto clean;
    }

    //Encrypt
    if(EVP_PKEY_encrypt(ctx, encrypt_data, &data_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Encrypt data step2 failed\n");
        goto clean;
    }

    *out_len = data_len;
    *out = encrypt_data;

    OPENSSL_DEBUG("Encrypt data:\n%s\n", encrypt_data);
    ret = 1;

    clean:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---Encrypt finish---\n");
    return ret;
}

int do_decrypt(const char *keyfile, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len){
    OPENSSL_DEBUG("---Decrypt---\n");
    int ret = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *decrypt_out = NULL;
    size_t decrypt_len = 0;

    pkey = load_key(libctx, keyfile, EVP_PKEY_KEYPAIR);
    if(pkey == NULL){
        OPENSSL_DEBUG("Priv EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get priv EVP_PKEY\n");

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        goto clean;
    }
    if(EVP_PKEY_decrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Decrypt init failed\n");
        goto clean;
    }

    OPENSSL_DEBUG("Message befor decrypt (length = %ld)(strlen = %ld):\n%s\n", in_len, strlen(in), in);
    if(EVP_PKEY_decrypt(ctx, NULL, &decrypt_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Decrypt data step1 failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("Decrypted string length = %ld\n", decrypt_len);
    decrypt_out = OPENSSL_zalloc(decrypt_len);
    if(decrypt_out == NULL){
        OPENSSL_DEBUG("Malloc failed\n");
        goto clean;
    }

    int decrypt_ret = EVP_PKEY_decrypt(ctx, decrypt_out, &decrypt_len, in, in_len);
    if(decrypt_ret <= 0){
        OPENSSL_DEBUG("Decrypt data step2 failed (%d)\n", decrypt_ret);
        goto clean;
    }

    *out = decrypt_out;
    *out_len = decrypt_len;

    OPENSSL_DEBUG("Decrypt data:\n%s\n", decrypt_out);
    ret = 1;

    clean:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---Decrypt finish---\n");
    return ret;
}

int pkcs8_maker(const char *infile, const int public, const char *outfile){
    OPENSSL_DEBUG("---Make PKCS#8 key---\n");
    int ret = 0;
    int selection;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *pkcs8 = NULL;

    if(public == 1) selection = EVP_PKEY_PUBLIC_KEY;
    else selection = EVP_PKEY_KEYPAIR;

    //Get EVP_PKEY from PEM key file
    pkey = load_key(libctx, infile, selection);
    if(pkey == NULL){
        OPENSSL_DEBUG("Can't get EVP_KEY from %s\n", infile);
        goto clean;
    }else OPENSSL_DEBUG("Get EVP_PKEY from %s\n", infile);

    //Create PKCS#8 PEM key file
    pkcs8 = fopen(outfile, "w");
    if(pkcs8 == NULL){
        OPENSSL_DEBUG("Can't creat pkcs8 file %s\n", outfile);
        goto clean;
    }else OPENSSL_DEBUG("Creat pkcs8 file %s\n", outfile);

    //Write Pubkey or privkey
    if(public == 1){
        if(PEM_write_PUBKEY(pkcs8, pkey) <= 0){
            OPENSSL_DEBUG("Can't write %s\n", outfile);
            goto clean;
        }else OPENSSL_DEBUG("Write key to pkcs8 file %s\n", outfile);
    }else{
        if(PEM_write_PKCS8PrivateKey(pkcs8, pkey, NULL, NULL, 0, NULL, NULL) <= 0){
            OPENSSL_DEBUG("Can't write %s\n", outfile);
            goto clean;
        }else OPENSSL_DEBUG("Write key to pkcs8 file %s\n", outfile);
    }

    ret = 1;

    clean:
    EVP_PKEY_free(pkey);
    OSSL_LIB_CTX_free(libctx);
    if(pkcs8 != NULL) fclose(pkcs8);
    OPENSSL_DEBUG("---Make PKCS#8 key finish---\n");
    return ret;
}

static int key_encode_str(EVP_PKEY *pkey, unsigned char **out, size_t *out_len, const int selection){
    OPENSSL_DEBUG("---Key encode---\n");
    int ret = 0;
    unsigned char *buf = NULL;
    size_t buf_len;

    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", NULL, NULL);
    if(ectx == NULL){
        printf("Fail to creat encoder\n");
        goto clean;
    }
    OPENSSL_DEBUG("encode step1\n");

    if(OSSL_ENCODER_to_data(ectx, &buf, &buf_len) == 0){
        printf("Fail to encode\n");
        goto clean;
    }
    OPENSSL_DEBUG("encode step2\n");

    *out = buf;
    *out_len = buf_len;
    ret = 1;

    clean:
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_DEBUG("---Encode finish---\n");
    return ret;
}

int genkey_str(unsigned char **pubout, size_t *pubout_len, unsigned char **privout, size_t *privout_len){
    OPENSSL_DEBUG("---genkey()---\n");
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubbuf;
    size_t pubbuf_len;
    unsigned char *privbuf;
    size_t privbuf_len;

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

    OPENSSL_DEBUG("Ready to write pubkey\n");
    if(key_encode_str(pkey, &pubbuf, &pubbuf_len, EVP_PKEY_PUBLIC_KEY) <= 0){
        OPENSSL_DEBUG("Pubkey create failed\n");
        goto clean;
    }

    OPENSSL_DEBUG("Ready to write prikey\n");
    if(key_encode_str(pkey, &privbuf, &privbuf_len, EVP_PKEY_KEYPAIR) <= 0){
        OPENSSL_DEBUG("Privkey create failed\n");
        goto clean;
    }

    *pubout = pubbuf;
    *pubout_len = pubbuf_len;
    *privout = privbuf;
    *privout_len = privbuf_len;
    ret = 1;

    clean:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_DEBUG("---genkey() finish---\n");
    return ret;
}

static EVP_PKEY *load_key_str(OSSL_LIB_CTX *libctx, const unsigned char *key, size_t key_len, const int selection){
    OPENSSL_DEBUG("---Load key---\n");
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *pkey = NULL;

    OPENSSL_DEBUG("---Key decode---\n");
    dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "PEM", NULL, "RSA", selection, libctx, NULL);
    if(dctx == NULL){
        OPENSSL_DEBUG("Fail to creat decoder\n");
        pkey = NULL;
        goto clean;
    }
    OPENSSL_DEBUG("Decode step1\n");

    const unsigned char *data;
    data = key;

    if(OSSL_DECODER_from_data(dctx, &data, &key_len) <= 0){
        OPENSSL_DEBUG("Fail to decode\n");
        pkey = NULL;
        goto clean;
    }
    OPENSSL_DEBUG("Decode step2\n");

    clean:
    OSSL_DECODER_CTX_free(dctx);
    OPENSSL_DEBUG("---Decode finish---\n");
    OPENSSL_DEBUG("---Load key finish---\n");
    return pkey;
}

int do_encrypt_str(const unsigned char *pubkey, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len){
    OPENSSL_DEBUG("---Encrypt---\n");
    int ret = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    pkey = load_key_str(libctx, pubkey, strlen(pubkey), EVP_PKEY_PUBLIC_KEY);
    if(pkey == NULL){
        OPENSSL_DEBUG("Pub EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get pub EVP_PKEY\n");

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        goto clean;
    }
    if(EVP_PKEY_encrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Encrypt init failed\n");
        goto clean;
    }

    unsigned char *encrypt_data = NULL;
    size_t data_len = 0;

    if(EVP_PKEY_encrypt(ctx, NULL, &data_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Encrypt data step1 failed\n");
        goto clean;
    }
    encrypt_data = OPENSSL_zalloc(data_len);
    if(encrypt_data == NULL){
        OPENSSL_DEBUG("Malloc failed\n");
        goto clean;
    }

    if(EVP_PKEY_encrypt(ctx, encrypt_data, &data_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Encrypt data step2 failed\n");
        goto clean;
    }

    *out_len = data_len;
    *out = encrypt_data;

    OPENSSL_DEBUG("Encrypt data:\n%s\n", encrypt_data);
    ret = 1;

    clean:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---Encrypt finish---\n");
    return ret;
}

int do_decrypt_str(const unsigned char *privkey, const unsigned char *in, const size_t in_len, unsigned char **out, size_t *out_len){
    OPENSSL_DEBUG("---Decrypt---\n");
    int ret = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    pkey = load_key_str(libctx, privkey, strlen(privkey), EVP_PKEY_KEYPAIR);
    if(pkey == NULL){
        OPENSSL_DEBUG("Priv EVP_PKEY is NULL\n");
        goto clean;
    }else OPENSSL_DEBUG("Get priv EVP_PKEY\n");

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, NULL);
    if(!ctx){
        OPENSSL_DEBUG("Fail to creat ctx\n");
        goto clean;
    }
    if(EVP_PKEY_decrypt_init(ctx) <= 0){
        OPENSSL_DEBUG("Decrypt init failed\n");
        goto clean;
    }

    unsigned char *decrypt_out = NULL;
    size_t decrypt_len = 0;

    OPENSSL_DEBUG("Message befor decrypt (length = %ld)(strlen = %ld):\n%s\n", in_len, strlen(in), in);
    if(EVP_PKEY_decrypt(ctx, NULL, &decrypt_len, in, in_len) <= 0){
        OPENSSL_DEBUG("Decrypt data step1 failed\n");
        goto clean;
    }
    OPENSSL_DEBUG("Decrypted string length = %ld\n", decrypt_len);
    decrypt_out = OPENSSL_zalloc(decrypt_len);
    if(decrypt_out == NULL){
        OPENSSL_DEBUG("Malloc failed\n");
        goto clean;
    }

    int decrypt_ret = EVP_PKEY_decrypt(ctx, decrypt_out, &decrypt_len, in, in_len);
    if(decrypt_ret <= 0){
        OPENSSL_DEBUG("Decrypt data step2 failed (%d)\n", decrypt_ret);
        goto clean;
    }

    *out = decrypt_out;
    *out_len = decrypt_len;

    OPENSSL_DEBUG("Decrypt data:\n%s\n", decrypt_out);
    ret = 1;

    clean:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_DEBUG("---Decrypt finish---\n");
    return ret;
}

int pkcs8_maker_str(const unsigned char *in, const int public, unsigned char **out, size_t *out_len){
    OPENSSL_DEBUG("---Make PKCS#8 key---\n");
    int ret = 0;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY *pkey = NULL;
    FILE *tmp = NULL;
    int selection;
    char buf[2048];
    size_t buf_len;
    char *pkcs8_key = NULL;

    if(public == 1) selection = EVP_PKEY_PUBLIC_KEY;
    else selection = EVP_PKEY_KEYPAIR;

    pkey = load_key_str(libctx, in, strlen(in), selection);
    if(pkey == NULL){
        OPENSSL_DEBUG("Can't get EVP_KEY from %s\n");
        goto clean;
    }else OPENSSL_DEBUG("Get EVP_PKEY from %s\n");

    tmp = tmpfile();
    if(tmp == NULL){
        OPENSSL_DEBUG("Can't creat pkcs8 tmp file\n");
        goto clean;
    }

    if(public == 1){
        if(PEM_write_PUBKEY(tmp, pkey) <= 0){
            OPENSSL_DEBUG("Can't write pkcs8 file\n");
            fclose(tmp);
            goto clean;
        }else OPENSSL_DEBUG("Write key to pkcs8 file\n");
    }else{
        if(PEM_write_PKCS8PrivateKey(tmp, pkey, NULL, NULL, 0, NULL, NULL) <= 0){
            OPENSSL_DEBUG("Can't write pkcs8 file\n");
            fclose(tmp);
            goto clean;
        }else OPENSSL_DEBUG("Write key to pkcs8 file\n");
    }

    if(fseek(tmp, 0, SEEK_SET) != 0){
        OPENSSL_DEBUG("Can't seek pkcs8 file\n");
        fclose(tmp);
        goto clean;
    }
    buf_len = fread(buf, sizeof(char), 2048, tmp);
    OPENSSL_DEBUG("Buffer data from tmp (length = %ld) =\n%s\n", buf_len, buf);
    if(buf_len <= 0){
        OPENSSL_DEBUG("Can't read pkcs8 file\n");
        fclose(tmp);
        goto clean;
    }else{
        pkcs8_key = malloc(buf_len+1);
        strncpy(pkcs8_key, buf, buf_len);
        pkcs8_key[buf_len] = '\0';
        OPENSSL_DEBUG("Key from buffer (length = %ld) =\n%s\n", strlen(pkcs8_key), pkcs8_key);
    }

    *out = pkcs8_key;
    *out_len = strlen(pkcs8_key);
    fclose(tmp);
    ret = 1;

    clean:
    OSSL_LIB_CTX_free(libctx);
    EVP_PKEY_free(pkey);
    OSSL_LIB_CTX_free(libctx);
    OPENSSL_DEBUG("---Make PKCS#8 key finish---\n");
    return ret;
}