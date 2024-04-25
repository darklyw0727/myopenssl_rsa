### INSTALL
1. Install openssl
2. `make`

- Depands on openssl 3.0
    - Manpage : - Depands on https://github.com/babelouest/rhonabwy
- demo for create RSA keys / encrypt / decrypt in PEM format "file"
    - include base64 encode / decode
- str_demo for create RSA keys / encrypt / decrypt in PEM format "string"
    - include base64url encode / decode

### HOW TO USE
- `myopenssl_d` for save encrypt/decrypt data
- `myopenssl_k` for save RSA keypair
- `myopenssl_genkey()` to create RSA keypair, it will return a **myopenssl_k** pointer
    - `myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file)` will return **1 or 0** for successes or error
- `myopenssl_encrypt/decrypt/encrypt_f/decrypt_f(const unsigned char *key/keyfile, const unsigned char *in, const size_t in_len)` for encrypt/decrypt data, it will return a **myopenssl_d** pointer
- `myopenssl_pkcs8(const unsigned char *in, const int public)` for create a PKCS#8 format pubkey/privkey from PKCS#1 key, it will return a **myopenssl_k** pointer
    - `myopenssl_genkey_f(const char *infile, const int public, const char *outfile)` will return **1 or 0** for successes or error
```c
//you RSA keys are string format
myopenssl_k *mpk = genkey();
if(!mpk) return;
printf("pubkey (length = %ld) : \n%s\n", mpk->pubkey, mpk->publen);
printf("privkey (length = %ld) : \n%s\n", mpk->privkey, mpk->privlen);

myopenssl_d *mp_enc = myopenssl_encrypt(mpk->pubkey, "hello world", strlen("hello world"));
if(!mp_enc) goto clean1;
myopenssl_d *mp_dec = myopenssl_decrypt(mpk->privkey, mp_enc->data, mp_enc->data_len);
if(!mp_dec) goto clean2;
printf("decrypt data (length = %ld) : \n%s\n", mp_dec->data_len, mp_dec->data);

myopenssl_k *mpk8 = myopenssl_pkcs8(mpk->pubkey, 1);
if(!mpk8) goto clean3;

myopenssl_k_free(mpk8);
clean3:
myopenssl_d_free(mp_dec);
clean2:
myopenssl_d_free(mp_enc);
clean1:
myopenssl_k_free(mpk);
```
```c
//your RSA keys are file format
#define PUB_PATH "your pubkey file path"
#define PRIV_PATH "your privkey file path"
#define PKCS8_PATH "your PKCS#8 privkey file path"

if(genkey_f(PUB_PATH, PRIV_PATH) != 1) return;

myopenssl_d *mp_enc = myopenssl_encrypt_f(PUB_PATH, "hello world", strlen("hello world"));
if(!mp_enc) return;
myopenssl_d *mp_dec = myopenssl_decrypt_f(PRIV_PATH, mp_enc->data, mp_enc->data_len);
if(!mp_dec) goto clean1;
printf("decrypt data (length = %ld) : \n%s\n", mp_dec->data_len, mp_dec->data);

if(myopenssl_pkcs8_f(PRIV_PATH, 0, PKCS8_PATH) != 1) goto clean2;

clean2:
myopenssl_d_free(mp_dec);
clean1:
myopenssl_d_free(mp_enc);
```