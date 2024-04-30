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
- `myopenssl_k` struct for save RSA keypair data
- `myopenssl_genkey()` to create RSA keypair, it will return a **myopenssl_k** pointer
    - `myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file)` will return **1 or 0** for successes or error
    - If your work is done, plase use `myopenssl_k_free(myopenssl_k *ptr)` to free the memory
- `myopenssl_encrypt/decrypt/encrypt_f/decrypt_f(const unsigned char *key/keyfile, const unsigned char *in, const size_t in_len, unsigned char *out)` for encrypt/decrypt data, it will return the output length
    - Function will do memcpy on `out`, please make sure you have enought space (256 bytes)
- `myopenssl_pkcs8(const unsigned char *in, const int public)` for create a PKCS#8 format pubkey/privkey from PKCS#1 key, it will return a **myopenssl_k** pointer
    - `myopenssl_pkcs8_f(const char *infile, const int public, const char *outfile)` will return **1 or 0** for successes or error
```c
//you RSA keys are string format
unsigned char enc[256];
unsigned char dec[256];
size_t enc_len, dec_len;

myopenssl_k *mpk = genkey();
if(!mpk) return;
printf("pubkey (length = %ld) : \n%s\n", mpk->pubkey, mpk->publen);
printf("privkey (length = %ld) : \n%s\n", mpk->privkey, mpk->privlen);

enc_len = myopenssl_encrypt(mpk->pubkey, "hello world", strlen("hello world"), enc);
if(len == 0) goto clean;
printf("encrypt data (length = %ld) : \n%s\n", enc_len, enc);
dec_len = myopenssl_decrypt(mpk->privkey, enc, enc_len, dec);
if(dec_len == 0) goto clean;
printf("decrypt data (length = %ld) : \n%s\n", dec_len, dec);

myopenssl_k *mpk8 = myopenssl_pkcs8(mpk->pubkey, 1);
if(!mpk8) goto clean;
myopenssl_k_free(mpk8);
myopenssl_k *mpk8 = myopenssl_pkcs8(mpk->privkey, 0);
if(!mpk8) goto clean;
myopenssl_k_free(mpk8);

clean:
myopenssl_k_free(mpk);
```
```c
//your RSA keys are file format
#define PUB_PATH "your pubkey file path"
#define PRIV_PATH "your privkey file path"
#define PKCS8_PATH "your PKCS#8 privkey file path"

unsigned char enc[256];
unsigned char dec[256];
size_t enc_len, dec_len;

if(genkey_f(PUB_PATH, PRIV_PATH) != 1) return;

enc_len = myopenssl_encrypt_f(PUB_PATH, "hello world", strlen("hello world"), enc);
if(enc_len == 0) return;
dec_len = myopenssl_decrypt_f(PRIV_PATH, enc, enc_len, dec);
if(dec_len == 0) return;
printf("decrypt data (length = %ld) : \n%s\n", dec_len, dec);

if(myopenssl_pkcs8_f(PRIV_PATH, 0, PKCS8_PATH) != 1) return;
```