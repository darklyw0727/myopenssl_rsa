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
- myopenssl_d for save encrypt/decrypt data
- myopenssl_k for save RSA keypair
- myopenssl_genkey() to create RSA keypair, it will return a myopenssl_k pointer
```c
myopenssl_k *mpk = genkey();
printf("pubkey (length = %d) : \n%s\n", mpk->pubkey, mpk->publen);
printf("privkey (length = %d) : \n%s\n", mpk->privkey, mpk->privlen);
```