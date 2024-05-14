### INSTALL
1. Install openssl
2. `make`

- Depands on openssl 1.1.1

### HOW TO USE
- `myopenssl_k` struct for save RSA keypair data
- `myopenssl_genkey()` to create RSA keypair, it will return a **myopenssl_k** pointer
    - `myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file)` will return **1 or 0** for successes or error
    - They will create PKCS#8 keys
    - If your work is done, plase use `myopenssl_k_free(myopenssl_k *ptr)` to free the memory
- `myopenssl_encrypt/decrypt/encrypt_f/decrypt_f(const unsigned char *key/keyfile, const unsigned char *in, const size_t in_len, unsigned char *out)` for encrypt/decrypt data, it will return the output length
    - Function will do memcpy on `out`, please make sure you have enought space (256 bytes) and the space clean