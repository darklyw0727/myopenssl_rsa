### INSTALL
1. Install openssl
2. `make`

- Depands on openssl 1.1.1

### HOW TO USE
- `myopenssl_k` struct for save RSA keypair data
- `myopenssl_genkey()` to create RSA keypair, it will return a **myopenssl_k** pointer
    - `myopenssl_genkey_f(const char *pubkey_file, const char *privkey_file)` will return **1 or 0** for successes or error
    - They will create PKCS#8 keys
    - If your work is done, plase use `myopenssl0_free_k(myopenssl_k *ptr)` to free the memory
- `myopenssl_encrypt/decrypt/encrypt_f/decrypt_f(char *pubkey, const size_t key_len, unsigned char *in, const size_t in_len, size_t *out_len)` for encrypt/decrypt data
    - If work success, it will malloc a memory with encrypt/decrypt result and return it
    - If your work is done, plase use `myopenssl_free(unsigned char *in)` to free the memory