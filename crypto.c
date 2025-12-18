#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <gpg-error.h>
#include "crypto.h"

#define ITERATIONS 600000

void crypto_init(void) {
    if (!gcry_check_version(GCRYPT_VERSION)) {
        fprintf(stderr, "libgcrypt version mismatch\n");
        exit(1);
    }
    // Attempt to enable secure memory. 
    // If it fails (e.g. strict limits), we proceed but warn if critical.
    // For this simple tool, we just request it.
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); 
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

int derive_key(const char *password, const uint8_t *salt, uint8_t *key) {
    gpg_error_t err;
    err = gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2,
                          GCRY_MD_SHA256, salt, SALT_LEN, ITERATIONS, KEY_LEN, key);
    if (err) {
        fprintf(stderr, "Key derivation failed: %s\n", gpg_strerror(err));
        return -1;
    }
    return 0;
}

encrypted_blob_t *encrypt_data(const uint8_t *plaintext, size_t len, const char *password) {
    encrypted_blob_t *blob = malloc(sizeof(encrypted_blob_t));
    if (!blob) return NULL;

    // 1. Generate Salt
    gcry_randomize(blob->salt, SALT_LEN, GCRY_STRONG_RANDOM);

    // 2. Derive Key
    uint8_t key[KEY_LEN];
    if (derive_key(password, blob->salt, key) != 0) {
        free(blob);
        return NULL;
    }

    // 3. Generate IV
    gcry_randomize(blob->iv, IV_LEN, GCRY_STRONG_RANDOM);

    // 4. Setup Cipher (AES256-GCM)
    gcry_cipher_hd_t hd;
    gpg_error_t err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
    if (err) {
        fprintf(stderr, "Cipher open failed: %s\n", gpg_strerror(err));
        free(blob);
        return NULL;
    }

    err = gcry_cipher_setkey(hd, key, KEY_LEN);
    if (err) {
        fprintf(stderr, "Set key failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        free(blob);
        return NULL;
    }

    err = gcry_cipher_setiv(hd, blob->iv, IV_LEN);
    if (err) {
        fprintf(stderr, "Set IV failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        free(blob);
        memset(key, 0, KEY_LEN); // Wipe key
        return NULL;
    }

    // 5. Encrypt
    blob->data_len = len;
    blob->data = malloc(len);
    if (!blob->data) {
        gcry_cipher_close(hd);
        free(blob);
        memset(key, 0, KEY_LEN); // Wipe key
        return NULL;
    }

    err = gcry_cipher_encrypt(hd, blob->data, len, plaintext, len);
    if (err) {
        fprintf(stderr, "Encryption failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        free(blob->data);
        free(blob);
        memset(key, 0, KEY_LEN); // Wipe key
        return NULL;
    }

    // 6. Get Tag
    err = gcry_cipher_gettag(hd, blob->tag, TAG_LEN);
    if (err) {
        fprintf(stderr, "Get tag failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        free(blob->data);
        free(blob);
        memset(key, 0, KEY_LEN); // Wipe key
        return NULL;
    }

    gcry_cipher_close(hd);
    memset(key, 0, KEY_LEN); // Wipe key
    return blob;
}

uint8_t *decrypt_data(const encrypted_blob_t *blob, size_t *out_len, const char *password) {
    // 1. Derive Key
    uint8_t key[KEY_LEN];
    if (derive_key(password, blob->salt, key) != 0) {
        return NULL;
    }

    // 2. Setup Cipher
    gcry_cipher_hd_t hd;
    gpg_error_t err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_GCM, 0);
    if (err) {
        fprintf(stderr, "Cipher open failed: %s\n", gpg_strerror(err));
        return NULL;
    }

    err = gcry_cipher_setkey(hd, key, KEY_LEN);
    if (err) {
        fprintf(stderr, "Set key failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        return NULL;
    }

    err = gcry_cipher_setiv(hd, blob->iv, IV_LEN);
    if (err) {
        fprintf(stderr, "Set IV failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        memset(key, 0, KEY_LEN);
        return NULL;
    }

    // 3. Decrypt
    uint8_t *plaintext = malloc(blob->data_len + 1); // +1 for null terminator safety
    if (!plaintext) {
        gcry_cipher_close(hd);
        memset(key, 0, KEY_LEN);
        return NULL;
    }

    err = gcry_cipher_decrypt(hd, plaintext, blob->data_len, blob->data, blob->data_len);
    if (err) {
        fprintf(stderr, "Decryption failed: %s\n", gpg_strerror(err));
        gcry_cipher_close(hd);
        free(plaintext);
        memset(key, 0, KEY_LEN);
        return NULL;
    }

    // 4. Check Tag
    err = gcry_cipher_checktag(hd, blob->tag, TAG_LEN);
    if (err) {
        // Tag mismatch means wrong password or tampered data
        // Don't print "Tag check failed" to user, just generic error or NULL
        // But for debug/this cli, we can be slightly verbose or just return NULL
        gcry_cipher_close(hd);
        free(plaintext);
        memset(key, 0, KEY_LEN);
        return NULL;
    }

    gcry_cipher_close(hd);
    memset(key, 0, KEY_LEN);
    plaintext[blob->data_len] = '\0'; // Null terminate
    *out_len = blob->data_len;
    return plaintext;
}

void free_blob(encrypted_blob_t *blob) {
    if (blob) {
        if (blob->data) free(blob->data);
        free(blob);
    }
}

// Character sets for password generation
static const char CHARSET_STRONG[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!@#$%^&*()-_=+[]{}";

static const char CHARSET_SIMPLE[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789";

static const char CHARSET_PIN[] = "0123456789";

char *generate_password(passgen_preset_t preset, size_t length) {
    const char *charset;
    size_t charset_len;

    // Select character set based on preset
    switch (preset) {
        case PASSGEN_STRONG:
            charset = CHARSET_STRONG;
            charset_len = sizeof(CHARSET_STRONG) - 1; // exclude null terminator
            break;
        case PASSGEN_SIMPLE:
            charset = CHARSET_SIMPLE;
            charset_len = sizeof(CHARSET_SIMPLE) - 1;
            break;
        case PASSGEN_PIN:
            charset = CHARSET_PIN;
            charset_len = sizeof(CHARSET_PIN) - 1;
            break;
        default:
            return NULL;
    }

    // Validate length
    if (length < PASSGEN_MIN_LEN || length > PASSGEN_MAX_LEN) {
        return NULL;
    }

    // Allocate from secure memory (mlock'd, won't swap to disk)
    char *password = gcry_malloc_secure(length + 1);
    if (!password) {
        fprintf(stderr, "Failed to allocate secure memory for password\n");
        return NULL;
    }

    // Calculate rejection threshold for unbiased sampling
    // We reject values >= (256 / charset_len) * charset_len to avoid modulo bias
    unsigned int threshold = 256 - (256 % charset_len);

    for (size_t i = 0; i < length; i++) {
        unsigned char rand_byte;
        
        // Rejection sampling: keep generating until we get an unbiased value
        do {
            gcry_randomize(&rand_byte, 1, GCRY_STRONG_RANDOM);
        } while (rand_byte >= threshold);

        password[i] = charset[rand_byte % charset_len];
    }

    password[length] = '\0';
    return password;
}
