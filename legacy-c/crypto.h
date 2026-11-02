#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <gpg-error.h>
#include <gcrypt.h>

#define SALT_LEN 16
#define IV_LEN 12
#define TAG_LEN 16
#define KEY_LEN 32 // AES-256

// Structure to hold encrypted data container
typedef struct {
    uint8_t salt[SALT_LEN];
    uint8_t iv[IV_LEN];
    uint8_t tag[TAG_LEN];
    size_t data_len;
    uint8_t *data; // Ciphertext
} encrypted_blob_t;

// Initialize the crypto library
void crypto_init(void);

// Derive a key from a password using PBKDF2
// Returns 0 on success
int derive_key(const char *password, const uint8_t *salt, uint8_t *key);

// Encrypt plaintext
// Returns a blob on success (caller must free blob.data), NULL on failure
encrypted_blob_t *encrypt_data(const uint8_t *plaintext, size_t len, const char *password);

// Decrypt blob
// Returns pointer to plaintext (caller must free), NULL on failure
uint8_t *decrypt_data(const encrypted_blob_t *blob, size_t *out_len, const char *password);

// Helper to free blob
void free_blob(encrypted_blob_t *blob);

// Password generation presets
typedef enum {
    PASSGEN_STRONG,  // uppercase, lowercase, digits, symbols
    PASSGEN_SIMPLE,  // uppercase, lowercase, digits
    PASSGEN_PIN      // digits only
} passgen_preset_t;

// Default lengths for each preset
#define PASSGEN_STRONG_DEFAULT_LEN 20
#define PASSGEN_SIMPLE_DEFAULT_LEN 16
#define PASSGEN_PIN_DEFAULT_LEN 6
#define PASSGEN_MIN_LEN 4
#define PASSGEN_MAX_LEN 128

// Generate a secure password using CSPRNG
// Returns secure-allocated string (caller must gcry_free()), NULL on failure
char *generate_password(passgen_preset_t preset, size_t length);

#endif
