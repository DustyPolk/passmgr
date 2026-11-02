#ifndef MANAGER_H
#define MANAGER_H

#include "crypto.h"

typedef struct {
    char *service;
    char *username;
    char *password;
} credential_t;

// Load all credentials from file
// Returns array of credentials (terminated by NULL entry or count), or NULL on error/empty
credential_t **load_credentials(const char *filename, const char *password, int *count);

// Save all credentials to file
int save_credentials(const char *filename, const char *password, credential_t **creds, int count);

// Add a new credential
int add_credential(const char *filename, const char *password, const char *service, const char *user, const char *pass);

// Get a credential by service
credential_t *get_credential(const char *filename, const char *password, const char *service);

// Delete a credential by service
int delete_credential(const char *filename, const char *password, const char *service);

// Free credential array
void free_credentials(credential_t **creds, int count);

#endif
