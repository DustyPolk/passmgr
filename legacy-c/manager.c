#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "manager.h"
#include "crypto.h"

#define MAGIC "PMGR"
#define VERSION 1

// --- Helper: Read/Write Encrypted File ---

static int write_blob_to_file(const char *filename, encrypted_blob_t *blob) {
    // Open with secure permissions (0600)
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open write");
        return -1;
    }

    FILE *f = fdopen(fd, "wb");
    if (!f) {
        perror("fdopen");
        close(fd);
        return -1;
    }

    fwrite(MAGIC, 1, 4, f);
    uint8_t ver = VERSION;
    fwrite(&ver, 1, 1, f);
    fwrite(blob->salt, 1, SALT_LEN, f);
    fwrite(blob->iv, 1, IV_LEN, f);
    fwrite(blob->tag, 1, TAG_LEN, f);
    
    uint32_t len = (uint32_t)blob->data_len;
    fwrite(&len, sizeof(uint32_t), 1, f);
    fwrite(blob->data, 1, blob->data_len, f);

    fclose(f); // This also closes fd
    return 0;
}

#define MAX_DATA_SIZE (10 * 1024 * 1024) // 10MB limit

static encrypted_blob_t *read_blob_from_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL; // File doesn't exist or cant read

    char magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, MAGIC, 4) != 0) {
        fclose(f);
        return NULL; // Not our file
    }
    
    uint8_t ver;
    if (fread(&ver, 1, 1, f) != 1 || ver != VERSION) {
        fclose(f);
        return NULL; // Wrong version
    }

    encrypted_blob_t *blob = malloc(sizeof(encrypted_blob_t));
    if (fread(blob->salt, 1, SALT_LEN, f) != SALT_LEN) { free(blob); fclose(f); return NULL; }
    if (fread(blob->iv, 1, IV_LEN, f) != IV_LEN) { free(blob); fclose(f); return NULL; }
    if (fread(blob->tag, 1, TAG_LEN, f) != TAG_LEN) { free(blob); fclose(f); return NULL; }
    
    uint32_t len;
    if (fread(&len, sizeof(uint32_t), 1, f) != 1) { free(blob); fclose(f); return NULL; }
    
    if (len > MAX_DATA_SIZE) {
        fprintf(stderr, "Error: Data size too large (corrupted file?)\n");
        free(blob);
        fclose(f);
        return NULL;
    }
    blob->data_len = len;

    blob->data = malloc(len);
    if (fread(blob->data, 1, len, f) != len) {
        free(blob->data);
        free(blob);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return blob;
}

// --- Helper: Parse/Serialize Credentials ---

static credential_t **parse_creds(char *text, int *count) {
    // Estimate count
    int lines = 0;
    for (char *p = text; *p; p++) if (*p == '\n') lines++;
    
    credential_t **creds = malloc(sizeof(credential_t*) * (lines + 1));
    *count = 0;

    char *line = strtok(text, "\n");
    while (line) {
        // format: service:username:password
        char *serv = line;
        char *user = strchr(serv, ':');
        if (!user) { line = strtok(NULL, "\n"); continue; }
        *user = '\0'; user++;
        
        char *pass = strchr(user, ':');
        if (!pass) { line = strtok(NULL, "\n"); continue; }
        *pass = '\0'; pass++;

        credential_t *c = malloc(sizeof(credential_t));
        c->service = strdup(serv);
        c->username = strdup(user);
        c->password = strdup(pass);
        creds[(*count)++] = c;

        line = strtok(NULL, "\n");
    }
    return creds;
}

static char *creds_to_text(credential_t **creds, int count) {
    size_t total_len = 0;
    for (int i = 0; i < count; i++) {
        total_len += strlen(creds[i]->service) + strlen(creds[i]->username) + strlen(creds[i]->password) + 3; // 2 colons + newline
    }
    
    char *text = malloc(total_len + 1);
    if (!text) return NULL; // Handle malloc failure
    text[0] = '\0'; // Ensure null-termination

    char *p = text;
    for (int i = 0; i < count; i++) {
        int written = snprintf(p, total_len + 1 - (p - text), "%s:%s:%s\n", creds[i]->service, creds[i]->username, creds[i]->password);
        if (written < 0) break; 
        p += written;
    }
    return text;
}

// --- Public Interface ---

void free_credentials(credential_t **creds, int count) {
    if (!creds) return;
    for (int i = 0; i < count; i++) {
        if (creds[i]->service) {
            memset(creds[i]->service, 0, strlen(creds[i]->service));
            free(creds[i]->service);
        }
        if (creds[i]->username) {
            memset(creds[i]->username, 0, strlen(creds[i]->username));
            free(creds[i]->username);
        }
        if (creds[i]->password) {
            memset(creds[i]->password, 0, strlen(creds[i]->password));
            free(creds[i]->password);
        }
        free(creds[i]);
    }
    free(creds);
}

credential_t **load_credentials(const char *filename, const char *password, int *count) {
    *count = 0;
    encrypted_blob_t *blob = read_blob_from_file(filename);
    if (!blob) {
        return NULL;
    }

    size_t plain_len;
    uint8_t *plain = decrypt_data(blob, &plain_len, password);
    free_blob(blob);

    if (!plain) {
        fprintf(stderr, "Decryption failed (Wrong password or corrupted file)\n");
        return NULL;
    }

    credential_t **creds = parse_creds((char*)plain, count);
    
    // Wipe and free plaintext
    memset(plain, 0, plain_len);
    free(plain);
    return creds;
}

int save_credentials(const char *filename, const char *password, credential_t **creds, int count) {
    char *text = creds_to_text(creds, count);
    if (!text) return -1; // Malloc failed

    encrypted_blob_t *blob = encrypt_data((uint8_t*)text, strlen(text), password);
    free(text);
    
    if (!blob) return -1;

    int ret = write_blob_to_file(filename, blob);
    free_blob(blob);
    return ret;
}

int add_credential(const char *filename, const char *password, const char *service, const char *user, const char *pass) {
    int count;
    credential_t **creds = load_credentials(filename, password, &count);
    // If load failed but file exists, we shouldn't overwrite.
    // Check if file exists first? 
    // load_credentials returns NULL on file missing OR decrypt fail.
    // If decrypt fail, we must STOP.
    
    // Safety check: try to read blob. If it exists but decrypt failed, load_credentials returns NULL.
    // If blob read failed (no file), it returns NULL.
    // We need to distinguish.
    FILE *f = fopen(filename, "rb");
    if (f) {
        fclose(f);
        if (!creds) return -1; // Exists but decrypt failed
    }
    // If creds is NULL here and file didn't exist, we start fresh.
    
    // Realloc or create new array
    credential_t **new_creds = realloc(creds, sizeof(credential_t*) * (count + 1));
    if (!new_creds) return -1; // realloc failed
    creds = new_creds;

    credential_t *c = malloc(sizeof(credential_t));
    c->service = strdup(service);
    c->username = strdup(user);
    c->password = strdup(pass);
    creds[count] = c;
    count++;

    int ret = save_credentials(filename, password, creds, count);
    free_credentials(creds, count);
    return ret;
}

credential_t *get_credential(const char *filename, const char *password, const char *service) {
    int count;
    credential_t **creds = load_credentials(filename, password, &count);
    if (!creds) return NULL;

    credential_t *found = NULL;
    for (int i = 0; i < count; i++) {
        if (strcmp(creds[i]->service, service) == 0) {
            found = malloc(sizeof(credential_t));
            found->service = strdup(creds[i]->service);
            found->username = strdup(creds[i]->username);
            found->password = strdup(creds[i]->password);
            break;
        }
    }
    free_credentials(creds, count);
    return found;
}

int delete_credential(const char *filename, const char *password, const char *service) {
    int count;
    credential_t **creds = load_credentials(filename, password, &count);
    if (!creds) return -1;

    int found_idx = -1;
    for (int i = 0; i < count; i++) {
        if (strcmp(creds[i]->service, service) == 0) {
            found_idx = i;
            break;
        }
    }

    if (found_idx == -1) {
        free_credentials(creds, count);
        return -1; // Not found
    }

    // Free the deleted one
    free(creds[found_idx]->service);
    free(creds[found_idx]->username);
    free(creds[found_idx]->password);
    free(creds[found_idx]);

    // Shift rest
    for (int i = found_idx; i < count - 1; i++) {
        creds[i] = creds[i+1];
    }
    count--;

    int ret = save_credentials(filename, password, creds, count);
    free_credentials(creds, count); // This technically frees the pointers which we just shifted... 
    // Wait, free_credentials frees creds[i]. If we shifted, we have duplicate pointers if we didn't NULL the last one?
    // Actually, we reduced 'count'. free_credentials loops up to 'count'.
    // The shifted pointers are valid. The last pointer (now outside count) is dangling in the array but ignored.
    // Correct.
    return ret;
}
