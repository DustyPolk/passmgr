#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "manager.h"
#include "crypto.h"

#define DB_FILE "passwords.dat"

void print_help(const char *prog_name) {
    printf("Simple Secure Password Manager\n\n");
    printf("Usage: %s <command> [arguments]\n\n", prog_name);
    
    printf("Commands:\n");
    printf("  add [options] <service> <username>\n");
    printf("                             Add a new credential. You will be prompted for the password\n");
    printf("                             unless --generate is used.\n");
    printf("  get <service>              Retrieve the password for a specific service.\n");
    printf("  delete <service>           Remove a credential permanently.\n");
    printf("  list                       List all stored services and usernames.\n");
    printf("  generate [options]         Generate a secure random password.\n");
    printf("  --help, -h                 Show this help message.\n\n");

    printf("Password Generation Options (for 'add' and 'generate' commands):\n");
    printf("  --generate                 Auto-generate password instead of prompting (add only).\n");
    printf("  --strong                   Use uppercase, lowercase, digits, symbols (default).\n");
    printf("  --simple                   Use uppercase, lowercase, digits only.\n");
    printf("  --pin                      Use digits only.\n");
    printf("  --length N                 Set password length (4-128, default varies by preset).\n\n");

    printf("Examples:\n");
    printf("  1. Add a new password for Google:\n");
    printf("     %s add google.com myemail@gmail.com\n", prog_name);
    printf("     (You will be asked to enter the master password and the new credential password)\n\n");

    printf("  2. Add with auto-generated password:\n");
    printf("     %s add --generate github.com myuser\n", prog_name);
    printf("     %s add --generate --simple --length 24 github.com myuser\n\n", prog_name);

    printf("  3. Generate a password (no master password needed):\n");
    printf("     %s generate                     # Strong, 20 chars\n", prog_name);
    printf("     %s generate --simple            # Alphanumeric, 16 chars\n", prog_name);
    printf("     %s generate --pin --length 8   # 8-digit PIN\n\n", prog_name);

    printf("  4. Retrieve the password for Google:\n");
    printf("     %s get google.com\n", prog_name);
    printf("     (Outputs: Service, Username, and Password)\n\n");

    printf("  5. List all accounts:\n");
    printf("     %s list\n\n", prog_name);

    printf("  6. Delete the Google account:\n");
    printf("     %s delete google.com\n\n", prog_name);

    printf("Notes:\n");
    printf("  - The Master Password is required for all commands except 'generate'.\n");
    printf("  - The database file is '%s' created in the current directory.\n", DB_FILE);
    printf("  - Generated passwords use cryptographically secure random numbers.\n");
}

void get_password(const char *prompt, char *password, size_t len) {
    struct termios oldt, newt;
    int i = 0;
    int c;

    printf("%s", prompt);
    fflush(stdout); // Ensure prompt is displayed
    
    // Turn off echo
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while ((c = getchar()) != '\n' && c != EOF && i < (int)len - 1) {
        password[i++] = c;
    }
    password[i] = '\0';

    // Restore echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

// Parse generate command flags and return default length for preset
static size_t get_default_length(passgen_preset_t preset) {
    switch (preset) {
        case PASSGEN_STRONG: return PASSGEN_STRONG_DEFAULT_LEN;
        case PASSGEN_SIMPLE: return PASSGEN_SIMPLE_DEFAULT_LEN;
        case PASSGEN_PIN:    return PASSGEN_PIN_DEFAULT_LEN;
        default:             return PASSGEN_STRONG_DEFAULT_LEN;
    }
}

// Parse password generation flags from argv starting at index start_idx
// Returns 0 on success, -1 on error
// Sets preset and length, advances *idx past consumed arguments
static int parse_passgen_flags(int argc, char *argv[], int start_idx, 
                                passgen_preset_t *preset, size_t *length) {
    *preset = PASSGEN_STRONG;
    *length = 0; // 0 means use default

    for (int i = start_idx; i < argc; i++) {
        if (strcmp(argv[i], "--strong") == 0) {
            *preset = PASSGEN_STRONG;
        } else if (strcmp(argv[i], "--simple") == 0) {
            *preset = PASSGEN_SIMPLE;
        } else if (strcmp(argv[i], "--pin") == 0) {
            *preset = PASSGEN_PIN;
        } else if (strcmp(argv[i], "--length") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --length requires a number\n");
                return -1;
            }
            long len = strtol(argv[++i], NULL, 10);
            if (len < PASSGEN_MIN_LEN || len > PASSGEN_MAX_LEN) {
                fprintf(stderr, "Error: length must be between %d and %d\n", 
                        PASSGEN_MIN_LEN, PASSGEN_MAX_LEN);
                return -1;
            }
            *length = (size_t)len;
        } else if (argv[i][0] == '-') {
            // Unknown flag in this context - stop parsing
            break;
        } else {
            // Non-flag argument - stop parsing
            break;
        }
    }

    // Use default length if not specified
    if (*length == 0) {
        *length = get_default_length(*preset);
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_help(argv[0]);
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <command> [args]\n", argv[0]);
        fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
        return 1;
    }

    crypto_init();

    const char *cmd = argv[1];

    // Handle generate command (doesn't need master password)
    if (strcmp(cmd, "generate") == 0) {
        passgen_preset_t preset;
        size_t length;
        
        if (parse_passgen_flags(argc, argv, 2, &preset, &length) != 0) {
            return 1;
        }

        char *password = generate_password(preset, length);
        if (!password) {
            fprintf(stderr, "Failed to generate password.\n");
            return 1;
        }

        printf("%s\n", password);
        gcry_free(password); // Securely wipes and frees
        return 0;
    }

    // All other commands require master password
    char master_pass[256];
    get_password("Enter Master Password: ", master_pass, sizeof(master_pass));
    if (strlen(master_pass) == 0) {
        fprintf(stderr, "Password cannot be empty.\n");
        return 1;
    }

    if (strcmp(cmd, "add") == 0) {
        // Check for --generate flag and parse options
        int use_generate = 0;
        passgen_preset_t preset = PASSGEN_STRONG;
        size_t gen_length = 0;
        int arg_idx = 2;

        // Parse flags starting at argv[2]
        while (arg_idx < argc && argv[arg_idx][0] == '-') {
            if (strcmp(argv[arg_idx], "--generate") == 0) {
                use_generate = 1;
                arg_idx++;
            } else if (strcmp(argv[arg_idx], "--strong") == 0) {
                preset = PASSGEN_STRONG;
                arg_idx++;
            } else if (strcmp(argv[arg_idx], "--simple") == 0) {
                preset = PASSGEN_SIMPLE;
                arg_idx++;
            } else if (strcmp(argv[arg_idx], "--pin") == 0) {
                preset = PASSGEN_PIN;
                arg_idx++;
            } else if (strcmp(argv[arg_idx], "--length") == 0) {
                if (arg_idx + 1 >= argc) {
                    fprintf(stderr, "Error: --length requires a number\n");
                    return 1;
                }
                arg_idx++;
                long len = strtol(argv[arg_idx], NULL, 10);
                if (len < PASSGEN_MIN_LEN || len > PASSGEN_MAX_LEN) {
                    fprintf(stderr, "Error: length must be between %d and %d\n",
                            PASSGEN_MIN_LEN, PASSGEN_MAX_LEN);
                    return 1;
                }
                gen_length = (size_t)len;
                arg_idx++;
            } else {
                fprintf(stderr, "Unknown flag: %s\n", argv[arg_idx]);
                return 1;
            }
        }

        // After flags, we need exactly 2 more args: service and username
        if (argc - arg_idx != 2) {
            fprintf(stderr, "Usage: %s add [--generate] [--strong|--simple|--pin] [--length N] <service> <username>\n", argv[0]);
            return 1;
        }

        const char *service = argv[arg_idx];
        const char *username = argv[arg_idx + 1];

        char *generated_pass = NULL;
        char manual_pass[256];
        const char *cred_password;

        if (use_generate) {
            // Use default length if not specified
            if (gen_length == 0) {
                gen_length = get_default_length(preset);
            }

            generated_pass = generate_password(preset, gen_length);
            if (!generated_pass) {
                fprintf(stderr, "Failed to generate password.\n");
                return 1;
            }
            cred_password = generated_pass;
            printf("Generated password: %s\n", generated_pass);
        } else {
            char prompt[512];
            snprintf(prompt, sizeof(prompt), "Enter password for %s: ", service);
            get_password(prompt, manual_pass, sizeof(manual_pass));
            cred_password = manual_pass;
        }

        int result = add_credential(DB_FILE, master_pass, service, username, cred_password);
        
        // Secure cleanup
        if (generated_pass) {
            gcry_free(generated_pass); // Securely wipes and frees
        } else {
            memset(manual_pass, 0, sizeof(manual_pass));
        }

        if (result == 0) {
            printf("Credential added successfully.\n");
        } else {
            fprintf(stderr, "Failed to add credential.\n");
            return 1;
        }
    } else if (strcmp(cmd, "get") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s get <service>\n", argv[0]);
            return 1;
        }
        credential_t *c = get_credential(DB_FILE, master_pass, argv[2]);
        if (c) {
            printf("Service: %s\nUsername: %s\nPassword: %s\n", c->service, c->username, c->password);
            free(c->service); free(c->username); free(c->password); free(c);
        } else {
            fprintf(stderr, "Credential not found or decryption failed.\n");
            return 1;
        }
    } else if (strcmp(cmd, "delete") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: %s delete <service>\n", argv[0]);
            return 1;
        }
        if (delete_credential(DB_FILE, master_pass, argv[2]) == 0) {
            printf("Credential deleted successfully.\n");
        } else {
            fprintf(stderr, "Failed to delete credential (not found or error).\n");
            return 1;
        }
    } else if (strcmp(cmd, "list") == 0) {
        int count;
        credential_t **creds = load_credentials(DB_FILE, master_pass, &count);
        if (creds) {
            printf("Stored Services:\n");
            for (int i = 0; i < count; i++) {
                printf("- %s (%s)\n", creds[i]->service, creds[i]->username);
            }
            free_credentials(creds, count);
        } else {
            fprintf(stderr, "Failed to load credentials (or empty).\n");
            return 1;
        }
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        return 1;
    }

    return 0;
}
