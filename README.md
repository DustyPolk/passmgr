# Simple Secure Password Manager (C)

A lightweight, local command-line password manager written in C. It uses **AES-256-GCM** for encryption and **PBKDF2** for secure key derivation, ensuring your credentials remain safe.

## Features

-   **Strong Encryption**: Uses AES-256 in Galois/Counter Mode (GCM) for authenticated encryption.
-   **Secure Key Derivation**: Uses PBKDF2 (SHA-256) with 600,000 iterations and a random salt to protect against brute-force attacks.
-   **Memory Safety**: Explicitly wipes sensitive data (passwords, keys) from memory after use.
-   **Secure Storage**: Database file is created with strict permissions (0600), readable only by the owner.
-   **No Argument Leaks**: Passwords are prompted interactively and securely (no echo), ensuring they don't appear in shell history.
-   **Dependencies**: Built on top of `libgcrypt` and `libgpg-error`.

## Prerequisites

You need a C compiler (`gcc`) and the GnuPG development libraries.

### Linux (Debian/Ubuntu)
```bash
sudo apt update
sudo apt install build-essential libgcrypt20-dev libgpg-error-dev
```

### macOS (Homebrew)
```bash
brew install libgcrypt libgpg-error
```

## Building

Clone the repository and run `make`:

```bash
git clone https://github.com/DustyPolk/passmgr.git
cd passmgr
make
```

This produces the `passmgr` binary.

## Usage

### 1. Add a Credential
Add a new service. You will be securely prompted for the Master Password (to unlock the DB) and then the password for the service.

```bash
./passmgr add google.com myemail@gmail.com
```

### 2. Get a Credential
Retrieve a password.

```bash
./passmgr get google.com
# Output:
# Service: google.com
# Username: myemail@gmail.com
# Password: <decrypted_password>
```

### 3. List Credentials
See all stored accounts (usernames and services only).

```bash
./passmgr list
```

### 4. Delete a Credential
Remove an entry permanently.

```bash
./passmgr delete google.com
```

### 5. Help
View all commands and options.

```bash
./passmgr --help
```

## Security Implementation

-   **Initialization Vector (IV)**: A unique 12-byte random IV is generated for every save operation.
-   **Salt**: A unique 16-byte random salt is generated for the PBKDF2 derivation.
-   **Auth Tag**: The GCM authentication tag verifies the integrity of the data, preventing tampering.
-   **Memory**: `mlock` (via `libgcrypt` secure memory) is requested to prevent swapping sensitive data to disk. Buffers are `memset` to zero immediately after use.

## License

MIT License
