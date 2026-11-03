//! The `--help` and usage text.

pub(crate) const USAGE: &str = "Usage: passmgr [--db PATH] [--agent] <command> [arguments]
Try 'passmgr --help' for more information.";

pub(crate) const HELP: &str = r#"Simple Secure Password Manager (Rust)

Usage: passmgr [--db PATH] [--agent] <command> [arguments]

Commands:
  add [options] <service> <username>
                             Add a credential. The credential password is
                             prompted (and confirmed) unless --generate is used.
                             With --generate the password is stored but never
                             printed; only the entry name is confirmed.
                             --tag TAG (repeatable) attaches a label for
                             filtering and future grant scopes.
  get [--reveal] <service>   Show credential metadata. Allowed flags:
                               --reveal   Print the password. Human use only:
                                          stdin and stdout must both be a
                                          terminal and no agent environment
                                          marker (PASSMGR_AGENT, CLAUDECODE,
                                          CURSOR_AGENT, CODEX_SANDBOX) may be
                                          set, and --agent must not be passed.
                                          Otherwise the command is refused
                                          with exit code 5. There is no
                                          bypass flag.
  delete <service>           Remove a credential permanently.
  rm <service>               Alias for delete.
  edit [options] <service>   Update a credential. Without a metadata flag
                             (--username, --rename, --tag, --clear-tags) the
                             password is rotated: the new value is prompted
                             twice and never printed.
                             Allowed flags:
                               --username U   Set the username.
                               --rename NAME  Rename the service.
                               --tag TAG      Replace the tag set
                                              (repeatable).
                               --clear-tags   Remove all tags.
                               --generate     Generate a new password instead
                                              of prompting (implies rotation).
                               --strong, --simple, --pin, --length N
                                              Generation options for --generate.
  list [--json] [--tag TAG] List stored services, usernames, references and
                             tags. --tag filters to entries that carry every
                             given tag and is repeatable. With --json, print
                             {"entries":[...]} where each entry has "ref",
                             "service", "username", "tags", "created" and
                             "last_rotated".
  show [--json] <ref>        Show one credential by its pm:// reference.
                             Metadata only, no password. --json prints the
                             entry object directly.
  generate [options]         Generate a secure random password.
  unlock [--idle-timeout SECS]
                             Derive the vault key and start the unlock daemon.
                             Human use only: stdin and stdout must both be a
                             terminal and no agent environment marker may be
                             set, otherwise the command is refused with exit
                             code 5. The master password is prompted once;
                             the derived key reaches the daemon through a
                             pipe, never through argv or this process's
                             output. The daemon wipes its key and stops
                             after SECS without activity (default: 900).
  lock                       Ask the unlock daemon to wipe its key and stop.
                             Requires no terminal: it only shuts the daemon
                             down, so an agent may use it.
  run --env NAME=<ref> -- <command> [args...]
                             Run <command> with the secret from the referenced
                             credential injected as the environment variable
                             NAME. The daemon injects it: no secret passes
                             through this process, and the child's stdout and
                             stderr are relayed with an exact, contiguous
                             occurrence of the secret replaced by [REDACTED].
                             Encoded or transformed copies (base64, hex,
                             percent-encoding, case changes) are not
                             replaced. passmgr exits with the child's status,
                             or 128+N when the child was killed by signal N.
                             Needs a running unlock daemon; the master
                             password is not prompted, so this is the
                             agent-facing way to use a secret. NAME must be a
                             valid variable name and may not be a loader or
                             shell-hook variable (PATH, LD_*, BASH_ENV, ...).
                             The command is executed directly, never through a
                             shell string; it receives a small fixed inherited
                             environment (PATH, HOME, USER, LOGNAME, LANG,
                             TZ, TMPDIR, TERM, LC_*) plus NAME.
                             A relative program or argument is resolved against
                             the caller's working directory and PATH, never the
                             daemon's (which belong to the shell that ran
                             'unlock'), and the child starts in the caller's
                             working directory. An unresolvable program is a
                             usage error (exit 2).
  help                       Show this help.
  version                    Show version information.

Global options:
  --db PATH                  Vault file (default: ./passwords.dat, or $PASSMGR_DB).
  --agent                    Force agent mode. This can only make the tool more
                             restrictive: 'get --reveal' is refused even on a
                             terminal. It never reveals a secret by itself.
  -h, --help                 Show this help.
  -V, --version              Show version information.

Password generation options (add/edit/generate):
  --generate                 Generate the password instead of prompting (add/edit only).
  --strong                   Uppercase, lowercase, digits, symbols (default).
  --simple                   Uppercase, lowercase, digits only.
  --pin                      Digits only.
  --length N                 Length 4-128 (defaults: strong 20, simple 16, pin 6).

Examples:
  passmgr add github.com octocat
  passmgr add --tag work --tag prod github.com octocat
  passmgr add --generate --simple --length 24 github.com octocat
  passmgr edit --generate github.com
  passmgr edit --rename github.example github.com
  passmgr edit --tag work github.com
  passmgr generate --pin --length 8
  passmgr get github.com
  passmgr list
  passmgr list --tag prod
  passmgr list --json
  passmgr show pm://0123456789abcdef0123456789abcdef
  passmgr unlock --idle-timeout 300
  passmgr lock
  passmgr run --env GH_TOKEN=pm://0123456789abcdef0123456789abcdef \
      -- gh auth status
  passmgr --db ~/.secrets/work.dat list

Notes:
  - The master password is required for every command except generate/help/version.
  - Prompts are written to stderr; command data is written to stdout.
  - 'add --generate' never prints the generated password; read it back with
    the TTY-gated 'get --reveal'.
  - Every credential has a stable reference 'pm://<32 hex characters>', shown
    by 'list' and 'get'. A reference identifies an entry for agents and tools
    without revealing any secret, and survives renames. 'show' accepts only a
    full reference, never a service name.
  - 'list --json' and 'show --json' emit references and metadata only; there
    is no JSON field that carries a password. "created" and "last_rotated"
    are RFC 3339 UTC strings, or null when the timestamp is unknown.
  - Tags are lowercase labels: 1-32 bytes starting with a letter or digit, then
    [a-z0-9._-]; at most 32 per credential. They are metadata, never secrets.
  - Tags are metadata, not secrets. They are lowercase letters, digits, '-',
    '_' and '.', at most 32 bytes, and at most 32 per credential. Tags are
    stored sorted; 'list --tag' requires every given tag to match.
  - 'edit' never prints the new password either; rotating prompts for it
    twice, and a generated one is only confirmed by name.
  - Creating a new vault asks for the master password twice.
  - global options (--db, --agent) must come before the command.
  - Exit codes are stable: 0 success, 1 runtime failure, 2 usage or invalid
    input, 3 not found, 4 wrong master password, 5 refused (for example
    'get --reveal' without a terminal, in an agent context, or with --agent),
    6 malformed, truncated or unsupported vault file.
  - 'unlock' starts a per-user background daemon that keeps the vault key in
    memory, so later commands do not prompt again. The daemon listens on a
    socket inside $XDG_RUNTIME_DIR/passmgr that only the owning user can
    connect to, and it has no request that returns plaintext. Clients
    authenticate with the session token that 'unlock' writes to
    session in that directory (mode 0600); 'lock' removes it. The token is a
    local convenience, not a human/agent boundary. The daemon stops on
    'lock', on SIGTERM/SIGINT, or after the idle timeout (default 15 minutes,
    set with 'unlock --idle-timeout SECS').
  - 'run' needs the unlock daemon ('run' refuses with exit code 1 when it is
    not running). Its child receives only the fixed inherited environment
    listed above, then NAME; it never inherits the rest of the caller's
    environment. The secret is used, not read: output is redacted, and
    nothing on this side of the daemon ever holds the value.
  - Vaults are encrypted with Argon2id and AES-256-GCM.
  - The legacy C vault format is not readable; this version uses a new format.
"#;
