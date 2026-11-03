//! Binary entry point for `passmgr`; the CLI lives in `src/cli/`.

mod cli;

fn main() -> std::process::ExitCode {
    cli::main()
}
