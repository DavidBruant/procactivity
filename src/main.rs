use std::io::{Write};

use anyhow::{bail, Result};
use clap::{CommandFactory, Parser};
use nix::unistd::{fork, ForkResult};

use procactivity::args::{ArgCommand, Args};
use procactivity::{run_tracee, Tracer};



fn main() -> Result<()> {
        
    let config = Args::parse();
    let pid = if let Some(ArgCommand::Command(command)) = &config.command {
        if command.is_empty() {
            Args::command().print_help()?;
            return Ok(());
        }
        // FIXME: I suspect this breaks Rust's safety: fork() spawn a thread and that thread
        //        is accessing the same memory as the parent thread (command/env/username/config)
        match unsafe { fork() } {
            Ok(ForkResult::Child) => return run_tracee(command, &config.env, &config.username),
            Ok(ForkResult::Parent { child }) => child,
            Err(err) => bail!("fork() failed: {err}"),
        }
    } else {
        Args::command().print_help()?;
        return Ok(());
    };

    // TODO: we may also add a --color option to force colors, and a --no-color option to disable it
    let output: Box<dyn Write> = Box::new(std::io::stdout());

    Tracer::new(pid, config, output)?.run_tracer()
}
