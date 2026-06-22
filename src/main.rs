use std::io::{Write};

use anyhow::{Result, bail};
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
            Ok(ForkResult::Child) => return run_tracee(command),
            Ok(ForkResult::Parent { child }) => child,
            Err(err) => bail!("fork() failed: {err}"),
        }
    } else {
        Args::command().print_help()?;
        return Ok(());
    };

    // TODO: we may also add a --color option to force colors, and a --no-color option to disable it
    let output: Box<dyn Write> = Box::new(std::io::stdout());

    let mut tracer = match Tracer::new(pid, config, output)  {
        Err(_) => panic!("Error during Tracer::new"),
        Ok(t) => t
    };

    let _ = tracer.run_tracer();

    // display output
    println!("__Files attempted to be opened (openat syscall):__");

    let attempted_opened_filepaths = tracer.get_opened_files().unwrap();
    for filepath in attempted_opened_filepaths {
        println!("{}", filepath);
    }


    println!("\n__Files read (read syscall)__");

    let read_filepaths = tracer.get_read_files().unwrap();
    for filepath in read_filepaths {
        println!("{}", filepath);
    }

    
    println!("\n__Files written to (write syscall)__");
    
    let written_to_filepaths = tracer.get_written_files().unwrap();
    for filepath in written_to_filepaths.clone() {
        println!("{}", filepath);
    }

    Ok(())
}
