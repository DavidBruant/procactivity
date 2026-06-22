
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

// This is a really bad adding function, its purpose is to fail in this
// example.
#[allow(dead_code)]
fn bad_add(a: i32, b: i32) -> i32 {
    a - b
}

#[cfg(test)]
mod tests {
    use std::io::{Write};
    use syscalls::Sysno;
    
    use anyhow::{Error, Result, bail};
    use nix::unistd::{fork, ForkResult};
    
    use procactivity::args::{ArgCommand, Args};
    use procactivity::{run_tracee, Tracer};

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    //use super::*;

    /*
    #[test]
    fn test_add() {
        assert_eq!(add(1, 2), 3);
    }

    #[test]
    fn test_bad_add() {
        // This assert would fire and test will fail.
        // Please note, that private functions can be tested too!
        assert_eq!(bad_add(1, 2), 3);
    }
    */


    #[test]
    fn procactivity_tracer_ls() -> Result<(), Error> {
        let command = [String::from("ls")];

        println!("TEST procactivity_tracer_ls");

        // create Trace instance manually
        // fed it "ls"
        let config= Args::from({Args {
            follow_forks: true, 
            collapse_exec_retries: false, 
            command: Some(ArgCommand::Command(vec![])),
        }});

        let child_pid = {
            match unsafe { fork() } {
                Ok(ForkResult::Child) => return run_tracee(&command),
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => bail!("fork() failed: {err}"),
            }
        };

        let output: Box<dyn Write> = Box::new(std::io::stdout());

        println!("TEST procactivity_tracer_ls - tracer.run_tracer");

        let mut tracer = Tracer::new(child_pid, config, output)?;
        let _ = tracer.run_tracer();

        println!("TEST procactivity_tracer_ls - after tracer.run_tracer");

        // get tracer.syscall_infos.
        let syscalls = tracer.syscall_infos;

        // perform filters to find the 'fstat'
        let fstat_syscalls: Vec<&procactivity::syscall_info::SyscallInfo> = syscalls.iter().filter(|&si| si.syscall == Sysno::fstat).collect();

        assert!(fstat_syscalls.len() >= 1, "At least one call to fstat during call to ls");

        Ok(())
    }

    
    #[test]
    fn exec_tracer_cat() -> Result<(), Error> {
        let command = [String::from("cat"), String::from(".gitignore")];

        let config= Args::from({Args { 
            follow_forks: true, 
            collapse_exec_retries: false,
            command: Some(ArgCommand::Command(vec![])),
        }});

        let child_pid = {
            match unsafe { fork() } {
                Ok(ForkResult::Child) => return run_tracee(&command),
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => bail!("fork() failed: {err}"),
            }
        };

        let output: Box<dyn Write> = Box::new(std::io::stdout());

        let mut tracer = Tracer::new(child_pid, config, output)?;
        let _ = tracer.run_tracer() ;

        let attempted_opened_filepaths = tracer.get_opened_files().unwrap();

        assert!(
            attempted_opened_filepaths.clone().any(|filepath| filepath == ".gitignore"),
            "'.gitignore' should be one of the filepath opened"
        );      

        println!("Files attempted to be opened (openat syscall)");
        
        for filepath in attempted_opened_filepaths {
            println!("{}", filepath);
        }


        Ok(())
    }

   
    #[test]
    fn exec_tracer_less() -> Result<(), Error> {
        let command = [String::from("less"), String::from(".gitignore")];

        let config= Args::from({Args { 
            follow_forks: true, 
            collapse_exec_retries: false,
            command: Some(ArgCommand::Command(vec![])),
        }});

        let child_pid = {
            match unsafe { fork() } {
                Ok(ForkResult::Child) => return run_tracee(&command),
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => bail!("fork() failed: {err}"),
            }
        };

        let output: Box<dyn Write> = Box::new(std::io::stdout());

        let mut tracer = Tracer::new(child_pid, config, output)?;
        let _ = tracer.run_tracer() ;

        let read_filepaths = tracer.get_read_files().unwrap();

        assert!(
            read_filepaths.clone().any(|filepath| filepath == ".gitignore"),
            "'.gitignore' should be read by a call to less"
        );      

        println!("Files read (read syscall)");
        
        for filepath in read_filepaths {
            println!("{}", filepath);
        }


        Ok(())
    }

    
    #[test]
    fn tracer_simple_write() -> Result<(), Error> {
        let command = [String::from("tests/simple-write.sh")];

        let config= Args::from({Args {
            follow_forks: true, 
            collapse_exec_retries: false,
            command: Some(ArgCommand::Command(vec![])),
        }});

        let child_pid = {
            match unsafe { fork() } {
                Ok(ForkResult::Child) => return run_tracee(&command),
                Ok(ForkResult::Parent { child }) => child,
                Err(err) => bail!("fork() failed: {err}"),
            }
        };

        let output: Box<dyn Write> = Box::new(std::io::stdout());

        let mut tracer = Tracer::new(child_pid, config, output)?;
        let _ = tracer.run_tracer() ;

        let written_to_filepaths = tracer.get_written_files().unwrap();

        println!("Files written to (write syscall)");
        
        for filepath in written_to_filepaths.clone() {
            println!("{}", filepath);
        }

        assert!(
            written_to_filepaths.clone().any(|filepath| filepath == "/tmp/yo.txt"),
            "'/tmp/yo.txt' should be written to by a call to tests/simple-write.sh"
        );      




        Ok(())
    }


}


