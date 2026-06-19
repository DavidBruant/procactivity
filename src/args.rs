
use clap::{Parser, Subcommand};
use libc::pid_t;
use syscalls::{SysnoSet};

#[derive(Parser, Debug, Default)]
#[command(name = "procactivity", about, version, allow_external_subcommands = true)]
pub struct Args {
    /// Trace child processes as they are created by currently traced processes.
    #[arg(short, long)]
    pub follow_forks: bool,
    
    /// Collapse repeated failing `execve` attempts and only show final success
    #[arg(long)]
    pub collapse_exec_retries: bool,

    #[command(subcommand)]
    pub command: Option<ArgCommand>,
}

// The command/subcommand is a bit hacky, but gets the job done:
// https://github.com/clap-rs/clap/discussions/4560#discussioncomment-5392780

#[derive(Subcommand, Debug, PartialEq)]
pub enum ArgCommand {
    /// Trace command
    #[command(external_subcommand)]
    Command(Vec<String>),
}

#[derive(Parser, Debug, PartialEq)]
pub struct ArgAttach {
    /// Attach to a running process with the given pid.
    #[arg(short = 'p', long)]
    pub attach: pid_t,
}

impl Args {
    pub fn create_filter(&self) -> anyhow::Result<Filter> {
        // hardcoded filter after removal of lurks arguments
        // TODO remove all the filtering plumbing eventually
        Ok(Filter {
            ret_code_filter: FilterRetCode::All,
            sysno_filter: FilterSysno::All
        })
    }
}

enum FilterRetCode {
    All,
}

enum FilterSysno {
    All
}

pub struct Filter {
    ret_code_filter: FilterRetCode,
    sysno_filter: FilterSysno,
}

impl Filter {
    pub fn matches(&mut self) -> bool {
        (
            // Should this result code be printed?
            match self.ret_code_filter {
                FilterRetCode::All => true,
            }
        ) && (
            // Should this sys_no be printed?
            match &self.sysno_filter {
                FilterSysno::All => true
            }
        )
    }

    pub fn all_enabled(&self) -> SysnoSet {
        match &self.sysno_filter {
            FilterSysno::All => SysnoSet::all()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_simple() {
        let args = Args::parse_from(["procactivity", "app"]);
        assert_eq!(
            args.command,
            Some(ArgCommand::Command(vec!["app".to_string()])),
        );
    }
}
