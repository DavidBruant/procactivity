//! lurk is a pretty (simple) alternative to strace.
//!
//! ## Installation
//!
//! Add the following dependencies to your `Cargo.toml`
//!
//! ```toml
//! [dependencies]
//! lurk-cli = "0.3.6"
//! nix = { version = "0.27.1", features = ["ptrace", "signal"] }
//! console = "0.15.8"
//! ```
//!
//! ## Usage
//!
//! First crate a tracee using [`run_tracee`] method. Then you can construct a [`Tracer`]
//! struct to trace the system calls via calling [`run_tracer`].
//!
//! ## Examples
//!
//! ```rust
//! use anyhow::{bail, Result};
//! use lurk_cli::{args::Args, style::StyleConfig, Tracer};
//! use nix::unistd::{fork, ForkResult};
//! use std::io;
//!
//! fn main() -> Result<()> {
//!     let command = String::from("/usr/bin/ls");
//!
//!     let pid = match unsafe { fork() } {
//!         Ok(ForkResult::Child) => {
//!             return lurk_cli::run_tracee(&[command], &[], &None);
//!         }
//!         Ok(ForkResult::Parent { child }) => child,
//!         Err(err) => bail!("fork() failed: {err}"),
//!     };
//!
//!     let args = Args::default();
//!     let output = io::stdout();
//!
//!     Tracer::new(pid, args, output)?.run_tracer()
//! }
//! ```
//!
//! [`run_tracee`]: crate::run_tracee
//! [`Tracer`]: crate::Tracer
//! [`run_tracer`]: crate::Tracer::run_tracer

#[deny(clippy::pedantic, clippy::format_push_string)]
// TODO: re-check the casting lints - they might indicate an issue
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::redundant_closure_for_method_calls,
    clippy::struct_excessive_bools
)]
pub mod arch;
pub mod args;
pub mod style;
pub mod syscall_info;

use anyhow::{anyhow, Result};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_BORDERS_ONLY;
use comfy_table::CellAlignment::Right;
use comfy_table::{Cell, ContentArrangement, Row, Table};
use im::HashMap as ImmHashMap;
use std::collections::HashMap;
use libc::user_regs_struct;
use libc::{F_DUPFD, F_DUPFD_CLOEXEC};
use nix::sys::personality::{self, Persona};
use nix::sys::ptrace::{self, Event};
use nix::sys::signal::Signal;
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use std::fs;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};
use syscalls::{Sysno, SysnoMap, SysnoSet};
use uzers::get_user_by_name;

use crate::args::{Args, Filter};
use crate::syscall_info::{FdToFdtype, FdType, RetCode, SyscallArg, SyscallArgs, SyscallInfo};



pub struct Tracer<W: Write> {
    pid: Pid,
    args: Args,
    filter: Filter,
    syscalls_time: SysnoMap<Duration>,
    syscalls_pass: SysnoMap<u64>,
    syscalls_fail: SysnoMap<u64>,

    pub syscall_infos: Vec<SyscallInfo>,
    fd_to_fdtype_by_pid: ImmHashMap<Pid, FdToFdtype>,

    output: W,
    // If enabled, count and collapse repeated failing execve attempts per pid
    exec_retry_counts: std::collections::HashMap<Pid, usize>,
}

impl<W: Write> Tracer<W> {
    pub fn new(pid: Pid, args: Args, output: W) -> Result<Self> {
        let mut fd_to_fdtype_by_pid = ImmHashMap::new();
        fd_to_fdtype_by_pid = fd_to_fdtype_by_pid.update(pid, ImmHashMap::new());

        Ok(Self {
            pid,
            filter: args.create_filter()?,
            args,
            syscalls_time: SysnoMap::from_iter(
                SysnoSet::all().iter().map(|v| (v, Duration::default())),
            ),
            syscalls_pass: SysnoMap::from_iter(SysnoSet::all().iter().map(|v| (v, 0))),
            syscalls_fail: SysnoMap::from_iter(SysnoSet::all().iter().map(|v| (v, 0))),

            syscall_infos: Vec::new(),
            fd_to_fdtype_by_pid,

            output,
            exec_retry_counts: HashMap::new(),
        })
    }

    pub fn set_output(&mut self, output: W) {
        self.output = output;
    }

    #[allow(clippy::too_many_lines)]
    pub fn run_tracer(&mut self) -> Result<()> {
        // Create a hashmap to track entry and exit times across all forked processes individually.
        let mut start_times = HashMap::<Pid, Option<SystemTime>>::new();
        // Store pre-parsed args for special syscalls (execve/execveat) captured at syscall entry
        let mut pending_args = HashMap::<Pid, Option<SyscallArgs>>::new();
        start_times.insert(self.pid, None);
        pending_args.insert(self.pid, None);

        let mut options_initialized = false;
        let mut entry_regs = None;

        loop {
            let status = wait()?;

            if !options_initialized {
                if self.args.follow_forks {
                    arch::ptrace_init_options_fork(self.pid)?;
                } else {
                    arch::ptrace_init_options(self.pid)?;
                }
                options_initialized = true;
            }

            match status {
                // `WIFSTOPPED(status), signal is WSTOPSIG(status)
                WaitStatus::Stopped(pid, signal) => {
                    // There are three reasons why a child might stop with SIGTRAP:
                    // 1) syscall entry
                    // 2) syscall exit
                    // 3) child calls exec
                    //
                    // Because we are tracing with PTRACE_O_TRACESYSGOOD, syscall entry and syscall exit
                    // are stopped in PtraceSyscall and not here, which means if we get a SIGTRAP here,
                    // it's because the child called exec.
                    if signal == Signal::SIGTRAP {
                        // At exec the address space may change; prefer registers captured
                        // at the previous syscall entry (if present) so we can read argv/envp
                        // from the original address space. Consume `entry_regs` if set.
                        let regs = entry_regs.take();
                        let pre = pending_args.remove(&pid).unwrap_or(None);

                        // If we don't have entry registers (e.g. first-stop), try a best-effort
                        // parse from the current registers before falling back to pointer hex.
                        if regs.is_none() {
                            if let Ok(cur_regs) = self.get_registers(pid) {
                                if let Ok(sysno) = self.get_syscall(cur_regs) {
                                    if sysno == Sysno::execve || sysno == Sysno::execveat {
                                        // parse args now
                                        let args_now = arch::parse_args(pid, sysno, cur_regs);
                                        self.log_standard_syscall(
                                            pid,
                                            Some(cur_regs),
                                            Some(args_now),
                                            None,
                                            None,
                                        )?;
                                        self.issue_ptrace_syscall_request(pid, None)?;
                                        continue;
                                    }
                                }
                            }
                        }

                        self.log_standard_syscall(pid, regs, pre, None, None)?;
                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    // If we trace with PTRACE_O_TRACEFORK, PTRACE_O_TRACEVFORK, and PTRACE_O_TRACECLONE,
                    // a created child of our tracee will stop with SIGSTOP.
                    // If our tracee creates children of their own, we want to trace their syscall times with a new value.
                    if signal == Signal::SIGSTOP {
                        if self.args.follow_forks {
                            start_times.insert(pid, None);

                            if !self.args.summary_only {
                                writeln!(&mut self.output, "Attaching to child {}", pid,)?;
                            }
                        }

                        self.issue_ptrace_syscall_request(pid, None)?;
                        continue;
                    }

                    // The SIGCHLD signal is sent to a process when a child process terminates, interrupted, or resumes after being interrupted
                    // This means, that if our tracee forked and said fork exits before the parent, the parent will get stopped.
                    // Therefor issue a PTRACE_SYSCALL request to the parent to continue execution.
                    // This is also important if we trace without the following forks option.
                    if signal == Signal::SIGCHLD {
                        self.issue_ptrace_syscall_request(pid, Some(signal))?;
                        continue;
                    }

                    // If we fall through to here, we have another signal that's been sent to the tracee,
                    // in this case, just forward the singal to the tracee to let it handle it.
                    // TODO: Finer signal handling, edge-cases etc.
                    ptrace::cont(pid, signal)?;
                }
                // WIFEXITED(status)
                WaitStatus::Exited(pid, _) => {
                    // If the process that exits is the original tracee, we can safely break here,
                    // but we need to continue if the process that exits is a child of the original tracee.
                    if self.pid == pid {
                        break;
                    } else {
                        continue;
                    };
                }
                // The traced process was stopped by a `PTRACE_EVENT_*` event.
                WaitStatus::PtraceEvent(pid, _, code) => {
                    // Handle exec events specially: prefer pre-parsed args captured at syscall
                    // entry time (stored in `pending_args`) so we can print argv/envp even
                    // after the address space has been replaced. When we detect an exec
                    // event, log it as a successful exec (return 0) using the stored
                    // args if present, otherwise fall back to best-effort parsing.
                    if code == Event::PTRACE_EVENT_EXEC as i32 {
                        // consume any pending args parsed at entry
                        let pre = pending_args.remove(&pid).unwrap_or(None);
                        if let Some(args_now) = pre {
                            // Log as successful exec (execve should not return on success).
                            self.log_exec_event(pid, args_now)?;
                        } else if let Ok(regs) = self.get_registers(pid) {
                            if let Ok(sysno) = self.get_syscall(regs) {
                                if sysno == Sysno::execve || sysno == Sysno::execveat {
                                    let args_now = arch::parse_args(pid, sysno, regs);
                                    self.log_exec_event(pid, args_now)?;
                                }
                            }
                        }
                    }

                    // We also stop at the PTRACE_EVENT_EXIT event because of the PTRACE_O_TRACEEXIT option.
                    // We do this to properly catch and log exit-family syscalls, which do not have an PTRACE_SYSCALL_INFO_EXIT event.
                    if code == Event::PTRACE_EVENT_EXIT as i32 && self.is_exit_syscall(pid)? {
                        // use any pending args if present
                        let pre = pending_args.remove(&pid).unwrap_or(None);
                        self.log_standard_syscall(pid, None, pre, None, None)?;
                    }

                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                // Tracee is traced with the PTRACE_O_TRACESYSGOOD option.
                WaitStatus::PtraceSyscall(pid) => {
                    // ptrace(PTRACE_GETEVENTMSG,...) can be one of three values here:
                    // https://github.com/torvalds/linux/blob/e7ae89a0c97ce2b68b0983cd01eda67cf373517d/include/uapi/linux/ptrace.h#L78-L80
                    // 1) PTRACE_SYSCALL_INFO_NONE (0)
                    // 2) PTRACE_SYSCALL_INFO_ENTRY (1)
                    // 3) PTRACE_SYSCALL_INFO_EXIT (2)
                    let event = ptrace::getevent(pid)? as u8;

                    // Snapshot current time, to avoid polluting the syscall time with
                    // non-syscall related latency.
                    let timestamp = Some(SystemTime::now());

                    // We only want to log regular syscalls on exit
                    if let Some(syscall_start_time) = start_times.get_mut(&pid) {
                        if event == 2 { // PTRACE_SYSCALL_INFO_EXIT
                            let pre = pending_args.remove(&pid).unwrap_or(None);
                            self.log_standard_syscall(
                                pid,
                                entry_regs,
                                pre,
                                *syscall_start_time,
                                timestamp,
                            )?;
                            *syscall_start_time = None;
                        } else { // PTRACE_SYSCALL_INFO_ENTRY and PTRACE_SYSCALL_INFO_NONE
                            *syscall_start_time = timestamp;
                            let regs = self.get_registers(pid)?;
                            // Save entry registers for later use
                            entry_regs = Some(regs);

                            // Try to detect exec-like syscalls and pre-parse their args while
                            // the address space is still intact.
                            if let Ok(sysno) = self.get_syscall(regs) {
                                if sysno == Sysno::execve || sysno == Sysno::execveat {
                                    let args = arch::parse_args(pid, sysno, regs);
                                    pending_args.insert(pid, Some(args));
                                } else {
                                    pending_args.insert(pid, None);
                                }
                            }
                        }
                    } else {
                        return Err(anyhow!("Unable to get start time for tracee {}", pid));
                    }

                    self.issue_ptrace_syscall_request(pid, None)?;
                }
                // WIFSIGNALED(status), signal is WTERMSIG(status) and coredump is WCOREDUMP(status)
                WaitStatus::Signaled(pid, signal, coredump) => {
                    writeln!(
                        &mut self.output,
                        "Child {} terminated by signal {} {}",
                        pid,
                        signal,
                        if coredump { "(core dumped)" } else { "" }
                    )?;
                    break;
                }
                // WIFCONTINUED(status), this usually happens when a process receives a SIGCONT.
                // Just continue with the next iteration of the loop.
                WaitStatus::Continued(_) | WaitStatus::StillAlive => {
                    continue;
                }
            }
        }

        
        if !self.args.json && (self.args.summary_only || self.args.summary) {
            if !self.args.summary_only {
                // Make a gap between the last syscall and the summary
                writeln!(&mut self.output)?;
            }
            self.report_summary()?;
        }


        Ok(())
    }

    pub fn report_summary(&mut self) -> Result<()> {
        let headers = vec!["% time", "time", "time/call", "calls", "errors", "syscall"];
        let mut table = Table::new();
        table
            .load_preset(UTF8_BORDERS_ONLY)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(&headers);

        for i in 0..headers.len() {
            table.column_mut(i).unwrap().set_cell_alignment(Right);
        }

        let mut sorted_sysno: Vec<_> = self.filter.all_enabled().iter().collect();
        sorted_sysno.sort_by_key(|k| k.name());
        let t_time: Duration = self.syscalls_time.values().sum();

        for sysno in sorted_sysno {
            let (Some(pass), Some(fail), Some(time)) = (
                self.syscalls_pass.get(sysno),
                self.syscalls_fail.get(sysno),
                self.syscalls_time.get(sysno),
            ) else {
                continue;
            };

            let calls = pass + fail;
            if calls == 0 {
                continue;
            }

            let time_percent = if !t_time.is_zero() {
                time.as_secs_f32() / t_time.as_secs_f32() * 100f32
            } else {
                0f32
            };

            table.add_row(vec![
                Cell::new(format!("{time_percent:.1}%")),
                Cell::new(format!("{}µs", time.as_micros())),
                Cell::new(format!("{:.1}ns", time.as_nanos() as f64 / calls as f64)),
                Cell::new(format!("{calls}")),
                Cell::new(format!("{fail}")),
                Cell::new(sysno.name()),
            ]);
        }

        // Create the totals row, but don't add it to the table yet
        let failed = self.syscalls_fail.values().sum::<u64>();
        let calls: u64 = self.syscalls_pass.values().sum::<u64>() + failed;
        let totals: Row = vec![
            Cell::new("100%"),
            Cell::new(format!("{}µs", t_time.as_micros())),
            Cell::new(format!("{:.1}ns", t_time.as_nanos() as f64 / calls as f64)),
            Cell::new(calls),
            Cell::new(failed.to_string()),
            Cell::new("total"),
        ]
        .into();

        // TODO: consider using another table-creating crate
        //       https://github.com/Nukesor/comfy-table/issues/104
        // This is a hack to add a line between the table and the summary,
        // computing max column width of each existing row plus the totals row
        let divider_row: Vec<String> = table
            .column_max_content_widths()
            .iter()
            .copied()
            .enumerate()
            .map(|(idx, val)| {
                let cell_at_idx = totals.cell_iter().nth(idx).unwrap();
                (val as usize).max(cell_at_idx.content().len())
            })
            .map(|v| str::repeat("-", v))
            .collect();
        table.add_row(divider_row);
        table.add_row(totals);

        if !self.args.summary_only {
            // separate a list of syscalls from the summary table with an blank line
            writeln!(&mut self.output)?;
        }
        writeln!(&mut self.output, "{table}")?;

        Ok(())
    }

    pub fn get_opened_files(&self) -> Result<impl Iterator<Item = &String> + Clone>{
        
        // PPP add other open* syscalls
        let openat_syscalls = self.syscall_infos.iter()
            .filter(|&si| si.syscall == Sysno::openat);


        let attempted_opened_filepaths = openat_syscalls
            .map(|osi| match osi.args.0.iter().nth(1) {
                Some(val) => match val {
                    SyscallArg::Int(_) => None,
                    SyscallArg::Str(s) => Some(s),
                    SyscallArg::StrVec(_items, _) => None,
                    SyscallArg::Addr(_) => None,
                },
                None => None
            })
            .map(|filepath| filepath.unwrap());

        return Ok(attempted_opened_filepaths)
    }

    // get read syscalls for which return value is >= 1 (read at least one byte from file)
    pub fn get_read_files(&self) -> Result<impl Iterator<Item = &String> + Clone>{
        
        let read_at_least_one_byte_syscalls = self.syscall_infos.iter()
            // select only read syscalls
            .filter(|&si| si.syscall == Sysno::read && match si.result {
                RetCode::Address(_) => false,
                RetCode::Err(_) => false,
                RetCode::Ok(read) => read >= 1 
            })
            // keep syscalls reading an actual fs file 
            .filter(|&si| {
                // only read syscalls, so si.args.0[0] must be a fd (number)
                let fd: i32 = match &si.args.0[0] {
                    SyscallArg::Int(i) => *i as i32,
                    SyscallArg::Str(_s) => panic!("First arg of read syscall should be a fd not a Str"),
                    SyscallArg::StrVec(_items, _) => panic!("First arg of read syscall should be a fd not a StrVec"),
                    SyscallArg::Addr(_) => panic!("First arg of read syscall should be a fd not an Addr"),
                };

                let fdtype = si.fd_to_fdtype.get(&fd);

                match fdtype {
                    None => false,
                    Some(fdtype) => match fdtype {
                        FdType::Stdin => false,
                        FdType::Stdout => false,
                        FdType::Stderr => false,
                        FdType::File(_) => true,
                    }
                }
            });

        // get the filepath corresponding to this fd 
        let read_filepaths = read_at_least_one_byte_syscalls
            .map(|osi| {
                let fd: i32 = match &osi.args.0[0] {
                    SyscallArg::Int(i) => *i as i32,
                    SyscallArg::Str(_s) => panic!("First arg of read syscall should be a fd not a Str"),
                    SyscallArg::StrVec(_items, _) => panic!("First arg of read syscall should be a fd not a StrVec"),
                    SyscallArg::Addr(_) => panic!("First arg of read syscall should be a fd not an Addr"),
                };

                let fdtype = osi.fd_to_fdtype.get(&fd);

                match fdtype {
                    None => panic!("Did not find corresponding pathname for fd {}", fd),
                    Some(fdtype) => match fdtype {
                        FdType::Stdin => panic!("fdtype should be a filepath, not stdin"),
                        FdType::Stdout => panic!("fdtype should be a filepath, not stdout"),
                        FdType::Stderr => panic!("fdtype should be a filepath, not stderr"),
                        FdType::File(str) => str,
                    }
                }
            });

        return Ok(read_filepaths)
    }

    // get write syscalls 
    pub fn get_written_files(&self) -> Result<impl Iterator<Item = &String> + Clone>{

        let write_syscalls = self.syscall_infos.iter()
            .filter(|&si| si.syscall == Sysno::write)
            // keep syscalls writing to an actual fs file 
            .filter(|&si| {
                // only read syscalls, so si.args.0[0] must be a fd (number)
                let fd: i32 = match &si.args.0[0] {
                    SyscallArg::Int(i) => *i as i32,
                    SyscallArg::Str(_s) => panic!("First arg of read syscall should be a fd not a Str"),
                    SyscallArg::StrVec(_items, _) => panic!("First arg of read syscall should be a fd not a StrVec"),
                    SyscallArg::Addr(_) => panic!("First arg of read syscall should be a fd not an Addr"),
                };

                let fdtype = si.fd_to_fdtype.get(&fd);

                match fdtype {
                    None => false,
                    Some(fdtype) => match fdtype {
                        FdType::Stdin => false,
                        FdType::Stdout => false,
                        FdType::Stderr => false,
                        FdType::File(_) => true,
                    }
                }
            });

        // get the filepath corresponding to this fd 
        let written_to_filepaths = write_syscalls
            .map(|osi| {
                let fd: i32 = match &osi.args.0[0] {
                    SyscallArg::Int(i) => *i as i32,
                    SyscallArg::Str(_s) => panic!("First arg of read syscall should be a fd not a Str"),
                    SyscallArg::StrVec(_items, _) => panic!("First arg of read syscall should be a fd not a StrVec"),
                    SyscallArg::Addr(_) => panic!("First arg of read syscall should be a fd not an Addr"),
                };

                let fdtype = osi.fd_to_fdtype.get(&fd);

                match fdtype {
                    None => panic!("Did not find corresponding pathname for fd {}", fd),
                    Some(fdtype) => match fdtype {
                        FdType::Stdin => panic!("fdtype should be a filepath, not stdin"),
                        FdType::Stdout => panic!("fdtype should be a filepath, not stdout"),
                        FdType::Stderr => panic!("fdtype should be a filepath, not stderr"),
                        FdType::File(str) => str,
                    }
                }
            });

        return Ok(written_to_filepaths)
    }


    fn log_standard_syscall(
        &mut self,
        pid: Pid,
        entry_regs: Option<user_regs_struct>,
        pre_parsed_args: Option<SyscallArgs>,
        syscall_start_time: Option<SystemTime>,
        syscall_end_time: Option<SystemTime>,
    ) -> Result<()> {
        let register_data = self.parse_register_data(pid);
        if let Err(e) = register_data {
            eprintln!("{e}");
            return Ok(());
        }
        let (syscall_number, registers) = register_data.unwrap();

        // Theres no PTRACE_SYSCALL_INFO_EXIT for an exit-family syscall, hence ret_code will always be 0xffffffffffffffda (which is -38)
        // -38 is ENOSYS which is put into RAX as a default return value by the kernel's syscall entry code.
        // In order to not pollute the summary with this false positive, avoid exit-family syscalls from being counted (same behaviour as strace).
        let ret_code = match syscall_number {
            Sysno::exit | Sysno::exit_group => RetCode::from_raw(0),
            _ => {
                #[cfg(target_arch = "x86_64")]
                let code = RetCode::from_raw(registers.rax);
                #[cfg(target_arch = "riscv64")]
                let code = RetCode::from_raw(registers.a7);
                #[cfg(target_arch = "aarch64")]
                let code = RetCode::from_raw(registers.regs[0]);
                match code {
                    RetCode::Err(_) => self.syscalls_fail[syscall_number] += 1,
                    _ => self.syscalls_pass[syscall_number] += 1,
                }
                code
            }
        };

        // Prefer entry registers if provided (they allow reading strings before exec).
        // This means that either entry or exit registers are read
        let registers = entry_regs.unwrap_or(registers);

        // Special handling: collapse repeated failing execve attempts if enabled.
        if self.args.collapse_exec_retries
            && (syscall_number == Sysno::execve || syscall_number == Sysno::execveat)
        {
            if let RetCode::Err(errno) = ret_code {
                // ENOENT is -2: common when execvp probes PATH entries.
                if errno == -2 {
                    let counter = self.exec_retry_counts.entry(pid).or_default();
                    *counter += 1;
                    // suppress printing this failing execve
                    return Ok(());
                }
            } else {
                // success: if we suppressed prior failures, print a compact summary
                if let Some(count) = self.exec_retry_counts.remove(&pid) {
                    if count > 0 {
                        writeln!(
                            &mut self.output,
                            "[{}] execve: collapsed {} failed attempts",
                            pid, count
                        )?;
                    }
                }
            }
        }

        if self.filter.matches(syscall_number, ret_code) {
            let elapsed = syscall_start_time.map_or(Duration::default(), |start_time| {
                let end_time = syscall_end_time.unwrap_or(SystemTime::now());
                end_time.duration_since(start_time).unwrap_or_default()
            });

            if syscall_start_time.is_some() {
                self.syscalls_time[syscall_number] += elapsed;
            }

            if !self.args.summary_only {
                let fd_to_pathname = match self.fd_to_fdtype_by_pid.get(&pid) {
                    None => panic!("No fd_to_path found for pid {}", pid),
                    Some(map) => map
                };

                // Use pre-parsed args if provided (captured at entry), otherwise parse now.
                let args = pre_parsed_args
                    .unwrap_or_else(|| arch::parse_args(pid, syscall_number, registers));
                let info = SyscallInfo {
                    typ: "SYSCALL",
                    pid,
                    syscall: syscall_number,
                    args,
                    result: ret_code,
                    duration: elapsed,
                    fd_to_fdtype: fd_to_pathname.clone() // maybe this clone is a performance problem. Maybe not
                };
                self.store_syscall_info(info);
            }
        }

        Ok(())
    }

    fn log_exec_event(&mut self, pid: Pid, args: SyscallArgs) -> Result<()> {
        let fd_to_pathname = match self.fd_to_fdtype_by_pid.get(&pid) {
            None => panic!("No fd_to_path found for pid {}", pid),
            Some(map) => map
        };

        // Construct a SyscallInfo-like record for exec events. Mark result as Ok(0)
        // since PTRACE_EVENT_EXEC means the exec completed successfully.
        let info = SyscallInfo {
            typ: "SYSCALL",
            pid,
            syscall: Sysno::execve,
            args,
            result: RetCode::Ok(0),
            duration: Duration::default(),
            fd_to_fdtype: fd_to_pathname.clone() // maybe this clone is a performance problem. Maybe not
            // PPP add fd => pathname association
        };
        self.store_syscall_info(info);
        Ok(())
    }

    fn update_fd_to_fdtype_by_pid(&mut self, syscall_info: &SyscallInfo){
        // if syscall is a open*, associate the path used as argument with the fd returned as result
        if syscall_info.syscall == Sysno::open || 
            syscall_info.syscall == Sysno::openat || 
            syscall_info.syscall == Sysno::openat2 || 
            syscall_info.syscall == Sysno::creat {
                let fd = match syscall_info.result {
                    RetCode::Ok(ret) => ret,
                    RetCode::Address(_) => panic!("Return value of an open* syscall shouldn't be an address"),
                    RetCode::Err(err) => err
                };

                if fd >= 0 {
                    let path_arg: &SyscallArg = if syscall_info.syscall == Sysno::open || syscall_info.syscall == Sysno::creat {
                            &syscall_info.args.0[0]
                        } else if syscall_info.syscall == Sysno::openat || syscall_info.syscall == Sysno::openat2{
                            &syscall_info.args.0[1]
                        }
                        else {
                            panic!("Syscall {} not covered", syscall_info.syscall)
                        };

                    let pathname = match path_arg {
                        SyscallArg::Int(_) => panic!("path_arg should be a string not an Int"),
                        SyscallArg::Str(str) => str,
                        SyscallArg::StrVec(_, _) => panic!("path_arg should be a string not a StrVec"),
                        SyscallArg::Addr(_) => panic!("path_arg should be a string not an Addr"),
                    };

                    let fd_to_pathname = match self.fd_to_fdtype_by_pid.get(&self.pid){
                        None => panic!("Missing fd_to_path for pid {}", &self.pid),
                        Some(fd_to_pathname) => fd_to_pathname
                    };

                    self.fd_to_fdtype_by_pid = self.fd_to_fdtype_by_pid.update(
                        self.pid,
                        fd_to_pathname.update(fd, syscall_info::FdType::File(pathname.to_string()))
                    )
                }
        }

        // if syscall is a close, remove the fd from the hashmap
        if syscall_info.syscall == Sysno::close {

            let fd: i32 = match &syscall_info.args.0[0] {
                SyscallArg::Int(i) => *i as i32,
                SyscallArg::Str(_s) => panic!("First arg of close syscall should be a fd not a Str"),
                SyscallArg::StrVec(_items, _) => panic!("First arg of close syscall should be a fd not a StrVec"),
                SyscallArg::Addr(_) => panic!("First arg of close syscall should be a fd not an Addr"),
            };

            let fd_to_fdtype = match self.fd_to_fdtype_by_pid.get(&self.pid){
                None => panic!("Missing fd_to_fdtype for pid {}", &self.pid),
                Some(fd_to_fdtype) => fd_to_fdtype
            };

            self.fd_to_fdtype_by_pid = self.fd_to_fdtype_by_pid.update(
                self.pid,
                fd_to_fdtype.without(&fd)
            )
        }

        // if syscall is a dup, dup2 or dup3, the syscall return value is the duplicated fs
        if syscall_info.syscall == Sysno::dup || syscall_info.syscall == Sysno::dup2 || syscall_info.syscall == Sysno::dup3 {
            
            let returned_fd = match syscall_info.result {
                RetCode::Ok(fd) => fd,
                RetCode::Address(_) => panic!("return value of dup syscall ({}) shouldn't be an address", syscall_info.syscall),
                RetCode::Err(_) => -1,
            };

            if returned_fd >= 0 {
                let source_fd: i32 = match &syscall_info.args.0[0] {
                    SyscallArg::Int(i) => *i as i32,
                    SyscallArg::Str(_s) => panic!("First arg of dup/2/3 syscall should be a fd not a Str"),
                    SyscallArg::StrVec(_items, _) => panic!("First arg of dup/2/3 syscall should be a fd not a StrVec"),
                    SyscallArg::Addr(_) => panic!("First arg of dup/2/3 syscall should be a fd not an Addr"),
                };

                let fd_to_fdtype = match self.fd_to_fdtype_by_pid.get(&self.pid){
                    None => panic!("Missing fd_to_fdtype for pid {}", &self.pid),
                    Some(fd_to_fdtype) => fd_to_fdtype
                };

                let source_fd_fdtype = match fd_to_fdtype.get(&source_fd) {
                    None => panic!("Missing fdtype for fd {}", &source_fd),
                    Some(fdtype) => fdtype
                };
                
                // duplicate fdtype
                self.fd_to_fdtype_by_pid = self.fd_to_fdtype_by_pid.update(
                    self.pid,
                    fd_to_fdtype.update(returned_fd, source_fd_fdtype.clone())
                )

            }
        }

        // if syscall is fcntl with argument, the syscall return value is the duplicated fs
        if syscall_info.syscall == Sysno::fcntl {
            let op = match &syscall_info.args.0[1] {
                SyscallArg::Int(i) => *i as i32,
                SyscallArg::Str(_s) => panic!("Second arg of fcntl syscall should be an int, not a Str"),
                SyscallArg::StrVec(_items, _) => panic!("Second arg of fcntl syscall should be an int, not a StrVec"),
                SyscallArg::Addr(_) => panic!("Second arg of fcntl syscall should be an int, not an Addr"),
            };

            if op == F_DUPFD || op == F_DUPFD_CLOEXEC {
                let returned_fd = match syscall_info.result {
                    RetCode::Ok(fd) => fd,
                    RetCode::Address(_) => panic!("return value of dup syscall ({}) shouldn't be an address", syscall_info.syscall),
                    RetCode::Err(_) => -1,
                };

                if returned_fd >= 0 {
                    let source_fd = match &syscall_info.args.0[0] {
                        SyscallArg::Int(i) => *i as i32,
                        SyscallArg::Str(_s) => panic!("First arg of fcntl syscall should be an int, not a Str"),
                        SyscallArg::StrVec(_items, _) => panic!("First arg of fcntl syscall should be an int, not a StrVec"),
                        SyscallArg::Addr(_) => panic!("First arg of fcntl syscall should be an int, not an Addr"),
                    };

                    let fd_to_fdtype = match self.fd_to_fdtype_by_pid.get(&self.pid){
                        None => panic!("Missing fd_to_fdtype for pid {}", &self.pid),
                        Some(fd_to_fdtype) => fd_to_fdtype
                    };

                    let source_fd_fdtype = match fd_to_fdtype.get(&source_fd) {
                        None => panic!("Missing fdtype for fd {}", &source_fd),
                        Some(fdtype) => fdtype
                    };

                    self.fd_to_fdtype_by_pid = self.fd_to_fdtype_by_pid.update(
                        self.pid,
                        fd_to_fdtype.update(returned_fd, source_fd_fdtype.clone())
                    )
                }

            }


        }


    }

    fn store_syscall_info(&mut self, syscall_info: SyscallInfo) -> () {
        
        self.update_fd_to_fdtype_by_pid(&syscall_info);
        
        self.syscall_infos.push(syscall_info);
    }

    // Issue a PTRACE_SYSCALL request to the tracee, forwarding a signal if one is provided.
    fn issue_ptrace_syscall_request(&self, pid: Pid, signal: Option<Signal>) -> Result<()> {
        ptrace::syscall(pid, signal)
            .map_err(|_| anyhow!("Unable to issue a PTRACE_SYSCALL request in tracee {}", pid))
    }

    // TODO: This is arch-specific code and should be modularized
    fn get_registers(&self, pid: Pid) -> Result<user_regs_struct> {
        ptrace::getregs(pid).map_err(|_| anyhow!("Unable to get registers from tracee {}", pid))
    }

    fn get_syscall(&self, registers: user_regs_struct) -> Result<Sysno> {
        #[cfg(target_arch = "x86_64")]
        let reg = registers.orig_rax;
        #[cfg(target_arch = "riscv64")]
        let reg = registers.a7;
        #[cfg(target_arch = "aarch64")]
        let reg = registers.regs[8];

        Ok(u32::try_from(reg)
            .map_err(|_| anyhow!("Invalid syscall number {reg}"))?
            .into())
    }

    // Issues a ptrace(PTRACE_GETREGS, ...) request and gets the corresponding syscall number (Sysno).
    fn parse_register_data(&self, pid: Pid) -> Result<(Sysno, user_regs_struct)> {
        let registers = self.get_registers(pid)?;
        let syscall_number = self.get_syscall(registers)?;

        Ok((syscall_number, registers))
    }

    fn is_exit_syscall(&self, pid: Pid) -> Result<bool> {
        self.get_registers(pid).map(|registers| {
            #[cfg(target_arch = "x86_64")]
            let reg = registers.orig_rax;
            #[cfg(target_arch = "riscv64")]
            let reg = registers.a7;
            #[cfg(target_arch = "aarch64")]
            let reg = registers.regs[8];
            reg == Sysno::exit as u64 || reg == Sysno::exit_group as u64
        })
    }
}

pub fn run_tracee(command: &[String], envs: &[String], username: &Option<String>) -> Result<()> {
    ptrace::traceme()?;
    // Stop ourselves so the tracer parent can set ptrace options before exec.
    // This improves reliability of capturing the initial execve syscall arguments.
    // Make this behavior conditional: set `LURK_DISABLE_SIGSTOP=1` in the environment
    // to skip raising SIGSTOP (useful when running under debuggers or wrappers).
    if std::env::var_os("LURK_DISABLE_SIGSTOP").is_none() {
        nix::sys::signal::raise(Signal::SIGSTOP).map_err(|_| anyhow!("Unable to raise SIGSTOP"))?;
    }
    personality::set(Persona::ADDR_NO_RANDOMIZE)
        .map_err(|_| anyhow!("Unable to set ADDR_NO_RANDOMIZE"))?;
    let mut binary = command
        .first()
        .ok_or_else(|| anyhow!("No command"))?
        .to_string();
    if let Ok(bin) = fs::canonicalize(&binary) {
        binary = bin
            .to_str()
            .ok_or_else(|| anyhow!("Invalid binary path"))?
            .to_string()
    }
    let mut cmd = Command::new(binary);
    cmd.args(command[1..].iter()).stdout(Stdio::null());

    for token in envs {
        let mut parts = token.splitn(2, '=');
        match (parts.next(), parts.next()) {
            (Some(key), Some(value)) => cmd.env(key, value),
            (Some(key), None) => cmd.env_remove(key),
            _ => unreachable!(),
        };
    }

    if let Some(username) = username {
        if let Some(user) = get_user_by_name(username) {
            cmd.uid(user.uid());
        }
    }

    let _ = cmd.exec();

    Ok(())
}
