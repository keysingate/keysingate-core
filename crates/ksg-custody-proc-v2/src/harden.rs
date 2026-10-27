//! The process around the key: what the operating system is told before a
//! single byte of a share is read (audit of 2026-10-01, finding Sh-11).
//!
//! The library cannot wipe what the compiler keeps in registers and on the
//! stack — the Horner accumulator, the Lagrange basis, the spill of a loop.
//! What it cannot wipe must not leave the process, so the process is shut:
//!
//! | Call | Closes |
//! |---|---|
//! | `setrlimit(RLIMIT_CORE, 0)` | a core file with the memory in it |
//! | `prctl(PR_SET_DUMPABLE, 0)` (Linux) | the same through `core_pattern` pipes, and `ptrace` / `/proc/<pid>/mem` by another process of the same user |
//! | `mlockall(MCL_CURRENT \| MCL_FUTURE)` | pages written to swap, where they outlive the process |
//!
//! And the process is short: it splits or joins and exits, so what is left in
//! its memory lives milliseconds, not the uptime of a server.
//!
//! What stays open, said plainly: **root on the machine at that moment**, and
//! a hibernation image written by the kernel. Those are the TEE-environment
//! question, not this module's.
//!
//! The only `unsafe` in the crate is here: three foreign calls with plain
//! integer arguments and no pointers handed over except to a local `rlimit`.

#![allow(unsafe_code)]

use std::io;

/// What the process ended up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct State {
    /// The core-file limit is zero.
    pub no_core: bool,
    /// The kernel will not dump or let another process attach (Linux).
    pub not_dumpable: bool,
    /// All memory is locked against swap.
    pub locked: bool,
}

/// Shuts the process. `lock` asks for `mlockall`; failing it is an error, not a
/// warning — a split that silently swapped is the case this exists to prevent.
///
/// # Errors
///
/// The operating system's error of the first call that failed, with the
/// remedy in its message.
pub fn harden(lock: bool) -> io::Result<State> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `setrlimit` reads one `rlimit` from a valid local reference.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero) } != 0 {
        return Err(io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    {
        // SAFETY: integer arguments only; `PR_SET_DUMPABLE` takes no pointer.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    if lock {
        // SAFETY: integer flags only.
        if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
            let e = io::Error::last_os_error();
            return Err(io::Error::new(
                e.kind(),
                format!(
                    "mlockall failed ({e}): raise the locked-memory limit (`ulimit -l`) \
                     or grant CAP_IPC_LOCK; --no-mlock runs without it, knowingly"
                ),
            ));
        }
    }
    state()
}

/// Reads the state back from the kernel rather than trusting what was asked.
///
/// # Errors
///
/// The operating system's error, if a query fails.
pub fn state() -> io::Result<State> {
    let mut core = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: `getrlimit` writes one `rlimit` into a valid local reference.
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } != 0 {
        return Err(io::Error::last_os_error());
    }

    #[cfg(target_os = "linux")]
    // SAFETY: integer arguments only; the flag is the return value.
    let not_dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0;
    #[cfg(not(target_os = "linux"))]
    let not_dumpable = false;

    Ok(State {
        no_core: core.rlim_cur == 0,
        not_dumpable,
        locked: locked_kib() > 0,
    })
}

/// `VmLck` from `/proc/self/status`, in KiB; 0 where there is no such file.
fn locked_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmLck:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or(0)
}
