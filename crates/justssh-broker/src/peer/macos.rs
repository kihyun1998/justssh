//! The macOS measurement, as acwbroker's `peer_darwin.go`, `table_darwin.go` and
//! `hold_darwin.go`: libproc for the owner of a socket, one `kern.proc.all` copy for the
//! process list, and a kqueue for an exit.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, UNIX_EPOCH};

use crate::caller::{Caller, Owner, ProcessInfo, ProcessKey, ProcessTable};
use crate::tokens::{Held, Hold};

/// `<sys/proc_info.h>`.
const PROC_ALL_PIDS: u32 = 1;
const PROC_PIDLISTFDS: i32 = 1;
const PROC_PIDFDSOCKETINFO: i32 = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_TCP: i32 = 2;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

/// How long a hold waits on its kqueue before it looks whether it was dropped.
const POLL_EXIT: Duration = Duration::from_millis(500);

/// `struct proc_fileinfo`.
#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct vinfo_stat`.
#[repr(C)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_times: [i64; 8],
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

/// `struct sockbuf_info`.
#[repr(C)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

/// `struct in_sockinfo`. Each address is the union of `in4in6_addr`, whose IPv4 address is its
/// last four bytes, and `in6_addr`.
#[repr(C)]
struct InSockInfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: [u8; 16],
    insi_laddr: [u8; 16],
    insi_v4: u8,
    insi_v6: [u32; 3],
}

/// `struct tcp_sockinfo`.
#[repr(C)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

/// `struct socket_info`. `soi_proto` is a union whose largest arm is `un_sockinfo`, two
/// opaque handles and two `SOCK_MAXADDRLEN` (255) addresses.
#[repr(C)]
struct SocketInfo {
    soi_stat: VinfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: [u64; 66],
}

/// `struct socket_fdinfo`.
#[repr(C)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

const _: () = assert!(size_of::<TcpSockInfo>() <= size_of::<[u64; 66]>());

/// `struct kinfo_proc` as `kern.proc.all` copies it out: its size and the offsets of the
/// fields read, the same on arm64 and x86-64 (x/sys/unix `KinfoProc`).
mod kinfo {
    pub const SIZE: usize = 648;
    pub const START_SEC: usize = 0;
    pub const START_USEC: usize = 8;
    pub const PID: usize = 40;
    pub const COMM: usize = 243;
    pub const COMM_LEN: usize = 17;
    pub const PPID: usize = 560;
    pub const TDEV: usize = 572;
}

/// `NODEV`: no controlling terminal.
const NODEV: i32 = -1;

/// The caller on the other end of `addr`, measured from one snapshot of processes.
pub fn probe(addr: SocketAddr) -> Caller {
    let owner = owner(addr);
    let table = table();
    Caller::measure(
        owner,
        Some(
            table
                .as_ref()
                .map(|t| t as &dyn ProcessTable)
                .map_err(Clone::clone),
        ),
        false,
    )
}

/// The process owning the local TCP endpoint `addr`, with its image.
pub fn owner(addr: SocketAddr) -> Owner {
    let pid = match owning_pid(addr) {
        Ok(pid) => pid,
        Err(e) => return Owner::unmeasured(e),
    };
    let (image_path, error) = match image_path(pid) {
        Ok(path) => (path, None),
        Err(e) => (String::new(), Some(e)),
    };
    Owner {
        pid,
        image_path,
        error,
        ..Owner::default()
    }
}

/// The first process that holds a TCP socket bound to `addr`, among those this process may
/// read.
fn owning_pid(addr: SocketAddr) -> Result<u32, String> {
    let want = addr.ip().to_canonical();
    for pid in all_pids()? {
        if pid <= 0 {
            continue;
        }
        let Some(fds) = socket_fds(pid) else {
            continue;
        };
        for fd in fds {
            match tcp_local_endpoint(pid, fd) {
                Some((ip, port)) if port == addr.port() && ip.to_canonical() == want => {
                    return Ok(pid as u32);
                }
                _ => {}
            }
        }
    }
    Err(format!("peer: no socket owns that endpoint: {addr}"))
}

fn all_pids() -> Result<Vec<i32>, String> {
    let size = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return Err(format!("peer: proc_listpids sizing returned {size}"));
    }
    let n = size as usize / size_of::<i32>() + 128;
    let mut pids = vec![0i32; n];
    let got = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast::<c_void>(),
            (n * size_of::<i32>()) as i32,
        )
    };
    if got <= 0 {
        return Err(format!("peer: proc_listpids returned {got}"));
    }
    pids.truncate(got as usize / size_of::<i32>());
    Ok(pids)
}

/// The descriptors of `pid` that are sockets, or none when it cannot be read.
fn socket_fds(pid: i32) -> Option<Vec<i32>> {
    let size = unsafe { libc::proc_pidinfo(pid, PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if size <= 0 {
        return None;
    }
    let entry = size_of::<libc::proc_fdinfo>();
    let mut buf: Vec<libc::proc_fdinfo> = Vec::with_capacity(size as usize / entry + 1);
    let got = unsafe {
        libc::proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            buf.as_mut_ptr().cast::<c_void>(),
            (buf.capacity() * entry) as i32,
        )
    };
    if got <= 0 {
        return None;
    }
    unsafe { buf.set_len(got as usize / entry) };
    Some(
        buf.iter()
            .filter(|f| f.proc_fdtype == PROX_FDTYPE_SOCKET)
            .map(|f| f.proc_fd)
            .collect(),
    )
}

/// The local address and port of `pid`'s descriptor `fd` when it is a TCP socket.
fn tcp_local_endpoint(pid: i32, fd: i32) -> Option<(IpAddr, u16)> {
    let mut si: SocketFdInfo = unsafe { zeroed() };
    let size = size_of::<SocketFdInfo>() as i32;
    let got = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            (&raw mut si).cast::<c_void>(),
            size,
        )
    };
    if got < size || si.psi.soi_kind != SOCKINFO_TCP {
        return None;
    }
    let tcp = unsafe { &*(&raw const si.psi.soi_proto).cast::<TcpSockInfo>() };
    let ini = &tcp.tcpsi_ini;
    let port = u16::from_be(ini.insi_lport as u16);
    let raw = ini.insi_laddr;
    if ini.insi_vflag & INI_IPV4 != 0 {
        Some((
            IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15])),
            port,
        ))
    } else if ini.insi_vflag & INI_IPV6 != 0 {
        Some((IpAddr::V6(Ipv6Addr::from(raw)), port))
    } else {
        None
    }
}

fn image_path(pid: u32) -> Result<String, String> {
    let mut buf = vec![0u8; PROC_PIDPATHINFO_MAXSIZE];
    let got = unsafe {
        libc::proc_pidpath(
            pid as i32,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len() as u32,
        )
    };
    if got <= 0 {
        return Err(format!("peer: proc_pidpath({pid}) returned {got}"));
    }
    buf.truncate(got as usize);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// One `kern.proc.all` copy of the process list, with each process's controlling terminal.
pub struct Table {
    by_pid: HashMap<u32, (ProcessInfo, Option<i32>)>,
}

pub fn table() -> Result<Table, String> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL];
    let buf = loop {
        let mut n = 0usize;
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut n,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return Err(format!(
                "peer: sysctl kern.proc.all: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut buf = vec![0u8; n + n / 8 + kinfo::SIZE];
        let mut got = buf.len();
        let r = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                buf.as_mut_ptr().cast::<c_void>(),
                &mut got,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 {
            buf.truncate(got);
            break buf;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOMEM) {
            return Err(format!("peer: sysctl kern.proc.all: {e}"));
        }
    };
    if buf.len() % kinfo::SIZE != 0 {
        return Err(format!(
            "peer: sysctl kern.proc.all gave {} bytes, not a multiple of {}",
            buf.len(),
            kinfo::SIZE
        ));
    }
    let mut by_pid = HashMap::with_capacity(buf.len() / kinfo::SIZE);
    for p in buf.as_chunks::<{ kinfo::SIZE }>().0 {
        let pid = i32_at(p, kinfo::PID) as u32;
        let sec = i64::from_ne_bytes(p[kinfo::START_SEC..][..8].try_into().unwrap());
        let usec = i32_at(p, kinfo::START_USEC);
        let created = u64::try_from(sec)
            .ok()
            .map(|s| UNIX_EPOCH + Duration::from_secs(s) + Duration::from_micros(usec as u64));
        let mut info = ProcessInfo::new(pid, i32_at(p, kinfo::PPID) as u32, created);
        let comm = &p[kinfo::COMM..][..kinfo::COMM_LEN];
        let len = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
        info.name = String::from_utf8_lossy(&comm[..len]).into_owned();
        let tty = Some(i32_at(p, kinfo::TDEV)).filter(|&d| d != NODEV);
        by_pid.insert(pid, (info, tty));
    }
    Ok(Table { by_pid })
}

fn i32_at(p: &[u8], at: usize) -> i32 {
    i32::from_ne_bytes(p[at..][..4].try_into().unwrap())
}

impl ProcessTable for Table {
    fn info(&self, pid: u32) -> Result<ProcessInfo, String> {
        self.by_pid
            .get(&pid)
            .map(|(p, _)| p.clone())
            .ok_or_else(|| format!("peer: no process {pid} in the snapshot"))
    }
}

/// The processes whose controlling terminal is `terminal`, from a fresh snapshot; none when
/// nobody holds it.
pub fn terminal_holders(terminal: i32) -> Result<Vec<ProcessKey>, String> {
    Ok(table()?
        .by_pid
        .values()
        .filter(|(_, tty)| *tty == Some(terminal))
        .map(|(p, _)| ProcessKey::new(p.pid, p.created))
        .collect())
}

/// Watches processes for their exit through a kqueue `EVFILT_PROC` `NOTE_EXIT` filter, bound to
/// the process the pid named when it was registered.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Holder;

impl Hold for Holder {
    fn hold(&self, pid: u32) -> Result<Held, String> {
        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return Err(format!(
                "peer: kqueue to hold {pid}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut ev: libc::kevent = unsafe { zeroed() };
        ev.ident = pid as usize;
        ev.filter = libc::EVFILT_PROC;
        ev.flags = libc::EV_ADD | libc::EV_ONESHOT;
        ev.fflags = libc::NOTE_EXIT;
        let r = unsafe { libc::kevent(kq, &ev, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
        if r < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(kq) };
            return Err(format!("peer: kevent to hold {pid}: {e}"));
        }
        let (exited, held) = Held::channel();
        std::thread::spawn(move || {
            let wait = libc::timespec {
                tv_sec: POLL_EXIT.as_secs() as libc::time_t,
                tv_nsec: POLL_EXIT.subsec_nanos() as libc::c_long,
            };
            while !exited.is_closed() {
                let mut out: libc::kevent = unsafe { zeroed() };
                let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut out, 1, &wait) };
                if n < 0 {
                    if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    break;
                }
                if n > 0 && out.fflags & libc::NOTE_EXIT != 0 {
                    let _ = exited.send(());
                    break;
                }
            }
            unsafe { libc::close(kq) };
        });
        Ok(held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_structures_have_the_sizes_the_kernel_copies() {
        assert_eq!(size_of::<ProcFileInfo>(), 24);
        assert_eq!(size_of::<VinfoStat>(), 136);
        assert_eq!(size_of::<InSockInfo>(), 80);
        assert_eq!(size_of::<TcpSockInfo>(), 120);
        assert_eq!(size_of::<SocketInfo>(), 768);
        assert_eq!(size_of::<SocketFdInfo>(), 792);
    }

    #[test]
    fn the_local_address_sits_where_the_header_puts_it() {
        assert_eq!(std::mem::offset_of!(SocketInfo, soi_kind), 232);
        assert_eq!(std::mem::offset_of!(SocketInfo, soi_proto), 240);
        assert_eq!(std::mem::offset_of!(InSockInfo, insi_lport), 4);
        assert_eq!(std::mem::offset_of!(InSockInfo, insi_vflag), 24);
        assert_eq!(std::mem::offset_of!(InSockInfo, insi_laddr), 48);
    }
}
