use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
    LocalFree, NO_ERROR, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT, FindClose, FindFirstFileW,
    GetFileInformationByHandle, GetFileVersionInfoSizeW, GetFileVersionInfoW, GetLongPathNameW,
    VerQueryValueW, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessTimes, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    WaitForSingleObject,
};
use windows_sys::Win32::System::Time::{
    GetTimeZoneInformation, TIME_ZONE_ID_INVALID, TIME_ZONE_INFORMATION,
};

use crate::caller::{Caller, Owner, ProcessImage, ProcessInfo, ProcessTable};
use crate::rule::ImageMetadata;
use crate::tokens::{Held, Hold};

const AF_INET: u32 = 2;
/// What `GetTimeZoneInformation` returns while standard time, or daylight saving, is in force.
const TIME_ZONE_ID_STANDARD: u32 = 1;
const TIME_ZONE_ID_DAYLIGHT: u32 = 2;
const AF_INET6: u32 = 23;
/// The longest path Windows reports, in UTF-16 units.
const MAX_LONG_PATH: usize = 32768;
/// How long one wait on a held process lasts before it checks whether the hold was dropped.
const POLL_EXIT: u32 = 500;
/// 100-nanosecond intervals from 1601 to 1970.
const FILETIME_UNIX: u64 = 116_444_736_000_000_000;

/// A process or token handle, closed when dropped.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn open(pid: u32, access: u32) -> Result<Owned, String> {
    let h = unsafe { OpenProcess(access, 0, pid) };
    if h.is_null() {
        return Err(format!(
            "peer: OpenProcess({pid}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Owned(h))
}

/// The caller on the other end of `local`, connected to `remote`, from one snapshot of
/// processes.
pub fn probe(local: SocketAddr, remote: SocketAddr) -> Caller {
    let owner = owner(local, remote);
    let table = table();
    Caller::measure(
        owner,
        Some(
            table
                .as_ref()
                .map(|t| t as &dyn ProcessTable)
                .map_err(Clone::clone),
        ),
        true,
    )
}

/// The process owning the TCP socket whose endpoints are `local` and `remote`, with its
/// session, account and image.
pub fn owner(local: SocketAddr, remote: SocketAddr) -> Owner {
    let pid = match owning_pid(local, remote) {
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
        session: session_of(pid),
        user: user_of(pid),
    }
}

fn owning_pid(local: SocketAddr, remote: SocketAddr) -> Result<u32, String> {
    // The two ends of a loopback connection share a family, so the local end picks the table
    // and the remote end is read from the same row. Both ends are matched, since a local
    // address and port alone is not unique: a second socket can reuse-bind it (#75).
    let want = |a: SocketAddr| match a.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    };
    let (lip, lport, rip, rport) = (want(local), local.port(), want(remote), remote.port());
    match (lip, rip) {
        (IpAddr::V4(lip), IpAddr::V4(rip)) => {
            let buf = tcp_table(AF_INET)?;
            rows::<MIB_TCPROW_OWNER_PID>(&buf)
                .find(|r| {
                    port_of(r.dwLocalPort) == lport
                        && r.dwLocalAddr.to_le_bytes() == lip.octets()
                        && port_of(r.dwRemotePort) == rport
                        && r.dwRemoteAddr.to_le_bytes() == rip.octets()
                })
                .map(|r| r.dwOwningPid)
                .ok_or_else(|| format!("peer: no IPv4 socket owns {lip}:{lport}"))
        }
        (IpAddr::V6(lip), IpAddr::V6(rip)) => {
            let buf = tcp_table(AF_INET6)?;
            rows::<MIB_TCP6ROW_OWNER_PID>(&buf)
                .find(|r| {
                    port_of(r.dwLocalPort) == lport
                        && r.ucLocalAddr == lip.octets()
                        && port_of(r.dwRemotePort) == rport
                        && r.ucRemoteAddr == rip.octets()
                })
                .map(|r| r.dwOwningPid)
                .ok_or_else(|| format!("peer: no IPv6 socket owns [{lip}]:{lport}"))
        }
        _ => Err(format!("peer: {local} and {remote} are different families")),
    }
}

/// The port a table row holds in network byte order in the low word of a DWORD.
fn port_of(v: u32) -> u16 {
    u16::from_be_bytes([v as u8, (v >> 8) as u8])
}

/// The rows of a `MIB_TCPTABLE_OWNER_PID` or `MIB_TCP6TABLE_OWNER_PID` buffer.
fn rows<R: Copy + 'static>(buf: &[u32]) -> impl Iterator<Item = R> + '_ {
    let n = buf[0] as usize;
    let base = buf[1..].as_ptr().cast::<R>();
    let fits = (buf.len() - 1) * 4 / size_of::<R>();
    (0..n.min(fits)).map(move |i| unsafe { base.add(i).read_unaligned() })
}

/// The TCP table of `family` with owning pids, asked for its size and then read, again when
/// it grew in between.
fn tcp_table(family: u32) -> Result<Vec<u32>, String> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u32; (size as usize).div_ceil(4).max(1)];
        let r = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        match r {
            NO_ERROR => return Ok(buf),
            ERROR_INSUFFICIENT_BUFFER => continue,
            e => {
                return Err(format!(
                    "peer: GetExtendedTcpTable: {}",
                    std::io::Error::from_raw_os_error(e as i32)
                ));
            }
        }
    }
    Err("peer: TCP table kept growing between sizing and read".to_owned())
}

fn image_path(pid: u32) -> Result<String, String> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let mut buf = vec![0u16; MAX_LONG_PATH];
    let mut size = buf.len() as u32;
    if unsafe { QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut size) } == 0 {
        return Err(format!(
            "peer: QueryFullProcessImageName({pid}): {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(long_path(&buf[..size as usize]))
}

/// `path` with every 8.3 short name replaced by its long name, or `path` itself when that
/// cannot be read.
fn long_path(path: &[u16]) -> String {
    let short = String::from_utf16_lossy(path);
    let mut input = path.to_vec();
    input.push(0);
    let mut buf = vec![0u16; MAX_LONG_PATH];
    let n = unsafe { GetLongPathNameW(input.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if n == 0 || n as usize >= buf.len() {
        return short;
    }
    String::from_utf16_lossy(&buf[..n as usize])
}

/// The logon session `pid` runs in, read from the pid alone.
fn session_of(pid: u32) -> Option<u32> {
    let mut id = 0;
    (unsafe { ProcessIdToSessionId(pid, &mut id) } != 0).then_some(id)
}

/// The account SID `pid` runs as.
fn user_of(pid: u32) -> Option<String> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    token_user(h.0)
}

fn token_user(process: HANDLE) -> Option<String> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return None;
    }
    let token = Owned(token);
    let mut len = 0u32;
    unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    if unsafe { GetTokenInformation(token.0, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) }
        == 0
    {
        return None;
    }
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return None;
    }
    let sid = String::from_utf16_lossy(unsafe { terminated(text) });
    unsafe { LocalFree(text as HLOCAL) };
    Some(sid)
}

/// The NUL-terminated UTF-16 string at `p`, without its NUL.
unsafe fn terminated<'a>(p: *const u16) -> &'a [u16] {
    let mut n = 0;
    while unsafe { *p.add(n) } != 0 {
        n += 1;
    }
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// This process's logon session.
pub fn own_session() -> Result<Option<u32>, String> {
    session_of(unsafe { GetCurrentProcessId() })
        .map(Some)
        .ok_or_else(|| format!("peer: own session: {}", std::io::Error::last_os_error()))
}

/// This process's account SID, when it can be read.
pub fn own_user() -> Option<String> {
    token_user(unsafe { GetCurrentProcess() })
}

/// This process's parent, from the process list.
pub fn parent() -> Option<u32> {
    let own = unsafe { GetCurrentProcessId() };
    table().ok()?.by_pid.get(&own).map(|p| p.parent)
}

/// Every process in `session` with its full executable path, or why that could not be read.
/// A process whose session cannot be read is listed too, as unreadable: it might be in it.
pub fn candidates(session: Option<u32>) -> Result<Vec<ProcessImage>, String> {
    let t = table()?;
    let mut out = Vec::new();
    for (&pid, info) in t.by_pid.iter().filter(|(pid, _)| **pid != 0) {
        let Some(s) = session_of(pid) else {
            out.push(ProcessImage::unreadable(
                pid,
                &info.name,
                "peer: the process's session could not be read",
            ));
            continue;
        };
        if Some(s) != session {
            continue;
        }
        let (image, error) = match image_path(pid) {
            Ok(image) => (image, None),
            Err(e) => (String::new(), Some(e)),
        };
        out.push(ProcessImage {
            pid,
            name: info.name.clone(),
            image,
            created: created(pid),
            error,
        });
    }
    Ok(out)
}

/// One snapshot of the process list. Start times are read per process asked about.
pub struct Table {
    by_pid: HashMap<u32, ProcessInfo>,
}

pub fn table() -> Result<Table, String> {
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return Err(format!(
            "peer: CreateToolhelp32Snapshot: {}",
            std::io::Error::last_os_error()
        ));
    }
    let snap = Owned(snap);
    let mut e = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..PROCESSENTRY32W::default()
    };
    if unsafe { Process32FirstW(snap.0, &mut e) } == 0 {
        return Err(format!(
            "peer: Process32First: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut by_pid = HashMap::with_capacity(512);
    loop {
        let name_len = e
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(e.szExeFile.len());
        let mut p = ProcessInfo::new(e.th32ProcessID, e.th32ParentProcessID, None);
        p.name = String::from_utf16_lossy(&e.szExeFile[..name_len]);
        by_pid.insert(e.th32ProcessID, p);
        if unsafe { Process32NextW(snap.0, &mut e) } == 0 {
            break;
        }
    }
    Ok(Table { by_pid })
}

impl ProcessTable for Table {
    fn info(&self, pid: u32) -> Result<ProcessInfo, String> {
        let mut p = self
            .by_pid
            .get(&pid)
            .cloned()
            .ok_or_else(|| format!("peer: no process {pid} in the snapshot"))?;
        p.created = created(pid);
        Ok(p)
    }
}

/// When `pid` started, when that can be read.
fn created(pid: u32) -> Option<SystemTime> {
    let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION).ok()?;
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut x, mut k, mut u) = (zero, zero, zero, zero);
    if unsafe { GetProcessTimes(h.0, &mut c, &mut x, &mut k, &mut u) } == 0 {
        return None;
    }
    let ticks = u64::from(c.dwHighDateTime) << 32 | u64::from(c.dwLowDateTime);
    let since = ticks.checked_sub(FILETIME_UNIX)?;
    Some(UNIX_EPOCH + Duration::from_nanos(since * 100))
}

/// An executable's version resource, cached by path, size and modification time.
pub fn metadata(path: &str) -> Result<ImageMetadata, String> {
    type Cache = HashMap<(String, u64, SystemTime), ImageMetadata>;
    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
    let st = std::fs::metadata(path).map_err(|e| format!("peer: metadata: {e}"))?;
    let key = (
        path.to_owned(),
        st.len(),
        st.modified().map_err(|e| format!("peer: metadata: {e}"))?,
    );
    let lock = || CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(m) = lock().as_ref().and_then(|c| c.get(&key)) {
        return Ok(m.clone());
    }
    let m = version_resource(path)?;
    lock().get_or_insert_default().insert(key, m.clone());
    Ok(m)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn version_resource(path: &str) -> Result<ImageMetadata, String> {
    let name = wide(path);
    let fail = || {
        format!(
            "peer: version resource of {path}: {}",
            std::io::Error::last_os_error()
        )
    };
    let size = unsafe { GetFileVersionInfoSizeW(name.as_ptr(), std::ptr::null_mut()) };
    if size == 0 {
        return Err(fail());
    }
    let mut buf = vec![0u8; size as usize];
    if unsafe { GetFileVersionInfoW(name.as_ptr(), 0, size, buf.as_mut_ptr().cast()) } == 0 {
        return Err(fail());
    }
    let mut langs = translations(&buf);
    langs.extend(["040904b0".to_owned(), "040904e4".to_owned()]);
    for lang in langs {
        let field = |f: &str| query_string(&buf, &format!("\\StringFileInfo\\{lang}\\{f}"));
        let m = ImageMetadata {
            company: field("CompanyName"),
            product: field("ProductName"),
            original_filename: field("OriginalFilename"),
        };
        if m != ImageMetadata::default() {
            return Ok(m);
        }
    }
    Err("peer: version resource has no company, product or original filename".to_owned())
}

/// The value `sub` names in the version resource `buf`, and its length as reported.
fn query(buf: &[u8], sub: &str) -> Option<(*const c_void, u32)> {
    let sub = wide(sub);
    let mut p = std::ptr::null_mut();
    let mut n = 0u32;
    let ok = unsafe { VerQueryValueW(buf.as_ptr().cast(), sub.as_ptr(), &mut p, &mut n) };
    (ok != 0 && !p.is_null()).then_some((p.cast_const(), n))
}

fn translations(buf: &[u8]) -> Vec<String> {
    let Some((p, n)) = query(buf, "\\VarFileInfo\\Translation") else {
        return Vec::new();
    };
    let words = unsafe { std::slice::from_raw_parts(p.cast::<u16>(), n as usize / 2) };
    words
        .as_chunks::<2>()
        .0
        .iter()
        .map(|[lang, page]| format!("{lang:04x}{page:04x}"))
        .collect()
}

fn query_string(buf: &[u8], sub: &str) -> String {
    let Some((p, n)) = query(buf, sub) else {
        return String::new();
    };
    let s = unsafe { std::slice::from_raw_parts(p.cast::<u16>(), n as usize) };
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

/// Whether `held` is the file now at `path`: the same volume and file index.
pub fn same_file(held: &std::fs::File, path: &std::path::Path) -> std::io::Result<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    let at = std::fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(0x1 | 0x2 | 0x4)
        .open(path)?;
    let id = |f: &std::fs::File| -> std::io::Result<(u32, u32, u32)> {
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((
            info.dwVolumeSerialNumber,
            info.nFileIndexHigh,
            info.nFileIndexLow,
        ))
    };
    Ok(id(held)? == id(&at)?)
}

/// This machine's offset from UTC now, in minutes, daylight saving included.
pub fn utc_offset_minutes() -> i32 {
    let mut tz = TIME_ZONE_INFORMATION::default();
    let bias = match unsafe { GetTimeZoneInformation(&mut tz) } {
        TIME_ZONE_ID_DAYLIGHT => tz.Bias + tz.DaylightBias,
        TIME_ZONE_ID_STANDARD => tz.Bias + tz.StandardBias,
        TIME_ZONE_ID_INVALID => return 0,
        _ => tz.Bias,
    };
    -bias
}

/// The reparse tag of what is at `path`, when it is a reparse point and can be read.
pub fn reparse_tag(path: &str) -> Option<u32> {
    let name = wide(path);
    let mut data = WIN32_FIND_DATAW::default();
    let h = unsafe { FindFirstFileW(name.as_ptr(), &mut data) };
    if h == INVALID_HANDLE_VALUE {
        return None;
    }
    unsafe { FindClose(h) };
    (data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0).then_some(data.dwReserved0)
}

/// Watches processes for their exit through a handle, which binds the watch to the process
/// the pid named when it was opened.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Holder;

impl Hold for Holder {
    fn hold(&self, pid: u32) -> Result<Held, String> {
        let h = open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)
            .map_err(|e| format!("{e} to hold"))?;
        let (exited, held) = Held::channel();
        std::thread::spawn(move || {
            let h = h;
            while !exited.is_closed() {
                match unsafe { WaitForSingleObject(h.0, POLL_EXIT) } {
                    WAIT_OBJECT_0 => {
                        let _ = exited.send(());
                        return;
                    }
                    WAIT_TIMEOUT => {}
                    _ => return,
                }
            }
        });
        Ok(held)
    }
}

unsafe impl Send for Owned {}
