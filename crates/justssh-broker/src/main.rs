//! `justssh-broker -listen ADDR -host-key FILE [-logpath DIR] [-attach-root DIR]...`: acwbroker's
//! command line, its handoff pipe on stdin and stdout, and nothing else on stdout.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::mpsc::{Sender, channel};
use std::time::Duration;

use justssh::HostKey;
use justssh_broker::broker;
use justssh_broker::caller::ProcessKey;
use justssh_broker::hostkey;
use justssh_broker::hostkey::HostKeys;
use justssh_broker::issue::require_loopback;
use justssh_broker::log::Log;
use justssh_broker::logfile::{self, LogFile, Tee};
use justssh_broker::peer;
use justssh_broker::session::{End, Hooks, Session};
use justssh_broker::shred::Shredder;
use justssh_broker::tokens::{Hold, Tokens};
use tokio::runtime::Handle;
use tokio::task::AbortHandle;

/// acwbroker's flags that this broker acts on; the others are read and ignored.
#[derive(Debug)]
struct Options {
    listen: Option<String>,
    host_key: Option<PathBuf>,
    dial_timeout: Duration,
    attach_roots: Vec<PathBuf>,
    logpath: Option<PathBuf>,
    profile: Option<String>,
    version: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            listen: None,
            host_key: None,
            dial_timeout: Duration::from_secs(15),
            attach_roots: Vec::new(),
            logpath: None,
            profile: None,
            version: false,
        }
    }
}

/// Reads flags as Go's `flag` package does: `-name value`, `-name=value` or with two dashes,
/// stopping at `--` or the first argument that is not a flag.
fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, String> {
    const VALUED: [&str; 6] = [
        "listen",
        "host-key",
        "dial-timeout",
        "logpath",
        "profile",
        "attach-root",
    ];
    const BOOL: [&str; 2] = ["unsafe-no-harden", "version"];
    let mut options = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--" || !arg.starts_with('-') || arg == "-" {
            break;
        }
        let flag = arg.trim_start_matches('-');
        let (name, inline) = match flag.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (flag, None),
        };
        if BOOL.contains(&name) {
            let on = match inline.as_deref() {
                None | Some("1" | "t" | "T" | "true" | "TRUE" | "True") => true,
                Some("0" | "f" | "F" | "false" | "FALSE" | "False") => false,
                Some(v) => return Err(format!("invalid boolean value {v:?} for -{name}")),
            };
            if name == "version" {
                options.version = on;
            }
            continue;
        }
        if !VALUED.contains(&name) {
            return Err(format!("flag provided but not defined: -{name}"));
        }
        let value = match inline {
            Some(v) => v,
            None => args
                .next()
                .ok_or_else(|| format!("flag needs an argument: -{name}"))?,
        };
        match name {
            "listen" => options.listen = Some(value),
            "host-key" => options.host_key = Some(PathBuf::from(value)),
            "attach-root" => options.attach_roots.push(PathBuf::from(value)),
            "logpath" => {
                options.logpath = Some(PathBuf::from(value)).filter(|p| !p.as_os_str().is_empty())
            }
            "profile" => options.profile = Some(value),
            "dial-timeout" => {
                options.dial_timeout = duration(&value)
                    .ok_or_else(|| format!("invalid value {value:?} for flag -dial-timeout"))?;
            }
            _ => {}
        }
    }
    Ok(options)
}

/// A duration as Go's `time.ParseDuration` writes one, such as `15s`, `1m30s` or `500ms`.
fn duration(text: &str) -> Option<Duration> {
    let mut rest = text;
    let mut total = Duration::ZERO;
    if rest == "0" {
        return Some(total);
    }
    while !rest.is_empty() {
        let digits = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let (number, after) = rest.split_at(digits);
        let unit_len = after
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(after.len());
        let (unit, after) = after.split_at(unit_len);
        let seconds = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        total += Duration::try_from_secs_f64(number.parse::<f64>().ok()? * seconds).ok()?;
        rest = after;
    }
    Some(total)
}

fn main() -> ExitCode {
    let options = match parse(std::env::args().skip(1)) {
        Ok(options) => options,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    if options.version {
        println!("justssh-broker {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("justssh-broker: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The process's log: every line to `acwbroker.log` in `dir`, or in the ACRA home, and to
/// stderr. A file that cannot be opened leaves stderr alone and says so there.
fn logger(dir: Option<PathBuf>, profile: Option<String>) -> Log {
    let path = dir
        .or_else(hostkey::acra_home)
        .map(|d| d.join(logfile::NAME))
        .ok_or_else(|| "no ACRA_HOME and no home directory".to_owned());
    let file = path.and_then(|p| {
        LogFile::open(&p, logfile::LIMIT, logfile::KEEP)
            .map_err(|e| format!("open {}: {e}", p.display()))
    });
    match file {
        Ok(file) => Log::new(Tee::new(file, std::io::stderr()), profile),
        Err(e) => {
            let log = Log::new(std::io::stderr(), profile);
            log.warn(
                "log file unavailable; logging to stderr only",
                &[("err", e.into())],
            );
            log
        }
    }
}

fn run(options: Options) -> Result<(), String> {
    let log = logger(options.logpath.clone(), options.profile.clone());
    let mut session = Session::new(std::io::stdin(), std::io::stdout());
    session.set_log(log.clone());
    session.handshake().map_err(|e| format!("{e:?}"))?;
    let mut config = match peer::config(&log) {
        Ok(config) => config,
        Err(e) => {
            let _ = session.fail("session unavailable");
            return Err(e);
        }
    };

    let path = options
        .host_key
        .or_else(hostkey::default_path)
        .ok_or("no ACRA_HOME and no home directory")?;
    let key = match hostkey::load(&path) {
        Ok(key) => key,
        Err(e) => {
            let _ = session.fail("host key unavailable");
            return Err(e);
        }
    };

    let addr = options.listen.unwrap_or_else(|| "127.0.0.1:0".to_owned());
    let listener = require_loopback(addr.as_bytes())
        .map_err(|e| format!("{addr}: {e:?}"))
        .and_then(|()| TcpListener::bind(&addr).map_err(|e| format!("{addr}: {e}")));
    let listener = match listener {
        Ok(listener) => listener,
        Err(e) => {
            let _ = session.fail("listener unavailable");
            return Err(e);
        }
    };
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    session
        .announce(&bound.to_string(), &key.private_key().plain_public_blob())
        .map_err(|e| format!("{e:?}"))?;

    let shredder = Shredder::new(options.attach_roots);
    let pipe = session.pipe();
    config.claimed = Some(Arc::new(move |pid| pipe.claimed(pid)));
    let pipe = session.pipe();
    config.unclaimed = Some(Arc::new(move |pid| pipe.disposed(pid)));
    let shred = shredder.clone();
    let l = log.clone();
    config.shred = Some(Arc::new(move |path| {
        let (shred, l) = (shred.clone(), l.clone());
        std::thread::spawn(move || match shred.shred(&path) {
            Ok(()) => l.info("attached file shredded", &[]),
            Err(e) => l.warn(
                "could not shred an attached file; the app's next start clears it",
                &[("err", e.into())],
            ),
        });
    }));
    let l = log.clone();
    config.disposed = Some(Arc::new(move |reason, live| {
        l.info(
            "credential disposed",
            &[("reason", reason.into()), ("live", live.into())],
        )
    }));
    let l = log.clone();
    config.hold_failed = Some(Arc::new(move |pid, err| {
        l.warn(
            "could not watch a pinned process for its exit; its session will not end when it does",
            &[("pid", pid.into()), ("err", err.into())],
        )
    }));
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let tokens = Tokens::new(config, runtime.handle().clone());
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let listener = {
        let _entered = runtime.enter();
        tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?
    };
    let host_keys =
        HostKeys::new(HostKey::new(key.private_key().clone())).legacy(hostkey::legacy_path(&path));
    let serving = runtime.spawn(broker::serve(
        listener,
        host_keys,
        tokens.clone(),
        options.dial_timeout,
        Arc::new(peer::probe),
        log.clone(),
    ));
    let (events, ended) = channel();
    let mut hooks = Freezer {
        tokens: tokens.clone(),
        serving: serving.abort_handle(),
        shredder,
        runtime: runtime.handle().clone(),
        events: events.clone(),
        log: log.clone(),
    };
    std::thread::spawn(move || {
        let served = session.serve(&tokens, &mut hooks);
        let _ = events.send(Event::PipeEnded(served, session.frozen()));
    });
    let result = match ended.recv() {
        Ok(Event::PipeEnded(served, false)) => served.map_err(|e| format!("{e:?}")),
        Ok(Event::PipeEnded(_, true)) => {
            log.info("the app has let go; staying until the tunnel exits", &[]);
            if ended.iter().all(|e| !matches!(e, Event::TunnelExited)) {
                loop {
                    std::thread::park();
                }
            }
            log.info("the tunnel exited; shutting down", &[]);
            Ok(())
        }
        Ok(Event::TunnelExited) => {
            log.info("the tunnel exited; shutting down", &[]);
            Ok(())
        }
        Err(_) => Err("the handoff session ended without saying how".to_owned()),
    };
    runtime.shutdown_background();
    result
}

/// What ends the process: the pipe ending, and whether it had frozen, or the tunnel a FREEZE
/// watches exiting.
enum Event {
    PipeEnded(Result<(), End>, bool),
    TunnelExited,
}

/// Carries out a FREEZE and judges ATTACH paths.
struct Freezer {
    tokens: Tokens,
    serving: AbortHandle,
    shredder: Shredder,
    runtime: Handle,
    events: Sender<Event>,
    log: Log,
}

impl Hooks for Freezer {
    /// Watches `tunnel` first, changing nothing when it cannot; then the tokens take nothing
    /// more and the listener closes. Connections already accepted go on.
    fn freeze(&mut self, tunnel: u32) -> Result<(), String> {
        let held = peer::Holder::default().hold(tunnel)?;
        self.tokens.freeze();
        self.serving.abort();
        self.log.info(
            "frozen: no new connections; staying until the tunnel exits",
            &[("tunnel", tunnel.into())],
        );
        let events = self.events.clone();
        self.runtime.spawn(async move {
            if held.exited().await {
                let _ = events.send(Event::TunnelExited);
            }
        });
        Ok(())
    }

    fn admit(&self, path: &str) -> Result<(), String> {
        self.shredder.admit(path)
    }

    fn terminal_holders(&self, terminal: i32) -> Result<Vec<ProcessKey>, String> {
        peer::terminal_holders(terminal)
    }
}
