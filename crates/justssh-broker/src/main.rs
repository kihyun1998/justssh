//! `justssh-broker -listen ADDR -host-key FILE [-logpath DIR] [-attach-root DIR]...`: acwbroker's
//! command line, its handoff pipe on stdin and stdout, and nothing else on stdout.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use justssh::HostKey;
use justssh_broker::broker;
use justssh_broker::hostkey;
use justssh_broker::issue::require_loopback;
use justssh_broker::peer;
use justssh_broker::session::Session;
use justssh_broker::tokens::Tokens;

/// acwbroker's flags that this broker acts on; the others are read and ignored.
#[derive(Debug)]
struct Options {
    listen: Option<String>,
    host_key: Option<PathBuf>,
    dial_timeout: Duration,
    version: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            listen: None,
            host_key: None,
            dial_timeout: Duration::from_secs(15),
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

fn run(options: Options) -> Result<(), String> {
    let mut session = Session::new(std::io::stdin().lock(), std::io::stdout().lock());
    session.handshake().map_err(|e| format!("{e:?}"))?;
    let config = match peer::config() {
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

    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let tokens = Tokens::new(config, runtime.handle().clone());
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let listener = {
        let _entered = runtime.enter();
        tokio::net::TcpListener::from_std(listener).map_err(|e| e.to_string())?
    };
    let host_key = HostKey::new(key.private_key().clone());
    runtime.spawn(broker::serve(
        listener,
        host_key,
        tokens.clone(),
        options.dial_timeout,
        Arc::new(peer::probe),
    ));
    let served = session.serve(&tokens).map_err(|e| format!("{e:?}"));
    runtime.shutdown_background();
    served
}
