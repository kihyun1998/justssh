//! `justssh-broker -listen ADDR -host-key FILE [-logpath DIR] [-attach-root DIR]...`: acwbroker's
//! command line, its handoff pipe on stdin and stdout, and nothing else on stdout.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::ExitCode;

use justssh_broker::hostkey;
use justssh_broker::issue::require_loopback;
use justssh_broker::session::{Session, Tokens};

/// acwbroker's flags that this broker acts on; the others are read and ignored.
#[derive(Debug, Default)]
struct Options {
    listen: Option<String>,
    host_key: Option<PathBuf>,
    version: bool,
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
            _ => {}
        }
    }
    Ok(options)
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

    let mut tokens = Tokens::default();
    session.serve(&mut tokens).map_err(|e| format!("{e:?}"))
}
