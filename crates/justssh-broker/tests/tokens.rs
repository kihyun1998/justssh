//! The tokens' judgement, ported from acwbroker's `service/tokens`, `domain/model` and
//! `infrastructure/peer/chain` tests. The callers are the shapes measured against acwbroker:
//! WinSCP one process with many connections; FileZilla fzsftp under filezilla under the app;
//! MobaXterm `_ssh.exe` and its main window 0.237 s apart and unrelated; SecureCRT started by
//! the user under explorer.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use justssh::Zeroizing;
use justssh_broker::caller::{
    Caller, MAX_DEPTH, Owner, ProcessImage, ProcessInfo, ProcessKey, ProcessTable, Stop, walk,
};
use justssh_broker::issue::{self, Issue, Rule};
use justssh_broker::rule::{ImageMetadata, admits};
use justssh_broker::tokens::{
    Admission, AttachError, Config, DEFAULT_ADMIT, DEFAULT_GRACE, DEFAULT_WINDOW, Grant, Held,
    Hold, Refusal, Tokens,
};
use tokio::sync::oneshot;
use tokio::time::{Instant, advance, timeout};

const APP: u32 = 4242;
const EXPLORER: u32 = 11312;
const FILEZILLA: u32 = 35156;
const FZSFTP: u32 = 35032;
const WINSCP: u32 = 16880;
const MOBA_SSH: u32 = 31672;
const MOBA_MAIN: u32 = 20296;
const SECURECRT: u32 = 29324;
const PUTTY: u32 = 10816;
const THIEF: u32 = 66666;
const OWN_SESSION: u32 = 1;
const OWN_SID: &str = "S-1-5-21-1-2-3-1001";
const OTHER_SID: &str = "S-1-5-21-1-2-3-1002";
const USER: &[u8] = b"srv42@10.0.0.9";

fn rec(tag: u8, val: &[u8]) -> Vec<u8> {
    [&[tag][..], &(val.len() as u32).to_be_bytes(), val].concat()
}

/// A password ISSUE for `user` to `upstream`, with `extra` records.
fn issue_for(user: &[u8], upstream: &str, password: &[u8], extra: &[(u8, &[u8])]) -> Issue {
    let mut payload = [
        rec(0x10, b"password"),
        rec(0x15, user),
        rec(0x16, upstream.as_bytes()),
        rec(0x11, password),
    ]
    .concat();
    for (tag, val) in extra {
        payload.extend(rec(*tag, val));
    }
    issue::decode(&payload).unwrap()
}

/// A caller whose ancestry reaches the app, with the shells above it a real chain carries.
fn in_tree(chain: &[u32]) -> Caller {
    let mut c = Caller::new(chain[0]);
    c.ancestry = [chain, &[APP, 5504, 34924]].concat();
    c
}

/// An instance the user started from the desktop.
fn out_of_tree(pid: u32) -> Caller {
    let mut c = Caller::new(pid);
    c.ancestry = vec![pid, EXPLORER];
    c
}

/// MobaXterm's `_ssh.exe`, whose recorded parent is already gone.
fn orphan(pid: u32) -> Caller {
    let mut c = Caller::new(pid);
    c.ancestry = vec![pid];
    c
}

fn unowned() -> Caller {
    let mut c = Caller::default();
    c.error = Some("peer: no socket owns that endpoint".to_owned());
    c
}

fn in_session(mut c: Caller, id: u32) -> Caller {
    c.session = Some(id);
    c
}

fn as_user(mut c: Caller, sid: &str) -> Caller {
    c.user = Some(sid.to_owned());
    c
}

fn with_image(mut c: Caller, image: &str) -> Caller {
    c.image_path = image.to_owned();
    c
}

/// Process exits the test causes, and every watch the tokens started.
#[derive(Default)]
struct FakeHold {
    watches: Mutex<Vec<(u32, oneshot::Sender<()>)>>,
    fail: Vec<u32>,
}

impl Hold for FakeHold {
    fn hold(&self, pid: u32) -> Result<Held, String> {
        if self.fail.contains(&pid) {
            return Err("no such process".to_owned());
        }
        let (tx, held) = Held::channel();
        self.watches.lock().unwrap().push((pid, tx));
        Ok(held)
    }
}

impl FakeHold {
    fn exit(&self, pid: u32) {
        let mut w = self.watches.lock().unwrap();
        if let Some(i) = w.iter().position(|(p, _)| *p == pid) {
            let (_, tx) = w.remove(i);
            let _ = tx.send(());
        }
    }

    fn held(&self) -> Vec<u32> {
        self.watches
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| *p)
            .collect()
    }

    fn released(&self) -> usize {
        let w = self.watches.lock().unwrap();
        w.iter().filter(|(_, tx)| tx.is_closed()).count()
    }
}

/// Lets the tasks the tokens spawned run.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// Tokens on a paused clock the test drives, the connections the test holds open, and when
/// the test began.
struct Bench {
    tokens: Tokens,
    start: Instant,
    open: Vec<Grant>,
}

impl Bench {
    fn new() -> Self {
        Bench::with(|_| {})
    }

    fn with(f: impl FnOnce(&mut Config)) -> Self {
        let mut config = Config::default();
        config.app = APP;
        f(&mut config);
        Bench {
            tokens: Tokens::new(config, tokio::runtime::Handle::current()),
            start: Instant::now(),
            open: Vec::new(),
        }
    }

    /// Tokens whose timers run on the real clock, so not within a test, as acwbroker's tests
    /// drive its clock without its timers. What they tell runs at once.
    fn without_timers(f: impl FnOnce(&mut Config)) -> Self {
        let idle: &'static tokio::runtime::Runtime = Box::leak(Box::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(1)
                .enable_time()
                .build()
                .unwrap(),
        ));
        let mut config = Config::default();
        config.app = APP;
        f(&mut config);
        Bench {
            tokens: Tokens::new(config, idle.handle().clone()),
            start: Instant::now(),
            open: Vec::new(),
        }
    }

    fn issue(&self) -> Zeroizing<String> {
        self.issue_with(&[])
    }

    fn issue_with(&self, extra: &[(u8, &[u8])]) -> Zeroizing<String> {
        self.tokens
            .issue(issue_for(USER, "127.0.0.1:2222", b"p", extra))
    }

    /// Moves the clock to `d` after the test began.
    async fn at(&self, d: Duration) {
        let target = self.start + d;
        let now = Instant::now();
        if target > now {
            advance(target - now).await;
        }
        settle().await;
    }

    fn connect(&self, token: &str, c: &Caller) -> Grant {
        match self.tokens.authorize(token.as_bytes(), USER, c) {
            Ok(g) => g,
            Err(r) => panic!("caller pid={} was refused: {r:?}", c.pid),
        }
    }

    /// Admits `c`, keeping its connection open, and says by which rule.
    fn admit(&mut self, token: &str, c: &Caller) -> Admission {
        let g = self.connect(token, c);
        let a = g.admission;
        self.open.push(g);
        a
    }

    fn refuse(&self, token: &str, c: &Caller) -> Refusal {
        match self.tokens.authorize(token.as_bytes(), USER, c) {
            Ok(_) => panic!("caller pid={} was admitted", c.pid),
            Err(r) => r,
        }
    }
}

// pin_test.go

#[tokio::test(start_paused = true)]
async fn the_same_process_is_refused_a_reconnection_after_admission() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(Duration::from_secs(319)).await;
    assert_eq!(b.refuse(&t, &in_tree(&[WINSCP])), Refusal::AdmissionClosed);
}

#[tokio::test(start_paused = true)]
async fn another_process_is_refused_once_the_token_is_claimed() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(Duration::from_secs(30)).await;
    assert_eq!(b.refuse(&t, &in_tree(&[THIEF])), Refusal::CallerNotPinned);
}

#[tokio::test(start_paused = true)]
async fn an_unrelated_sibling_within_grace_may_also_claim() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &orphan(MOBA_SSH));
    b.at(Duration::from_millis(237)).await;
    b.admit(&t, &out_of_tree(MOBA_MAIN));
    b.at(Duration::from_secs(30)).await;
    b.admit(&t, &orphan(MOBA_SSH));
    b.admit(&t, &out_of_tree(MOBA_MAIN));
}

#[tokio::test(start_paused = true)]
async fn an_unrelated_process_after_grace_is_refused() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(DEFAULT_GRACE + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &out_of_tree(THIEF)), Refusal::CallerNotPinned);
}

#[tokio::test(start_paused = true)]
async fn a_process_that_arrives_first_claims_the_token_and_shuts_out_the_program() {
    let mut b = Bench::new();
    let t = b.issue();
    assert_eq!(b.admit(&t, &out_of_tree(THIEF)), Admission::Claim);
    b.at(DEFAULT_GRACE + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &in_tree(&[PUTTY])), Refusal::CallerNotPinned);
}

#[tokio::test(start_paused = true)]
async fn a_process_that_arrives_first_within_grace_leaves_the_program_admitted() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &out_of_tree(THIEF));
    b.at(Duration::from_millis(400)).await;
    assert_eq!(b.admit(&t, &in_tree(&[PUTTY])), Admission::Grace);
}

#[tokio::test(start_paused = true)]
async fn a_helper_started_later_is_admitted_by_its_parent() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[FZSFTP, FILEZILLA]));
    b.at(Duration::from_secs(30)).await;
    b.admit(&t, &in_tree(&[41000, FILEZILLA]));
    b.at(DEFAULT_ADMIT + Duration::from_secs(1)).await;
    assert_eq!(
        b.refuse(&t, &in_tree(&[41001, FILEZILLA])),
        Refusal::AdmissionClosed
    );
}

#[tokio::test(start_paused = true)]
async fn another_program_we_launched_is_refused() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[FZSFTP, FILEZILLA]));
    b.at(Duration::from_secs(30)).await;
    assert_eq!(b.refuse(&t, &in_tree(&[PUTTY])), Refusal::CallerNotPinned);
}

#[tokio::test(start_paused = true)]
async fn an_out_of_tree_caller_pins_only_itself() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &out_of_tree(SECURECRT));
    b.at(Duration::from_secs(30)).await;
    assert_eq!(b.refuse(&t, &out_of_tree(THIEF)), Refusal::CallerNotPinned);
    b.admit(&t, &out_of_tree(SECURECRT));
}

#[tokio::test(start_paused = true)]
async fn a_token_presented_after_its_window_expires() {
    let b = Bench::without_timers(|_| {});
    let t = b.issue();
    b.at(DEFAULT_WINDOW + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &in_tree(&[WINSCP])), Refusal::TokenExpired);
    assert_eq!(b.tokens.len(), 0);
    assert_eq!(b.refuse(&t, &in_tree(&[WINSCP])), Refusal::UnknownToken);
}

#[tokio::test(start_paused = true)]
async fn the_window_does_not_apply_once_the_token_is_claimed() {
    let mut b = Bench::new();
    let t = b.issue();
    b.at(DEFAULT_WINDOW - Duration::from_secs(1)).await;
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(DEFAULT_WINDOW + Duration::from_secs(30)).await;
    b.admit(&t, &in_tree(&[WINSCP]));
}

#[tokio::test(start_paused = true)]
async fn pinning_holds_the_process_ids_it_pinned_and_disposal_releases_them() {
    let hold = Arc::new(FakeHold::default());
    let mut b = Bench::with(|c| c.peer.hold = Some(hold.clone()));
    let t = b.issue();
    b.admit(&t, &in_tree(&[FZSFTP, FILEZILLA]));
    assert_eq!(hold.held(), [FZSFTP, FILEZILLA]);
    assert!(b.tokens.revoke(&t));
    settle().await;
    assert_eq!(hold.released(), 2);
}

#[tokio::test(start_paused = true)]
async fn revoke_removes_the_token() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[WINSCP]));
    assert!(b.tokens.revoke(&t));
    assert_eq!(b.tokens.len(), 0);
    assert_eq!(b.refuse(&t, &in_tree(&[WINSCP])), Refusal::UnknownToken);
    assert!(!b.tokens.revoke(&t));
}

#[tokio::test(start_paused = true)]
async fn an_unused_token_is_disposed_of_without_being_presented() {
    let b = Bench::with(|c| c.window = Duration::from_millis(30));
    let t = b.issue();
    b.at(Duration::from_millis(31)).await;
    assert_eq!(b.tokens.len(), 0);
    assert_eq!(b.refuse(&t, &in_tree(&[WINSCP])), Refusal::UnknownToken);
}

// admission_test.go

#[tokio::test(start_paused = true)]
async fn the_first_caller_is_admitted_by_claim() {
    let mut b = Bench::new();
    let t = b.issue();
    assert_eq!(b.admit(&t, &in_tree(&[PUTTY])), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn the_same_process_again_is_admitted_by_pin() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(Duration::from_secs(30)).await;
    assert_eq!(b.admit(&t, &in_tree(&[WINSCP])), Admission::Pin);
}

#[tokio::test(start_paused = true)]
async fn a_helper_under_the_pinned_program_is_admitted_as_descendant() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[FZSFTP, FILEZILLA]));
    b.at(Duration::from_secs(30)).await;
    assert_eq!(
        b.admit(&t, &in_tree(&[35040, FILEZILLA])),
        Admission::Descendant
    );
}

#[tokio::test(start_paused = true)]
async fn an_unrelated_process_inside_the_grace_is_admitted_by_grace_and_pinned_afterwards() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &orphan(MOBA_SSH));
    b.at(Duration::from_millis(237)).await;
    assert_eq!(b.admit(&t, &out_of_tree(MOBA_MAIN)), Admission::Grace);
    b.at(DEFAULT_GRACE + Duration::from_secs(1)).await;
    assert_eq!(b.admit(&t, &out_of_tree(MOBA_MAIN)), Admission::Pin);
}

#[tokio::test(start_paused = true)]
async fn an_unmeasured_caller_is_still_named_by_branch() {
    let mut b = Bench::new();
    let t = b.issue();
    let unmeasured = Caller::new(PUTTY);
    assert_eq!(b.admit(&t, &unmeasured), Admission::Claim);
    b.at(Duration::from_secs(30)).await;
    assert_eq!(b.admit(&t, &unmeasured), Admission::Pin);
}

// admit_test.go

#[tokio::test(start_paused = true)]
async fn the_pinned_process_is_refused_a_new_connection_after_admission_closes() {
    let mut b = Bench::new();
    let t = b.issue();
    let securecrt = out_of_tree(SECURECRT);
    b.admit(&t, &securecrt);
    b.at(DEFAULT_ADMIT - Duration::from_secs(1)).await;
    b.admit(&t, &securecrt);
    b.at(DEFAULT_ADMIT + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &securecrt), Refusal::AdmissionClosed);
}

#[tokio::test(start_paused = true)]
async fn admission_is_checked_before_the_pin() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(DEFAULT_ADMIT + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &out_of_tree(THIEF)), Refusal::AdmissionClosed);
}

#[tokio::test(start_paused = true)]
async fn admission_counts_from_the_first_connection() {
    let mut b = Bench::new();
    let t = b.issue();
    let putty = in_tree(&[PUTTY]);
    let first = DEFAULT_WINDOW - Duration::from_secs(10);
    b.at(first).await;
    b.admit(&t, &putty);
    b.at(first + DEFAULT_ADMIT - Duration::from_secs(1)).await;
    b.admit(&t, &putty);
    b.at(first + DEFAULT_ADMIT + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &putty), Refusal::AdmissionClosed);
}

#[tokio::test(start_paused = true)]
async fn an_open_connection_outlives_admission() {
    let b = Bench::with(|c| {
        c.admit = Duration::from_millis(20);
        c.idle = Duration::from_secs(3600);
    });
    let t = b.issue();
    let g = b.connect(&t, &in_tree(&[WINSCP]));
    b.at(Duration::from_millis(80)).await;
    assert_eq!(b.tokens.len(), 1);
    assert!(
        timeout(Duration::ZERO, g.conn.disposed()).await.is_err(),
        "admission closing closed a live upstream"
    );
}

#[tokio::test(start_paused = true)]
async fn the_last_connection_closing_after_admission_disposes_at_once() {
    let b = Bench::with(|c| c.idle = Duration::from_secs(3600));
    let t = b.issue();
    let g = b.connect(&t, &in_tree(&[WINSCP]));
    b.at(DEFAULT_ADMIT + Duration::from_secs(1)).await;
    drop(g);
    settle().await;
    assert_eq!(b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn admission_closing_with_nothing_connected_disposes() {
    let b = Bench::with(|c| {
        c.admit = Duration::from_millis(40);
        c.idle = Duration::from_secs(3600);
    });
    let t = b.issue();
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    settle().await;
    assert_eq!(b.tokens.len(), 1, "disposed while admission was still open");
    b.at(Duration::from_millis(41)).await;
    assert_eq!(b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_reconnection_inside_admission_keeps_the_credential() {
    let b = Bench::with(|c| {
        c.admit = Duration::from_millis(60);
        c.idle = Duration::from_secs(3600);
    });
    let t = b.issue();
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    b.at(Duration::from_millis(20)).await;
    let _g = b.connect(&t, &in_tree(&[WINSCP]));
    b.at(Duration::from_millis(140)).await;
    assert_eq!(b.tokens.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn the_close_countdown_runs_from_the_first_connection() {
    let b = Bench::with(|c| c.idle = Duration::from_secs(3600));
    let t = b.issue();
    let first = DEFAULT_WINDOW - Duration::from_secs(10);
    b.at(first).await;
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    b.at(first + DEFAULT_ADMIT - Duration::from_millis(1)).await;
    assert_eq!(b.tokens.len(), 1);
    b.at(first + DEFAULT_ADMIT).await;
    assert_eq!(b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn admission_disposes_even_without_idle() {
    let b = Bench::with(|c| {
        c.admit = Duration::from_millis(30);
        c.idle = Duration::ZERO;
    });
    let t = b.issue();
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    b.at(Duration::from_millis(31)).await;
    assert_eq!(b.tokens.len(), 0);
}

// dispose_test.go

#[tokio::test(start_paused = true)]
async fn a_credential_is_disposed_of_after_its_last_connection_stays_gone() {
    let b = Bench::with(|c| c.idle = Duration::from_millis(30));
    let t = b.issue();
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    b.at(Duration::from_millis(29)).await;
    assert_eq!(b.tokens.len(), 1);
    b.at(Duration::from_millis(31)).await;
    assert_eq!(b.tokens.len(), 0);
    assert_eq!(b.refuse(&t, &in_tree(&[WINSCP])), Refusal::UnknownToken);
}

#[tokio::test(start_paused = true)]
async fn disposal_closes_upstreams_that_are_still_live_or_opened_after_it() {
    let b = Bench::new();
    let t = b.issue();
    let g = b.connect(&t, &in_tree(&[WINSCP]));
    let waiting = tokio::spawn(async move { g.conn.disposed().await });
    settle().await;
    let late = b.connect(&t, &in_tree(&[WINSCP]));
    assert!(b.tokens.revoke(&t));
    timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(1), late.conn.disposed())
        .await
        .expect("a connection told after disposal was left running");
}

#[tokio::test(start_paused = true)]
async fn a_reconnection_inside_the_idle_window_keeps_the_credential() {
    let mut b = Bench::with(|c| c.idle = Duration::from_millis(80));
    let t = b.issue();
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    b.at(Duration::from_millis(20)).await;
    b.admit(&t, &in_tree(&[WINSCP]));
    b.at(Duration::from_millis(180)).await;
    assert_eq!(b.tokens.len(), 1);
    b.admit(&t, &in_tree(&[WINSCP]));
}

#[tokio::test(start_paused = true)]
async fn disposal_waits_for_every_pinned_process_to_exit() {
    let hold = Arc::new(FakeHold::default());
    let mut b = Bench::with(|c| c.peer.hold = Some(hold.clone()));
    let t = b.issue();
    b.admit(&t, &in_tree(&[FZSFTP, FILEZILLA]));
    hold.exit(FZSFTP);
    settle().await;
    assert_eq!(
        b.tokens.len(),
        1,
        "a helper exiting disposed of the credential"
    );
    hold.exit(FILEZILLA);
    settle().await;
    assert_eq!(b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_second_connection_closing_keeps_the_first_counted() {
    let b = Bench::with(|c| c.idle = Duration::from_secs(3600));
    let t = b.issue();
    let a = b.connect(&t, &in_tree(&[WINSCP]));
    let second = b.connect(&t, &in_tree(&[WINSCP]));
    drop(a);
    b.at(DEFAULT_ADMIT + Duration::from_secs(1)).await;
    assert_eq!(b.tokens.len(), 1);
    drop(second);
    settle().await;
    assert_eq!(b.tokens.len(), 0);
}

// owner_test.go, session_test.go, user_test.go, order_test.go

#[tokio::test(start_paused = true)]
async fn a_caller_with_no_owner_is_refused_before_the_token_and_leaves_it_usable() {
    let mut b = Bench::new();
    let t = b.issue();
    assert_eq!(b.refuse(&t, &unowned()), Refusal::OwnerUnknown);
    assert_eq!(b.refuse("not-a-token", &unowned()), Refusal::OwnerUnknown);
    assert_eq!(b.admit(&t, &in_tree(&[PUTTY])), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn a_caller_with_an_owner_but_no_image_is_judged_as_before() {
    let mut b = Bench::new();
    let t = b.issue();
    let mut c = Caller::new(PUTTY);
    c.error = Some("peer: proc_pidpath returned 0".to_owned());
    assert_eq!(b.admit(&t, &c), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn a_terminal_bound_token_refuses_no_owner_first() {
    let mut b = Bench::new();
    let t = b.tokens.issue_bound(
        issue_for(USER, "127.0.0.1:2222", b"p", &[]),
        vec![zsh_key(), login_key()],
    );
    assert_eq!(b.refuse(&t, &unowned()), Refusal::OwnerUnknown);
    assert_eq!(b.refuse(&t, &thief()), Refusal::WrongTerminal);
    b.admit(&t, &in_tab());
}

#[tokio::test(start_paused = true)]
async fn with_an_own_session_the_session_answers_first() {
    let b = Bench::with(|c| c.peer.own_session = Some(OWN_SESSION));
    let t = b.issue();
    assert_eq!(b.refuse(&t, &unowned()), Refusal::SessionUnknown);
}

#[tokio::test(start_paused = true)]
async fn a_caller_in_our_session_is_judged_as_before() {
    let mut b = Bench::with(|c| c.peer.own_session = Some(OWN_SESSION));
    let t = b.issue();
    let c = in_session(in_tree(&[PUTTY]), OWN_SESSION);
    assert_eq!(b.admit(&t, &c), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn a_caller_in_another_session_is_refused_before_the_token_and_leaves_it_usable() {
    for other in [0, 2, 3] {
        let mut b = Bench::with(|c| c.peer.own_session = Some(OWN_SESSION));
        let t = b.issue();
        let thief = in_session(out_of_tree(THIEF), other);
        assert_eq!(b.refuse(&t, &thief), Refusal::OtherSession);
        assert_eq!(b.refuse("not-a-token", &thief), Refusal::OtherSession);
        let c = in_session(in_tree(&[PUTTY]), OWN_SESSION);
        assert_eq!(b.admit(&t, &c), Admission::Claim);
    }
}

#[tokio::test(start_paused = true)]
async fn a_caller_whose_session_is_unknown_is_refused() {
    let b = Bench::with(|c| c.peer.own_session = Some(OWN_SESSION));
    let t = b.issue();
    assert_eq!(b.refuse(&t, &out_of_tree(THIEF)), Refusal::SessionUnknown);
}

#[tokio::test(start_paused = true)]
async fn without_an_own_session_or_user_nothing_is_compared() {
    let mut b = Bench::new();
    let t = b.issue();
    let c = as_user(in_session(in_tree(&[PUTTY]), 7), OTHER_SID);
    assert_eq!(b.admit(&t, &c), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn a_caller_of_our_own_user_is_admitted() {
    let mut b = Bench::with(|c| c.peer.own_user = Some(OWN_SID.to_owned()));
    let t = b.issue();
    let c = as_user(in_tree(&[PUTTY]), OWN_SID);
    assert_eq!(b.admit(&t, &c), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn a_caller_of_another_user_is_refused_before_the_token_and_leaves_it_usable() {
    let mut b = Bench::with(|c| c.peer.own_user = Some(OWN_SID.to_owned()));
    let t = b.issue();
    let thief = as_user(out_of_tree(THIEF), OTHER_SID);
    assert_eq!(b.refuse("not-a-token", &thief), Refusal::OtherUser);
    assert_eq!(b.refuse(&t, &thief), Refusal::OtherUser);
    let c = as_user(in_tree(&[PUTTY]), OWN_SID);
    assert_eq!(b.admit(&t, &c), Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn a_caller_whose_user_is_unknown_is_refused() {
    let b = Bench::with(|c| c.peer.own_user = Some(OWN_SID.to_owned()));
    let t = b.issue();
    assert_eq!(b.refuse(&t, &out_of_tree(THIEF)), Refusal::UserUnknown);
}

#[tokio::test(start_paused = true)]
async fn the_caller_checks_answer_in_order() {
    let mut everything_wrong = unowned();
    everything_wrong.session = Some(OWN_SESSION + 1);
    everything_wrong.user = Some(OTHER_SID.to_owned());
    let mut own_session_unowned = everything_wrong.clone();
    own_session_unowned.session = Some(OWN_SESSION);
    let owned = in_session(as_user(out_of_tree(THIEF), OTHER_SID), OWN_SESSION);
    for (caller, want) in [
        (everything_wrong, Refusal::OtherSession),
        (own_session_unowned, Refusal::OwnerUnknown),
        (owned, Refusal::OtherUser),
    ] {
        let b = Bench::with(|c| {
            c.peer.own_session = Some(OWN_SESSION);
            c.peer.own_user = Some(OWN_SID.to_owned());
        });
        let t = b.issue();
        assert_eq!(b.refuse(&t, &caller), want);
    }
}

// terminal_test.go

fn origin_minus(secs: u64) -> Option<SystemTime> {
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_757_332_020 - secs))
}

fn key(pid: u32) -> ProcessKey {
    ProcessKey::new(pid, origin_minus(1))
}

fn zsh_key() -> ProcessKey {
    ProcessKey::new(3339, origin_minus(2))
}

fn login_key() -> ProcessKey {
    ProcessKey::new(3338, origin_minus(3))
}

fn lineage(keys: &[ProcessKey]) -> Caller {
    let mut c = Caller::new(keys[0].pid);
    c.lineage = keys.to_vec();
    c.ancestry = keys.iter().map(|k| k.pid).collect();
    c
}

/// ssh under expect under bash under the tab's zsh and login, in the terminal app.
fn in_tab() -> Caller {
    lineage(&[
        key(3739),
        key(3737),
        key(3735),
        zsh_key(),
        login_key(),
        key(612),
        key(1),
    ])
}

fn thief() -> Caller {
    lineage(&[key(THIEF), key(1)])
}

fn bound(b: &Bench) -> Zeroizing<String> {
    b.tokens.issue_bound(
        issue_for(USER, "127.0.0.1:2222", b"p", &[]),
        vec![zsh_key(), login_key()],
    )
}

#[tokio::test(start_paused = true)]
async fn a_bound_token_refuses_a_first_caller_outside_the_terminal() {
    let mut b = Bench::new();
    let t = bound(&b);
    assert_eq!(b.refuse(&t, &thief()), Refusal::WrongTerminal);
    b.at(Duration::from_millis(600)).await;
    b.admit(&t, &in_tab());
    b.at(Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &thief()), Refusal::WrongTerminal);
}

#[tokio::test(start_paused = true)]
async fn a_bound_token_refuses_a_caller_in_another_terminal_or_a_reused_number() {
    let mut b = Bench::new();
    let t = bound(&b);
    let reused = lineage(&[key(THIEF), ProcessKey::new(5120, origin_minus(0)), key(1)]);
    assert_eq!(b.refuse(&t, &reused), Refusal::WrongTerminal);
    b.admit(&t, &in_tab());
    b.at(Duration::from_secs(1)).await;
    let other_shell = ProcessKey::new(4411, origin_minus(0));
    let other = lineage(&[key(4415), key(4413), other_shell, key(612), key(1)]);
    assert_eq!(b.refuse(&t, &other), Refusal::WrongTerminal);
}

#[tokio::test(start_paused = true)]
async fn a_bound_token_refuses_a_recycled_pid_of_the_tabs_shell() {
    let b = Bench::new();
    let t = bound(&b);
    let recycled = ProcessKey::new(
        3339,
        Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_757_332_021)),
    );
    let c = lineage(&[key(THIEF), recycled, key(1)]);
    assert_eq!(b.refuse(&t, &c), Refusal::WrongTerminal);
}

#[tokio::test(start_paused = true)]
async fn a_binding_with_no_holders_admits_nobody() {
    let b = Bench::new();
    let t = b
        .tokens
        .issue_bound(issue_for(USER, "127.0.0.1:2222", b"p", &[]), Vec::new());
    assert_eq!(b.refuse(&t, &in_tab()), Refusal::WrongTerminal);
}

#[tokio::test(start_paused = true)]
async fn a_bound_token_refuses_an_unmeasured_caller() {
    let b = Bench::new();
    let t = bound(&b);
    let mut failed = in_tab();
    failed.error = Some("no socket owns that endpoint".to_owned());
    assert_eq!(b.refuse(&t, &failed), Refusal::WrongTerminal);
    let mut no_chain = in_tab();
    no_chain.ancestry.clear();
    assert_eq!(b.refuse(&t, &no_chain), Refusal::WrongTerminal);
}

#[tokio::test(start_paused = true)]
async fn a_bound_token_keeps_its_admission_limit() {
    let mut b = Bench::new();
    let t = bound(&b);
    b.admit(&t, &in_tab());
    b.at(DEFAULT_ADMIT + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&t, &in_tab()), Refusal::AdmissionClosed);
}

#[tokio::test(start_paused = true)]
async fn an_unbound_token_ignores_terminals() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &thief());
}

// callerrule_test.go (service/tokens)

const PUTTY_IMAGE: &str = r"C:\Users\u\Desktop\Applications\terminal\putty.exe";
const PLINK_IMAGE: &str = r"C:\Users\u\Desktop\Applications\terminal\plink.exe";
const MOBA_IMAGE: &str = r"C:\Program Files (x86)\Mobatek\MobaXterm\MobaXterm.exe";
const MOBA_SSH_IMAGE: &str = r"C:\Users\u\AppData\Roaming\MobaXterm\slash\mx86_64b\bin\_ssh.exe";
const XSHELL_IMAGE: &str = r"C:\Program Files (x86)\NetSarang\Xshell 8\Xshell.exe";
const XSHELL_CORE: &str = r"C:\Program Files (x86)\NetSarang\Xshell 8\XshellCore.exe";
const XSHELL_OTHER: &str = r"D:\Portable\Xshell\XshellCore.exe";

/// The records of a caller rule.
fn rule_records<'a>(
    kind: u8,
    path: &'a str,
    meta: Option<(&'a str, &'a str, &'a str)>,
    extra: &'a [u8],
) -> Vec<(u8, Vec<u8>)> {
    let mut r = vec![(0x19, vec![kind]), (0x1a, path.as_bytes().to_vec())];
    if let Some((c, p, o)) = meta {
        r.push((0x1b, c.as_bytes().to_vec()));
        r.push((0x1c, p.as_bytes().to_vec()));
        r.push((0x1d, o.as_bytes().to_vec()));
    }
    if !extra.is_empty() {
        r.push((0x1e, extra.to_vec()));
    }
    r
}

fn ruled(b: &Bench, records: &[(u8, Vec<u8>)]) -> Zeroizing<String> {
    let extra: Vec<(u8, &[u8])> = records.iter().map(|(t, v)| (*t, &v[..])).collect();
    b.issue_with(&extra)
}

fn rule(records: &[(u8, Vec<u8>)]) -> Rule {
    let extra: Vec<(u8, &[u8])> = records.iter().map(|(t, v)| (*t, &v[..])).collect();
    issue_for(USER, "127.0.0.1:2222", b"p", &extra)
        .rule
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn another_executable_cannot_claim_a_ruled_token() {
    let b = Bench::new();
    let t = ruled(&b, &rule_records(1, PUTTY_IMAGE, None, b""));
    let plink = with_image(out_of_tree(THIEF), PLINK_IMAGE);
    assert!(matches!(b.refuse(&t, &plink), Refusal::NotTheProgram(_)));
    let putty = with_image(in_tree(&[PUTTY]), PUTTY_IMAGE);
    assert_eq!(b.connect(&t, &putty).admission, Admission::Claim);
}

#[tokio::test(start_paused = true)]
async fn the_rule_holds_within_the_grace() {
    let mut b = Bench::new();
    let mut records = rule_records(
        3,
        MOBA_IMAGE,
        Some(("", "", "x")),
        MOBA_SSH_IMAGE.as_bytes(),
    );
    records.push((0x1f, 5000u32.to_be_bytes().to_vec()));
    let t = ruled(&b, &records);
    b.admit(&t, &with_image(orphan(MOBA_SSH), MOBA_SSH_IMAGE));
    b.at(Duration::from_millis(400)).await;
    let plink = with_image(out_of_tree(THIEF), PLINK_IMAGE);
    assert!(matches!(b.refuse(&t, &plink), Refusal::NotTheProgram(_)));
    let moba = with_image(in_tree(&[MOBA_MAIN]), MOBA_IMAGE);
    assert_eq!(b.admit(&t, &moba), Admission::Grace);
}

#[tokio::test(start_paused = true)]
async fn a_zero_grace_admits_no_other_process() {
    let mut b = Bench::new();
    let t = b.issue_with(&[(0x1f, &0u32.to_be_bytes())]);
    b.admit(&t, &in_tree(&[PUTTY]));
    b.at(Duration::from_millis(100)).await;
    assert_eq!(b.refuse(&t, &out_of_tree(THIEF)), Refusal::CallerNotPinned);
}

#[tokio::test(start_paused = true)]
async fn a_token_without_a_grace_keeps_the_registrys() {
    let mut b = Bench::new();
    let t = b.issue();
    b.admit(&t, &in_tree(&[PUTTY]));
    b.at(DEFAULT_GRACE - Duration::from_millis(1)).await;
    assert_eq!(b.admit(&t, &out_of_tree(THIEF)), Admission::Grace);
}

#[tokio::test(start_paused = true)]
async fn a_metadata_rule_uses_the_tokens_reader() {
    let records = rule_records(
        3,
        XSHELL_IMAGE,
        Some(("NetSarang", "Xshell", "Xshell.exe")),
        b"",
    );
    let other = with_image(out_of_tree(42424), XSHELL_OTHER);
    let b = Bench::new();
    let t = ruled(&b, &records);
    assert!(matches!(b.refuse(&t, &other), Refusal::NotTheProgram(_)));
    let b = Bench::with(|c| {
        c.peer.metadata = Some(Arc::new(|_: &str| {
            Ok(ImageMetadata::new(
                "NetSarang Computer, Inc.",
                "Xshell 8",
                "Xshell.exe",
            ))
        }))
    });
    let t = ruled(&b, &records);
    b.connect(&t, &other);
}

// holdfail_test.go

#[tokio::test(start_paused = true)]
async fn a_pinned_process_that_could_not_be_held_stays_pinned() {
    let hold = Arc::new(FakeHold {
        fail: vec![PUTTY],
        ..FakeHold::default()
    });
    let mut b = Bench::with(|c| c.peer.hold = Some(hold.clone()));
    let t = b.issue();
    b.admit(&t, &out_of_tree(PUTTY));
    b.at(DEFAULT_GRACE + Duration::from_secs(1)).await;
    assert_eq!(b.admit(&t, &out_of_tree(PUTTY)), Admission::Pin);
}

#[tokio::test(start_paused = true)]
async fn a_pinned_process_that_exited_no_longer_matches_its_number() {
    let hold = Arc::new(FakeHold::default());
    let mut b = Bench::with(|c| c.peer.hold = Some(hold.clone()));
    let t = b.issue();
    b.admit(&t, &out_of_tree(PUTTY));
    b.at(Duration::from_secs(1)).await;
    b.admit(&t, &out_of_tree(SECURECRT));
    hold.exit(PUTTY);
    b.at(DEFAULT_GRACE + Duration::from_secs(5)).await;
    assert_eq!(b.refuse(&t, &out_of_tree(PUTTY)), Refusal::CallerNotPinned);
    b.admit(&t, &out_of_tree(SECURECRT));
}

// authorize_test.go, registry_test.go, upstream_test.go

#[tokio::test(start_paused = true)]
async fn a_username_other_than_the_bound_one_is_refused() {
    let b = Bench::new();
    let t = b.issue();
    for presented in [
        &b"srv99@10.0.0.9"[..],
        b"srv42@10.0.0.10",
        b"SRV42@10.0.0.9",
        b"srv42@10.0.0.9 ",
        b"srv42",
        b"",
    ] {
        let r = b
            .tokens
            .authorize(t.as_bytes(), presented, &Caller::default());
        assert_eq!(r.err(), Some(Refusal::UsernameMismatch), "{presented:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn an_unknown_token_is_refused_as_such_even_with_a_wrong_username() {
    let b = Bench::new();
    b.issue();
    let r = b.tokens.authorize(
        b"00000000000000000000000000000000",
        b"someone-else",
        &Caller::default(),
    );
    assert_eq!(r.err(), Some(Refusal::UnknownToken));
}

#[tokio::test(start_paused = true)]
async fn issued_tokens_are_thirty_two_hex_characters_and_never_repeat() {
    let b = Bench::new();
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2000 {
        let t = b.issue();
        assert_eq!(t.len(), 32);
        assert!(
            t.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "{}",
            *t
        );
        assert!(seen.insert(t.to_string()));
    }
    assert_eq!(b.tokens.len(), 2000);
}

#[tokio::test(start_paused = true)]
async fn each_token_resolves_to_its_own_grant() {
    let b = Bench::new();
    let mut want = HashMap::new();
    for i in 0..50 {
        let user = format!("srv{i}@10.0.0.{i}");
        let up = format!("127.0.0.7:{}", 51200 + i);
        let pw = format!("password-{i}");
        let t = b
            .tokens
            .issue(issue_for(user.as_bytes(), &up, pw.as_bytes(), &[]));
        want.insert(t.to_string(), (user, up, pw));
    }
    for (t, (user, up, pw)) in want {
        let g = b
            .tokens
            .authorize(t.as_bytes(), user.as_bytes(), &Caller::default())
            .unwrap();
        assert_eq!(g.username, user.as_bytes());
        assert_eq!(g.upstream, up.as_bytes());
        assert_eq!(g.password.as_deref().map(|p| &p[..]), Some(pw.as_bytes()));
    }
}

#[tokio::test(start_paused = true)]
async fn lookup_rejects_what_was_never_issued() {
    let b = Bench::new();
    let live = b.issue().to_string();
    for presented in [
        String::new(),
        "not-a-token".to_owned(),
        live[..live.len() - 1].to_owned(),
        format!("{live}0"),
        "00000000000000000000000000000000".to_owned(),
    ] {
        let r = b
            .tokens
            .authorize(presented.as_bytes(), USER, &Caller::default());
        assert_eq!(r.err(), Some(Refusal::UnknownToken), "{presented:?}");
    }
    let empty = Bench::new();
    let r = empty
        .tokens
        .authorize(b"anything", USER, &Caller::default());
    assert_eq!(r.err(), Some(Refusal::UnknownToken));
}

// shell_test.go

#[tokio::test(start_paused = true)]
async fn one_shell_per_token_given_back_when_closed_and_none_once_disposed() {
    let b = Bench::new();
    let t = b.issue();
    let first = b.connect(&t, &in_tree(&[WINSCP]));
    let second = b.connect(&t, &in_tree(&[WINSCP]));
    let shell = first
        .conn
        .handle()
        .open_shell()
        .expect("the first shell was refused");
    assert!(second.conn.handle().open_shell().is_none());
    assert!(first.conn.handle().open_shell().is_none());
    drop(shell);
    let shell = second
        .conn
        .handle()
        .open_shell()
        .expect("the shell was not given back");
    let other = b.issue();
    let elsewhere = b.connect(&other, &in_tree(&[WINSCP]));
    assert!(elsewhere.conn.handle().open_shell().is_some());
    b.tokens.revoke(&t);
    drop(shell);
    assert!(first.conn.handle().open_shell().is_none());
}

#[tokio::test(start_paused = true)]
async fn the_tokens_policy_says_whether_file_transfer_is_allowed() {
    let b = Bench::new();
    let denied = b.issue_with(&[(0x18, &[1])]);
    let allowed = b.issue();
    let d = b.connect(&denied, &in_tree(&[WINSCP]));
    let a = b.connect(&allowed, &in_tree(&[WINSCP]));
    assert!(!d.conn.handle().file_transfer_allowed());
    assert!(a.conn.handle().file_transfer_allowed());
    b.tokens.revoke(&allowed);
    assert!(!a.conn.handle().file_transfer_allowed());
}

// domain/model/callerrule_test.go

fn known_metadata(path: &str) -> Result<ImageMetadata, String> {
    match path {
        XSHELL_OTHER => Ok(ImageMetadata::new(
            "NetSarang Computer, Inc.",
            "Xshell 8",
            "Xshell.exe",
        )),
        r"D:\x\fake.exe" => Ok(ImageMetadata::new(
            "NetSarang Computer, Inc.",
            "Xshell",
            "fake.exe",
        )),
        r"D:\y\wrapper.exe" => Ok(ImageMetadata::new(
            "NetSarang Computer, Inc.",
            "Xshell",
            "MyXshell.exe",
        )),
        _ => Err("no version resource".to_owned()),
    }
}

#[test]
fn caller_rules() {
    let putty = rule(&rule_records(1, PUTTY_IMAGE, None, b""));
    let fz = rule(&rule_records(
        2,
        r"C:\Program Files\FileZilla FTP Client\filezilla.exe",
        None,
        b"",
    ));
    let xshell = rule(&rule_records(
        3,
        XSHELL_IMAGE,
        Some(("NetSarang", "Xshell", "Xshell.exe")),
        b"",
    ));
    let moba = rule(&rule_records(
        3,
        MOBA_IMAGE,
        Some(("Mobatek", "MobaXterm", "MobaXterm")),
        MOBA_SSH_IMAGE.as_bytes(),
    ));
    let python = r"C:\Python312\python.exe";
    let cases: &[(&str, Option<&Rule>, &str, bool)] = &[
        ("no rule admits anything", None, python, true),
        ("putty itself", Some(&putty), PUTTY_IMAGE, true),
        (
            "putty path in another case",
            Some(&putty),
            r"c:\users\u\desktop\applications\terminal\PUTTY.EXE",
            true,
        ),
        ("plink beside putty", Some(&putty), PLINK_IMAGE, false),
        (
            "windows ssh on a putty token",
            Some(&putty),
            r"C:\Windows\System32\OpenSSH\ssh.exe",
            false,
        ),
        (
            "filezilla itself",
            Some(&fz),
            r"C:\Program Files\FileZilla FTP Client\filezilla.exe",
            true,
        ),
        (
            "fzsftp beside filezilla",
            Some(&fz),
            r"C:\Program Files\FileZilla FTP Client\fzsftp.exe",
            true,
        ),
        ("python on a filezilla token", Some(&fz), python, false),
        (
            "xshell core in the registered folder",
            Some(&xshell),
            XSHELL_CORE,
            true,
        ),
        (
            "xshell core of another copy, by its version resource",
            Some(&xshell),
            XSHELL_OTHER,
            true,
        ),
        (
            "a tool copying the product but not the filename",
            Some(&xshell),
            r"D:\x\fake.exe",
            false,
        ),
        (
            "an original filename that only contains the program's",
            Some(&xshell),
            r"D:\y\wrapper.exe",
            false,
        ),
        (
            "an executable with no version resource elsewhere",
            Some(&xshell),
            python,
            false,
        ),
        ("mobaxterm itself", Some(&moba), MOBA_IMAGE, true),
        (
            "mobaxterm _ssh.exe by its listed path",
            Some(&moba),
            MOBA_SSH_IMAGE,
            true,
        ),
        (
            "another _ssh.exe",
            Some(&moba),
            r"D:\elsewhere\bin\_ssh.exe",
            false,
        ),
        (
            "a caller whose executable could not be read",
            Some(&putty),
            "",
            false,
        ),
        (
            "the same path through dot segments and forward slashes",
            Some(&putty),
            "C:/Users/u/Desktop/./Applications/x/../terminal/putty.exe",
            true,
        ),
    ];
    for (name, rule, image, want) in cases {
        let got = admits(*rule, image, Some(&known_metadata));
        assert_eq!(got.is_ok(), *want, "{name}: {got:?}");
        if let Err(why) = got {
            assert!(!why.is_empty(), "{name}: a refusal gave no reason");
        }
    }
}

#[test]
fn a_metadata_rule_without_a_reader_refuses_outside_the_folder() {
    let xshell = rule(&rule_records(
        3,
        XSHELL_IMAGE,
        Some(("NetSarang", "Xshell", "Xshell.exe")),
        b"",
    ));
    assert!(admits(Some(&xshell), XSHELL_OTHER, None).is_err());
    assert!(admits(Some(&xshell), XSHELL_CORE, None).is_ok());
}

#[test]
fn an_unreadable_executable_is_refused_as_unreadable() {
    let xshell = rule(&rule_records(
        3,
        XSHELL_IMAGE,
        Some(("NetSarang", "Xshell", "Xshell.exe")),
        b"",
    ));
    let why = admits(Some(&xshell), "", Some(&known_metadata)).unwrap_err();
    assert!(why.contains("could not be read"), "{why}");
}

// domain/model/caller.go

#[test]
fn identity_pins_the_tree_below_the_app_or_the_caller_alone() {
    assert_eq!(
        in_tree(&[FZSFTP, FILEZILLA]).identity(APP),
        [FZSFTP, FILEZILLA]
    );
    assert_eq!(out_of_tree(SECURECRT).identity(APP), [SECURECRT]);
    assert_eq!(Caller::new(PUTTY).identity(APP), [PUTTY]);
    assert!(unowned().identity(APP).is_empty());
    assert_eq!(in_tree(&[PUTTY]).identity(0), [PUTTY]);
}

// infrastructure/peer/chain_test.go

struct FakeTable(HashMap<u32, ProcessInfo>);

impl ProcessTable for FakeTable {
    fn info(&self, pid: u32) -> Result<ProcessInfo, String> {
        self.0
            .get(&pid)
            .cloned()
            .ok_or_else(|| "fake: no such pid".to_owned())
    }
}

fn at(min: u64) -> Option<SystemTime> {
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_757_239_200 + min * 60))
}

fn table(procs: &[(u32, u32, Option<SystemTime>)]) -> FakeTable {
    FakeTable(
        procs
            .iter()
            .map(|&(pid, parent, created)| (pid, ProcessInfo::new(pid, parent, created)))
            .collect(),
    )
}

fn pids(t: &FakeTable, pid: u32) -> (Vec<u32>, Stop) {
    let c = walk(t, pid);
    (c.links.iter().map(|l| l.pid).collect(), c.stop)
}

#[test]
fn a_grandchild_is_walked_back_to_the_root() {
    let t = table(&[(100, 0, at(0)), (200, 100, at(1)), (300, 200, at(2))]);
    assert_eq!(pids(&t, 300), (vec![300, 200, 100], Stop::NoParent));
}

#[test]
fn a_recycled_parent_cuts_the_chain_and_is_not_included() {
    let t = table(&[(100, 0, at(0)), (200, 100, at(9)), (300, 200, at(2))]);
    assert_eq!(pids(&t, 300), (vec![300], Stop::StaleParent));
}

#[test]
fn an_older_parent_keeps_the_link() {
    let t = table(&[(100, 0, at(0)), (200, 100, at(1))]);
    assert_eq!(pids(&t, 200), (vec![200, 100], Stop::NoParent));
}

#[test]
fn an_unmeasured_creation_time_does_not_cut_the_chain() {
    let t = table(&[(100, 0, None), (200, 100, at(1))]);
    assert_eq!(pids(&t, 200), (vec![200, 100], Stop::NoParent));
}

#[test]
fn a_cycle_ends_the_walk() {
    let t = table(&[(100, 200, at(1)), (200, 100, at(1))]);
    assert_eq!(pids(&t, 100).1, Stop::Cycle);
}

#[test]
fn the_depth_bound_is_reported() {
    let deepest = MAX_DEPTH as u32 + 5;
    let mut procs: Vec<_> = (1..deepest)
        .map(|i| (i, i + 1, at(u64::from(deepest - i))))
        .collect();
    procs.push((deepest, 0, at(0)));
    let (links, stop) = pids(&table(&procs), 1);
    assert_eq!((links.len(), stop), (MAX_DEPTH, Stop::Depth));
}

#[test]
fn a_parent_missing_from_the_snapshot_is_reported_as_such() {
    let t = table(&[(200, 100, at(1))]);
    assert_eq!(pids(&t, 200), (vec![200], Stop::ParentGone));
}

#[test]
fn a_caller_missing_from_the_snapshot_is_unreadable_and_measured_as_failed() {
    let t = table(&[(100, 0, at(0))]);
    assert_eq!(pids(&t, 200), (vec![], Stop::Unreadable));
    let mut owner = Owner::default();
    owner.pid = 200;
    let c = Caller::measure(owner, Some(Ok(&t)), false);
    assert!(c.error.is_some() && c.ancestry.is_empty() && !c.unowned());
}

#[test]
fn the_lineage_carries_each_links_start_time_and_stops_at_a_recycled_parent() {
    let t = table(&[
        (100, 0, at(0)),
        (200, 100, at(9)),
        (300, 200, at(2)),
        (400, 300, at(3)),
    ]);
    let mut owner = Owner::default();
    owner.pid = 400;
    let c = Caller::measure(owner, Some(Ok(&t)), false);
    assert_eq!(c.ancestry, [400, 300]);
    assert_eq!(
        c.lineage,
        [ProcessKey::new(400, at(3)), ProcessKey::new(300, at(2))]
    );
}

// attach_test.go, claimed_test.go, freeze_test.go, launched_test.go, unclaimed_test.go

const SESSION_FILE: &str = r"C:\Users\u\AppData\Local\ACRA\cache\5f1c";
const OTHER_FILE: &str = r"C:\Users\u\AppData\Local\ACRA\cache\9a0e";
const LAUNCHER: u32 = 4242;
const WINDOW: u32 = 5804;
const NEWER: u32 = 32988;

/// What the tokens told and shredded, in order.
#[derive(Default)]
struct Told {
    claimed: Mutex<Vec<u32>>,
    unclaimed: Mutex<Vec<u32>>,
    shredded: Mutex<Vec<String>>,
}

impl Told {
    fn claimed(&self) -> Vec<u32> {
        std::mem::take(&mut self.claimed.lock().unwrap())
    }

    fn unclaimed(&self) -> Vec<u32> {
        std::mem::take(&mut self.unclaimed.lock().unwrap())
    }

    fn shredded(&self) -> Vec<String> {
        std::mem::take(&mut self.shredded.lock().unwrap())
    }
}

/// The processes of this session, as the test sets them.
struct Processes(Mutex<Result<Vec<ProcessImage>, String>>);

impl Default for Processes {
    fn default() -> Self {
        Processes(Mutex::new(Ok(Vec::new())))
    }
}

impl Processes {
    fn set(&self, list: Vec<ProcessImage>) {
        *self.0.lock().unwrap() = Ok(list);
    }

    fn fail(&self) {
        *self.0.lock().unwrap() = Err("snapshot failed".to_owned());
    }
}

/// Tokens that report to `told`, watch with `hold` and list `processes`.
fn reporting(told: &Arc<Told>, hold: &Arc<FakeHold>, processes: &Arc<Processes>) -> Bench {
    let (t1, t2, t3) = (told.clone(), told.clone(), told.clone());
    let ps = processes.clone();
    let hold = hold.clone();
    Bench::with(move |c| {
        c.claimed = Some(Arc::new(move |pid| t1.claimed.lock().unwrap().push(pid)));
        c.unclaimed = Some(Arc::new(move |pid| t2.unclaimed.lock().unwrap().push(pid)));
        c.shred = Some(Arc::new(move |p| t3.shredded.lock().unwrap().push(p)));
        c.peer.hold = Some(hold);
        c.peer.candidates = Some(Arc::new(move || ps.0.lock().unwrap().clone()));
    })
}

struct Launch {
    b: Bench,
    token: Zeroizing<String>,
    told: Arc<Told>,
    hold: Arc<FakeHold>,
    processes: Arc<Processes>,
    /// A start before the launcher's.
    before: Option<SystemTime>,
}

/// A token for putty, its file attached, and the launcher reported for it.
fn launched() -> Launch {
    let told = Arc::new(Told::default());
    let hold = Arc::new(FakeHold::default());
    let processes = Arc::new(Processes::default());
    let b = reporting(&told, &hold, &processes);
    let token = ruled(&b, &rule_records(1, PUTTY_IMAGE, None, b""));
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    assert!(!b.tokens.launched(&token, LAUNCHER).unwrap());
    Launch {
        b,
        token,
        told,
        hold,
        processes,
        before: Some(SystemTime::now() - Duration::from_secs(60)),
    }
}

fn after_now(secs: u64) -> Option<SystemTime> {
    Some(SystemTime::now() + Duration::from_secs(secs))
}

fn plain() -> (Bench, Arc<Told>, Arc<FakeHold>) {
    let told = Arc::new(Told::default());
    let hold = Arc::new(FakeHold::default());
    let b = reporting(&told, &hold, &Arc::new(Processes::default()));
    (b, told, hold)
}

#[tokio::test(start_paused = true)]
async fn a_claim_shreds_only_that_tokens_file() {
    let (mut b, told, _) = plain();
    let token = b.issue();
    let other = b.issue();
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    b.tokens.attach(&other, OTHER_FILE).unwrap();
    settle().await;
    assert!(told.shredded().is_empty());
    b.admit(&token, &in_tree(&[PUTTY]));
    settle().await;
    assert_eq!(told.shredded(), [SESSION_FILE]);
}

#[tokio::test(start_paused = true)]
async fn a_refused_caller_leaves_the_file() {
    let (b, told, _) = plain();
    let token = ruled(&b, &rule_records(1, PUTTY_IMAGE, None, b""));
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    b.refuse(&token, &with_image(out_of_tree(THIEF), PLINK_IMAGE));
    settle().await;
    assert!(told.shredded().is_empty());
}

#[tokio::test(start_paused = true)]
async fn the_file_is_shredded_once() {
    let (mut b, told, _) = plain();
    let token = b.issue();
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    b.admit(&token, &in_tree(&[PUTTY]));
    settle().await;
    assert_eq!(told.shredded(), [SESSION_FILE]);
    b.at(Duration::from_secs(1)).await;
    b.admit(&token, &in_tree(&[PUTTY]));
    b.tokens.revoke(&token);
    settle().await;
    assert!(told.shredded().is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_expired_or_revoked_token_shreds_its_file_and_tells_its_launcher() {
    let (b, told, _) = plain();
    let expired = b.issue();
    b.tokens.attach(&expired, SESSION_FILE).unwrap();
    b.tokens.launched(&expired, LAUNCHER).unwrap();
    b.at(DEFAULT_WINDOW + Duration::from_millis(1)).await;
    assert_eq!(told.shredded(), [SESSION_FILE]);
    assert_eq!(told.unclaimed(), [LAUNCHER]);
    let revoked = b.issue();
    b.tokens.attach(&revoked, OTHER_FILE).unwrap();
    b.tokens.launched(&revoked, LAUNCHER + 1).unwrap();
    settle().await;
    assert!(told.unclaimed().is_empty());
    b.tokens.revoke(&revoked);
    settle().await;
    assert_eq!(told.shredded(), [OTHER_FILE]);
    assert_eq!(told.unclaimed(), [LAUNCHER + 1]);
}

#[tokio::test(start_paused = true)]
async fn a_late_presentation_shreds_the_file() {
    let told = Arc::new(Told::default());
    let t = told.clone();
    let b = Bench::without_timers(move |c| {
        c.shred = Some(Arc::new(move |p| t.shredded.lock().unwrap().push(p)));
    });
    let token = b.issue();
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    b.at(DEFAULT_WINDOW + Duration::from_secs(1)).await;
    assert_eq!(b.refuse(&token, &in_tree(&[PUTTY])), Refusal::TokenExpired);
    for _ in 0..100 {
        if !told.shredded.lock().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(told.shredded(), [SESSION_FILE]);
}

#[tokio::test(start_paused = true)]
async fn a_freeze_refuses_every_token_wipes_and_shreds_and_keeps_what_is_open() {
    let (b, told, _) = plain();
    let claimed = b.issue();
    let open = b.connect(&claimed, &in_tree(&[WINSCP]));
    let unclaimed = b.issue();
    b.tokens.attach(&unclaimed, OTHER_FILE).unwrap();
    settle().await;
    assert!(told.shredded().is_empty());
    b.tokens.freeze();
    settle().await;
    assert_eq!(told.shredded(), [OTHER_FILE]);
    for token in [&claimed, &unclaimed] {
        assert_eq!(b.refuse(token, &in_tree(&[WINSCP])), Refusal::Frozen);
    }
    assert_eq!(b.tokens.len(), 2, "a freeze disposes of nothing");
    assert!(
        timeout(Duration::ZERO, open.conn.disposed()).await.is_err(),
        "an open connection was told to close"
    );
    let late = b.tokens.issue(issue_for(USER, "127.0.0.1:2222", b"p", &[]));
    b.tokens.attach(&late, SESSION_FILE).unwrap();
    settle().await;
    assert_eq!(told.shredded(), [SESSION_FILE]);
}

#[tokio::test(start_paused = true)]
async fn a_late_attach_shreds_at_once() {
    let (mut b, told, _) = plain();
    let token = b.issue();
    b.admit(&token, &in_tree(&[PUTTY]));
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    settle().await;
    assert_eq!(told.shredded(), [SESSION_FILE]);
}

#[tokio::test(start_paused = true)]
async fn attach_refuses_an_unknown_token_and_a_second_path() {
    let (b, _, _) = plain();
    assert_eq!(
        b.tokens
            .attach("00112233445566778899aabbccddeeff", SESSION_FILE),
        Err(AttachError::UnknownToken)
    );
    let token = b.issue();
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    assert_eq!(
        b.tokens.attach(&token, OTHER_FILE),
        Err(AttachError::AlreadyAttached)
    );
    assert_eq!(
        b.tokens
            .launched("00112233445566778899aabbccddeeff", LAUNCHER),
        Err(AttachError::UnknownToken)
    );
}

#[tokio::test(start_paused = true)]
async fn take_attachment_admits_the_path_before_the_token_and_hands_the_pid_over() {
    let (b, _, hold) = plain();
    let refused = b.tokens.take_attachment(
        "00112233445566778899aabbccddeeff",
        Some(SESSION_FILE),
        Some(LAUNCHER),
        |_| Err("outside".to_owned()),
    );
    assert_eq!(refused, Err(AttachError::Refused("outside".to_owned())));
    let token = b.issue();
    assert_eq!(
        b.tokens
            .take_attachment(&token, Some(SESSION_FILE), Some(LAUNCHER), |_| Ok(())),
        Ok(false)
    );
    assert_eq!(hold.held(), [LAUNCHER]);
}

#[tokio::test(start_paused = true)]
async fn a_claim_tells_the_reported_process_once() {
    let (mut b, told, _) = plain();
    let token = b.issue();
    assert!(!b.tokens.launched(&token, LAUNCHER).unwrap());
    settle().await;
    assert!(told.claimed().is_empty());
    b.admit(&token, &in_tree(&[LAUNCHER + 1, LAUNCHER]));
    settle().await;
    assert_eq!(told.claimed(), [LAUNCHER]);
    b.admit(&token, &in_tree(&[LAUNCHER + 2, LAUNCHER]));
    b.tokens.revoke(&token);
    settle().await;
    assert!(told.claimed().is_empty());
    assert!(told.unclaimed().is_empty(), "a revoke after the claim told");
}

#[tokio::test(start_paused = true)]
async fn a_claim_tells_the_reported_process_without_a_hold() {
    let told = Arc::new(Told::default());
    let t = told.clone();
    let mut b = Bench::with(move |c| {
        c.claimed = Some(Arc::new(move |pid| t.claimed.lock().unwrap().push(pid)));
    });
    let token = b.issue();
    b.tokens.launched(&token, LAUNCHER).unwrap();
    b.admit(&token, &in_tree(&[LAUNCHER + 1, LAUNCHER]));
    settle().await;
    assert_eq!(told.claimed(), [LAUNCHER]);
}

#[tokio::test(start_paused = true)]
async fn a_report_after_the_claim_is_answered_as_used_and_not_watched() {
    let (mut b, told, hold) = plain();
    let token = b.issue();
    b.admit(&token, &in_tree(&[PUTTY]));
    assert!(b.tokens.launched(&token, LAUNCHER).unwrap());
    settle().await;
    assert!(told.claimed().is_empty());
    assert!(!hold.held().contains(&LAUNCHER));
}

#[tokio::test(start_paused = true)]
async fn an_unreported_token_tells_nothing() {
    let (mut b, told, _) = plain();
    let used = b.issue();
    b.admit(&used, &in_tree(&[PUTTY]));
    let revoked = b.issue();
    b.tokens.revoke(&revoked);
    settle().await;
    assert!(told.claimed().is_empty() && told.unclaimed().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_launcher_gone_with_nothing_left_disposes_the_token() {
    let l = launched();
    l.processes.set(vec![
        ProcessImage::new(777, PLINK_IMAGE, l.before),
        ProcessImage::new(LAUNCHER, PUTTY_IMAGE, l.before),
    ]);
    l.hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
    assert_eq!(l.told.unclaimed(), [LAUNCHER]);
    assert_eq!(l.b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_tab_handed_to_a_running_window_waits_for_that_window() {
    let l = launched();
    l.processes
        .set(vec![ProcessImage::new(WINDOW, PUTTY_IMAGE, l.before)]);
    l.hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(l.b.tokens.len(), 1);
    assert!(l.told.shredded().is_empty());
    l.processes.set(Vec::new());
    l.hold.exit(WINDOW);
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
    assert_eq!(
        l.b.refuse(&l.token, &in_tree(&[PUTTY])),
        Refusal::UnknownToken
    );
}

#[tokio::test(start_paused = true)]
async fn a_waited_window_can_still_use_the_token_and_its_watch_ends() {
    let mut l = launched();
    l.processes
        .set(vec![ProcessImage::new(WINDOW, PUTTY_IMAGE, l.before)]);
    l.hold.exit(LAUNCHER);
    settle().await;
    let before = l.hold.released();
    l.b.admit(&l.token, &with_image(in_tree(&[WINDOW]), PUTTY_IMAGE));
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
    assert!(
        l.hold.released() > before,
        "the claim left the launch watch on the window running"
    );
}

#[tokio::test(start_paused = true)]
async fn a_used_token_ignores_its_launcher() {
    let mut l = launched();
    l.b.admit(&l.token, &with_image(in_tree(&[PUTTY]), PUTTY_IMAGE));
    settle().await;
    l.processes.set(Vec::new());
    l.hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(l.b.tokens.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn what_cannot_be_read_leaves_the_token_to_its_window() {
    for unreadable in [true, false] {
        let l = launched();
        if unreadable {
            l.processes.set(vec![ProcessImage::unreadable(
                900,
                "PUTTY.EXE",
                "access denied",
            )]);
        } else {
            l.processes.fail();
        }
        l.hold.exit(LAUNCHER);
        settle().await;
        assert_eq!(l.b.tokens.len(), 1, "unreadable={unreadable}");
        assert!(l.told.shredded().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn a_token_without_a_rule_is_left_to_its_window() {
    let told = Arc::new(Told::default());
    let hold = Arc::new(FakeHold::default());
    let processes = Arc::new(Processes::default());
    let b = reporting(&told, &hold, &processes);
    let token = b.issue();
    b.tokens.attach(&token, SESSION_FILE).unwrap();
    b.tokens.launched(&token, LAUNCHER).unwrap();
    hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(b.tokens.len(), 1);
    assert!(told.shredded().is_empty());
}

#[tokio::test(start_paused = true)]
async fn an_unreadable_process_named_otherwise_is_not_the_program() {
    let l = launched();
    l.processes.set(vec![ProcessImage::unreadable(
        900,
        "svchost.exe",
        "session unknown",
    )]);
    l.hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
    assert_eq!(l.b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_window_started_after_the_launcher_is_not_waited_for() {
    let l = launched();
    l.processes
        .set(vec![ProcessImage::new(NEWER, PUTTY_IMAGE, after_now(1))]);
    l.hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
    assert_eq!(l.b.tokens.len(), 0);
}

#[tokio::test(start_paused = true)]
async fn the_cut_off_stays_at_the_launchers_exit() {
    let l = launched();
    l.processes
        .set(vec![ProcessImage::new(WINDOW, PUTTY_IMAGE, l.before)]);
    l.hold.exit(LAUNCHER);
    settle().await;
    std::thread::sleep(Duration::from_millis(20));
    let newer = Some(SystemTime::now() - Duration::from_millis(10));
    l.processes
        .set(vec![ProcessImage::new(NEWER, PUTTY_IMAGE, newer)]);
    l.hold.exit(WINDOW);
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
}

#[tokio::test(start_paused = true)]
async fn a_window_with_an_unknown_start_is_waited_for() {
    let l = launched();
    l.processes
        .set(vec![ProcessImage::new(WINDOW, PUTTY_IMAGE, None)]);
    l.hold.exit(LAUNCHER);
    settle().await;
    assert_eq!(l.b.tokens.len(), 1);
    l.processes.set(Vec::new());
    l.hold.exit(WINDOW);
    settle().await;
    assert_eq!(l.told.shredded(), [SESSION_FILE]);
}

#[tokio::test(start_paused = true)]
async fn a_frozen_tokens_launch_is_recorded_and_not_watched() {
    let (b, told, hold) = plain();
    let token = b.issue();
    b.tokens.freeze();
    assert!(!b.tokens.launched(&token, LAUNCHER).unwrap());
    assert!(hold.held().is_empty());
    b.tokens.revoke(&token);
    settle().await;
    assert_eq!(told.unclaimed(), [LAUNCHER]);
}

// dispose_test.go and holdfail_test.go: what is reported

/// The disposals and failed watches the tokens reported, in order.
#[derive(Default)]
struct Reports {
    disposed: Mutex<Vec<(String, usize)>>,
    hold_failed: Mutex<Vec<(u32, String)>>,
}

fn reported(f: impl FnOnce(&mut Config)) -> (Bench, Arc<Reports>) {
    let r = Arc::new(Reports::default());
    let (d, h) = (r.clone(), r.clone());
    let b = Bench::with(move |c| {
        c.disposed = Some(Arc::new(move |why, live| {
            d.disposed.lock().unwrap().push((why.to_owned(), live))
        }));
        c.hold_failed = Some(Arc::new(move |pid, why| {
            h.hold_failed.lock().unwrap().push((pid, why.to_owned()))
        }));
        f(c);
    });
    (b, r)
}

#[tokio::test(start_paused = true)]
async fn each_disposal_reports_why_and_how_many_are_left_and_an_expiry_reports_nothing() {
    let hold = Arc::new(FakeHold::default());
    let processes = Arc::new(Processes::default());
    let (h, ps) = (hold.clone(), processes.clone());
    let (b, r) = reported(move |c| {
        c.idle = Duration::from_millis(20);
        c.peer.hold = Some(h);
        c.peer.candidates = Some(Arc::new(move || ps.0.lock().unwrap().clone()));
    });
    let keep = b.issue();
    let _kept = b.connect(&keep, &in_tree(&[9]));

    let idle = b.issue();
    drop(b.connect(&idle, &in_tree(&[WINSCP])));
    b.at(Duration::from_millis(21)).await;

    let asked = b.issue();
    b.tokens.revoke(&asked);

    let exited = b.issue();
    let _open = b.connect(&exited, &out_of_tree(PUTTY));
    hold.exit(PUTTY);
    settle().await;

    let gone = ruled(&b, &rule_records(1, PUTTY_IMAGE, None, b""));
    b.tokens.launched(&gone, LAUNCHER).unwrap();
    hold.exit(LAUNCHER);
    settle().await;

    let _expired = b.issue();
    b.at(DEFAULT_WINDOW + Duration::from_secs(1)).await;
    let refused = b.issue();
    b.at(DEFAULT_WINDOW * 2 + Duration::from_secs(2)).await;
    drop(refused);

    assert_eq!(
        *r.disposed.lock().unwrap(),
        [
            ("idle".to_owned(), 1),
            ("requested".to_owned(), 1),
            ("program exited".to_owned(), 1),
            ("program gone before use".to_owned(), 1),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn admission_closing_with_nothing_connected_reports_it() {
    let (b, r) = reported(|c| c.idle = Duration::from_secs(3600));
    let t = b.issue();
    drop(b.connect(&t, &in_tree(&[WINSCP])));
    b.at(DEFAULT_ADMIT + Duration::from_millis(1)).await;
    assert_eq!(
        *r.disposed.lock().unwrap(),
        [("admission closed".to_owned(), 0)]
    );
}

#[tokio::test(start_paused = true)]
async fn a_failed_hold_is_reported_and_a_successful_one_is_not() {
    let hold = Arc::new(FakeHold {
        fail: vec![PUTTY],
        ..FakeHold::default()
    });
    let h = hold.clone();
    let (mut b, r) = reported(move |c| c.peer.hold = Some(h));
    let t = b.issue();
    b.admit(&t, &out_of_tree(PUTTY));
    let other = b.issue();
    b.admit(&other, &out_of_tree(SECURECRT));
    settle().await;
    assert_eq!(
        *r.hold_failed.lock().unwrap(),
        [(PUTTY, "no such process".to_owned())]
    );
}

// chain_test.go and peer.go: how a caller reads in a log line

#[test]
fn a_caller_reads_as_its_owner_then_its_chain_and_why_it_stopped() {
    let t = table(&[(100, 0, at(0)), (200, 100, at(1)), (300, 200, at(2))]);
    let mut owner = Owner::default();
    owner.pid = 300;
    owner.image_path = r"C:\x\fzsftp.exe".to_owned();
    owner.session = Some(1);
    let c = Caller::measure(owner.clone(), Some(Ok(&t)), false);
    assert_eq!(
        c.described,
        r"pid=300 image=C:\x\fzsftp.exe session=1 chain=300<-200<-100 stop=no-parent"
    );

    let mut named = FakeTable(t.0.clone());
    named.0.get_mut(&200).unwrap().name = "filezilla.exe".to_owned();
    owner.user = Some("S-1-5-21-1".to_owned());
    let c = Caller::measure(owner.clone(), Some(Ok(&named)), true);
    assert_eq!(
        c.described,
        r"pid=300 image=C:\x\fzsftp.exe session=1 user=S-1-5-21-1 chain=300<-200(filezilla.exe)<-100 stop=no-parent"
    );

    owner.user = None;
    let c = Caller::measure(owner.clone(), None, true);
    assert_eq!(
        c.described,
        r"pid=300 image=C:\x\fzsftp.exe session=1 user=?"
    );

    let c = Caller::measure(
        owner.clone(),
        Some(Err("snapshot failed".to_owned())),
        false,
    );
    assert_eq!(
        c.described,
        r"pid=300 image=C:\x\fzsftp.exe session=1 chain=? stop=unreadable (snapshot failed)"
    );

    let empty = table(&[]);
    let c = Caller::measure(owner.clone(), Some(Ok(&empty)), false);
    assert_eq!(
        c.described,
        r"pid=300 image=C:\x\fzsftp.exe session=1 chain=? stop=unreadable (fake: no such pid)"
    );

    let c = Caller::measure(Owner::unmeasured("peer: no socket owns it"), None, true);
    assert_eq!(
        c.described,
        "pid=? image=? (peer: no socket owns it) user=?"
    );

    let recycled = table(&[(100, 0, at(0)), (200, 100, at(9)), (300, 200, at(2))]);
    owner.session = None;
    let c = Caller::measure(owner, Some(Ok(&recycled)), false);
    assert_eq!(
        c.described,
        r"pid=300 image=C:\x\fzsftp.exe chain=300 stop=stale-parent"
    );
}

#[test]
fn the_verdict_classifies_the_caller() {
    let tree = |a: &[u32]| {
        let mut c = Caller::new(a[0]);
        c.ancestry = a.to_vec();
        c
    };
    assert_eq!(tree(&[APP]).verdict(APP), "in-tree");
    assert_eq!(tree(&[900, APP]).verdict(APP), "in-tree");
    assert_eq!(tree(&[901, 900, APP]).verdict(APP), "in-tree");
    assert_eq!(tree(&[14664, 10356]).verdict(APP), "out-of-tree");
    let mut failed = Caller::new(900);
    failed.error = Some("no such process".to_owned());
    assert_eq!(failed.verdict(APP), "unmeasured");
    assert_eq!(Caller::new(900).verdict(APP), "unmeasured");
    assert_eq!(tree(&[900, 0]).verdict(0), "out-of-tree");
}

#[test]
fn a_refusal_reads_as_acwbroker_words_it() {
    assert_eq!(
        Refusal::UnknownToken.to_string(),
        "acwbroker: no live token matches the presented password"
    );
    assert_eq!(
        Refusal::NotTheProgram("x is not y".to_owned()).to_string(),
        "acwbroker: the caller is not the program the token was issued for: x is not y"
    );
    assert_eq!(
        Refusal::Frozen.to_string(),
        "acwbroker: frozen; no new connections"
    );
    assert_eq!(
        AttachError::AlreadyAttached.to_string(),
        "acwbroker: the token already has a path attached"
    );
}
