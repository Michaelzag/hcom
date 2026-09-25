//! `hcom compact` — compact an idle seat's context via PTY injection.
//!
//! Compaction is not something hcom can do to a seat from the outside: the
//! seat's own tool has to run `/compact`. So delivery is a PTY injection of
//! `/compact <focus>` + Enter over the seat's inject endpoint, and the answer
//! is read back from the seat's session file (a `type=compaction` record).
//!
//! Safety is idle-only. Before anything is injected, every reason that
//! applies is named — live turn, open background jobs, in-flight foreground
//! tools, running jobs / queued deliveries, pending hcom messages, unknown job
//! data, no delivery path. All of them, not just the first. The facts are
//! re-read immediately before the injection, and the seat's input box must be
//! empty (with a short poll for it to clear).
//!
//! `--dry-run` runs the whole preflight and prints what it would do, changing
//! nothing.
//!
//! Old-plugin seats have no separate view of omp's own delivery queue: a job
//! that has finished but not yet been delivered has no end record in the
//! session file, so it still counts as open.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::commands::term;
use crate::context::{
    self, CompactionRecord, ContextSource, JobsScan, OpenJob, OpenTool, SeatContext,
    SeatContextRequest,
};
use crate::db::HcomDb;
use crate::instance_lifecycle::get_instance_status;
use crate::instances::is_remote_instance;
use crate::shared::time::now_epoch_ms;
use crate::shared::{CommandContext, ST_LISTENING};

/// Parsed arguments for `hcom compact`.
#[derive(clap::Parser, Debug)]
#[command(name = "compact", about = "Compact an idle seat's context via PTY injection")]
pub struct CompactArgs {
    /// Seat name
    pub name: String,
    /// Extra one-line focus, added to the default focus
    #[arg(long)]
    pub focus: Option<String>,
    /// Print would-compact or refuse; change nothing
    #[arg(long)]
    pub dry_run: bool,
    /// Seconds to wait for the new compaction record
    #[arg(long, default_value_t = 600)]
    pub timeout: u64,
}

/// How long the seat's input box is given to clear before we refuse.
const PROMPT_CLEAR_TIMEOUT: Duration = Duration::from_secs(5);
/// Poll interval while waiting for the input box to clear.
const PROMPT_CLEAR_POLL: Duration = Duration::from_millis(200);
/// Interval between re-reads of the session file while waiting for the record.
const RECORD_POLL: Duration = Duration::from_secs(2);
/// Longest job label carried into a refusal line.
const LABEL_MAX_CHARS: usize = 40;

// ── Facts ─────────────────────────────────────────────────────────────────────

/// Everything the refusal rules are computed from. Pure data: no DB, no PTY.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// The effective status `hcom status` shows.
    pub status: String,
    /// Running jobs / queued deliveries from a live plugin answer. `Some(0)`
    /// is a real answer; `None` means no live answer at all.
    pub live_jobs: Option<u64>,
    /// Session-file job/tool scan.
    pub scan: JobsScan,
    /// hcom messages not yet delivered to this seat.
    pub pending_messages: usize,
    /// The seat's inject endpoint port; `None` means nothing to deliver to.
    pub inject_port: Option<i32>,
}

/// The preflight plus what the report needs (display context).
#[derive(Debug, Clone)]
struct Facts {
    preflight: Preflight,
    ctx: SeatContext,
}


/// One applicable refusal, carrying the data its line renders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// A relay-mirrored seat: no local PTY to inject into.
    Remote,
    /// The seat is not idle/listening — a live turn may be running.
    NotIdle { status: String },
    /// Open background jobs in the session file.
    OpenJobs(Vec<OpenJob>),
    /// In-flight foreground tool calls in the session file.
    OpenTools(Vec<OpenTool>),
    /// The live plugin reports running jobs / queued deliveries.
    LiveJobs(u64),
    /// hcom messages this seat has not been delivered.
    PendingMessages(usize),
    /// Neither the scan nor a live answer knows anything about jobs.
    UnknownJobs,
    /// No inject endpoint: nothing to deliver through.
    NoDeliveryPath,
    /// The seat's input box holds text: injecting would prepend to it.
    PromptNotEmpty,
}

impl Reason {
    /// The one-line rendering of this reason (no leading indent).
    pub fn render(&self) -> String {
        match self {
            Reason::Remote => "remote seat (relay compaction unsupported)".to_string(),
            Reason::NotIdle { status } => format!("not idle/listening (status={status})"),
            Reason::OpenJobs(jobs) => format!(
                "{} open job(s) ({})",
                jobs.len(),
                jobs.iter().map(render_job_ref).collect::<Vec<_>>().join(", ")
            ),
            Reason::OpenTools(tools) => format!(
                "{} in-flight foreground tool(s) ({})",
                tools.len(),
                tools.iter()
                    .map(|t| format!("{} {}", t.tool_call_id, t.tool_name))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Reason::LiveJobs(n) => {
                format!("{n} running job(s) / queued deliveries (live plugin snapshot)")
            }
            Reason::PendingMessages(n) => format!("{n} pending hcom message(s)"),
            Reason::UnknownJobs => "unknown: no job data (no recognizable job or tool records \
                 in session file; no live plugin answer)"
                .to_string(),
            Reason::NoDeliveryPath => "no delivery path (no inject endpoint registered)"
                .to_string(),
            Reason::PromptNotEmpty => {
                "prompt not empty (seat input busy; refusing to inject)".to_string()
            }
        }
    }
}

/// `<job_id> <kind>`, plus ` "<label>"` when the job carries one.
fn render_job_ref(job: &OpenJob) -> String {
    match job.label.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
        Some(label) => {
            let label: String = label.chars().take(LABEL_MAX_CHARS).collect();
            format!("{} {} \"{}\"", job.job_id, job.kind, label)
        }
        None => format!("{} {}", job.job_id, job.kind),
    }
}

/// Every applicable refusal reason, in report order. A reason that does not
/// apply contributes nothing; the caller prints all of them, never just the
/// first.
pub fn refusal_reasons(p: &Preflight) -> Vec<Reason> {
    let mut reasons = Vec::new();

    if p.status != ST_LISTENING {
        reasons.push(Reason::NotIdle {
            status: p.status.clone(),
        });
    }

    if let JobsScan::Known {
        open_jobs,
        open_tools,
    } = &p.scan
    {
        if !open_jobs.is_empty() {
            reasons.push(Reason::OpenJobs(open_jobs.clone()));
        }
        if !open_tools.is_empty() {
            reasons.push(Reason::OpenTools(open_tools.clone()));
        }
    }

    if let Some(n) = p.live_jobs.filter(|n| *n > 0) {
        reasons.push(Reason::LiveJobs(n));
    }

    if p.pending_messages > 0 {
        reasons.push(Reason::PendingMessages(p.pending_messages));
    }

    // No scan records AND no live answer at all: a live answer of 0 already
    // proves the seat is idle, so only total ignorance refuses here.
    if matches!(p.scan, JobsScan::Unknown) && p.live_jobs.is_none() {
        reasons.push(Reason::UnknownJobs);
    }

    if p.inject_port.is_none() {
        reasons.push(Reason::NoDeliveryPath);
    }

    reasons
}

// ── Focus ─────────────────────────────────────────────────────────────────────

/// The one line handed to `/compact`. Never more than one line: a newline
/// would submit the prompt early.
pub fn build_focus(
    purpose: Option<&str>,
    current: Option<&str>,
    scan: &JobsScan,
    extra: Option<&str>,
) -> String {
    let open_jobs: &[OpenJob] = match scan {
        JobsScan::Known { open_jobs, .. } => open_jobs,
        JobsScan::Unknown => &[],
    };
    let mut parts: Vec<String> = Vec::new();
    if let Some(p) = purpose.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("purpose: {p}"));
    }
    if let Some(c) = current.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("current: {c}"));
    }
    if !open_jobs.is_empty() {
        parts.push(format!(
            "open jobs: {}",
            open_jobs.iter().map(render_job_ref).collect::<Vec<_>>().join(", ")
        ));
    }
    if let Some(e) = extra.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(format!("next: {e}"));
    }
    // Collapse every whitespace run (including \r and \n) to one space.
    parts.join(" | ").split_whitespace().collect::<Vec<_>>().join(" ")
}

// ── Rendering ────────────────────────────────────────────────────────────────

/// `tokens: ...` — unknown, window unknown, or both.
pub fn render_tokens(ctx: &SeatContext) -> String {
    let Some(tokens) = ctx.tokens else {
        return "tokens: unknown".to_string();
    };
    match (ctx.window, ctx.pct) {
        (Some(window), _) => {
            let pct = ctx
                .pct
                .unwrap_or_else(|| tokens as f64 / window as f64 * 100.0);
            format!("tokens: {tokens} / {window} ({pct:.1}%)")
        }
        (None, _) => format!("tokens: {tokens} / window unknown"),
    }
}

/// `jobs: N (source: ...)`.
pub fn render_jobs(ctx: &SeatContext, scan: &JobsScan) -> String {
    let (value, source) = match ctx.source {
        ContextSource::Live => (ctx.jobs.map(|n| n.to_string()), "live plugin"),
        ContextSource::Transcript => (
            match scan {
                JobsScan::Known {
                    open_jobs,
                    open_tools,
                } => Some((open_jobs.len() + open_tools.len()).to_string()),
                JobsScan::Unknown => None,
            },
            "session-file fallback",
        ),
        ContextSource::None => (None, "none"),
    };
    format!(
        "jobs: {} (source: {source})",
        value.unwrap_or_else(|| "unknown".to_string())
    )
}

/// `delivery path: pty inject (inject endpoint port N)`.
pub fn render_delivery(inject_port: Option<i32>) -> String {
    match inject_port {
        Some(port) => format!("delivery path: pty inject (inject endpoint port {port})"),
        None => "delivery path: pty inject (no inject endpoint port)".to_string(),
    }
}

/// The whole `would-compact` report.
fn render_would_compact(
    name: &str,
    facts: &Facts,
    focus: &str,
) -> String {
    format!(
        "would-compact {name}\n  reasons: none\n  {}\n  {}\n  {}\n  focus: {focus}",
        render_tokens(&facts.ctx),
        render_jobs(&facts.ctx, &facts.preflight.scan),
        render_delivery(facts.preflight.inject_port),
    )
}

/// The refusal block: header plus one indented line per reason.
pub fn render_refusal(name: &str, reasons: &[Reason]) -> String {
    let mut out = format!("refuse: compact {name}");
    for reason in reasons {
        out.push_str(&format!("\n  - {}", reason.render()));
    }
    out
}


// ── Execution ────────────────────────────────────────────────────────────────

/// What a successful run did.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// `--dry-run`: the report that would have been acted on. Nothing changed.
    WouldCompact { report: String },
    /// The seat wrote a new compaction record.
    Compacted { record: CompactionRecord },
}

/// Why a run did not compact.
#[derive(Debug, Clone, PartialEq)]
pub enum Fail {
    /// Preflight (or the pre-inject re-check) refused. Carries the full list.
    Refused { reasons: Vec<Reason> },
    /// No new compaction record within the timeout.
    Timeout,
    /// A message printed verbatim, exit code 1.
    Error(String),
}

/// Inject port for a seat (`notify_endpoints` kind `inject`), as
/// `commands::term` resolves it.
fn inject_port(db: &HcomDb, name: &str) -> Option<i32> {
    db.conn()
        .query_row(
            "SELECT port FROM notify_endpoints WHERE instance = ?1 AND kind = 'inject'",
            rusqlite::params![name],
            |row| row.get::<_, i32>(0),
        )
        .ok()
}


/// Read every fact the refusal rules and the report need, right now.
fn gather(db: &HcomDb, row: &crate::db::InstanceRow, name: &str) -> Facts {
    let status = get_instance_status(row, db).status;
    let port = inject_port(db, name);
    let ctx = context::probe(SeatContextRequest {
        plugin_port: context::plugin_port(db, name),
        transcript_path: row.transcript_path.clone(),
        tool: row.tool.clone(),
        remote: false,
        idle_seconds: 0,
    });
    let live_jobs = if ctx.source == ContextSource::Live {
        ctx.jobs
    } else {
        None
    };
    Facts {
        preflight: Preflight {
            status,
            live_jobs,
            scan: ctx.jobs_scan.clone(),
            pending_messages: db.get_unread_messages(name).len(),
            inject_port: port,
        },
        ctx,
    }
}

/// True when the seat's input box still holds text. `None` input (no parser
/// for this tool) reads as empty, same as `hcom term` does.
fn prompt_is_busy(port: i32) -> bool {
    let deadline = Instant::now() + PROMPT_CLEAR_TIMEOUT;
    loop {
        let busy = term::query_screen(port)
            .and_then(|screen| {
                screen
                    .get("input_text")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
            })
            .unwrap_or(false);
        if !busy || Instant::now() >= deadline {
            return busy;
        }
        std::thread::sleep(PROMPT_CLEAR_POLL);
    }
}

/// The compaction record written after `since_ms`, polled until it appears or
/// `timeout` seconds pass.
fn wait_for_compaction(
    path: &Path,
    since_ms: i64,
    timeout: Duration,
) -> Option<CompactionRecord> {
    let started = Instant::now();
    loop {
        if let Some(record) = context::find_compaction_after(path, since_ms) {
            return Some(record);
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return None;
        }
        std::thread::sleep(RECORD_POLL.min(timeout - elapsed));
    }
}

/// Run the whole command, returning its outcome instead of printing it.
pub fn execute(db: &HcomDb, args: &CompactArgs) -> Result<Outcome, Fail> {
    let name = &args.name;
    let row = db
        .get_instance_full(name)
        .map_err(|e| Fail::Error(e.to_string()))?
        .ok_or_else(|| Fail::Error(format!("no such seat: {name}")))?;

    // Remote first, before any scanning: relay-mirrored seats have no local
    // PTY to inject into and no local session file to read.
    if is_remote_instance(&row) || name.contains(':') {
        return Err(Fail::Refused {
            reasons: vec![Reason::Remote],
        });
    }

    let facts = gather(db, &row, name);
    let reasons = refusal_reasons(&facts.preflight);
    if !reasons.is_empty() {
        return Err(Fail::Refused { reasons });
    }

    let focus = build_focus(
        row.purpose.as_deref(),
        row.current.as_deref(),
        &facts.preflight.scan,
        args.focus.as_deref(),
    );

    if args.dry_run {
        return Ok(Outcome::WouldCompact {
            report: render_would_compact(name, &facts, &focus),
        });
    }

    // Re-read the facts immediately before injecting: a turn that started
    // since the preflight must be caught here.
    let recheck = gather(db, &row, name);
    let reasons = refusal_reasons(&recheck.preflight);
    if !reasons.is_empty() {
        return Err(Fail::Refused { reasons });
    }

    let port = recheck
        .preflight
        .inject_port
        .expect("NoDeliveryPath already refused above");
    if prompt_is_busy(port) {
        return Err(Fail::Refused {
            reasons: vec![Reason::PromptNotEmpty],
        });
    }

    let command = if focus.is_empty() {
        "/compact".to_string()
    } else {
        format!("/compact {focus}")
    };
    // Record the instant before the injection so the wait only accepts a
    // record the seat writes in response to this command.
    let injection_ms = now_epoch_ms();
    term::inject_text_remote_result(db, name, &command, true).map_err(Fail::Error)?;
    // Tell the user the command is in before the wait, not after it.
    println!(
        "injected /compact to {name}; waiting up to {}s for a new compaction record",
        args.timeout
    );
    match wait_for_compaction(
        Path::new(&row.transcript_path),
        injection_ms,
        Duration::from_secs(args.timeout),
    ) {
        Some(record) => Ok(Outcome::Compacted { record }),
        None => Err(Fail::Timeout),
    }
}

/// Main entry point for `hcom compact`. Returns the exit code.
pub fn cmd_compact(db: &HcomDb, args: &CompactArgs, _ctx: Option<&CommandContext>) -> i32 {
    match execute(db, args) {
        Ok(Outcome::WouldCompact { report }) => {
            println!("{report}");
            0
        }
        Ok(Outcome::Compacted { record }) => {
            println!(
                "compacted {}: {} -> {} tokens (method={}, record={})",
                args.name,
                record.tokens_before,
                record.tokens_after,
                record.method,
                record.timestamp
            );
            0
        }
        Err(Fail::Refused { reasons }) => {
            println!("{}", render_refusal(&args.name, &reasons));
            1
        }
        Err(Fail::Timeout) => {
            println!(
                "timeout: no new compaction record within {}s for {}",
                args.timeout, args.name
            );
            2
        }
        Err(Fail::Error(message)) => {
            println!("{message}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// One completed background job: start record + async-result that ends it.
    /// Scans as Known { open_jobs: 0, open_tools: 0 }.
    const COMPLETED_JOB: &str = r#"{"type":"message","id":"aa11","parentId":"bb22","timestamp":"2026-09-25T10:00:00.000Z","message":{"role":"toolResult","toolCallId":"call_1","toolName":"bash","content":[{"type":"text","text":"Backgrounded as job bg_3"}],"details":{"async":{"state":"running","jobId":"bg_3","type":"bash"},"timeoutSeconds":1800},"isError":false,"timestamp":1758792000000}}
{"type":"custom_message","customType":"async-result","content":"done","display":true,"details":{"jobs":[{"jobId":"bg_3","type":"bash","label":"sleep 5","durationMs":5211}]},"attribution":"agent","id":"cc33","timestamp":"2026-09-25T10:00:06.211Z"}
"#;

    // A task job carries no timeoutSeconds: it never expires.
    const OPEN_JOB: &str = r#"{"type":"message","id":"aa11","parentId":"bb22","timestamp":"2026-09-25T10:00:00.000Z","message":{"role":"toolResult","toolCallId":"call_1","toolName":"task","content":[{"type":"text","text":"Backgrounded as job bg_3"}],"details":{"async":{"state":"running","jobId":"bg_3","type":"bash"}},"isError":false,"timestamp":1758792000000}}
"#;

    const OPEN_TOOL: &str = r#"{"type":"custom","customType":"tool_execution_start","data":{"toolCallId":"toolu_1","toolName":"bash","startedAt":"2026-09-25T10:02:00.000Z"},"id":"ff77","timestamp":"2026-09-25T10:02:00.000Z"}
"#;

    const COMPACTION: &str = r#"{"type":"compaction","id":"ab99","timestamp":"2099-01-01T00:00:00.000Z","summary":"synthetic","shortSummary":"synthetic short","tokensBefore":90363,"tokensAfter":17405,"method":"local"}
"#;

    /// A preflight with every reason switched off.
    fn clean() -> Preflight {
        Preflight {
            status: "listening".to_string(),
            live_jobs: Some(0),
            scan: JobsScan::Known {
                open_jobs: Vec::new(),
                open_tools: Vec::new(),
            },
            pending_messages: 0,
            inject_port: Some(41234),
        }
    }

    fn known(open_jobs: Vec<OpenJob>, open_tools: Vec<OpenTool>) -> JobsScan {
        JobsScan::Known {
            open_jobs,
            open_tools,
        }
    }
    fn job(id: &str, kind: &str, label: Option<&str>) -> OpenJob {
        OpenJob {
            job_id: id.to_string(),
            kind: kind.to_string(),
            label: label.map(str::to_string),
        }
    }

    fn lines(reasons: &[Reason]) -> Vec<String> {
        reasons.iter().map(|r| r.render()).collect()
    }

    // --- 1. one reason alone ------------------------------------------------

    #[test]
    fn reason_not_idle_alone() {
        let mut p = clean();
        p.status = "active".to_string();
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["not idle/listening (status=active)".to_string()]
        );
    }

    #[test]
    fn reason_open_job_alone() {
        let mut p = clean();
        p.scan = known(vec![job("bg_3", "bash", Some("sleep 5"))], Vec::new());
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["1 open job(s) (bg_3 bash \"sleep 5\")".to_string()]
        );
    }

    #[test]
    fn reason_open_job_label_is_truncated() {
        let mut p = clean();
        let long = "x".repeat(60);
        p.scan = known(vec![job("bg_3", "bash", Some(&long))], Vec::new());
        assert_eq!(
            refusal_reasons(&p)[0].render(),
            format!("1 open job(s) (bg_3 bash \"{}\")", "x".repeat(40))
        );
    }

    #[test]
    fn reason_open_tool_alone() {
        let mut p = clean();
        p.scan = known(
            Vec::new(),
            vec![OpenTool {
                tool_call_id: "toolu_1".to_string(),
                tool_name: "bash".to_string(),
            }],
        );
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["1 in-flight foreground tool(s) (toolu_1 bash)".to_string()]
        );
    }

    #[test]
    fn reason_live_jobs_alone() {
        let mut p = clean();
        p.live_jobs = Some(2);
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["2 running job(s) / queued deliveries (live plugin snapshot)".to_string()]
        );
    }

    #[test]
    fn reason_pending_messages_alone() {
        let mut p = clean();
        p.pending_messages = 3;
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["3 pending hcom message(s)".to_string()]
        );
    }

    #[test]
    fn reason_unknown_jobs_alone() {
        let mut p = clean();
        p.live_jobs = None;
        p.scan = JobsScan::Unknown;
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["unknown: no job data (no recognizable job or tool records in session file; \
              no live plugin answer)"
                .to_string()]
        );
    }

    #[test]
    fn a_live_zero_suppresses_the_unknown_jobs_reason() {
        let mut p = clean();
        p.live_jobs = Some(0);
        p.scan = JobsScan::Unknown;
        assert!(refusal_reasons(&p).is_empty());
    }

    #[test]
    fn reason_no_delivery_path_alone() {
        let mut p = clean();
        p.inject_port = None;
        assert_eq!(
            lines(&refusal_reasons(&p)),
            ["no delivery path (no inject endpoint registered)".to_string()]
        );
    }

    // --- 2. several reasons, in order ---------------------------------------

    #[test]
    fn every_applicable_reason_is_named_in_order() {
        let mut p = clean();
        p.status = "working".to_string();
        p.scan = known(
            vec![job("bg_3", "bash", Some("sleep 5"))],
            vec![OpenTool {
                tool_call_id: "toolu_1".to_string(),
                tool_name: "bash".to_string(),
            }],
        );
        p.live_jobs = Some(1);
        p.pending_messages = 2;
        p.inject_port = None;
        assert_eq!(
            lines(&refusal_reasons(&p)),
            [
                "not idle/listening (status=working)".to_string(),
                "1 open job(s) (bg_3 bash \"sleep 5\")".to_string(),
                "1 in-flight foreground tool(s) (toolu_1 bash)".to_string(),
                "1 running job(s) / queued deliveries (live plugin snapshot)".to_string(),
                "2 pending hcom message(s)".to_string(),
                "no delivery path (no inject endpoint registered)".to_string(),
            ]
        );
    }

    #[test]
    fn a_clean_seat_has_no_reasons() {
        assert!(refusal_reasons(&clean()).is_empty());
    }

    // --- 3./4. focus ---------------------------------------------------------

    #[test]
    fn focus_is_collapsed_to_one_line_and_keeps_every_part() {
        let focus = build_focus(
            Some("ship the\nrelease"),
            Some("fix\r\n  the flaky test"),
            &known(vec![job("bg_3", "bash", Some("run\nsuite"))], Vec::new()),
            Some("then  tag  and push"),
        );
        assert!(!focus.contains('\n') && !focus.contains('\r'), "{focus}");
        assert!(focus.contains("purpose: ship the release"), "{focus}");
        assert!(focus.contains("current: fix the flaky test"), "{focus}");
        assert!(focus.contains("open jobs: bg_3 bash \"run suite\""), "{focus}");
        assert!(focus.contains("next: then tag and push"), "{focus}");
    }

    #[test]
    fn focus_is_empty_when_there_is_nothing_to_say() {
        assert_eq!(build_focus(None, None, &JobsScan::Unknown, None), "");
    }

    // --- e2e setup ------------------------------------------------------------

    struct Seat {
        _dir: tempfile::TempDir,
        db: HcomDb,
    }

    /// A seat with the given status, transcript body and inject port.
    fn seat(status: &str, transcript: &str, inject: Option<i32>) -> Seat {
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_at(&dir.path().join("hcom.db")).unwrap();
        let path = dir.path().join("session.jsonl");
        std::fs::write(&path, transcript).unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, tool, status, status_context, status_time,
                                       created_at, transcript_path, last_event_id)
                 VALUES ('luna', 'omp', ?1, 'ready', ?2, 0, ?3, 0)",
                rusqlite::params![status, now_epoch_ms(), path.to_string_lossy()],
            )
            .unwrap();
        if let Some(port) = inject {
            db.conn()
                .execute(
                    "INSERT INTO notify_endpoints (instance, kind, port, updated_at)
                     VALUES ('luna', 'inject', ?1, 0)",
                    rusqlite::params![port],
                )
                .unwrap();
        }
        Seat { _dir: dir, db }
    }

    fn event_count(db: &HcomDb) -> i64 {
        db.conn()
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))
            .unwrap()
    }

    fn args(name: &str) -> CompactArgs {
        CompactArgs {
            name: name.to_string(),
            focus: None,
            dry_run: false,
            timeout: 10,
        }
    }

    /// A port with nothing listening on it: a real inject attempt would fail.
    fn dead_port() -> i32 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port() as i32
    }

    /// A stub inject endpoint: accepts, reads, closes without replying.
    fn stub_endpoint() -> (i32, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port() as i32;
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                seen.fetch_add(1, Ordering::SeqCst);
                use std::io::Read;
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
            }
        });
        (port, count)
    }

    // --- 5. dry run changes nothing -------------------------------------------

    #[test]
    fn dry_run_reports_and_injects_nothing() {
        let s = seat("listening", COMPLETED_JOB, Some(dead_port()));
        let before = event_count(&s.db);
        let outcome = execute(&s.db, &CompactArgs {
            dry_run: true,
            ..args("luna")
        })
        .expect("would-compact");
        match outcome {
            Outcome::WouldCompact { report } => {
                assert!(report.starts_with("would-compact luna\n  reasons: none\n"), "{report}");
                assert!(report.contains("jobs: 0 (source: session-file fallback)"), "{report}");
                assert!(report.contains("delivery path: pty inject (inject endpoint port "), "{report}");
            }
            other => panic!("expected WouldCompact, got {other:?}"),
        }
        assert_eq!(event_count(&s.db), before, "dry-run wrote events");
    }

    #[test]
    fn dry_run_refuses_for_every_reason() {
        let s = seat("active", OPEN_JOB, Some(dead_port()));
        let fail = execute(
            &s.db,
            &CompactArgs {
                dry_run: true,
                ..args("luna")
            },
        )
        .expect_err("refused");
        match fail {
            Fail::Refused { reasons } => {
                let text = lines(&reasons);
                assert!(text.contains(&"not idle/listening (status=active)".to_string()), "{text:?}");
                assert!(text.contains(&"1 open job(s) (bg_3 bash)".to_string()), "{text:?}");
            }
            other => panic!("expected Refused, got {other:?}"),
        }
    }

    #[test]
    fn an_in_flight_foreground_tool_refuses_with_its_own_line() {
        let (port, connections) = stub_endpoint();
        let s = seat("listening", OPEN_TOOL, Some(port));
        let fail = execute(&s.db, &args("luna")).expect_err("refused");
        match fail {
            Fail::Refused { reasons } => assert_eq!(
                reasons[0].render(),
                "1 in-flight foreground tool(s) (toolu_1 bash)"
            ),
            other => panic!("expected Refused, got {other:?}"),
        }
        assert_eq!(connections.load(Ordering::SeqCst), 0, "refused seat was contacted");
    }

    // --- 6. real run ---------------------------------------------------------

    #[test]
    fn real_run_injects_and_waits_for_the_record() {
        let (port, connections) = stub_endpoint();
        let body = format!("{COMPLETED_JOB}{COMPACTION}");
        let s = seat("listening", &body, Some(port));
        let outcome = execute(&s.db, &args("luna")).expect("compacted");
        match outcome {
            Outcome::Compacted { record } => {
                assert_eq!(record.tokens_before, 90363);
                assert_eq!(record.tokens_after, 17405);
                assert_eq!(record.method, "local");
                assert_eq!(record.timestamp, "2099-01-01T00:00:00.000Z");
            }
            other => panic!("expected Compacted, got {other:?}"),
        }
        assert!(
            connections.load(Ordering::SeqCst) >= 1,
            "the inject endpoint was never contacted"
        );
    }

    // --- 7. timeout ----------------------------------------------------------

    #[test]
    fn no_record_within_the_timeout_times_out() {
        let (port, _) = stub_endpoint();
        let s = seat("listening", COMPLETED_JOB, Some(port));
        let fail = execute(
            &s.db,
            &CompactArgs {
                timeout: 1,
                ..args("luna")
            },
        )
        .expect_err("timeout");
        assert_eq!(fail, Fail::Timeout);
    }

    // --- 8. refusal never reaches the PTY -----------------------------------

    #[test]
    fn a_working_seat_is_refused_before_any_connection() {
        let (port, connections) = stub_endpoint();
        let body = format!("{COMPLETED_JOB}{COMPACTION}");
        let s = seat("active", &body, Some(port));
        let fail = execute(&s.db, &args("luna")).expect_err("refused");
        match fail {
            Fail::Refused { reasons } => assert_eq!(reasons[0].render(), "not idle/listening (status=active)"),
            other => panic!("expected Refused, got {other:?}"),
        }
        assert_eq!(connections.load(Ordering::SeqCst), 0, "refused seat was contacted");
    }

    #[test]
    fn an_unknown_seat_reports_no_such_seat() {
        let s = seat("listening", COMPLETED_JOB, None);
        let fail = execute(&s.db, &args("nobody")).expect_err("no seat");
        assert_eq!(fail, Fail::Error("no such seat: nobody".to_string()));
    }

    #[test]
    fn a_remote_seat_is_refused_outright() {
        let s = seat("listening", COMPLETED_JOB, Some(dead_port()));
        s.db.conn().execute(
            "INSERT INTO instances (name, tool, status, status_context, status_time,
                                    created_at, origin_device_id)
             VALUES ('luna:BOXE', 'omp', 'listening', 'ready', ?1, 0, 'laptop')",
            rusqlite::params![now_epoch_ms()],
        ).unwrap();
        let fail = execute(&s.db, &args("luna:BOXE")).expect_err("remote");
        assert_eq!(fail, Fail::Refused { reasons: vec![Reason::Remote] });
        assert_eq!(
            render_refusal("luna:BOXE", &[Reason::Remote]),
            "refuse: compact luna:BOXE\n  - remote seat (relay compaction unsupported)"
        );
    }

    // --- 9. render helpers ----------------------------------------------------

    #[test]
    fn render_tokens_variants() {
        let ctx = |tokens, window| SeatContext {
            source: ContextSource::Transcript,
            tokens,
            window,
            pct: None,
            jobs: None,
            jobs_scan: JobsScan::Unknown,
            idle_seconds: None,
        };
        assert_eq!(render_tokens(&ctx(None, None)), "tokens: unknown");
        assert_eq!(
            render_tokens(&ctx(Some(182_340), Some(258_400))),
            "tokens: 182340 / 258400 (70.6%)"
        );
        assert_eq!(
            render_tokens(&ctx(Some(182_340), None)),
            "tokens: 182340 / window unknown"
        );
    }

    #[test]
    fn render_jobs_variants() {
        let ctx = |source, jobs| SeatContext {
            source,
            tokens: None,
            window: None,
            pct: None,
            jobs,
            jobs_scan: JobsScan::Unknown,
            idle_seconds: None,
        };
        assert_eq!(
            render_jobs(&ctx(ContextSource::Live, Some(0)), &JobsScan::Unknown),
            "jobs: 0 (source: live plugin)"
        );
        assert_eq!(
            render_jobs(
                &ctx(ContextSource::Transcript, None),
                &known(vec![job("bg_3", "bash", None)], Vec::new())
            ),
            "jobs: 1 (source: session-file fallback)"
        );
        assert_eq!(
            render_jobs(&ctx(ContextSource::None, None), &JobsScan::Unknown),
            "jobs: unknown (source: none)"
        );
    }

    #[test]
    fn render_would_compact_report_is_the_documented_shape() {
        let facts = Facts {
            preflight: clean(),
            ctx: SeatContext {
                source: ContextSource::Live,
                tokens: Some(182_340),
                window: Some(258_400),
                pct: Some(70.6),
                jobs: Some(0),
                jobs_scan: JobsScan::Unknown,
                idle_seconds: None,
            },
        };
        assert_eq!(
            render_would_compact("luna", &facts, "purpose: ship it"),
            "would-compact luna\n  reasons: none\n  \
             tokens: 182340 / 258400 (70.6%)\n  \
             jobs: 0 (source: live plugin)\n  \
             delivery path: pty inject (inject endpoint port 41234)\n  \
             focus: purpose: ship it"
        );
    }
}
