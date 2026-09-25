//! `hcom list --context` — per-seat context size and in-flight work.
//!
//! Opt-in (`--context`); nothing here runs without the flag and nothing is
//! persisted. Per seat we report `tokens` / `window` / `pct` / `jobs` plus an
//! idle duration, from one of three sources:
//!
//! - [`ContextSource::Live`] — the seat's hcom plugin (omp/pi) answered a
//!   one-line JSON query over its notify port (`{"q":"context"}` → one reply
//!   line). The numbers are the seat's own (`getContextUsage()` /
//!   `getAsyncJobSnapshot()`).
//! - [`ContextSource::Transcript`] — no live answer (old plugin, non-omp
//!   seat): the newest usage record in the tail of the session file.
//! - [`ContextSource::None`] — remote/relay-mirrored seat or no transcript;
//!   every value renders as `-`.
//!
//! `jobs` is `unknown` (never `0`) whenever the count is not known.

use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use crate::db::HcomDb;
use crate::shared::ST_LISTENING;
use crate::tool::Tool;

/// One line the live client writes to the plugin's notify port. Anything that
/// sends no request (every existing wake sender) keeps the wake behavior.
const CONTEXT_QUERY: &str = "{\"q\":\"context\"}\n";

/// Per-seat budget for the live query (connect + one reply line). Seats are
/// queried concurrently, so this bounds `hcom list --context` as a whole.
const LIVE_QUERY_TIMEOUT: Duration = Duration::from_millis(500);

/// Sanity cap on the reply line; a context reply is far smaller.
const MAX_REPLY_BYTES: usize = 4096;

/// How much of the session file the fallback reads (from the end, never whole).
const TRANSCRIPT_TAIL_BYTES: u64 = 64 * 1024;

/// Threshold above which the human output marks a seat's context usage.
pub(crate) const PCT_MARK_THRESHOLD: f64 = 60.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSource {
    Live,
    Transcript,
    None,
}

impl ContextSource {
    pub fn as_str(self) -> &'static str {
        match self {
            ContextSource::Live => "live",
            ContextSource::Transcript => "transcript",
            ContextSource::None => "none",
        }
    }
}

/// What `hcom list --context` knows about one seat. `None` means unknown and
/// renders as `?` (`unknown` for `jobs`, `-` for every value on a
/// [`ContextSource::None`] seat).
#[derive(Debug, Clone, PartialEq)]
pub struct SeatContext {
    pub source: ContextSource,
    pub tokens: Option<u64>,
    pub window: Option<u64>,
    pub pct: Option<f64>,
    pub jobs: Option<u64>,
    pub idle_seconds: Option<i64>,
}

impl SeatContext {
    fn unknown() -> Self {
        SeatContext {
            source: ContextSource::None,
            tokens: None,
            window: None,
            pct: None,
            jobs: None,
            idle_seconds: None,
        }
    }
}

/// Everything [`probe`] needs about one seat; owned so it can move into a
/// query thread. Built by the list command from the instance row (the DB is
/// only read on the calling thread — `HcomDb` is not `Sync`).
#[derive(Debug, Clone)]
pub struct SeatContextRequest {
    /// `notify_endpoints` port with kind `plugin` (omp/pi live query).
    pub plugin_port: Option<u16>,
    pub transcript_path: String,
    pub tool: String,
    /// Relay-mirrored / remote seat: no local truth to report.
    pub remote: bool,
    pub idle_seconds: i64,
}

/// The plugin's reply line: flat `{tokens, contextWindow, percent, jobs}`,
/// each field `null` when the seat could not compute it.
#[derive(Debug, Clone, Copy, PartialEq)]
struct LiveReply {
    tokens: Option<u64>,
    window: Option<u64>,
    pct: Option<f64>,
    jobs: Option<u64>,
}

/// Newest usage found in a transcript tail. `window` only where the file
/// itself records one (codex) — never a hardcoded model-window table.
#[derive(Debug, Clone, Copy, PartialEq)]
struct TailUsage {
    tokens: u64,
    window: Option<u64>,
}

/// Read the last [`TRANSCRIPT_TAIL_BYTES`] of a session file. Seeks from the
/// end; never reads the whole file. The first line of a partial read is
/// dropped so a half-record can never parse as someone's usage.
fn read_tail(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let start = len.saturating_sub(TRANSCRIPT_TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf).into_owned();
    if start == 0 {
        return Some(text);
    }
    // The window cut a line in half; drop it rather than risk parsing a
    // truncated record as someone's usage.
    text.find('\n').map(|idx| text[idx + 1..].to_string())
}

fn jnum(value: Option<&Value>) -> u64 {
    match value {
        Some(Value::Number(n)) => n
            .as_u64()
            .or_else(|| n.as_f64().map(|f| f.max(0.0) as u64))
            .unwrap_or(0),
        _ => 0,
    }
}

/// omp/pi session records: the newest assistant `message.usage`; tokens =
/// input + cacheRead + cacheWrite.
fn parse_pi_usage(tail: &str) -> Option<TailUsage> {
    let mut newest = None;
    for line in tail.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if entry.get("type").and_then(Value::as_str) != Some("message") {
            continue;
        }
        let Some(message) = entry.get("message") else {
            continue;
        };
        if message.get("role").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        let Some(usage) = message.get("usage").filter(|u| u.is_object()) else {
            continue;
        };
        let tokens =
            jnum(usage.get("input")) + jnum(usage.get("cacheRead")) + jnum(usage.get("cacheWrite"));
        newest = Some(TailUsage {
            tokens,
            window: None,
        });
    }
    newest
}

/// Claude session records: the newest non-sidechain assistant `message.usage`;
/// tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.
fn parse_claude_usage(tail: &str) -> Option<TailUsage> {
    let mut newest = None;
    for line in tail.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if entry.get("type").and_then(Value::as_str) != Some("assistant") {
            continue;
        }
        if entry
            .get("isSidechain")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let Some(usage) = entry
            .get("message")
            .and_then(|m| m.get("usage"))
            .filter(|u| u.is_object())
        else {
            continue;
        };
        let tokens = jnum(usage.get("input_tokens"))
            + jnum(usage.get("cache_creation_input_tokens"))
            + jnum(usage.get("cache_read_input_tokens"));
        newest = Some(TailUsage {
            tokens,
            window: None,
        });
    }
    newest
}

/// Codex rollout records: the newest `token_count` event; tokens =
/// last_token_usage.total_tokens, window = model_context_window.
fn parse_codex_usage(tail: &str) -> Option<TailUsage> {
    let mut newest = None;
    for line in tail.lines() {
        let Ok(entry) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let payload = entry.get("payload").unwrap_or(&entry);
        if payload.get("type").and_then(Value::as_str) != Some("token_count") {
            continue;
        }
        let Some(info) = payload.get("info") else {
            continue;
        };
        let Some(last) = info.get("last_token_usage") else {
            continue;
        };
        let window = info
            .get("model_context_window")
            .and_then(Value::as_u64)
            .filter(|w| *w > 0);
        newest = Some(TailUsage {
            tokens: jnum(last.get("total_tokens")),
            window,
        });
    }
    newest
}

/// Dispatch the tail parsers for a seat's tool. `None` when the tool has no
/// usage-record format here (the seat still reports `transcript` source).
fn tail_usage(tool: &str, transcript_path: &str) -> Option<TailUsage> {
    if transcript_path.is_empty() {
        return None;
    }
    let tool = tool.parse::<Tool>().ok()?;
    let tail = read_tail(Path::new(transcript_path))?;
    match tool {
        Tool::Omp | Tool::Pi => parse_pi_usage(&tail),
        Tool::Claude => parse_claude_usage(&tail),
        Tool::Codex => parse_codex_usage(&tail),
        _ => None,
    }
}

/// One live query against a plugin notify port. Sends [`CONTEXT_QUERY`] and
/// reads one JSON reply line; `None` on any failure (old plugin closes without
/// replying, no answer within [`LIVE_QUERY_TIMEOUT`], malformed reply).
fn query_plugin(port: u16) -> Option<LiveReply> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, LIVE_QUERY_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(LIVE_QUERY_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(LIVE_QUERY_TIMEOUT)).ok()?;
    stream.write_all(CONTEXT_QUERY.as_bytes()).ok()?;

    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if reply.len() >= MAX_REPLY_BYTES {
            return None;
        }
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                reply.push(byte[0]);
            }
            Err(_) => return None,
        }
    }
    let value: Value = serde_json::from_slice(&reply).ok()?;
    Some(LiveReply {
        tokens: value.get("tokens").and_then(json_u64),
        window: value.get("contextWindow").and_then(json_u64),
        pct: value.get("percent").and_then(Value::as_f64),
        jobs: value.get("jobs").and_then(json_u64),
    })
}

/// Number from a live reply field. Only a JSON number counts: `null` (and any
/// other shape a host might send) is *unknown*, never a fabricated 0.
fn json_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f.max(0.0) as u64)),
        _ => None,
    }
}

/// Usage percent: the seat's own number when reported, else computed from
/// tokens/window when both are known.
fn pct_of(tokens: Option<u64>, window: Option<u64>, reported: Option<f64>) -> Option<f64> {
    if let Some(pct) = reported {
        return Some(pct);
    }
    match (tokens, window) {
        (Some(tokens), Some(window)) if window > 0 => Some(tokens as f64 * 100.0 / window as f64),
        _ => None,
    }
}

/// Gather one seat's context: live query first, transcript tail as fallback.
pub fn probe(req: SeatContextRequest) -> SeatContext {
    if req.remote {
        return SeatContext::unknown();
    }

    if let Some(port) = req.plugin_port
        && let Some(reply) = query_plugin(port)
    {
        return SeatContext {
            source: ContextSource::Live,
            tokens: reply.tokens,
            window: reply.window,
            pct: pct_of(reply.tokens, reply.window, reply.pct),
            jobs: reply.jobs,
            idle_seconds: Some(req.idle_seconds),
        };
    }

    if req.transcript_path.is_empty() || !Path::new(&req.transcript_path).is_file() {
        return SeatContext::unknown();
    }

    let usage = tail_usage(&req.tool, &req.transcript_path);
    SeatContext {
        source: ContextSource::Transcript,
        tokens: usage.map(|u| u.tokens),
        window: usage.and_then(|u| u.window),
        pct: usage.and_then(|u| pct_of(Some(u.tokens), u.window, None)),
        jobs: None,
        idle_seconds: Some(req.idle_seconds),
    }
}

/// [`probe`] for many seats concurrently (one short-lived query thread each,
/// order-preserving). Keeps `hcom list --context` fast as seats grow.
pub fn probe_seats(reqs: Vec<SeatContextRequest>) -> Vec<SeatContext> {
    if reqs.len() <= 1 {
        return reqs.into_iter().map(probe).collect();
    }
    std::thread::scope(|scope| {
        let handles: Vec<_> = reqs
            .into_iter()
            .map(|req| scope.spawn(move || probe(req)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap_or_else(|_| SeatContext::unknown()))
            .collect()
    })
}

/// Idle duration for the context view: hcom's own tracking — `idle_since` when
/// set, else time since `status_time` for listening seats. A working seat is
/// not idle (0).
pub fn idle_seconds_for(status: &str, status_time: i64, idle_since: Option<&str>, now: i64) -> i64 {
    if let Some(since) = idle_since
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<f64>().ok())
    {
        return (now - since as i64).max(0);
    }
    if status == ST_LISTENING && status_time > 0 {
        return (now - status_time).max(0);
    }
    0
}

/// The per-seat columns for human output. `-` everywhere for a
/// [`ContextSource::None`] seat; `unknown` (never `0`) for an unknown job
/// count; `!` marks pct over [`PCT_MARK_THRESHOLD`].
pub fn format_columns(ctx: &SeatContext) -> String {
    if ctx.source == ContextSource::None {
        return "ctx: tokens=- window=- pct=- jobs=- idle=- src=none".to_string();
    }
    let tokens = ctx
        .tokens
        .map_or_else(|| "?".to_string(), |v| v.to_string());
    let window = ctx
        .window
        .map_or_else(|| "?".to_string(), |v| v.to_string());
    let pct = match ctx.pct {
        Some(pct) => {
            let mark = if pct > PCT_MARK_THRESHOLD { "!" } else { "" };
            format!("{pct:.1}%{mark}")
        }
        None => "?".to_string(),
    };
    let jobs = ctx
        .jobs
        .map_or_else(|| "unknown".to_string(), |v| v.to_string());
    let idle = ctx
        .idle_seconds
        .map_or_else(|| "-".to_string(), format_idle);
    format!(
        "ctx: tokens={tokens} window={window} pct={pct} jobs={jobs} idle={idle} src={}",
        ctx.source.as_str()
    )
}

/// Idle duration as a short string; a working seat reads `0s`.
fn format_idle(seconds: i64) -> String {
    if seconds <= 0 {
        "0s".to_string()
    } else {
        crate::shared::time::format_age(seconds)
    }
}

/// The `context` object for `--json` output.
pub fn to_json(ctx: &SeatContext) -> Value {
    json!({
        "source": ctx.source.as_str(),
        "tokens": ctx.tokens,
        "window": ctx.window,
        "pct": ctx.pct,
        "jobs": ctx.jobs,
        "idle_seconds": ctx.idle_seconds,
    })
}

/// `notify_endpoints` port for the seat's plugin (kind `plugin`), if bound.
pub fn plugin_port(db: &HcomDb, instance: &str) -> Option<u16> {
    db.conn()
        .query_row(
            "SELECT port FROM notify_endpoints WHERE instance = ?1 AND kind = 'plugin'",
            rusqlite::params![instance],
            |row| row.get::<_, i64>(0),
        )
        .ok()
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::time::Instant;

    const OMP_FIXTURE: &str = r#"{"id":"a1","type":"message","timestamp":"2026-09-25T00:00:00Z","message":{"role":"assistant","content":[],"usage":{"input":10,"output":50,"cacheRead":1000,"cacheWrite":200}}}
{"id":"a2","type":"message","timestamp":"2026-09-25T00:01:00Z","message":{"role":"assistant","content":[],"usage":{"input":2,"output":30,"cacheRead":6000,"cacheWrite":10}}}
{"id":"u1","type":"message","message":{"role":"user","content":"hi"}}
"#;

    const CLAUDE_FIXTURE: &str = r#"{"type":"assistant","isSidechain":false,"message":{"role":"assistant","usage":{"input_tokens":5,"cache_creation_input_tokens":100,"cache_read_input_tokens":900,"output_tokens":20}}}
{"type":"assistant","isSidechain":true,"message":{"role":"assistant","usage":{"input_tokens":5000,"cache_creation_input_tokens":5000,"cache_read_input_tokens":5000,"output_tokens":20}}}
"#;

    const CODEX_FIXTURE: &str = r#"{"timestamp":"2026-09-25T00:00:00Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":100,"cached_input_tokens":50,"output_tokens":10,"total_tokens":160},"model_context_window":200000}}}
{"timestamp":"2026-09-25T00:02:00Z","type":"event_msg","payload":{"type":"token_count","info":{"last_token_usage":{"input_tokens":300,"cached_input_tokens":150,"output_tokens":50,"total_tokens":500},"model_context_window":258400}}}
"#;

    fn fixture_file(dir: &Path, name: &str, body: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn parse_pi_usage_takes_newest_assistant_usage() {
        let usage = parse_pi_usage(OMP_FIXTURE).expect("pi usage");
        // 2 + 6000 + 10 (input + cacheRead + cacheWrite of the newest record).
        assert_eq!(usage.tokens, 6012);
        assert_eq!(
            usage.window, None,
            "pi records no window — must stay unknown"
        );
    }

    #[test]
    fn parse_claude_usage_skips_sidechain_lines() {
        let usage = parse_claude_usage(CLAUDE_FIXTURE).expect("claude usage");
        // 5 + 100 + 900: the newer sidechain record must not win.
        assert_eq!(usage.tokens, 1005);
        assert_eq!(usage.window, None);
    }

    #[test]
    fn parse_codex_usage_reads_last_token_count_with_window() {
        let usage = parse_codex_usage(CODEX_FIXTURE).expect("codex usage");
        assert_eq!(usage.tokens, 500);
        assert_eq!(usage.window, Some(258_400));
    }

    #[test]
    fn read_tail_never_returns_a_partial_first_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.jsonl");
        let filler = "x".repeat(200);
        let mut body = String::new();
        for i in 0..500 {
            body.push_str(&format!("{{\"pad\":\"{filler}\",\"i\":{i}}}\n"));
        }
        body.push_str(OMP_FIXTURE);
        std::fs::write(&path, body).unwrap();
        let tail = read_tail(&path).expect("tail");
        let usage = parse_pi_usage(&tail).expect("usage in tail");
        assert_eq!(usage.tokens, 6012);
    }

    fn fake_plugin_server(
        mode: &str,
    ) -> (
        u16,
        std::sync::mpsc::Receiver<String>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        let mode = mode.to_string();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            match mode.as_str() {
                // Old plugin: end the connection without answering.
                "close" => {
                    drop(stream);
                }
                // A plugin that never answers.
                "silent" => {
                    let mut buf = [0u8; 64];
                    let _ = stream.read(&mut buf);
                    let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
                    std::thread::sleep(Duration::from_millis(3_000));
                }
                "reply" => {
                    let mut buf = [0u8; 64];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                    stream
                        .write_all(b"{\"tokens\":4200,\"contextWindow\":200000,\"percent\":2.1,\"jobs\":3}\n")
                        .unwrap();
                }
                // A reply whose job count is not a number: unknown, not 0.
                "garbage" => {
                    let mut buf = [0u8; 64];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    let _ = tx.send(String::from_utf8_lossy(&buf[..n]).into_owned());
                    stream
                        .write_all(b"{\"tokens\":null,\"contextWindow\":null,\"percent\":null,\"jobs\":\"many\"}\n")
                        .unwrap();
                }
                _ => unreachable!(),
            }
        });
        (port, rx, handle)
    }

    fn transcript_req(port: Option<u16>, transcript_path: String) -> SeatContextRequest {
        SeatContextRequest {
            plugin_port: port,
            transcript_path,
            tool: "claude".to_string(),
            remote: false,
            idle_seconds: 42,
        }
    }

    #[test]
    fn live_reply_is_parsed_as_live() {
        let (port, rx, handle) = fake_plugin_server("reply");
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_file(dir.path(), "s.jsonl", CLAUDE_FIXTURE);
        let ctx = probe(transcript_req(Some(port), path));
        handle.join().unwrap();
        let request = rx.recv().unwrap();
        assert_eq!(
            request.trim(),
            r#"{"q":"context"}"#,
            "the live query must be exactly one request line"
        );
        assert_eq!(ctx.source, ContextSource::Live);
        assert_eq!(ctx.tokens, Some(4200));
        assert_eq!(ctx.window, Some(200_000));
        assert_eq!(ctx.pct, Some(2.1));
        assert_eq!(ctx.jobs, Some(3), "numeric job count from the snapshot");
        assert_eq!(ctx.idle_seconds, Some(42));
    }

    #[test]
    fn old_plugin_close_falls_back_with_unknown_jobs() {
        let (port, _rx, handle) = fake_plugin_server("close");
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_file(dir.path(), "s.jsonl", CLAUDE_FIXTURE);
        let ctx = probe(transcript_req(Some(port), path));
        handle.join().unwrap();
        assert_eq!(ctx.source, ContextSource::Transcript);
        assert_eq!(ctx.tokens, Some(1005));
        assert_eq!(ctx.jobs, None, "fallback path never knows the job count");
    }

    #[test]
    fn silent_plugin_times_out_and_falls_back() {
        let (port, _rx, handle) = fake_plugin_server("silent");
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_file(dir.path(), "s.jsonl", CLAUDE_FIXTURE);
        let started = Instant::now();
        let ctx = probe(transcript_req(Some(port), path));
        let elapsed = started.elapsed();
        handle.join().unwrap();
        assert_eq!(ctx.source, ContextSource::Transcript);
        assert_eq!(ctx.jobs, None);
        assert!(
            elapsed < Duration::from_millis(2_000),
            "the query must fall back inside its per-seat bound, took {elapsed:?}"
        );
    }

    #[test]
    fn probe_without_plugin_or_transcript_reports_none() {
        let ctx = probe(SeatContextRequest {
            plugin_port: None,
            transcript_path: String::new(),
            tool: "omp".to_string(),
            remote: false,
            idle_seconds: 5,
        });
        assert_eq!(ctx.source, ContextSource::None);
        assert_eq!(ctx.tokens, None);
        assert_eq!(ctx.jobs, None);
        assert_eq!(
            ctx.idle_seconds, None,
            "a source-none seat shows no idle value"
        );
    }

    #[test]
    fn remote_seats_report_none_even_with_a_transcript() {
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_file(dir.path(), "s.jsonl", OMP_FIXTURE);
        let ctx = probe(SeatContextRequest {
            plugin_port: None,
            transcript_path: path,
            tool: "omp".to_string(),
            remote: true,
            idle_seconds: 5,
        });
        assert_eq!(ctx.source, ContextSource::None);
        assert_eq!(ctx.tokens, None);
    }

    #[test]
    fn jobs_null_renders_unknown_never_zero() {
        let ctx = SeatContext {
            source: ContextSource::Transcript,
            tokens: Some(100),
            window: None,
            pct: None,
            jobs: None,
            idle_seconds: Some(3),
        };
        let line = format_columns(&ctx);
        assert!(line.contains("jobs=unknown"), "got: {line}");
        assert!(!line.contains("jobs=0"), "got: {line}");
    }

    #[test]
    fn non_numeric_live_fields_are_unknown_not_zero() {
        let (port, _rx, handle) = fake_plugin_server("garbage");
        let dir = tempfile::tempdir().unwrap();
        let path = fixture_file(dir.path(), "s.jsonl", CLAUDE_FIXTURE);
        let ctx = probe(transcript_req(Some(port), path));
        handle.join().unwrap();
        assert_eq!(ctx.source, ContextSource::Live);
        assert_eq!(
            ctx.jobs, None,
            "a non-number job count is not a known count"
        );
        let line = format_columns(&ctx);
        assert!(line.contains("jobs=unknown"), "got: {line}");
        assert!(!line.contains("jobs=0"), "got: {line}");
    }

    #[test]
    fn over_60_pct_marker_on_off_at_boundary() {
        let render = |pct: f64| {
            format_columns(&SeatContext {
                source: ContextSource::Live,
                tokens: Some(100),
                window: Some(200),
                pct: Some(pct),
                jobs: Some(0),
                idle_seconds: Some(0),
            })
        };
        assert!(!render(60.0).contains('!'), "60.0%% must not mark");
        assert!(render(61.0).contains('!'), "61.0%% must mark");
    }

    #[test]
    fn source_none_renders_dashes() {
        let line = format_columns(&SeatContext::unknown());
        assert_eq!(
            line, "ctx: tokens=- window=- pct=- jobs=- idle=- src=none",
            "a source-none seat shows dashes for every value"
        );
    }

    #[test]
    fn idle_seconds_from_status_time_for_listening() {
        assert_eq!(idle_seconds_for(ST_LISTENING, 100, None, 130), 30);
        assert_eq!(idle_seconds_for("active", 100, None, 130), 0);
        assert_eq!(
            idle_seconds_for(ST_LISTENING, 100, Some("110"), 130),
            20,
            "explicit idle_since wins over status_time"
        );
        assert_eq!(idle_seconds_for(ST_LISTENING, 0, None, 130), 0);
    }

    #[test]
    fn to_json_carries_source_and_optionals() {
        let ctx = SeatContext {
            source: ContextSource::Live,
            tokens: Some(1),
            window: None,
            pct: Some(12.5),
            jobs: Some(0),
            idle_seconds: Some(7),
        };
        let v = to_json(&ctx);
        assert_eq!(v["source"], "live");
        assert_eq!(v["tokens"], 1);
        assert_eq!(v["window"], Value::Null);
        assert_eq!(v["pct"], 12.5);
        assert_eq!(v["jobs"], 0);
        assert_eq!(v["idle_seconds"], 7);
    }
}
