//! `hcom buzz` — the Buzz connector's command family.
//!
//! `serve` runs the connector; `status`, `read` and `down` operate against the
//! connector's state; `query`, `members`, `prepare` and `publish` are the
//! mbai-local Q&A transport, restricted to the identities the connector config
//! lists as `local_signers`.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::buzz::config::Config;
use crate::buzz::nostr::{self, Event, UnsignedEvent, sign};
use crate::buzz::relay::PublishError;
use crate::buzz::route;
use crate::buzz::serve::{AgentIdentity, Connector, ServeLock};
use crate::buzz::store::{self, Store};
use crate::db::HcomDb;
use crate::relay::control::{RPC_DEFAULT_TIMEOUT, dispatch_remote, rpc_action};

/// Parsed arguments for `hcom buzz`.
#[derive(clap::Parser, Debug)]
#[command(
    name = "buzz",
    about = "Buzz connector: bridge Buzz humans and hcom agents"
)]
pub struct BuzzArgs {
    #[command(subcommand)]
    pub cmd: BuzzSubcmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum BuzzSubcmd {
    /// Run the connector (the only command that talks as the connector)
    Serve,
    /// Connector state: channels, people, outbox, errors
    Status(StatusArgs),
    /// Read a bridged channel's cached Buzz events
    Read(ReadArgs),
    /// Drain, stop the connector, and mark hosted rows stopped
    Down,
    /// Signed `/query` as a local signer (mbai only)
    Query(QueryArgs),
    /// Channel members as a local signer (mbai only)
    Members(MembersArgs),
    /// Sign a kind 9 without sending it (mbai only)
    Prepare(PrepareArgs),
    /// Post a signed event from stdin, enrolling first (mbai only)
    Publish(PublishArgs),
    /// A local signer's Buzz identity: name and pubkey, no signing (mbai only)
    Identity(IdentityArgs),
    /// Inspect or seed a channel's Buzz cursor while the connector is down
    Cursor(CursorArgs),
}

#[derive(clap::Parser, Debug)]
pub struct StatusArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct ReadArgs {
    /// Channel slug, `ch_<slug>`, or channel id
    pub channel: String,
    /// Only this Buzz thread root
    #[arg(long)]
    pub thread: Option<String>,
    /// How many events (default: 20)
    #[arg(long, default_value_t = 20)]
    pub limit: usize,
    /// Continue before this Buzz event id
    #[arg(long)]
    pub before: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct QueryArgs {
    /// hcom name of a configured local signer
    #[arg(long)]
    pub as_name: String,
    /// Relay filter JSON
    #[arg(long)]
    pub filter: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct MembersArgs {
    pub channel: String,
    #[arg(long)]
    pub as_name: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct PrepareArgs {
    #[arg(long)]
    pub as_name: String,
    /// Channel row (`ch_warehouse`) or slug
    #[arg(long)]
    pub channel: String,
    /// Pubkey to p-tag, repeatable
    #[arg(long = "p")]
    pub mentions: Vec<String>,
    /// The reservation's own created_at, so the root id is stable
    #[arg(long)]
    pub created_at: u64,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct PublishArgs {
    #[arg(long)]
    pub as_name: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct IdentityArgs {
    #[arg(long)]
    pub as_name: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Parser, Debug)]
pub struct CursorArgs {
    #[command(subcommand)]
    pub cmd: CursorSubcmd,
}

#[derive(clap::Subcommand, Debug)]
pub enum CursorSubcmd {
    /// Seed where a channel's backfill starts, before the connector's first run
    Set(CursorSetArgs),
}

#[derive(clap::Parser, Debug)]
pub struct CursorSetArgs {
    /// Channel slug or `ch_<slug>`
    pub channel: String,
    /// Unix seconds: the newest Buzz event already handled elsewhere
    #[arg(long)]
    pub since: u64,
    /// Allow moving an existing cursor backwards (replays history)
    #[arg(long)]
    pub force: bool,
}

/// Entry point from the router.
pub fn cmd_buzz(db: &HcomDb, args: &BuzzArgs, _ctx: Option<&crate::shared::CommandContext>) -> i32 {
    match &args.cmd {
        BuzzSubcmd::Serve => match cmd_serve(args) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("Error: {error}");
                1
            }
        },
        BuzzSubcmd::Status(sub) => cmd_status(db, sub),
        BuzzSubcmd::Read(sub) => cmd_read(db, sub),
        BuzzSubcmd::Down => cmd_down(db),
        BuzzSubcmd::Query(sub) => cmd_query(sub),
        BuzzSubcmd::Members(sub) => cmd_members(sub),
        BuzzSubcmd::Prepare(sub) => cmd_prepare(sub),
        BuzzSubcmd::Publish(sub) => cmd_publish(sub),
        BuzzSubcmd::Identity(sub) => report(run_identity(sub)),
        BuzzSubcmd::Cursor(sub) => match &sub.cmd {
            CursorSubcmd::Set(set) => report(run_cursor_set(set)),
        },
    }
}

/// Exit code for a subcommand: errors are printed, never panicked.
fn report(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn cmd_serve(_args: &BuzzArgs) -> Result<i32> {
    let config = Config::load()?;
    crate::buzz::serve::serve(config)
}

/// Connector state, read straight from `state.db`.
fn cmd_status(db: &HcomDb, args: &StatusArgs) -> i32 {
    let path = Config::state_db_path();
    let store = match Store::open_read_only(&path) {
        Ok(store) => store,
        Err(error) => {
            if args.json {
                println!("{}", json!({"error": error.to_string(), "running": false}));
            } else {
                println!("connector: not running ({error})");
            }
            return 1;
        }
    };

    let running = ServeLock::holder_pid(&Config::lock_path())
        .is_some_and(crate::buzz::config::lock_holder_alive);
    let mut channels = Vec::new();
    let mut parked = Vec::new();
    if let Ok(rows) = store.channels() {
        for row in rows {
            if row.parked_reason.is_some() {
                parked.push(json!({
                    "channel": row.slug,
                    "id": row.id,
                    "reason": row.parked_reason,
                }));
            } else {
                channels.push(json!({
                    "channel": row.slug,
                    "id": row.id,
                    "cursor": row.cursor_created_at,
                }));
            }
        }
    }
    let outbox = store.outbox_counts().unwrap_or_default();
    let pending = outbox
        .iter()
        .find(|(state, _)| state == "pending")
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let retrying = outbox
        .iter()
        .find(|(state, _)| state == "retry")
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let failed = outbox
        .iter()
        .find(|(state, _)| state == "failed")
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let parked_targets = store
        .target_counts()
        .unwrap_or_default()
        .iter()
        .find(|(state, _)| state == "parked")
        .map(|(_, count)| *count)
        .unwrap_or(0);
    let people = store.people().unwrap_or_default();
    let enrolled = store.enrolled_count().unwrap_or(0);
    let errors = store.recent_errors(5).unwrap_or_default();

    // Whether a hosted row exists locally for each mirrored `ch_*` row, which is
    // what `read` uses to find the origin device.
    let local_mirrors: Vec<String> = hosted_channel_rows(db);

    if args.json {
        println!(
            "{}",
            json!({
                "running": running,
                "channels": channels,
                "parked": parked,
                "outbox": {"pending": pending, "retry": retrying, "failed": failed},
                "parked_targets": parked_targets,
                "people": people.len(),
                "people_active": people.iter().filter(|p| p.active).count(),
                "enrolled": enrolled,
                "origin_devices": local_mirrors,
                "errors": errors.iter().map(|(destination, id, error)| json!({
                    "destination": destination,
                    "hcom_event": id,
                    "error": error,
                })).collect::<Vec<_>>(),
            })
        );
        return 0;
    }

    println!("connector: {}", if running { "running" } else { "stopped" });
    println!("channels:  {}", channels.len());
    for row in &channels {
        println!(
            "  {} {} cursor={}",
            row["channel"].as_str().unwrap_or_default(),
            row["id"].as_str().unwrap_or_default(),
            row["cursor"]
        );
    }
    if !parked.is_empty() {
        println!("parked:    {}", parked.len());
        for row in &parked {
            println!(
                "  {} {} ({})",
                row["channel"].as_str().unwrap_or_default(),
                row["id"].as_str().unwrap_or_default(),
                row["reason"].as_str().unwrap_or_default()
            );
        }
    }
    println!(
        "outbox:    {pending} pending, {retrying} retrying, {failed} failed, {parked_targets} parked targets"
    );
    println!(
        "people:    {} ({} active)",
        people.len(),
        people.iter().filter(|p| p.active).count()
    );
    println!("enrolled:  {enrolled}");
    if !errors.is_empty() {
        println!("last errors:");
        for (destination, id, error) in &errors {
            println!("  #{id} -> {destination}: {error}");
        }
    }
    0
}

/// Hosted channel rows published by *this* device; the origin for `read` on a
/// device without connector state.
fn hosted_channel_rows(db: &HcomDb) -> Vec<String> {
    let sql = "SELECT name, origin_device_id FROM instances
         WHERE tool = ?1 AND COALESCE(origin_device_id, '') = ''
         ORDER BY name";
    let Ok(mut stmt) = db.conn().prepare(sql) else {
        return Vec::new();
    };
    let Ok(rows) = stmt.query_map(rusqlite::params![crate::hosted::HOSTED_TOOL_BUZZ], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) else {
        return Vec::new();
    };
    rows.filter_map(std::result::Result::ok)
        .filter(|(_, origin)| origin.as_deref().unwrap_or("").is_empty())
        .map(|(name, _)| name)
        .collect()
}

/// `hcom buzz read <channel>`: the local cache, or the connector host's over RPC.
fn cmd_read(db: &HcomDb, args: &ReadArgs) -> i32 {
    let local = Config::state_db_path();
    // Answer from this device's cache; otherwise ask the connector host over
    // the `buzz_read` RPC, addressed by the `ch_*` mirror row's short id.
    let answer = if local.exists() {
        resolve_channel(&args.channel).and_then(|(channel_id, slug)| {
            let store = Store::open_read_only(&local)?;
            let events: Vec<Value> = store
                .list_events(
                    Some(&channel_id),
                    args.thread.as_deref(),
                    args.before.as_deref(),
                    args.limit,
                )?
                .iter()
                .map(event_json)
                .collect();
            Ok(json!({"channel": slug, "channel_id": channel_id, "events": events}))
        })
    } else {
        remote_read(db, args)
    };
    let answer = match answer {
        Ok(answer) => answer,
        Err(error) => {
            eprintln!("Error: {error}");
            return 1;
        }
    };

    if args.json {
        println!("{answer}");
        return 0;
    }
    let slug = answer["channel"].as_str().unwrap_or(&args.channel);
    let events = answer["events"].as_array().cloned().unwrap_or_default();
    if events.is_empty() {
        println!("no cached Buzz events for {slug}");
        return 0;
    }
    println!("{slug}: {} event(s)", events.len());
    for event in &events {
        let id = event["id"].as_str().unwrap_or_default();
        let author = event["author"].as_str().unwrap_or_default();
        let text = event["text"].as_str().unwrap_or_default();
        let created = event["created_at"].as_u64().unwrap_or_default();
        let reply = event["root_id"].as_str().unwrap_or("-");
        println!("[{created}] {author} (thread {reply}): {text}\n  {id}");
    }
    if answer["truncated"] == json!(true) {
        println!(
            "(more: continue with --before {})",
            events
                .last()
                .and_then(|e| e["id"].as_str())
                .unwrap_or_default()
        );
    }
    0
}

/// Ask the connector host for its cache, over the `buzz_read` RPC.
fn remote_read(db: &HcomDb, args: &ReadArgs) -> Result<Value> {
    let (row, short) = mirror_channel_row(db, &args.channel)?;
    let slug = args.channel.strip_prefix("ch_").unwrap_or(&args.channel);
    let params = json!({
        "channel": slug,
        "thread": args.thread,
        "limit": args.limit,
        "before": args.before,
    });
    dispatch_remote(
        db,
        &short,
        Some(&row),
        rpc_action::BUZZ_READ,
        &params,
        RPC_DEFAULT_TIMEOUT,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))
}

/// The mirror of a bridged channel's row on this device: `ch_<slug>:SHORT`,
/// and the short id of the connector host that publishes it. A device without
/// connector state knows a channel only through this row.
fn mirror_channel_row(db: &HcomDb, channel: &str) -> Result<(String, String)> {
    let slug = channel.strip_prefix("ch_").unwrap_or(channel);
    let wanted = format!("ch_{slug}");
    let mut stmt = db.conn().prepare(
        "SELECT name FROM instances
         WHERE tool = ?1 AND COALESCE(origin_device_id, '') != ''
         ORDER BY name",
    )?;
    let rows: Vec<String> = stmt
        .query_map(rusqlite::params![crate::hosted::HOSTED_TOOL_BUZZ], |row| {
            row.get(0)
        })?
        .filter_map(std::result::Result::ok)
        .collect();
    rows.into_iter()
        .find_map(|name| {
            let (base, short) = crate::relay::control::split_device_suffix(&name)?;
            (base == wanted).then(|| (name.clone(), short.to_string()))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no device here mirrors {wanted}: is this device in the connector's relay group?"
            )
        })
}

/// Resolve a channel argument to `(channel_id, slug)`.
fn resolve_channel(arg: &str) -> Result<(String, String)> {
    if let Ok(config) = Config::load()
        && let Some(channel) = config.channel_by_slug(arg)
    {
        return Ok((
            channel.id.clone(),
            channel.slug.clone().unwrap_or_else(|| channel.id.clone()),
        ));
    }
    // Otherwise treat it as a channel id; the store knows the slug.
    if let Ok(store) = Store::open_read_only(&Config::state_db_path())
        && let Ok(Some(row)) = store.channel(arg)
    {
        return Ok((row.id, row.slug));
    }
    bail!("unknown channel '{arg}': name a slug, a ch_ row, or a channel id")
}

fn event_json(event: &store::CachedEvent) -> Value {
    let content = serde_json::from_str::<Value>(&event.json)
        .ok()
        .and_then(|value| {
            value
                .get("content")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    json!({
        "id": event.buzz_id,
        "channel_id": event.channel_id,
        "kind": event.kind,
        "author": event.author,
        "created_at": event.created_at,
        "root_id": event.root_id,
        "parent_id": event.parent_id,
        "text": content,
    })
}

/// `hcom buzz down`: drain the outbox, stop the process, stop the rows.
fn cmd_down(db: &HcomDb) -> i32 {
    let path = Config::state_db_path();
    if !path.exists() {
        println!("connector is not installed here");
        let _ = crate::hosted::stop_hosted(db, crate::hosted::HOSTED_TOOL_BUZZ);
        return 0;
    }

    // 1. Wait for the outbox to drain, bounded, printing anything still owed.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let leftovers = match Store::open_read_only(&path) {
            Ok(store) => store.unsent_outbox().unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        let posting = leftovers
            .iter()
            .any(|row| row.state == "pending" || row.state == "retry");
        if !posting {
            for row in &leftovers {
                println!(
                    "unposted: {} #{} -> {} ({})",
                    row.signer_name, row.hcom_id, row.destination, row.state
                );
            }
            break;
        }
        if Instant::now() >= deadline {
            println!("outbox still posting after 60s; stopping anyway");
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    // 2. Stop the serve process, politely first.
    let lock = Config::lock_path();
    match ServeLock::holder_pid(&lock) {
        Some(pid) => {
            println!("stopping hcom buzz serve (pid {pid})");
            terminate(pid);
            let wait_until = Instant::now() + Duration::from_secs(10);
            while Instant::now() < wait_until {
                if !crate::buzz::config::lock_holder_alive(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        None => println!("hcom buzz serve is not running"),
    }

    // 3. Rollback: hosted rows go `stopped`, so senders get a clear refusal
    //    instead of queueing into nothing.
    match crate::hosted::stop_hosted(db, crate::hosted::HOSTED_TOOL_BUZZ) {
        Ok(count) => {
            println!("stopped {count} Buzz-hosted row(s)");
            0
        }
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

/// Ask a pid to exit, then insist.
fn terminate(pid: u32) {
    #[cfg(unix)]
    {
        let sent = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) == 0 };
        if sent {
            return;
        }
        let _ = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
}

// ── mbai-local Q&A transport ───────────────────────────────────────────

/// Load the config and connector, refusing any signer this device may not use.
fn load_local_signer(name: &str) -> Result<Connector> {
    let config = Config::load()?;
    if !config.is_local_signer(name) {
        bail!(
            "'{name}' is not a local signer; only {} may sign from this device (see local_signers in {})",
            Config::load()
                .map(|c| c.local_signers.join(", "))
                .unwrap_or_default(),
            Config::path().display()
        );
    }
    Connector::load(config)
}

fn cmd_query(args: &QueryArgs) -> i32 {
    match run_query(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn run_query(args: &QueryArgs) -> Result<()> {
    let connector = load_local_signer(&args.as_name)?;
    let identity = connector.agent_identity(&args.as_name);
    // An unscoped filter is refused by the relay, so kinds always ride along.
    let mut filter: Value = serde_json::from_str(&args.filter)
        .map_err(|e| anyhow::anyhow!("--filter must be JSON: {e}"))?;
    let object = filter
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("--filter must be a JSON object"))?;
    object
        .entry("kinds")
        .or_insert_with(|| json!(store::CHANNEL_KINDS));
    let auth = connector.reader_auth_tag_for(&identity.pubkey);
    let events = connector.http.query(&filter, &identity.key, Some(&auth))?;
    if args.json {
        println!("{}", json!({"events": events}));
    } else {
        for event in &events {
            println!("{} {} {}", event.created_at, event.pubkey, event.content);
        }
    }
    Ok(())
}

fn cmd_members(args: &MembersArgs) -> i32 {
    match run_members(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn run_members(args: &MembersArgs) -> Result<()> {
    let connector = load_local_signer(&args.as_name)?;
    let (channel_id, slug) = resolve_channel(&args.channel)?;
    let identity = connector.agent_identity(&args.as_name);
    let roster: Vec<Value> = channel_members(&connector, &identity, &channel_id)?
        .into_iter()
        .map(|(pubkey, role)| json!({"pubkey": pubkey, "role": role}))
        .collect();
    if args.json {
        println!(
            "{}",
            json!({"channel": slug, "channel_id": channel_id, "members": roster})
        );
    } else {
        for member in &roster {
            println!(
                "{} {}",
                member["pubkey"].as_str().unwrap_or_default(),
                member["role"].as_str().unwrap_or_default()
            );
        }
    }
    Ok(())
}

/// A channel's members from its 39002 roster. Rosters are signed by the
/// relay, not omp, so they are found by `d` = channel id, and the relay may
/// return several revisions: the newest wins.
fn channel_members(
    connector: &Connector,
    identity: &AgentIdentity,
    channel_id: &str,
) -> Result<Vec<(String, String)>> {
    let auth = connector.reader_auth_tag_for(&identity.pubkey);
    let filter = json!({ "kinds": [route::KIND_ROSTER], "#d": [channel_id] });
    let events = connector.http.query(&filter, &identity.key, Some(&auth))?;
    Ok(events
        .into_iter()
        .filter(|event| route::tag(event, "d") == Some(channel_id))
        .max_by_key(|event| event.created_at)
        .map(|event| route::roster_members(&event))
        .unwrap_or_default())
}

/// `hcom buzz identity --as-name <n>`: who a local signer is on Buzz, without
/// signing anything.
fn run_identity(args: &IdentityArgs) -> Result<()> {
    let connector = load_local_signer(&args.as_name)?;
    let identity = identity_json(&connector, &args.as_name);
    if args.json {
        println!("{identity}");
    } else {
        println!(
            "{} {}",
            identity["name"].as_str().unwrap_or_default(),
            identity["pubkey"].as_str().unwrap_or_default()
        );
    }
    Ok(())
}

fn identity_json(connector: &Connector, name: &str) -> Value {
    json!({"name": name, "pubkey": connector.agent_identity(name).pubkey})
}

/// `hcom buzz cursor set <slug> --since <unix>`: seed where a channel's
/// backfill starts. Only while the connector is down, so nothing races it.
fn run_cursor_set(args: &CursorSetArgs) -> Result<()> {
    if ServeLock::holder_pid(&Config::lock_path())
        .is_some_and(crate::buzz::config::lock_holder_alive)
    {
        bail!("hcom buzz serve is running; stop it (hcom buzz down) before moving a cursor");
    }
    let config = Config::load()?;
    let channel = config.channel_by_slug(&args.channel).ok_or_else(|| {
        anyhow::anyhow!("'{}' is not a bridged channel in the config", args.channel)
    })?;
    let slug = channel.slug.clone().unwrap_or_else(|| channel.id.clone());
    let store = Store::open(&Config::state_db_path())?;
    set_cursor(&store, &channel.id, &slug, args.since, args.force)?;
    println!("{slug}: cursor at {}", args.since);
    Ok(())
}

/// Seed one channel's cursor. Moving it back would replay history into hcom,
/// so that takes `force`.
fn set_cursor(store: &Store, channel_id: &str, slug: &str, since: u64, force: bool) -> Result<()> {
    store.upsert_channel(channel_id, slug)?;
    let current = store
        .channel(channel_id)?
        .and_then(|row| row.cursor_created_at);
    if let Some(current) = current
        && since < current
        && !force
    {
        bail!(
            "{slug}'s cursor is already at {current}; moving it back to {since} replays history (use --force)"
        );
    }
    store.force_channel_cursor(channel_id, since)
}

fn cmd_prepare(args: &PrepareArgs) -> i32 {
    match run_prepare(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn run_prepare(args: &PrepareArgs) -> Result<()> {
    let connector = load_local_signer(&args.as_name)?;

    let (channel_id, _) = resolve_channel(&args.channel)?;
    let content = read_stdin()?;
    let identity = connector.agent_identity(&args.as_name);
    let event = sign(
        UnsignedEvent {
            created_at: args.created_at,
            kind: route::KIND_MESSAGE,
            tags: {
                let mut tags = vec![vec!["h".into(), channel_id]];
                for mention in &args.mentions {
                    tags.push(vec!["p".into(), mention.clone()]);
                }
                tags
            },
            content,
        },
        &identity.key,
    );
    // Nothing is sent: the Q&A layer stores this exact event and its root id.
    println!("{}", serde_json::to_string(&event)?);
    Ok(())
}

fn cmd_publish(args: &PublishArgs) -> i32 {
    match run_publish(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("Error: {error}");
            1
        }
    }
}

fn run_publish(args: &PublishArgs) -> Result<()> {
    let connector = load_local_signer(&args.as_name)?;
    let raw = read_stdin()?;
    let event: Event = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("stdin is not a signed event: {e}"))?;
    publish_signed(&connector, &args.as_name, &event)?;
    if args.json {
        println!("{}", json!({"published": true, "id": event.id}));
    } else {
        println!("published {}", event.id);
    }
    Ok(())
}

/// Post a signed event as `name`, enrolling first if needed, and confirm by
/// id. Idempotent: a re-publish of the same event is a confirmation.
fn publish_signed(connector: &Connector, name: &str, event: &Event) -> Result<()> {
    if !nostr::verify(event) {
        bail!("stdin event fails signature verification");
    }
    let identity = connector.agent_identity(name);
    if event.pubkey != identity.pubkey {
        bail!(
            "stdin event is signed by {}, not by the '{name}' identity",
            event.pubkey
        );
    }
    let Some(channel_id) = route::tag(event, "h") else {
        bail!("stdin event carries no h tag");
    };
    ensure_publish_enrolled(connector, &identity, channel_id)?;

    let auth = connector.reader_auth_tag_for(&identity.pubkey);
    match connector.http.post_event(event, &identity.key, Some(&auth)) {
        Ok(()) => {}
        Err(PublishError::Rejected(message)) if message.starts_with("duplicate:") => {}
        Err(error) => return Err(anyhow::anyhow!("{error}")),
    }

    // Confirm by id, so an abandoned publish can never look published.
    let filter = json!({ "ids": [event.id.clone()], "kinds": store::CHANNEL_KINDS });
    let confirmed = connector
        .http
        .query(&filter, &identity.key, Some(&auth))?
        .iter()
        .any(|found| found.id == event.id);
    if !confirmed {
        bail!("relay did not return {} after accepting it", event.id);
    }
    Ok(())
}

/// Enroll a local signer in a channel unless the shared state already says
/// it is: the agent's kind 0 under its own key, omp's 30177 and 9000 under
/// omp's key (the relay requires author == signer). Recorded in `state.db`
/// the same way `serve` records its own enrollments.
fn ensure_publish_enrolled(
    connector: &Connector,
    identity: &AgentIdentity,
    channel_id: &str,
) -> Result<()> {
    if connector
        .store
        .lock()
        .enrollment(&identity.pubkey, channel_id)?
        .as_deref()
        == Some("enrolled")
    {
        return Ok(());
    }
    let tag = connector.reader_auth_tag_for(&identity.pubkey);
    connector.http.post_event(
        &identity.profile_event(&connector.owner),
        &identity.key,
        Some(&tag),
    )?;
    for event in [
        identity.managed_agent_event(&connector.owner),
        identity.add_member_event(&connector.owner, channel_id),
    ] {
        connector.http.post_event(&event, &connector.owner, None)?;
    }
    let store = connector.store.lock();
    store.put_enrollment(&identity.pubkey, channel_id, "enrolled")?;
    store.put_author(&store::Author {
        pubkey: identity.pubkey.clone(),
        kind: store::AuthorKind::Agent,
        hcom_name: Some(identity.row.clone()),
        device_label: identity
            .canonical
            .rsplit_once('@')
            .map(|(_, device)| device.to_string()),
    })?;
    Ok(())
}

fn read_stdin() -> Result<String> {
    use std::io::Read;
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .context("cannot read stdin")?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buzz::nostr::{SecretKey, derive_secret, public_hex};
    use crate::buzz::testing::{FakeRelay, connector_config};
    use serial_test::serial;

    const SEED: [u8; 32] = [11; 32];
    const CHANNEL: &str = "33333333-4444-5555-6666-777777888899";

    /// An isolated HCOM_DIR and a connector aimed at a fake relay. The guard
    /// and dir must outlive the test.
    fn setup() -> (
        (
            tempfile::TempDir,
            std::path::PathBuf,
            std::path::PathBuf,
            crate::hooks::test_helpers::EnvGuard,
        ),
        FakeRelay,
        Connector,
    ) {
        let env = crate::hooks::test_helpers::isolated_test_env();
        let relay = FakeRelay::http();
        let connector =
            Connector::load(connector_config(&relay, "mbai", &SEED, CHANNEL, "infra")).unwrap();
        (env, relay, connector)
    }

    fn roster(relay_key: &SecretKey, created_at: u64, channel: &str, member: &str) -> Event {
        sign(
            UnsignedEvent {
                created_at,
                kind: route::KIND_ROSTER,
                tags: vec![
                    vec!["d".into(), channel.into()],
                    vec!["p".into(), member.into(), String::new(), "member".into()],
                ],
                content: String::new(),
            },
            relay_key,
        )
    }

    #[test]
    #[serial]
    fn identity_names_the_signer_and_signs_nothing() {
        let (_env, relay, connector) = setup();
        let before = relay.http_requests();
        let identity = identity_json(&connector, "qa");
        assert_eq!(identity["name"], "qa");
        assert_eq!(
            identity["pubkey"],
            public_hex(&derive_secret(&SEED, "qa@mbai")),
            "the same key the connector derives for qa"
        );
        assert_eq!(relay.http_requests(), before, "no relay traffic");
    }

    #[test]
    #[serial]
    fn members_come_from_the_newest_relay_signed_roster() {
        let (_env, relay, connector) = setup();
        // Relay-signed, as deployed: never omp's key.
        let relay_key = derive_secret(&SEED, "relay@test");
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        relay.seed(roster(&relay_key, 1_000, CHANNEL, &old));
        relay.seed(roster(&relay_key, 2_000, CHANNEL, &new));
        relay.seed(roster(&relay_key, 3_000, "other-channel", &"c".repeat(64)));

        let identity = connector.agent_identity("qa");
        assert_eq!(
            channel_members(&connector, &identity, CHANNEL).unwrap(),
            vec![(new, "member".to_string())]
        );
    }

    #[test]
    #[serial]
    fn publish_enrolls_once_with_omps_own_signature_on_the_policy() {
        let (_env, relay, connector) = setup();
        let identity = connector.agent_identity("qa");
        let post = |text: &str| {
            sign(
                UnsignedEvent {
                    created_at: nostr::now(),
                    kind: route::KIND_MESSAGE,
                    tags: vec![vec!["h".into(), CHANNEL.into()]],
                    content: text.into(),
                },
                &identity.key,
            )
        };
        publish_signed(&connector, "qa", &post("first")).unwrap();
        let owner = public_hex(&connector.owner);
        let policy: Vec<Event> = relay
            .events()
            .into_iter()
            .filter(|e| e.kind == 30177)
            .collect();
        assert_eq!(policy.len(), 1);
        assert_eq!(
            policy[0].pubkey, owner,
            "omp signs the managed-agent policy"
        );

        // The relay dedupes identical enrollment events, so stored events
        // can't show a repeat; the request count can. A cached enrollment
        // costs exactly the post and its confirming lookup.
        let before = relay.http_requests();
        publish_signed(&connector, "qa", &post("second")).unwrap();
        assert_eq!(
            relay.http_requests() - before,
            2,
            "the second publish reuses the enrollment"
        );
        assert_eq!(
            relay
                .events()
                .iter()
                .filter(|e| e.kind == route::KIND_MESSAGE)
                .count(),
            2
        );
    }

    #[test]
    #[serial]
    fn a_seeded_cursor_never_moves_back_without_force() {
        let (_env, _relay, connector) = setup();
        let store = connector.store.lock();
        set_cursor(&store, CHANNEL, "infra", 5_000, false).unwrap();
        assert!(
            set_cursor(&store, CHANNEL, "infra", 6_000, false).is_ok(),
            "forward is fine"
        );
        let refused = set_cursor(&store, CHANNEL, "infra", 4_000, false).unwrap_err();
        assert!(refused.to_string().contains("--force"), "{refused}");
        assert_eq!(
            store.channel(CHANNEL).unwrap().unwrap().cursor_created_at,
            Some(6_000)
        );
        set_cursor(&store, CHANNEL, "infra", 4_000, true).unwrap();
        assert_eq!(
            store.channel(CHANNEL).unwrap().unwrap().cursor_created_at,
            Some(4_000)
        );
    }

    #[test]
    #[serial]
    fn a_device_without_connector_state_reads_through_the_mirror_row() {
        let (_env, _relay, _connector) = setup();
        let db = HcomDb::open().unwrap();
        let now = crate::shared::time::now_epoch_i64();
        let mirror = json!({
            "name": "ch_infra:BOXE", "tool": crate::hosted::HOSTED_TOOL_BUZZ,
            "status": "listening", "status_time": now, "status_context": "buzz:online",
            "last_stop": now, "tcp_mode": 1, "last_event_id": 0,
            "origin_device_id": "9f2c-boxe-device-uuid", "directory": "",
            "transcript_path": "", "background": 0, "name_announced": 0,
            "created_at": crate::shared::time::now_epoch_f64(),
        });
        db.save_instance_named("ch_infra:BOXE", mirror.as_object().unwrap())
            .unwrap();

        let expected = ("ch_infra:BOXE".to_string(), "BOXE".to_string());
        assert_eq!(mirror_channel_row(&db, "infra").unwrap(), expected);
        assert_eq!(mirror_channel_row(&db, "ch_infra").unwrap(), expected);
        assert!(mirror_channel_row(&db, "warehouse").is_err());
    }
}
