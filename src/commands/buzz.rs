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
use crate::buzz::serve::{Connector, ServeLock};
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
        .is_some_and(|pid| crate::buzz::config::lock_holder_alive(pid));
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
    let sql = format!(
        "SELECT name, origin_device_id FROM instances
         WHERE tool = ?1 AND COALESCE(origin_device_id, '') = ''
         ORDER BY name"
    );
    let Ok(mut stmt) = db.conn().prepare(&sql) else {
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
    let (channel_id, channel_slug) = match resolve_channel(&args.channel) {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("Error: {error}");
            return 1;
        }
    };

    let local = Config::state_db_path();
    // Answer from this device's cache; otherwise ask the connector host over
    // the `buzz_read` RPC, addressed by the `ch_*` row's origin short id.
    let events = if local.exists() {
        match Store::open_read_only(&local).and_then(|store| {
            Ok(store
                .list_events(
                    Some(&channel_id),
                    args.thread.as_deref(),
                    args.before.as_deref(),
                    args.limit,
                )?
                .iter()
                .map(event_json)
                .collect())
        }) {
            Ok(events) => events,
            Err(error) => {
                eprintln!("Error: {error}");
                return 1;
            }
        }
    } else {
        match remote_read(db, &channel_id, args) {
            Ok(events) => events,
            Err(error) => {
                eprintln!("Error: {error}");
                return 1;
            }
        }
    };

    if args.json {
        println!(
            "{}",
            json!({"channel": channel_slug, "channel_id": channel_id, "events": events})
        );
        return 0;
    }
    if events.is_empty() {
        println!("no cached Buzz events for {channel_slug}");
        return 0;
    }
    println!("{channel_slug}: {} event(s)", events.len());
    for event in &events {
        let id = event["id"].as_str().unwrap_or_default();
        let author = event["author_name"]
            .as_str()
            .unwrap_or_else(|| event["author"].as_str().unwrap_or_default());
        let text = event["text"].as_str().unwrap_or_default();
        let created = event["created_at"].as_u64().unwrap_or_default();
        let reply = event["root_id"].as_str().unwrap_or("-");
        println!("[{created}] {author} (thread {reply}): {text}\n  {id}");
    }
    0
}

/// Ask the connector host for its cache, over the `buzz_read` RPC.
fn remote_read(db: &HcomDb, channel_id: &str, args: &ReadArgs) -> Result<Vec<Value>> {
    let device = origin_device_of(db, channel_id)?;
    let params = json!({
        "channel_id": channel_id,
        "thread": args.thread,
        "limit": args.limit,
        "before": args.before,
    });
    let result = dispatch_remote(
        db,
        &device,
        Some(&format!("ch_{channel_id}")),
        rpc_action::BUZZ_READ,
        &params,
        RPC_DEFAULT_TIMEOUT,
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(result["events"].as_array().cloned().unwrap_or_default())
}

/// The short id of the device that publishes this channel's `ch_*` row.
fn origin_device_of(db: &HcomDb, channel_id: &str) -> Result<String> {
    let row: Option<String> = db
        .conn()
        .query_row(
            "SELECT origin_device_id FROM instances
             WHERE name = ?1 AND tool = ?2 AND COALESCE(origin_device_id, '') != ''",
            rusqlite::params![format!("ch_{channel_id}"), crate::hosted::HOSTED_TOOL_BUZZ],
            |row| row.get(0),
        )
        .ok();
    let Some(device) = row else {
        bail!(
            "no connector host publishes this channel here — is the connector running on this device?"
        );
    };
    Ok(crate::relay::control::split_device_suffix(&device)
        .map(|(_, short)| short.to_string())
        .unwrap_or(device))
}

/// Resolve a channel argument to `(channel_id, slug)`.
fn resolve_channel(arg: &str) -> Result<(String, String)> {
    if let Ok(config) = Config::load() {
        if let Some(channel) = config.channel_by_slug(arg) {
            return Ok((
                channel.id.clone(),
                channel.slug.clone().unwrap_or_else(|| channel.id.clone()),
            ));
        }
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
    let auth = connector.reader_auth_tag_for(&identity.pubkey);
    // A 39002 roster is relay-signed, so query by kind rather than by channel
    // tag: the discovery events carry `d`, not `h`.
    let filter =
        json!({ "kinds": [route::KIND_ROSTER], "authors": [connector.owner_pubkey.clone()] });
    let events = connector.http.query(&filter, &identity.key, Some(&auth))?;
    let roster = events
        .into_iter()
        .find(|event| route::tag(event, "d") == Some(channel_id.as_str()))
        .map(|event| {
            route::roster_members(&event)
                .into_iter()
                .map(|(pubkey, role)| json!({"pubkey": pubkey, "role": role}))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
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
    if !nostr::verify(&event) {
        bail!("stdin event fails signature verification");
    }
    let identity = connector.agent_identity(&args.as_name);
    if event.pubkey != identity.pubkey {
        bail!(
            "stdin event is signed by {}, not by the '{}' identity",
            event.pubkey,
            args.as_name
        );
    }
    let Some(channel_id) = route::tag(&event, "h") else {
        bail!("stdin event carries no h tag");
    };
    let auth = connector.reader_auth_tag_for(&identity.pubkey);

    // Enroll if needed: kind 0 + 30177 as the signer, 9000 as omp.
    if !publish_enroll(&connector, &identity, &channel_id)? {
        bail!(
            "could not enroll {args_name} in {channel_id}",
            args_name = args.as_name
        );
    }

    match connector
        .http
        .post_event(&event, &identity.key, Some(&auth))
    {
        Ok(()) => {}
        Err(PublishError::Rejected(message)) if message.starts_with("duplicate:") => {
            // Idempotent by event id: a re-publish is a confirmation.
        }
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
    if args.json {
        println!("{}", json!({"published": true, "id": event.id}));
    } else {
        println!("published {}", event.id);
    }
    Ok(())
}

/// The kind 0 / 30177 / 9000 sequence `publish` needs before a post lands.
fn publish_enroll(
    connector: &Connector,
    identity: &crate::buzz::serve::AgentIdentity,
    channel_id: &str,
) -> Result<bool> {
    let auth = connector.reader_auth_tag_for(&identity.pubkey);
    let tag = auth.clone();
    for event in [
        identity
            .publish_profile_event(&connector.owner)
            .context("cannot build the profile event")?,
        identity
            .publish_managed_agent_event(&connector.owner)
            .context("cannot build the managed-agent event")?,
    ] {
        connector
            .http
            .post_event(&event, &identity.key, Some(&tag))?;
    }
    // Membership is omp's act, signed with omp's key and no delegation.
    let member = sign(
        UnsignedEvent {
            created_at: nostr::now(),
            kind: 9000,
            tags: route::add_member_tags(channel_id, &identity.pubkey),
            content: String::new(),
        },
        &connector.owner,
    );
    connector.http.post_event(&member, &connector.owner, None)?;
    Ok(true)
}

fn read_stdin() -> Result<String> {
    use std::io::Read;
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .context("cannot read stdin")?;
    Ok(buffer)
}
