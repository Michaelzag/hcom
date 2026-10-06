//! The connector process: one long-lived hcom participant host.
//!
//! Composition root and loops. Composition: config, keys, the lock, both
//! databases, hosted rows and one shared notify endpoint. Loops: a reader
//! thread holding the channel subscriptions, and a main loop that owns both
//! databases, delivers inbound traffic and drains the outbox.
//!
//! Nothing here exits the process because the relay misbehaved. Only config and
//! key load failures at startup, and a lock held by a live process, return an
//! error.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::buzz::config::{self, Config};
use crate::buzz::nostr::{self, Event, SecretKey, UnsignedEvent, auth_tag, public_hex, sign};
use crate::buzz::relay::{HttpRelay, PublishError, RelayMsg, WsSession};
use crate::buzz::route::{self, AgentRoster, Ancestor, ChannelRow, InboundEvent, PersonRow};
use crate::buzz::store::{self, Author, AuthorKind, OutboxRow, Store};
use crate::db::HcomDb;

/// Backstop wake when no notify endpoint fires.
const TICK: Duration = Duration::from_secs(5);
/// How often the enrollment planner runs.
const ENROLL_INTERVAL: Duration = Duration::from_secs(60);
/// How long an agent's hcom row must be gone before it leaves Buzz channels.
const ENROLL_STALE_SECS: i64 = 3600;
/// How long a person stays registered after leaving every bridged channel.
const PERSON_RETIRE_SECS: i64 = 24 * 3600;
/// Reconnect backoff bounds for the reader.
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Gap between REQs, so one reconnect never spends the WS frame budget at once.
const REQ_STAGGER: Duration = Duration::from_millis(700);
/// How long an unresolvable inbound target keeps being retried.
const PARK_WINDOW: Duration = Duration::from_secs(15 * 60);
/// HTTP calls per signing key per minute (the relay allows 300).
pub const HTTP_PER_MINUTE: usize = 240;
/// WS frames per 5 s window (the relay allows 50).
pub const WS_FRAMES_PER_WINDOW: usize = 40;
/// Connect/read timeout for the reader session.
const WS_TIMEOUT: Duration = Duration::from_secs(10);
/// Post retry backoff bounds.
const POST_BACKOFF_MIN: Duration = Duration::from_secs(1);
const POST_BACKOFF_MAX: Duration = Duration::from_secs(60);
/// An outbox entry older than this is looked up by id before a re-send.
const STALE_RECHECK_AFTER: Duration = Duration::from_secs(store::STALE_OUTBOX_SECS);

/// A signing key and its identity.
#[derive(Clone)]
pub struct AgentIdentity {
    /// The hcom name, without any device suffix (the profile's `name`).
    pub name: String,
    /// The hcom row this identity speaks for, as this device addresses it:
    /// `luna` locally, `luna:BOXE` for a mirror. Routing, the outbox and the
    /// author cache all use this, so a mirror is never confused with a local
    /// row of the same base name.
    pub row: String,
    /// `name@device`, the derivation input.
    pub canonical: String,
    pub pubkey: String,
    pub key: SecretKey,
    /// True for a mirror row from another device (`luna:BOXE`).
    pub remote: bool,
}

/// Everything the connector owns after startup.
pub struct Connector {
    pub config: Config,
    pub seed: [u8; 32],
    pub owner: SecretKey,
    pub owner_pubkey: String,
    pub reader: AgentIdentity,
    pub http: HttpRelay,
    pub store: Arc<Mutex<Store>>,
    /// Hosted rows currently registered, kept in step by the main loop.
    pub hosted: Arc<Mutex<Vec<String>>>,
    pub shutdown: Arc<AtomicBool>,
}

impl Connector {
    /// Load config and keys. The only startup failures allowed to exit nonzero.
    pub fn load(config: Config) -> Result<Self> {
        let dir = Config::dir();
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let seed = nostr::load_seed(config::resolve_relative(&dir, &config.seed_path))?;
        let owner = nostr::load_owner_key(config::resolve_relative(&dir, &config.owner_env_path))?;
        let owner_pubkey = public_hex(&owner);

        let canonical = config::reader_canonical(&config.device_label)?;
        let key = nostr::derive_secret(&seed, &canonical);
        let reader = AgentIdentity {
            name: "reader".to_string(),
            row: "reader".to_string(),
            canonical,
            pubkey: public_hex(&key),
            key,
            remote: false,
        };

        let state_db = Config::state_db_path();
        let store = if state_db.exists() {
            Store::open(&state_db, epoch_from_path(&state_db))?
        } else {
            Store::open(&state_db, String::new())?
        };

        Ok(Self {
            http: HttpRelay {
                base_url: config.http_url.clone(),
            },
            config,
            seed,
            owner,
            owner_pubkey,
            reader,
            store: Arc::new(Mutex::new(store)),
            hosted: Arc::new(Mutex::new(Vec::new())),
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// The reader's NIP-OA delegation tag (omp owns it, empty conditions).
    pub fn reader_auth_tag(&self) -> [String; 4] {
        auth_tag(&self.owner, &self.reader.pubkey, "")
    }

    /// omp's NIP-OA delegation tag for any key, as JSON for `x-auth-tag`.
    pub fn reader_auth_tag_for(&self, pubkey: &str) -> String {
        serde_json::to_string(&auth_tag(&self.owner, pubkey, "")).unwrap_or_default()
    }

    /// Derive an agent's Buzz identity from its hcom name.
    ///
    /// `luna` on this device is `luna@mbai`; a mirror row `luna:BOXE` is
    /// `luna@boxe`, lowercased. A remote identity needs no local Buzz state.
    pub fn agent_identity(&self, row_name: &str) -> AgentIdentity {
        let (name, canonical, remote) = match split_device(row_name) {
            Some((base, device)) => (base.to_string(), format!("{base}@{device}"), true),
            None => (
                row_name.to_string(),
                route::canonical_identity(row_name, &self.config.device_label),
                false,
            ),
        };
        let key = nostr::derive_secret(&self.seed, &canonical);
        AgentIdentity {
            name,
            row: row_name.to_string(),
            canonical,
            pubkey: public_hex(&key),
            key,
            remote,
        }
    }

    /// Bridged channels as routing rows.
    pub fn channel_rows(&self) -> Vec<ChannelRow> {
        self.config
            .channels()
            .iter()
            .map(|c| ChannelRow {
                id: c.id.clone(),
                slug: c.slug.clone().unwrap_or_else(|| c.id.clone()),
            })
            .collect()
    }
}

impl AgentIdentity {
    /// NIP-OA delegation of this key, owned by omp with empty conditions.
    fn auth_tag(&self, owner: &SecretKey) -> [String; 4] {
        auth_tag(owner, &self.pubkey, "")
    }

    /// Kind 0: display name, the hcom marker in `about`, NIP-OA tag.
    fn profile_event(&self, owner: &SecretKey) -> Event {
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_PROFILE,
                tags: vec![self.auth_tag(owner).to_vec()],
                content: route::agent_profile_content(&self.name, &self.canonical, self.remote),
            },
            &self.key,
        )
    }

    /// omp's kind 30177 managed-agent policy: what the mention popup reads.
    fn managed_agent_event(&self, owner: &SecretKey) -> Event {
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: 30177,
                tags: vec![vec!["d".into(), self.pubkey.clone()]],
                content: route::managed_agent_content(&self.name),
            },
            owner,
        )
    }

    /// omp's kind 9000 add with role `bot`.
    fn add_member_event(&self, owner: &SecretKey, channel_id: &str) -> Event {
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: 9000,
                tags: route::add_member_tags(channel_id, &self.pubkey),
                content: String::new(),
            },
            owner,
        )
    }

    /// omp's kind 9001 remove.
    fn remove_member_event(&self, owner: &SecretKey, channel_id: &str) -> Event {
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: 9001,
                tags: route::remove_member_tags(channel_id, &self.pubkey),
                content: String::new(),
            },
            owner,
        )
    }

    /// The same kind 0 `publish` posts, exposed for the CLI's publish path.
    pub fn publish_profile_event(&self, owner: &SecretKey) -> Result<Event> {
        Ok(self.profile_event(owner))
    }

    /// The same kind 30177 `publish` posts.
    pub fn publish_managed_agent_event(&self, owner: &SecretKey) -> Result<Event> {
        Ok(self.managed_agent_event(owner))
    }

    /// The reader's own kind 0: marked as the connector, never as an agent.
    fn reader_profile_event(&self, owner: &SecretKey) -> Event {
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_PROFILE,
                tags: vec![self.auth_tag(owner).to_vec()],
                content: json!({
                    "name": "hcom-buzz",
                    "display_name": "hcom-buzz (connector)",
                    "about": format!("{}{}", route::READER_CANONICAL_PREFIX, self.canonical),
                })
                .to_string(),
            },
            &self.key,
        )
    }
}

/// `luna:BOXE` → `("luna", "boxe")`; a plain name → None.
fn split_device(name: &str) -> Option<(&str, String)> {
    crate::relay::control::split_device_suffix(name)
        .map(|(base, short)| (base, short.to_lowercase()))
}

/// The hcom DB epoch: `hcom.db`'s inode plus kv `relay_local_reset_ts`.
///
/// Event ids restart from 1 after `hcom reset`, so any remembered id must be
/// scoped by this value or it points at unrelated history. Mirrors the bridge's
/// `database_epoch`.
pub fn hcom_epoch(db: &HcomDb) -> Result<String> {
    let reset_ts = db
        .kv_get("relay_local_reset_ts")
        .ok()
        .flatten()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "none".to_string());
    let path = crate::paths::db_path();
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        match std::fs::metadata(&path) {
            Ok(meta) => format!("{}:{}", meta.dev(), meta.ino()),
            Err(_) => "0:0".to_string(),
        }
    };
    #[cfg(not(unix))]
    let identity = std::fs::metadata(&path)
        .map(|_| "present".to_string())
        .unwrap_or_else(|_| "absent".to_string());
    Ok(format!("{identity}:{reset_ts}"))
}

/// The epoch recorded in the store, for reopening it.
fn epoch_from_path(path: &std::path::Path) -> String {
    let db = match HcomDb::open_at(path) {
        Ok(db) => db,
        Err(_) => return String::new(),
    };
    hcom_epoch(&db).unwrap_or_default()
}

/// A token bucket over a sliding window, one per signing key.
pub struct TokenBucket {
    capacity: usize,
    window: Duration,
    used: usize,
    started: Instant,
}

impl TokenBucket {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            used: 0,
            started: Instant::now(),
        }
    }

    /// Take one token, or say how long to wait.
    pub fn take(&mut self) -> Result<(), Duration> {
        if self.started.elapsed() >= self.window {
            self.started = Instant::now();
            self.used = 0;
        }
        if self.used < self.capacity {
            self.used += 1;
            return Ok(());
        }
        let wait = self.window.saturating_sub(self.started.elapsed());
        Err(wait.max(Duration::from_millis(1)))
    }
}

/// Exponential backoff with jitter, bounded.
pub fn backoff(attempt: u32, min: Duration, max: Duration) -> Duration {
    let factor = 1u32 << attempt.min(16);
    let capped = min.saturating_mul(factor).min(max);
    // Up to 10% jitter so reconnecting channels do not synchronize.
    let jitter_millis = (capped.as_millis() / 10) as u64;
    capped + Duration::from_millis(jitter_millis)
}

/// Held for the process's lifetime; released when this drops.
pub struct ServeLock {
    file: File,
}

impl ServeLock {
    /// Take the single-connector lock, refusing while a live process holds it.
    pub fn acquire(path: &std::path::Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;

        if !matches!(crate::sys::fs::try_lock_exclusive(&file), Ok(true)) {
            // A lock file left by a dead process must not block a restart, so
            // liveness of the recorded pid decides.
            let holder = Self::holder_pid(path);
            match holder {
                Some(pid) if config::lock_holder_alive(pid) => {
                    bail!("hcom buzz serve is already running (pid {pid})");
                }
                other => {
                    crate::log::log_warn(
                        "buzz",
                        "serve.stale_lock",
                        &format!("clearing a lock left by pid {:?}", other),
                    );
                }
            }
            if !matches!(crate::sys::fs::try_lock_exclusive(&file), Ok(true)) {
                bail!("hcom buzz serve is already running");
            }
        }

        let mut file = file;
        file.set_len(0).ok();
        writeln!(file, "{}", std::process::id())?;
        Ok(Self { file })
    }

    /// The pid recorded in the lock file, if any.
    pub fn holder_pid(path: &std::path::Path) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
    }
}

impl Drop for ServeLock {
    fn drop(&mut self) {
        let _ = crate::sys::fs::try_lock_exclusive(&self.file);
    }
}

/// One inbound relay message, handed from the reader thread to the main loop.
pub struct InboundItem {
    pub sub: String,
    pub event: Event,
}

/// Start the connector and run until shutdown. Returns the process exit code.
pub fn serve(config: Config) -> Result<i32> {
    let lock = ServeLock::acquire(&Config::lock_path())?;
    let connector = Connector::load(config)?;
    let db = HcomDb::open().context("cannot open hcom.db")?;
    let epoch = hcom_epoch(&db)?;
    {
        let mut store = connector.store.lock();
        store.adopt_epoch(epoch.clone())?;
    }

    // One notify endpoint, one port, every hosted row: `wake_all` dedupes by
    // port, so one wake reaches the connector for any row.
    let notify = crate::notify::NotifyServer::new().context("cannot bind notify endpoint")?;

    crate::sys::signal::register_term(&connector.shutdown);

    // The reader must be a member of every bridged channel *before* it opens a
    // subscription: a live single-`#h` REQ from a non-member is refused with
    // CLOSED "not a channel member", and no amount of reconnecting fixes that.
    // Enrollment is HTTP and omp is the channel admin, so this is one write per
    // channel, done before the reader thread exists.
    let mut buckets: HashMap<String, TokenBucket> = HashMap::new();
    for channel in connector.channel_rows() {
        {
            // The row is the durable cursor holder; without it the backfill
            // always restarts from zero and `status` reports no channels.
            let store = connector.store.lock();
            let _ = store.upsert_channel(&channel.id, &channel.slug);
        }
        enroll_reader(&connector, &channel.id, &mut buckets);
    }

    let (tx, rx) = mpsc::channel::<InboundItem>();
    let handles = ReaderHandles {
        relay_url: connector.config.relay_url.clone(),
        reader: connector.reader.clone(),
        reader_auth_tag: connector.reader_auth_tag(),
        channels: connector.channel_rows(),
        store: connector.store.clone(),
        shutdown: connector.shutdown.clone(),
    };
    let reader_thread = std::thread::Builder::new()
        .name("buzz-reader".into())
        .spawn(move || reader_loop(handles, tx))
        .context("cannot spawn reader thread")?;

    let shutdown_flag = connector.shutdown.clone();
    let mut main = MainLoop {
        connector,
        db,
        notify,
        epoch,
        inbound: rx,
        last_enroll: Instant::now(),
        last_stale_check: Instant::now(),
        buckets,
    };
    let code = main.run();

    shutdown_flag.store(true, Ordering::SeqCst);
    let _ = reader_thread.join();
    drop(lock);
    Ok(code)
}

/// The reader thread's own view of what it needs.
struct ReaderHandles {
    relay_url: String,
    reader: AgentIdentity,
    reader_auth_tag: [String; 4],
    channels: Vec<ChannelRow>,
    store: Arc<Mutex<Store>>,
    shutdown: Arc<AtomicBool>,
}

/// Enroll the connector's reader in one channel, before any subscription.
///
/// The reader's own kind 0 (marked as the connector, never as an hcom agent)
/// plus omp's kind 9000 add with role `bot`. Both are HTTP writes from the main
/// thread, before the reader thread exists, because a subscription from a
/// non-member is refused outright and reconnecting cannot fix it.
fn enroll_reader(
    connector: &Connector,
    channel_id: &str,
    buckets: &mut HashMap<String, TokenBucket>,
) {
    let reader = &connector.reader;
    let profile = reader.reader_profile_event(&connector.owner);
    let member = sign(
        UnsignedEvent {
            created_at: nostr::now(),
            kind: 9000,
            tags: route::add_member_tags(channel_id, &reader.pubkey),
            content: String::new(),
        },
        &connector.owner,
    );
    let tag = serde_json::to_string(&reader.auth_tag(&connector.owner)).unwrap_or_default();

    for (event, signer, delegation) in [
        (profile, &reader.key, Some(tag.as_str())),
        (member, &connector.owner, None),
    ] {
        if let Err(wait) = buckets
            .entry(event.pubkey.clone())
            .or_insert_with(|| TokenBucket::new(HTTP_PER_MINUTE, Duration::from_secs(60)))
            .take()
        {
            crate::log::log_warn(
                "buzz",
                "serve.reader_enroll_throttled",
                &format!("{channel_id}: waiting {}s", wait.as_secs().max(1)),
            );
            return;
        }
        if let Err(error) = connector.http.post_event(&event, signer, delegation) {
            crate::log::log_warn(
                "buzz",
                "serve.reader_enroll_failed",
                &format!("{channel_id}: kind {}: {error}", event.kind),
            );
            return;
        }
    }
    let _ = connector
        .store
        .lock()
        .put_enrollment(&reader.pubkey, channel_id, "enrolled");
    crate::log::log_info(
        "buzz",
        "serve.reader_enrolled",
        &format!("reader is a member of {channel_id}"),
    );
}

/// Register or refresh every hosted row: active people plus one row per
/// bridged channel. A refusal is logged loudly and the row stays unhosted, so
/// nothing silently pretends to be bridged.
fn register_hosted_rows(db: &HcomDb, connector: &Connector, port: u16) {
    let people: Vec<String> = connector
        .store
        .lock()
        .active_people()
        .map(|people| people.into_iter().map(|p| p.name).collect())
        .unwrap_or_default();
    let mut names = people;
    names.extend(connector.channel_rows().iter().map(|c| c.row_name()));

    let mut hosted = connector.hosted.lock();
    for name in &names {
        match crate::hosted::register_hosted(db, name, crate::hosted::HOSTED_TOOL_BUZZ) {
            Ok(_) => {
                let _ =
                    db.upsert_notify_endpoint(name, crate::notify::WakeKind::Listen.as_str(), port);
                if !hosted.iter().any(|row| row == name) {
                    hosted.push(name.to_string());
                }
            }
            Err(error) => crate::log::log_warn(
                "buzz",
                "serve.register_refused",
                &format!("{name}: {error}"),
            ),
        }
    }
}

/// The reader thread: one WS session as the reader key, one REQ per channel.
fn reader_loop(handles: ReaderHandles, tx: mpsc::Sender<InboundItem>) {
    let mut attempt = 0u32;
    while !handles.shutdown.load(Ordering::SeqCst) {
        let connected = WsSession::connect(
            &handles.relay_url,
            &handles.reader.key,
            Some(handles.reader_auth_tag.clone()),
            WS_TIMEOUT,
        );
        match connected {
            Ok(mut session) => {
                attempt = 0;
                if let Err(error) = subscribe_all(&mut session, &handles) {
                    crate::log::log_warn(
                        "buzz",
                        "serve.reader_subscribe",
                        &format!("{error}; reconnecting"),
                    );
                    continue;
                }
                if pump_session(&mut session, &handles, &tx) {
                    return;
                }
            }
            Err(error) => {
                let wait = backoff(attempt, BACKOFF_MIN, BACKOFF_MAX);
                crate::log::log_warn(
                    "buzz",
                    "serve.reader_connect",
                    &format!("{error}; retrying in {}s", wait.as_secs().max(1)),
                );
                attempt = attempt.saturating_add(1);
                if sleep_unless(&handles.shutdown, wait) {
                    return;
                }
            }
        }
    }
}

/// Open one subscription per channel, staggered under the WS frame budget and
/// backfilling from each channel's cursor.
fn subscribe_all(session: &mut WsSession, handles: &ReaderHandles) -> Result<()> {
    let mut budget = TokenBucket::new(WS_FRAMES_PER_WINDOW, Duration::from_secs(5));
    for (index, channel) in handles.channels.iter().enumerate() {
        if let Err(wait) = budget.take() {
            sleep(Duration::from_millis(100).min(wait));
            budget.take().ok();
        }
        if index > 0 {
            sleep(REQ_STAGGER);
        }
        let since = handles
            .store
            .lock()
            .channel(&channel.id)
            .ok()
            .flatten()
            .and_then(|row| row.cursor_created_at)
            .map(|cursor| cursor.saturating_sub(store::BACKFILL_SLACK_SECS))
            .unwrap_or(0);
        // Always carry kinds: the relay refuses an unscoped query filter.
        let filter = json!({
            "kinds": store::CHANNEL_KINDS,
            "#h": [channel.id],
            "since": since,
        });
        session.req(&sub_id(&channel.slug), &[filter])?;
    }
    Ok(())
}

/// Subscription id for a channel slug.
fn sub_id(slug: &str) -> String {
    format!("buzz-{slug}")
}

/// Read one session until it fails or the process stops. True when shutting
/// down; false hands the session back to the reconnect loop.
fn pump_session(
    session: &mut WsSession,
    handles: &ReaderHandles,
    tx: &mpsc::Sender<InboundItem>,
) -> bool {
    while !handles.shutdown.load(Ordering::SeqCst) {
        match session.recv(Duration::from_millis(500)) {
            Err(error) => {
                crate::log::log_warn("buzz", "serve.reader_error", &error.to_string());
                return false;
            }
            Ok(None) => {}
            Ok(Some(RelayMsg::Event { sub, event })) => {
                if tx.send(InboundItem { sub, event }).is_err() {
                    return true;
                }
            }
            Ok(Some(RelayMsg::Eose(sub))) => {
                crate::log::log_info("buzz", "serve.backfill_done", &sub);
            }
            Ok(Some(RelayMsg::Closed { sub, reason })) => {
                // One closed subscription parks its channel; the rest keep
                // running, so a single failure never stops the connector.
                if let Some(channel_id) = channel_for_sub(&handles.channels, &sub) {
                    let _ = handles
                        .store
                        .lock()
                        .set_channel_parked(&channel_id, Some(&reason));
                }
                crate::log::log_warn("buzz", "serve.channel_closed", &format!("{sub}: {reason}"));
            }
            Ok(Some(RelayMsg::Notice(message))) => {
                crate::log::log_warn("buzz", "serve.reader_notice", &message);
            }
            Ok(Some(RelayMsg::Ok {
                id,
                accepted,
                message,
            })) => {
                if !accepted && !message.starts_with("duplicate:") {
                    crate::log::log_warn(
                        "buzz",
                        "serve.reader_event_refused",
                        &format!("{id}: {message}"),
                    );
                }
            }
        }
    }
    true
}

/// Channel id behind a `buzz-<slug>` subscription id.
fn channel_for_sub(channels: &[ChannelRow], sub: &str) -> Option<String> {
    let slug = sub.strip_prefix("buzz-")?;
    channels
        .iter()
        .find(|c| c.slug == slug)
        .map(|c| c.id.clone())
}

/// Sleep unless shutdown arrives first. True when shutdown was requested.
fn sleep_unless(shutdown: &AtomicBool, wait: Duration) -> bool {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        sleep(Duration::from_millis(50).min(remaining));
    }
    shutdown.load(Ordering::SeqCst)
}

/// The main loop. Owns both databases: it is the only writer to them.
struct MainLoop {
    connector: Connector,
    db: HcomDb,
    notify: crate::notify::NotifyServer,
    epoch: String,
    inbound: mpsc::Receiver<InboundItem>,
    last_enroll: Instant,
    last_stale_check: Instant,
    buckets: HashMap<String, TokenBucket>,
}

impl MainLoop {
    /// Build a loop around an already-loaded connector, keeping the sending half
    /// of the inbound channel so a test can inject exactly what the reader
    /// thread would have handed over.
    #[cfg(test)]
    fn for_test(
        connector: Connector,
        db: HcomDb,
        epoch: String,
    ) -> (Self, mpsc::Sender<InboundItem>) {
        let (tx, rx) = mpsc::channel();
        let loop_self = Self {
            connector,
            db,
            notify: crate::notify::NotifyServer::new().expect("notify endpoint"),
            epoch,
            inbound: rx,
            last_enroll: Instant::now(),
            last_stale_check: Instant::now(),
            buckets: HashMap::new(),
        };
        (loop_self, tx)
    }

    /// One iteration of the main loop: inbound, tick, enrollment. Returns the
    /// next wake wait. The tests drive this directly, so they exercise the
    /// production loop body rather than a stand-in.
    fn step(&mut self) {
        self.drain_inbound();
        self.tick();
        if self.last_enroll.elapsed() >= ENROLL_INTERVAL {
            self.last_enroll = Instant::now();
            self.plan_enrollment();
        }
    }

    /// Run until SIGTERM/SIGINT, then shut down cleanly.
    fn run(&mut self) -> i32 {
        register_hosted_rows(&self.db, &self.connector, self.notify.port());
        while !self.connector.shutdown.load(Ordering::SeqCst) {
            self.drain_inbound();
            self.tick();
            if self.last_enroll.elapsed() >= ENROLL_INTERVAL {
                self.last_enroll = Instant::now();
                self.plan_enrollment();
            }
            // Wake on any hosted row's message, or on the backstop tick.
            self.notify.wait(TICK);
        }
        self.shutdown()
    }

    /// Graceful stop: flush what is queued, mark rows offline, drop endpoints.
    fn shutdown(&mut self) -> i32 {
        crate::log::log_info("buzz", "serve.stopping", "flushing outbox");
        self.flush_outbox(Duration::from_secs(10));
        if let Err(error) =
            crate::hosted::set_hosted_offline(&self.db, crate::hosted::HOSTED_TOOL_BUZZ)
        {
            crate::log::log_warn("buzz", "serve.offline", &error.to_string());
        }
        for name in self.hosted_rows() {
            let _ = self
                .db
                .delete_notify_endpoint(&name, crate::notify::WakeKind::Listen.as_str());
        }
        0
    }

    fn hosted_rows(&self) -> Vec<String> {
        self.connector.hosted.lock().clone()
    }

    /// One pass: heartbeat, epoch check, re-register, parked retries, outbound.
    fn tick(&mut self) {
        if let Err(error) =
            crate::hosted::heartbeat_hosted(&self.db, crate::hosted::HOSTED_TOOL_BUZZ)
        {
            crate::log::log_warn("buzz", "serve.heartbeat", &error.to_string());
        }

        if let Ok(epoch) = hcom_epoch(&self.db)
            && epoch != self.epoch
        {
            crate::log::log_warn(
                "buzz",
                "serve.epoch_changed",
                "hcom.db was replaced; hosted rows re-register",
            );
            self.epoch = epoch.clone();
            let _ = self.connector.store.lock().adopt_epoch(epoch);
        }
        self.reregister_missing_rows();
        self.retry_parked_targets();
        self.scan_outbound();
        self.flush_all_channels();
        if self.last_stale_check.elapsed() >= Duration::from_secs(60) {
            self.last_stale_check = Instant::now();
            self.recheck_stale_outbox();
        }
    }

    /// Re-register any hosted row the store still calls active whose hcom row
    /// has gone (an operator `hcom stop`, a reset, a deletion).
    fn reregister_missing_rows(&mut self) {
        let port = self.notify.port();
        let people: Vec<String> = self
            .connector
            .store
            .lock()
            .active_people()
            .map(|people| people.into_iter().map(|p| p.name).collect())
            .unwrap_or_default();
        let mut wanted: Vec<String> = people;
        wanted.extend(self.connector.channel_rows().iter().map(|c| c.row_name()));

        let mut hosted = self.connector.hosted.lock();
        for name in wanted {
            if hosted.contains(&name) {
                continue;
            }
            match crate::hosted::register_hosted(&self.db, &name, crate::hosted::HOSTED_TOOL_BUZZ) {
                Ok(_) => {
                    let _ = self.db.upsert_notify_endpoint(
                        &name,
                        crate::notify::WakeKind::Listen.as_str(),
                        port,
                    );
                    crate::log::log_info(
                        "buzz",
                        "serve.row_restored",
                        &format!("{name} is back in the active roster"),
                    );
                    hosted.push(name);
                }
                Err(error) => crate::log::log_warn(
                    "buzz",
                    "serve.register_refused",
                    &format!("{name}: {error}"),
                ),
            }
        }
    }

    /// Retry parked inbound targets; after the window, say so in Buzz as omp.
    fn retry_parked_targets(&mut self) {
        let now = crate::shared::time::now_epoch_i64();
        let due = self
            .connector
            .store
            .lock()
            .due_targets(now)
            .unwrap_or_default();
        for target in due {
            match self.deliver_parked(&target.buzz_id, &target.target) {
                Ok(true) => {
                    {
                        let store = self.connector.store.lock();
                        let _ =
                            store.update_target(&target.buzz_id, &target.target, "delivered", 0);
                    }
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    crate::log::log_warn("buzz", "serve.park_failed", &error.to_string());
                }
            }

            let parked_for = now.saturating_sub(target.first_parked_at);
            if parked_for < PARK_WINDOW.as_secs() as i64 {
                let attempts = target.attempts.saturating_add(1);
                let next = now + park_retry_delay(attempts);
                {
                    let store = self.connector.store.lock();
                    let _ = store.update_target(&target.buzz_id, &target.target, "parked", next);
                }
                continue;
            }
            // The window is over: the channel is told, as omp, in the same
            // thread. The cursor moved on regardless, so nothing stalls.
            self.announce_undelivered(&target.buzz_id, &target.target);
            {
                let store = self.connector.store.lock();
                let _ = store.expire_targets(&target.buzz_id, &target.target);
            }
        }
    }

    /// Try one parked delivery. `Ok(true)` when it resolved.
    fn deliver_parked(&mut self, buzz_id: &str, target: &str) -> Result<bool> {
        let event = {
            let store = self.connector.store.lock();
            store.cached_event(buzz_id)?
        };
        let Some(cached) = event else {
            // Nothing cached to redeliver: the notice already covered it.
            return Ok(true);
        };
        let event: Event = serde_json::from_str(&cached.json)
            .map_err(|e| anyhow!("cached event is unreadable: {e}"))?;
        let thread = route::thread_name(&cached.channel_id, buzz_id);
        crate::commands::send::send_message(
            &self.db,
            &hosted_identity(target),
            &event.content,
            Some(&crate::messages::MessageEnvelope {
                thread: Some(thread),
                ..Default::default()
            }),
            Some(&[target.to_string()]),
        )
        .map_err(|error| anyhow!("{error}"))?;
        crate::log::log_info(
            "buzz",
            "serve.park_delivered",
            &format!("{buzz_id} -> {target}"),
        );
        Ok(true)
    }

    /// Post the "isn't running — not delivered" notice as omp.
    fn announce_undelivered(&mut self, buzz_id: &str, target: &str) {
        let channel_id = {
            let store = self.connector.store.lock();
            match store.cached_event(buzz_id) {
                Ok(Some(cached)) => cached.channel_id,
                _ => return,
            }
        };
        let text = format!("{target} isn't running — not delivered");
        // Posted as omp's own key: it is a relay member and the channel admin, so
        // no enrollment or delegation is needed, and the notice reads as coming
        // from omp rather than from whichever agent failed.
        let event = sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_MESSAGE,
                tags: {
                    let mut tags = route::message_tags(&route::Destination {
                        channel_id,
                        root_id: Some(buzz_id.to_string()),
                        mentions: Vec::new(),
                    });
                    tags.retain(|tag| tag.first().is_none_or(|n| n != "p"));
                    tags
                },
                content: text,
            },
            &self.connector.owner,
        );
        match self
            .connector
            .http
            .post_event(&event, &self.connector.owner, None)
        {
            Ok(()) => crate::log::log_info(
                "buzz",
                "serve.not_delivered",
                &format!("{buzz_id}: {target}"),
            ),
            Err(error) => crate::log::log_warn(
                "buzz",
                "serve.not_delivered_failed",
                &format!("{target}: {error}"),
            ),
        }
    }

    /// The slug of a bridged channel id.
    fn channel_slug(&self, channel_id: &str) -> String {
        self.connector
            .channel_rows()
            .into_iter()
            .find(|c| c.id == channel_id)
            .map(|c| c.slug)
            .unwrap_or_else(|| channel_id.to_string())
    }

    /// Read each hosted row's unread messages and route them.
    fn scan_outbound(&mut self) {
        for row in self.hosted_rows() {
            let messages = self.db.get_unread_messages(&row);
            let Some(last) = messages.last() else {
                continue;
            };
            for message in &messages {
                self.route_outbound_message(&row, message);
            }
            // The cursor advances the way `hcom listen` advances it: past the
            // batch, whatever the posts' fate, because the outbox already holds
            // a signed copy of anything still owed to Buzz.
            if let Some(id) = last.event_id {
                let mut updates = serde_json::Map::new();
                updates.insert("last_event_id".into(), json!(id));
                crate::instances::update_instance_position(&self.db, &row, &updates);
            }
        }
    }

    /// Route one hcom message, queueing a signed post per destination.
    fn route_outbound_message(&mut self, hosted_row: &str, message: &crate::db::Message) {
        let Some(hcom_id) = message.event_id else {
            return;
        };
        if route::is_unroutable_sender(&message.from) {
            crate::log::log_info(
                "buzz",
                "serve.sender_skipped",
                &format!("{hosted_row}: {} is not a Buzz identity", message.from),
            );
            return;
        }

        let identity = self.connector.agent_identity(&message.from);
        let outbound = route::HcomMessage {
            from: message.from.clone(),
            text: message.text.clone(),
            thread: message.thread.clone(),
            exact_targets: exact_targets_of(&self.db, hcom_id),
            delivered_to: message.delivered_to.clone().unwrap_or_default(),
        };

        let inputs = match self.route_inputs() {
            Ok(inputs) => inputs,
            Err(error) => {
                crate::log::log_warn("buzz", "serve.route_inputs", &error.to_string());
                return;
            }
        };
        let ctx = route::OutboundContext {
            people: &inputs.people,
            channels: &inputs.channels,
            threads: &inputs.threads,
            host_device: &inputs.host_device,
        };

        match route::route_outbound(&outbound, &ctx) {
            route::Outbound::Drop => {}
            route::Outbound::Notice { sender, text } => {
                // The agent learns this from hcom, as the person's row.
                crate::log::log_info(
                    "buzz",
                    "serve.no_home_channel",
                    &format!("{}: {text}", identity.row),
                );
                if let Err(error) = crate::commands::send::send_message(
                    &self.db,
                    &hosted_identity(&sender),
                    &text,
                    Some(&crate::messages::MessageEnvelope {
                        thread: message.thread.clone(),
                        ..Default::default()
                    }),
                    Some(std::slice::from_ref(&identity.row)),
                ) {
                    crate::log::log_warn("buzz", "serve.notice_failed", &error);
                }
            }
            route::Outbound::Post(destinations) => {
                for destination in destinations {
                    self.queue_post(&identity, hcom_id, &destination, &message.text);
                }
            }
        }
    }

    /// Sign one post and queue it. Signing first means the Buzz id is known
    /// before the send, which is what makes the outbox idempotent.
    ///
    /// The outbox records `identity.row` (`luna`, or `luna:BOXE` for a
    /// mirror). The publisher re-derives the key from it for NIP-98, so it must
    /// carry the device: the bare name derives this device's key, and the
    /// relay refuses a header that doesn't match the event's author.
    fn queue_post(
        &self,
        identity: &AgentIdentity,
        hcom_id: i64,
        destination: &route::Destination,
        text: &str,
    ) {
        let event = sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_MESSAGE,
                tags: route::message_tags(destination),
                content: route::post_content(text),
            },
            &identity.key,
        );
        let row = OutboxRow {
            hcom_id,
            destination: destination.channel_id.clone(),
            signer_name: identity.row.clone(),
            signed_json: serde_json::to_string(&event).unwrap_or_default(),
            buzz_id: event.id.clone(),
            state: "pending".into(),
            attempts: 0,
            next_at: 0,
            last_error: None,
        };
        let queued = self.connector.store.lock().enqueue_outbox(&row);
        match queued {
            Ok(true) => crate::log::log_info(
                "buzz",
                "serve.queued",
                &format!("{} #{hcom_id} -> {}", identity.row, destination.channel_id),
            ),
            // Re-reading a message after a crash re-queues nothing: the key is
            // already there, so the same Buzz id is posted at most once.
            Ok(false) => {}
            Err(error) => crate::log::log_warn("buzz", "serve.queue_failed", &error.to_string()),
        }
    }

    /// The routing inputs for outbound decisions: active people, bridged
    /// channels, and every Buzz thread this connector has recorded.
    fn route_inputs(&self) -> Result<OutboundInputs> {
        let store = self.connector.store.lock();
        Ok(OutboundInputs {
            people: store
                .active_people()?
                .into_iter()
                .map(|p| PersonRow {
                    pubkey: p.pubkey,
                    name: p.name,
                    home_slug: p.home_slug,
                })
                .collect(),
            channels: self.connector.channel_rows(),
            threads: store
                .threads()?
                .into_iter()
                .map(|row| (row.thread_name, (row.channel_id, row.root_id)))
                .collect(),
            host_device: self.connector.config.device_label.clone(),
        })
    }

    /// Post everything queued for every bridged channel.
    ///
    /// Queuing and posting are separate steps so a message addressed to two
    /// channels becomes two independent outbox rows, and one failing never
    /// holds the other.
    fn flush_all_channels(&mut self) {
        let channels: Vec<String> = self
            .connector
            .channel_rows()
            .into_iter()
            .map(|channel| channel.id)
            .collect();
        for channel_id in channels {
            self.post_due(&channel_id);
        }
    }

    /// Post every due outbox row for one Buzz channel, honoring budgets.
    fn post_due(&mut self, channel_id: &str) {
        let now = crate::shared::time::now_epoch_i64();
        let due = self
            .connector
            .store
            .lock()
            .due_outbox(channel_id, now)
            .unwrap_or_default();
        for row in due {
            if self.connector.shutdown.load(Ordering::SeqCst) {
                return;
            }
            let event: Event = match serde_json::from_str(&row.signed_json) {
                Ok(event) => event,
                Err(error) => {
                    self.fail_row(&row, &format!("unreadable signed event: {error}"));
                    continue;
                }
            };
            let identity = self.connector.agent_identity(&row.signer_name);

            // Enrollment first: membership and the managed-agent policy are
            // what make an agent answerable in the mention popup.
            if !self.ensure_enrolled(&identity, channel_id) {
                let next = crate::shared::time::now_epoch_i64()
                    + post_retry_delay(row.attempts).as_secs() as i64;
                self.retry_row(&row, next, "enrollment incomplete");
                continue;
            }

            if let Err(wait) = self.take_http_token(&identity.pubkey) {
                let next = crate::shared::time::now_epoch_i64() + wait.as_secs().max(1) as i64;
                self.retry_row(&row, next, "HTTP token bucket exhausted");
                continue;
            }

            let auth = identity.auth_tag(&self.connector.owner);
            let tag = serde_json::to_string(&auth).unwrap_or_default();
            match self
                .connector
                .http
                .post_event(&event, &identity.key, Some(&tag))
            {
                Ok(()) => {
                    crate::log::log_info(
                        "buzz",
                        "serve.posted",
                        &format!("{} {} -> {channel_id}", row.signer_name, row.buzz_id),
                    );
                    {
                        let store = self.connector.store.lock();
                        let _ = store.ack_outbox(&row.buzz_id);
                    }
                }
                Err(PublishError::RateLimited { retry_after }) => {
                    // Per-key: only this signer waits.
                    let next =
                        crate::shared::time::now_epoch_i64() + retry_after.as_secs().max(1) as i64;
                    self.retry_row(&row, next, "rate limited");
                }
                Err(PublishError::Server(message)) | Err(PublishError::Transport(message)) => {
                    // A 40 s buzz-pg switchover lands here: backoff, keep going.
                    let next = crate::shared::time::now_epoch_i64()
                        + post_retry_delay(row.attempts).as_secs() as i64;
                    self.retry_row(&row, next, &message);
                }
                Err(PublishError::Timeout) => {
                    let next = crate::shared::time::now_epoch_i64()
                        + post_retry_delay(row.attempts).as_secs() as i64;
                    self.retry_row(&row, next, "relay timed out");
                }
                Err(PublishError::Rejected(message)) => {
                    // The relay will never accept this event.
                    self.fail_row(&row, &message);
                }
                // A 401 is a bug, not a retry case: NIP-98 headers are never
                // reused, so a refusal means the credential itself is wrong.
                Err(PublishError::Auth(message)) => {
                    self.fail_row(&row, &format!("authentication refused: {message}"));
                }
                Err(PublishError::Protocol(message)) => self.fail_row(&row, &message),
            }
        }
    }

    /// An outbox entry unacked past the admission window is looked up by id
    /// first; only if the relay never stored it is it re-signed with a fresh
    /// `created_at`.
    fn recheck_stale_outbox(&mut self) {
        let now = crate::shared::time::now_epoch_i64();
        let stale = self
            .connector
            .store
            .lock()
            .stale_outbox(now - STALE_RECHECK_AFTER.as_secs() as i64)
            .unwrap_or_default();
        for row in stale {
            let identity = self.connector.agent_identity(&row.signer_name);
            let auth = identity.auth_tag(&self.connector.owner);
            let tag = serde_json::to_string(&auth).unwrap_or_default();
            let filter = json!({ "ids": [row.buzz_id], "kinds": store::CHANNEL_KINDS });
            match self
                .connector
                .http
                .query(&filter, &identity.key, Some(&tag))
            {
                // The relay has it after all: the lost ack, not a lost post.
                Ok(events) if !events.is_empty() => {
                    {
                        let store = self.connector.store.lock();
                        let _ = store.ack_outbox(&row.buzz_id);
                    }
                    crate::log::log_info(
                        "buzz",
                        "serve.stale_present",
                        &format!("{} {channel}", row.signer_name, channel = row.destination),
                    );
                }
                _ => {
                    let previous: Event = match serde_json::from_str(&row.signed_json) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    // Only the timestamp changes, so the thread shape, mentions and
                    // content are exactly what the relay would have received.
                    let event = sign(
                        UnsignedEvent {
                            created_at: nostr::now(),
                            kind: previous.kind,
                            tags: previous.tags,
                            content: previous.content,
                        },
                        &identity.key,
                    );
                    let signed = serde_json::to_string(&event).unwrap_or_default();
                    let now = crate::shared::time::now_epoch_i64();
                    {
                        let store = self.connector.store.lock();
                        let _ = store.replace_outbox_event(
                            row.hcom_id,
                            &row.destination,
                            &event.id,
                            &signed,
                            now,
                        );
                        let _ = store.retry_outbox(
                            &row.buzz_id,
                            now,
                            "re-signed after the relay never stored it",
                        );
                        let _ = store.drop_outbox(&row.buzz_id);
                    }
                    crate::log::log_info(
                        "buzz",
                        "serve.stale_resigned",
                        &format!("{} -> {}", row.signer_name, row.destination),
                    );
                    crate::log::log_info(
                        "buzz",
                        "serve.stale_resigned",
                        &format!("{} -> {}", row.signer_name, row.destination),
                    );
                }
            }
        }
    }

    /// Take one HTTP token for a signing key.
    fn take_http_token(&mut self, pubkey: &str) -> Result<(), Duration> {
        self.buckets
            .entry(pubkey.to_string())
            .or_insert_with(|| TokenBucket::new(HTTP_PER_MINUTE, Duration::from_secs(60)))
            .take()
    }

    fn retry_row(&self, row: &OutboxRow, next_at: i64, error: &str) {
        crate::log::log_warn(
            "buzz",
            "serve.post_retry",
            &format!("{} {}: {error}", row.signer_name, row.destination),
        );
        {
            let store = self.connector.store.lock();
            let _ = store.retry_outbox(&row.buzz_id, next_at, error);
        }
    }

    fn fail_row(&self, row: &OutboxRow, error: &str) {
        crate::log::log_error(
            "buzz",
            "serve.post_failed",
            &format!("{} {}: {error}", row.signer_name, row.destination),
        );
        {
            let store = self.connector.store.lock();
            let _ = store.fail_outbox(&row.buzz_id, error);
        }
    }

    /// Bounded drain, used by shutdown.
    fn flush_outbox(&mut self, budget: Duration) {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline && !self.connector.shutdown.load(Ordering::SeqCst) {
            let pending: i64 = self
                .connector
                .store
                .lock()
                .outbox_counts()
                .unwrap_or_default()
                .iter()
                .filter(|(state, _)| state == "pending" || state == "retry")
                .map(|(_, count)| *count)
                .sum();
            if pending == 0 {
                return;
            }
            let channels: Vec<String> = self
                .connector
                .channel_rows()
                .into_iter()
                .map(|c| c.id)
                .collect();
            for channel_id in channels {
                self.post_due(&channel_id);
            }
            sleep(Duration::from_millis(200));
        }
    }

    /// Enroll one identity in a channel: kind 0, kind 30177, then kind 9000.
    /// The reader is enrolled the same way, so it exists as a channel member
    /// with role `bot` and is never classified as a person.
    fn ensure_enrolled(&mut self, identity: &AgentIdentity, channel_id: &str) -> bool {
        let enrolled = self
            .connector
            .store
            .lock()
            .enrollment(&identity.pubkey, channel_id)
            .ok()
            .flatten();
        if enrolled.as_deref() == Some("enrolled") {
            return true;
        }

        let is_reader = identity.pubkey == self.connector.reader.pubkey;
        let agent_events = if is_reader {
            vec![identity.reader_profile_event(&self.connector.owner)]
        } else {
            vec![
                identity.profile_event(&self.connector.owner),
                identity.managed_agent_event(&self.connector.owner),
            ]
        };
        let admin_event = identity.add_member_event(&self.connector.owner, channel_id);
        let admin_events = std::slice::from_ref(&admin_event);

        for event in agent_events.iter().chain(admin_events) {
            if let Err(wait) = self.take_http_token(&event.pubkey) {
                crate::log::log_warn(
                    "buzz",
                    "serve.enroll_throttled",
                    &format!("waiting {}s for the HTTP bucket", wait.as_secs().max(1)),
                );
                return false;
            }
            // Only a delegated non-member key needs `x-auth-tag`; omp's own
            // events are authenticated as themselves.
            let delegated = event.pubkey != self.connector.owner_pubkey;
            let signer = if delegated {
                identity.key.clone()
            } else {
                self.connector.owner.clone()
            };
            let auth = delegated.then(|| {
                serde_json::to_string(&identity.auth_tag(&self.connector.owner)).unwrap_or_default()
            });
            if let Err(error) = self
                .connector
                .http
                .post_event(event, &signer, auth.as_deref())
            {
                crate::log::log_warn(
                    "buzz",
                    "serve.enroll_failed",
                    &format!("kind {} {channel_id}: {error}", event.kind),
                );
                return false;
            }
        }
        {
            let store = self.connector.store.lock();
            let _ = store.put_enrollment(&identity.pubkey, channel_id, "enrolled");
            // We just published this agent's kind 0, so its classification is
            // known without waiting for the profile to come back. The reader
            // only subscribes to `#h` kinds, so kind 0 never arrives on its
            // own; without this a mention of an agent whose session has ended
            // names nobody and is skipped instead of parked.
            if !is_reader {
                // `row` keeps a mirror as `luna:BOXE`; the bare name would park
                // a mention for a local row that never exists.
                let _ = store.put_author(&Author {
                    pubkey: identity.pubkey.clone(),
                    kind: AuthorKind::Agent,
                    hcom_name: Some(identity.row.clone()),
                    device_label: identity
                        .canonical
                        .rsplit_once('@')
                        .map(|(_, device)| device.to_string()),
                });
            }
        }
        crate::log::log_info(
            "buzz",
            "serve.enrolled",
            &format!("{} in {channel_id}", identity.canonical),
        );
        true
    }

    /// Enroll every deliverable agent row into every bridged channel, and remove
    /// agents whose row has been gone for an hour.
    fn plan_enrollment(&mut self) {
        let roster: Vec<AgentIdentity> = self
            .deliverable_agents()
            .into_iter()
            .map(|name| self.connector.agent_identity(&name))
            .collect();
        let channels = self.connector.channel_rows();
        for identity in &roster {
            for channel in &channels {
                self.ensure_enrolled(identity, &channel.id);
            }
        }
        // The reader is a channel member too, so it never reads as a person.
        let reader = self.connector.reader.clone();
        for channel in &channels {
            self.ensure_enrolled(&reader, &channel.id);
        }

        let now = crate::shared::time::now_epoch_i64();
        let enrollments = self
            .connector
            .store
            .lock()
            .enrollments()
            .unwrap_or_default();
        for row in enrollments {
            if row.state != "enrolled" || row.agent_pubkey == self.connector.reader.pubkey {
                continue;
            }
            if roster
                .iter()
                .any(|identity| identity.pubkey == row.agent_pubkey)
            {
                continue;
            }
            if now.saturating_sub(row.updated_at) < ENROLL_STALE_SECS {
                continue;
            }
            let identity = self.connector.agent_identity(&row.agent_pubkey);
            let event = identity.remove_member_event(&self.connector.owner, &row.channel_id);
            let owner_pubkey = self.connector.owner_pubkey.clone();
            if let Err(wait) = self.take_http_token(&owner_pubkey) {
                crate::log::log_warn(
                    "buzz",
                    "serve.unenroll_throttled",
                    &format!("waiting {}s", wait.as_secs().max(1)),
                );
                continue;
            }
            if self
                .connector
                .http
                .post_event(&event, &self.connector.owner, None)
                .is_ok()
                && let store = self.connector.store.lock()
            {
                let _ = store.drop_enrollment(&row.agent_pubkey);
                crate::log::log_info(
                    "buzz",
                    "serve.unenrolled",
                    &format!("{} left {}", identity.canonical, row.channel_id),
                );
            }
        }
    }

    /// Every deliverable hcom agent row: local and remote mirrors, excluding
    /// hosted rows, `_`/`sys_` names and subagents.
    fn deliverable_agents(&self) -> Vec<String> {
        let sql = format!(
            "SELECT name, tool, parent_name FROM instances
             WHERE {predicate}
             ORDER BY name",
            predicate = crate::fleet_names::LIVE_ROW_PREDICATE
        );
        let Ok(mut stmt) = self.db.conn().prepare(&sql) else {
            return Vec::new();
        };
        let rows: Vec<(String, String, Option<String>)> =
            match stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))) {
                Ok(iter) => iter.filter_map(std::result::Result::ok).collect(),
                Err(_) => return Vec::new(),
            };
        rows.into_iter()
            .filter(|(name, tool, parent)| {
                !name.starts_with('_')
                    && !name.starts_with("sys_")
                    && parent.is_none()
                    && !crate::hosted::is_hosted_tool(tool)
            })
            .map(|(name, _, _)| name)
            .collect()
    }

    /// Handle every inbound relay message: verify, dedupe, cache, deliver.
    fn drain_inbound(&mut self) {
        while let Ok(item) = self.inbound.try_recv() {
            if let Err(error) = self.handle_inbound(item) {
                crate::log::log_warn("buzz", "serve.inbound", &error.to_string());
            }
        }
    }

    fn handle_inbound(&mut self, item: InboundItem) -> Result<()> {
        let event = item.event;
        if !nostr::verify(&event) {
            return Err(anyhow!("{} failed signature verification", event.id));
        }
        let channel = self
            .connector
            .channel_rows()
            .into_iter()
            .find(|c| item.sub == sub_id(&c.slug))
            .ok_or_else(|| anyhow!("event on unknown subscription {}", item.sub))?;

        {
            let store = self.connector.store.lock();
            if !store.mark_seen(&event.id)? {
                return Ok(());
            }
        }

        let (root_id, parent_id) = route::thread_refs(&event);
        {
            let store = self.connector.store.lock();
            store.cache_event(&store::cached_from_event(
                &event,
                &channel.id,
                root_id.as_deref(),
                parent_id.as_deref(),
            )?)?;
            store.set_channel_cursor(&channel.id, event.created_at)?;
        }

        match event.kind {
            route::KIND_ROSTER => return self.handle_roster(&event),
            route::KIND_PROFILE => return self.handle_profile(&event),
            _ => {}
        }

        // An edit or deletion addresses a previous event through its `e` tag:
        // the delivered check, the thread and the targets all follow that
        // original, not the revision itself.
        let revision = matches!(
            event.kind,
            route::KIND_EDIT | route::KIND_DELETE | route::KIND_CHANNEL_DELETE
        );
        let subject = if revision {
            route::tag(&event, "e").unwrap_or(&event.id).to_string()
        } else {
            event.id.clone()
        };
        let original = if revision {
            self.connector
                .store
                .lock()
                .cached_event(&subject)?
                .and_then(|cached| serde_json::from_str::<Event>(&cached.json).ok())
        } else {
            None
        };
        let threaded = original.as_ref().unwrap_or(&event);
        let ancestry = self.load_ancestry(threaded)?;
        let (root_id, parent_id) = if original.is_some() {
            route::thread_refs(threaded)
        } else {
            (root_id, parent_id)
        };
        let root = root_id.or(parent_id).unwrap_or_else(|| threaded.id.clone());
        let input = InboundEvent {
            event: event.clone(),
            channel: channel.clone(),
            root_id: root,
            ancestry,
            original,
        };

        let people = self.route_inputs_people()?;
        let roster = self.agent_roster();
        let kinds = self.author_kinds(&people);
        let delivered = self
            .connector
            .store
            .lock()
            .was_delivered(&subject)
            .unwrap_or(false);

        match route::route_inbound(&input, &people, &roster, &kinds, delivered) {
            route::Inbound::Skip(reason) => crate::log::log_info(
                "buzz",
                "serve.inbound_skipped",
                &format!("{}: {reason:?}", event.id),
            ),
            route::Inbound::Deliver(delivery) => {
                // A target hcom cannot route is one with no deliverable row at
                // all: `send_message` refuses it, and the whole event is parked
                // for that target rather than dropped for the others.
                let unroutable: Vec<String> = delivery
                    .targets
                    .iter()
                    .filter(|target| {
                        !self
                            .db
                            .get_instance_full(target)
                            .ok()
                            .flatten()
                            .is_some_and(|row| {
                                crate::hosted::is_hosted_tool(&row.tool)
                                    || !row.status.eq_ignore_ascii_case("stopped")
                            })
                    })
                    .cloned()
                    .collect();
                if unroutable.is_empty() {
                    self.deliver_to_hcom(&subject, delivery)?;
                } else {
                    self.park_all(&subject, &unroutable)?;
                }
            }
        }
        Ok(())
    }

    /// Active people rows, as routing rows.
    fn route_inputs_people(&self) -> Result<Vec<PersonRow>> {
        let store = self.connector.store.lock();
        Ok(store
            .active_people()?
            .into_iter()
            .map(|p| PersonRow {
                pubkey: p.pubkey,
                name: p.name,
                home_slug: p.home_slug,
            })
            .collect())
    }

    /// Author classifications for inbound routing.
    fn author_kinds(&self, people: &[PersonRow]) -> HashMap<String, AuthorKind> {
        let mut kinds = HashMap::new();
        for person in people {
            kinds.insert(person.pubkey.clone(), AuthorKind::Person);
        }
        for identity in self.all_known_identities() {
            kinds.insert(identity.pubkey.clone(), AuthorKind::Agent);
        }
        kinds.insert(self.connector.reader.pubkey.clone(), AuthorKind::Reader);
        kinds.insert(self.connector.owner_pubkey.clone(), AuthorKind::Owner);
        kinds
    }

    /// Every identity this connector can recognise as an agent: the deliverable
    /// rows plus anything already cached in the author table.
    fn all_known_identities(&self) -> Vec<AgentIdentity> {
        let mut identities: Vec<AgentIdentity> = self
            .deliverable_agents()
            .into_iter()
            .map(|name| self.connector.agent_identity(&name))
            .collect();
        let cached: Vec<(String, String)> = self
            .connector
            .store
            .lock()
            .authors_of_kind(AuthorKind::Agent)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(pubkey, name)| name.map(|name| (pubkey, name)))
            .collect();
        for (pubkey, name) in cached {
            let identity = self.connector.agent_identity(&name);
            if identity.pubkey == pubkey && !identities.iter().any(|known| known.pubkey == pubkey) {
                identities.push(identity);
            }
        }
        identities
    }

    /// hcom rows that are agents, mapped to their Buzz pubkeys.
    fn agent_roster(&self) -> AgentRoster {
        let mut roster = AgentRoster::default();
        for identity in self.all_known_identities() {
            roster
                .by_pubkey
                .insert(identity.pubkey.clone(), identity.row.clone());
            roster.deliverable.insert(identity.row);
        }
        roster
    }

    /// Ancestors of an event, walking `e` tags to the root, fetching by id when
    /// the cache has not seen one.
    fn load_ancestry(&mut self, event: &Event) -> Result<Vec<Ancestor>> {
        let (root, reply) = route::thread_refs(event);
        let mut chain: Vec<Ancestor> = Vec::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut pending = reply.or(root);
        let mut hops = 0usize;
        while let Some(id) = pending {
            if !seen.insert(id.clone()) || hops > 64 {
                break;
            }
            hops += 1;
            let cached = {
                let store = self.connector.store.lock();
                store.cached_event(&id)?
            };
            let (author, parent) = match cached {
                Some(cached) => (cached.author, cached.parent_id),
                None => match self.fetch_event(&id)? {
                    Some(found) => found,
                    None => break,
                },
            };
            chain.push(Ancestor {
                buzz_id: id.clone(),
                author,
            });
            pending = parent;
        }
        Ok(chain)
    }

    /// Fetch one event by id over HTTP `/query`, signed by the reader.
    fn fetch_event(&mut self, id: &str) -> Result<Option<(String, Option<String>)>> {
        // The relay refuses an unscoped filter, so kinds always ride along.
        let filter = json!({ "ids": [id], "kinds": store::CHANNEL_KINDS });
        let tag = serde_json::to_string(&self.connector.reader_auth_tag()).unwrap_or_default();
        match self
            .connector
            .http
            .query(&filter, &self.connector.reader.key, Some(&tag))
        {
            Ok(events) => Ok(events
                .into_iter()
                .find(|event| event.id == id)
                .map(|event| {
                    let (root, reply) = route::thread_refs(&event);
                    (event.pubkey, reply.or(root))
                })),
            Err(error) => {
                crate::log::log_warn("buzz", "serve.fetch_failed", &error.to_string());
                Ok(None)
            }
        }
    }

    /// Park a whole inbound event: every target is unroutable, so nothing is
    /// delivered and the retry window owns the outcome.
    fn park_all(&mut self, buzz_id: &str, targets: &[String]) -> Result<()> {
        let now = crate::shared::time::now_epoch_i64();
        let store = self.connector.store.lock();
        for target in targets {
            store.park_target(buzz_id, target, now)?;
        }
        crate::log::log_warn(
            "buzz",
            "serve.parked",
            &format!("{buzz_id}: {} has no deliverable row", targets.join(", ")),
        );
        Ok(())
    }

    /// Send one delivery as the person's hosted row.
    fn deliver_to_hcom(&mut self, buzz_id: &str, delivery: route::InboundDelivery) -> Result<()> {
        let thread = delivery.thread.clone();
        {
            let store = self.connector.store.lock();
            store.put_thread(&thread, &delivery.channel_id, &delivery.root_id)?;
        }
        let targets = delivery.targets.clone();
        let sender = delivery.sender.clone();
        let text = delivery.text.clone();

        match crate::commands::send::send_message(
            &self.db,
            &hosted_identity(&sender),
            &text,
            Some(&crate::messages::MessageEnvelope {
                thread: Some(thread),
                ..Default::default()
            }),
            Some(&targets),
        ) {
            Ok(delivered_to) => {
                // At least once: the Buzz id is recorded right after the send, so
                // a crash between the two repeats one message rather than
                // dropping it.
                let store = self.connector.store.lock();
                store.mark_delivered(buzz_id)?;
                crate::log::log_info(
                    "buzz",
                    "serve.delivered",
                    &format!("{sender} -> {} ({buzz_id})", delivered_to.join(",")),
                );
            }
            Err(error) => {
                // Park the targets: the cursor moves on regardless, so one
                // sleeping laptop cannot stall a channel.
                crate::log::log_warn(
                    "buzz",
                    "serve.deliver_refused",
                    &format!("{sender}: {error}"),
                );
                let now = crate::shared::time::now_epoch_i64();
                let store = self.connector.store.lock();
                for target in &targets {
                    store.park_target(buzz_id, target, now)?;
                }
            }
        }
        Ok(())
    }

    /// Roster event for one channel: record who is in it, host new people, and
    /// retire anyone gone from every bridged channel once the grace period ends.
    fn handle_roster(&mut self, event: &Event) -> Result<()> {
        let Some(channel_id) = route::tag(event, "d").map(str::to_string) else {
            return Ok(());
        };
        if !self
            .connector
            .channel_rows()
            .iter()
            .any(|c| c.id == channel_id)
        {
            return Ok(());
        }
        let now = crate::shared::time::now_epoch_i64();

        let mut here: Vec<String> = Vec::new();
        for (pubkey, role) in route::roster_members(event) {
            // Role `bot` is an owned agent, and the reader and omp are ours:
            // none of them is ever a person.
            if role == "bot"
                || pubkey == self.connector.reader.pubkey
                || pubkey == self.connector.owner_pubkey
            {
                continue;
            }
            let Some(name) = self.person_name_for(&pubkey) else {
                continue;
            };
            let home = self
                .connector
                .config
                .person_home(&pubkey)
                .map(str::to_string);
            self.connector
                .store
                .lock()
                .upsert_person(&pubkey, &name, home.as_deref())?;
            self.host_person(&name);
            here.push(pubkey);
        }
        self.connector
            .store
            .lock()
            .set_channel_members(&channel_id, &here)?;

        // A roster covers one channel. Someone absent from every bridged
        // channel starts the grace period; they stay a person until it ends,
        // so a single missing roster does not churn rows.
        let people = self.connector.store.lock().active_people()?;
        for person in people {
            if self
                .connector
                .store
                .lock()
                .is_member_anywhere(&person.pubkey)?
            {
                if person.left_at.is_some() {
                    self.connector
                        .store
                        .lock()
                        .clear_person_leaving(&person.pubkey)?;
                }
                continue;
            }
            match person.left_at {
                None => self
                    .connector
                    .store
                    .lock()
                    .mark_person_leaving(&person.pubkey, now)?,
                Some(left_at) if now.saturating_sub(left_at) >= PERSON_RETIRE_SECS => {
                    crate::log::log_info(
                        "buzz",
                        "serve.person_retired",
                        &format!("{} left every bridged channel", person.name),
                    );
                    self.connector
                        .store
                        .lock()
                        .retire_person(&person.pubkey, left_at)?;
                    self.connector
                        .hosted
                        .lock()
                        .retain(|row| row != &person.name);
                    if let Err(error) = crate::hosted::stop_hosted_row(
                        &self.db,
                        crate::hosted::HOSTED_TOOL_BUZZ,
                        &person.name,
                    ) {
                        crate::log::log_warn("buzz", "serve.person_stop", &error.to_string());
                    }
                }
                Some(_) => {}
            }
        }
        Ok(())
    }

    /// The hcom name for a roster member: the config override, else the name
    /// already stored for this pubkey (names are stable once assigned), else a
    /// new slug from their kind 0. None when a new member has no profile yet.
    fn person_name_for(&self, pubkey: &str) -> Option<String> {
        if let Some(name) = self.connector.config.person_name(pubkey) {
            return Some(name.to_string());
        }
        if let Ok(Some(person)) = self.connector.store.lock().person_by_pubkey(pubkey) {
            return Some(person.name);
        }
        let (slug, _) = self.profile_for(pubkey)?;
        // A name held by another Buzz person, or by a row that is not one of
        // our own `ch_` rows, gets the `_bz` suffix instead of being stolen.
        Some(config::unique_person_name(&slug, |candidate| {
            let held = self
                .connector
                .store
                .lock()
                .person_by_name(candidate)
                .ok()
                .flatten()
                .is_some_and(|other| other.pubkey != pubkey);
            held || self
                .db
                .get_instance_full(candidate)
                .ok()
                .flatten()
                .is_some_and(|row| !row.name.starts_with("ch_"))
        }))
    }

    /// Register one person's hosted row and its notify endpoint.
    fn host_person(&mut self, name: &str) {
        match crate::hosted::register_hosted(&self.db, name, crate::hosted::HOSTED_TOOL_BUZZ) {
            Ok(_) => {
                let _ = self.db.upsert_notify_endpoint(
                    name,
                    crate::notify::WakeKind::Listen.as_str(),
                    self.notify.port(),
                );
                let mut hosted = self.connector.hosted.lock();
                if !hosted.iter().any(|row| row == name) {
                    hosted.push(name.to_string());
                }
            }
            Err(error) => crate::log::log_warn(
                "buzz",
                "serve.register_refused",
                &format!("{name}: {error}"),
            ),
        }
    }

    /// A kind 0 event: cache the author's classification.
    ///
    /// The name comes from the profile's own marker, re-derived against this
    /// seed, so an agent is recognised even when its hcom row has gone — that is
    /// what lets an unresolvable target be parked instead of dropped.
    fn handle_profile(&mut self, event: &Event) -> Result<()> {
        let derived: HashMap<String, String> = self
            .all_known_identities()
            .into_iter()
            .map(|identity| (identity.pubkey, identity.canonical))
            .collect();
        let kind = route::classify_profile(
            &event.pubkey,
            event,
            &self.connector.owner_pubkey,
            &derived,
            &self.connector.seed,
        );
        let marker = serde_json::from_str::<Value>(&event.content)
            .ok()
            .and_then(|value| {
                value
                    .get("about")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            });
        let claimed = marker.as_deref().and_then(route::identity_from_marker);
        let author = match (kind, claimed) {
            (AuthorKind::Reader, _) => Author {
                pubkey: event.pubkey.clone(),
                kind,
                hcom_name: Some(self.connector.reader.name.clone()),
                device_label: Some(self.connector.reader.canonical.clone()),
            },
            (AuthorKind::Agent, Some((name, device))) => Author {
                pubkey: event.pubkey.clone(),
                kind,
                // As this device addresses it: a mirror is `name:DEVICE`, and
                // `agent_identity` re-derives the same key from that form.
                hcom_name: Some(if device == self.connector.config.device_label {
                    name
                } else {
                    format!("{name}:{}", device.to_uppercase())
                }),
                device_label: Some(device),
            },
            (kind, _) => Author {
                pubkey: event.pubkey.clone(),
                kind,
                hcom_name: None,
                device_label: None,
            },
        };
        let store = self.connector.store.lock();
        store.put_author(&author)?;
        Ok(())
    }

    /// Fetch a person's kind 0 over HTTP, signed by the reader.
    fn profile_for(&self, pubkey: &str) -> Option<(String, Event)> {
        let filter = json!({ "kinds": [route::KIND_PROFILE], "authors": [pubkey] });
        let tag = serde_json::to_string(&self.connector.reader_auth_tag()).unwrap_or_default();
        let events = self
            .connector
            .http
            .query(&filter, &self.connector.reader.key, Some(&tag))
            .ok()?;
        let profile = events.into_iter().next()?;
        let value: Value = serde_json::from_str(&profile.content).ok()?;
        let name = value
            .get("name")
            .or_else(|| value.get("display_name"))
            .and_then(Value::as_str)?;
        Some((config::person_slug(name), profile))
    }
}

/// A snapshot of everything outbound routing reads, taken under one lock so
/// the routing call does not hold the store.
struct OutboundInputs {
    people: Vec<PersonRow>,
    channels: Vec<ChannelRow>,
    threads: BTreeMap<String, (String, String)>,
    host_device: String,
}

/// A hosted row's sender identity. `SenderKind::Instance` gets real routing,
/// so an inbound Buzz message is delivered to its explicit targets only.
fn hosted_identity(name: &str) -> crate::shared::SenderIdentity {
    crate::shared::SenderIdentity {
        kind: crate::shared::SenderKind::Instance,
        name: name.to_string(),
        instance_data: Some(json!({
            "name": name,
            "tool": crate::hosted::HOSTED_TOOL_BUZZ,
        })),
        session_id: None,
    }
}

/// `exact_targets` recorded on an hcom message event.
fn exact_targets_of(db: &HcomDb, event_id: i64) -> Vec<String> {
    let raw = db
        .conn()
        .query_row(
            "SELECT data FROM events WHERE id = ?1",
            rusqlite::params![event_id],
            |row| row.get::<_, String>(0),
        )
        .ok();
    let Some(raw) = raw else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    value
        .get("exact_targets")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Backoff before retrying a parked inbound target.
fn park_retry_delay(attempts: u32) -> i64 {
    backoff(attempts, Duration::from_secs(15), Duration::from_secs(300))
        .as_secs()
        .max(1) as i64
}

/// Backoff before retrying a failed post.
fn post_retry_delay(attempts: u32) -> Duration {
    backoff(attempts, POST_BACKOFF_MIN, POST_BACKOFF_MAX)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::buzz::testing::FakeRelay;
    use serial_test::serial;

    const SEED: [u8; 32] = [7; 32];
    const CHANNEL_ID: &str = "11111111-2222-3333-4444-55555566666677";
    const OTHER_CHANNEL_ID: &str = "22222222-3333-4444-5555-666666777788";

    fn owner_key() -> SecretKey {
        SecretKey::from_bytes(&[3; 32]).unwrap()
    }
    fn human_key() -> SecretKey {
        nostr::derive_secret(&SEED, "human@test")
    }
    fn agent_key() -> SecretKey {
        nostr::derive_secret(&SEED, "luna@mbai")
    }

    /// TEST key material only: a seed file at mode 0600 and an owner env file.
    fn write_key_files(dir: &std::path::Path) {
        let seed_path = dir.join("seed.bin");
        std::fs::write(&seed_path, SEED).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&seed_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(
            dir.join("owner.env"),
            "BUZZ_PRIVATE_KEY=0303030303030303030303030303030303030303030303030303030303030303\n",
        )
        .unwrap();
    }

    /// The connector's config for the fake relay.
    ///
    /// Built in memory rather than round-tripped through the config file: the
    /// loader rightly refuses a plaintext relay URL, and the fake relay speaks
    /// plaintext HTTP on loopback. Config validation has its own tests; what
    /// these tests care about is the loop, not the file.
    fn test_config(relay: &FakeRelay, device: &str) -> Config {
        std::fs::create_dir_all(Config::dir()).unwrap();
        write_key_files(&Config::dir());
        Config {
            relay_url: relay.url.replace("http://", "ws://"),
            http_url: relay.url.clone(),
            device_label: device.to_string(),
            seed_path: std::path::PathBuf::from("seed.bin"),
            owner_env_path: std::path::PathBuf::from("owner.env"),
            local_signers: vec!["qa".to_string()],
            channels: vec![config::ChannelConfig {
                id: CHANNEL_ID.to_string(),
                slug: Some("infra".to_string()),
                home: false,
            }],
            people: vec![],
        }
    }

    /// An isolated HCOM_DIR, the fake relay, and the real main loop over the
    /// real databases. A test drives `step` directly, so it exercises production
    /// loop code rather than a stand-in for it.
    struct Harness {
        _dir: tempfile::TempDir,
        _guard: crate::hooks::test_helpers::EnvGuard,
        relay: FakeRelay,
        main: MainLoop,
        inbound: mpsc::Sender<InboundItem>,
    }

    impl Harness {
        /// Register a person row and its hosted participant.
        fn add_person(&mut self, name: &str, home: Option<&str>) -> String {
            let pubkey = public_hex(&human_key());
            self.main
                .connector
                .store
                .lock()
                .upsert_person(&pubkey, name, home)
                .unwrap();
            crate::hosted::register_hosted(&self.main.db, name, crate::hosted::HOSTED_TOOL_BUZZ)
                .unwrap();
            self.main.connector.hosted.lock().push(name.to_string());
            pubkey
        }

        /// Make the configured channel a home channel for one person.
        fn use_home_channel(&mut self, slug: &str, person: &str) {
            let mut config = self.main.connector.config.clone();
            config.channels = vec![config::ChannelConfig {
                id: CHANNEL_ID.to_string(),
                slug: Some(slug.to_string()),
                home: true,
            }];
            config.people = vec![config::PersonConfig {
                pubkey: public_hex(&human_key()),
                name: Some(person.to_string()),
                home: Some(slug.to_string()),
            }];
            self.main.connector.config = config;
        }

        /// Send an hcom message as `from`, the way the CLI would.
        fn send(&self, from: &str, text: &str, targets: &[&str], thread: Option<&str>) {
            let envelope = thread.map(|thread| crate::messages::MessageEnvelope {
                thread: Some(thread.to_string()),
                ..Default::default()
            });
            crate::commands::send::send_message(
                &self.main.db,
                &crate::shared::SenderIdentity {
                    kind: crate::shared::SenderKind::Instance,
                    name: from.to_string(),
                    instance_data: Some(json!({ "name": from })),
                    session_id: None,
                },
                text,
                envelope.as_ref(),
                Some(
                    &targets
                        .iter()
                        .map(|t| t.to_string())
                        .collect::<Vec<String>>(),
                ),
            )
            .expect("the message should be accepted");
        }

        /// Register an ordinary hcom agent row, the way `hcom start` would: a
        /// live participant with a normal tool, which is what makes it both
        /// addressable in hcom and visible to the connector's agent roster.
        fn add_agent(&self, name: &str) {
            let now = crate::shared::time::now_epoch_i64();
            let data = json!({
                "name": name,
                "tool": "claude",
                "status": "listening",
                "status_time": now,
                "status_context": "ready",
                "last_stop": now,
                "tcp_mode": 0,
                "last_event_id": self.main.db.get_last_event_id(),
                // A `name:DEVICE` row is a mirror of another device's agent.
                "origin_device_id": if name.contains(':') { "boxe-device-uuid" } else { "" },
                "directory": "",
                "transcript_path": "",
                "background": 0,
                "name_announced": 0,
                "created_at": crate::shared::time::now_epoch_f64(),
            });
            self.main
                .db
                .save_instance_named(name, data.as_object().unwrap())
                .unwrap();
        }

        fn offer(&self, event: Event) {
            self.inbound
                .send(InboundItem {
                    sub: sub_id("infra"),
                    event,
                })
                .unwrap();
        }

        /// Deliver an event on one channel's subscription.
        fn offer_on(&self, slug: &str, event: Event) {
            self.inbound
                .send(InboundItem {
                    sub: sub_id(slug),
                    event,
                })
                .unwrap();
        }

        /// Bridge a second channel, the way a config entry plus startup would.
        fn add_channel(&mut self, id: &str, slug: &str) {
            self.main
                .connector
                .config
                .channels
                .push(config::ChannelConfig {
                    id: id.to_string(),
                    slug: Some(slug.to_string()),
                    home: false,
                });
            let row = format!("ch_{slug}");
            crate::hosted::register_hosted(&self.main.db, &row, crate::hosted::HOSTED_TOOL_BUZZ)
                .unwrap();
            self.main.connector.hosted.lock().push(row);
        }

        fn step(&mut self) {
            self.main.step();
        }

        /// One loop pass per remaining unit of work, bounded: enrollment and the
        /// post that depends on it are separate HTTP writes, so a single pass can
        /// legitimately do only the first.
        fn step_until(&mut self, wanted: impl Fn(&Self) -> bool) {
            for _ in 0..8 {
                if wanted(self) {
                    return;
                }
                self.main.step();
            }
        }

        /// Kind 9 posts the agent key made, as the fake relay stored them.
        fn agent_posts(&self) -> Vec<Event> {
            self.relay
                .events()
                .into_iter()
                .filter(|e| e.kind == route::KIND_MESSAGE && e.pubkey == public_hex(&agent_key()))
                .collect()
        }

        fn unread(&self, row: &str) -> Vec<crate::db::Message> {
            self.main.db.get_unread_messages(row)
        }

        fn set_http_status(&self, status: u16) {
            self.relay
                .switches
                .http_status
                .store(status, std::sync::atomic::Ordering::SeqCst);
        }

        fn store(&self) -> parking_lot::MutexGuard<'_, Store> {
            self.main.connector.store.lock()
        }
    }

    fn harness(device: &str) -> Harness {
        let (_dir, _hcom_dir, _home, guard) = crate::hooks::test_helpers::isolated_test_env();
        let relay = FakeRelay::http();
        let config = test_config(&relay, device);
        let channel_rows: Vec<String> = config
            .channels
            .iter()
            .map(|c| format!("ch_{}", c.slug.clone().unwrap_or_else(|| c.id.clone())))
            .collect();
        let connector = Connector::load(config).unwrap();
        let db = HcomDb::open().unwrap();
        let epoch = hcom_epoch(&db).unwrap();
        let (main, inbound) = MainLoop::for_test(connector, db, epoch);

        // Startup registers one hosted row per bridged channel before the first
        // loop pass, so a test starts in the same state `serve` would.
        for row in &channel_rows {
            crate::hosted::register_hosted(&main.db, row, crate::hosted::HOSTED_TOOL_BUZZ).unwrap();
            main.connector.hosted.lock().push(row.clone());
        }
        Harness {
            _dir,
            _guard: guard,
            relay,
            main,
            inbound,
        }
    }

    fn message(key: &SecretKey, channel: &str, content: &str, tags: Vec<Vec<String>>) -> Event {
        let mut all = vec![vec!["h".into(), channel.to_string()]];
        all.extend(tags);
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_MESSAGE,
                tags: all,
                content: content.to_string(),
            },
            key,
        )
    }

    fn profile(key: &SecretKey, name: &str, about: &str) -> Event {
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_PROFILE,
                tags: vec![nostr::auth_tag(&owner_key(), &public_hex(key), "").to_vec()],
                content: json!({"name": name, "display_name": name, "about": about}).to_string(),
            },
            key,
        )
    }

    /// A kind 39002 roster for one channel: `(pubkey, role)` members.
    fn roster(channel: &str, members: &[(&str, &str)]) -> Event {
        let mut tags = vec![vec!["d".to_string(), channel.to_string()]];
        for (pubkey, role) in members {
            tags.push(vec![
                "p".into(),
                pubkey.to_string(),
                String::new(),
                role.to_string(),
            ]);
        }
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_ROSTER,
                tags,
                content: String::new(),
            },
            &owner_key(),
        )
    }

    #[test]
    #[serial]
    fn a_human_mention_becomes_an_hcom_message_from_that_person() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let event = message(
            &human_key(),
            CHANNEL_ID,
            "luna, deploy the thing",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(event.clone());
        harness.step();

        let messages = harness.unread("luna");
        assert_eq!(messages.len(), 1, "the mention reached the agent's row");
        assert_eq!(messages[0].from, "michael", "sent as the person");
        assert_eq!(messages[0].text, "luna, deploy the thing");
        assert!(
            messages[0]
                .thread
                .as_deref()
                .is_some_and(|t| t.starts_with("buzz_infra_")),
            "the thread is the Buzz correlation: {:?}",
            messages[0].thread
        );
        let store = harness.store();
        assert!(
            store.was_delivered(&event.id).unwrap(),
            "recorded as delivered"
        );
        assert!(
            store.cached_event(&event.id).unwrap().is_some(),
            "cached for read"
        );
    }

    #[test]
    #[serial]
    fn an_agent_send_posts_into_the_home_channel_and_enrolls_first() {
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        let michael = harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        // The agent addresses Michael: the message lands on the person's hosted
        // row, which the connector reads and posts as the agent.
        harness.send("luna", "please deploy", &["michael"], None);
        harness.step();

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1, "exactly one post: {posts:?}");
        assert_eq!(posts[0].content, "please deploy");
        assert_eq!(route::tag(&posts[0], "h"), Some(CHANNEL_ID));
        assert!(
            posts[0]
                .tags
                .iter()
                .any(|t| t.first().is_some_and(|n| n == "p") && t.get(1) == Some(&michael)),
            "Michael is p-tagged: {:?}",
            posts[0].tags
        );

        // Enrollment came first: kind 0, 30177, then omp's 9000 with role bot.
        let events = harness.relay.events();
        let agent_pubkey = public_hex(&agent_key());
        assert!(
            events
                .iter()
                .any(|e| e.kind == route::KIND_PROFILE && e.pubkey == agent_pubkey),
            "kind 0 published"
        );
        assert!(
            events
                .iter()
                .any(|e| { e.kind == 30177 && route::tag(e, "d") == Some(agent_pubkey.as_str()) })
        );
        let add = events
            .iter()
            .find(|e| e.kind == 9000 && route::tag(e, "p") == Some(agent_pubkey.as_str()))
            .expect("kind 9000 add");
        assert_eq!(route::tag(add, "h"), Some(CHANNEL_ID));
        assert_eq!(route::tag(add, "role"), Some("bot"));

        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("sent".to_string(), 1)]
        );
        assert!(harness.unread("michael").is_empty(), "the cursor advanced");
    }

    #[test]
    #[serial]
    fn a_send_from_another_device_posts_as_that_devices_identity() {
        // Requirement 3: `luna` on BOXE talks to Michael through the hcom relay.
        // The post is signed as luna@boxe, and the NIP-98 header must be too:
        // the relay refuses a header whose signer is not the event's author.
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.send("luna:BOXE", "from the laptop", &["michael"], None);
        harness.step_until(|h| {
            h.store()
                .outbox_counts()
                .unwrap()
                .iter()
                .any(|(state, _)| state == "sent" || state == "failed")
        });

        let remote = public_hex(&nostr::derive_secret(&SEED, "luna@boxe"));
        let posts: Vec<Event> = harness
            .relay
            .events()
            .into_iter()
            .filter(|e| e.kind == route::KIND_MESSAGE && e.pubkey == remote)
            .collect();
        assert_eq!(posts.len(), 1, "{:?}", harness.store().outbox_counts());
        assert_eq!(posts[0].content, "from the laptop");
        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("sent".to_string(), 1)]
        );
    }

    #[test]
    #[serial]
    fn a_channel_row_posts_once_in_that_channel() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.send("luna", "heads up", &["ch_infra"], None);
        harness.step();

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(route::tag(&posts[0], "h"), Some(CHANNEL_ID));
    }

    #[test]
    #[serial]
    fn a_broadcast_and_an_external_sender_never_reach_buzz() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");

        // A broadcast is not forwarded: nothing addresses a Buzz row.
        harness.send("luna", "everyone", &[], None);
        // An external sender has no Buzz identity at all.
        crate::commands::send::send_message(
            &harness.main.db,
            &crate::shared::SenderIdentity {
                kind: crate::shared::SenderKind::External,
                name: "ext_operator".into(),
                instance_data: None,
                session_id: None,
            },
            "from outside",
            None,
            Some(&["ch_infra".to_string()]),
        )
        .unwrap();
        harness.step();

        assert!(
            harness.agent_posts().is_empty(),
            "neither reached Buzz: {:?}",
            harness.agent_posts()
        );
        assert!(harness.store().unsent_outbox().unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn a_reply_under_a_remote_agents_post_reaches_its_mirror_row() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna:BOXE");
        let remote = nostr::derive_secret(&SEED, "luna@boxe");
        let post = message(&remote, CHANNEL_ID, "build is green", vec![]);
        harness.offer(post.clone());
        harness.offer(message(
            &human_key(),
            CHANNEL_ID,
            "nice, ship it",
            vec![vec![
                "e".into(),
                post.id.clone(),
                String::new(),
                "reply".into(),
            ]],
        ));
        harness.step();

        assert_eq!(
            harness.unread("luna:BOXE").len(),
            1,
            "the reply targets the mirror row, not a bare local `luna`"
        );
        assert!(
            harness.store().target_counts().unwrap().is_empty(),
            "nothing parked"
        );
    }

    #[test]
    #[serial]
    fn a_reply_in_a_buzz_thread_lands_in_that_thread() {
        let mut harness = harness("mbai");
        let michael = harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        // Michael asks the agent something in the channel.
        let root = message(
            &human_key(),
            CHANNEL_ID,
            "how is the deploy?",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(root.clone());
        harness.step();
        let thread = harness.unread("luna")[0].thread.clone().unwrap();

        // The agent answers with --reply-to, inheriting the buzz_* thread.
        harness.send("luna", "shipped", &["michael"], Some(&thread));
        harness.step();

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1, "one reply: {posts:?}");
        let reply = &posts[0];
        assert_eq!(reply.content, "shipped");
        assert_eq!(route::thread_refs(reply).1, Some(root.id.clone()));
        assert!(
            reply.tags.iter().any(|t| t.get(1) == Some(&michael)),
            "the human is tagged"
        );
    }

    #[test]
    #[serial]
    fn a_rate_limited_post_retries_without_duplicating() {
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        harness.set_http_status(429);
        harness.send("luna", "only once", &["michael"], None);
        harness.step();

        let buzz_id = {
            let store = harness.store();
            assert!(
                store
                    .outbox_counts()
                    .unwrap()
                    .iter()
                    .any(|(state, n)| state == "retry" && *n == 1),
                "the post waits instead of being lost"
            );
            assert!(
                harness.agent_posts().is_empty(),
                "nothing posted under the 429"
            );
            let row = store.unsent_outbox().unwrap();
            assert_eq!(row.len(), 1);
            row[0].buzz_id.clone()
        };

        // The quota window closes and the retry time arrives. Enrollment and the
        // post are separate writes, and enrollment's writes were rate limited
        // too, so give the loop the passes it needs.
        harness.set_http_status(0);
        harness
            .store()
            .retry_outbox(&buzz_id, 0, "rate limited")
            .unwrap();
        harness.step_until(|h| !h.agent_posts().is_empty());

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1, "exactly one post after the retry");
        assert_eq!(posts[0].id, buzz_id);
        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("sent".to_string(), 1)]
        );
    }

    #[test]
    #[serial]
    fn a_server_error_window_backs_off_and_does_not_exit() {
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        // A buzz-pg switchover: every HTTP call answers 503 for a while.
        harness.set_http_status(503);
        harness.send("luna", "during the switchover", &["michael"], None);
        harness.step();

        let buzz_id = {
            let store = harness.store();
            assert!(
                store
                    .outbox_counts()
                    .unwrap()
                    .iter()
                    .any(|(s, _)| s == "retry"),
                "the post waits instead of failing"
            );
            store.unsent_outbox().unwrap()[0].buzz_id.clone()
        };

        // The relay comes back and the queued post catches up on its own.
        harness.set_http_status(0);
        harness.store().retry_outbox(&buzz_id, 0, "503").unwrap();
        harness.step_until(|h| !h.agent_posts().is_empty());

        assert_eq!(
            harness.agent_posts().len(),
            1,
            "the post went out once the relay recovered"
        );
    }

    #[test]
    #[serial]
    fn a_rejected_post_fails_loudly_instead_of_retrying_forever() {
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        harness.set_http_status(400);
        harness.send("luna", "will be rejected", &["michael"], None);
        // Enrollment's own writes fail too under a 400, so the row is retried
        // rather than failed: only the post itself proves terminal handling.
        harness
            .main
            .connector
            .store
            .lock()
            .put_enrollment(&public_hex(&agent_key()), CHANNEL_ID, "enrolled")
            .unwrap();
        harness.step_until(|h| {
            h.store()
                .outbox_counts()
                .unwrap()
                .iter()
                .any(|(s, _)| s == "failed")
        });

        let store = harness.store();
        assert!(
            store
                .outbox_counts()
                .unwrap()
                .iter()
                .any(|(s, _)| s == "failed"),
            "a rejection is terminal: {:?}",
            store.outbox_counts().unwrap()
        );
        assert!(
            !store.recent_errors(5).unwrap().is_empty(),
            "the reason is kept"
        );
    }

    #[test]
    #[serial]
    fn a_restart_with_a_pending_outbox_posts_once() {
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        // The relay refuses everything, so the post stays queued while the
        // hosted cursor advances past the message.
        harness.set_http_status(503);
        harness.send("luna", "survives a restart", &["michael"], None);
        harness.step();
        assert!(harness.unread("michael").is_empty(), "the cursor advanced");
        assert!(harness.agent_posts().is_empty());

        let buzz_id = harness.store().unsent_outbox().unwrap()[0].buzz_id.clone();

        // A restart: a fresh loop over the same state, relay healthy again. The
        // message is not re-routed, and the queued post goes out once.
        harness.set_http_status(0);
        harness.store().retry_outbox(&buzz_id, 0, "503").unwrap();
        let (main, inbound) = MainLoop::for_test(
            harness.main.connector,
            harness.main.db,
            harness.main.epoch.clone(),
        );
        harness.main = main;
        harness.inbound = inbound;
        harness.step_until(|h| !h.agent_posts().is_empty());

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1, "no duplicate post after the restart");
        assert_eq!(posts[0].id, buzz_id);
    }

    #[test]
    #[serial]
    fn an_epoch_change_keeps_unposted_outbox_sendable() {
        let mut harness = harness("mbai");
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");

        harness.set_http_status(503);
        harness.send("luna", "queued before the reset", &["michael"], None);
        harness.step();
        let buzz_id = harness.store().unsent_outbox().unwrap()[0].buzz_id.clone();

        // `hcom reset` replaces the database, so the epoch the loop computes
        // differs from the one the store was opened with.
        harness.set_http_status(0);
        harness.store().retry_outbox(&buzz_id, 0, "503").unwrap();
        harness.main.epoch = "before-reset".to_string();
        let before = harness.main.epoch.clone();
        harness.step_until(|h| h.main.epoch != before);

        assert_ne!(
            harness.main.epoch, before,
            "the loop recomputed the epoch after hcom reset"
        );
        assert!(
            harness.agent_posts().iter().any(|e| e.id == buzz_id),
            "the unposted post still goes out after hcom reset"
        );
    }

    #[test]
    #[serial]
    fn an_unresolvable_target_is_parked_then_announced_in_buzz() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");

        // A mention of an agent that is known (its kind 0 is cached, so the
        // marker resolves it to a name) but whose session has ended: the send is
        // refused, so the target is parked rather than dropped.
        let ghost = nostr::derive_secret(&SEED, "ghost@mbai");
        // Its kind 0 is delivered, so the connector classifies it as an agent
        // and knows the name it claims — but no hcom row ever appears for it.
        harness.offer(profile(
            &ghost,
            "ghost",
            &format!("{}{}", route::AGENT_MARKER_PREFIX, "ghost@mbai"),
        ));
        harness.step();
        let event = message(
            &human_key(),
            CHANNEL_ID,
            "ghost, are you there?",
            vec![vec!["p".into(), public_hex(&ghost)]],
        );
        harness.offer(event.clone());
        harness.step();

        {
            let store = harness.store();
            assert!(
                store
                    .target_counts()
                    .unwrap()
                    .iter()
                    .any(|(state, n)| state == "parked" && *n == 1),
                "the unresolvable target is parked"
            );
        }

        // The window closes; the connector says so in Buzz, as omp. Age the row
        // first, then give the loop the pass that notices.
        harness.store().age_parked_target(&event.id, 0).unwrap();
        harness.step_until(|h| {
            h.relay
                .events()
                .iter()
                .any(|e| e.content.contains("isn't running"))
        });

        let notice = harness
            .relay
            .events()
            .into_iter()
            .find(|e| e.content.contains("isn't running"))
            .expect("the notice reached Buzz");
        assert!(notice.content.contains("ghost"), "{}", notice.content);
        assert_eq!(
            notice.pubkey,
            public_hex(&owner_key()),
            "posted as omp itself"
        );
        assert_eq!(route::thread_refs(&notice).1, Some(event.id.clone()));
        assert!(
            harness
                .store()
                .target_counts()
                .unwrap()
                .iter()
                .any(|(s, _)| s == "expired"),
            "the parked target is retired, not retried forever"
        );
    }

    #[test]
    #[serial]
    fn a_mention_of_an_enrolled_agent_whose_row_is_gone_is_parked() {
        // Live shape: the reader only subscribes to `#h` kinds, so an agent's
        // kind 0 never comes back to it. What the connector knows about a
        // finished session is what it published when it enrolled the agent.
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.main.last_enroll = Instant::now() - ENROLL_INTERVAL - Duration::from_secs(1);
        harness.step_until(|h| {
            h.store()
                .enrollment(&public_hex(&agent_key()), CHANNEL_ID)
                .ok()
                .flatten()
                .as_deref()
                == Some("enrolled")
        });
        assert!(harness.main.db.delete_instance("luna").unwrap());

        let event = message(
            &human_key(),
            CHANNEL_ID,
            "luna, still there?",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(event);
        harness.step();

        assert!(
            harness
                .store()
                .target_counts()
                .unwrap()
                .iter()
                .any(|(state, n)| state == "parked" && *n == 1),
            "the mention is parked for luna, not skipped as naming nobody"
        );
    }

    #[test]
    #[serial]
    fn a_target_that_is_deliverable_is_delivered_not_announced() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");

        let event = message(
            &human_key(),
            CHANNEL_ID,
            "luna, ping",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(event.clone());
        harness.step();
        assert_eq!(harness.unread("luna").len(), 1, "delivered straight away");
        assert!(harness.store().target_counts().unwrap().is_empty());
    }

    #[test]
    #[serial]
    fn a_forged_signature_is_refused() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let mut event = message(
            &human_key(),
            CHANNEL_ID,
            "trust me",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        // Same id, different content: verification must fail.
        event.content = "actually something else".into();
        harness.offer(event);
        harness.step();

        assert!(
            harness.unread("luna").is_empty(),
            "a tampered event never becomes an hcom message"
        );
    }

    #[test]
    #[serial]
    fn a_duplicate_relay_delivery_is_deduped() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let event = message(
            &human_key(),
            CHANNEL_ID,
            "only once",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(event.clone());
        harness.offer(event);
        harness.step();

        assert_eq!(harness.unread("luna").len(), 1, "one message, not two");
    }

    #[test]
    #[serial]
    fn an_edit_of_a_delivered_post_reaches_the_same_target() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");

        let original = message(
            &human_key(),
            CHANNEL_ID,
            "deploy at 3pm",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(original.clone());
        harness.step();
        assert_eq!(harness.unread("luna")[0].text, "deploy at 3pm");

        let edit = sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_EDIT,
                tags: vec![
                    vec!["h".into(), CHANNEL_ID.into()],
                    vec![
                        "e".into(),
                        original.id.clone(),
                        String::new(),
                        "root".into(),
                    ],
                    vec!["p".into(), public_hex(&agent_key())],
                ],
                content: "deploy at 4pm".into(),
            },
            &human_key(),
        );
        harness.offer(edit);
        harness.step();

        let messages = harness.unread("luna");
        assert_eq!(messages.len(), 2, "the edit is a second message");
        let edit_notice = messages.iter().find(|m| m.text.starts_with("(edited) "));
        let edit_notice =
            edit_notice.unwrap_or_else(|| panic!("expected an (edited) notice, got {messages:?}"));
        assert!(edit_notice.text.contains("deploy at 4pm"));
        assert_eq!(
            messages
                .iter()
                .find(|m| m.text == "deploy at 3pm")
                .and_then(|m| m.thread.clone()),
            edit_notice.thread,
            "the edit rides the same Buzz thread"
        );
    }

    #[test]
    #[serial]
    fn the_reader_is_enrolled_and_never_becomes_a_person() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.main.last_enroll = Instant::now() - ENROLL_INTERVAL - Duration::from_secs(1);
        harness.step();

        let reader_pubkey = harness.main.connector.reader.pubkey.clone();
        let events = harness.relay.events();

        // The reader has a kind 0, marked as the connector rather than as an
        // hcom agent, so a classifier can never read it as an agent.
        let reader_profile = events
            .iter()
            .find(|e| e.kind == route::KIND_PROFILE && e.pubkey == reader_pubkey)
            .expect("reader profile");
        let about = serde_json::from_str::<Value>(&reader_profile.content)
            .unwrap()
            .get("about")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        assert!(
            about.starts_with(route::READER_CANONICAL_PREFIX),
            "the reader carries the connector marker: {about}"
        );

        // It is a channel member with role bot, so a roster counts it as an
        // agent, never as a person.
        let add = events
            .iter()
            .find(|e| e.kind == 9000 && route::tag(e, "p") == Some(reader_pubkey.as_str()))
            .expect("the reader is enrolled as a bot");
        assert_eq!(route::tag(add, "role"), Some("bot"));

        let store = harness.store();
        assert!(
            store.person_by_pubkey(&reader_pubkey).unwrap().is_none(),
            "the reader is not a person"
        );
        assert!(
            store
                .person_by_pubkey(&harness.main.connector.owner_pubkey)
                .unwrap()
                .is_none(),
            "omp is not a person"
        );
    }

    #[test]
    #[serial]
    fn a_roster_creates_a_hosted_row_and_a_bot_does_not() {
        let mut harness = harness("mbai");
        let agent_pubkey = public_hex(&agent_key());
        let reader_pubkey = harness.main.connector.reader.pubkey.clone();
        let human_pubkey = public_hex(&human_key());

        // The connector needs the humans' kind 0 to slug their names.
        harness
            .relay
            .seed(profile(&human_key(), "Michael", "just a person"));
        harness.offer(sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_ROSTER,
                tags: vec![
                    vec!["d".into(), CHANNEL_ID.into()],
                    vec![
                        "p".into(),
                        human_pubkey.clone(),
                        String::new(),
                        "member".into(),
                    ],
                    vec![
                        "p".into(),
                        agent_pubkey.clone(),
                        String::new(),
                        "bot".into(),
                    ],
                    vec![
                        "p".into(),
                        reader_pubkey.clone(),
                        String::new(),
                        "member".into(),
                    ],
                ],
                content: String::new(),
            },
            &owner_key(),
        ));
        harness.step();

        let store = harness.store();
        let people = store.active_people().unwrap();
        assert_eq!(
            people.len(),
            1,
            "only the human became a person: {people:?}"
        );
        assert_eq!(people[0].name, "michael", "the profile name is slugged");
        assert!(store.person_by_pubkey(&agent_pubkey).unwrap().is_none());
        assert!(store.person_by_pubkey(&reader_pubkey).unwrap().is_none());

        // And the person's hcom row exists as a Buzz-hosted participant.
        let row = harness.main.db.get_instance_full("michael").unwrap();
        assert!(row.is_some(), "the roster created the hosted row");
        assert_eq!(row.unwrap().tool, crate::hosted::HOSTED_TOOL_BUZZ);
    }

    #[test]
    #[serial]
    fn a_person_keeps_their_name_across_rosters() {
        // Two bridged channels each send a roster at startup; the second one
        // for the same person must not rename them `michael_bz`.
        let mut harness = harness("mbai");
        let human = public_hex(&human_key());
        harness
            .relay
            .seed(profile(&human_key(), "Michael", "just a person"));
        harness.offer(roster(CHANNEL_ID, &[(&human, "member")]));
        harness.step();
        // A later roster (someone else joined) still lists Michael.
        let luna = public_hex(&agent_key());
        harness.offer(roster(CHANNEL_ID, &[(&human, "member"), (&luna, "bot")]));
        harness.step();

        let people = harness.store().active_people().unwrap();
        assert_eq!(
            people.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["michael"],
            "the stored name is reused, never suffixed against itself"
        );
        assert!(
            harness
                .main
                .db
                .get_instance_full("michael_bz")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[serial]
    fn another_channels_roster_does_not_retire_a_member() {
        let mut harness = harness("mbai");
        harness.add_channel(OTHER_CHANNEL_ID, "ops");
        harness.add_agent("luna");
        let human = public_hex(&human_key());
        harness
            .relay
            .seed(profile(&human_key(), "Michael", "just a person"));
        harness.offer(roster(CHANNEL_ID, &[(&human, "member")]));
        harness.step();
        // `ops` doesn't list Michael: he is still in #infra.
        harness.offer_on("ops", roster(OTHER_CHANNEL_ID, &[]));
        harness.step();
        assert_eq!(harness.store().active_people().unwrap().len(), 1);

        harness.offer(message(
            &human_key(),
            CHANNEL_ID,
            "luna, still with me?",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        ));
        harness.step();
        assert_eq!(harness.unread("luna").len(), 1, "his mention still lands");

        // Leaving #infra too starts the grace period: still a person until it
        // ends, then retired and the hosted row stopped.
        harness.offer(roster(CHANNEL_ID, &[]));
        harness.step();
        let left_at = {
            let person = harness.store().person_by_pubkey(&human).unwrap().unwrap();
            assert!(person.active, "the grace period keeps him a person");
            person.left_at.expect("leaving is recorded")
        };
        harness
            .store()
            .mark_person_leaving(&human, left_at - PERSON_RETIRE_SECS - 1)
            .unwrap();
        // The next roster (a distinct event: an agent was added) still lacks him.
        let luna = public_hex(&agent_key());
        harness.offer(roster(CHANNEL_ID, &[(&luna, "bot")]));
        harness.step();
        assert!(
            !harness
                .store()
                .person_by_pubkey(&human)
                .unwrap()
                .unwrap()
                .active
        );
        let row = harness
            .main
            .db
            .get_instance_full("michael")
            .unwrap()
            .unwrap();
        assert_eq!(row.status, "stopped", "the hosted row stops when he's gone");
    }

    #[test]
    #[serial]
    fn an_agent_whose_row_was_stopped_by_hand_comes_back() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);

        // The operator stops the row while the connector runs.
        harness
            .main
            .db
            .conn()
            .execute(
                "UPDATE instances SET status = 'stopped' WHERE name = 'michael'",
                [],
            )
            .unwrap();
        harness
            .main
            .connector
            .hosted
            .lock()
            .retain(|n| n != "michael");
        harness.step();

        let row = harness
            .main
            .db
            .get_instance_full("michael")
            .unwrap()
            .unwrap();
        assert_ne!(
            row.status, "stopped",
            "an active roster row is restored while the connector runs"
        );
    }

    #[test]
    #[serial]
    fn a_person_with_no_home_channel_gets_an_hcom_notice() {
        let mut harness = harness("mbai");
        // No home channel for this person and the only configured channel is a
        // plain stream, so addressing the person must not post.
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.send("luna", "hello", &["michael"], None);
        harness.step();

        assert!(
            harness.agent_posts().is_empty(),
            "nothing was posted for a person with no home channel"
        );
        let messages = harness.unread("luna");
        let notice = messages
            .iter()
            .find(|m| m.text.contains("no home channel"))
            .unwrap_or_else(|| panic!("expected a notice, got {messages:?}"));
        assert!(notice.from == "michael", "it comes from the person's row");
        assert!(notice.text.contains("@ch_warehouse"), "names the way out");
    }

    #[test]
    #[serial]
    fn token_buckets_and_backoff_stay_inside_their_bounds() {
        let mut bucket = TokenBucket::new(2, Duration::from_secs(60));
        assert!(bucket.take().is_ok());
        assert!(bucket.take().is_ok());
        assert!(bucket.take().is_err(), "the third call exceeds the budget");

        let first = backoff(0, Duration::from_secs(1), Duration::from_secs(60));
        assert!(
            (Duration::from_secs(1)..=Duration::from_millis(1100)).contains(&first),
            "the first backoff is the minimum plus jitter: {first:?}"
        );
        // Bounded at the maximum, with jitter on top but nowhere near 2x.
        let late = backoff(30, Duration::from_secs(1), Duration::from_secs(60));
        assert!(
            late >= Duration::from_secs(60) && late <= Duration::from_secs(66),
            "backoff stayed bounded: {late:?}"
        );

        let mut rolling = TokenBucket::new(1, Duration::from_millis(20));
        assert!(rolling.take().is_ok());
        assert!(rolling.take().is_err());
        std::thread::sleep(Duration::from_millis(30));
        assert!(rolling.take().is_ok(), "the window refilled");
    }

    #[test]
    #[serial]
    fn the_lock_refuses_a_second_connector() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serve.lock");
        let held = ServeLock::acquire(&path).unwrap();
        let second = ServeLock::acquire(&path);
        assert!(
            second.is_err(),
            "a live holder blocks a second serve: {:?}",
            second.err()
        );
        drop(held);
        assert!(
            ServeLock::acquire(&path).is_ok(),
            "releasing the lock lets a new connector start"
        );
    }

    #[test]
    #[serial]
    fn a_stale_lock_from_a_dead_process_is_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serve.lock");
        // Written without taking the lock, so only liveness can clear it.
        std::fs::write(&path, "4294967294\n").unwrap();
        assert!(!config::lock_holder_alive(4294967294));
        assert!(
            ServeLock::acquire(&path).is_ok(),
            "a dead holder must not block a restart"
        );
    }
}
