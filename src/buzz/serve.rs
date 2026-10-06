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
use std::sync::{Arc, Mutex, mpsc};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
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
    /// The hcom name, without any device suffix.
    pub name: String,
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
        let mut store = connector.store.lock().expect("store lock");
        store.adopt_epoch(epoch.clone())?;
    }

    // One notify endpoint, one port, every hosted row: `wake_all` dedupes by
    // port, so one wake reaches the connector for any row.
    let notify = crate::notify::NotifyServer::new().context("cannot bind notify endpoint")?;

    crate::sys::signal::register_term(&connector.shutdown);

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
        buckets: HashMap::new(),
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

/// Register or refresh every hosted row: active people plus one row per
/// bridged channel. A refusal is logged loudly and the row stays unhosted, so
/// nothing silently pretends to be bridged.
fn register_hosted_rows(db: &HcomDb, connector: &Connector, port: u16) {
    let people: Vec<String> = connector
        .store
        .lock()
        .expect("store lock")
        .active_people()
        .map(|people| people.into_iter().map(|p| p.name).collect())
        .unwrap_or_default();
    let mut names = people;
    names.extend(connector.channel_rows().iter().map(|c| c.row_name()));

    let mut hosted = connector.hosted.lock().expect("hosted lock");
    for name in &names {
        match crate::hosted::register_hosted(db, name, crate::hosted::HOSTED_TOOL_BUZZ) {
            Ok(_) => {
                let _ =
                    db.upsert_notify_endpoint(name, crate::notify::WakeKind::Listen.as_str(), port);
                if !hosted.contains(name) {
                    hosted.push(name.clone());
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
            .expect("store lock")
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
                if let Some(channel_id) = channel_for_sub(&handles.channels, &sub)
                    && let Ok(store) = handles.store.lock()
                {
                    let _ = store.set_channel_parked(&channel_id, Some(&reason));
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
        self.connector.hosted.lock().expect("hosted lock").clone()
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
            if let Ok(mut store) = self.connector.store.lock() {
                let _ = store.adopt_epoch(epoch);
            }
        }
        self.reregister_missing_rows();
        self.retry_parked_targets();
        self.scan_outbound();
        if self.last_stale_check.elapsed() >= Duration::from_secs(60) {
            self.last_stale_check = Instant::now();
            self.recheck_stale_outbox();
        }
    }

    /// Re-register any hosted row the store still calls active whose hcom row
    /// has gone (an operator `hcom stop`, a reset, a deletion).
    fn reregister_missing_rows(&mut self) {
        let port = self.notify.port();
        let people: Vec<String> = match self.connector.store.lock() {
            Ok(store) => store
                .active_people()
                .map(|people| people.into_iter().map(|p| p.name).collect())
                .unwrap_or_default(),
            Err(_) => return,
        };
        let mut wanted = people;
        wanted.extend(self.connector.channel_rows().iter().map(|c| c.row_name()));

        let mut hosted = self.connector.hosted.lock().expect("hosted lock");
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
        let due = match self.connector.store.lock() {
            Ok(store) => store.due_targets(now).unwrap_or_default(),
            Err(_) => return,
        };
        for target in due {
            match self.deliver_parked(&target.buzz_id, &target.target) {
                Ok(true) => {
                    if let Ok(store) = self.connector.store.lock() {
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

            let parked_for = now.saturating_sub(target.first_parked_at.max(now));
            if parked_for < PARK_WINDOW.as_secs() as i64 {
                let attempts = target.attempts.saturating_add(1);
                let next = now + park_retry_delay(attempts);
                if let Ok(store) = self.connector.store.lock() {
                    let _ = store.update_target(&target.buzz_id, &target.target, "parked", next);
                }
                continue;
            }
            // The window is over: the channel is told, as omp, in the same
            // thread. The cursor moved on regardless, so nothing stalls.
            self.announce_undelivered(&target.buzz_id, &target.target);
            if let Ok(store) = self.connector.store.lock() {
                let _ = store.expire_targets(&target.buzz_id, &target.target);
            }
        }
    }

    /// Try one parked delivery. `Ok(true)` when it resolved.
    fn deliver_parked(&mut self, buzz_id: &str, target: &str) -> Result<bool> {
        let event = {
            let store = self.connector.store.lock().expect("store lock");
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
            let store = self.connector.store.lock().expect("store lock");
            match store.cached_event(buzz_id) {
                Ok(Some(cached)) => cached.channel_id,
                _ => return,
            }
        };
        let text = format!("{target} isn't running — not delivered");
        let identity = self.connector.agent_identity(OMP_ROW);
        let _thread = route::thread_name(&self.channel_slug(&channel_id), buzz_id);
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
            &identity.key,
        );
        match self.connector.http.post_event(&event, &identity.key, None) {
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
                    &format!("{}: {text}", identity.name),
                );
                if let Err(error) = crate::commands::send::send_message(
                    &self.db,
                    &hosted_identity(&sender),
                    &text,
                    Some(&crate::messages::MessageEnvelope {
                        thread: message.thread.clone(),
                        ..Default::default()
                    }),
                    Some(std::slice::from_ref(&identity.name)),
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
            signer_name: identity.name.clone(),
            signed_json: serde_json::to_string(&event).unwrap_or_default(),
            buzz_id: event.id.clone(),
            state: "pending".into(),
            attempts: 0,
            next_at: 0,
            last_error: None,
        };
        let queued = match self.connector.store.lock() {
            Ok(store) => store.enqueue_outbox(&row),
            Err(_) => return,
        };
        match queued {
            Ok(true) => crate::log::log_info(
                "buzz",
                "serve.queued",
                &format!("{} #{hcom_id} -> {}", identity.name, destination.channel_id),
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
        let store = self.connector.store.lock().expect("store lock");
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

    /// Post everything due for one Buzz channel.
    fn flush_channel(&mut self, channel_id: &str) {
        self.post_due(channel_id);
    }

    /// Post every due outbox row for one Buzz channel, honoring budgets.
    fn post_due(&mut self, channel_id: &str) {
        let now = crate::shared::time::now_epoch_i64();
        let due = match self.connector.store.lock() {
            Ok(store) => store.due_outbox(channel_id, now).unwrap_or_default(),
            Err(_) => return,
        };
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
                    if let Ok(store) = self.connector.store.lock() {
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
        let stale = match self.connector.store.lock() {
            Ok(store) => store
                .stale_outbox(now - STALE_RECHECK_AFTER.as_secs() as i64)
                .unwrap_or_default(),
            Err(_) => return,
        };
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
                    if let Ok(store) = self.connector.store.lock() {
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
                    if let Ok(store) = self.connector.store.lock() {
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
        if let Ok(store) = self.connector.store.lock() {
            let _ = store.retry_outbox(&row.buzz_id, next_at, error);
        }
    }

    fn fail_row(&self, row: &OutboxRow, error: &str) {
        crate::log::log_error(
            "buzz",
            "serve.post_failed",
            &format!("{} {}: {error}", row.signer_name, row.destination),
        );
        if let Ok(store) = self.connector.store.lock() {
            let _ = store.fail_outbox(&row.buzz_id, error);
        }
    }

    /// Bounded drain, used by shutdown.
    fn flush_outbox(&mut self, budget: Duration) {
        let deadline = Instant::now() + budget;
        while Instant::now() < deadline && !self.connector.shutdown.load(Ordering::SeqCst) {
            let pending: i64 = match self.connector.store.lock() {
                Ok(store) => store
                    .outbox_counts()
                    .unwrap_or_default()
                    .iter()
                    .filter(|(state, _)| state == "pending" || state == "retry")
                    .map(|(_, count)| *count)
                    .sum(),
                Err(_) => return,
            };
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
        let enrolled = self.connector.store.lock().ok().and_then(|store| {
            store
                .enrollment(&identity.pubkey, channel_id)
                .ok()
                .flatten()
        });
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
        if let Ok(store) = self.connector.store.lock() {
            let _ = store.put_enrollment(&identity.pubkey, channel_id, "enrolled");
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
        let enrollments = match self.connector.store.lock() {
            Ok(store) => store.enrollments().unwrap_or_default(),
            Err(_) => return,
        };
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
                && let Ok(store) = self.connector.store.lock()
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
            let store = self.connector.store.lock().expect("store lock");
            if !store.mark_seen(&event.id)? {
                return Ok(());
            }
        }

        let (root_id, parent_id) = route::thread_refs(&event);
        {
            let store = self.connector.store.lock().expect("store lock");
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

        let ancestry = self.load_ancestry(&event)?;
        let root = root_id.or(parent_id).unwrap_or_else(|| event.id.clone());
        let input = InboundEvent {
            event: event.clone(),
            channel: channel.clone(),
            root_id: root,
            ancestry,
        };

        let people = self.route_inputs_people()?;
        let roster = self.agent_roster();
        let kinds = self.author_kinds(&people);
        let delivered = self
            .connector
            .store
            .lock()
            .map(|store| store.was_delivered(&event.id))
            .unwrap_or(Ok(false))
            .unwrap_or(false);

        match route::route_inbound(&input, &people, &roster, &kinds, delivered) {
            route::Inbound::Skip(reason) => crate::log::log_info(
                "buzz",
                "serve.inbound_skipped",
                &format!("{}: {reason:?}", event.id),
            ),
            route::Inbound::Deliver(delivery) => self.deliver_to_hcom(&event.id, delivery)?,
        }
        Ok(())
    }

    /// Active people rows, as routing rows.
    fn route_inputs_people(&self) -> Result<Vec<PersonRow>> {
        let store = self.connector.store.lock().expect("store lock");
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
            .map(|store| {
                store
                    .authors_of_kind(AuthorKind::Agent)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|(pubkey, name)| name.map(|name| (pubkey, name)))
                    .collect()
            })
            .unwrap_or_default();
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
                .insert(identity.pubkey.clone(), identity.name.clone());
            roster.deliverable.insert(identity.name);
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
                let store = self.connector.store.lock().expect("store lock");
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

    /// Send one delivery as the person's hosted row.
    fn deliver_to_hcom(&mut self, buzz_id: &str, delivery: route::InboundDelivery) -> Result<()> {
        let thread = delivery.thread.clone();
        {
            let store = self.connector.store.lock().expect("store lock");
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
                let store = self.connector.store.lock().expect("store lock");
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
                let store = self.connector.store.lock().expect("store lock");
                for target in &targets {
                    store.park_target(buzz_id, target, now)?;
                }
            }
        }
        Ok(())
    }

    /// Roster event: upsert or retire people and re-key their hosted rows.
    fn handle_roster(&mut self, event: &Event) -> Result<()> {
        let members = route::roster_members(event);
        let now = crate::shared::time::now_epoch_i64();

        for (pubkey, role) in &members {
            // Role `bot` is an owned agent, and the reader and omp are ours:
            // none of them is ever a person.
            if role == "bot"
                || pubkey == &self.connector.reader.pubkey
                || pubkey == &self.connector.owner_pubkey
            {
                continue;
            }
            let Some((slug, profile)) = self.profile_for(pubkey) else {
                continue;
            };
            let _ = profile;
            let name = self
                .connector
                .config
                .person_name(pubkey)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    config::unique_person_name(&slug, |candidate| {
                        crate::hosted::is_hosted_tool(&tool_of(&self.db, candidate))
                            && !candidate.starts_with("ch_")
                            || self.connector.store.lock().is_ok_and(|store| {
                                store.person_by_name(candidate).is_ok_and(|p| p.is_some())
                            })
                    })
                });
            let home = self
                .connector
                .config
                .person_home(pubkey)
                .map(str::to_string);
            if let Ok(store) = self.connector.store.lock() {
                store.upsert_person(pubkey, &name, home.as_deref())?;
            }
            self.host_person(&name);
        }

        // Anyone the roster no longer lists leaves: first mark, then stop after
        // the grace period, so a single missing roster does not churn rows.
        let listed: std::collections::HashSet<String> =
            members.iter().map(|(pubkey, _)| pubkey.clone()).collect();
        let people = match self.connector.store.lock() {
            Ok(store) => store.active_people().unwrap_or_default(),
            Err(_) => return Ok(()),
        };
        for person in people {
            if listed.contains(&person.pubkey) {
                continue;
            }
            match person.left_at {
                None => {
                    if let Ok(store) = self.connector.store.lock() {
                        store.retire_person(&person.pubkey, now)?;
                    }
                }
                Some(left_at) if now.saturating_sub(left_at) >= PERSON_RETIRE_SECS => {
                    crate::log::log_info(
                        "buzz",
                        "serve.person_retired",
                        &format!("{} left every bridged channel", person.name),
                    );
                    if let Ok(store) = self.connector.store.lock() {
                        let _ = store.retire_person(&person.pubkey, left_at);
                    }
                }
                Some(_) => {}
            }
        }
        Ok(())
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
                let mut hosted = self.connector.hosted.lock().expect("hosted lock");
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
        let author = match kind {
            AuthorKind::Agent => {
                let identity = self
                    .all_known_identities()
                    .into_iter()
                    .find(|identity| identity.pubkey == event.pubkey);
                Author {
                    pubkey: event.pubkey.clone(),
                    kind,
                    hcom_name: identity.as_ref().map(|i| i.name.clone()),
                    device_label: Some(
                        identity
                            .as_ref()
                            .map(|i| i.canonical.clone())
                            .unwrap_or_default(),
                    ),
                }
            }
            AuthorKind::Reader => Author {
                pubkey: event.pubkey.clone(),
                kind,
                hcom_name: Some(self.connector.reader.name.clone()),
                device_label: Some(self.connector.reader.canonical.clone()),
            },
            _ => Author {
                pubkey: event.pubkey.clone(),
                kind,
                hcom_name: None,
                device_label: None,
            },
        };
        let store = self.connector.store.lock().expect("store lock");
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

/// omp's own row name. The connector posts its notices (an undelivered-target
/// notice, and nothing else) as this identity, so they are clearly not an
/// agent's message. It is derived like every other row: `omp@<device_label>`.
const OMP_ROW: &str = "omp";

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

/// `tool` of a row, for the hosted-row filter.
fn tool_of(db: &HcomDb, name: &str) -> String {
    db.get_instance_full(name)
        .ok()
        .flatten()
        .map(|row| row.tool)
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
