//! The connector process: one long-lived hcom participant host.
//!
//! Composition root and loops. Composition: config, keys, the lock, both
//! databases, hosted rows and one shared notify endpoint. Loops: a reader
//! thread that fetches every bridged channel into the inbox (live
//! subscriptions plus paged HTTP catch-up), and a main loop that owns hcom: it
//! handles the inbox, delivers inbound obligations and drains the outbox.
//!
//! Nothing here exits the process because the relay misbehaved. Only config and
//! key load failures at startup, and a lock held by a live process, return an
//! error.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::buzz::config::{self, Config};
use crate::buzz::nostr::{self, Event, SecretKey, UnsignedEvent, auth_tag, public_hex, sign};
use crate::buzz::relay::{HttpRelay, PublishError, RelayMsg, WsSession};
use crate::buzz::route::{self, AgentRoster, Ancestor, ChannelRow, InboundEvent, PersonRow};
use crate::buzz::store::{
    self, Author, AuthorKind, CachedEvent, InboxItem, Obligation, OutboxRow, OwedDelivery, Store,
};
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
/// Longest wait between tries of one channel's catch-up, of a pending inbox
/// item and of an unapplied roster: they retry forever, so they back off far.
const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(300);
/// HTTP calls per signing key per minute (the relay allows 300).
pub const HTTP_PER_MINUTE: usize = 240;
/// WS frames per 5 s window (the relay allows 50).
pub const WS_FRAMES_PER_WINDOW: usize = 40;
/// Connect/read timeout for the reader session.
const WS_TIMEOUT: Duration = Duration::from_secs(10);
/// Post retry backoff bounds.
const POST_BACKOFF_MIN: Duration = Duration::from_secs(1);
const POST_BACKOFF_MAX: Duration = Duration::from_secs(60);

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
    /// The reader key's HTTP budget. The relay limits per signing key, and
    /// both the reader thread (catch-up pages) and the main loop (ancestor
    /// and profile lookups) sign as the reader, so they draw from one bucket.
    pub reader_budget: SharedBudget,
    /// Channels that owe a follow-on catch-up: a revision whose original is
    /// absent waits for a catch-up begun after it arrived, and a healthy
    /// session runs none on its own. The main loop asks; the reader runs it.
    pub catch_up_requests: Arc<Mutex<BTreeSet<String>>>,
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

        let store = Store::open(&Config::state_db_path())?;

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
            reader_budget: SharedBudget::new(HTTP_PER_MINUTE, Duration::from_secs(60)),
            catch_up_requests: Arc::new(Mutex::new(BTreeSet::new())),
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
    pub fn auth_tag(&self, owner: &SecretKey) -> [String; 4] {
        auth_tag(owner, &self.pubkey, "")
    }

    /// Kind 0: display name, the hcom marker in `about`, NIP-OA tag.
    pub fn profile_event(&self, owner: &SecretKey) -> Event {
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
    pub fn managed_agent_event(&self, owner: &SecretKey) -> Event {
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
    pub fn add_member_event(&self, owner: &SecretKey, channel_id: &str) -> Event {
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

/// The hcom DB epoch: `hcom.db`'s on-disk identity plus kv
/// `relay_local_reset_ts`, as `{device}:{index}:{reset_ts}`.
///
/// The identity is `dev:ino` on Unix and `volume-serial:file-index` on
/// Windows (`sys::fs::file_identity`), `0:0` when the file can't be read, so a
/// replaced file changes the epoch even when the reset marker is unset.
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
    let (device, index) = crate::sys::fs::file_identity(&crate::paths::db_path()).unwrap_or((0, 0));
    Ok(format!("{device}:{index}:{reset_ts}"))
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

/// One signing key's token bucket shared between threads, plus the relay's
/// own `retry in Ns` hold for that key.
#[derive(Clone)]
pub struct SharedBudget {
    inner: Arc<Mutex<(TokenBucket, Option<Instant>)>>,
}

impl SharedBudget {
    pub fn new(capacity: usize, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new((TokenBucket::new(capacity, window), None))),
        }
    }

    /// Take one token, or say how long to wait.
    pub fn take(&self) -> Result<(), Duration> {
        let mut inner = self.inner.lock();
        if let Some(until) = inner.1 {
            let now = Instant::now();
            if now < until {
                return Err(until - now);
            }
            inner.1 = None;
        }
        inner.0.take()
    }

    /// Honor a 429's `retry in Ns` for every request this key signs.
    pub fn hold(&self, retry_after: Duration) {
        let until = Instant::now() + retry_after.max(Duration::from_secs(1));
        let mut inner = self.inner.lock();
        inner.1 = Some(inner.1.map_or(until, |held| held.max(until)));
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
                Some(pid) if crate::sys::process::is_alive(pid) => {
                    bail!(
                        "the Buzz connector lock is held by pid {pid} (hcom buzz serve or a cursor command)"
                    );
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
                bail!("the Buzz connector lock is held (hcom buzz serve or a cursor command)");
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
    let started = nostr::now();
    for channel in connector.channel_rows() {
        {
            // The row holds the durable read position. A channel bridged for
            // the first time starts at now: it has no history the connector
            // owes anyone, and recording that keeps a later restart's
            // catch-up from starting at whatever "now" is then.
            let store = connector.store.lock();
            let _ = store.upsert_channel(&channel.id, &channel.slug);
            let _ = store.start_position(&channel.id, started);
        }
        enroll_reader(&connector, &channel.id, &mut buckets);
    }

    let handles = reader_handles(&connector);
    let reader_thread = std::thread::Builder::new()
        .name("buzz-reader".into())
        .spawn(move || reader_loop(handles))
        .context("cannot spawn reader thread")?;

    let shutdown_flag = connector.shutdown.clone();
    let mut main = MainLoop {
        connector,
        db,
        notify,
        epoch,
        last_enroll: Instant::now(),
        buckets,
        held_until: HashMap::new(),
        draining: false,
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
    /// `/query` for catch-up: pageable, unlike a REQ's single stored batch.
    http: HttpRelay,
    reader: AgentIdentity,
    reader_auth_tag: [String; 4],
    budget: SharedBudget,
    channels: Vec<ChannelRow>,
    store: Arc<Mutex<Store>>,
    /// Follow-on catch-ups the main loop asked for, by channel id.
    catch_up_requests: Arc<Mutex<BTreeSet<String>>>,
    shutdown: Arc<AtomicBool>,
}

/// What the reader thread takes from the connector.
fn reader_handles(connector: &Connector) -> ReaderHandles {
    ReaderHandles {
        relay_url: connector.config.relay_url.clone(),
        http: HttpRelay {
            base_url: connector.config.http_url.clone(),
        },
        reader: connector.reader.clone(),
        reader_auth_tag: connector.reader_auth_tag(),
        budget: connector.reader_budget.clone(),
        channels: connector.channel_rows(),
        store: connector.store.clone(),
        catch_up_requests: connector.catch_up_requests.clone(),
        shutdown: connector.shutdown.clone(),
    }
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

/// The reader thread: one WS session as the reader key, and every fetched
/// event stored straight into the inbox. Every (re)connect opens one live REQ
/// per channel first; a channel is caught up over paged HTTP `/query` once its
/// REQ is answered, so anything published after the catch-up's last page
/// still arrives live. A failed session backs off 1 s → 60 s; only a session
/// that stayed up resets the backoff.
fn reader_loop(handles: ReaderHandles) {
    let mut attempt = 0u32;
    while !handles.shutdown.load(Ordering::SeqCst) {
        let started = Instant::now();
        match WsSession::connect(
            &handles.relay_url,
            &handles.reader.key,
            Some(handles.reader_auth_tag.clone()),
            WS_TIMEOUT,
        ) {
            Ok(mut session) => {
                if run_session(&mut session, &handles) {
                    return;
                }
            }
            Err(error) => {
                crate::log::log_warn("buzz", "serve.reader_connect", &error.to_string());
            }
        }
        if started.elapsed() >= HEALTHY_SESSION {
            attempt = 0;
        }
        let wait = backoff(attempt, BACKOFF_MIN, BACKOFF_MAX);
        attempt = attempt.saturating_add(1);
        crate::log::log_warn(
            "buzz",
            "serve.reader_reconnect",
            &format!("reconnecting in {}s", wait.as_secs().max(1)),
        );
        if sleep_unless(&handles.shutdown, wait) {
            return;
        }
    }
}

/// A session that lasted this long was healthy: the next failure starts the
/// backoff over rather than continuing it.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);
/// Events asked for per catch-up page. The relay clamps this to its own
/// maximum; the walk doesn't care, because only an empty page ends it.
const CATCH_UP_PAGE: usize = 500;

/// One session: subscribe, then pump, catching each channel up once its
/// subscription is answered. True when shutting down.
fn run_session(session: &mut WsSession, handles: &ReaderHandles) -> bool {
    // The live filter starts the relay's admission window (plus skew) before
    // now: a publication backdated by up to 900 s that arrives live after the
    // catch-up's last page is still inside it.
    let live_since = nostr::now().saturating_sub(store::BACKFILL_SLACK_SECS);
    if let Err(error) = subscribe_all(session, handles, live_since) {
        crate::log::log_warn("buzz", "serve.reader_subscribe", &error.to_string());
        return false;
    }
    pump_session(session, handles, live_since)
}

/// Catch one channel up: everything from its read position less the admission
/// slack to now, plus its newest roster, stored in one transaction that moves
/// the position. An error stores nothing and moves nothing.
fn catch_up(handles: &ReaderHandles, channel: &ChannelRow) -> Result<usize> {
    let started_at = crate::shared::time::now_epoch_f64();
    let position = handles
        .store
        .lock()
        .channel(&channel.id)?
        .and_then(|row| row.position);
    let since = position
        .map_or_else(nostr::now, |position| position.created_at)
        .saturating_sub(store::BACKFILL_SLACK_SECS);
    let mut events = walk_channel(handles, &channel.id, since)?;
    events.extend(newest_rosters(handles, &channel.id)?);
    handles
        .store
        .lock()
        .store_caught_up(&channel.id, &events, nostr::now(), started_at)
}

/// Every event in one channel from `since` on, or an error: never a partial
/// answer. Walks the relay's `created_at DESC, id ASC` order with the
/// composite `(until, before_id)` cursor from the last row of each page
/// (`until` alone re-reads a same-second batch and loses the rest of it), and
/// ends only on an empty page, because a short page may just be the relay
/// clamping its limit. A page that adds nothing, a cursor that doesn't move or
/// an event failing its own signature is an error. There is no count cap.
fn walk_channel(handles: &ReaderHandles, channel_id: &str, since: u64) -> Result<Vec<Event>> {
    let mut events = Vec::new();
    let mut ids = std::collections::HashSet::new();
    let mut cursor: Option<(u64, String)> = None;
    loop {
        // Always carry kinds: the relay refuses an unscoped query filter.
        let mut filter = json!({
            "kinds": store::CHANNEL_KINDS,
            "#h": [channel_id],
            "since": since,
            "limit": CATCH_UP_PAGE,
        });
        if let Some((until, before_id)) = &cursor {
            filter["until"] = json!(until);
            filter["before_id"] = json!(before_id);
        }
        let page = reader_query(handles, &filter)?;
        if page.is_empty() {
            return Ok(events);
        }
        if let Some(bad) = page.iter().find(|event| !nostr::verify(event)) {
            bail!("relay returned {} failing its own signature check", bad.id);
        }
        // The last row in the relay's order: the oldest second, and the
        // largest id within it.
        let last = page
            .iter()
            .min_by(|a, b| {
                a.created_at
                    .cmp(&b.created_at)
                    .then_with(|| b.id.cmp(&a.id))
            })
            .map(|event| (event.created_at, event.id.clone()))
            .expect("page is not empty");
        let known = ids.len();
        for event in page {
            if ids.insert(event.id.clone()) {
                events.push(event);
            }
        }
        if ids.len() == known {
            bail!("relay repeated a page without advancing; refusing an incomplete catch-up");
        }
        if cursor.as_ref() == Some(&last) {
            bail!("relay cursor did not advance; refusing an incomplete catch-up");
        }
        cursor = Some(last);
    }
}

/// A channel's roster, asked for by `d`. Rosters are replaceable, so the
/// newest can be older than any catch-up window, yet it is what names the
/// people whose messages the catch-up just fetched.
fn newest_rosters(handles: &ReaderHandles, channel_id: &str) -> Result<Vec<Event>> {
    let filter = json!({ "kinds": [route::KIND_ROSTER], "#d": [channel_id] });
    let rosters = reader_query(handles, &filter)?;
    if let Some(bad) = rosters.iter().find(|event| !nostr::verify(event)) {
        bail!(
            "relay returned roster {} failing its own signature check",
            bad.id
        );
    }
    Ok(rosters
        .into_iter()
        .filter(|event| route::tag(event, "d") == Some(channel_id))
        .collect())
}

/// One `/query` signed as the reader, drawing on the reader key's shared
/// budget and waiting it out unless the process is stopping.
fn reader_query(handles: &ReaderHandles, filter: &Value) -> Result<Vec<Event>> {
    while let Err(wait) = handles.budget.take() {
        if sleep_unless(&handles.shutdown, wait) {
            bail!("shutting down");
        }
    }
    let tag = serde_json::to_string(&handles.reader_auth_tag)?;
    handles
        .http
        .query(filter, &handles.reader.key, Some(&tag))
        .map_err(|error| {
            if let PublishError::RateLimited { retry_after } = &error {
                handles.budget.hold(*retry_after);
            }
            anyhow!("{error}")
        })
}

/// Store one live event. A bad signature is logged and dropped: the relay
/// hands the genuine event to the next catch-up. The position moves only once
/// this session caught the channel up; before that, a live event newer than
/// the unfetched gap must not carry the position past it. An error means the
/// event isn't stored, so the session ends and the reconnect's catch-up
/// fetches it again.
fn ingest_live(
    handles: &ReaderHandles,
    channel_id: &str,
    event: Event,
    caught_up: bool,
) -> Result<()> {
    if !nostr::verify(&event) {
        crate::log::log_warn(
            "buzz",
            "serve.bad_signature",
            &format!("{} failed signature verification", event.id),
        );
        return Ok(());
    }
    handles.store.lock().store_fetched(
        channel_id,
        std::slice::from_ref(&event),
        caught_up.then(nostr::now),
    )?;
    Ok(())
}

/// The live filter for one channel.
fn live_filter(channel_id: &str, since: u64) -> Value {
    // Always carry kinds: the relay refuses an unscoped query filter.
    json!({
        "kinds": store::CHANNEL_KINDS,
        "#h": [channel_id],
        "since": since,
    })
}

/// Open one live subscription per channel, staggered under the WS frame budget.
fn subscribe_all(session: &mut WsSession, handles: &ReaderHandles, since: u64) -> Result<()> {
    let mut budget = TokenBucket::new(WS_FRAMES_PER_WINDOW, Duration::from_secs(5));
    for (index, channel) in handles.channels.iter().enumerate() {
        if let Err(wait) = budget.take() {
            sleep(Duration::from_millis(100).min(wait));
            budget.take().ok();
        }
        if index > 0 {
            sleep(REQ_STAGGER);
        }
        session.req(&sub_id(&channel.slug), &[live_filter(&channel.id, since)])?;
    }
    Ok(())
}

/// Subscription id for a channel slug.
fn sub_id(slug: &str) -> String {
    format!("buzz-{slug}")
}

/// One channel's read state within a session. Each channel runs on its own
/// schedule, so one failing or closed channel never holds the others.
#[derive(Default)]
struct ChannelSync {
    /// A catch-up completed this session: live events may move the position.
    caught_up: bool,
    /// The subscription is answered and a catch-up is owed, from this time.
    catch_up_at: Option<Instant>,
    /// Catch-up failures in a row, for this channel's backoff.
    failures: u32,
    /// CLOSED: request the subscription again at this time.
    reopen_at: Option<Instant>,
    /// CLOSED answers in a row, for this channel's backoff.
    closes: u32,
}

/// Read one session until it fails or the process stops. True when shutting
/// down; false hands the session back to the reconnect loop.
///
/// A channel's catch-up runs once its subscription is answered (EOSE), and
/// again with backoff if it fails. A CLOSED channel is parked and requested
/// again with backoff (the usual cause, not yet being a member, fixes itself
/// once omp's 9000 lands); when it is answered it gets a full catch-up, so the
/// gap while it was closed is drained from the old position, not skipped. A
/// caught-up channel also runs one follow-on catch-up when the main loop asks
/// for it through `catch_up_requests`.
fn pump_session(session: &mut WsSession, handles: &ReaderHandles, since: u64) -> bool {
    let mut sync: HashMap<String, ChannelSync> = handles
        .channels
        .iter()
        .map(|channel| (channel.id.clone(), ChannelSync::default()))
        .collect();
    while !handles.shutdown.load(Ordering::SeqCst) {
        for channel in &handles.channels {
            let state = sync
                .get_mut(&channel.id)
                .expect("every channel has a state");
            let now = Instant::now();
            if state.reopen_at.is_some_and(|at| at <= now) {
                if let Err(error) =
                    session.req(&sub_id(&channel.slug), &[live_filter(&channel.id, since)])
                {
                    crate::log::log_warn("buzz", "serve.reader_error", &error.to_string());
                    return false;
                }
                // Wait for the answer before scheduling another try.
                state.reopen_at = Some(now + BACKOFF_MAX);
            }
            if state.catch_up_at.is_some_and(|at| at <= now) {
                match catch_up(handles, channel) {
                    Ok(stored) => {
                        state.caught_up = true;
                        state.catch_up_at = None;
                        state.failures = 0;
                        crate::log::log_info(
                            "buzz",
                            "serve.caught_up",
                            &format!("{}: {stored} new event(s)", channel.slug),
                        );
                    }
                    Err(error) => {
                        state.failures = state.failures.saturating_add(1);
                        let wait = backoff(state.failures, BACKOFF_MIN, RETRY_BACKOFF_MAX);
                        state.catch_up_at = Some(Instant::now() + wait);
                        crate::log::log_warn(
                            "buzz",
                            "serve.catch_up_failed",
                            &format!(
                                "{}: {error}; retrying in {}s",
                                channel.slug,
                                wait.as_secs().max(1)
                            ),
                        );
                    }
                }
                if handles.shutdown.load(Ordering::SeqCst) {
                    return true;
                }
            }
            // A revision waiting on an absent original asked for a catch-up
            // begun after it arrived. A caught-up channel runs one next pass;
            // one not caught up yet keeps the request until it is.
            if state.caught_up
                && state.catch_up_at.is_none()
                && handles.catch_up_requests.lock().remove(&channel.id)
            {
                state.catch_up_at = Some(Instant::now());
            }
        }

        match session.recv(Duration::from_millis(500)) {
            Err(error) => {
                crate::log::log_warn("buzz", "serve.reader_error", &error.to_string());
                return false;
            }
            Ok(None) => {}
            Ok(Some(RelayMsg::Event { sub, event })) => {
                let Some(channel) = channel_for_sub(&handles.channels, &sub) else {
                    crate::log::log_warn("buzz", "serve.unknown_sub", &sub);
                    continue;
                };
                let state = sync
                    .get_mut(&channel.id)
                    .expect("every channel has a state");
                reopened(handles, state, channel);
                if let Err(error) = ingest_live(handles, &channel.id, event, state.caught_up) {
                    crate::log::log_warn(
                        "buzz",
                        "serve.store_failed",
                        &format!("{}: {error}; reconnecting to catch up", channel.slug),
                    );
                    return false;
                }
            }
            Ok(Some(RelayMsg::Eose(sub))) => {
                let Some(channel) = channel_for_sub(&handles.channels, &sub) else {
                    continue;
                };
                let state = sync
                    .get_mut(&channel.id)
                    .expect("every channel has a state");
                reopened(handles, state, channel);
                // From here on the subscription carries everything new, so a
                // catch-up now leaves no gap behind it.
                if !state.caught_up && state.catch_up_at.is_none() {
                    state.catch_up_at = Some(Instant::now());
                }
                crate::log::log_info("buzz", "serve.subscribed", &sub);
            }
            Ok(Some(RelayMsg::Closed { sub, reason })) => {
                let Some(channel) = channel_for_sub(&handles.channels, &sub) else {
                    continue;
                };
                // One closed subscription parks its channel; the rest keep
                // running, so a single failure never stops the connector.
                let _ = handles
                    .store
                    .lock()
                    .set_channel_parked(&channel.id, Some(&reason));
                let state = sync
                    .get_mut(&channel.id)
                    .expect("every channel has a state");
                state.caught_up = false;
                state.catch_up_at = None;
                let wait = backoff(state.closes, BACKOFF_MIN, BACKOFF_MAX);
                state.closes = state.closes.saturating_add(1);
                state.reopen_at = Some(Instant::now() + wait);
                crate::log::log_warn(
                    "buzz",
                    "serve.channel_closed",
                    &format!("{sub}: {reason}; retrying in {}s", wait.as_secs().max(1)),
                );
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

/// A closed subscription answered: its channel is live again.
fn reopened(handles: &ReaderHandles, state: &mut ChannelSync, channel: &ChannelRow) {
    if state.reopen_at.take().is_some() {
        state.closes = 0;
        let _ = handles.store.lock().set_channel_parked(&channel.id, None);
        crate::log::log_info("buzz", "serve.channel_unparked", &channel.slug);
    }
}

/// The channel behind a `buzz-<slug>` subscription id.
fn channel_for_sub<'a>(channels: &'a [ChannelRow], sub: &str) -> Option<&'a ChannelRow> {
    let slug = sub.strip_prefix("buzz-")?;
    channels.iter().find(|c| c.slug == slug)
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

/// The main loop. Owns hcom: it handles the inbox the reader thread fills,
/// delivers inbound obligations and drains the outbox.
struct MainLoop {
    connector: Connector,
    db: HcomDb,
    notify: crate::notify::NotifyServer,
    epoch: String,
    last_enroll: Instant,
    buckets: HashMap<String, TokenBucket>,
    /// A 429's `retry in Ns`, per signing key: every write by that key waits.
    held_until: HashMap<String, Instant>,
    /// True while shutdown drains the outbox: posting continues even though
    /// the shutdown flag is already set.
    draining: bool,
}

impl MainLoop {
    /// Build a loop around an already-loaded connector. A test stores events
    /// with `ingest_live`, exactly as the reader thread does.
    #[cfg(test)]
    fn for_test(connector: Connector, db: HcomDb, epoch: String) -> Self {
        Self {
            connector,
            db,
            notify: crate::notify::NotifyServer::new().expect("notify endpoint"),
            epoch,
            last_enroll: Instant::now(),
            buckets: HashMap::new(),
            held_until: HashMap::new(),
            draining: false,
        }
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

    /// One pass: heartbeat, epoch check, re-register, outbound.
    fn tick(&mut self) {
        if let Err(error) =
            crate::hosted::heartbeat_hosted(&self.db, crate::hosted::HOSTED_TOOL_BUZZ)
        {
            crate::log::log_warn("buzz", "serve.heartbeat", &error.to_string());
        }

        if let Ok(epoch) = hcom_epoch(&self.db)
            && epoch != self.epoch
        {
            self.adopt_new_database();
        }
        self.reregister_missing_rows();
        self.scan_outbound();
        self.flush_all_channels();
        // Finishes rows a crash left acknowledged but not yet logged.
        self.log_posted();
    }

    /// `hcom reset` replaced hcom.db: the open connection still points at the
    /// archived file, so every send and scan would go to a dead database. Open
    /// the new one, record its epoch, and host every row in it again.
    fn adopt_new_database(&mut self) {
        crate::log::log_warn(
            "buzz",
            "serve.epoch_changed",
            "hcom.db was replaced; reopening it and re-registering hosted rows",
        );
        let db = match HcomDb::open() {
            Ok(db) => db,
            Err(error) => {
                crate::log::log_error("buzz", "serve.reopen_failed", &error.to_string());
                return;
            }
        };
        self.db = db;
        let epoch = hcom_epoch(&self.db).unwrap_or_default();
        let _ = self.connector.store.lock().adopt_epoch(epoch.clone());
        self.epoch = epoch;
        self.connector.hosted.lock().clear();
        register_hosted_rows(&self.db, &self.connector, self.notify.port());
    }

    /// Re-register any hosted row the store still calls active whose hcom row
    /// is missing or stopped (an operator `hcom stop`, a deletion). The real
    /// row is checked, not the connector's own list, which a stop never edits.
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

        for name in wanted {
            let live = self
                .db
                .get_instance_full(&name)
                .ok()
                .flatten()
                .is_some_and(|row| !row.status.eq_ignore_ascii_case("stopped"));
            if live {
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
                    let mut hosted = self.connector.hosted.lock();
                    if !hosted.contains(&name) {
                        hosted.push(name);
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

    /// Work every due obligation: deliver it, or back it off, or (once its
    /// window closed) post the "isn't running" notice and close it. Each
    /// obligation is its own unit: one target failing never holds another,
    /// and nothing is dropped for failing.
    fn deliver_obligations(&mut self) {
        let now = crate::shared::time::now_epoch_i64();
        let due = match self.connector.store.lock().due_obligations(now) {
            Ok(due) => due,
            Err(error) => {
                crate::log::log_warn("buzz", "serve.obligations_unreadable", &error.to_string());
                return;
            }
        };
        for mut obligation in due {
            if obligation.state != "notice" {
                match self.deliver_obligation(&obligation) {
                    Ok(true) => {
                        if let Err(error) = self
                            .connector
                            .store
                            .lock()
                            .obligation_delivered(&obligation.buzz_id, &obligation.target)
                        {
                            // Sent but not recorded: the next pass sends it
                            // again. At least once, never lost.
                            crate::log::log_warn(
                                "buzz",
                                "serve.delivered_unrecorded",
                                &error.to_string(),
                            );
                        }
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => crate::log::log_warn(
                        "buzz",
                        "serve.deliver_failed",
                        &format!("{} -> {}: {error}", obligation.buzz_id, obligation.target),
                    ),
                }
                if now.saturating_sub(obligation.first_at) < store::OBLIGATION_WINDOW_SECS {
                    let attempts = obligation.attempts.saturating_add(1);
                    let _ = self.connector.store.lock().defer_obligation(
                        &obligation.buzz_id,
                        &obligation.target,
                        attempts,
                        now + park_retry_delay(attempts),
                    );
                    continue;
                }
                // The window closed. The notice is signed once and stored, so
                // however often posting it is retried, Buzz sees one notice.
                let notice = serde_json::to_string(&self.undelivered_notice(&obligation))
                    .expect("event serializes");
                if let Err(error) = self.connector.store.lock().obligation_notice(
                    &obligation.buzz_id,
                    &obligation.target,
                    &notice,
                ) {
                    crate::log::log_warn("buzz", "serve.notice_unrecorded", &error.to_string());
                    continue;
                }
                obligation.state = "notice".into();
                obligation.notice_json = Some(notice);
            }
            self.post_notice(&obligation);
        }
    }

    /// True when hcom can deliver to `name` now: a hosted row, or any row that
    /// isn't stopped. A name with no row at all is unroutable.
    fn is_routable(&self, name: &str) -> bool {
        self.db
            .get_instance_full(name)
            .ok()
            .flatten()
            .is_some_and(|row| {
                crate::hosted::is_hosted_tool(&row.tool)
                    || !row.status.eq_ignore_ascii_case("stopped")
            })
    }

    /// Send one target exactly what was routed for it: from the person, in the
    /// Buzz thread. `Ok(true)` once hcom delivered it.
    fn deliver_obligation(&mut self, obligation: &Obligation) -> Result<bool> {
        if !self.is_routable(&obligation.target) {
            return Ok(false);
        }
        let owed = &obligation.delivery;
        let delivered_to = crate::commands::send::send_message(
            &self.db,
            &hosted_identity(&owed.sender),
            &owed.text,
            Some(&crate::messages::MessageEnvelope {
                thread: Some(owed.thread.clone()),
                ..Default::default()
            }),
            Some(std::slice::from_ref(&obligation.target)),
        )
        .map_err(|error| anyhow!("{error}"))?;
        let reached = delivered_to.iter().any(|name| name == &obligation.target);
        if reached {
            crate::log::log_info(
                "buzz",
                "serve.delivered",
                &format!(
                    "{} -> {} ({})",
                    owed.sender, obligation.target, obligation.buzz_id
                ),
            );
        }
        Ok(reached)
    }

    /// The "isn't running — not delivered" notice for one closed obligation,
    /// as omp, in the thread the message belonged to. Posted as omp's own key:
    /// it is a relay member and the channel admin, so no enrollment or
    /// delegation is needed, and the notice reads as coming from omp rather
    /// than from whichever agent failed.
    fn undelivered_notice(&self, obligation: &Obligation) -> Event {
        let owed = &obligation.delivery;
        sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_MESSAGE,
                tags: route::message_tags(&route::Destination {
                    channel_id: owed.channel_id.clone(),
                    root_id: Some(owed.root_id.clone()),
                    mentions: Vec::new(),
                }),
                content: format!("{} isn't running — not delivered", obligation.target),
            },
            &self.connector.owner,
        )
    }

    /// Post a closed obligation's stored notice. Transient failures retry the
    /// same event with backoff; a notice the relay will never take closes the
    /// obligation with the reason logged.
    fn post_notice(&mut self, obligation: &Obligation) {
        let now = crate::shared::time::now_epoch_i64();
        let retry = |main: &mut Self, next_at: i64, why: &str| {
            crate::log::log_warn(
                "buzz",
                "serve.not_delivered_retry",
                &format!("{} {}: {why}", obligation.buzz_id, obligation.target),
            );
            let _ = main.connector.store.lock().defer_obligation(
                &obligation.buzz_id,
                &obligation.target,
                obligation.attempts.saturating_add(1),
                next_at,
            );
        };
        let Some(event) = obligation
            .notice_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<Event>(json).ok())
        else {
            crate::log::log_error(
                "buzz",
                "serve.not_delivered_failed",
                &format!(
                    "{} {}: unreadable notice",
                    obligation.buzz_id, obligation.target
                ),
            );
            let _ = self
                .connector
                .store
                .lock()
                .obligation_expired(&obligation.buzz_id, &obligation.target);
            return;
        };
        let owner_pubkey = self.connector.owner_pubkey.clone();
        if let Err(wait) = self.take_http_token(&owner_pubkey) {
            retry(
                self,
                now + wait.as_secs().max(1) as i64,
                "HTTP bucket exhausted",
            );
            return;
        }
        match self
            .connector
            .http
            .post_event(&event, &self.connector.owner, None)
        {
            Ok(()) => {
                crate::log::log_info(
                    "buzz",
                    "serve.not_delivered",
                    &format!("{}: {}", obligation.buzz_id, obligation.target),
                );
                let _ = self
                    .connector
                    .store
                    .lock()
                    .obligation_expired(&obligation.buzz_id, &obligation.target);
            }
            Err(PublishError::RateLimited { retry_after }) => {
                self.hold_key(&owner_pubkey, retry_after);
                retry(
                    self,
                    now + retry_after.as_secs().max(1) as i64,
                    "rate limited",
                );
            }
            Err(
                error @ (PublishError::Server(_)
                | PublishError::Transport(_)
                | PublishError::Timeout),
            ) => {
                let next = now + post_retry_delay(obligation.attempts).as_secs() as i64;
                retry(self, next, &error.to_string());
            }
            Err(error) => {
                crate::log::log_error(
                    "buzz",
                    "serve.not_delivered_failed",
                    &format!("{} {}: {error}", obligation.buzz_id, obligation.target),
                );
                let _ = self
                    .connector
                    .store
                    .lock()
                    .obligation_expired(&obligation.buzz_id, &obligation.target);
            }
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

    /// Read each hosted row's unread messages and route them. A row's cursor
    /// advances only past messages whose outbox rows committed: a store error
    /// stops that row here, and the next pass reads the rest again (re-queuing
    /// is a no-op by key).
    fn scan_outbound(&mut self) {
        for row in self.hosted_rows() {
            let messages = self.db.get_unread_messages(&row);
            let mut handled = None;
            for message in &messages {
                if let Err(error) = self.route_outbound_message(&row, message) {
                    crate::log::log_warn(
                        "buzz",
                        "serve.queue_failed",
                        &format!("{row} #{:?}: {error}; retrying next pass", message.event_id),
                    );
                    break;
                }
                handled = message.event_id.or(handled);
            }
            if let Some(id) = handled {
                let mut updates = serde_json::Map::new();
                updates.insert("last_event_id".into(), json!(id));
                crate::instances::update_instance_position(&self.db, &row, &updates);
            }
        }
    }

    /// Route one hcom message, queueing a signed post per destination. `Err`
    /// only when something owed to Buzz could not be committed.
    fn route_outbound_message(
        &mut self,
        hosted_row: &str,
        message: &crate::db::Message,
    ) -> Result<()> {
        let Some(hcom_id) = message.event_id else {
            return Ok(());
        };
        if route::is_unroutable_sender(&message.from) {
            crate::log::log_info(
                "buzz",
                "serve.sender_skipped",
                &format!("{hosted_row}: {} is not a Buzz identity", message.from),
            );
            return Ok(());
        }

        let identity = self.connector.agent_identity(&message.from);
        let outbound = route::HcomMessage {
            from: message.from.clone(),
            text: message.text.clone(),
            thread: message.thread.clone(),
            exact_targets: exact_targets_of(&self.db, hcom_id),
            delivered_to: message.delivered_to.clone().unwrap_or_default(),
        };
        let inputs = self.route_inputs()?;
        let ctx = route::OutboundContext {
            people: &inputs.people,
            channels: &inputs.channels,
            threads: &inputs.threads,
            host_device: &inputs.host_device,
        };

        let posts = match route::route_outbound(&outbound, &ctx) {
            route::Outbound::Drop => Vec::new(),
            route::Outbound::Post(posts) => posts,
            route::Outbound::Notice {
                sender,
                text,
                posts,
            } => {
                // Every addressed person's row reads this message; only the
                // one the notice comes from sends it, so the agent hears it once.
                if sender == hosted_row {
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
                posts
            }
        };
        // The hosted rows this message was for: their delivery status is
        // logged once the relay holds the post.
        let hosted = self.hosted_rows();
        let mut recipients: Vec<String> = outbound
            .delivered_to
            .iter()
            .filter(|name| hosted.contains(name))
            .cloned()
            .collect();
        if !recipients.iter().any(|name| name == hosted_row) {
            recipients.push(hosted_row.to_string());
        }
        for destination in posts {
            self.prepare_post(&identity, hcom_id, &destination, &message.text, &recipients)?;
        }
        Ok(())
    }

    /// Sign one post and store it before the hosted cursor moves. Signing
    /// first means the Buzz id is known before the send; storing it means
    /// every retry sends that same event.
    ///
    /// The event carries `["hcom", "<epoch>:<hcom id>"]`, so two distinct
    /// sends with the same text, signer, channel and second are two events,
    /// never one id that acknowledges both. A re-read of the same message is
    /// a no-op by key and keeps the event first stored.
    ///
    /// The outbox records `identity.row` (`luna`, or `luna:BOXE` for a
    /// mirror). The publisher re-derives the key from it for NIP-98, so it must
    /// carry the device: the bare name derives this device's key, and the
    /// relay refuses a header that doesn't match the event's author.
    fn prepare_post(
        &self,
        identity: &AgentIdentity,
        hcom_id: i64,
        destination: &route::Destination,
        text: &str,
        recipients: &[String],
    ) -> Result<()> {
        let store = self.connector.store.lock();
        let mut tags = route::message_tags(destination);
        tags.push(vec!["hcom".into(), format!("{}:{hcom_id}", store.epoch())]);
        let event = sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_MESSAGE,
                tags,
                content: route::post_content(text),
            },
            &identity.key,
        );
        let row = OutboxRow {
            epoch: store.epoch().to_string(),
            hcom_id,
            destination: destination.channel_id.clone(),
            signer_name: identity.row.clone(),
            signed_json: serde_json::to_string(&event)?,
            buzz_id: event.id.clone(),
            recipients: recipients.to_vec(),
            state: "pending".into(),
            attempts: 0,
            next_at: 0,
            last_error: None,
        };
        if store.prepare_outbox(&row)? {
            crate::log::log_info(
                "buzz",
                "serve.prepared",
                &format!("{} #{hcom_id} -> {}", identity.row, destination.channel_id),
            );
        }
        Ok(())
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
            if self.connector.shutdown.load(Ordering::SeqCst) && !self.draining {
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
                Ok(()) => self.mark_posted(&row, None),
                Err(PublishError::RateLimited { retry_after }) => {
                    // Per-key: this signer's every write waits, not just this row.
                    self.hold_key(&identity.pubkey, retry_after);
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
                // The relay refuses a created_at outside its ±900 s window
                // before it checks for a duplicate, so this says nothing about
                // whether it stored the event earlier: find out first.
                Err(PublishError::Rejected(message))
                    if message.contains("too far from server time") =>
                {
                    self.recover_rejected(&row, &identity);
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

    /// The relay holds the post: mark the row posted, then log the hcom
    /// delivery status (`log_posted`, which also finishes any row a crash
    /// left posted but unlogged).
    fn mark_posted(&mut self, row: &OutboxRow, found: Option<&Event>) {
        crate::log::log_info(
            "buzz",
            "serve.posted",
            &format!(
                "{} {} -> {}",
                row.signer_name,
                found.map_or(row.buzz_id.as_str(), |event| event.id.as_str()),
                row.destination
            ),
        );
        if let Err(error) = self.connector.store.lock().mark_outbox_posted(row, found) {
            // Not recorded: the next pass posts the same event again, and the
            // relay answers `duplicate:`.
            crate::log::log_warn("buzz", "serve.posted_unrecorded", &error.to_string());
            return;
        }
        self.log_posted();
    }

    /// Log the hcom delivery status of every posted row for its hosted
    /// recipients, then mark it logged. Runs right after an ack and on every
    /// tick, so a crash between the two is finished on restart.
    fn log_posted(&mut self) {
        let posted = match self.connector.store.lock().posted_unlogged() {
            Ok(posted) => posted,
            Err(error) => {
                crate::log::log_warn("buzz", "serve.posted_unreadable", &error.to_string());
                return;
            }
        };
        for row in posted {
            let detail = format!(
                "hcom #{} posted to Buzz {} as {}",
                row.hcom_id, row.destination, row.buzz_id
            );
            let logged = row.recipients.iter().try_for_each(|recipient| {
                self.db.log_status_event(
                    recipient,
                    crate::shared::ST_LISTENING,
                    &format!("deliver:{}", row.signer_name),
                    Some(&detail),
                    None,
                )
            });
            if let Err(error) = logged {
                crate::log::log_warn("buzz", "serve.status_unlogged", &error.to_string());
                continue;
            }
            if let Err(error) = self.connector.store.lock().mark_outbox_logged(&row) {
                crate::log::log_warn("buzz", "serve.status_unrecorded", &error.to_string());
            }
        }
    }

    /// A post refused as outside the admission window. First look up every
    /// prepared id; a found event is the ack. An empty lookup also needs a
    /// deletion lookup, since /query hides soft-deleted events. Only absence
    /// from both permits re-signing; a failed lookup keeps the prepared event.
    fn recover_rejected(&mut self, row: &OutboxRow, identity: &AgentIdentity) {
        let now = crate::shared::time::now_epoch_i64();
        let ids = match self.connector.store.lock().prepared_ids(row) {
            Ok(ids) if !ids.is_empty() => ids,
            Ok(_) => vec![row.buzz_id.clone()],
            Err(error) => {
                self.retry_row(row, now + 1, &format!("prepared ids unreadable: {error}"));
                return;
            }
        };
        if let Err(wait) = self.take_http_token(&identity.pubkey) {
            self.retry_row(
                row,
                now + wait.as_secs().max(1) as i64,
                "HTTP token bucket exhausted",
            );
            return;
        }
        let auth = identity.auth_tag(&self.connector.owner);
        let tag = serde_json::to_string(&auth).unwrap_or_default();
        let filter = json!({ "ids": ids, "kinds": store::CHANNEL_KINDS });
        let events = match self
            .connector
            .http
            .query(&filter, &identity.key, Some(&tag))
        {
            Ok(events) => events,
            Err(error) => {
                if let PublishError::RateLimited { retry_after } = &error {
                    self.hold_key(&identity.pubkey, *retry_after);
                }
                let next = now + post_retry_delay(row.attempts).as_secs() as i64;
                self.retry_row(row, next, &format!("lookup before re-sign failed: {error}"));
                return;
            }
        };
        if let Some(found) = events
            .iter()
            .find(|event| ids.contains(&event.id) && nostr::verify(event))
        {
            self.mark_posted(row, Some(found));
            return;
        }

        if let Err(wait) = self.take_http_token(&identity.pubkey) {
            self.retry_row(
                row,
                now + wait.as_secs().max(1) as i64,
                "HTTP token bucket exhausted before deletion lookup",
            );
            return;
        }
        // No #h: standard NIP-09 tombstones need not carry a channel tag.
        let filter = json!({ "kinds": [5, 9005], "#e": ids });
        match self
            .connector
            .http
            .query(&filter, &identity.key, Some(&tag))
        {
            Ok(events) => {
                if let Some(tombstone) = events.iter().find(|event| {
                    matches!(event.kind, route::KIND_DELETE | route::KIND_CHANNEL_DELETE)
                        && nostr::verify(event)
                        && event.tags.iter().any(|tag| {
                            tag.first().is_some_and(|key| key == "e")
                                && tag.get(1).is_some_and(|id| ids.contains(id))
                        })
                }) {
                    let recorded = self
                        .connector
                        .store
                        .lock()
                        .mark_outbox_deleted(row, &tombstone.id);
                    match recorded {
                        Ok(()) => crate::log::log_info(
                            "buzz",
                            "serve.rejected_but_deleted",
                            &format!(
                                "{} -> {}: deletion {} references a prepared id",
                                row.signer_name, row.destination, tombstone.id
                            ),
                        ),
                        Err(error) => {
                            self.retry_row(row, now + 1, &format!("deletion unrecorded: {error}"))
                        }
                    }
                } else {
                    self.resign_row(row, identity);
                }
            }
            Err(error) => {
                if let PublishError::RateLimited { retry_after } = &error {
                    self.hold_key(&identity.pubkey, *retry_after);
                }
                let next = now + post_retry_delay(row.attempts).as_secs() as i64;
                self.retry_row(row, next, &format!("deletion lookup failed: {error}"));
            }
        }
    }

    /// Re-sign an outbox row the relay holds no version of, with a fresh
    /// `created_at`. Only the timestamp changes, so the thread shape, mentions,
    /// hcom identity and content are exactly what the relay would have
    /// received; the new id joins the row's id history.
    fn resign_row(&mut self, row: &OutboxRow, identity: &AgentIdentity) {
        let Ok(previous) = serde_json::from_str::<Event>(&row.signed_json) else {
            self.fail_row(row, "unreadable signed event");
            return;
        };
        // Strictly newer than the original, so the id always changes even if
        // the clock stepped back; an identical id would make this a no-op.
        let event = sign(
            UnsignedEvent {
                created_at: nostr::now().max(previous.created_at + 1),
                kind: previous.kind,
                tags: previous.tags,
                content: previous.content,
            },
            &identity.key,
        );
        let signed = serde_json::to_string(&event).unwrap_or_default();
        if let Err(error) = self
            .connector
            .store
            .lock()
            .resign_outbox(row, &event.id, &signed)
        {
            crate::log::log_warn("buzz", "serve.resign_failed", &error.to_string());
            return;
        }
        crate::log::log_info(
            "buzz",
            "serve.resigned",
            &format!(
                "{} -> {}: {} is now {}",
                row.signer_name, row.destination, row.buzz_id, event.id
            ),
        );
    }

    /// Take one HTTP token for a signing key.
    fn take_http_token(&mut self, pubkey: &str) -> Result<(), Duration> {
        if let Some(until) = self.held_until.get(pubkey) {
            let now = Instant::now();
            if now < *until {
                return Err(*until - now);
            }
            self.held_until.remove(pubkey);
        }
        self.buckets
            .entry(pubkey.to_string())
            .or_insert_with(|| TokenBucket::new(HTTP_PER_MINUTE, Duration::from_secs(60)))
            .take()
    }

    /// Honor a 429's `retry in Ns` for every write by this key.
    fn hold_key(&mut self, pubkey: &str, retry_after: Duration) {
        let until = Instant::now() + retry_after.max(Duration::from_secs(1));
        let held = self.held_until.entry(pubkey.to_string()).or_insert(until);
        *held = (*held).max(until);
    }

    fn retry_row(&self, row: &OutboxRow, next_at: i64, error: &str) {
        crate::log::log_warn(
            "buzz",
            "serve.post_retry",
            &format!("{} {}: {error}", row.signer_name, row.destination),
        );
        if let Err(failure) = self
            .connector
            .store
            .lock()
            .retry_outbox(row, next_at, error)
        {
            crate::log::log_warn("buzz", "serve.retry_unrecorded", &failure.to_string());
        }
    }

    fn fail_row(&self, row: &OutboxRow, error: &str) {
        crate::log::log_error(
            "buzz",
            "serve.post_failed",
            &format!("{} {}: {error}", row.signer_name, row.destination),
        );
        if let Err(failure) = self.connector.store.lock().fail_outbox(row, error) {
            crate::log::log_warn("buzz", "serve.fail_unrecorded", &failure.to_string());
        }
    }

    /// Bounded drain, used by shutdown. Runs with the shutdown flag already
    /// set, so it posts under `draining` until the queue empties or time is up.
    fn flush_outbox(&mut self, budget: Duration) {
        let deadline = Instant::now() + budget;
        self.draining = true;
        while Instant::now() < deadline {
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
                break;
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
        self.draining = false;
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
                if let PublishError::RateLimited { retry_after } = &error {
                    self.hold_key(&event.pubkey, *retry_after);
                }
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
        let now = crate::shared::time::now_epoch_i64();
        let enrollments = self
            .connector
            .store
            .lock()
            .enrollments()
            .unwrap_or_default();

        // Track absence first: `missing` rows record when the agent's row went
        // away, and one that came back is enrolled again with no new writes,
        // because omp never removed it from the channel.
        for row in &enrollments {
            if row.agent_pubkey == self.connector.reader.pubkey {
                continue;
            }
            let present = roster.iter().any(|id| id.pubkey == row.agent_pubkey);
            let state = match (row.state.as_str(), present) {
                ("enrolled", false) => "missing",
                ("missing", true) => "enrolled",
                _ => continue,
            };
            let _ = self.connector.store.lock().put_enrollment(
                &row.agent_pubkey,
                &row.channel_id,
                state,
            );
        }

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

        for row in enrollments {
            let present = roster.iter().any(|id| id.pubkey == row.agent_pubkey);
            let missing_since = match row.state.as_str() {
                "missing" => row.updated_at,
                // Marked missing in this very pass.
                "enrolled" => now,
                _ => continue,
            };
            if present
                || row.agent_pubkey == self.connector.reader.pubkey
                || now.saturating_sub(missing_since) < ENROLL_STALE_SECS
            {
                continue;
            }
            let owner_pubkey = self.connector.owner_pubkey.clone();
            if let Err(wait) = self.take_http_token(&owner_pubkey) {
                crate::log::log_warn(
                    "buzz",
                    "serve.unenroll_throttled",
                    &format!("waiting {}s", wait.as_secs().max(1)),
                );
                continue;
            }
            // Built from the stored pubkey: the agent's row, and so its name,
            // is exactly what no longer exists.
            let event = sign(
                UnsignedEvent {
                    created_at: nostr::now(),
                    kind: 9001,
                    tags: route::remove_member_tags(&row.channel_id, &row.agent_pubkey),
                    content: String::new(),
                },
                &self.connector.owner,
            );
            match self
                .connector
                .http
                .post_event(&event, &self.connector.owner, None)
            {
                Ok(()) => {
                    let _ = self
                        .connector
                        .store
                        .lock()
                        .drop_enrollment(&row.agent_pubkey, &row.channel_id);
                    crate::log::log_info(
                        "buzz",
                        "serve.unenrolled",
                        &format!("{} left {}", row.agent_pubkey, row.channel_id),
                    );
                }
                Err(error) => crate::log::log_warn(
                    "buzz",
                    "serve.unenroll_failed",
                    &format!("{} {}: {error}", row.agent_pubkey, row.channel_id),
                ),
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

    /// One pass over the inbound side, in the model's order: configured
    /// people, then per channel its newest roster and its due inbox items
    /// (oldest first), then every due obligation. Nothing here drops work: a
    /// failure leaves the item or the obligation pending with backoff.
    fn drain_inbound(&mut self) {
        self.ensure_configured_people();
        let now = crate::shared::time::now_epoch_i64();
        for channel in self.connector.channel_rows() {
            self.apply_roster(&channel);
            let due = match self.connector.store.lock().due_inbox(&channel.id, now) {
                Ok(due) => due,
                Err(error) => {
                    crate::log::log_warn("buzz", "serve.inbox_unreadable", &error.to_string());
                    continue;
                }
            };
            for item in due {
                self.handle_item(&channel, item);
            }
        }
        self.deliver_obligations();
        if let Err(error) = self.connector.store.lock().finish_routed() {
            crate::log::log_warn("buzz", "serve.finish_failed", &error.to_string());
        }
    }

    /// Configured people are people from the first pass, before any roster
    /// names them. A configured person the rosters later retired stays
    /// retired: only a missing row is created.
    fn ensure_configured_people(&mut self) {
        let configured: Vec<(String, String, Option<String>)> = self
            .connector
            .config
            .people
            .iter()
            .filter_map(|person| {
                Some((
                    person.pubkey.clone(),
                    person.name.clone()?,
                    person.home.clone(),
                ))
            })
            .collect();
        for (pubkey, name, home) in configured {
            let created = self.connector.store.lock().insert_person_if_absent(
                &pubkey,
                &name,
                home.as_deref(),
            );
            match created {
                Ok(true) => self.host_person(&name),
                Ok(false) => {}
                Err(error) => crate::log::log_warn(
                    "buzz",
                    "serve.configured_person",
                    &format!("{name}: {error}"),
                ),
            }
        }
    }

    /// Adopt a channel's newest fetched roster and apply the saved one if it
    /// isn't applied yet. Runs before any of the channel's messages, so a
    /// sender a roster names is a person by the time their message is handled.
    fn apply_roster(&mut self, channel: &ChannelRow) {
        if let Err(error) = self.adopt_newest_roster(channel) {
            crate::log::log_warn(
                "buzz",
                "serve.roster_unreadable",
                &format!("{}: {error}", channel.slug),
            );
        }
        let now = crate::shared::time::now_epoch_i64();
        let saved = match self.connector.store.lock().saved_roster(&channel.id) {
            Ok(Some(saved)) if !saved.applied && saved.next_at <= now => saved,
            _ => return,
        };
        let outcome = serde_json::from_str::<Event>(&saved.json)
            .map_err(anyhow::Error::from)
            .and_then(|event| self.handle_roster(&channel.id, &event));
        let store = self.connector.store.lock();
        let result = match outcome {
            Ok(true) => store.roster_applied(&channel.id),
            Ok(false) | Err(_) => {
                let attempts = saved.attempts.saturating_add(1);
                let wait = backoff(attempts, BACKOFF_MIN, RETRY_BACKOFF_MAX).as_secs() as i64;
                if let Err(error) = &outcome {
                    crate::log::log_warn(
                        "buzz",
                        "serve.roster_failed",
                        &format!("{}: {error}", channel.slug),
                    );
                }
                store.defer_roster(&channel.id, attempts, now + wait.max(1))
            }
        };
        if let Err(error) = result {
            crate::log::log_warn("buzz", "serve.roster_unrecorded", &error.to_string());
        }
    }

    /// Save the newest of a channel's fetched rosters, if it is newer than the
    /// saved one, and settle every fetched roster item. Newest is NIP-01's
    /// rule for replaceable events: the later `created_at`, then the lower id.
    fn adopt_newest_roster(&mut self, channel: &ChannelRow) -> Result<()> {
        let store = self.connector.store.lock();
        let fetched = store.pending_rosters(&channel.id)?;
        if fetched.is_empty() {
            return Ok(());
        }
        let newer = |a: &CachedEvent, created_at: u64, id: &str| {
            a.created_at > created_at || (a.created_at == created_at && a.buzz_id.as_str() < id)
        };
        let mut newest: Option<&CachedEvent> = None;
        for roster in &fetched {
            let names_this_channel = serde_json::from_str::<Event>(&roster.json)
                .is_ok_and(|event| route::tag(&event, "d") == Some(channel.id.as_str()));
            if names_this_channel
                && newest.is_none_or(|best| newer(roster, best.created_at, &best.buzz_id))
            {
                newest = Some(roster);
            }
        }
        let saved = store.saved_roster(&channel.id)?;
        let newest = newest.filter(|roster| {
            saved
                .as_ref()
                .is_none_or(|saved| newer(roster, saved.created_at, &saved.buzz_id))
        });
        let settled: Vec<String> = fetched
            .iter()
            .map(|roster| roster.buzz_id.clone())
            .collect();
        store.adopt_roster(&channel.id, newest, &settled)
    }

    /// Handle one inbox item and record the outcome: done, routed (its
    /// obligations already written), or left pending with backoff.
    fn handle_item(&mut self, channel: &ChannelRow, item: InboxItem) {
        let buzz_id = item.event.buzz_id.clone();
        let outcome = self
            .handle_event(channel, &item.event)
            .unwrap_or_else(|error| Handled::Wait(error.to_string()));
        let store = self.connector.store.lock();
        let recorded = match outcome {
            Handled::Done => store.finish_item(&buzz_id),
            Handled::Routed => Ok(()),
            Handled::Wait(reason) => {
                let attempts = item.attempts.saturating_add(1);
                let wait = backoff(attempts, BACKOFF_MIN, RETRY_BACKOFF_MAX).as_secs() as i64;
                crate::log::log_warn(
                    "buzz",
                    "serve.inbound_pending",
                    &format!("{buzz_id}: {reason}; again in {}s", wait.max(1)),
                );
                store.defer_item(
                    &buzz_id,
                    attempts,
                    crate::shared::time::now_epoch_i64() + wait.max(1),
                    &reason,
                )
            }
        };
        if let Err(error) = recorded {
            crate::log::log_warn("buzz", "serve.inbound_unrecorded", &error.to_string());
        }
    }

    /// Decide one fetched event: who sent it, who it is for, and (when
    /// someone is) write their obligations.
    fn handle_event(&mut self, channel: &ChannelRow, cached: &CachedEvent) -> Result<Handled> {
        let event: Event = serde_json::from_str(&cached.json).context("stored event")?;
        match event.kind {
            // Rosters are adopted before messages; a stray one is settled.
            route::KIND_ROSTER => return Ok(Handled::Done),
            route::KIND_PROFILE => {
                self.handle_profile(&event)?;
                return Ok(Handled::Done);
            }
            _ => {}
        }

        let people = self.route_inputs_people()?;
        let kinds = self.author_kinds(&people);
        match kinds
            .get(&event.pubkey)
            .copied()
            .unwrap_or(AuthorKind::Unknown)
        {
            AuthorKind::Agent | AuthorKind::Owner | AuthorKind::Reader => {
                return Ok(Handled::Done);
            }
            AuthorKind::Person => {}
            AuthorKind::Unknown => {
                if self.known_not_a_person(channel, &event)? {
                    crate::log::log_info(
                        "buzz",
                        "serve.inbound_skipped",
                        &format!("{}: not a bridged person", event.id),
                    );
                    return Ok(Handled::Done);
                }
                return Ok(Handled::Wait("sender not known yet".into()));
            }
        }

        // An edit or deletion addresses a previous event through its `e` tag:
        // the routed check, the thread and the targets all follow that
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
        let (original, original_state) = if revision {
            let store = self.connector.store.lock();
            let state = store.inbox_state(&subject)?;
            if state.is_none() {
                let settled = store.caught_up_after(&channel.id, &event.id)?;
                drop(store);
                if !settled {
                    // Only a catch-up begun after this item arrived can show
                    // the original is absent, and a healthy session runs none
                    // on its own: ask the reader for one.
                    self.connector
                        .catch_up_requests
                        .lock()
                        .insert(channel.id.clone());
                    return Ok(Handled::Wait("its original is not fetched yet".into()));
                }
                crate::log::log_info(
                    "buzz",
                    "serve.inbound_skipped",
                    &format!("{}: original absent after channel catch-up", event.id),
                );
                return Ok(Handled::Done);
            }
            (
                store
                    .cached_event(&subject)?
                    .and_then(|cached| serde_json::from_str::<Event>(&cached.json).ok()),
                state,
            )
        } else {
            (None, None)
        };
        if original_state.as_deref() == Some("pending") {
            // Whether the revision reaches anyone depends on how the original
            // was routed, so it waits for that.
            return Ok(Handled::Wait("its original is not handled yet".into()));
        }
        let threaded = original.as_ref().unwrap_or(&event);
        let ancestry = self.load_ancestry(threaded)?;
        let (root_id, parent_id) = route::thread_refs(threaded);
        let root = root_id.or(parent_id).unwrap_or_else(|| threaded.id.clone());
        let input = InboundEvent {
            event: event.clone(),
            channel: channel.clone(),
            root_id: root,
            ancestry,
            original,
        };

        let roster = self.agent_roster();
        let routed = self.connector.store.lock().was_routed(&subject)?;
        match route::route_inbound(&input, &people, &roster, &kinds, routed) {
            route::Inbound::Skip(reason) => {
                crate::log::log_info(
                    "buzz",
                    "serve.inbound_skipped",
                    &format!("{}: {reason:?}", event.id),
                );
                Ok(Handled::Done)
            }
            route::Inbound::Deliver(delivery) => {
                let owed = OwedDelivery {
                    sender: delivery.sender,
                    thread: delivery.thread,
                    root_id: delivery.root_id,
                    channel_id: delivery.channel_id,
                    text: delivery.text,
                };
                self.connector.store.lock().route_item(
                    &event,
                    &delivery.targets,
                    &owed,
                    crate::shared::time::now_epoch_i64(),
                )?;
                crate::log::log_info(
                    "buzz",
                    "serve.routed",
                    &format!("{} -> {}", event.id, delivery.targets.join(",")),
                );
                Ok(Handled::Routed)
            }
        }
    }

    /// True when an unclassified author is known not to be a bridged person,
    /// so their message needs nothing: a retired person, a `bot` on the
    /// channel's roster, or an author absent from an applied roster at least
    /// as new as the message. Anything else may still become a person (a
    /// listed member whose profile isn't readable yet, a roster that predates
    /// them), so the message waits.
    fn known_not_a_person(&self, channel: &ChannelRow, event: &Event) -> Result<bool> {
        let store = self.connector.store.lock();
        if store
            .person_by_pubkey(&event.pubkey)?
            .is_some_and(|person| !person.active)
        {
            return Ok(true);
        }
        let Some(saved) = store.saved_roster(&channel.id)? else {
            return Ok(false);
        };
        let roster: Event = serde_json::from_str(&saved.json).context("saved roster")?;
        Ok(
            match route::roster_members(&roster)
                .into_iter()
                .find(|(pubkey, _)| pubkey == &event.pubkey)
            {
                Some((_, role)) => role == "bot",
                None => saved.applied && saved.created_at >= event.created_at,
            },
        )
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
        // A 429 or a 5xx mid-switchover is not "no such event": without the
        // ancestor a plain thread reply has no target, so the item stays
        // pending instead.
        let events = self
            .reader_query(&filter)
            .map_err(|error| anyhow!("ancestor {id}: {error}"))?;
        Ok(events
            .into_iter()
            .find(|event| event.id == id && nostr::verify(event))
            .map(|event| {
                let (root, reply) = route::thread_refs(&event);
                (event.pubkey, reply.or(root))
            }))
    }

    /// One `/query` signed as the reader, on the reader key's shared budget.
    /// An exhausted budget is an error the caller retries later; the main
    /// loop never sleeps on it.
    fn reader_query(&self, filter: &Value) -> Result<Vec<Event>> {
        let budget = &self.connector.reader_budget;
        if let Err(wait) = budget.take() {
            bail!(
                "reader HTTP budget exhausted; retry in {}s",
                wait.as_secs().max(1)
            );
        }
        let tag = serde_json::to_string(&self.connector.reader_auth_tag()).unwrap_or_default();
        self.connector
            .http
            .query(filter, &self.connector.reader.key, Some(&tag))
            .map_err(|error| {
                if let PublishError::RateLimited { retry_after } = &error {
                    budget.hold(*retry_after);
                }
                anyhow!("{error}")
            })
    }

    /// Apply a channel's roster: record who is in it, host new people, and
    /// retire anyone gone from every bridged channel once the grace period
    /// ends. True when every listed member is resolved; false when a member's
    /// profile isn't readable yet, so the roster is applied again later and
    /// their messages wait meanwhile.
    ///
    /// A roster that leaves out the reader means the reader lost the channel:
    /// the channel is parked with that reason (shown by `hcom buzz status`)
    /// until a roster lists it again.
    fn handle_roster(&mut self, channel_id: &str, event: &Event) -> Result<bool> {
        if route::tag(event, "d") != Some(channel_id) {
            return Ok(true);
        }
        let now = crate::shared::time::now_epoch_i64();
        let members = route::roster_members(event);
        self.note_reader_listed(
            channel_id,
            members
                .iter()
                .any(|(pubkey, _)| pubkey == &self.connector.reader.pubkey),
        );

        let mut complete = true;
        let mut here: Vec<String> = Vec::new();
        for (pubkey, role) in members {
            // Role `bot` is an owned agent, and the reader and omp are ours:
            // none of them is ever a person.
            if role == "bot"
                || pubkey == self.connector.reader.pubkey
                || pubkey == self.connector.owner_pubkey
            {
                continue;
            }
            let Some(name) = self.person_name_for(&pubkey) else {
                complete = false;
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
            .set_channel_members(channel_id, &here)?;

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
        Ok(complete)
    }

    /// Park or unpark a channel on whether its roster lists the reader.
    fn note_reader_listed(&self, channel_id: &str, listed: bool) {
        let store = self.connector.store.lock();
        let parked = store
            .channel(channel_id)
            .ok()
            .flatten()
            .and_then(|row| row.parked_reason);
        if !listed {
            if parked.as_deref() != Some(READER_NOT_LISTED) {
                crate::log::log_error(
                    "buzz",
                    "serve.reader_lost",
                    &format!("{channel_id}: {READER_NOT_LISTED}; add the reader back to resume"),
                );
            }
            let _ = store.set_channel_parked(channel_id, Some(READER_NOT_LISTED));
        } else if parked.as_deref() == Some(READER_NOT_LISTED) {
            crate::log::log_info("buzz", "serve.reader_back", channel_id);
            let _ = store.set_channel_parked(channel_id, None);
        }
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

    /// Fetch a person's newest kind 0 over HTTP, signed by the reader.
    fn profile_for(&self, pubkey: &str) -> Option<(String, Event)> {
        let filter = json!({ "kinds": [route::KIND_PROFILE], "authors": [pubkey] });
        let profile = self
            .reader_query(&filter)
            .ok()?
            .into_iter()
            .filter(|event| event.pubkey == pubkey && nostr::verify(event))
            .max_by_key(|event| event.created_at)?;
        let value: Value = serde_json::from_str(&profile.content).ok()?;
        let name = value
            .get("name")
            .or_else(|| value.get("display_name"))
            .and_then(Value::as_str)?;
        Some((config::person_slug(name), profile))
    }
}

/// What handling one inbox item came to.
enum Handled {
    /// Nothing is owed: our own post, nobody addressed, not a person.
    Done,
    /// Its obligations are written; the item is done once they all are.
    Routed,
    /// Not decidable yet (sender unknown, ancestor unreadable, store error):
    /// stays pending and is handled again after a backoff.
    Wait(String),
}

/// Parked reason of a channel whose roster no longer lists the reader.
const READER_NOT_LISTED: &str = "the reader is not on this channel's roster";

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

    fn test_config(relay: &FakeRelay, device: &str) -> Config {
        crate::buzz::testing::connector_config(relay, device, &SEED, CHANNEL_ID, "infra")
    }

    /// An isolated HCOM_DIR, the fake relay, and the real main loop over the
    /// real databases. A test drives `step` directly, so it exercises production
    /// loop code rather than a stand-in for it.
    struct Harness {
        _dir: tempfile::TempDir,
        _guard: crate::hooks::test_helpers::EnvGuard,
        relay: FakeRelay,
        main: MainLoop,
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

        /// Store an event exactly as the reader thread does for a live event
        /// on the `infra` subscription of a caught-up session.
        fn offer(&self, event: Event) {
            self.offer_on("infra", event);
        }

        /// Store an event as live on one channel's subscription.
        fn offer_on(&self, slug: &str, event: Event) {
            let handles = reader_handles(&self.main.connector);
            let channel = channel_for_sub(&handles.channels, &sub_id(slug))
                .expect("a bridged channel")
                .id
                .clone();
            ingest_live(&handles, &channel, event, true).unwrap();
        }

        /// An inbox item's handling state.
        fn inbox_state(&self, buzz_id: &str) -> Option<String> {
            self.store().inbox_state(buzz_id).unwrap()
        }

        /// How many obligations are in one state.
        fn obligations(&self, state: &str) -> i64 {
            self.store()
                .obligation_counts()
                .unwrap()
                .into_iter()
                .find(|(s, _)| s == state)
                .map_or(0, |(_, n)| n)
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
        let main = MainLoop::for_test(connector, db, epoch);

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

    /// A kind 39002 roster for one channel: `(pubkey, role)` members. Each one
    /// is a second newer than the last, because a roster is replaceable and
    /// two in the same second order by id, not by when they were made.
    fn roster(channel: &str, members: &[(&str, &str)]) -> Event {
        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut tags = vec![vec!["d".to_string(), channel.to_string()]];
        for (pubkey, role) in members {
            tags.push(vec![
                "p".into(),
                pubkey.to_string(),
                String::new(),
                role.to_string(),
            ]);
        }
        let created_at = nostr::now().max(LAST.load(Ordering::SeqCst) + 1);
        LAST.store(created_at, Ordering::SeqCst);
        sign(
            UnsignedEvent {
                created_at,
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
        assert_eq!(
            harness.inbox_state(&event.id).as_deref(),
            Some("done"),
            "handled to the end"
        );
        assert_eq!(harness.obligations("delivered"), 1);
        let store = harness.store();
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
            vec![("logged".to_string(), 1)]
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
                .any(|(state, _)| state == "logged" || state == "failed")
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
            vec![("logged".to_string(), 1)]
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
        assert_eq!(harness.obligations("pending"), 0, "nothing owed");
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

        // The quota window closes and the retry time arrives: the row is due
        // and the key's `retry in 7s` hold has run out. Enrollment and the
        // post are separate writes, and enrollment's writes were rate limited
        // too, so give the loop the passes it needs.
        harness.set_http_status(0);
        harness.store().make_outbox_due().unwrap();
        harness.main.held_until.clear();
        harness.step_until(|h| !h.agent_posts().is_empty());

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1, "exactly one post after the retry");
        assert_eq!(posts[0].id, buzz_id);
        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("logged".to_string(), 1)]
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

        assert!(
            harness
                .store()
                .outbox_counts()
                .unwrap()
                .iter()
                .any(|(s, _)| s == "retry"),
            "the post waits instead of failing"
        );

        // The relay comes back and the queued post catches up on its own.
        harness.set_http_status(0);
        harness.store().make_outbox_due().unwrap();
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

    /// Re-sign the one unposted row `age` seconds into the past through the
    /// store's own re-sign, as if it was prepared that long ago and the outage
    /// outlasted the relay's admission window. Returns the event now stored.
    fn age_unposted(harness: &Harness, age: u64) -> Event {
        let row = harness.store().unsent_outbox().unwrap().remove(0);
        let previous: Event = serde_json::from_str(&row.signed_json).unwrap();
        let aged = sign(
            UnsignedEvent {
                created_at: previous.created_at - age,
                kind: previous.kind,
                tags: previous.tags,
                content: previous.content,
            },
            &agent_key(),
        );
        harness
            .store()
            .resign_outbox(&row, &aged.id, &serde_json::to_string(&aged).unwrap())
            .unwrap();
        aged
    }

    /// The agent's kind 9 posts with this content, as the relay stored them.
    fn posts_saying(harness: &Harness, content: &str) -> Vec<Event> {
        harness
            .agent_posts()
            .into_iter()
            .filter(|post| post.content == content)
            .collect()
    }

    #[test]
    #[serial]
    fn a_window_rejection_finds_an_earlier_prepared_id_and_never_re_signs() {
        // The relay stored an earlier version of the post but the ack was
        // lost; the outage then outlasted the 900 s window, so the version the
        // row holds now is refused as too old. Looking up only that version,
        // or none, and re-signing posts the message twice.
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(503);
        harness.send("luna", "late", &["michael"], None);
        harness.step();
        harness.set_http_status(0);
        let stored = age_unposted(&harness, 1100);
        harness.relay.seed(stored.clone());
        age_unposted(&harness, 1000);
        harness.step_until(|h| h.store().unsent_outbox().unwrap().is_empty());

        let posts = posts_saying(&harness, "late");
        assert_eq!(posts.len(), 1, "posted once: {posts:?}");
        assert_eq!(posts[0].id, stored.id, "the version the relay already held");
        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("logged".to_string(), 1)]
        );
    }

    #[test]
    #[serial]
    fn revision_round_recovery_logs_the_id_the_relay_actually_holds() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(503);
        harness.send("luna", "lost ack", &["michael"], None);
        harness.step();
        harness.set_http_status(0);
        let found = age_unposted(&harness, 1100);
        harness.relay.seed(found.clone());
        let absent = age_unposted(&harness, 1000);
        // Stop after the durable ack, as a crash before the hcom status log
        // would. Recovery must remember which prepared event was found.
        harness
            .main
            .db
            .conn()
            .execute_batch(
                "CREATE TRIGGER no_status BEFORE INSERT ON events
                 WHEN NEW.type = 'status' AND json_extract(NEW.data, '$.context') = 'deliver:luna'
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        harness.step();
        let posted = harness.store().posted_unlogged().unwrap().remove(0);
        assert_eq!(posted.buzz_id, found.id, "the found id survives the crash");
        assert_eq!(
            serde_json::from_str::<Event>(&posted.signed_json).unwrap(),
            found,
            "the stored signature belongs to the found id"
        );
        harness
            .main
            .db
            .conn()
            .execute_batch("DROP TRIGGER no_status")
            .unwrap();
        harness.main = MainLoop::for_test(
            harness.main.connector,
            harness.main.db,
            harness.main.epoch.clone(),
        );
        harness.step();
        let mut stmt = harness
            .main
            .db
            .conn()
            .prepare(
                "SELECT json_extract(data, '$.detail') FROM events
                 WHERE type = 'status' AND instance = 'michael'
                   AND json_extract(data, '$.context') = 'deliver:luna'",
            )
            .unwrap();
        let details = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            details,
            vec![format!(
                "hcom #{} posted to Buzz {} as {}",
                posted.hcom_id, CHANNEL_ID, found.id
            )]
        );
        assert_ne!(found.id, absent.id);
        assert_eq!(posts_saying(&harness, "lost ack"), vec![found]);
    }

    fn deleted_rejection(kind: u16) {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(503);
        harness.send("luna", "removed", &["michael"], None);
        harness.step();
        harness.set_http_status(0);
        let deleted = age_unposted(&harness, 1100);
        let current = age_unposted(&harness, 1000);
        let row = harness.store().unsent_outbox().unwrap().remove(0);
        let prepared = harness.store().prepared_ids(&row).unwrap();
        // Only the tombstone is queryable. It targets an earlier prepared id
        // and has no h tag: a channel-scoped or current-id-only lookup misses it.
        harness.relay.seed(sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind,
                tags: vec![vec!["e".into(), deleted.id]],
                content: String::new(),
            },
            &owner_key(),
        ));
        harness.step();
        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("deleted".to_string(), 1)],
            "a deleted post is settled, not re-signed"
        );
        assert_eq!(harness.store().prepared_ids(&row).unwrap(), prepared);
        harness.main = MainLoop::for_test(
            harness.main.connector,
            harness.main.db,
            harness.main.epoch.clone(),
        );
        harness.step();
        assert!(harness.store().unsent_outbox().unwrap().is_empty());
        assert!(posts_saying(&harness, "removed").is_empty());
        assert!(prepared.contains(&current.id));
    }

    #[test]
    #[serial]
    fn revision_round_a_nip09_tombstone_prevents_reposting() {
        deleted_rejection(route::KIND_DELETE);
    }

    #[test]
    #[serial]
    fn revision_round_a_nip29_tombstone_prevents_reposting() {
        deleted_rejection(route::KIND_CHANNEL_DELETE);
    }

    #[test]
    #[serial]
    fn revision_round_a_failed_tombstone_lookup_keeps_the_prepared_event() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(503);
        harness.send("luna", "uncertain deletion", &["michael"], None);
        harness.step();
        harness.set_http_status(0);
        let aged = age_unposted(&harness, 1000);
        harness
            .relay
            .switches
            .tombstone_query_status
            .store(503, Ordering::SeqCst);
        harness.step();
        let rows = harness.store().unsent_outbox().unwrap();
        assert_eq!(rows[0].buzz_id, aged.id, "failed lookup proves nothing");
        assert_eq!(
            serde_json::from_str::<Event>(&rows[0].signed_json).unwrap(),
            aged
        );
        assert!(posts_saying(&harness, "uncertain deletion").is_empty());
        harness
            .relay
            .switches
            .tombstone_query_status
            .store(0, Ordering::SeqCst);
        // An unrelated tombstone isn't evidence that this post was deleted.
        harness.relay.seed(sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_DELETE,
                tags: vec![vec!["e".into(), "f".repeat(64)]],
                content: String::new(),
            },
            &owner_key(),
        ));
        harness.store().make_outbox_due().unwrap();
        harness.step_until(|h| !posts_saying(h, "uncertain deletion").is_empty());
        let posts = posts_saying(&harness, "uncertain deletion");
        assert_eq!(posts.len(), 1);
        assert!(posts[0].created_at > aged.created_at);
    }

    #[test]
    #[serial]
    fn a_failed_lookup_keeps_the_original_and_retries() {
        // A refused post whose lookup fails proves nothing about whether the
        // relay holds it: the stored event stays until a lookup answers.
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(503);
        harness.send("luna", "late", &["michael"], None);
        harness.step();
        harness.set_http_status(0);
        let aged = age_unposted(&harness, 1000);
        harness
            .relay
            .switches
            .query_status
            .store(503, Ordering::SeqCst);
        harness.step();
        let rows = harness.store().unsent_outbox().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].buzz_id, aged.id, "kept until a lookup succeeds");
        assert!(posts_saying(&harness, "late").is_empty());

        // The lookup works again and finds nothing: now it is re-signed.
        harness
            .relay
            .switches
            .query_status
            .store(0, Ordering::SeqCst);
        harness.store().make_outbox_due().unwrap();
        harness.step_until(|h| !posts_saying(h, "late").is_empty());
        let posts = posts_saying(&harness, "late");
        assert_eq!(posts.len(), 1);
        assert!(posts[0].created_at > aged.created_at, "a fresh timestamp");
    }

    #[test]
    #[serial]
    fn two_identical_sends_in_one_second_are_two_buzz_posts() {
        // Same signer, text, channel, mentions and second: without the hcom
        // message identity in the event they are one id, one post, and the
        // ack for it settles both rows.
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.send("luna", "ok", &["michael"], None);
        harness.send("luna", "ok", &["michael"], None);
        harness.step_until(|h| posts_saying(h, "ok").len() >= 2);

        let posts = posts_saying(&harness, "ok");
        assert_eq!(posts.len(), 2, "two sends, two posts: {posts:?}");
        let identities: std::collections::BTreeSet<_> = posts
            .iter()
            .map(|post| route::tag(post, "hcom").map(str::to_string))
            .collect();
        assert_eq!(identities.len(), 2, "each carries its own hcom message id");
        assert!(identities.iter().all(Option::is_some));
    }

    #[test]
    #[serial]
    fn an_acked_post_logs_its_delivery_status_even_across_a_crash() {
        let status_details = |harness: &Harness| -> Vec<String> {
            let mut stmt = harness
                .main
                .db
                .conn()
                .prepare("SELECT data FROM events WHERE type = 'status' AND instance = 'michael'")
                .unwrap();
            stmt.query_map([], |row| row.get::<_, String>(0))
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter_map(|data| serde_json::from_str::<Value>(&data).ok())
                .filter(|data| data["context"] == "deliver:luna")
                .filter_map(|data| data["detail"].as_str().map(str::to_string))
                .collect()
        };
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.send("luna", "first", &["michael"], None);
        harness.step_until(|h| !posts_saying(h, "first").is_empty());
        let first = posts_saying(&harness, "first").remove(0);
        assert!(
            status_details(&harness)
                .iter()
                .any(|detail| detail.contains(&first.id)),
            "the ack is logged for Michael: {:?}",
            status_details(&harness)
        );

        // The relay acknowledged a second post and the process died before
        // logging it: the restart writes the status.
        harness.set_http_status(503);
        harness.send("luna", "second", &["michael"], None);
        harness.step();
        let row = harness.store().unsent_outbox().unwrap().remove(0);
        harness.store().mark_outbox_posted(&row, None).unwrap();
        harness.set_http_status(0);
        harness.main = MainLoop::for_test(
            harness.main.connector,
            harness.main.db,
            harness.main.epoch.clone(),
        );
        harness.step();
        assert!(
            status_details(&harness)
                .iter()
                .any(|detail| detail.contains(&row.buzz_id)),
            "logged after the restart: {:?}",
            status_details(&harness)
        );
        assert_eq!(
            harness.store().outbox_counts().unwrap(),
            vec![("logged".to_string(), 2)]
        );
    }

    /// Michael's home channel with luna already enrolled in it, so a test sees
    /// only post traffic.
    fn enrolled_home(harness: &mut Harness) {
        harness.use_home_channel("michael", "michael");
        harness.add_person("michael", Some("michael"));
        harness.add_agent("luna");
        harness
            .store()
            .put_enrollment(&public_hex(&agent_key()), CHANNEL_ID, "enrolled")
            .unwrap();
    }

    #[test]
    #[serial]
    fn a_429_holds_every_queued_post_of_that_key() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(429);
        harness.send("luna", "one", &["michael"], None);
        harness.send("luna", "two", &["michael"], None);
        let before = harness.relay.http_requests();
        harness.step();
        assert_eq!(
            harness.relay.http_requests() - before,
            1,
            "after 'retry in 7s' the key's next post waits instead of drawing another 429"
        );
    }

    #[test]
    #[serial]
    fn a_post_that_aged_past_the_relay_window_is_re_signed_not_failed() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.set_http_status(503);
        harness.send("luna", "late", &["michael"], None);
        harness.step();
        harness.set_http_status(0);
        let aged = age_unposted(&harness, 1000);
        harness.step_until(|h| !h.agent_posts().is_empty());

        let posts = harness.agent_posts();
        assert_eq!(posts.len(), 1, "{:?}", harness.store().outbox_counts());
        assert_eq!(posts[0].content, "late");
        assert!(posts[0].created_at > aged.created_at, "a fresh timestamp");
    }

    #[test]
    #[serial]
    fn shutdown_flushes_what_is_queued() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        harness.send("luna", "last words", &["michael"], None);
        harness.main.scan_outbound();
        harness
            .main
            .connector
            .shutdown
            .store(true, Ordering::SeqCst);
        harness.main.shutdown();
        assert_eq!(
            harness.agent_posts().len(),
            1,
            "the bounded flush posts what was queued before exiting"
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
        harness.store().make_outbox_due().unwrap();
        harness.main = MainLoop::for_test(
            harness.main.connector,
            harness.main.db,
            harness.main.epoch.clone(),
        );
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
        harness.store().make_outbox_due().unwrap();
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
    fn an_unresolvable_target_is_owed_then_announced_in_buzz() {
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

        assert_eq!(
            harness.obligations("pending"),
            1,
            "the unresolvable target is owed"
        );

        // The window closes; the connector says so in Buzz, as omp. Age the row
        // first, then give the loop the pass that notices.
        harness.store().age_obligation(&event.id, 0).unwrap();
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
        assert_eq!(
            harness.obligations("expired"),
            1,
            "the obligation is closed, not retried forever"
        );
    }

    #[test]
    #[serial]
    fn a_mention_of_an_enrolled_agent_whose_row_is_gone_stays_owed() {
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

        assert_eq!(
            harness.obligations("pending"),
            1,
            "the mention is owed to luna, not skipped as naming nobody"
        );
    }

    #[test]
    #[serial]
    fn live_targets_get_the_message_while_a_stopped_one_stays_owed() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.add_agent("nova");
        let nova = nostr::derive_secret(&SEED, "nova@mbai");
        // nova is known (enrolled earlier) but its session ended.
        harness
            .store()
            .put_author(&Author {
                pubkey: public_hex(&nova),
                kind: AuthorKind::Agent,
                hcom_name: Some("nova".into()),
                device_label: Some("mbai".into()),
            })
            .unwrap();
        assert!(harness.main.db.delete_instance("nova").unwrap());

        harness.offer(message(
            &human_key(),
            CHANNEL_ID,
            "both of you, look",
            vec![
                vec!["p".into(), public_hex(&agent_key())],
                vec!["p".into(), public_hex(&nova)],
            ],
        ));
        harness.step();

        assert_eq!(
            harness.unread("luna").len(),
            1,
            "luna is live and gets it now"
        );
        assert_eq!(harness.obligations("pending"), 1, "only nova is owed");
    }

    #[test]
    #[serial]
    fn an_owed_target_is_redelivered_from_the_person_in_the_buzz_thread() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness
            .store()
            .put_author(&Author {
                pubkey: public_hex(&agent_key()),
                kind: AuthorKind::Agent,
                hcom_name: Some("luna".into()),
                device_label: Some("mbai".into()),
            })
            .unwrap();
        assert!(harness.main.db.delete_instance("luna").unwrap());

        let event = message(
            &human_key(),
            CHANNEL_ID,
            "luna, when you're back",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(event.clone());
        harness.step();

        // The session comes back; the next retry delivers what was routed.
        harness.add_agent("luna");
        harness
            .store()
            .age_obligation(&event.id, crate::shared::time::now_epoch_i64())
            .unwrap();
        harness.step();

        let unread = harness.unread("luna");
        assert_eq!(unread.len(), 1, "redelivered once");
        assert_eq!(
            unread[0].from, "michael",
            "from the person, not the agent itself"
        );
        assert_eq!(unread[0].text, "luna, when you're back");
        let thread = route::thread_name("infra", &event.id);
        assert_eq!(unread[0].thread.as_deref(), Some(thread.as_str()));
        assert!(
            harness.store().thread(&thread).unwrap().is_some(),
            "the thread is recorded, so a reply goes back to Buzz"
        );
    }

    #[test]
    #[serial]
    fn an_ancestor_fetch_failure_is_retried_not_dropped() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        // luna's post is on the relay but not in the cache, and the relay is in
        // a 503 window when Michael's plain reply arrives.
        let post = message(&agent_key(), CHANNEL_ID, "deployed", vec![]);
        harness.relay.seed(post.clone());
        let reply = message(
            &human_key(),
            CHANNEL_ID,
            "thanks",
            vec![vec![
                "e".into(),
                post.id.clone(),
                String::new(),
                "reply".into(),
            ]],
        );
        harness.set_http_status(503);
        harness.offer(reply.clone());
        harness.step();
        assert!(harness.unread("luna").is_empty());
        assert_eq!(
            harness.inbox_state(&reply.id).as_deref(),
            Some("pending"),
            "an event that wasn't handled stays pending"
        );

        harness.set_http_status(0);
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(harness.unread("luna").len(), 1, "the retry delivers it");
        assert_eq!(harness.inbox_state(&reply.id).as_deref(), Some("done"));
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
        assert_eq!(harness.obligations("pending"), 0);
    }

    #[test]
    #[serial]
    fn history_from_a_sender_named_only_by_the_newer_roster_is_delivered() {
        // A fresh state DB catches up a mention, then the roster that names its
        // sender. Rosters are applied before messages, so the mention is from
        // a person by the time it is handled, not skipped for good.
        let mut harness = harness("mbai");
        harness.add_agent("luna");
        let human = public_hex(&human_key());
        harness
            .relay
            .seed(profile(&human_key(), "Michael", "just a person"));
        let mention = message(
            &human_key(),
            CHANNEL_ID,
            "luna, from the history",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(mention.clone());
        harness.offer(roster(CHANNEL_ID, &[(&human, "member")]));
        harness.step();

        let unread = harness.unread("luna");
        assert_eq!(unread.len(), 1, "the mention reached luna");
        assert_eq!(unread[0].from, "michael");
    }

    #[test]
    #[serial]
    fn a_configured_person_is_a_person_before_any_roster() {
        let mut harness = harness("mbai");
        harness.add_agent("luna");
        harness.main.connector.config.people = vec![config::PersonConfig {
            pubkey: public_hex(&human_key()),
            name: Some("michael".into()),
            home: None,
        }];
        harness.offer(message(
            &human_key(),
            CHANNEL_ID,
            "luna, from the config",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        ));
        harness.step();

        let unread = harness.unread("luna");
        assert_eq!(unread.len(), 1, "no roster needed for a configured person");
        assert_eq!(unread[0].from, "michael");
    }

    #[test]
    #[serial]
    fn a_message_from_a_sender_not_yet_known_waits_for_the_roster() {
        let mut harness = harness("mbai");
        harness.add_agent("luna");
        let human = public_hex(&human_key());
        harness
            .relay
            .seed(profile(&human_key(), "Michael", "just a person"));
        let mention = message(
            &human_key(),
            CHANNEL_ID,
            "luna, are you there?",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        harness.offer(mention.clone());
        harness.step();
        assert!(harness.unread("luna").is_empty());
        assert_eq!(
            harness.inbox_state(&mention.id).as_deref(),
            Some("pending"),
            "kept until the sender is known, not settled"
        );

        harness.offer(roster(CHANNEL_ID, &[(&human, "member")]));
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(harness.unread("luna").len(), 1);
        assert_eq!(harness.inbox_state(&mention.id).as_deref(), Some("done"));
    }

    #[test]
    #[serial]
    fn a_message_from_a_roster_bot_or_a_non_member_is_settled() {
        let mut harness = harness("mbai");
        harness.add_agent("luna");
        let bot = nostr::derive_secret(&SEED, "someone-elses-bot@test");
        let stranger = nostr::derive_secret(&SEED, "stranger@test");
        let addressed = || vec![vec!["p".to_string(), public_hex(&agent_key())]];
        let from_bot = message(&bot, CHANNEL_ID, "luna, beep", addressed());
        let from_stranger = message(&stranger, CHANNEL_ID, "luna, hi", addressed());
        harness.offer(from_bot.clone());
        harness.offer(from_stranger.clone());
        // A roster at least as new as both lists the bot as a bot and doesn't
        // list the stranger: neither will ever be a person.
        harness.offer(roster(CHANNEL_ID, &[(&public_hex(&bot), "bot")]));
        harness.step();

        assert_eq!(harness.inbox_state(&from_bot.id).as_deref(), Some("done"));
        assert_eq!(
            harness.inbox_state(&from_stranger.id).as_deref(),
            Some("done")
        );
        assert!(harness.unread("luna").is_empty());
    }

    #[test]
    #[serial]
    fn a_target_whose_obligation_failed_to_commit_is_never_lost() {
        // luna is live, nova's session is gone. Writing nova's obligation fails
        // (a full disk): nothing is sent or settled on a partial record, and
        // once writes work again both are owed, and nova gets it on return.
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.add_agent("nova");
        let nova = nostr::derive_secret(&SEED, "nova@mbai");
        harness
            .store()
            .put_author(&Author {
                pubkey: public_hex(&nova),
                kind: AuthorKind::Agent,
                hcom_name: Some("nova".into()),
                device_label: Some("mbai".into()),
            })
            .unwrap();
        assert!(harness.main.db.delete_instance("nova").unwrap());
        harness
            .store()
            .exec_for_test(
                "CREATE TRIGGER no_room BEFORE INSERT ON obligations WHEN NEW.target = 'nova'
                 BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
            )
            .unwrap();
        let event = message(
            &human_key(),
            CHANNEL_ID,
            "both of you, look",
            vec![
                vec!["p".into(), public_hex(&agent_key())],
                vec!["p".into(), public_hex(&nova)],
            ],
        );
        harness.offer(event.clone());
        harness.step();
        assert_eq!(harness.inbox_state(&event.id).as_deref(), Some("pending"));

        harness
            .store()
            .exec_for_test("DROP TRIGGER no_room;")
            .unwrap();
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(harness.unread("luna").len(), 1, "luna got it once");
        assert_eq!(harness.obligations("pending"), 1, "nova is still owed");

        harness.add_agent("nova");
        harness
            .store()
            .age_obligation(&event.id, crate::shared::time::now_epoch_i64())
            .unwrap();
        harness.step();
        assert_eq!(harness.unread("nova").len(), 1, "nova gets it on return");
        assert_eq!(harness.unread("luna").len(), 1, "and luna not twice");
        assert_eq!(harness.inbox_state(&event.id).as_deref(), Some("done"));
    }

    #[test]
    #[serial]
    fn an_item_failing_past_eight_attempts_is_still_retried() {
        // A plain reply whose ancestor lookup fails through a long outage stays
        // pending however many times it fails; it is never given up.
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let post = message(&agent_key(), CHANNEL_ID, "deployed", vec![]);
        harness.relay.seed(post.clone());
        let reply = message(
            &human_key(),
            CHANNEL_ID,
            "thanks",
            vec![vec![
                "e".into(),
                post.id.clone(),
                String::new(),
                "reply".into(),
            ]],
        );
        harness.set_http_status(503);
        harness.offer(reply.clone());
        for _ in 0..12 {
            harness.store().make_inbox_due().unwrap();
            harness.step();
        }
        assert_eq!(harness.inbox_state(&reply.id).as_deref(), Some("pending"));

        harness.set_http_status(0);
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(
            harness.unread("luna").len(),
            1,
            "delivered after the outage"
        );
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

    fn revision_before_original(kind: u16) {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let original = sign(
            UnsignedEvent {
                created_at: nostr::now() - 600,
                kind: route::KIND_MESSAGE,
                tags: vec![
                    vec!["h".into(), CHANNEL_ID.into()],
                    vec!["p".into(), public_hex(&agent_key())],
                ],
                content: "original from history".into(),
            },
            &human_key(),
        );
        let revision = sign(
            UnsignedEvent {
                created_at: nostr::now() - 30,
                kind,
                tags: vec![
                    vec!["h".into(), CHANNEL_ID.into()],
                    vec!["e".into(), original.id.clone()],
                    vec!["p".into(), public_hex(&agent_key())],
                ],
                content: "revised from history".into(),
            },
            &human_key(),
        );
        // The bounded WS batch contains the revision; its older original is
        // queryable (including by ancestry lookup) but not in the inbox yet.
        harness.relay.seed(original.clone());
        let handles = reader_handles(&harness.main.connector);
        let channel = handles.channels[0].clone();
        ingest_live(&handles, CHANNEL_ID, revision.clone(), false).unwrap();
        harness.step();
        assert_eq!(
            harness.inbox_state(&revision.id).as_deref(),
            Some("pending")
        );
        assert!(harness.unread("luna").is_empty());
        catch_up(&handles, &channel).unwrap();
        harness.store().make_inbox_due().unwrap();
        harness.step();
        harness.step();
        let messages = harness.unread("luna");
        assert_eq!(messages.len(), 2, "original, then its revision");
        assert_eq!(messages[0].text, original.content);
        let prefix = if kind == route::KIND_EDIT {
            "(edited) "
        } else {
            "(deleted)"
        };
        assert!(messages[1].text.starts_with(prefix), "{messages:?}");
        assert_eq!(messages[0].thread, messages[1].thread);
        assert_eq!(harness.inbox_state(&revision.id).as_deref(), Some("done"));
    }

    #[test]
    #[serial]
    fn revision_round_an_edit_waits_for_its_original_to_be_fetched() {
        revision_before_original(route::KIND_EDIT);
    }

    #[test]
    #[serial]
    fn revision_round_a_nip09_deletion_waits_for_its_original_to_be_fetched() {
        revision_before_original(route::KIND_DELETE);
    }

    #[test]
    #[serial]
    fn revision_round_a_nip29_deletion_waits_for_its_original_to_be_fetched() {
        revision_before_original(route::KIND_CHANNEL_DELETE);
    }

    #[test]
    #[serial]
    fn revision_round_an_absent_original_waits_for_a_new_channel_catch_up() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.add_channel(OTHER_CHANNEL_ID, "other");
        harness.store().upsert_channel(CHANNEL_ID, "infra").unwrap();
        harness
            .store()
            .upsert_channel(OTHER_CHANNEL_ID, "other")
            .unwrap();
        let handles = reader_handles(&harness.main.connector);
        let channel = handles
            .channels
            .iter()
            .find(|c| c.id == CHANNEL_ID)
            .unwrap();
        let other = handles
            .channels
            .iter()
            .find(|c| c.id == OTHER_CHANNEL_ID)
            .unwrap();
        // An earlier completed fetch, even in the same second, cannot settle
        // a newly stored revision. created_at is old; arrival time matters.
        catch_up(&handles, channel).unwrap();
        let revision = sign(
            UnsignedEvent {
                created_at: nostr::now() - 600,
                kind: route::KIND_EDIT,
                tags: vec![
                    vec!["h".into(), CHANNEL_ID.into()],
                    vec!["e".into(), "f".repeat(64)],
                    vec!["p".into(), public_hex(&agent_key())],
                ],
                content: "outside the fetched history".into(),
            },
            &human_key(),
        );
        harness.offer(revision.clone());
        harness.step();
        assert_eq!(
            harness.inbox_state(&revision.id).as_deref(),
            Some("pending")
        );
        catch_up(&handles, other).unwrap();
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(
            harness.inbox_state(&revision.id).as_deref(),
            Some("pending")
        );
        harness
            .relay
            .switches
            .query_status
            .store(503, Ordering::SeqCst);
        assert!(catch_up(&handles, channel).is_err());
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(
            harness.inbox_state(&revision.id).as_deref(),
            Some("pending")
        );
        harness
            .relay
            .switches
            .query_status
            .store(0, Ordering::SeqCst);
        catch_up(&handles, channel).unwrap();
        harness.main = MainLoop::for_test(
            harness.main.connector,
            harness.main.db,
            harness.main.epoch.clone(),
        );
        harness.store().make_inbox_due().unwrap();
        harness.step();
        assert_eq!(harness.inbox_state(&revision.id).as_deref(), Some("done"));
        assert!(harness.unread("luna").is_empty());
    }

    #[test]
    #[serial]
    fn revision_round_historical_obligations_deliver_in_source_order() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let at = nostr::now() - 600;
        let make = |created_at, content| {
            sign(
                UnsignedEvent {
                    created_at,
                    kind: route::KIND_MESSAGE,
                    tags: vec![
                        vec!["h".into(), CHANNEL_ID.into()],
                        vec!["p".into(), public_hex(&agent_key())],
                    ],
                    content,
                },
                &human_key(),
            )
        };
        let first = make(at, "older message".into());
        let second = (0..1000)
            .map(|i| make(at + 100, format!("newer message {i}")))
            .find(|event| event.id < first.id)
            .expect("a newer event whose id sorts before the older event");
        harness.offer(first.clone());
        harness.offer(second.clone());
        let channel = reader_handles(&harness.main.connector).channels.remove(0);
        let now = crate::shared::time::now_epoch_i64();
        let due = harness.store().due_inbox(CHANNEL_ID, now).unwrap();
        for item in due {
            harness.main.handle_item(&channel, item);
        }
        // Pin both routing times to the same second: timestamp/ID source
        // order must win over the obligation's retry/expiry bookkeeping.
        harness.store().age_obligation(&first.id, now).unwrap();
        harness.store().age_obligation(&second.id, now).unwrap();
        harness.main.deliver_obligations();
        assert_eq!(
            harness
                .unread("luna")
                .iter()
                .map(|m| m.text.as_str())
                .collect::<Vec<_>>(),
            vec![first.content.as_str(), second.content.as_str()]
        );
    }

    #[test]
    #[serial]
    fn revision_round_a_backdated_revision_cannot_overtake_its_original() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        let original = message(
            &human_key(),
            CHANNEL_ID,
            "original",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        );
        let revision = sign(
            UnsignedEvent {
                created_at: original.created_at - 1,
                kind: route::KIND_EDIT,
                tags: vec![
                    vec!["h".into(), CHANNEL_ID.into()],
                    vec!["e".into(), original.id.clone()],
                    vec!["p".into(), public_hex(&agent_key())],
                ],
                content: "backdated edit".into(),
            },
            &human_key(),
        );
        harness.offer(original.clone());
        harness.offer(revision.clone());
        let channel = reader_handles(&harness.main.connector).channels.remove(0);
        // The original is routed but not sent when the revision is routed.
        for event in [&original, &revision] {
            let cached = harness.store().cached_event(&event.id).unwrap().unwrap();
            harness.main.handle_item(
                &channel,
                InboxItem {
                    event: cached,
                    attempts: 0,
                },
            );
        }
        let now = crate::shared::time::now_epoch_i64();
        // Make the revision older in both bookkeeping and source order.
        harness.store().age_obligation(&original.id, now).unwrap();
        harness
            .store()
            .age_obligation(&revision.id, now - 1)
            .unwrap();
        harness.main.deliver_obligations();
        harness.main.deliver_obligations();
        assert_eq!(
            harness
                .unread("luna")
                .iter()
                .map(|m| m.text.as_str())
                .collect::<Vec<_>>(),
            vec!["original", "(edited) backdated edit"]
        );
    }

    #[test]
    #[serial]
    fn an_agent_gone_for_an_hour_is_removed_by_its_own_pubkey() {
        let mut harness = harness("mbai");
        harness.add_agent("luna");
        let luna = public_hex(&agent_key());
        harness.main.plan_enrollment();
        assert_eq!(
            harness
                .store()
                .enrollment(&luna, CHANNEL_ID)
                .unwrap()
                .as_deref(),
            Some("enrolled")
        );

        // The session ends. The hour runs from when the row went missing, not
        // from when the agent was enrolled.
        assert!(harness.main.db.delete_instance("luna").unwrap());
        harness.main.plan_enrollment();
        assert!(
            !harness.relay.events().iter().any(|e| e.kind == 9001),
            "not removed the moment the row disappears"
        );
        let now = crate::shared::time::now_epoch_i64();
        harness
            .store()
            .age_enrollment(&luna, now - ENROLL_STALE_SECS - 1)
            .unwrap();
        harness.main.plan_enrollment();

        let removal = harness
            .relay
            .events()
            .into_iter()
            .find(|e| e.kind == 9001)
            .expect("omp removed the agent");
        assert_eq!(
            route::tag(&removal, "p"),
            Some(luna.as_str()),
            "luna's own key"
        );
        assert_eq!(route::tag(&removal, "h"), Some(CHANNEL_ID));
        assert!(
            harness
                .store()
                .enrollment(&luna, CHANNEL_ID)
                .unwrap()
                .is_none()
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
    fn a_hosted_row_stopped_or_deleted_by_hand_comes_back() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);

        // The operator stops one row and deletes another while the connector
        // runs; the connector's own bookkeeping still lists both.
        harness
            .main
            .db
            .conn()
            .execute(
                "UPDATE instances SET status = 'stopped' WHERE name = 'michael'",
                [],
            )
            .unwrap();
        assert!(harness.main.db.delete_instance("ch_infra").unwrap());
        harness.step();

        let michael = harness
            .main
            .db
            .get_instance_full("michael")
            .unwrap()
            .unwrap();
        assert_ne!(
            michael.status, "stopped",
            "an active roster row is restored while the connector runs"
        );
        assert!(
            harness
                .main
                .db
                .get_instance_full("ch_infra")
                .unwrap()
                .is_some(),
            "a deleted channel row is recreated"
        );
    }

    #[test]
    #[serial]
    fn an_hcom_reset_reopens_the_database_and_rehosts_the_rows() {
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        let old_epoch = harness.main.epoch.clone();

        // `hcom reset`: the database file is archived and a new one created,
        // while the loop still holds the old file open. The loop's handle is
        // let go for the rename, because Windows refuses to rename a file
        // SQLite holds, then pointed at the archived file: the stale handle
        // production holds after a reset.
        let path = crate::paths::db_path();
        drop(std::mem::replace(
            &mut harness.main.db,
            HcomDb::open_raw(std::path::Path::new(":memory:")).unwrap(),
        ));
        for suffix in ["", "-wal", "-shm"] {
            let from = format!("{}{suffix}", path.display());
            if std::path::Path::new(&from).exists() {
                std::fs::rename(&from, format!("{from}.archived")).unwrap();
            }
        }
        let archived_path = std::path::PathBuf::from(format!("{}.archived", path.display()));
        harness.main.db = HcomDb::open_raw(&archived_path).unwrap();
        let fresh = HcomDb::open().unwrap();
        let now = crate::shared::time::now_epoch_i64();
        let luna = json!({
            "name": "luna", "tool": "claude", "status": "listening",
            "status_time": now, "status_context": "ready", "last_stop": now,
            "tcp_mode": 0, "last_event_id": fresh.get_last_event_id(),
            "origin_device_id": "", "directory": "", "transcript_path": "",
            "background": 0, "name_announced": 0,
            "created_at": crate::shared::time::now_epoch_f64(),
        });
        fresh
            .save_instance_named("luna", luna.as_object().unwrap())
            .unwrap();
        // Neither file carries a reset marker, so only the file's identity
        // can tell the loop it was replaced.
        for db in [&harness.main.db, &fresh] {
            assert_eq!(db.kv_get("relay_local_reset_ts").unwrap(), None);
        }
        harness.step();

        let epoch = harness.main.epoch.clone();
        assert_ne!(
            epoch, old_epoch,
            "the loop adopted the new database's epoch"
        );
        assert_eq!(
            harness.store().epoch(),
            epoch,
            "the store scopes hcom ids by the new epoch"
        );
        for row in ["michael", "ch_infra"] {
            assert!(
                fresh.get_instance_full(row).unwrap().is_some(),
                "{row}'s hosted row exists in the new database"
            );
        }
        harness.offer(message(
            &human_key(),
            CHANNEL_ID,
            "after the reset",
            vec![vec!["p".into(), public_hex(&agent_key())]],
        ));
        harness.step();
        assert_eq!(
            fresh.get_unread_messages("luna").len(),
            1,
            "delivery goes to the live database"
        );
        let archived = HcomDb::open_raw(&archived_path).unwrap();
        let leaked = archived
            .get_events_since(0, Some("message"), None)
            .unwrap()
            .into_iter()
            .filter(|event| {
                event["data"]["text"]
                    .as_str()
                    .is_some_and(|text| text.contains("after the reset"))
            })
            .count();
        assert_eq!(leaked, 0, "the archived database receives nothing");
    }

    #[test]
    #[serial]
    fn a_message_whose_outbox_write_fails_is_read_again() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        // The outbox insert fails, as on a full disk.
        harness
            .store()
            .exec_for_test(
                "CREATE TRIGGER no_room BEFORE INSERT ON outbox
                 BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
            )
            .unwrap();
        harness.send("luna", "do not lose me", &["michael"], None);
        harness.main.scan_outbound();
        assert_eq!(
            harness.unread("michael").len(),
            1,
            "the cursor stays put while nothing owed to Buzz is committed"
        );

        harness
            .store()
            .exec_for_test("DROP TRIGGER no_room;")
            .unwrap();
        harness.step_until(|h| !h.agent_posts().is_empty());
        assert_eq!(harness.agent_posts().len(), 1);
        assert!(harness.unread("michael").is_empty());
    }

    #[test]
    #[serial]
    fn a_homeless_addressee_gets_one_notice_and_the_others_still_get_posts() {
        let mut harness = harness("mbai");
        enrolled_home(&mut harness);
        // A second person, with no home channel.
        let sean = public_hex(&nostr::derive_secret(&SEED, "sean@test"));
        harness
            .store()
            .upsert_person(&sean, "seanfitz", None)
            .unwrap();
        crate::hosted::register_hosted(
            &harness.main.db,
            "seanfitz",
            crate::hosted::HOSTED_TOOL_BUZZ,
        )
        .unwrap();
        harness.main.connector.hosted.lock().push("seanfitz".into());

        harness.send("luna", "status update", &["michael", "seanfitz"], None);
        harness.step_until(|h| !h.agent_posts().is_empty());
        harness.step();

        assert_eq!(
            harness.agent_posts().len(),
            1,
            "Michael's home post still goes out"
        );
        let notices: Vec<_> = harness
            .unread("luna")
            .into_iter()
            .filter(|m| m.text.contains("no home channel"))
            .collect();
        assert_eq!(
            notices.len(),
            1,
            "one notice, not one per hosted row: {notices:?}"
        );
        assert_eq!(notices[0].from, "seanfitz");
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
    fn the_connector_state_is_never_opened_as_an_hcom_database() {
        let harness = harness("mbai");
        harness.store().adopt_epoch("epoch-x".into()).unwrap();
        let config = harness.main.connector.config.clone();
        // A second start reopens state.db: it must read the epoch it stored,
        // not run hcom's schema and migrations against the connector's tables.
        let again = Connector::load(config).unwrap();
        assert_eq!(again.store.lock().epoch(), "epoch-x");
        let conn = rusqlite::Connection::open(Config::state_db_path()).unwrap();
        let hcom_tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('instances', 'events', 'kv')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            hcom_tables, 0,
            "no hcom schema inside the connector's state"
        );
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

    /// A connector whose reader speaks WS to `ws` and HTTP to `http`, both over
    /// the same fake store; the reader thread runs on its own, as in `serve`.
    struct LiveReader {
        _env: (
            tempfile::TempDir,
            std::path::PathBuf,
            std::path::PathBuf,
            crate::hooks::test_helpers::EnvGuard,
        ),
        http: FakeRelay,
        ws: FakeRelay,
        connector: Connector,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl LiveReader {
        fn start(before: impl FnOnce(&FakeRelay)) -> Self {
            let env = crate::hooks::test_helpers::isolated_test_env();
            let http = FakeRelay::http();
            let ws = http.ws_twin();
            before(&http);
            let mut config = test_config(&http, "mbai");
            config.relay_url = ws.url.clone();
            let connector = Connector::load(config).unwrap();
            connector
                .store
                .lock()
                .upsert_channel(CHANNEL_ID, "infra")
                .unwrap();
            let handles = reader_handles(&connector);
            let thread = std::thread::spawn(move || reader_loop(handles));
            Self {
                _env: env,
                http,
                ws,
                connector,
                thread: Some(thread),
            }
        }

        /// The channel's inbox once it holds `count` events or the deadline
        /// passed.
        fn inbox(&self, count: usize, deadline: Duration) -> Vec<CachedEvent> {
            let end = Instant::now() + deadline;
            loop {
                let events = self
                    .connector
                    .store
                    .lock()
                    .list_events(Some(CHANNEL_ID), None, None, 1_000_000)
                    .unwrap();
                if events.len() >= count || Instant::now() >= end {
                    return events;
                }
                sleep(Duration::from_millis(50));
            }
        }

        /// True once one event is in the inbox, false at the deadline.
        fn stored(&self, id: &str, deadline: Duration) -> bool {
            let end = Instant::now() + deadline;
            while Instant::now() < end {
                if self
                    .connector
                    .store
                    .lock()
                    .cached_event(id)
                    .unwrap()
                    .is_some()
                {
                    return true;
                }
                sleep(Duration::from_millis(50));
            }
            false
        }

        /// Post live, over WS, as the test human.
        fn publish_live(&self, text: &str) -> Event {
            self.publish_live_at(text, nostr::now())
        }

        /// Post live with a chosen `created_at`, as a client may backdate.
        fn publish_live_at(&self, text: &str, created_at: u64) -> Event {
            let event = sign(
                UnsignedEvent {
                    created_at,
                    kind: route::KIND_MESSAGE,
                    tags: vec![vec!["h".into(), CHANNEL_ID.into()]],
                    content: text.into(),
                },
                &human_key(),
            );
            let tag = nostr::auth_tag(&owner_key(), &public_hex(&human_key()), "");
            let mut session = WsSession::connect(
                &self.ws.url,
                &human_key(),
                Some(tag),
                Duration::from_secs(5),
            )
            .unwrap();
            session.publish(&event).unwrap();
            event
        }

        fn parked(&self) -> Option<String> {
            self.connector
                .store
                .lock()
                .channel(CHANNEL_ID)
                .unwrap()
                .and_then(|row| row.parked_reason)
        }

        fn position(&self) -> Option<store::Position> {
            self.connector
                .store
                .lock()
                .channel(CHANNEL_ID)
                .unwrap()
                .and_then(|row| row.position)
        }

        /// Wait until a condition holds or the deadline passes.
        fn wait_for(&self, deadline: Duration, done: impl Fn(&Self) -> bool) -> bool {
            let end = Instant::now() + deadline;
            while Instant::now() < end {
                if done(self) {
                    return true;
                }
                sleep(Duration::from_millis(50));
            }
            done(self)
        }
    }

    impl Drop for LiveReader {
        fn drop(&mut self) {
            self.connector.shutdown.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    /// `count` channel messages by the test human, `created_at` from `at(i)`.
    fn history(count: usize, at: impl Fn(usize) -> u64) -> Vec<Event> {
        (0..count)
            .map(|i| {
                sign(
                    UnsignedEvent {
                        created_at: at(i),
                        kind: route::KIND_MESSAGE,
                        tags: vec![vec!["h".into(), CHANNEL_ID.into()]],
                        content: format!("history {i}"),
                    },
                    &human_key(),
                )
            })
            .collect()
    }

    #[test]
    #[serial]
    fn the_reader_catches_up_every_page_then_streams_live_events() {
        // 150 events behind a relay that clamps pages to 100: a catch-up that
        // stops on a short page or doesn't page loses some.
        let now = nostr::now();
        let events = history(150, |i| now - 300 + i as u64);
        let reader = LiveReader::start(|relay| {
            relay.switches.max_page.store(100, Ordering::SeqCst);
            for event in &events {
                relay.seed(event.clone());
            }
        });

        assert_eq!(reader.inbox(150, Duration::from_secs(15)).len(), 150);
        let newest = events
            .iter()
            .max_by_key(|e| (e.created_at, e.id.clone()))
            .unwrap();
        let wanted = store::Position {
            created_at: newest.created_at,
            id: newest.id.clone(),
        };
        assert!(
            reader.wait_for(Duration::from_secs(5), |r| r.position().as_ref()
                == Some(&wanted)),
            "the position is the newest stored key: {:?}",
            reader.position()
        );

        let live = reader.publish_live("hello, live");
        assert!(
            reader.stored(&live.id, Duration::from_secs(10)),
            "the live event reaches the inbox"
        );
    }

    #[test]
    #[serial]
    fn revision_round_an_absent_original_settles_in_a_healthy_session() {
        /// Stops and joins the reader even when an assertion fails first.
        struct Running(Arc<AtomicBool>, Option<std::thread::JoinHandle<()>>);
        impl Drop for Running {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
                if let Some(thread) = self.1.take() {
                    let _ = thread.join();
                }
            }
        }
        fn until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
            let end = Instant::now() + deadline;
            while Instant::now() < end {
                if done() {
                    return true;
                }
                sleep(Duration::from_millis(50));
            }
            done()
        }

        // The reader thread and the main loop share one connector, as in
        // `serve`, and the session stays up throughout.
        let mut harness = harness("mbai");
        harness.add_person("michael", None);
        harness.add_agent("luna");
        harness.store().upsert_channel(CHANNEL_ID, "infra").unwrap();
        // One event in history: the position moves once the first catch-up
        // completes.
        harness.relay.seed(message(
            &human_key(),
            CHANNEL_ID,
            "before the session",
            vec![],
        ));
        let ws = harness.relay.ws_twin();
        harness.main.connector.config.relay_url = ws.url.clone();
        let handles = reader_handles(&harness.main.connector);
        let _reader = Running(
            harness.main.connector.shutdown.clone(),
            Some(std::thread::spawn(move || reader_loop(handles))),
        );
        assert!(
            until(Duration::from_secs(15), || harness
                .store()
                .channel(CHANNEL_ID)
                .unwrap()
                .is_some_and(|row| row.position.is_some())),
            "the first catch-up completes"
        );

        // An edit whose original the relay never had arrives live.
        let revision = sign(
            UnsignedEvent {
                created_at: nostr::now(),
                kind: route::KIND_EDIT,
                tags: vec![
                    vec!["h".into(), CHANNEL_ID.into()],
                    vec!["e".into(), "f".repeat(64)],
                    vec!["p".into(), public_hex(&agent_key())],
                ],
                content: "an edit of something never fetched".into(),
            },
            &human_key(),
        );
        let mut session = WsSession::connect(
            &ws.url,
            &human_key(),
            Some(nostr::auth_tag(&owner_key(), &public_hex(&human_key()), "")),
            Duration::from_secs(5),
        )
        .unwrap();
        session.publish(&revision).unwrap();
        assert!(
            until(Duration::from_secs(10), || harness
                .inbox_state(&revision.id)
                .is_some()),
            "the live edit reaches the inbox"
        );
        harness.step();
        assert_eq!(
            harness.inbox_state(&revision.id).as_deref(),
            Some("pending"),
            "no catch-up has begun since it arrived"
        );

        // No reconnect, no restart, no manual catch-up: the loop alone
        // settles it.
        assert!(
            until(Duration::from_secs(20), || {
                harness.step();
                harness.inbox_state(&revision.id).as_deref() == Some("done")
            }),
            "the edit settles once a catch-up begun after it completes: {:?}",
            harness.inbox_state(&revision.id)
        );
        assert!(harness.unread("luna").is_empty());
    }

    #[test]
    #[serial]
    fn a_same_second_bucket_of_250_is_caught_up_whole() {
        // 250 events in one second, then 30 a second earlier, behind 100-event
        // pages: `until` alone re-reads the bucket's first page, and a walk
        // that calls a repeated page the end loses 150 of the bucket and all
        // the older history.
        let second = nostr::now() - 100;
        let mut events = history(250, |_| second);
        events.extend(history(30, |_| second - 1));
        let reader = LiveReader::start(|relay| {
            relay.switches.max_page.store(100, Ordering::SeqCst);
            for event in &events {
                relay.seed(event.clone());
            }
        });

        let stored = reader.inbox(280, Duration::from_secs(15));
        assert_eq!(stored.len(), 280, "every event of the bucket and before it");
        assert!(
            reader.wait_for(Duration::from_secs(5), |r| r
                .position()
                .is_some_and(|p| p.created_at == second)),
            "the position ends in the bucket's second: {:?}",
            reader.position()
        );
    }

    #[test]
    #[serial]
    fn a_backlog_past_ten_thousand_events_is_caught_up_whole() {
        // No count cap ends a catch-up: 10,500 owed events all arrive, well
        // past where a 10,000-event cap stops even after its last page.
        let now = nostr::now();
        let events = history(10_500, |i| now - 900 + (i % 800) as u64);
        let reader = LiveReader::start(|relay| {
            for event in &events {
                relay.seed(event.clone());
            }
        });
        assert_eq!(reader.inbox(10_500, Duration::from_secs(60)).len(), 10_500);
    }

    #[test]
    #[serial]
    fn a_relay_that_repeats_a_page_never_completes_a_catch_up() {
        // A relay that ignores `before_id` hands back the same page: that is
        // an error, never a short success that moves the position.
        let second = nostr::now() - 100;
        let events = history(150, |_| second);
        let reader = LiveReader::start(|relay| {
            relay.switches.max_page.store(100, Ordering::SeqCst);
            relay
                .switches
                .ignore_before_id
                .store(true, Ordering::SeqCst);
            for event in &events {
                relay.seed(event.clone());
            }
        });
        sleep(Duration::from_secs(3));
        assert_eq!(
            reader.position(),
            None,
            "an incomplete catch-up never moves the position"
        );
    }

    #[test]
    #[serial]
    fn a_backdated_publication_after_a_reconnect_reaches_the_inbox() {
        // The relay admits created_at up to 900 s in the past. One published
        // after the reconnect's catch-up must still reach the inbox live.
        let now = nostr::now();
        let old = history(1, |_| now - 700).remove(0);
        let reader = LiveReader::start(|relay| relay.seed(old.clone()));
        assert!(
            reader.wait_for(Duration::from_secs(10), |r| r.position().is_some()),
            "the first session caught up"
        );

        // The socket drops; the reader reconnects and catches up again.
        let before = reader.ws.ws_connections();
        reader
            .http
            .switches
            .drop_socket
            .store(true, Ordering::SeqCst);
        sleep(Duration::from_millis(300));
        reader
            .http
            .switches
            .drop_socket
            .store(false, Ordering::SeqCst);
        assert!(
            reader.wait_for(Duration::from_secs(10), |r| r.ws.ws_connections() > before),
            "the reader reconnected"
        );
        let marker = reader.publish_live("after the reconnect");
        assert!(
            reader.stored(&marker.id, Duration::from_secs(10)),
            "the new session is live"
        );

        let backdated = reader.publish_live_at("written ten minutes ago", nostr::now() - 600);
        assert!(
            reader.stored(&backdated.id, Duration::from_secs(10)),
            "a backdated publication arriving live is inside the live filter"
        );
    }

    #[test]
    #[serial]
    fn a_closed_channel_catches_up_what_it_missed() {
        let reader = LiveReader::start(|relay| {
            relay.switches.refuse_req.store(true, Ordering::SeqCst);
        });
        assert!(
            reader.wait_for(Duration::from_secs(10), |r| r.parked().is_some()),
            "CLOSED parks the channel"
        );
        // 150 publications while the subscription was closed: more than a
        // REQ's single stored batch, and older than any fresh live filter.
        let now = nostr::now();
        for event in history(150, |i| now - 300 + i as u64) {
            reader.http.seed(event);
        }
        reader
            .http
            .switches
            .refuse_req
            .store(false, Ordering::SeqCst);

        assert_eq!(
            reader.inbox(150, Duration::from_secs(20)).len(),
            150,
            "recovery drains the whole gap"
        );
        assert!(reader.parked().is_none(), "and the channel is unparked");
    }

    #[test]
    #[serial]
    fn a_closed_channel_is_resubscribed_and_unparked() {
        let reader = LiveReader::start(|relay| {
            relay.switches.refuse_req.store(true, Ordering::SeqCst);
        });
        assert!(
            reader.wait_for(Duration::from_secs(10), |r| r.parked().is_some()),
            "CLOSED parks the channel"
        );

        // Membership arrives (omp's 9000 landed): the next retry succeeds.
        reader
            .http
            .switches
            .refuse_req
            .store(false, Ordering::SeqCst);
        assert!(
            reader.wait_for(Duration::from_secs(10), |r| r.parked().is_none()),
            "the channel is unparked"
        );
        let live = reader.publish_live("after the retry");
        assert!(reader.stored(&live.id, Duration::from_secs(10)));
    }

    #[test]
    #[serial]
    fn a_relay_that_drops_every_session_is_retried_with_backoff() {
        let reader = LiveReader::start(|relay| {
            relay.switches.drop_socket.store(true, Ordering::SeqCst);
        });
        sleep(Duration::from_secs(3));
        let connections = reader.ws.ws_connections();
        assert!(
            connections <= 3,
            "1 s then 2 s of backoff allows three tries in 3 s, not {connections}"
        );
    }

    #[test]
    #[serial]
    fn a_stale_lock_from_a_dead_process_is_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serve.lock");
        // Written without taking the lock, so only liveness can clear it.
        std::fs::write(&path, "4294967294\n").unwrap();
        assert!(!crate::sys::process::is_alive(4294967294));
        assert!(
            ServeLock::acquire(&path).is_ok(),
            "a dead holder must not block a restart"
        );
    }
}
