//! MQTT client lifecycle — connect, subscribe, LWT, reconnect with backoff.
//!
//! Uses rumqttc v5 blocking Connection polling in a dedicated thread.
//! Manual exponential backoff on connection errors pauses that polling thread
//! so reconnect attempts do not hammer public brokers.

use rumqttc::TlsConfiguration;
use rumqttc::v5::mqttbytes::QoS;
use rumqttc::v5::mqttbytes::v5::Packet;
use rumqttc::v5::{Client, Connection, Event, MqttOptions};
use rustls::RootCertStore;
use rustls_native_certs::load_native_certs;
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::HcomConfig;
use crate::db::HcomDb;
use crate::log;
use serde_json::json;

use super::replay::ReplayGuard;
use super::{
    get_broker_from_config, is_relay_enabled, load_psk, read_device_uuid, set_relay_status,
    state_topic, wildcard_topic,
};

/// Build a TLS config that combines webpki-roots (bundled Mozilla CAs for Android/Termux
/// compatibility) with native system certs (for private broker support).
/// This ensures public brokers work everywhere while preserving user-installed CA support.
fn relay_tls_config() -> TlsConfiguration {
    let mut root_store = RootCertStore::empty();

    // Add webpki-roots as the base — fixes Android/Termux where rustls-native-certs fails
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Also add native system certs if available, for private broker support
    let native_certs = load_native_certs();
    for cert in native_certs.certs {
        let _ = root_store.add(cert);
    }
    if !native_certs.errors.is_empty() {
        log::log_warn(
            "relay",
            "relay.native_certs_partial",
            &format!(
                "failed to load {} native cert(s); continuing with bundled roots",
                native_certs.errors.len()
            ),
        );
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsConfiguration::Rustls(Arc::new(tls_config))
}

/// Commands sent from the main thread to the relay event loop.
pub enum RelayCommand {
    /// Trigger an immediate push cycle.
    Push,
    /// Shut down gracefully.
    Shutdown,
}

/// Exponential backoff state. Doubles on each error up to max, resets on success.
struct Backoff {
    current: Duration,
    max: Duration,
}

impl Backoff {
    fn new() -> Self {
        Self {
            current: Duration::from_secs(1),
            max: Duration::from_secs(60),
        }
    }

    fn wait_duration(&self) -> Duration {
        self.current
    }

    fn increase(&mut self) {
        self.current = (self.current * 2).min(self.max);
    }

    fn reset(&mut self) {
        self.current = Duration::from_secs(1);
    }
}

/// Why [`MqttRelay::run`] returned. Every deliberate stop the worker must
/// honour — shutdown signal, watchdog auto-exit, binary replacement, command
/// channel collapse — comes back as [`RunEnd::Shutdown`] and the process ends
/// exactly as before. [`RunEnd::Ended`] means the MQTT session ended or
/// errored and the worker must reconnect with a fresh one.
#[derive(Debug)]
pub enum RunEnd {
    /// Deliberate shutdown: the worker exits after its cleanup.
    Shutdown,
    /// The session ended; the payload is what to log as `relay.session_ended`.
    Ended(String),
}

/// Recover the inner `io::Error` of a connection error, if it carries one.
fn io_error_in(err: &rumqttc::v5::ConnectionError) -> Option<&std::io::Error> {
    use rumqttc::v5::StateError;
    use rumqttc::v5::mqttbytes::Error as MqttError;
    match err {
        rumqttc::v5::ConnectionError::Io(e) => Some(e),
        rumqttc::v5::ConnectionError::MqttState(StateError::Io(e)) => Some(e),
        rumqttc::v5::ConnectionError::MqttState(StateError::Deserialization(MqttError::Io(e))) => {
            Some(e)
        }
        _ => None,
    }
}

/// Human-readable, correctly labelled form of a connection error.
///
/// rumqttc 0.25.1 reports socket *write* failures as
/// `MqttState(Deserialization(Io(..)))` — v5/framed.rs maps `feed`/`flush`
/// errors onto `StateError::Deserialization` — so a dead socket's EPIPE would
/// otherwise log as "Deserialization". Classify by the inner io kind instead:
/// EPIPE can only come from a write (a read on a dead socket returns EOF).
fn classify_conn_error(err: &rumqttc::v5::ConnectionError) -> String {
    use std::io::ErrorKind;
    match io_error_in(err) {
        Some(io) if io.kind() == ErrorKind::BrokenPipe => {
            format!("write error: broken pipe (EPIPE) on the MQTT socket: {io}")
        }
        Some(io) => format!("io error ({:?}): {io}", io.kind()),
        None => format!("{err:?}"),
    }
}

/// The `hcom relay` status detail while disconnected: live retry state,
/// rewritten at every attempt so the status never freezes on the first error
/// of an outage. Once the worker has been down for
/// [`MqttRelay::LIVENESS_TIMEOUT`] the detail also says so.
fn reconnecting_detail(
    attempt: u32,
    next_in: Duration,
    last_error: &str,
    down_for: Duration,
) -> String {
    let mut detail = format!(
        "reconnecting (attempt {attempt}, next in {}s, last error: {last_error}",
        next_in.as_secs()
    );
    if down_for >= MqttRelay::LIVENESS_TIMEOUT {
        detail.push_str(&format!("; not connected for {}s", down_for.as_secs()));
    }
    detail.push(')');
    detail
}

/// Disconnect bookkeeping for one MQTT session. Drives the
/// `relay.disconnected` / `relay.reconnect_attempt` / `relay.connected` log
/// events and the live `hcom relay` status detail: one `relay.disconnected`
/// line per disconnect epoch (the first error after a healthy period, or a
/// server disconnect) and one `relay.reconnect_attempt` line per reconnect
/// attempt. The old first-error-and-every-10th sparseness hid whole retry
/// loops.
struct DisconnectEpoch {
    /// Last observed session state: true between ConnAck and the drop.
    connected: bool,
    /// When the current period without a connection began (session start
    /// until the first ConnAck).
    down_since: Instant,
    /// Failed (re)connect attempts in the current disconnect epoch.
    attempt: u32,
    /// Whether the current epoch's `relay.disconnected` line was logged.
    epoch_logged: bool,
    consecutive_errors: u32,
    last_error: String,
}

impl DisconnectEpoch {
    fn new() -> Self {
        Self {
            connected: false,
            down_since: Instant::now(),
            attempt: 0,
            epoch_logged: false,
            consecutive_errors: 0,
            last_error: String::new(),
        }
    }

    /// A connection error — one more failed (re)connect attempt. Logs the
    /// `relay.reconnect_attempt` line immediately (one line per attempt at the
    /// connection thread's 1s..60s cadence) and refreshes the status detail.
    fn note_error(&mut self, err: &rumqttc::v5::ConnectionError, next_in: Duration) {
        self.consecutive_errors += 1;
        let cause = classify_conn_error(err);
        self.open_epoch(&cause, log::log_warn);
        self.attempt += 1;
        self.last_error = cause;
        let detail = reconnecting_detail(
            self.attempt,
            next_in,
            &self.last_error,
            self.down_since.elapsed(),
        );
        log::log_warn("relay", "relay.reconnect_attempt", &detail);
        if let Ok(db) = HcomDb::open() {
            set_relay_status(&db, "error", Some(&detail), true);
        }
    }

    /// The broker sent DISCONNECT: the session is down before the socket
    /// errors out.
    fn note_server_disconnect(&mut self) {
        self.open_epoch("server disconnect", log::log_info);
        self.last_error = "server disconnect".to_string();
    }

    /// Start a disconnect epoch unless already in one, logging its
    /// `relay.disconnected` line exactly once.
    fn open_epoch(&mut self, cause: &str, level: fn(&str, &str, &str)) {
        if self.connected {
            self.connected = false;
            self.down_since = Instant::now();
            self.attempt = 0;
        }
        if !self.epoch_logged {
            self.epoch_logged = true;
            level(
                "relay",
                "relay.disconnected",
                &format!("{cause} (consecutive={})", self.consecutive_errors),
            );
        }
    }

    /// ConnAck: the session is up again. Logs `relay.connected` with the
    /// downtime when this ends a disconnect epoch.
    fn note_connected(&mut self) {
        let down = self.down_since.elapsed();
        let was_down = self.epoch_logged || self.attempt > 0;
        if was_down {
            log::log_info(
                "relay",
                "relay.connected",
                &format!(
                    "MQTT connected (reconnected after {}s down)",
                    down.as_secs()
                ),
            );
        } else {
            log::log_info("relay", "relay.connected", "MQTT connected");
        }
        self.connected = true;
        self.attempt = 0;
        self.consecutive_errors = 0;
        self.epoch_logged = false;
        self.last_error.clear();
    }
}

/// MQTT relay client. Manages connection, subscriptions, push/pull, and lifecycle.
///
/// One instance is one MQTT session. `cmd_rx` is borrowed from the worker,
/// which keeps the channel alive across sessions so a shutdown requested
/// while a session is down still reaches the next one.
pub struct MqttRelay<'a> {
    client: Client,
    relay_id: String,
    device_uuid: String,
    /// Active sealing key. Guarded by a mutex so future refactors cannot
    /// accidentally make concurrent access compile.
    psk: Mutex<[u8; 32]>,
    /// Replay guard (clock-skew + nonce LRU).
    replay_guard: Mutex<ReplayGuard>,
    /// Channel to receive commands (push, shutdown) from external callers.
    cmd_rx: &'a mpsc::Receiver<RelayCommand>,
    /// Push interval (seconds between automatic push cycles).
    push_interval: Duration,
    /// Artificial per-event apply latency. Set only by tests, so the drain
    /// budget can be exercised without waiting for real multi-second
    /// applies. Zero in every non-test build.
    #[cfg(test)]
    apply_delay: Duration,
}

impl<'a> MqttRelay<'a> {
    const INBOUND_PUSH_DEBOUNCE: Duration = Duration::from_millis(150);

    /// If no MQTT event (success or error) arrives within this duration, the
    /// connection thread is presumed stuck or dead and the session is ended
    /// so the worker can reconnect with a fresh one. Set to 2x the MQTT
    /// keepalive (30s) to allow for normal idle periods where only PingResp
    /// events flow. Also the "has not been connected" threshold past which
    /// `hcom relay` status must say so.
    const LIVENESS_TIMEOUT: Duration = Duration::from_secs(90);

    /// Wall-clock budget for one inbound drain pass. The heartbeat write and
    /// the push timers live at the top of the loop, so a tick that spends
    /// longer than this inside `handle_event` starves them: measured applies
    /// take 0.1–2.6s each, and a full 1024-event batch kept a live relay
    /// silent for minutes while every peer's sync time kept advancing.
    const DRAIN_BUDGET: Duration = Duration::from_millis(200);

    /// Build the MQTT relay client for one MQTT session.
    ///
    /// Returns (MqttRelay, Connection). The Connection must be polled in a
    /// loop (its iterator drives the network I/O). Commands arrive on the
    /// worker-lifetime `cmd_rx` channel.
    pub fn connect(
        config: &HcomConfig,
        cmd_rx: &'a mpsc::Receiver<RelayCommand>,
    ) -> Result<(Self, Connection), String> {
        if !is_relay_enabled(config) {
            return Err("relay not configured or disabled".into());
        }

        let (host, port, use_tls) = get_broker_from_config(config).ok_or("no broker configured")?;

        let psk = load_psk(config)?;

        let relay_id = config.relay_id.clone();
        let device_uuid =
            read_device_uuid().ok_or_else(|| "failed to create device_id file".to_string())?;
        let client_id = format!("hcom-{}", super::device_id_prefix(&device_uuid));

        let mut mqttoptions = MqttOptions::new(&client_id, &host, port);
        mqttoptions.set_keep_alive(Duration::from_secs(30));
        mqttoptions.set_clean_start(true);
        mqttoptions.set_max_packet_size(Some(128 * 1024));

        // TLS
        if use_tls {
            mqttoptions.set_transport(rumqttc::Transport::tls_with_config(relay_tls_config()));
        }

        // Auth
        if !config.relay_token.is_empty() {
            mqttoptions.set_credentials("hcom", &config.relay_token);
        }

        // An LWT cannot be freshly sealed when the broker emits it. Use an
        // empty retained payload to clear the broker snapshot; peers ignore
        // the unauthenticated payload and fall back to stale-device detection.
        let lwt_topic = state_topic(&relay_id, &device_uuid);
        let lwt = rumqttc::v5::mqttbytes::v5::LastWill {
            topic: lwt_topic.clone().into(),
            message: bytes::Bytes::new(),
            qos: QoS::AtLeastOnce,
            retain: true,
            properties: None,
        };
        mqttoptions.set_last_will(lwt);

        // Create client + connection (cap=10 for outgoing message buffer)
        let (client, connection) = Client::new(mqttoptions, 10);

        let relay = MqttRelay {
            client,
            relay_id,
            device_uuid,
            psk: Mutex::new(psk),
            replay_guard: Mutex::new(ReplayGuard::default()),
            cmd_rx,
            push_interval: Duration::from_secs(5),
            #[cfg(test)]
            apply_delay: Duration::ZERO,
        };

        log::log_info(
            "relay",
            "relay.connect",
            &format!("connecting to {}:{}", host, port),
        );

        Ok((relay, connection))
    }

    /// Subscribe to relay topics. Called on initial connect and after every reconnect.
    pub fn subscribe(&self) -> Result<(), String> {
        let topic = wildcard_topic(&self.relay_id);
        self.client
            .subscribe(&topic, QoS::AtLeastOnce)
            .map_err(|e| format!("subscribe failed: {}", e))?;
        log::log_info(
            "relay",
            "relay.subscribe",
            &format!("subscribed to {}", topic),
        );
        Ok(())
    }

    /// Run one MQTT session: the main relay event loop. Blocks until the
    /// session ends — see [`RunEnd`]: a deliberate shutdown (the worker
    /// exits) or a dead/errored session (the worker reconnects).
    ///
    /// Spawns a throttled thread for the Connection polling and interleaves
    /// MQTT events with commands in the main worker loop.
    /// Uses manual exponential backoff on connection errors.
    pub fn run(self, connection: Connection) -> RunEnd {
        // Forward MQTT events from the blocking connection poller to the main
        // loop. Sleeping in this thread after errors throttles rumqttc reconnects
        // while the main worker loop stays responsive and keeps heartbeating.
        let (event_tx, event_rx) = mpsc::channel();

        thread::spawn(move || {
            let mut connection = connection;
            let mut conn_backoff = Backoff::new();
            while let Ok(notification) = connection.recv() {
                let is_error = notification.is_err();
                if event_tx.send(notification).is_err() {
                    break;
                }
                if is_error {
                    thread::sleep(conn_backoff.wait_duration());
                    conn_backoff.increase();
                } else {
                    conn_backoff.reset();
                }
            }
        });

        self.run_loop(&event_rx)
    }

    /// The worker loop proper: heartbeat, commands, push timers and the
    /// bounded inbound drain. Split out of [`Self::run`] so a test can drive
    /// it with a synthetic inbound stream and no broker.
    fn run_loop(
        &self,
        event_rx: &mpsc::Receiver<Result<Event, rumqttc::v5::ConnectionError>>,
    ) -> RunEnd {
        let mut backoff = Backoff::new();
        let mut last_push = Instant::now();
        let mut pending_push_at: Option<Instant> = None;
        let mut epoch = DisconnectEpoch::new();
        // Track last time we received ANY event (success or error) from the
        // connection thread. If this goes stale, the connection thread is dead
        // or wedged and the session is ended so the worker can reconnect.
        let mut last_event_from_conn = Instant::now();

        // Heartbeat: write epoch timestamp to KV every ~1s so readers can detect
        // unclean exits (SIGKILL, panic) that leave a stale pidfile behind. Held
        // open across the loop to avoid repeated open() overhead, but reopened
        // on each tick if the previous open failed — otherwise a transient DB
        // open failure at startup would leave the worker forever heartbeat-less,
        // which derive_relay_health would (correctly) report as Starting.
        let mut hb_db: Option<HcomDb> = HcomDb::open().ok();
        let mut last_heartbeat: Option<Instant> = None;

        // Initial subscribe
        if let Err(e) = self.subscribe() {
            log::log_warn("relay", "relay.subscribe_err", &e);
        }

        loop {
            if last_heartbeat.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                if hb_db.is_none() {
                    hb_db = HcomDb::open().ok();
                }
                if let Some(ref db) = hb_db {
                    super::write_worker_heartbeat(db);
                }
                last_heartbeat = Some(Instant::now());
            }

            // Check for commands (non-blocking, always responsive)
            match self.cmd_rx.try_recv() {
                Ok(RelayCommand::Shutdown) => {
                    log::log_info("relay", "relay.shutdown", "shutdown requested");
                    self.shutdown_graceful(event_rx);
                    return RunEnd::Shutdown;
                }
                Ok(RelayCommand::Push) => {
                    self.do_push_cycle(epoch.connected);
                    last_push = Instant::now();
                    pending_push_at = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    log::log_info("relay", "relay.shutdown", "command channel closed");
                    self.shutdown_graceful(event_rx);
                    return RunEnd::Shutdown;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }

            // Periodic push
            if epoch.connected && last_push.elapsed() >= self.push_interval {
                self.do_push_cycle(epoch.connected);
                last_push = Instant::now();
                pending_push_at = None;
            }

            if epoch.connected && pending_push_at.is_some_and(|deadline| Instant::now() >= deadline)
            {
                self.do_push_cycle(epoch.connected);
                last_push = Instant::now();
                pending_push_at = None;
            }

            // Liveness check — every tick, including during reconnect backoff
            // (the old code reset this timer there, so it could never fire):
            // if no event (success or error) arrives from the connection
            // thread for well beyond the keepalive interval, the thread is
            // stuck or dead but hasn't closed the channel. End the session so
            // the worker reconnects, and say so in the status detail instead
            // of leaving a stale error frozen there.
            if last_event_from_conn.elapsed() > Self::LIVENESS_TIMEOUT {
                let silent = last_event_from_conn.elapsed();
                log::log_warn(
                    "relay",
                    "relay.liveness_timeout",
                    &format!(
                        "no MQTT events for {}s, connection presumed dead — ending session",
                        silent.as_secs()
                    ),
                );
                let cause = format!(
                    "no MQTT events for {}s (connection presumed dead)",
                    silent.as_secs()
                );
                if let Ok(db) = HcomDb::open() {
                    set_relay_status(
                        &db,
                        "error",
                        Some(&reconnecting_detail(
                            epoch.attempt,
                            backoff.wait_duration(),
                            &cause,
                            epoch.down_since.elapsed(),
                        )),
                        true,
                    );
                }
                return RunEnd::Ended(format!(
                    "liveness timeout: no MQTT events for {}s",
                    silent.as_secs()
                ));
            }

            // Drain queued MQTT events (bounded by count AND by elapsed
            // time), then poll once with timeout. This prevents stale error
            // backlogs from burying a ConnAck behind hours of
            // one-error-per-backoff processing, while capping per-tick work
            // so the heartbeat, cmd_rx and push timers stay responsive under
            // sustained inbound traffic. The count cap alone was not enough:
            // 1024 applies at the observed 0.1–2.6s each is minutes inside a
            // single tick, long enough for every reader to see the worker as
            // stale.
            let mut drained = false;
            let mut channel_disconnected = false;
            let mut trigger_push = false;
            let mut drain_count: u32 = 0;
            const MAX_DRAIN_PER_TICK: u32 = 1024;
            let drain_deadline = Instant::now() + Self::DRAIN_BUDGET;

            // Phase 1: drain queued events without blocking (bounded)
            while drain_count < MAX_DRAIN_PER_TICK && Instant::now() < drain_deadline {
                match event_rx.try_recv() {
                    Ok(Ok(event)) => {
                        drain_count += 1;
                        drained = true;
                        backoff.reset();
                        last_event_from_conn = Instant::now();
                        if self.handle_event(event, &mut epoch) {
                            trigger_push = true;
                        }
                    }
                    Ok(Err(conn_err)) => {
                        drain_count += 1;
                        drained = true;
                        last_event_from_conn = Instant::now();
                        epoch.note_error(&conn_err, backoff.wait_duration());
                        backoff.increase();
                    }
                    Err(mpsc::TryRecvError::Empty) => {
                        // Queue fully drained.
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        channel_disconnected = true;
                        break;
                    }
                }
            }
            if channel_disconnected {
                log::log_info("relay", "relay.shutdown", "connection thread ended");
                return RunEnd::Ended("connection thread ended".to_string());
            }

            if trigger_push {
                let next_push = last_push + Self::INBOUND_PUSH_DEBOUNCE;
                pending_push_at =
                    Some(pending_push_at.map_or(next_push, |existing| existing.min(next_push)));
            }

            // Phase 2: if nothing was drained, do one blocking poll
            if !drained {
                match event_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(Ok(event)) => {
                        backoff.reset();
                        last_event_from_conn = Instant::now();
                        if self.handle_event(event, &mut epoch) {
                            let next_push = last_push + Self::INBOUND_PUSH_DEBOUNCE;
                            pending_push_at = Some(
                                pending_push_at
                                    .map_or(next_push, |existing| existing.min(next_push)),
                            );
                        }
                    }
                    Ok(Err(conn_err)) => {
                        last_event_from_conn = Instant::now();
                        epoch.note_error(&conn_err, backoff.wait_duration());
                        backoff.increase();
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        // No events — loop back to check commands and push timer
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        log::log_info("relay", "relay.shutdown", "connection thread ended");
                        return RunEnd::Ended("connection thread ended".to_string());
                    }
                }
            }
        }
    }

    /// Handle a single MQTT event.
    fn handle_event(&self, event: Event, epoch: &mut DisconnectEpoch) -> bool {
        #[cfg(test)]
        if !self.apply_delay.is_zero() {
            thread::sleep(self.apply_delay);
        }
        match event {
            Event::Incoming(incoming) => match incoming {
                Packet::ConnAck(_connack) => {
                    epoch.note_connected();
                    if let Ok(db) = HcomDb::open() {
                        set_relay_status(&db, "ok", None, true);
                    }
                    // Re-subscribe after reconnect
                    if let Err(e) = self.subscribe() {
                        log::log_warn("relay", "relay.subscribe_err", &e);
                    }
                    // Push immediately on connect to sync state
                    self.do_push_cycle(true);
                    false
                }
                Packet::Publish(publish) => {
                    let topic = String::from_utf8_lossy(&publish.topic).to_string();
                    let payload = publish.payload.to_vec();
                    self.handle_incoming_message(&topic, &payload)
                }
                Packet::Disconnect(_) => {
                    epoch.note_server_disconnect();
                    false
                }
                _ => false, // PingResp, SubAck, PubAck — ignore
            },
            Event::Outgoing(_) => false, // Outgoing events — ignore
        }
    }

    /// Handle an incoming MQTT publish message.
    ///
    /// Topic layout: `{relay_id}/{device_uuid}` for state snapshots and
    /// `{relay_id}/control` for control events. Empty state payloads may be an
    /// ungraceful LWT, but are ignored because they are unauthenticated.
    fn handle_incoming_message(&self, topic: &str, payload: &[u8]) -> bool {
        let prefix = format!("{}/", self.relay_id);
        if !topic.starts_with(&prefix) {
            return false; // Not our relay group
        }
        let suffix = &topic[prefix.len()..];

        let db = match HcomDb::open() {
            Ok(db) => db,
            Err(e) => {
                log::log_error("relay", "relay.db_err", &format!("{}", e));
                return false;
            }
        };

        if payload.is_empty() {
            if !suffix.is_empty() && suffix != "control" {
                ignore_unauthenticated_empty_state(&db, suffix);
            }
            return false;
        }

        let psk = match self.psk.lock() {
            Ok(guard) => {
                let psk = *guard;
                drop(guard);
                psk
            }
            Err(e) => {
                log::log_error("relay", "relay.psk_lock_err", &format!("{}", e));
                return false;
            }
        };
        let mut guard = match self.replay_guard.lock() {
            Ok(guard) => guard,
            Err(e) => {
                log::log_error("relay", "relay.replay_lock_err", &format!("{}", e));
                return false;
            }
        };

        let mut ctx = super::pull::InboundContext {
            psk: &psk,
            relay_id: &self.relay_id,
            topic,
            replay_guard: &mut guard,
        };

        if suffix == "control" {
            super::pull::handle_control_message(&db, payload, &self.device_uuid, &mut ctx)
        } else {
            // State message from a remote device
            let device_id = suffix;
            if device_id == self.device_uuid {
                return false; // Ignore own messages
            }
            // MQTT RETAIN is delivery metadata, not authenticated state
            // freshness. State ordering comes from the sealed timestamp.
            super::pull::handle_state_message(&db, device_id, payload, &self.device_uuid, &mut ctx)
        }
    }

    /// Re-read the active PSK from disk. This is a best-effort escape hatch for
    /// same-namespace config changes; full relay resets still restart the worker.
    fn reload_psk_if_changed(&self) {
        let cfg = match HcomConfig::load(None) {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Ok(new) = load_psk(&cfg) {
            let mut psk = match self.psk.lock() {
                Ok(psk) => psk,
                Err(e) => {
                    log::log_error("relay", "relay.psk_lock_err", &format!("{}", e));
                    return;
                }
            };
            if new != *psk {
                log::log_info(
                    "relay",
                    "relay.psk_reload",
                    &format!(
                        "active key reloaded to fingerprint={}",
                        super::crypto::fingerprint(&new)
                    ),
                );
                *psk = new;
            }
        }
    }

    /// Execute a push cycle: build state + events, publish to MQTT.
    fn do_push_cycle(&self, mqtt_connected: bool) {
        let db = match HcomDb::open() {
            Ok(db) => db,
            Err(e) => {
                log::log_error("relay", "relay.db_err", &format!("{}", e));
                return;
            }
        };

        self.reload_psk_if_changed();
        let psk = match self.psk.lock() {
            Ok(psk) => *psk,
            Err(e) => {
                log::log_error("relay", "relay.psk_lock_err", &format!("{}", e));
                return;
            }
        };

        // Drain loop with 10s budget
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match super::push::push(
                &db,
                &self.client,
                &self.relay_id,
                &self.device_uuid,
                &psk,
                true,
                mqtt_connected,
            ) {
                Ok((true, has_more)) => {
                    if has_more && Instant::now() < deadline {
                        continue; // More events to drain
                    }
                    break;
                }
                Ok((false, _)) => break,
                Err(e) => {
                    log::log_warn("relay", "relay.push_err", &e);
                    if let Ok(db) = HcomDb::open() {
                        set_relay_status(&db, "error", Some(&e), true);
                    }
                    break;
                }
            }
        }
    }

    /// Graceful shutdown: publish an authenticated retained tombstone, wait for
    /// PUBACK, then disconnect.
    fn shutdown_graceful(
        &self,
        event_rx: &mpsc::Receiver<Result<Event, rumqttc::v5::ConnectionError>>,
    ) {
        let topic = state_topic(&self.relay_id, &self.device_uuid);
        log::log_info(
            "relay",
            "relay.shutdown_graceful",
            "publishing authenticated state tombstone",
        );

        let tombstone = self
            .psk
            .lock()
            .map_err(|e| format!("PSK lock poisoned: {e}"))
            .and_then(|psk| seal_state_tombstone(&psk, &self.relay_id, &topic));

        let publish_result = tombstone.and_then(|payload| {
            self.client
                .publish(&topic, QoS::AtLeastOnce, true, payload)
                .map_err(|e| e.to_string())
        });
        if let Err(e) = publish_result {
            log::log_warn("relay", "relay.shutdown_publish_err", &e);
        } else {
            // Wait for PUBACK (up to 5s) by draining the event channel
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                match event_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(Ok(Event::Incoming(Packet::PubAck(_)))) => break,
                    Ok(Err(_)) => break, // Connection error
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    _ => continue, // Other events or timeout — keep waiting
                }
            }
        }

        if let Err(e) = self.client.disconnect() {
            log::log_warn("relay", "relay.disconnect_err", &format!("{}", e));
        }

        // Update status in DB
        if let Ok(db) = HcomDb::open() {
            set_relay_status(&db, "disconnected", None, true);
        }
    }

    /// Get relay_id.
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Get device_uuid.
    pub fn device_uuid(&self) -> &str {
        &self.device_uuid
    }
}

fn ignore_unauthenticated_empty_state(_db: &HcomDb, device_id: &str) {
    log::log_warn(
        "relay",
        "relay.empty_state_ignored",
        &format!(
            "ignored unauthenticated empty retained payload for device={}",
            super::device_id_prefix(device_id)
        ),
    );
}

fn seal_state_tombstone(psk: &[u8; 32], relay_id: &str, topic: &str) -> Result<Vec<u8>, String> {
    let payload = serde_json::to_vec(&json!({
        "state": serde_json::Value::Null,
        "events": [],
    }))
    .map_err(|e| format!("failed to serialize state tombstone: {e}"))?;
    let ts_secs = crate::shared::time::now_epoch_f64() as u64;
    super::crypto::seal(psk, relay_id, topic, &payload, ts_secs)
        .map_err(|e| format!("failed to seal state tombstone: {e}"))
}

/// Tracks PUBACK or connection error for an ephemeral publish.
#[derive(Default)]
struct PubResult {
    acked: bool,
    errored: bool,
}

/// Ephemeral MQTT client for one-shot publishes (CLI callers like stop/kill).
/// Wraps a rumqttc Client with PUBACK tracking so callers can wait for
/// delivery confirmation instead of blindly sleeping.
pub struct EphemeralClient {
    client: Client,
    /// Signaled on PubAck (acked=true) or connection error (errored=true).
    pub_result: Arc<(Mutex<PubResult>, Condvar)>,
}

impl EphemeralClient {
    /// Publish a message and wait for PUBACK (up to `timeout`).
    /// Returns true if the broker acknowledged delivery within the timeout.
    /// Returns false immediately on connection error (no 5s wait).
    pub fn publish_and_wait(
        &self,
        topic: &str,
        qos: QoS,
        retain: bool,
        payload: Vec<u8>,
        timeout: Duration,
    ) -> bool {
        if self.client.publish(topic, qos, retain, payload).is_err() {
            return false;
        }

        let (lock, cvar) = &*self.pub_result;
        let guard = match lock.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };

        // Exit wait on either ack or error
        let (result, _) = cvar
            .wait_timeout_while(guard, timeout, |r| !r.acked && !r.errored)
            .ok()
            .unzip();

        result.map(|r| r.acked).unwrap_or(false)
    }

    /// Get a reference to the underlying rumqttc Client.
    pub fn client_ref(&self) -> &Client {
        &self.client
    }

    /// Disconnect the ephemeral client.
    pub fn disconnect(self) {
        let _ = self.client.disconnect();
    }
}

/// Create an ephemeral MQTT client for one-shot publishes (CLI callers like stop/kill).
/// Connects, waits for CONNACK (up to 5s), disconnects on failure. Returns None on failure.
/// The returned EphemeralClient tracks PUBACK so callers can wait for delivery confirmation.
pub fn create_ephemeral_client(config: &HcomConfig) -> Option<EphemeralClient> {
    let (host, port, use_tls) = super::get_broker_from_config(config)?;

    let client_id = format!("hcom-ephemeral-{}", std::process::id());
    let mut mqttoptions = MqttOptions::new(&client_id, &host, port);
    mqttoptions.set_keep_alive(Duration::from_secs(10));
    mqttoptions.set_clean_start(true);

    if use_tls {
        mqttoptions.set_transport(rumqttc::Transport::tls_with_config(relay_tls_config()));
    }

    if !config.relay_token.is_empty() {
        mqttoptions.set_credentials("hcom", &config.relay_token);
    }

    let (client, connection) = Client::new(mqttoptions, 10);

    // Shared state for CONNACK wait
    let connected = Arc::new((Mutex::new(false), Condvar::new()));
    let connected_clone = connected.clone();

    // Shared state for PUBACK tracking (single-shot: any PubAck means our publish was confirmed)
    let pub_result = Arc::new((Mutex::new(PubResult::default()), Condvar::new()));
    let pub_result_clone = pub_result.clone();

    // Spawn a background thread to drive the connection event loop.
    thread::spawn(move || {
        let mut connection = connection;
        for event in connection.iter() {
            match &event {
                Ok(Event::Incoming(Packet::ConnAck(_))) => {
                    let (lock, cvar) = &*connected_clone;
                    if let Ok(mut flag) = lock.lock() {
                        *flag = true;
                        cvar.notify_one();
                    }
                }
                Ok(Event::Incoming(Packet::PubAck(_))) => {
                    let (lock, cvar) = &*pub_result_clone;
                    if let Ok(mut r) = lock.lock() {
                        r.acked = true;
                        cvar.notify_one();
                    }
                }
                Err(_) => {
                    // Signal failure so waiters don't block forever.
                    // Must hold mutex when notifying to avoid lost-wakeup race.
                    // Leave flag=false so waiter knows connection failed.
                    let (lock, cvar) = &*connected_clone;
                    if let Ok(_g) = lock.lock() {
                        cvar.notify_one();
                    }
                    let (lock, cvar) = &*pub_result_clone;
                    if let Ok(mut r) = lock.lock() {
                        r.errored = true;
                        cvar.notify_one();
                    }
                    break;
                }
                _ => {}
            }
        }
    });

    // Wait for CONNACK with 5s timeout
    let (lock, cvar) = &*connected;
    let guard = lock.lock().ok()?;
    let (flag, _) = cvar.wait_timeout(guard, Duration::from_secs(5)).ok()?;

    if !*flag {
        let _ = client.disconnect();
        return None;
    }

    Some(EphemeralClient { client, pub_result })
}

/// Publish an authenticated retained tombstone to clear device state and
/// disconnect an ephemeral client. Literal empty MQTT payloads are ignored.
pub fn clear_retained_state(config: &HcomConfig) -> bool {
    if config.relay_id.is_empty() {
        return false;
    }
    let relay_id = &config.relay_id;

    let device_uuid = match read_device_uuid() {
        Some(uuid) => uuid,
        None => return false,
    };
    let topic = state_topic(relay_id, &device_uuid);
    let psk = match load_psk(config) {
        Ok(psk) => psk,
        Err(_) => return false,
    };
    let sealed = match seal_state_tombstone(&psk, relay_id, &topic) {
        Ok(sealed) => sealed,
        Err(_) => return false,
    };

    let client = match create_ephemeral_client(config) {
        Some(c) => c,
        None => return false,
    };

    let result = client.publish_and_wait(
        &topic,
        QoS::AtLeastOnce,
        true,
        sealed,
        Duration::from_secs(5),
    );

    client.disconnect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::test_helpers::isolated_test_env;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_ignore_unauthenticated_empty_state_does_not_delete_peer_instances() {
        let (_dir, _hcom_dir, _home, _guard) = isolated_test_env();
        let db = HcomDb::open().unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, origin_device_id, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params!["luna:ABCD", "device-1234", 1.0],
            )
            .unwrap();

        ignore_unauthenticated_empty_state(&db, "device-1234");

        assert!(db.get_instance_full("luna:ABCD").unwrap().is_some());
    }

    #[test]
    fn test_state_tombstone_is_authenticated_null_state() {
        let psk = [0x42; 32];
        let relay_id = "relay-test";
        let topic = "relay-test/device-1234";
        let sealed = seal_state_tombstone(&psk, relay_id, topic).unwrap();
        let plaintext = crate::relay::crypto::open(&psk, relay_id, topic, &sealed).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();

        assert!(payload["state"].is_null());
        assert_eq!(payload["events"], json!([]));
    }

    /// rumqttc 0.25.1 reports a socket write failure as
    /// `MqttState(Deserialization(Io(..)))` (v5/framed.rs maps `feed`/`flush`
    /// errors there). A write-side EPIPE must be labelled as a write error,
    /// never as "Deserialization".
    #[test]
    fn epipe_is_labeled_a_write_error_not_deserialization() {
        use rumqttc::v5::StateError;
        use rumqttc::v5::mqttbytes::Error as MqttError;
        let err = rumqttc::v5::ConnectionError::MqttState(StateError::Deserialization(
            MqttError::Io(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
        ));
        let label = classify_conn_error(&err);
        assert!(label.contains("write error"), "{label}");
        assert!(label.contains("broken pipe"), "{label}");
        assert!(!label.to_lowercase().contains("deserialization"), "{label}");
    }

    /// Non-write io errors keep their io kind in the label.
    #[test]
    fn io_errors_carry_their_kind() {
        let err = rumqttc::v5::ConnectionError::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        ));
        let label = classify_conn_error(&err);
        assert!(label.starts_with("io error (ConnectionRefused)"), "{label}");
    }

    /// The disconnected status detail is rewritten per attempt (never a frozen
    /// first error) and says "not connected for" past the liveness threshold.
    #[test]
    fn reconnecting_detail_is_live_and_reports_long_downtime() {
        let short = reconnecting_detail(
            3,
            Duration::from_secs(8),
            "write error: broken pipe (EPIPE)",
            Duration::from_secs(20),
        );
        assert_eq!(
            short,
            "reconnecting (attempt 3, next in 8s, last error: write error: broken pipe (EPIPE))"
        );

        let long = reconnecting_detail(
            12,
            Duration::from_secs(60),
            "io error (ConnectionRefused): refused",
            Duration::from_secs(125),
        );
        assert!(
            long.starts_with(
                "reconnecting (attempt 12, next in 60s, last error: io error (ConnectionRefused): refused"
            ),
            "{long}"
        );
        assert!(long.contains("not connected for 125s"), "{long}");
    }

    /// A steady inbound stream with slow applies must not starve the
    /// heartbeat or the push timer: both live at the top of the worker loop,
    /// so a drain that runs unbounded keeps every reader looking at a stale
    /// worker while peers' sync times advance. This is the mbai
    /// 2026-10-01T06:50Z stall — a 1024-event tick at the observed per-apply
    /// cost lasted minutes.
    ///
    /// Asserts two consumer-visible facts while the queue is deep: the
    /// heartbeat KV keeps advancing (at least every ~1.5s), and at least one
    /// push happens before the last queued event has been applied.
    #[test]
    #[serial]
    fn slow_inbound_drain_still_heartbeats_and_pushes() {
        use rumqttc::v5::mqttbytes::v5::{ConnAck, ConnectReturnCode, Publish};
        use std::sync::atomic::{AtomicBool, Ordering};

        const EVENTS: u64 = 150;
        const APPLY_DELAY: Duration = Duration::from_millis(30);
        const PUSH_INTERVAL: Duration = Duration::from_millis(300);
        const SAMPLE: Duration = Duration::from_millis(25);
        // The heartbeat writes on its own ~1s cadence, and the loop revisits
        // the top at least once per DRAIN_BUDGET (200ms), so the floor is
        // ~1.2s. Leave room for a push cycle and scheduler noise on a loaded
        // runner: the unfixed loop wrote the heartbeat exactly once for the
        // whole ~4.5s drain, which fails both this bound and the count above.
        const MAX_HEARTBEAT_GAP: Duration = Duration::from_millis(2500);
        const RELAY_ID: &str = "relay-drain";

        let (_dir, _hcom_dir, _home, _guard) = isolated_test_env();

        // The Connection is never polled, so no socket is opened; holding it
        // keeps the request channel alive, which is what makes a push cycle
        // (and its `relay_last_push` write) succeed without a broker.
        let (client, _connection) =
            Client::new(MqttOptions::new("hcom-drain-test", "127.0.0.1", 1883), 4096);
        let (_cmd_tx, cmd_rx) = mpsc::channel::<RelayCommand>();
        let relay = MqttRelay {
            client,
            relay_id: RELAY_ID.to_string(),
            device_uuid: "device-own".to_string(),
            psk: Mutex::new([0x42; 32]),
            replay_guard: Mutex::new(ReplayGuard::default()),
            cmd_rx: &cmd_rx,
            push_interval: PUSH_INTERVAL,
            apply_delay: APPLY_DELAY,
        };

        let (event_tx, event_rx) = mpsc::channel::<Result<Event, rumqttc::v5::ConnectionError>>();
        // ConnAck first: the push timers only run in a connected epoch.
        event_tx
            .send(Ok(Event::Incoming(Packet::ConnAck(ConnAck {
                session_present: false,
                code: ConnectReturnCode::Success,
                properties: None,
            }))))
            .unwrap();

        let producer = thread::spawn(move || {
            let psk = [0x42u8; 32];
            let base_ts = crate::shared::time::now_epoch_f64() as u64;
            for i in 0..EVENTS {
                let device = format!("device-peer-{i:03}");
                let topic = format!("{RELAY_ID}/{device}");
                let payload = json!({
                    "state": {
                        "short_id": format!("P{i:03}"),
                        "reset_ts": 0.0,
                        "instances": {},
                    },
                    "events": []
                });
                let envelope = crate::relay::crypto::seal(
                    &psk,
                    RELAY_ID,
                    &topic,
                    &serde_json::to_vec(&payload).unwrap(),
                    base_ts + i,
                )
                .unwrap();
                let publish = Publish {
                    qos: QoS::AtLeastOnce,
                    retain: true,
                    topic: bytes::Bytes::copy_from_slice(topic.as_bytes()),
                    payload: bytes::Bytes::from(envelope),
                    ..Default::default()
                };
                // All events are queued up front: the loop cannot outrun a
                // 30ms-per-apply drain of the whole batch.
                if event_tx
                    .send(Ok(Event::Incoming(Packet::Publish(publish))))
                    .is_err()
                {
                    break;
                }
            }
        });

        let done = Arc::new(AtomicBool::new(false));
        let last_device = format!("device-peer-{:03}", EVENTS - 1);
        let sampler = {
            let sampler_device = last_device.clone();
            let done = done.clone();
            thread::spawn(move || {
                let db = HcomDb::open().unwrap();
                let mut hb_changes: Vec<Instant> = Vec::new();
                let mut last_hb: Option<String> = None;
                let mut push_changes = 0usize;
                let mut push_before_drain = 0usize;
                let mut last_push: Option<String> = None;
                while !done.load(Ordering::Relaxed) {
                    let drained = db
                        .kv_get(&format!("relay_sync_time_{sampler_device}"))
                        .ok()
                        .flatten()
                        .is_some();
                    if let Some(hb) = db.kv_get(super::super::HEARTBEAT_KEY).ok().flatten()
                        && last_hb.as_deref() != Some(hb.as_str())
                    {
                        hb_changes.push(Instant::now());
                        last_hb = Some(hb);
                    }
                    if let Some(p) = db.kv_get("relay_last_push").ok().flatten()
                        && last_push.as_deref() != Some(p.as_str())
                    {
                        push_changes += 1;
                        if !drained {
                            push_before_drain += 1;
                        }
                        last_push = Some(p);
                    }
                    thread::sleep(SAMPLE);
                }
                (hb_changes, push_changes, push_before_drain)
            })
        };

        let end = relay.run_loop(&event_rx);
        done.store(true, Ordering::Relaxed);
        producer.join().unwrap();
        let (hb_changes, push_changes, push_before_drain) = sampler.join().unwrap();

        assert!(
            matches!(end, RunEnd::Ended(_)),
            "loop should end when the producer drops the event channel: {end:?}"
        );

        // Every queued event was really applied (30ms each), so the sampler
        // above watched a deep, slow queue — not an idle loop.
        let db = HcomDb::open().unwrap();
        assert!(
            db.kv_get(&format!("relay_sync_time_{last_device}"))
                .ok()
                .flatten()
                .is_some(),
            "the synthetic inbound stream must be fully applied"
        );

        assert!(
            hb_changes.len() >= 2,
            "heartbeat must keep advancing while the inbound queue drains, saw {} writes",
            hb_changes.len()
        );
        let worst_gap = hb_changes
            .windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .max()
            .unwrap_or_default();
        assert!(
            worst_gap <= MAX_HEARTBEAT_GAP,
            "heartbeat stalled for {worst_gap:?} under a slow inbound drain"
        );

        assert!(
            push_before_drain >= 1,
            "a push must be attempted while events are still queued \
             (pushes={push_changes}, before_drain={push_before_drain})"
        );
    }
}
