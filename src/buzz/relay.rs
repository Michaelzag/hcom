//! Blocking WebSocket sessions and NIP-98 authenticated HTTP requests.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tungstenite::{Message, WebSocket, client::IntoClientRequest, stream::MaybeTlsStream};

use super::nostr::{Event, SecretKey, auth_event, http_auth_header};

const MAX_WS_BYTES: usize = 512 * 1024;
const HTTP_SUCCESS_LIMIT: u64 = 32 * 1024 * 1024;
const HTTP_ERROR_LIMIT: u64 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("relay rate limited; retry after {retry_after:?}")]
    RateLimited { retry_after: Duration },
    #[error("relay server error: {0}")]
    Server(String),
    #[error("relay rejected event: {0}")]
    Rejected(String),
    #[error("relay authentication failed: {0}")]
    Auth(String),
    #[error("relay transport error: {0}")]
    Transport(String),
    #[error("relay protocol error: {0}")]
    Protocol(String),
    #[error("relay operation timed out")]
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMsg {
    Event {
        sub: String,
        event: Event,
    },
    Eose(String),
    Closed {
        sub: String,
        reason: String,
    },
    Ok {
        id: String,
        accepted: bool,
        message: String,
    },
    Notice(String),
}

pub fn parse_retry_after(value: &str) -> Option<Duration> {
    let value = value.trim();
    let decimal = if value.bytes().all(|c| c.is_ascii_digit()) && !value.is_empty() {
        value
    } else {
        let remaining = value.split_once("retry in ")?.1;
        let end = remaining.find(|c: char| !c.is_ascii_digit())?;
        if !remaining[end..].starts_with('s') {
            return None;
        }
        &remaining[..end]
    };
    Some(Duration::from_secs(decimal.parse::<u64>().ok()?.max(1)))
}

fn transport(error: impl std::fmt::Display) -> PublishError {
    PublishError::Transport(error.to_string())
}

fn is_timeout(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
}

/// Tungstenite and rustls may issue several reads for one frame. The budget
/// belongs to the whole operation, not each successful partial socket read.
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "relay deadline expired",
            ))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn connect_socket(
    url: &str,
    timeout: Duration,
) -> Result<WebSocket<MaybeTlsStream<DeadlineStream>>, PublishError> {
    if timeout.is_zero() {
        return Err(PublishError::Timeout);
    }
    let request = url.into_client_request().map_err(transport)?;
    let host = request
        .uri()
        .host()
        .ok_or_else(|| PublishError::Protocol("missing relay host".into()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = request
        .uri()
        .port_u16()
        .unwrap_or(if request.uri().scheme_str() == Some("wss") {
            443
        } else {
            80
        });
    let deadline = Instant::now() + timeout;
    let mut last_error = io::Error::new(io::ErrorKind::NotFound, "relay host has no addresses");
    let mut stream = None;
    for address in (host, port).to_socket_addrs().map_err(transport)? {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PublishError::Timeout);
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(socket) => {
                // A blackholed path without a FIN must still die: keepalive
                // probes (60 s idle, 15 s apart) fail a half-open socket
                // even when the WS layer never reads again.
                // `socket2` is already in Cargo.lock (via tokio); promoting
                // it to a direct dependency adds no new crate. `all`
                // enables the retry-count builder; it pulls no extra
                // dependencies.
                let keepalive = socket2::TcpKeepalive::new()
                    .with_time(Duration::from_secs(60))
                    .with_interval(Duration::from_secs(15));
                // `with_retries` exists only where socket2 provides it
                // (this list mirrors socket2 0.6's own cfg); everywhere
                // else time+interval still apply.
                #[cfg(any(
                    target_os = "android",
                    target_os = "dragonfly",
                    target_os = "emscripten",
                    target_os = "freebsd",
                    target_os = "fuchsia",
                    target_os = "illumos",
                    target_os = "ios",
                    target_os = "visionos",
                    target_os = "linux",
                    target_os = "macos",
                    target_os = "netbsd",
                    target_os = "tvos",
                    target_os = "watchos",
                    target_os = "cygwin",
                    target_os = "windows",
                    target_os = "nuttx",
                    all(target_os = "wasi", not(target_env = "p1")),
                ))]
                let keepalive = keepalive.with_retries(4);
                // Best effort: a platform that refuses keepalive must not
                // lose the connector over it.
                if let Err(error) = socket2::SockRef::from(&socket).set_tcp_keepalive(&keepalive) {
                    crate::log::log_warn(
                        "buzz",
                        "relay.keepalive",
                        &format!("keeping the socket without keepalive: {error}"),
                    );
                }
                stream = Some(socket);
                break;
            }
            Err(error) => last_error = error,
        }
    }
    let stream = DeadlineStream {
        stream: stream.ok_or_else(|| transport(last_error))?,
        deadline,
    };
    // Use the tree's existing AWS-LC backend explicitly. Neither client relies
    // on installing a process-global provider, or on another caller doing so.
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(transport)?
    .with_root_certificates(rustls::RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ))
    .with_no_client_auth();
    let config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_BYTES))
        .max_frame_size(Some(MAX_WS_BYTES));
    tungstenite::client_tls_with_config(
        request,
        stream,
        Some(config),
        Some(tungstenite::Connector::Rustls(Arc::new(tls))),
    )
    .map(|(socket, _)| socket)
    .map_err(transport)
}

pub struct WsSession {
    socket: WebSocket<MaybeTlsStream<DeadlineStream>>,
    pending: VecDeque<RelayMsg>,
    timeout: Duration,
    /// When the last frame of any kind (TEXT, ping or pong) arrived. The
    /// reader's watchdog ends a session that stays silent past its
    /// read-idle limit, so a half-open socket reconnects instead of
    /// waiting on `recv` timeouts forever.
    last_inbound: Instant,
}

impl WsSession {
    pub fn connect(
        url: &str,
        key: &SecretKey,
        tag: Option<[String; 4]>,
        timeout: Duration,
    ) -> Result<Self, PublishError> {
        let socket = connect_socket(url, timeout)?;
        let mut session = Self {
            socket,
            pending: VecDeque::new(),
            timeout,
            last_inbound: Instant::now(),
        };
        // Buzz emits AUTH first and closes after five seconds. This deadline
        // covers both waiting for the challenge and receiving its acknowledgement.
        let deadline = Instant::now() + timeout.min(Duration::from_secs(5));
        let challenge = loop {
            let value = session.read_value(deadline)?.ok_or(PublishError::Timeout)?;
            if value.get(0).and_then(Value::as_str) == Some("AUTH") {
                break value
                    .get(1)
                    .and_then(Value::as_str)
                    .ok_or_else(|| PublishError::Protocol("malformed AUTH challenge".into()))?
                    .to_owned();
            }
            if let Some(message) = parse_message(&value)? {
                session.pending.push_back(message);
            }
        };
        let event = auth_event(key, url, &challenge, tag);
        session.set_deadline(deadline)?;
        session.send_value(&json!(["AUTH", event]))?;
        loop {
            let value = session.read_value(deadline)?.ok_or(PublishError::Timeout)?;
            if let Some(message) = parse_message(&value)? {
                match message {
                    RelayMsg::Ok {
                        id,
                        accepted,
                        message,
                    } if id == event.id => {
                        return if accepted {
                            Ok(session)
                        } else if message.starts_with("error:") {
                            Err(PublishError::Server(message))
                        } else {
                            Err(PublishError::Auth(message))
                        };
                    }
                    other => session.pending.push_back(other),
                }
            }
        }
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<(), PublishError> {
        self.set_deadline(Instant::now() + timeout)
    }

    fn set_deadline(&mut self, deadline: Instant) -> Result<(), PublishError> {
        if deadline <= Instant::now() {
            return Err(PublishError::Timeout);
        }
        let stream = match self.socket.get_mut() {
            MaybeTlsStream::Plain(stream) => stream,
            MaybeTlsStream::Rustls(stream) => &mut stream.sock,
            _ => return Err(PublishError::Protocol("unsupported TLS backend".into())),
        };
        stream.deadline = deadline;
        Ok(())
    }

    fn send_value(&mut self, value: &Value) -> Result<(), PublishError> {
        self.socket
            .send(Message::Text(value.to_string().into()))
            .map_err(transport)
    }

    // Tungstenite retains partially received frames on timeout, so the next
    // read can resume. Pings queue a pong automatically; flushing sends it now.
    fn read_value(&mut self, deadline: Instant) -> Result<Option<Value>, PublishError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            self.set_deadline(deadline)?;
            match self.socket.read() {
                Ok(Message::Text(text)) => {
                    self.last_inbound = Instant::now();
                    return serde_json::from_str(&text)
                        .map(Some)
                        .map_err(|_| PublishError::Protocol("invalid relay JSON".into()));
                }
                Ok(Message::Ping(_)) => {
                    self.last_inbound = Instant::now();
                    self.socket.flush().map_err(transport)?;
                }
                Ok(Message::Pong(_)) => {
                    self.last_inbound = Instant::now();
                }
                Ok(Message::Close(_)) => {
                    return Err(PublishError::Transport("relay closed socket".into()));
                }
                Ok(_) => {
                    return Err(PublishError::Protocol(
                        "unexpected non-text relay frame".into(),
                    ));
                }
                Err(error) if is_timeout(&error) => return Ok(None),
                Err(error) => return Err(transport(error)),
            }
        }
    }

    pub fn req(&mut self, sub_id: &str, filters: &[Value]) -> Result<(), PublishError> {
        self.set_timeout(self.timeout)?;
        let mut request = Vec::with_capacity(filters.len() + 2);
        request.push(json!("REQ"));
        request.push(json!(sub_id));
        request.extend_from_slice(filters);
        self.send_value(&Value::Array(request))
    }

    pub fn close(&mut self, sub_id: &str) -> Result<(), PublishError> {
        self.set_timeout(self.timeout)?;
        self.send_value(&json!(["CLOSE", sub_id]))
    }

    pub fn publish(&mut self, event: &Event) -> Result<(), PublishError> {
        let deadline = Instant::now() + self.timeout;
        self.set_deadline(deadline)?;
        self.send_value(&json!(["EVENT", event]))?;
        loop {
            let value = self.read_value(deadline)?.ok_or(PublishError::Timeout)?;
            let Some(message) = parse_message(&value)? else {
                continue;
            };
            match message {
                RelayMsg::Ok {
                    id,
                    accepted,
                    message,
                } if id == event.id => {
                    return if accepted || message.starts_with("duplicate:") {
                        Ok(())
                    } else if message.starts_with("error:") {
                        Err(PublishError::Server(message))
                    } else {
                        Err(PublishError::Rejected(message))
                    };
                }
                RelayMsg::Notice(message)
                    if message.starts_with("rate-limited: shared admission unavailable") =>
                {
                    return Err(PublishError::Server(message));
                }
                RelayMsg::Notice(message) if message.starts_with("rate-limited:") => {
                    return Err(PublishError::RateLimited {
                        retry_after: parse_retry_after(&message).unwrap_or(Duration::from_secs(1)),
                    });
                }
                other => self.pending.push_back(other),
            }
        }
    }

    /// A websocket Ping. A live relay answers with a Pong, which counts as
    /// inbound traffic and keeps an idle-but-healthy session off the
    /// reader's read-idle limit no matter how quiet the channels are.
    pub fn ping(&mut self) -> Result<(), PublishError> {
        self.set_timeout(self.timeout)?;
        self.socket
            .send(Message::Ping(Vec::new().into()))
            .map_err(transport)
    }

    /// How long since any frame (TEXT, ping or pong) arrived.
    pub fn idle(&self) -> Duration {
        self.last_inbound.elapsed()
    }

    pub fn recv(&mut self, timeout: Duration) -> Result<Option<RelayMsg>, PublishError> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(Some(message));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let Some(value) = self.read_value(deadline)? else {
                return Ok(None);
            };
            if let Some(message) = parse_message(&value)? {
                return Ok(Some(message));
            }
        }
    }
}

fn parse_message(value: &Value) -> Result<Option<RelayMsg>, PublishError> {
    let invalid = || PublishError::Protocol("malformed relay message".into());
    let array = value.as_array().ok_or_else(invalid)?;
    let text = |i| {
        array
            .get(i)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok(Some(match text(0)?.as_str() {
        "EVENT" if array.len() == 3 => RelayMsg::Event {
            sub: text(1)?,
            event: serde_json::from_value(array[2].clone()).map_err(|_| invalid())?,
        },
        "EOSE" if array.len() == 2 => RelayMsg::Eose(text(1)?),
        "CLOSED" if array.len() == 3 => RelayMsg::Closed {
            sub: text(1)?,
            reason: text(2)?,
        },
        "OK" if array.len() == 4 => RelayMsg::Ok {
            id: text(1)?,
            accepted: array[2].as_bool().ok_or_else(invalid)?,
            message: text(3)?,
        },
        "NOTICE" if array.len() == 2 => RelayMsg::Notice(text(1)?),
        // COUNT is a valid NIP-45 response but this layer doesn't request it.
        "COUNT" => return Ok(None),
        _ => return Err(invalid()),
    }))
}

pub struct HttpRelay {
    pub base_url: String,
}

impl HttpRelay {
    fn agent() -> ureq::Agent {
        let tls = ureq::tls::TlsConfig::builder()
            .unversioned_rustls_crypto_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .build();
        ureq::Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into()
    }

    fn post(
        &self,
        endpoint: &str,
        body: &[u8],
        signer: &SecretKey,
        tag: Option<&str>,
    ) -> Result<Vec<u8>, PublishError> {
        let url = format!("{}{endpoint}", self.base_url.trim_end_matches('/'));
        let agent = Self::agent();
        let mut request = agent
            .post(&url)
            .header("Content-Type", "application/json")
            .header(
                "Authorization",
                http_auth_header(signer, &url, "POST", body),
            );
        if let Some(tag) = tag {
            let tag: [String; 4] = serde_json::from_str(tag)
                .map_err(|_| PublishError::Protocol("malformed x-auth-tag".into()))?;
            request = request.header(
                "x-auth-tag",
                serde_json::to_string(&tag).expect("tag serializes"),
            );
        }
        let mut response = request.send(body).map_err(transport)?;
        let status = response.status().as_u16();
        let retry_header = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after);
        let limit = if (200..300).contains(&status) {
            HTTP_SUCCESS_LIMIT
        } else {
            HTTP_ERROR_LIMIT
        };
        let bytes = response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(transport)?;
        if (200..300).contains(&status) {
            return Ok(bytes);
        }
        let message = serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&bytes).into_owned());
        match status {
            429 => Err(PublishError::RateLimited {
                retry_after: retry_header
                    .into_iter()
                    .chain(parse_retry_after(&message))
                    .max()
                    .unwrap_or(Duration::from_secs(1)),
            }),
            500..=599 => Err(PublishError::Server(message)),
            401 | 403 => Err(PublishError::Auth(message)),
            400 => Err(PublishError::Rejected(message)),
            _ => Err(PublishError::Protocol(format!("HTTP {status}: {message}"))),
        }
    }

    pub fn post_event(
        &self,
        event: &Event,
        signer: &SecretKey,
        tag: Option<&str>,
    ) -> Result<(), PublishError> {
        let body = serde_json::to_vec(event).expect("event serializes");
        // Deployed Buzz returns HTTP 200 for duplicates, including
        // accepted=false with "duplicate: reaction already exists".
        self.post("/events", &body, signer, tag).map(|_| ())
    }

    pub fn query(
        &self,
        filter: &Value,
        signer: &SecretKey,
        tag: Option<&str>,
    ) -> Result<Vec<Event>, PublishError> {
        // The bridge always requires an array, even for one filter.
        let body = if filter.is_array() {
            serde_json::to_vec(filter)
        } else {
            serde_json::to_vec(&[filter])
        }
        .expect("filters serialize");
        let bytes = self.post("/query", &body, signer, tag)?;
        serde_json::from_slice(&bytes)
            .map_err(|_| PublishError::Protocol("invalid query response".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        nostr::{UnsignedEvent, auth_tag, derive_secret, sign},
        testing::FakeRelay,
    };
    use super::*;
    use std::sync::atomic::Ordering;

    const TIMEOUT: Duration = Duration::from_secs(2);

    fn key() -> SecretKey {
        derive_secret(&[7; 32], "TEST@mbai")
    }
    fn owner() -> SecretKey {
        SecretKey::from_bytes(&[3; 32]).unwrap()
    }
    fn message(key: &SecretKey, channel: &str, created_at: u64, text: &str) -> Event {
        sign(
            UnsignedEvent {
                created_at,
                kind: 9,
                tags: vec![vec!["h".into(), channel.into()]],
                content: text.into(),
            },
            key,
        )
    }
    fn session(fake: &FakeRelay) -> WsSession {
        let key = key();
        WsSession::connect(
            &fake.url,
            &key,
            Some(auth_tag(
                &owner(),
                &super::super::nostr::public_hex(&key),
                "",
            )),
            TIMEOUT,
        )
        .unwrap()
    }

    #[test]
    fn ws_auth_publish_history_eose_live_and_close() {
        let fake = FakeRelay::ws();
        let mut publisher = session(&fake);
        let stored = message(&key(), "channel-a", 1700000000, "stored");
        publisher.publish(&stored).unwrap();
        publisher.publish(&stored).unwrap(); // ordinary duplicate is success
        let mut reader = session(&fake);
        reader
            .req("channel", &[json!({"#h":["channel-a"],"kinds":[9]})])
            .unwrap();
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Event {
                sub: "channel".into(),
                event: stored.clone()
            })
        );
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Eose("channel".into()))
        );
        let live = message(&key(), "channel-a", 1700000001, "live");
        publisher.publish(&live).unwrap();
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Event {
                sub: "channel".into(),
                event: live
            })
        );
        assert_eq!(reader.recv(Duration::from_millis(40)).unwrap(), None);
        assert!(fake.switches.pong_received.load(Ordering::SeqCst));
        reader.close("channel").unwrap();
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Closed {
                sub: "channel".into(),
                reason: "closed by client".into()
            })
        );
        publisher
            .publish(&message(&key(), "channel-a", 1700000002, "after close"))
            .unwrap();
        assert_eq!(reader.recv(Duration::from_millis(40)).unwrap(), None);
    }

    #[test]
    fn ws_preserves_interleaved_events_and_duplicate_false_is_success() {
        let fake = FakeRelay::ws();
        let mut client = session(&fake);
        client.req("live", &[json!({"#h":["channel"]})]).unwrap();
        assert_eq!(
            client.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Eose("live".into()))
        );
        let event = message(&key(), "channel", 1700000000, "self");
        client.publish(&event).unwrap();
        assert_eq!(
            client.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Event {
                sub: "live".into(),
                event: event.clone()
            })
        );
        let reaction = sign(
            UnsignedEvent {
                created_at: 1700000001,
                kind: 7,
                tags: vec![vec!["e".into(), event.id]],
                content: "+".into(),
            },
            &key(),
        );
        client.publish(&reaction).unwrap();
        client.publish(&reaction).unwrap(); // relay OK false, duplicate prefix
        assert_eq!(
            client.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Event {
                sub: "live".into(),
                event: reaction
            })
        );
    }

    #[test]
    fn ws_rate_limited_notice_author_mismatch_auth_refusal_and_drop() {
        let fake = FakeRelay::ws();
        let mut client = session(&fake);
        fake.switches.rate_limited.store(true, Ordering::SeqCst);
        let event = message(&key(), "channel", 1700000000, "rate-limited");
        assert!(
            matches!(client.publish(&event), Err(PublishError::RateLimited { retry_after }) if retry_after == Duration::from_secs(3))
        );
        let wrong_author = message(&owner(), "channel", 1700000001, "wrong author");
        assert!(
            matches!(client.publish(&wrong_author), Err(PublishError::Rejected(message)) if message.contains("author"))
        );
        client.req("empty", &[json!({"ids":[event.id]})]).unwrap();
        assert_eq!(
            client.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Eose("empty".into())),
            "denied event wasn't stored"
        );
        fake.switches.refuse_auth.store(true, Ordering::SeqCst);
        assert!(
            matches!(WsSession::connect(&fake.url, &key(), None, TIMEOUT), Err(PublishError::Auth(message)) if message == "auth-required: verification failed")
        );
        fake.switches.drop_socket.store(true, Ordering::SeqCst);
        assert!(matches!(
            client.recv(TIMEOUT),
            Err(PublishError::Transport(_))
        ));
    }

    #[test]
    fn ws_fake_checks_signed_challenge_and_relay_binding() {
        let fake = FakeRelay::ws();
        for wrong_relay in [false, true] {
            let (mut socket, _) = tungstenite::connect(&fake.url).unwrap();
            let Message::Text(text) = socket.read().unwrap() else {
                panic!("expected challenge");
            };
            let challenge: Value = serde_json::from_str(&text).unwrap();
            let event = auth_event(
                &key(),
                if wrong_relay {
                    "ws://wrong.test"
                } else {
                    &fake.url
                },
                if wrong_relay {
                    challenge[1].as_str().unwrap()
                } else {
                    "wrong challenge"
                },
                None,
            );
            socket
                .send(Message::Text(json!(["AUTH", event]).to_string().into()))
                .unwrap();
            let Message::Text(text) = socket.read().unwrap() else {
                panic!("expected auth OK");
            };
            assert!(matches!(
                parse_message(&serde_json::from_str::<Value>(&text).unwrap()).unwrap(),
                Some(RelayMsg::Ok {
                    accepted: false,
                    ..
                })
            ));
        }
    }

    #[test]
    fn ws_filters_history_limit_and_single_channel_live_scope() {
        let fake = FakeRelay::ws();
        let mut publisher = session(&fake);
        let mut events = Vec::new();
        for i in 0..3 {
            let mut event = UnsignedEvent {
                created_at: 100 + i,
                kind: 9,
                tags: vec![
                    vec!["h".into(), "a".into()],
                    vec!["e".into(), format!("parent{i}")],
                    vec!["p".into(), "recipient".into()],
                    vec!["d".into(), "coordinate".into()],
                ],
                content: format!("event{i}"),
            };
            if i == 2 {
                event.tags[0][1] = "b".into();
            }
            let event = sign(event, &key());
            publisher.publish(&event).unwrap();
            events.push(event);
        }
        let mut reader = session(&fake);
        reader.req("filtered", &[json!({"authors":[events[0].pubkey],"kinds":[9],"#h":["a"],"#p":["recipient"],"#d":["coordinate"],"since":100,"until":101,"limit":1})]).unwrap();
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Event {
                sub: "filtered".into(),
                event: events[1].clone()
            })
        );
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Eose("filtered".into()))
        );
        reader
            .req("parent", &[json!({"#e":["parent0"],"ids":[events[0].id]})])
            .unwrap();
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Event {
                sub: "parent".into(),
                event: events[0].clone()
            })
        );
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Eose("parent".into()))
        );
        reader
            .req("global", &[json!({"#h":["a","b"],"since":1000})])
            .unwrap();
        assert_eq!(
            reader.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Eose("global".into()))
        );
        publisher
            .publish(&message(&key(), "b", 1001, "not global live"))
            .unwrap();
        assert_eq!(reader.recv(Duration::from_millis(50)).unwrap(), None);
    }

    #[test]
    fn ws_auth_timeout_is_bounded() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _socket = tungstenite::accept(stream).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });
        let started = Instant::now();
        assert!(matches!(
            WsSession::connect(&url, &key(), None, Duration::from_millis(60)),
            Err(PublishError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn http_post_query_duplicate_and_auth_boundaries() {
        let fake = FakeRelay::http();
        let relay = HttpRelay {
            base_url: fake.url.clone(),
        };
        let key = key();
        let tag = serde_json::to_string(&auth_tag(
            &owner(),
            &super::super::nostr::public_hex(&key),
            "",
        ))
        .unwrap();
        // Current: the relay refuses anything more than 900 s off its clock.
        let event = message(&key, "channel", super::super::nostr::now(), "HTTP");
        relay.post_event(&event, &key, Some(&tag)).unwrap();
        relay.post_event(&event, &key, Some(&tag)).unwrap(); // unique NIP-98 on retry
        assert_eq!(
            relay
                .query(
                    &json!({"#h":["channel"],"ids":[event.id]}),
                    &key,
                    Some(&tag)
                )
                .unwrap(),
            vec![event.clone()]
        );
        assert!(
            relay
                .query(&json!([{"#h":["wrong-channel"]}]), &key, Some(&tag))
                .unwrap()
                .is_empty()
        );
        assert!(
            matches!(relay.post_event(&event, &owner(), None), Err(PublishError::Auth(message)) if message.contains("author mismatch"))
        );
        let mut corrupt = event;
        corrupt.content.push('!');
        assert!(
            matches!(relay.post_event(&corrupt, &key, None), Err(PublishError::Rejected(message)) if message.contains("signature"))
        );
        let forged = serde_json::to_string(&auth_tag(&owner(), &"a".repeat(64), "")).unwrap();
        assert!(matches!(
            relay.query(&json!({}), &key, Some(&forged)),
            Err(PublishError::Auth(_))
        ));
    }

    #[test]
    fn http_429_retry_after_and_503_error_mapping() {
        let fake = FakeRelay::http();
        let relay = HttpRelay {
            base_url: fake.url.clone(),
        };
        let event = message(&key(), "channel", 1700000000, "limited");
        fake.switches.http_status.store(429, Ordering::SeqCst);
        assert!(
            matches!(relay.post_event(&event, &key(), None), Err(PublishError::RateLimited { retry_after }) if retry_after == Duration::from_secs(7))
        );
        fake.switches.http_retry_header.store(9, Ordering::SeqCst);
        assert!(
            matches!(relay.query(&json!({}), &key(), None), Err(PublishError::RateLimited { retry_after }) if retry_after == Duration::from_secs(9))
        );
        fake.switches.http_status.store(503, Ordering::SeqCst);
        assert!(
            matches!(relay.post_event(&event, &key(), None), Err(PublishError::Server(message)) if message == "rate-limited: shared admission unavailable")
        );
        fake.switches.http_status.store(400, Ordering::SeqCst);
        assert!(matches!(
            relay.query(&json!({}), &key(), None),
            Err(PublishError::Rejected(_))
        ));
        for status in [401, 403] {
            fake.switches.http_status.store(status, Ordering::SeqCst);
            assert!(matches!(
                relay.query(&json!({}), &key(), None),
                Err(PublishError::Auth(_))
            ));
        }
    }

    #[test]
    fn http_response_caps_and_transport_failure() {
        let fake = FakeRelay::http();
        let relay = HttpRelay {
            base_url: fake.url.clone(),
        };
        fake.switches.oversized_body.store(true, Ordering::SeqCst);
        assert!(matches!(
            relay.query(&json!({}), &key(), None),
            Err(PublishError::Transport(_))
        ));
        fake.switches.http_status.store(503, Ordering::SeqCst);
        assert!(matches!(
            relay.query(&json!({}), &key(), None),
            Err(PublishError::Transport(_))
        ));
        drop(fake);
        assert!(matches!(
            relay.query(&json!({}), &key(), None),
            Err(PublishError::Transport(_))
        ));
    }

    #[test]
    fn https_handshake_failure_returns_error_without_provider_panic() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = HttpRelay {
            base_url: format!("https://{}", listener.local_addr().unwrap()),
        };
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut hello = [0; 4096];
            assert!(stream.read(&mut hello).unwrap() > 0);
            // Deliberately close during TLS, rather than serving a certificate.
            // Provider construction must succeed and return a transport error.
        });
        assert!(matches!(
            relay.query(&json!({}), &key(), None),
            Err(PublishError::Transport(_))
        ));
        server.join().unwrap();
    }

    #[test]
    fn ws_partial_frame_respects_absolute_deadline_and_resumes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (start, ready) = std::sync::mpsc::sync_channel(0);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TIMEOUT)).unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            socket
                .send(Message::Text(
                    json!(["AUTH", "TEST challenge"]).to_string().into(),
                ))
                .unwrap();
            let Message::Text(text) = socket.read().unwrap() else {
                panic!("expected AUTH");
            };
            let auth: Value = serde_json::from_str(&text).unwrap();
            socket
                .send(Message::Text(
                    json!(["OK", auth[1]["id"], true, ""]).to_string().into(),
                ))
                .unwrap();
            ready.recv_timeout(TIMEOUT).unwrap();
            let body = json!(["NOTICE", "drip"]).to_string();
            assert!(body.len() < 126);
            socket
                .get_mut()
                .write_all(&[0x81, body.len() as u8])
                .unwrap();
            // A constant 120 ms socket timeout would restart for every byte,
            // returning the whole message after ~510 ms instead of timing out.
            for byte in body.bytes() {
                std::thread::sleep(Duration::from_millis(30));
                socket.get_mut().write_all(&[byte]).unwrap();
            }
        });
        let mut client = WsSession::connect(&url, &key(), None, TIMEOUT).unwrap();
        start.send(()).unwrap();
        let started = Instant::now();
        assert_eq!(client.recv(Duration::from_millis(120)).unwrap(), None);
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(250),
            "recv exceeded its absolute budget: {elapsed:?}"
        );
        assert_eq!(
            client.recv(TIMEOUT).unwrap(),
            Some(RelayMsg::Notice("drip".into()))
        );
        server.join().unwrap();
    }

    #[test]
    fn ws_backend_failures_are_server_errors_not_quota_or_rejection() {
        let fake = FakeRelay::ws();
        let mut client = session(&fake);
        let event = message(&key(), "channel", 1700000000, "backend failure");
        fake.switches.ws_status.store(500, Ordering::SeqCst);
        assert!(matches!(
            client.publish(&event),
            Err(PublishError::Server(message)) if message == "error: database error"
        ));
        fake.switches.ws_status.store(503, Ordering::SeqCst);
        assert!(matches!(
            client.publish(&event),
            Err(PublishError::Server(message)) if message == "rate-limited: shared admission unavailable"
        ));
        fake.switches.ws_status.store(400, Ordering::SeqCst);
        assert!(matches!(
            client.publish(&event),
            Err(PublishError::Rejected(message)) if message == "invalid: rejected by test relay"
        ));
        fake.switches.rate_limited.store(true, Ordering::SeqCst);
        assert!(matches!(
            client.publish(&event),
            Err(PublishError::RateLimited { retry_after }) if retry_after == Duration::from_secs(3)
        ));
        client.publish(&event).unwrap();
    }

    #[test]
    #[ignore = "live Buzz TLS smoke; no authentication or publication"]
    fn live_tls_nip11_and_wss_challenge() {
        // Use precisely the agent and socket connector used by the clients.
        let mut response = HttpRelay::agent()
            .get("https://zagcom.ffc-w.com/")
            .header("Accept", "application/nostr+json")
            .call()
            .unwrap();
        assert_eq!(response.status().as_u16(), 200);
        let body = response
            .body_mut()
            .with_config()
            .limit(HTTP_ERROR_LIMIT)
            .read_to_vec()
            .unwrap();
        let info: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            info["supported_nips"]
                .as_array()
                .is_some_and(|nips| nips.contains(&json!(42)))
        );
        println!("HTTPS NIP-11: status 200, advertises NIP-42, certificate verified");
        let mut socket = connect_socket("wss://zagcom.ffc-w.com", Duration::from_secs(10)).unwrap();
        let Message::Text(text) = socket.read().unwrap() else {
            panic!("expected AUTH challenge");
        };
        let frame: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(frame[0], "AUTH");
        assert!(
            frame[1]
                .as_str()
                .is_some_and(|challenge| challenge.len() == 64
                    && challenge.bytes().all(|c| c.is_ascii_hexdigit()))
        );
        println!("WSS: certificate verified, received AUTH challenge; no keys or AUTH sent");
    }

    #[test]
    fn ws_pongs_reset_read_idle_without_any_text_frame() {
        // Pongs alone are inbound traffic: a session that only pings and
        // gets ponged must never look stalled to the reader's watchdog,
        // even with no EVENT, EOSE, NOTICE or server ping at all.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            stream.set_write_timeout(Some(TIMEOUT)).unwrap();
            let mut socket = tungstenite::accept(stream).unwrap();
            socket
                .send(Message::Text(
                    json!(["AUTH", "TEST challenge"]).to_string().into(),
                ))
                .unwrap();
            let Message::Text(text) = socket.read().unwrap() else {
                panic!("expected AUTH");
            };
            let auth: Value = serde_json::from_str(&text).unwrap();
            socket
                .send(Message::Text(
                    json!(["OK", auth[1]["id"], true, ""]).to_string().into(),
                ))
                .unwrap();
            // Answer pings (tungstenite queues the pong; flushing sends it)
            // and send nothing else whatsoever.
            loop {
                match socket.read() {
                    Ok(Message::Ping(_)) => {
                        if socket.flush().is_err() {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
        let mut client = WsSession::connect(&url, &key(), None, TIMEOUT).unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            client.idle() >= Duration::from_millis(100),
            "silence accumulates idle: {:?}",
            client.idle()
        );
        // The pong lands during this wait and resets the clock mid-wait:
        // without it the idle would be the whole 150 ms sleep plus this
        // 100 ms wait (>= 250 ms); with it, only the time since the pong.
        client.ping().unwrap();
        assert_eq!(
            client.recv(Duration::from_millis(100)).unwrap(),
            None,
            "a pong is traffic, not a message"
        );
        assert!(
            client.idle() < Duration::from_millis(200),
            "the pong reset the idle clock: {:?}",
            client.idle()
        );
        drop(client);
        server.join().unwrap();
    }

    fn retry_after_parses_relay_and_header_and_floors_zero() {
        assert_eq!(
            parse_retry_after("rate-limited: quota exceeded; retry in 17s"),
            Some(Duration::from_secs(17))
        );
        assert_eq!(parse_retry_after("0"), Some(Duration::from_secs(1)));
        assert_eq!(
            parse_retry_after("retry in 0s"),
            Some(Duration::from_secs(1))
        );
        assert_eq!(parse_retry_after(" 9 "), Some(Duration::from_secs(9)));
        for invalid in [
            "",
            "retry in s",
            "retry in -1s",
            "retry in 2ms",
            "no hint",
            "18446744073709551616",
        ] {
            assert_eq!(parse_retry_after(invalid), None, "{invalid}");
        }
    }
}
