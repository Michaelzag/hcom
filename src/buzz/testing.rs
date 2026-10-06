//! In-process, blocking test relay. All keys used here are fixed TEST keys.

use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU16, Ordering},
    mpsc,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use tungstenite::{Message, WebSocket};

use super::nostr::{Event, now, sha256_hex, verify, verify_auth_tag};

#[derive(Default)]
pub struct Switches {
    pub rate_limited: AtomicBool,
    pub drop_socket: AtomicBool,
    pub refuse_auth: AtomicBool,
    pub ws_status: AtomicU16,
    pub http_status: AtomicU16,
    pub http_retry_header: AtomicU16,
    pub pong_received: AtomicBool,
    pub oversized_body: AtomicBool,
}

struct Subscription {
    client: usize,
    sub: String,
    filters: Vec<Value>,
    sender: mpsc::Sender<Value>,
}

#[derive(Default)]
struct State {
    events: Vec<Event>,
    subscriptions: Vec<Subscription>,
    auth_ids: HashSet<String>,
}

pub struct FakeRelay {
    pub url: String,
    pub switches: Arc<Switches>,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FakeRelay {
    /// Every event the relay has stored, oldest first.
    ///
    /// Reads the store directly rather than going back over HTTP, so an
    /// assertion still works while the fault switches make calls fail.
    pub fn events(&self) -> Vec<Event> {
        self.state.lock().events.clone()
    }

    /// Authenticated HTTP requests the relay has accepted a NIP-98 header for,
    /// whatever it answered: what a client's request discipline is judged by.
    pub fn http_requests(&self) -> usize {
        self.state.lock().auth_ids.len()
    }
    /// Store an event as if it had arrived over the wire, so a test can seed a
    /// history the connector then backfills.
    pub fn seed(&self, event: Event) {
        let mut state = self.state.lock();
        if !state.events.iter().any(|stored| stored.id == event.id) {
            state.events.push(event);
        }
    }

    pub fn ws() -> Self {
        Self::start(false)
    }
    pub fn http() -> Self {
        Self::start(true)
    }

    fn start(http: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "{}://{}",
            if http { "http" } else { "ws" },
            listener.local_addr().unwrap()
        );
        let state = Arc::new(Mutex::new(State::default()));
        let switches = Arc::new(Switches::default());
        let server_state = state.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let server_url = url.clone();
        let server_switches = switches.clone();
        let server_stop = stop.clone();
        let handle = thread::spawn(move || {
            let mut workers = Vec::new();
            while !server_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        // Windows accepted sockets inherit the listener's
                        // nonblocking mode; the handlers need blocking reads.
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        let state = server_state.clone();
                        let switches = server_switches.clone();
                        let stop = server_stop.clone();
                        let url = server_url.clone();
                        let client = workers.len();
                        workers.push(thread::spawn(move || {
                            if http {
                                handle_http(stream, &url, &state, &switches);
                            } else {
                                handle_ws(stream, &url, client, &state, &switches, &stop);
                            }
                        }));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
                    }
                    Err(e) => panic!("fake listener: {e}"),
                }
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            url,
            switches,
            state,
            stop,
            thread: Some(handle),
        }
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    let mut tags = event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|value| value == name));
    let value = tags.next()?.get(1)?.as_str();
    if tags.next().is_some() {
        return None;
    }
    Some(value)
}

fn valid_oa(event: &Event) -> bool {
    let tags: Vec<_> = event
        .tags
        .iter()
        .filter(|tag| tag.first().is_some_and(|t| t == "auth"))
        .collect();
    tags.is_empty() || (tags.len() == 1 && verify_auth_tag(tags[0], &event.pubkey))
}

fn send(socket: &mut WebSocket<TcpStream>, value: Value) -> bool {
    socket.send(Message::Text(value.to_string().into())).is_ok()
}

fn handle_ws(
    stream: TcpStream,
    url: &str,
    client: usize,
    state: &Mutex<State>,
    switches: &Switches,
    stop: &AtomicBool,
) {
    let Ok(mut socket) = tungstenite::accept(stream) else {
        return;
    };
    let challenge = uuid::Uuid::new_v4().to_string();
    if !send(&mut socket, json!(["AUTH", challenge])) {
        return;
    }
    let Ok(Message::Text(text)) = socket.read() else {
        return;
    };
    let Ok(auth) = serde_json::from_str::<Value>(&text) else {
        return;
    };
    let Some(raw) = auth.get(1) else {
        return;
    };
    let Ok(event) = serde_json::from_value::<Event>(raw.clone()) else {
        return;
    };
    let accepted = !switches.refuse_auth.load(Ordering::SeqCst)
        && auth.get(0).and_then(Value::as_str) == Some("AUTH")
        && event.kind == 22242
        && verify(&event)
        && valid_oa(&event)
        && event.created_at.abs_diff(now()) <= 60
        && tag_value(&event, "challenge") == Some(challenge.as_str())
        && tag_value(&event, "relay") == Some(url);
    if !send(
        &mut socket,
        json!([
            "OK",
            event.id,
            accepted,
            if accepted {
                ""
            } else {
                "auth-required: verification failed"
            }
        ]),
    ) || !accepted
    {
        return;
    }
    let pubkey = event.pubkey;
    if socket.send(Message::Ping(vec![1, 2, 3].into())).is_err() {
        return;
    }
    socket
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let (sender, receiver) = mpsc::channel();
    'session: while !stop.load(Ordering::SeqCst) && !switches.drop_socket.load(Ordering::SeqCst) {
        for message in receiver.try_iter() {
            if !send(&mut socket, message) {
                break 'session;
            }
        }
        let text = match socket.read() {
            Ok(Message::Text(text)) => text,
            Ok(Message::Ping(_)) => {
                if socket.flush().is_err() {
                    break;
                }
                continue;
            }
            Ok(Message::Pong(_)) => {
                switches.pong_received.store(true, Ordering::SeqCst);
                continue;
            }
            Ok(Message::Close(_)) => break,
            Ok(_) => continue,
            Err(tungstenite::Error::Io(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        match value.get(0).and_then(Value::as_str) {
            Some("EVENT") => {
                if switches.rate_limited.swap(false, Ordering::SeqCst) {
                    if !send(
                        &mut socket,
                        json!(["NOTICE", "rate-limited: quota exceeded; retry in 3s"]),
                    ) {
                        break;
                    }
                    continue;
                }
                let Ok(event) = serde_json::from_value::<Event>(value[1].clone()) else {
                    continue;
                };
                let injected = match switches.ws_status.swap(0, Ordering::SeqCst) {
                    400 => Some(json!([
                        "OK",
                        event.id,
                        false,
                        "invalid: rejected by test relay"
                    ])),
                    500 => Some(json!(["OK", event.id, false, "error: database error"])),
                    503 => Some(json!([
                        "NOTICE",
                        "rate-limited: shared admission unavailable"
                    ])),
                    _ => None,
                };
                if let Some(injected) = injected {
                    if !send(&mut socket, injected) {
                        break;
                    }
                    continue;
                }
                if event.pubkey != pubkey || !verify(&event) {
                    if !send(
                        &mut socket,
                        json!([
                            "OK",
                            event.id,
                            false,
                            "restricted: event author must match authenticated pubkey"
                        ]),
                    ) {
                        break;
                    }
                    continue;
                }
                let mut state = state.lock();
                let duplicate = state.events.iter().any(|stored| stored.id == event.id);
                if !duplicate {
                    state.events.push(event.clone());
                    for subscription in &state.subscriptions {
                        if live_channel(&subscription.filters).is_some_and(|channel| {
                            event_channel(&event, &state.events) == Some(channel)
                        }) && subscription
                            .filters
                            .iter()
                            .any(|filter| matches_filter(&event, filter, &state.events))
                        {
                            let _ =
                                subscription
                                    .sender
                                    .send(json!(["EVENT", subscription.sub, event]));
                        }
                    }
                }
                if !send(
                    &mut socket,
                    json!([
                        "OK",
                        event.id,
                        !duplicate || event.kind != 7,
                        if duplicate && event.kind == 7 {
                            "duplicate: reaction already exists"
                        } else if duplicate {
                            "duplicate:"
                        } else {
                            ""
                        }
                    ]),
                ) {
                    break;
                }
            }
            Some("REQ") => {
                let Some(sub) = value.get(1).and_then(Value::as_str) else {
                    continue;
                };
                let Some(array) = value.as_array() else {
                    continue;
                };
                let filters = &array[2..];
                let mut state = state.lock();
                let events = query_events(&state.events, filters);
                state
                    .subscriptions
                    .retain(|s| s.client != client || s.sub != sub);
                state.subscriptions.push(Subscription {
                    client,
                    sub: sub.into(),
                    filters: filters.to_vec(),
                    sender: sender.clone(),
                });
                for event in events {
                    if !send(&mut socket, json!(["EVENT", sub, event])) {
                        break 'session;
                    }
                }
                if !send(&mut socket, json!(["EOSE", sub])) {
                    break;
                }
            }
            Some("CLOSE") => {
                let sub = value.get(1).and_then(Value::as_str).unwrap_or("");
                state
                    .lock()
                    .subscriptions
                    .retain(|s| s.client != client || s.sub != sub);
                if !send(&mut socket, json!(["CLOSED", sub, "closed by client"])) {
                    break;
                }
            }
            Some("AUTH")
                if !send(
                    &mut socket,
                    json!(["NOTICE", "restricted: already authenticated"]),
                ) =>
            {
                break;
            }
            _ => {}
        }
    }
    state.lock().subscriptions.retain(|s| s.client != client);
}

fn live_channel(filters: &[Value]) -> Option<&str> {
    let channel = filters.first()?.get("#h")?.as_array()?;
    if channel.len() != 1 {
        return None;
    }
    let channel = channel[0].as_str()?;
    filters
        .iter()
        .all(|filter| {
            filter
                .get("#h")
                .and_then(Value::as_array)
                .is_some_and(|values| values.len() == 1 && values[0].as_str() == Some(channel))
        })
        .then_some(channel)
}

fn event_channel<'a>(event: &'a Event, events: &'a [Event]) -> Option<&'a str> {
    if let Some(channel) = tag_value(event, "h") {
        return Some(channel);
    }
    if matches!(event.kind, 5 | 7 | 9005) {
        let target = tag_value(event, "e")?;
        return events
            .iter()
            .find(|event| event.id == target)
            .and_then(|event| tag_value(event, "h"));
    }
    None
}

fn matches_filter(event: &Event, filter: &Value, events: &[Event]) -> bool {
    let Some(filter) = filter.as_object() else {
        return false;
    };
    filter.iter().all(|(key, value)| match key.as_str() {
        "ids" | "authors" => value.as_array().is_some_and(|values| {
            values.iter().any(|v| {
                v.as_str().is_some_and(|prefix| {
                    (if key == "ids" {
                        &event.id
                    } else {
                        &event.pubkey
                    })
                    .starts_with(prefix)
                })
            })
        }),
        "kinds" => value.as_array().is_some_and(|values| {
            values
                .iter()
                .any(|v| v.as_u64() == Some(u64::from(event.kind)))
        }),
        "since" => value
            .as_u64()
            .is_some_and(|since| event.created_at >= since),
        "until" => value
            .as_u64()
            .is_some_and(|until| event.created_at <= until),
        "limit" => true,
        tag if tag.starts_with('#') => value.as_array().is_some_and(|values| {
            values.iter().any(|v| {
                v.as_str().is_some_and(|wanted| {
                    if tag == "#h" {
                        event_channel(event, events) == Some(wanted)
                    } else {
                        event.tags.iter().any(|t| {
                            t.first().is_some_and(|n| n == &tag[1..])
                                && t.get(1).is_some_and(|value| value == wanted)
                        })
                    }
                })
            })
        }),
        _ => false,
    })
}

fn query_events(events: &[Event], filters: &[Value]) -> Vec<Event> {
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    for filter in filters {
        let mut matches: Vec<_> = events
            .iter()
            .filter(|event| matches_filter(event, filter, events))
            .collect();
        matches.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        let limit = filter
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        for event in matches
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
        {
            if seen.insert(&event.id) {
                result.push(event.clone());
            }
        }
    }
    result
}

fn handle_http(stream: TcpStream, url: &str, state: &Mutex<State>, switches: &Switches) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() {
        return;
    }
    let parts: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
    if parts.len() != 3 {
        return;
    }
    let mut headers = HashMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        if let Some((key, value)) = line.trim_end().split_once(':') {
            headers.insert(key.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    if length > 1024 * 1024 {
        return;
    }
    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let mut stream = reader.into_inner();
    let auth = headers
        .get("authorization")
        .and_then(|header| header.strip_prefix("Nostr "))
        .and_then(|raw| STANDARD.decode(raw).ok())
        .and_then(|bytes| serde_json::from_slice::<Event>(&bytes).ok());
    let Some(auth) = auth else {
        respond(
            &mut stream,
            401,
            json!({"error":"missing Nostr auth"}),
            switches,
        );
        return;
    };
    let valid = verify(&auth)
        && auth.kind == 27235
        && auth.created_at.abs_diff(now()) <= 60
        && tag_value(&auth, "u") == Some(format!("{url}{}", parts[1]).as_str())
        && tag_value(&auth, "method") == Some(parts[0].as_str())
        && tag_value(&auth, "payload") == Some(sha256_hex(&body).as_str())
        && headers.get("x-auth-tag").is_none_or(|raw| {
            serde_json::from_str::<Vec<String>>(raw)
                .is_ok_and(|tag| verify_auth_tag(&tag, &auth.pubkey))
        })
        && state.lock().auth_ids.insert(auth.id);
    if !valid || switches.refuse_auth.load(Ordering::SeqCst) {
        respond(
            &mut stream,
            401,
            json!({"error":"NIP-98 verification failed"}),
            switches,
        );
        return;
    }
    let override_status = switches.http_status.load(Ordering::SeqCst);
    if override_status != 0 {
        let message = match override_status {
            429 => "rate-limited: quota exceeded; retry in 7s",
            503 => "rate-limited: shared admission unavailable",
            400 => "invalid: rejected by test relay",
            _ => "restricted: denied by test relay",
        };
        respond(
            &mut stream,
            override_status,
            json!({"error":message}),
            switches,
        );
        return;
    }
    let value = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
    match (parts[0].as_str(), parts[1].as_str()) {
        ("POST", "/events") => {
            let Ok(event) = serde_json::from_value::<Event>(value) else {
                respond(&mut stream, 400, json!({"error":"invalid event"}), switches);
                return;
            };
            if event.pubkey != auth.pubkey {
                respond(
                    &mut stream,
                    403,
                    json!({"error":"restricted: author mismatch"}),
                    switches,
                );
                return;
            }
            // relay-v0.2.1 ingest.rs:1976-1982: MAX_TIMESTAMP_DRIFT_SECS = 900.
            if event.created_at.abs_diff(now()) > 900 {
                respond(
                    &mut stream,
                    400,
                    json!({"error":"invalid: event timestamp too far from server time"}),
                    switches,
                );
                return;
            }
            if !verify(&event) {
                respond(
                    &mut stream,
                    400,
                    json!({"error":"invalid event signature"}),
                    switches,
                );
                return;
            }
            let mut state = state.lock();
            let duplicate = state.events.iter().any(|old| old.id == event.id);
            let id = event.id.clone();
            if !duplicate {
                state.events.push(event);
            }
            respond(
                &mut stream,
                200,
                json!({"event_id":id,"accepted":true,"message":if duplicate {"duplicate:"} else {""}}),
                switches,
            );
        }
        ("POST", "/query") => {
            let Some(filters) = value.as_array() else {
                respond(
                    &mut stream,
                    400,
                    json!({"error":"query requires array"}),
                    switches,
                );
                return;
            };
            let events = query_events(&state.lock().events, filters);
            respond(&mut stream, 200, json!(events), switches);
        }
        _ => respond(&mut stream, 404, json!({"error":"not found"}), switches),
    }
}

fn respond(stream: &mut TcpStream, status: u16, value: Value, switches: &Switches) {
    let body = if switches.oversized_body.load(Ordering::SeqCst) {
        vec![
            b' ';
            if status < 300 {
                32 * 1024 * 1024 + 1
            } else {
                64 * 1024 + 1
            }
        ]
    } else {
        serde_json::to_vec(&value).unwrap()
    };
    let retry = switches.http_retry_header.load(Ordering::SeqCst);
    let retry = if retry == 0 {
        String::new()
    } else {
        format!("Retry-After: {retry}\r\n")
    };
    let header = format!(
        "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{retry}Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(&body));
}
