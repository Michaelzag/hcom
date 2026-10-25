use std::collections::BTreeMap;
use std::fs;

use rusqlite::{Connection, types::Value as SqlValue};

use super::Hcom;

pub(crate) const CONFIG: &str = "[relay]\nenabled = false\n[launch.omp]\nplain_sessions = true\n";

pub(crate) fn isolated_hcom() -> Hcom {
    let h = Hcom::new();
    fs::write(h.path().join("config.toml"), CONFIG).expect("disable fixture relay");
    let (code, _, stderr) = h.run(["status", "--json"]);
    assert_eq!(code, 0, "initialize isolated schema: {stderr}");
    h
}

pub(crate) fn db(h: &Hcom) -> Connection {
    Connection::open(h.path().join("hcom.db")).expect("open fixture database")
}

/// Every column, with its SQLite type preserved, including cursor,
/// name_announced, creation timestamps, role/tip/forward claims and raw event
/// payloads. No hand-picked projection can hide an unintended replacement.
pub(crate) fn full_state(h: &Hcom) -> BTreeMap<&'static str, Vec<Vec<SqlValue>>> {
    let db = db(h);
    [
        "instances",
        "process_bindings",
        "session_bindings",
        "notify_endpoints",
        "events",
        "kv",
        "sqlite_sequence",
    ]
    .into_iter()
    .map(|table| {
        let mut query = db
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .unwrap();
        let columns = query.column_count();
        let rows = query
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<SqlValue>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        (table, rows)
    })
    .collect()
}
