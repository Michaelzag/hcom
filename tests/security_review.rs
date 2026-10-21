//! Regression cases from the PR #83 cross-vendor review. All state is isolated.
mod support;

use support::Hcom;

#[test]
fn review_start_accepts_an_existing_long_generated_child_name() {
    let h = Hcom::new();
    let recipient = h.start();
    let db = rusqlite::Connection::open(h.path().join("hcom.db")).unwrap();
    let parent = "p".repeat(45);
    let child = format!("{parent}_task_1");
    db.execute(
        "INSERT INTO instances(name, session_id, tool, created_at)
         VALUES (?1, 'long-parent-session', 'claude', 1.0)",
        [&parent],
    )
    .unwrap();
    db.execute(
        "INSERT INTO instances(name, parent_name, parent_session_id, agent_id,
                               tool, status, name_announced, created_at)
         VALUES (?1, ?2, 'long-parent-session', 'a6d9caf',
                 'claude', 'inactive', 0, 1.0)",
        rusqlite::params![child, parent],
    )
    .unwrap();
    let (code, stdout, stderr) = h.run(["start", "--name", &child]);
    assert_eq!(code, 0, "existing child startup: {stdout} {stderr}");
    let status: String = db
        .query_row(
            "SELECT status FROM instances WHERE name = ?1",
            [&child],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status, "active", "the existing dormant child was promoted");
    let (code, stdout, stderr) = h.run(["start", "--name", "a6d9caf"]);
    assert_eq!(code, 0, "existing agent-id startup: {stdout} {stderr}");
    let (row_name, parent_name): (String, String) = db
        .query_row(
            "SELECT name, parent_name FROM instances WHERE agent_id = 'a6d9caf'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(row_name, child);
    assert_eq!(parent_name, parent);
    let (code, stdout, stderr) = h.run([
        "send",
        &recipient,
        "--name",
        &child,
        "--",
        "long child reply",
    ]);
    assert_eq!(code, 0, "{stdout} {stderr}");
    let (code, stdout, stderr) =
        h.run(["listen", "--name", &recipient, "--json", "--timeout", "1"]);
    assert_eq!(code, 0, "{stderr}");
    let message: serde_json::Value = stdout
        .lines()
        .find_map(|line| serde_json::from_str(line).ok())
        .unwrap();
    assert_eq!(message["from"], child);
    assert_eq!(message["text"], "long child reply");
}

#[test]
fn review_creation_refuses_case_twins_stopped_and_mirror_names() {
    for (row_name, status, origin, requested, flag) in [
        ("michael", "listening", "", "Michael", "--name"),
        ("michael", "listening", "", "Michael", "--as"),
        ("michael", "stopped", "", "michael", "--name"),
        ("michael:MBAI", "listening", "peer", "michael", "--name"),
        ("michael:MBAI", "listening", "peer", "michael", "--as"),
    ] {
        let h = Hcom::new();
        h.start();
        let db = rusqlite::Connection::open(h.path().join("hcom.db")).unwrap();
        db.execute(
            "INSERT INTO instances (name, tool, status, origin_device_id, created_at)
             VALUES (?1, 'buzz', ?2, ?3, 1000.0)",
            rusqlite::params![row_name, status, origin],
        )
        .unwrap();
        db.execute(
            "INSERT INTO kv (key, value) VALUES ('relay_sync_time_peer', ?1)",
            [chrono::Utc::now().timestamp().to_string()],
        )
        .unwrap();
        let (code, stdout, stderr) = h.run(["start", flag, requested]);
        assert_ne!(
            code, 0,
            "{row_name}: start {flag} {requested}: {stdout} {stderr}"
        );
        let tool: String = db
            .query_row(
                "SELECT tool FROM instances WHERE name = ?1",
                [row_name],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tool, "buzz", "the connector's row must not be replaced");
        let twins: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM instances WHERE name = 'Michael'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(twins, 0, "no ambiguous case twin may be created");
    }
}

#[test]
fn review_operator_name_cannot_be_created_from_start() {
    for flag in ["--name", "--as"] {
        let h = Hcom::new();
        h.start();
        let (code, stdout, stderr) = h.run(["start", flag, "bigboss"]);
        assert_ne!(code, 0, "start {flag} bigboss: {stdout} {stderr}");
        let db = rusqlite::Connection::open(h.path().join("hcom.db")).unwrap();
        let rows: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM instances WHERE name = 'bigboss'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 0, "@bigboss must remain the virtual operator target");
    }
}

#[test]
fn review_sender_lookalikes_are_rejected_and_script_labels_deliver() {
    let h = Hcom::new();
    let recipient = h.start();
    for name in [
        "bigboss ",
        "bigboss\u{200b}",
        "bіgboss",
        "michael\t",
        "mіchael",
        "michael\u{200b}",
    ] {
        for args in [
            vec![
                "send",
                recipient.as_str(),
                "--from",
                name,
                "--",
                "lookalike",
            ],
            vec![
                "events",
                "sub",
                "--as",
                name,
                "--on-hit",
                "lookalike",
                "--type",
                "status",
            ],
            vec!["start", "--name", name],
            vec!["start", "--as", name],
        ] {
            let (code, stdout, stderr) = h.run(&args);
            assert_ne!(code, 0, "{name:?} accepted via {args:?}: {stdout} {stderr}");
        }
    }
    for name in [
        "fleet-recovery",
        "mnemopi-split-watch",
        "build_alarm:BOXE",
        "build.alert",
    ] {
        let (code, stdout, stderr) =
            h.run(["send", &recipient, "--from", name, "--", "legitimate alert"]);
        assert_eq!(code, 0, "{name}: {stdout} {stderr}");
        let (code, stdout, stderr) =
            h.run(["listen", "--name", &recipient, "--json", "--timeout", "1"]);
        assert_eq!(code, 0, "{stderr}");
        let message: serde_json::Value = stdout
            .lines()
            .find_map(|line| serde_json::from_str(line).ok())
            .unwrap();
        assert_eq!(message["from"], name);
        assert_eq!(message["text"], "legitimate alert");
    }
}

#[test]
fn review_hosted_reservation_survives_mirror_expiry() {
    let h = Hcom::new();
    let recipient = h.start();
    let db = rusqlite::Connection::open(h.path().join("hcom.db")).unwrap();
    db.execute(
        "INSERT INTO instances (name, tool, status, origin_device_id, created_at)
         VALUES ('michael:MBAI', 'buzz', 'listening', 'peer', 1000.0)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO kv (key, value) VALUES ('relay_sync_time_peer', '1')",
        [],
    )
    .unwrap();
    // The sweep runs only against a live worker and a ticking fleet clock:
    // give it both, plus a second, freshly-syncing peer so 'peer' is judged
    // stale against the fleet's clock rather than wall time.
    db.execute(
        "INSERT INTO instances (name, tool, status, origin_device_id, created_at)
         VALUES ('beta:PEER2', 'claude', 'listening', 'peer2', 1000.0)",
        [],
    )
    .unwrap();
    db.execute(
        "INSERT INTO kv (key, value) VALUES ('relay_sync_time_peer2', ?1)",
        [chrono::Utc::now().timestamp().to_string()],
    )
    .unwrap();
    db.execute(
        "INSERT INTO kv (key, value) VALUES
            ('relay_status', 'ok'),
            ('relay_worker_heartbeat', ?1)",
        [chrono::Utc::now().timestamp().to_string()],
    )
    .unwrap();
    // The normal CLI cleanup expires this mirror; ownership must outlive it.
    h.run(["list", "--json"]);
    let rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM instances WHERE name = 'michael:MBAI'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(rows, 0, "fixture must exercise actual mirror expiry");
    for name in ["michael", "MICHAEL:MBAI"] {
        let (code, stdout, stderr) =
            h.run(["send", &recipient, "--from", name, "--", "expired owner"]);
        assert_ne!(code, 0, "{name}: {stdout} {stderr}");
    }
    let (code, stdout, stderr) = h.run(["start", "--name", "michael"]);
    assert_ne!(code, 0, "expired hosted name reclaimed: {stdout} {stderr}");
}
