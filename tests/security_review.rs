//! Regression cases from the PR #83 cross-vendor review. All state is isolated.
mod support;

use support::Hcom;

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
