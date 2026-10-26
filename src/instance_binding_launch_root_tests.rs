//! `omp_launch_root` persistence (#106). The PTY child is a launch's last
//! pre-hook pin; the first hook re-pins the owner to the interpreter, and
//! `hcom kill` still has to reach the launched tree. Only
//! `record_omp_launch_root` writes a root. Every other `launch_context`
//! writer carries the root and the receipt, and a new, replaced or released
//! reservation drops the root.

use super::*;
use serde_json::{Value, json};
use serial_test::serial;
use std::collections::HashMap;

/// Launcher UUIDs, as hcom launches mint them.
const LAUNCH_ID: &str = "6c0e2f4a-1b3d-4e5f-8a9b-0c1d2e3f4a5b";
const NEXT_LAUNCH_ID: &str = "7d1f3a5b-2c4e-4f6a-9b0c-1d2e3f4a5b6c";

/// A live process whose native identity a receipt or root can record.
struct Live(std::process::Child);

impl Live {
    fn spawn() -> Self {
        Self(
            std::process::Command::new("sleep")
                .arg("60")
                .spawn()
                .unwrap(),
        )
    }

    fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn open_db(env: &tempfile::TempDir, label: &str) -> HcomDb {
    HcomDb::open_at(&env.path().join(format!("{label}.db"))).unwrap()
}

/// An unhooked OMP launch reservation and its UUID binding, as launch
/// registration leaves it. A resume reservation already carries its session.
fn seed_reservation(db: &HcomDb, session_id: Option<&str>) {
    db.conn()
        .execute(
            "INSERT INTO instances
             (name, tool, created_at, agent_id, session_id, status, status_context, last_event_id)
             VALUES ('luna', 'omp', 1.25, 'launch-agent', ?1, 'inactive', 'new', 0)",
            rusqlite::params![session_id],
        )
        .unwrap();
    db.set_process_binding(LAUNCH_ID, "", "luna").unwrap();
}

fn row(db: &HcomDb, name: &str) -> InstanceRow {
    db.get_instance_full(name).unwrap().unwrap()
}

fn root(db: &HcomDb, name: &str) -> Option<Value> {
    launch_context_value(&row(db, name), "omp_launch_root")
}

fn receipt(db: &HcomDb, name: &str) -> Option<Value> {
    launch_context_value(&row(db, name), "omp_launch_pid")
}

/// The root a PTY child pin records: its PID and native identity.
fn root_of(pid: u32) -> Value {
    json!({"pid": pid, "identity": crate::sys::process::identity(pid).unwrap()})
}

/// One launch's pre-hook pins: the launch script, `hcom pty`, the PTY child.
fn pin_launch(db: &HcomDb, process_id: &str, runner: u32, pty: u32, child: u32) {
    let mut launch = capture_omp_launch_pid(db, process_id, "luna")
        .unwrap()
        .unwrap();
    assert!(record_omp_launch_pid(db, &mut launch, runner).unwrap());
    assert!(record_omp_launch_pid(db, &mut launch, pty).unwrap());
    assert!(record_omp_launch_root(db, &mut launch, child).unwrap());
}

/// The first hook: the PTY child started the interpreter, the nearest actual
/// OMP below it, and the bind re-pins the owner there.
fn hook_repin(db: &HcomDb, child: u32, interpreter: u32) -> Option<String> {
    let owner = |anchor: u32| {
        (anchor == child).then_some(OmpOwnerProof {
            owner_pid: interpreter,
            anchor_kind: AncestorProcess::Other,
        })
    };
    bind_omp_session_to_process_checked(db, "sid-owner", LAUNCH_ID, &owner).unwrap()
}

/// A seat after its first hook: owner and receipt on the interpreter, root
/// on the PTY child.
fn seed_hooked_seat(db: &HcomDb, child: u32, interpreter: u32) {
    seed_reservation(db, None);
    let mut launch = capture_omp_launch_pid(db, LAUNCH_ID, "luna")
        .unwrap()
        .unwrap();
    assert!(record_omp_launch_root(db, &mut launch, child).unwrap());
    assert_eq!(hook_repin(db, child, interpreter).as_deref(), Some("luna"));
}

#[test]
#[serial]
fn a_fresh_launch_records_its_pty_child_as_the_root() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let db = open_db(&env.0, "fresh");
    seed_reservation(&db, None);
    let (runner, pty, child) = (Live::spawn(), Live::spawn(), Live::spawn());
    let mut launch = capture_omp_launch_pid(&db, LAUNCH_ID, "luna")
        .unwrap()
        .unwrap();
    assert!(record_omp_launch_pid(&db, &mut launch, runner.pid()).unwrap());
    assert_eq!(root(&db, "luna"), None, "the launch script pin is no root");
    assert!(record_omp_launch_pid(&db, &mut launch, pty.pid()).unwrap());
    assert_eq!(root(&db, "luna"), None, "hcom pty's own pin is no root");
    assert!(record_omp_launch_root(&db, &mut launch, child.pid()).unwrap());
    assert_eq!(row(&db, "luna").pid, Some(i64::from(child.pid())));
    assert_eq!(root(&db, "luna"), Some(root_of(child.pid())));
    let pin_receipt = receipt(&db, "luna").unwrap();
    assert_eq!(pin_receipt["pid"], child.pid());
    assert_eq!(
        pin_receipt["identity"],
        root_of(child.pid())["identity"],
        "the root and its pin's receipt come from one identity read"
    );
}

#[test]
#[serial]
fn the_hook_repin_moves_the_owner_and_keeps_the_root() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let db = open_db(&env.0, "repin");
    seed_reservation(&db, None);
    let (runner, pty) = (Live::spawn(), Live::spawn());
    let (child, interpreter) = (Live::spawn(), Live::spawn());
    pin_launch(&db, LAUNCH_ID, runner.pid(), pty.pid(), child.pid());
    assert_eq!(
        hook_repin(&db, child.pid(), interpreter.pid()).as_deref(),
        Some("luna")
    );
    assert_eq!(row(&db, "luna").pid, Some(i64::from(interpreter.pid())));
    assert_eq!(receipt(&db, "luna").unwrap()["pid"], interpreter.pid());
    assert_eq!(root(&db, "luna"), Some(root_of(child.pid())));
}

/// A row an older binary pinned: an owner PID and its receipt, no root.
fn seed_legacy_pin(db: &HcomDb, owner: u32) {
    seed_reservation(db, None);
    db.update_instance_pid("luna", owner).unwrap();
    assert!(receipt(db, "luna").is_some());
}

#[test]
#[serial]
fn owner_writers_never_mint_a_root_on_a_legacy_row() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let (owner, next) = (Live::spawn(), Live::spawn());
    let (owner, next) = (owner.pid(), next.pid());
    let actual_owner = |anchor: u32| {
        (anchor == owner).then_some(OmpOwnerProof {
            owner_pid: owner,
            anchor_kind: AncestorProcess::Omp,
        })
    };
    let writers: [(&str, &dyn Fn(&HcomDb)); 6] = [
        ("hook bind", &|db| {
            assert_eq!(
                bind_omp_session_to_process_checked(db, "sid-owner", LAUNCH_ID, &actual_owner)
                    .unwrap()
                    .as_deref(),
                Some("luna")
            );
        }),
        ("start --as", &|db| {
            db.conn()
                .execute("UPDATE instances SET pid = NULL WHERE name = 'luna'", [])
                .unwrap();
            assert!(db.set_instance_pid_if_unset("luna", next).unwrap());
        }),
        ("owner setter", &|db| {
            db.update_instance_pid("luna", next).unwrap()
        }),
        ("owner CAS", &|db| {
            let expected = row(db, "luna");
            assert!(
                db.with_immediate_transaction(|tx| {
                    db.compare_and_set_instance_pid_in_txn(tx, &expected, Some(next))
                })
                .unwrap()
            );
        }),
        ("generic field write", &|db| {
            // A caller-supplied root cannot ride in on a generic owner write.
            let forged = json!({"pane_id": "p_9", "omp_launch_root": root_of(next)});
            db.update_instance_fields(
                "luna",
                &serde_json::Map::from_iter([
                    ("pid".to_string(), json!(next)),
                    ("launch_context".to_string(), json!(forged.to_string())),
                ]),
            )
            .unwrap();
        }),
        ("recovery", &|db| {
            let process_id = format!("omp-{owner}-recovery");
            assert_eq!(
                recover_process_binding_for_instance_checked(
                    db,
                    "luna",
                    "sid-recovered",
                    &process_id,
                    &actual_owner,
                )
                .unwrap()
                .as_deref(),
                Some("luna")
            );
        }),
    ];
    for (case, write) in writers {
        let db = open_db(&env.0, &case.replace([' ', '-'], "_"));
        seed_legacy_pin(&db, owner);
        write(&db);
        assert!(row(&db, "luna").pid.is_some(), "{case} left no owner");
        assert!(receipt(&db, "luna").is_some(), "{case} left no receipt");
        assert_eq!(root(&db, "luna"), None, "{case} minted a launch root");
    }
}

#[test]
#[serial]
fn a_replaced_reservation_takes_a_new_root_and_its_release_drops_it() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let db = open_db(&env.0, "replaced");
    seed_reservation(&db, Some("sid-prior"));
    let (runner, pty) = (Live::spawn(), Live::spawn());
    let first = Live::spawn();
    pin_launch(&db, LAUNCH_ID, runner.pid(), pty.pid(), first.pid());
    let first_root = root(&db, "luna");
    assert_eq!(first_root, Some(root_of(first.pid())));
    // The first launch died before its hook. The next registers its own UUID
    // and its first pin replaces the dead one.
    drop(first);
    db.set_process_binding(NEXT_LAUNCH_ID, "", "luna").unwrap();
    let mut next = capture_omp_launch_pid(&db, NEXT_LAUNCH_ID, "luna")
        .unwrap()
        .unwrap();
    assert!(next.replaces_stale_pin);
    let (next_pty, next_child) = (Live::spawn(), Live::spawn());
    assert!(record_omp_launch_pid(&db, &mut next, next_pty.pid()).unwrap());
    assert_eq!(
        root(&db, "luna"),
        None,
        "the replaced launch's root outlived its pin"
    );
    assert!(record_omp_launch_root(&db, &mut next, next_child.pid()).unwrap());
    assert_eq!(root(&db, "luna"), Some(root_of(next_child.pid())));
    assert_ne!(root(&db, "luna"), first_root);

    // That launch dies too; the next registration releases its pin, and the
    // receipt and root go with it.
    drop(next_child);
    assert!(
        db.with_immediate_transaction(|tx| {
            prepare_own_omp_reservation_in_txn(&db, tx, "luna", "sid-prior", "omp")
        })
        .unwrap()
        .is_none()
    );
    assert_eq!(row(&db, "luna").pid, None);
    assert_eq!(receipt(&db, "luna"), None);
    assert_eq!(
        root(&db, "luna"),
        None,
        "a released pin kept its launch root"
    );
}

#[test]
#[serial]
fn stopping_an_unhooked_reservation_removes_its_root_with_the_row() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let db = open_db(&env.0, "stopped");
    seed_reservation(&db, Some("sid-prior"));
    let (runner, pty, child) = (Live::spawn(), Live::spawn(), Live::spawn());
    pin_launch(&db, LAUNCH_ID, runner.pid(), pty.pid(), child.pid());
    assert!(root(&db, "luna").is_some());
    let expected = row(&db, "luna");
    let bindings = db.process_binding_ids("luna").unwrap();
    assert_eq!(
        crate::hooks::common::try_release_unhooked_omp_reservation(
            &db, &expected, &bindings, "test"
        ),
        Some(crate::hooks::common::StopOutcome::Stopped)
    );
    assert!(db.get_instance_full("luna").unwrap().is_none());
}

#[test]
#[serial]
fn every_context_and_owner_writer_carries_the_root_and_receipt() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let (child, interpreter, next) = (Live::spawn(), Live::spawn(), Live::spawn());
    let (child, interpreter, next) = (child.pid(), interpreter.pid(), next.pid());
    // Each writer and the PID its receipt names afterwards; `None` keeps the
    // hooked owner's receipt byte for byte.
    let writers: [(&str, Option<u32>, &dyn Fn(&HcomDb)); 9] = [
        ("terminal details save", None, &|db| {
            persist_terminal_launch_context(
                db,
                "luna",
                Some("kitty"),
                "kitty-tab",
                Some(LAUNCH_ID),
            )
            .unwrap();
        }),
        ("hook-time context rewrite", None, &|db| {
            capture_and_store_launch_context(db, "luna");
        }),
        ("pty early context merge", None, &|db| {
            db.store_launch_context("luna", r#"{"pane_id":"p_1","kitty_listen_on":"unix:/k"}"#)
                .unwrap();
        }),
        ("owner setter", Some(next), &|db| {
            db.update_instance_pid("luna", next).unwrap();
        }),
        ("owner CAS", Some(next), &|db| {
            let expected = row(db, "luna");
            assert!(
                db.with_immediate_transaction(|tx| {
                    db.compare_and_set_instance_pid_in_txn(tx, &expected, Some(next))
                })
                .unwrap()
            );
        }),
        ("generic field write, whole context", Some(next), &|db| {
            // The orphan-recovery shape: a new owner plus a rebuilt context.
            db.update_instance_fields(
                "luna",
                &serde_json::Map::from_iter([
                    ("pid".to_string(), json!(next)),
                    ("launch_context".to_string(), json!(r#"{"pane_id":"p_9"}"#)),
                ]),
            )
            .unwrap();
        }),
        ("generic update", Some(next), &|db| {
            db.update_instance("luna", &HashMap::from([("pid".to_string(), json!(next))]))
                .unwrap();
        }),
        ("generic upsert", Some(next), &|db| {
            db.save_instance(&HashMap::from([
                ("name".to_string(), json!("luna")),
                ("created_at".to_string(), json!(1.25)),
                ("pid".to_string(), json!(next)),
            ]))
            .unwrap();
        }),
        ("recovery re-pin", Some(interpreter), &|db| {
            // A seat whose session lost its bindings, as recovery finds it.
            db.conn()
                .execute_batch(
                    "UPDATE instances SET status = 'inactive' WHERE name = 'luna';
                     DELETE FROM session_bindings; DELETE FROM process_bindings;",
                )
                .unwrap();
            let actual_owner = |anchor: u32| {
                (anchor == interpreter).then_some(OmpOwnerProof {
                    owner_pid: interpreter,
                    anchor_kind: AncestorProcess::Omp,
                })
            };
            assert_eq!(
                recover_process_binding_for_instance_checked(
                    db,
                    "luna",
                    "sid-recovered",
                    &format!("omp-{interpreter}-recovery"),
                    &actual_owner,
                )
                .unwrap()
                .as_deref(),
                Some("luna")
            );
        }),
    ];
    for (case, receipt_pid, write) in writers {
        let db = open_db(&env.0, &case.replace([' ', ',', '-'], "_"));
        seed_hooked_seat(&db, child, interpreter);
        let hooked_receipt = receipt(&db, "luna");
        write(&db);
        assert_eq!(
            root(&db, "luna"),
            Some(root_of(child)),
            "{case} dropped or rewrote the launch root"
        );
        match receipt_pid {
            None => assert_eq!(
                receipt(&db, "luna"),
                hooked_receipt,
                "{case} lost the receipt"
            ),
            Some(pid) => {
                assert_eq!(row(&db, "luna").pid, Some(i64::from(pid)), "{case}");
                assert_eq!(
                    receipt(&db, "luna").map(|receipt| receipt["pid"].clone()),
                    Some(json!(pid)),
                    "{case} left a receipt for another PID"
                );
            }
        }
    }
}

/// Another incarnation's canonical row: its own pin, receipt and root.
fn seed_stale_canonical(db: &HcomDb, stale: u32) {
    db.conn()
        .execute(
            "INSERT INTO instances (name, tool, created_at, session_id, status)
             VALUES ('fano', 'omp', 2.25, 'sid-owner', 'inactive')",
            [],
        )
        .unwrap();
    db.update_instance_pid("fano", stale).unwrap();
    db.conn()
        .execute(
            "UPDATE instances SET launch_context =
                 json_set(launch_context, '$.omp_launch_root', json(?1))
             WHERE name = 'fano'",
            [root_of(stale).to_string()],
        )
        .unwrap();
}

#[test]
#[serial]
fn a_migration_moves_the_root_and_receipt_verbatim_with_the_pid() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let (child, stale) = (Live::spawn(), Live::spawn());
    for (rooted, transactional) in [(true, false), (true, true), (false, false), (false, true)] {
        let db = open_db(&env.0, &format!("migrate_{rooted}_{transactional}"));
        seed_reservation(&db, None);
        if rooted {
            let mut launch = capture_omp_launch_pid(&db, LAUNCH_ID, "luna")
                .unwrap()
                .unwrap();
            assert!(record_omp_launch_root(&db, &mut launch, child.pid()).unwrap());
        } else {
            // A placeholder an older binary pinned: receipt, no root.
            db.update_instance_pid("luna", child.pid()).unwrap();
        }
        seed_stale_canonical(&db, stale.pid());
        let placeholder = row(&db, "luna");
        if transactional {
            db.with_immediate_transaction(|tx| {
                migrate_placeholder_runtime_state_in_txn(&db, tx, "fano", Some(&placeholder))
            })
            .unwrap();
        } else {
            migrate_placeholder_runtime_state(&db, "fano", Some(&placeholder));
        }
        let case = format!("rooted={rooted} transactional={transactional}");
        assert_eq!(row(&db, "fano").pid, placeholder.pid, "{case}");
        assert_eq!(receipt(&db, "fano"), receipt(&db, "luna"), "{case}");
        assert_eq!(
            root(&db, "fano"),
            root(&db, "luna"),
            "{case}: the canonical row kept another incarnation's root"
        );
    }
}

#[test]
#[serial]
fn a_resume_bind_moves_the_root_to_the_canonical_row_across_the_repin() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let (child, interpreter) = (Live::spawn(), Live::spawn());
    for target in ["canonical", "stopped"] {
        let db = open_db(&env.0, &format!("resume_{target}"));
        seed_reservation(&db, None);
        let mut launch = capture_omp_launch_pid(&db, LAUNCH_ID, "luna")
            .unwrap()
            .unwrap();
        assert!(record_omp_launch_root(&db, &mut launch, child.pid()).unwrap());
        if target == "canonical" {
            db.conn()
                .execute(
                    "INSERT INTO instances (name, tool, created_at, session_id, status)
                     VALUES ('fano', 'omp', 2.25, 'sid-owner', 'inactive')",
                    [],
                )
                .unwrap();
            db.rebind_session("sid-owner", "fano").unwrap();
        } else {
            let mut exited = std::process::Command::new("true").spawn().unwrap();
            let owner = exited.id();
            exited.wait().unwrap();
            db.log_life_event(
                "fano",
                "stopped",
                "test",
                "exit",
                Some(json!({"tool": "omp", "session_id": "sid-owner", "pid": owner})),
                None,
            )
            .unwrap();
        }
        assert_eq!(
            hook_repin(&db, child.pid(), interpreter.pid()).as_deref(),
            Some("fano"),
            "{target}"
        );
        assert!(db.get_instance_full("luna").unwrap().is_none(), "{target}");
        assert_eq!(
            row(&db, "fano").pid,
            Some(i64::from(interpreter.pid())),
            "{target}"
        );
        assert_eq!(
            receipt(&db, "fano").unwrap()["pid"],
            interpreter.pid(),
            "{target}"
        );
        assert_eq!(root(&db, "fano"), Some(root_of(child.pid())), "{target}");
    }
}

#[test]
#[serial]
fn a_lost_or_failed_root_pin_writes_no_root() {
    let env = crate::hooks::test_helpers::isolated_test_env();
    let (pty, child, other) = (Live::spawn(), Live::spawn(), Live::spawn());
    for race in [
        "launch bound first",
        "pin moved",
        "receipt rewritten",
        "row replaced",
        "write aborted",
    ] {
        let db = open_db(&env.0, &race.replace(' ', "_"));
        seed_reservation(&db, None);
        let mut launch = capture_omp_launch_pid(&db, LAUNCH_ID, "luna")
            .unwrap()
            .unwrap();
        assert!(record_omp_launch_pid(&db, &mut launch, pty.pid()).unwrap());
        match race {
            "launch bound first" => db
                .set_process_binding(LAUNCH_ID, "sid-owner", "luna")
                .unwrap(),
            "pin moved" => db.update_instance_pid("luna", other.pid()).unwrap(),
            "receipt rewritten" => {
                db.conn()
                    .execute(
                        "UPDATE instances SET launch_context = json_set(launch_context,
                             '$.omp_launch_pid.identity', 'rewritten') WHERE name = 'luna'",
                        [],
                    )
                    .unwrap();
            }
            "row replaced" => {
                db.conn()
                    .execute(
                        "UPDATE instances SET created_at = 9.5 WHERE name = 'luna'",
                        [],
                    )
                    .unwrap();
            }
            "write aborted" => {
                db.conn()
                    .execute_batch(
                        "CREATE TRIGGER refuse_pin BEFORE UPDATE OF pid ON instances
                         BEGIN SELECT RAISE(ABORT, 'pin refused'); END;",
                    )
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let before = row(&db, "luna");
        let recorded = record_omp_launch_root(&db, &mut launch, child.pid());
        if race == "write aborted" {
            assert!(recorded.is_err(), "{race}");
        } else {
            assert!(!recorded.unwrap(), "{race}");
        }
        let after = row(&db, "luna");
        assert_eq!(
            (after.pid, after.launch_context),
            (before.pid, before.launch_context),
            "{race}"
        );
        assert_eq!(root(&db, "luna"), None, "{race}");
    }
}
