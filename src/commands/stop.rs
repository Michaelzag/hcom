//! `hcom stop` command — end hcom participation.
//!
//!
//! Supports: self-stop, named stop, multi-stop, `all`, `tag:<name>`.
//! Inside AI tools, destructive ops require `--go` flag.

use crate::db::HcomDb;
use crate::identity;
use crate::identity::{get_full_name, resolve_display_name};
use crate::instances::{is_remote_instance, is_subagent_instance};
use crate::log::log_info;
use crate::shared::{CommandContext, SENDER, SenderKind, is_inside_ai_tool};

/// Parsed arguments for `hcom stop`.
#[derive(clap::Parser, Debug)]
#[command(name = "stop", about = "Stop hcom participation")]
pub struct StopArgs {
    /// Targets to stop (names, tag:X, or "all")
    pub targets: Vec<String>,
}

/// Resolve the initiator name for event logging.
fn resolve_initiator(
    db: &HcomDb,
    ctx: Option<&CommandContext>,
    explicit_name: Option<&str>,
) -> String {
    if let Some(c) = ctx
        && let Some(ref id) = c.identity
        && matches!(id.kind, SenderKind::Instance)
    {
        return id.name.clone();
    }
    if let Some(name) = explicit_name {
        return name.to_string();
    }
    match identity::resolve_identity(db, None, None, None, None, None, None) {
        Ok(id) => id.name,
        Err(_) => "cli".to_string(),
    }
}

/// Main entry point for `hcom stop` command.
///
/// Returns exit code (0 = success, 1 = error).
pub fn cmd_stop(db: &HcomDb, args: &StopArgs, ctx: Option<&CommandContext>) -> i32 {
    let explicit_name = ctx.and_then(|c| c.explicit_name.as_deref());

    let targets: Vec<&str> = args.targets.iter().map(|s| s.as_str()).collect();

    // Handle 'all' target
    if targets.contains(&"all") {
        if targets.len() > 1 {
            eprintln!("Error: 'all' cannot be combined with other targets");
            return 1;
        }

        // Only stop local instances. Every row comes with its binding epoch
        // from ONE snapshot, and each release is bound to that incarnation
        // (see `stop_read_instance`).
        let instances = match db.iter_instances_with_bindings() {
            Ok(rows) => rows
                .into_iter()
                .filter(|(i, _)| !is_remote_instance(i))
                .collect::<Vec<_>>(),
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        };

        if instances.is_empty() {
            println!("Nothing to stop");
            return 0;
        }

        // Confirmation gate: inside AI tools, require --go
        if is_inside_ai_tool() && !ctx.map(|c| c.go).unwrap_or(false) {
            print_stop_preview("ALL", "all", &instances);
            return 0;
        }

        let launcher = resolve_initiator(db, ctx, explicit_name);
        log_info(
            "lifecycle",
            "stop.all",
            &format!("count={} initiated_by={launcher}", instances.len()),
        );

        let mut stopped_names = Vec::new();
        let mut failed_names = Vec::new();
        let mut skipped_names = Vec::new();
        let mut bg_logs = Vec::new();

        for (inst, binding_ids) in &instances {
            let display = get_full_name(inst);
            // The release reaps the whole tree first; a failure means live
            // processes remain, so the name must not be reported as stopped.
            match stop_read_instance(db, inst, binding_ids, &launcher, "stop_all") {
                outcome if outcome.is_re_registered() => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
                    skipped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped => {
                    stopped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::RetryableError(e) => {
                    eprintln!("Error stopping {display}: {e}");
                    failed_names.push(display.clone());
                }
            }

            if inst.background != 0 && !inst.background_log_file.is_empty() {
                bg_logs.push((display, inst.background_log_file.clone()));
            }
        }

        if stopped_names.is_empty() && failed_names.is_empty() && skipped_names.is_empty() {
            println!("Nothing to stop");
        } else {
            if !stopped_names.is_empty() {
                println!("Stopped: {}", stopped_names.join(", "));
            }
            if !failed_names.is_empty() {
                eprintln!("Failed to stop: {}", failed_names.join(", "));
            }
            if !bg_logs.is_empty() {
                println!("\nHeadless logs:");
                for (name, log_file) in &bg_logs {
                    println!("  {name}: {log_file}");
                }
            }
        }
        return if failed_names.is_empty() && skipped_names.is_empty() {
            0
        } else {
            1
        };
    }

    // Handle tag:name syntax
    if targets.len() == 1 && targets[0].starts_with("tag:") {
        let tag = &targets[0][4..];
        let tag_matches = match db.iter_instances_with_bindings() {
            Ok(rows) => rows
                .into_iter()
                .filter(|(i, _)| i.tag.as_deref() == Some(tag) && !is_remote_instance(i))
                .collect::<Vec<_>>(),
            Err(e) => {
                eprintln!("Error: {e}");
                return 1;
            }
        };

        if tag_matches.is_empty() {
            // Check orphans for this tag (already stopped but process may still be running)
            let orphans = crate::pidtrack::get_orphan_processes(&crate::paths::hcom_dir(), None);
            let tagged_orphans: Vec<_> = orphans.iter().filter(|o| o.tag == tag).collect();
            if !tagged_orphans.is_empty() {
                let names: Vec<_> = tagged_orphans
                    .iter()
                    .flat_map(|o| o.names.iter())
                    .cloned()
                    .collect();
                println!(
                    "No active agents with tag '{tag}' (already stopped: {})",
                    names.join(", ")
                );
                println!("Use 'hcom kill tag:{tag}' to terminate their processes.");
                return 0;
            }
            eprintln!("Error: No agents with tag '{tag}'");
            return 1;
        }

        // Confirmation gate
        if is_inside_ai_tool() && !ctx.map(|c| c.go).unwrap_or(false) {
            print_stop_preview(&format!("tag:{tag}"), &format!("tag:{tag}"), &tag_matches);
            return 0;
        }

        let launcher = resolve_initiator(db, ctx, explicit_name);
        log_info(
            "lifecycle",
            "stop.tag",
            &format!(
                "tag={tag} count={} initiated_by={launcher}",
                tag_matches.len()
            ),
        );
        let mut stopped_names = Vec::new();
        let mut failed_names = Vec::new();
        let mut skipped_names = Vec::new();
        let mut bg_logs = Vec::new();

        for (inst, binding_ids) in &tag_matches {
            let display = get_full_name(inst);
            match stop_read_instance(db, inst, binding_ids, &launcher, "tag_stop") {
                outcome if outcome.is_re_registered() => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
                    skipped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped => {
                    stopped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::RetryableError(e) => {
                    eprintln!("Error stopping {display}: {e}");
                    failed_names.push(display.clone());
                }
            }
            if inst.background != 0 && !inst.background_log_file.is_empty() {
                bg_logs.push((display, inst.background_log_file.clone()));
            }
        }

        if !stopped_names.is_empty() {
            println!("Stopped tag:{tag}: {}", stopped_names.join(", "));
        }
        if !failed_names.is_empty() {
            eprintln!("Failed to stop tag:{tag}: {}", failed_names.join(", "));
        }
        if !bg_logs.is_empty() {
            println!("\nHeadless logs:");
            for (name, log_file) in &bg_logs {
                println!("  {name}: {log_file}");
            }
        }
        return if failed_names.is_empty() && skipped_names.is_empty() {
            0
        } else {
            1
        };
    }

    // Handle multiple explicit targets
    if targets.len() > 1 {
        let mut instances_to_stop = Vec::new();
        let mut not_found = Vec::new();

        for t in &targets {
            if t.starts_with("tag:") {
                eprintln!("Error: Cannot mix tag: with other targets: {t}");
                return 1;
            }
            let resolved = resolve_display_name(db, t);
            let name = resolved.as_deref().unwrap_or(t);
            match db.get_instance_with_bindings(name) {
                Ok((Some(data), binding_ids)) => instances_to_stop.push((data, binding_ids)),
                _ => {
                    not_found.push(t.to_string());
                }
            }
        }

        if !not_found.is_empty() {
            let plural = if not_found.len() > 1 { "s" } else { "" };
            eprintln!("Error: Agent{plural} not found: {}", not_found.join(", "));
            return 1;
        }

        // Confirmation gate
        if is_inside_ai_tool() && !ctx.map(|c| c.go).unwrap_or(false) {
            print_stop_preview("", &targets.join(" "), &instances_to_stop);
            return 0;
        }

        let launcher = resolve_initiator(db, ctx, explicit_name);
        let mut stopped_names = Vec::new();
        let mut failed_names = Vec::new();
        let mut skipped_names = Vec::new();
        let mut bg_logs = Vec::new();

        for (inst, binding_ids) in &instances_to_stop {
            if is_remote_instance(inst) {
                println!("Skipping remote instance: {}", get_full_name(inst));
                continue;
            }
            let display = get_full_name(inst);
            match stop_read_instance(db, inst, binding_ids, &launcher, "multi_stop") {
                outcome if outcome.is_re_registered() => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
                    skipped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped => {
                    stopped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::RetryableError(e) => {
                    eprintln!("Error stopping {display}: {e}");
                    failed_names.push(display.clone());
                }
            }
            if inst.background != 0 && !inst.background_log_file.is_empty() {
                bg_logs.push((display, inst.background_log_file.clone()));
            }
        }

        if !stopped_names.is_empty() {
            println!("Stopped: {}", stopped_names.join(", "));
        }
        if !failed_names.is_empty() {
            eprintln!("Failed to stop: {}", failed_names.join(", "));
        }
        if !bg_logs.is_empty() {
            println!("\nHeadless logs:");
            for (name, log_file) in &bg_logs {
                println!("  {name}: {log_file}");
            }
        }
        return if failed_names.is_empty() && skipped_names.is_empty() {
            0
        } else {
            1
        };
    }

    // Single target or self-stop
    let instance_name = if !targets.is_empty() {
        // Named target
        let target = targets[0];
        let resolved = resolve_display_name(db, target);
        resolved.unwrap_or_else(|| target.to_string())
    } else {
        // Self-stop: resolve identity
        let identity = if let Some(c) = ctx {
            if let Some(ref id) = c.identity {
                Some(id.clone())
            } else {
                identity::resolve_identity(db, explicit_name, None, None, None, None, None).ok()
            }
        } else {
            identity::resolve_identity(db, None, None, None, None, None, None).ok()
        };

        match identity {
            Some(id) => id.name,
            None => {
                eprintln!(
                    "Error: Cannot determine identity\nUsage: hcom stop <name> | hcom stop all | run 'hcom stop' inside Claude/Gemini/Codex/Antigravity"
                );
                return 1;
            }
        }
    };

    // Handle SENDER (not real instance)
    if instance_name == SENDER {
        eprintln!("Error: Cannot resolve identity - launch via 'hcom <n>' for stable identity");
        return 1;
    }

    // Lookup instance: the row and its binding epoch in one snapshot, the
    // incarnation the release below is bound to.
    let (position, binding_ids) = match db.get_instance_with_bindings(&instance_name) {
        Ok((Some(data), binding_ids)) => (data, binding_ids),
        _ => {
            eprintln!("Error: '{instance_name}' not found");
            return 1;
        }
    };

    // Remote instances are mirrors only. Stopping them remotely would strand the
    // agent from hcom without giving a useful way to recover/control it remotely.
    if is_remote_instance(&position) {
        eprintln!(
            "Error: Remote stop is not supported for '{instance_name}'. Use remote kill or ask the agent to stop itself locally."
        );
        return 1;
    }

    let launcher = resolve_initiator(db, ctx, explicit_name);
    let is_external_stop = !targets.is_empty();
    let reason = if is_external_stop { "external" } else { "self" };

    let display = get_full_name(&position);
    log_info(
        "lifecycle",
        "stop.single",
        &format!("name={instance_name} reason={reason} initiated_by={launcher}"),
    );

    // The release reaps the whole tree first; on failure the name stays
    // live and must not be reported as stopped.
    match stop_read_instance(db, &position, &binding_ids, &launcher, reason) {
        outcome if outcome.is_re_registered() => {
            eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
            return 1;
        }
        crate::hooks::common::StopOutcome::Stopped
        | crate::hooks::common::StopOutcome::AlreadyStopped => {}
        crate::hooks::common::StopOutcome::RetryableError(e) => {
            eprintln!("Error stopping {display}: {e}");
            return 1;
        }
    }

    if is_subagent_instance(&position) {
        println!("Stopped hcom for subagent {display}.");
    } else {
        println!("Stopped hcom for {display}.");
    }

    if position.background != 0 && !position.background_log_file.is_empty() {
        println!("\nHeadless log: {}", position.background_log_file);
    }

    0
}

/// Stop `inst`, bound to the incarnation this command read: `inst` and
/// `binding_ids` are one snapshot, and the release refuses anything that
/// registered under the name since (a `start --as` replacement or a rebind),
/// which is reported skipped and never stopped.
fn stop_read_instance(
    db: &HcomDb,
    inst: &crate::db::InstanceRow,
    binding_ids: &[String],
    initiator: &str,
    reason: &str,
) -> crate::hooks::common::StopOutcome {
    let owners = crate::proctruth::omp_owner_bindings(db, &inst.name);
    // The capture is the gate: a refusal returns here, before the headless
    // group signal, the reap, and the release, leaving the row and its
    // bindings untouched. The caller's existing error channel prints the
    // owner named in the message and exits 1.
    let capture = match crate::proctruth::capture_reap_carriers(
        db,
        &inst.name,
        Some(inst),
        binding_ids,
        &owners,
        &[],
    ) {
        Ok(capture) => capture,
        Err(e) => {
            return crate::hooks::common::StopOutcome::RetryableError(e.to_string().into());
        }
    };
    crate::hooks::common::stop_instance_with_capture(db, &inst.name, initiator, reason, capture)
}

/// Print a stop preview for any scope (all, tag, or named targets).
fn print_stop_preview(
    scope: &str,
    cmd_suffix: &str,
    instances: &[(crate::db::InstanceRow, Vec<String>)],
) {
    let count = instances.len();
    let names: Vec<String> = instances.iter().map(|(i, _)| get_full_name(i)).collect();
    let headless = instances.iter().filter(|(i, _)| i.background != 0).count();
    let interactive = count - headless;
    let instance_list = if count <= 8 {
        names.join(", ")
    } else {
        format!("{} ... (+{} more)", names[..6].join(", "), count - 6)
    };

    println!("\n== STOP {scope} PREVIEW ==");
    println!(
        "This will stop {count} instance{}.\n",
        if count != 1 { "s" } else { "" }
    );
    println!("Instances to stop:\n  {instance_list}\n");
    println!("What happens:");
    println!(
        "  • Headless instances ({headless}): process killed (SIGTERM, then SIGKILL after 2s)"
    );
    println!("  • Interactive instances ({interactive}): notified via TCP (graceful)");
    println!("  • All: stopped event logged with snapshot, instance rows deleted");
    println!("  • Subagents: recursively stopped when parent stops\n");
    println!("Instance data preserved in events table (life.stopped with snapshot).\n");
    println!("Add --go flag and run again to proceed:");
    println!("  hcom --go stop {cmd_suffix}\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::common::STOP_ENTRY_GAP_HOOK;
    use serial_test::serial;

    /// A launched session's row, tagged `grp`, bound to its own process.
    fn seed(db: &HcomDb, name: &str, created_at: f64, session: &str, process: &str) {
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, created_at, tool, session_id, tag) \
                 VALUES (?1, 'active', ?2, 'codex', ?3, 'grp')",
                rusqlite::params![name, created_at, session],
            )
            .unwrap();
        db.set_process_binding(process, session, name).unwrap();
    }

    /// `start --as` between the command's read and its release: the row is
    /// recreated as another incarnation, same tag, bound to its own process.
    fn replace(db: &HcomDb, name: &str) {
        db.conn()
            .execute(
                "DELETE FROM process_bindings WHERE instance_name = ?1",
                rusqlite::params![name],
            )
            .unwrap();
        db.conn()
            .execute(
                "DELETE FROM instances WHERE name = ?1",
                rusqlite::params![name],
            )
            .unwrap();
        seed(db, name, 2.0, "sess-new", "proc-new");
    }

    /// Run `hcom --go stop <targets>` against a row a replacement takes over
    /// right after the command read it. The replacement keeps its row and
    /// binding and gets no stopped record, and the command reports the
    /// name skipped, not stopped (exit 1).
    fn assert_stop_spares_a_replacement(targets: &[&str]) {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        let name = "stop-target";
        seed(&db, name, 1.0, "sess-old", "proc-old");

        STOP_ENTRY_GAP_HOOK.with(|hook| hook.set(Some(replace)));
        let args = StopArgs {
            targets: targets.iter().map(|t| t.to_string()).collect(),
        };
        let go = CommandContext {
            explicit_name: None,
            identity: None,
            go: true,
        };
        let code = cmd_stop(&db, &args, Some(&go));
        STOP_ENTRY_GAP_HOOK.with(|hook| hook.set(None));

        let row = db
            .get_instance_full(name)
            .unwrap()
            .unwrap_or_else(|| panic!("{targets:?} released the replacement row"));
        assert_eq!(row.created_at, 2.0, "{targets:?}");
        assert_eq!(
            db.process_binding_ids(name).unwrap(),
            vec!["proc-new"],
            "{targets:?}"
        );
        let stopped: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE type = 'life' AND instance = ?1 \
                 AND json_extract(data, '$.action') = 'stopped'",
                rusqlite::params![name],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stopped, 0, "{targets:?}");
        assert_eq!(code, 1, "a skipped name is not stopped: {targets:?}");
    }

    #[test]
    #[serial]
    fn stop_all_spares_a_replacement_landing_after_its_read() {
        assert_stop_spares_a_replacement(&["all"]);
    }

    #[test]
    #[serial]
    fn stop_by_tag_spares_a_replacement_landing_after_its_read() {
        assert_stop_spares_a_replacement(&["tag:grp"]);
    }

    #[test]
    #[serial]
    fn single_stop_spares_a_replacement_landing_after_its_read() {
        assert_stop_spares_a_replacement(&["stop-target"]);
    }
}
