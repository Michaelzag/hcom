//! `hcom stop` command — end hcom participation.
//!
//!
//! Supports: self-stop, named stop, multi-stop, `all`, `tag:<name>`.
//! Inside AI tools, destructive ops require `--go` flag.

use crate::db::HcomDb;
use crate::identity;
use crate::identity::get_full_name;
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
        let mut orphan_notes = Vec::new();

        for (inst, binding_ids) in &instances {
            let display = get_full_name(inst);
            // The release reaps the whole tree first; a failure means live
            // processes remain, so the name must not be reported as stopped.
            let (outcome, released) =
                stop_read_instance(db, inst, binding_ids, &launcher, "stop_all");
            match outcome {
                outcome if outcome.is_re_registered() => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
                    skipped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped => {
                    stopped_names.push(display.clone());
                    orphan_notes.extend(released.iter().map(|(name, orphans)| {
                        crate::proctruth::describe_unsignalled_orphans(name, orphans)
                    }));
                }
                crate::hooks::common::StopOutcome::RetryableError(e) => {
                    eprintln!("Error stopping {display}: {e}");
                    orphan_notes.extend(released.iter().map(|(name, orphans)| {
                        crate::proctruth::describe_unsignalled_orphans(name, orphans)
                    }));
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
            for note in &orphan_notes {
                println!("{note}");
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
        let mut orphan_notes = Vec::new();

        for (inst, binding_ids) in &tag_matches {
            let display = get_full_name(inst);
            let (outcome, released) =
                stop_read_instance(db, inst, binding_ids, &launcher, "tag_stop");
            match outcome {
                outcome if outcome.is_re_registered() => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
                    skipped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped => {
                    stopped_names.push(display.clone());
                    orphan_notes.extend(released.iter().map(|(name, orphans)| {
                        crate::proctruth::describe_unsignalled_orphans(name, orphans)
                    }));
                }
                crate::hooks::common::StopOutcome::RetryableError(e) => {
                    eprintln!("Error stopping {display}: {e}");
                    orphan_notes.extend(released.iter().map(|(name, orphans)| {
                        crate::proctruth::describe_unsignalled_orphans(name, orphans)
                    }));
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
        for note in &orphan_notes {
            println!("{note}");
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
            // Fleet-first (see `identity::cli_target`): a bare name live on
            // one other device is that device's `X:DEV` form and is skipped
            // as a remote instance below; an ambiguous name is refused
            // outright; a name live nowhere keeps today's local lookup.
            let name = match resolve_stop_target(db, t) {
                Ok(name) => name,
                Err(msg) => {
                    eprintln!("Error: {msg}");
                    return 1;
                }
            };
            match db.get_instance_with_bindings(&name) {
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
        let mut orphan_notes = Vec::new();

        for (inst, binding_ids) in &instances_to_stop {
            if is_remote_instance(inst) {
                println!("Skipping remote instance: {}", get_full_name(inst));
                continue;
            }
            let display = get_full_name(inst);
            let (outcome, released) =
                stop_read_instance(db, inst, binding_ids, &launcher, "multi_stop");
            match outcome {
                outcome if outcome.is_re_registered() => {
                    eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
                    skipped_names.push(display.clone());
                }
                crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped => {
                    stopped_names.push(display.clone());
                    orphan_notes.extend(released.iter().map(|(name, orphans)| {
                        crate::proctruth::describe_unsignalled_orphans(name, orphans)
                    }));
                }
                crate::hooks::common::StopOutcome::RetryableError(e) => {
                    eprintln!("Error stopping {display}: {e}");
                    orphan_notes.extend(released.iter().map(|(name, orphans)| {
                        crate::proctruth::describe_unsignalled_orphans(name, orphans)
                    }));
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
        for note in &orphan_notes {
            println!("{note}");
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
        // Fleet-first: a bare name live on one other device resolves to that
        // device's `X:DEV` form and hits the remote-stop refusal below.
        match resolve_stop_target(db, target) {
            Ok(name) => name,
            Err(msg) => {
                eprintln!("Error: {msg}");
                return 1;
            }
        }
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
    let (outcome, released) = stop_read_instance(db, &position, &binding_ids, &launcher, reason);
    match outcome {
        outcome if outcome.is_re_registered() => {
            eprintln!("{}", crate::hooks::common::skipped_stop_line(&display));
            return 1;
        }
        crate::hooks::common::StopOutcome::Stopped
        | crate::hooks::common::StopOutcome::AlreadyStopped => {}
        crate::hooks::common::StopOutcome::RetryableError(e) => {
            eprintln!("Error stopping {display}: {e}");
            for (name, orphans) in &released {
                println!(
                    "{}",
                    crate::proctruth::describe_unsignalled_orphans(name, orphans)
                );
            }
            return 1;
        }
    }

    if is_subagent_instance(&position) {
        println!("Stopped hcom for subagent {display}.");
    } else {
        println!("Stopped hcom for {display}.");
    }
    for (name, orphans) in &released {
        println!(
            "{}",
            crate::proctruth::describe_unsignalled_orphans(name, orphans)
        );
    }

    if position.background != 0 && !position.background_log_file.is_empty() {
        println!("\nHeadless log: {}", position.background_log_file);
    }

    0
}

/// The instance name `hcom stop` acts on: fleet-first for a bare name, and
/// on a name live nowhere today's local lookup (the local row, else the
/// input unchanged so it hits the not-found report). `Err` is the fleet
/// refusal message (an ambiguous name, or one live only on suffix-only
/// devices).
fn resolve_stop_target(db: &HcomDb, target: &str) -> Result<String, String> {
    crate::identity::cli_target(db, target)
}

/// Stop `inst`, bound to the incarnation this command read: `inst` and
/// `binding_ids` are one snapshot, and the release refuses anything that
/// registered under the name since (a `start --as` replacement or a rebind),
/// which is reported skipped and never stopped.
///
/// A row with no live root whose only live carriers are orphans is released
/// with no signal to anyone ([`crate::proctruth::orphan_only_release`]), and
/// so is any such child row the stop reaches. Every row released that way
/// comes back with its orphans for the caller to list, this row first.
fn stop_read_instance(
    db: &HcomDb,
    inst: &crate::db::InstanceRow,
    binding_ids: &[String],
    initiator: &str,
    reason: &str,
) -> (
    crate::hooks::common::StopOutcome,
    crate::proctruth::OrphanReleases,
) {
    match capture_for_stop(db, inst, binding_ids) {
        Ok((capture, orphans)) => {
            release_captured(db, &inst.name, initiator, reason, capture, orphans)
        }
        Err(e) => (
            crate::hooks::common::StopOutcome::RetryableError(e.into()),
            Vec::new(),
        ),
    }
}

/// Run the stop `capture` gates, then gather every row it released with no
/// signal: `name` itself when `orphans` is non-empty and the release landed,
/// then its children. A failed release never lists `name` (its row is still
/// there); children the stop released before failing stay listed so the
/// caller reports their still-running orphans on the error path too.
fn release_captured(
    db: &HcomDb,
    name: &str,
    initiator: &str,
    reason: &str,
    capture: crate::proctruth::ReapCapture,
    orphans: Vec<crate::proctruth::OrphanCarrier>,
) -> (
    crate::hooks::common::StopOutcome,
    crate::proctruth::OrphanReleases,
) {
    let (outcome, children) = crate::hooks::common::stop_instance_with_capture_listing_orphans(
        db, name, initiator, reason, capture,
    );
    let mut released = Vec::new();
    if !orphans.is_empty()
        && matches!(
            outcome,
            crate::hooks::common::StopOutcome::Stopped
                | crate::hooks::common::StopOutcome::AlreadyStopped
        )
    {
        released.push((name.to_string(), orphans));
    }
    released.extend(children);
    (outcome, released)
}

/// Release `name`'s row with no signal to anyone when it has no live root
/// and its only live carriers are orphans — the release the daemon sweep
/// performs on its own. None when there is no row, the row is not
/// orphan-only, or a descendant child row cannot be proven orphan-only
/// (nothing was done, so a live row gets the caller's plain refusal);
/// otherwise every row released that way (this one first, then
/// any orphan-only children) with the orphans left running, or an error:
/// the row could not be read, the capture refused (the F2 foreign-owner
/// guard), or the release did not land.
pub(crate) fn release_orphaned_row(
    db: &HcomDb,
    name: &str,
    initiator: &str,
    reason: &str,
) -> Option<Result<crate::proctruth::OrphanReleases, String>> {
    let (row, binding_ids) = match db.get_instance_with_bindings(name) {
        Ok(read) => read,
        Err(e) => return Some(Err(format!("could not read instance {name}: {e}"))),
    };
    let row = row?;
    // Classify first, read-only: a row with a live root never reaches the
    // capture, so its refusal stays the caller's plain one.
    crate::proctruth::orphaned_row_carriers(db, &row, &binding_ids)?;
    let (capture, orphans) = match capture_for_stop(db, &row, &binding_ids) {
        Ok(captured) => captured,
        Err(e) => return Some(Err(e)),
    };
    // The carriers changed since the classification: not orphan-only now.
    if !capture.signal_free() {
        return None;
    }
    // A signal-free release takes every descendant child row with it: refuse
    // without changing anything when one cannot be proven orphan-only, so
    // the caller keeps its plain "still active" refusal.
    if let Some(blocker) = crate::hooks::common::signal_free_release_blocker(db, name) {
        log_info("lifecycle", "stop.orphan_release_refused", &blocker);
        return None;
    }
    match release_captured(db, name, initiator, reason, capture, orphans) {
        (
            crate::hooks::common::StopOutcome::Stopped
            | crate::hooks::common::StopOutcome::AlreadyStopped,
            released,
        ) => Some(Ok(released)),
        (crate::hooks::common::StopOutcome::RetryableError(e), _) => Some(Err(e.to_string())),
    }
}

/// The capture a stop of `inst` threads, and the orphans it leaves running.
/// The capture is the gate: a refusal (`Err`, the F2 foreign-owner guard)
/// means the stop sends nothing and leaves the row and its bindings
/// untouched; the caller's existing error channel prints the owner named in
/// the message and exits 1. When the row has no live root and every live
/// carrier is an orphan, the capture becomes a signal-free release and the
/// orphans are returned; otherwise they are empty.
fn capture_for_stop(
    db: &HcomDb,
    inst: &crate::db::InstanceRow,
    binding_ids: &[String],
) -> Result<
    (
        crate::proctruth::ReapCapture,
        Vec<crate::proctruth::OrphanCarrier>,
    ),
    String,
> {
    let owners = crate::proctruth::omp_owner_bindings(db, &inst.name);
    let capture = crate::proctruth::capture_reap_carriers(
        db,
        &inst.name,
        Some(inst),
        binding_ids,
        &owners,
        &[],
    )
    .map_err(|e| e.to_string())?;
    match crate::proctruth::orphan_only_release(db, inst, binding_ids, capture) {
        Ok((capture, orphans)) => {
            log_info(
                "lifecycle",
                "stop.orphan_release",
                &format!(
                    "name={} orphans={:?}: no live root, releasing without signals",
                    inst.name,
                    orphans.iter().map(|o| o.pid).collect::<Vec<_>>()
                ),
            );
            Ok((capture, orphans))
        }
        Err(capture) => Ok((capture, Vec::new())),
    }
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

    /// The henu shape: no live root, one carrier reparented to the user's
    /// subreaper. The stop releases the row with the same stopped record as
    /// any stop, names the orphan it left running, and signals nobody.
    #[test]
    #[cfg(target_os = "linux")]
    #[serial]
    fn stop_releases_a_root_less_row_without_signalling_its_orphan() {
        use crate::proctruth::orphan_fixtures;
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        let name = orphan_fixtures::unique("stop");
        let session = format!("{name}-session");
        orphan_fixtures::seed_seat_row(&db, &name, &session, dir.path());
        let orphan = orphan_fixtures::spawn_orphan(&name);

        let (row, binding_ids) = db.get_instance_with_bindings(&name).unwrap();
        let row = row.expect("seeded row");
        let (outcome, released) = stop_read_instance(&db, &row, &binding_ids, "test", "stopped");

        assert_eq!(outcome, crate::hooks::common::StopOutcome::Stopped);
        let orphans = vec![crate::proctruth::OrphanCarrier {
            pid: orphan.carrier,
            comm: orphan_fixtures::comm_of(orphan.carrier),
            ppid: Some(orphan.standin),
        }];
        assert_eq!(released, vec![(name.clone(), orphans.clone())]);
        assert!(db.get_instance_full(&name).unwrap().is_none());
        assert!(db.process_binding_ids(&name).unwrap().is_empty());
        let stopped = orphan_fixtures::stopped_events(&db, &name);
        assert_eq!(stopped.len(), 1, "{stopped:?}");
        assert_eq!(stopped[0]["by"], "test");
        assert!(
            orphan.alive(orphan.carrier),
            "the stop signalled the orphan"
        );
        assert!(orphan.alive(orphan.standin));

        let note = crate::proctruth::describe_unsignalled_orphans(&name, &orphans);
        assert!(note.starts_with("Not signalled"), "{note}");
        assert!(note.contains(&format!("pid {}", orphan.carrier)), "{note}");
    }

    // ── fleet-wide bare-name resolution ─────────────────────────────────

    const FLEET_DEV: &str = "11111111-1111-4111-8111-111111111111";
    const FLEET_DEV_B: &str = "22222222-2222-4222-8222-222222222222";

    /// The `x:DEV` form a device's rows carry, from the canonical short-id
    /// derivation.
    fn remote_form(base: &str, device_uuid: &str) -> String {
        format!("{base}:{}", crate::relay::device_short_id(device_uuid))
    }

    fn fleet_db() -> (tempfile::TempDir, HcomDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = HcomDb::open_raw(&dir.path().join("test.db")).unwrap();
        db.init_db().unwrap();
        (dir, db)
    }

    fn insert_mirror(db: &HcomDb, name: &str, device_uuid: &str) {
        let now = chrono::Utc::now().timestamp_millis() as f64;
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, status_context, status_time,
                                        created_at, tool, origin_device_id)
                 VALUES (?1, 'listening', 'ready', ?2, ?2, 'omp', ?3)",
                rusqlite::params![name, now, device_uuid],
            )
            .unwrap();
    }

    /// Run `hcom --go stop <targets>`.
    fn run_stop(db: &HcomDb, targets: &[&str]) -> i32 {
        let args = StopArgs {
            targets: targets.iter().map(|t| t.to_string()).collect(),
        };
        let go = CommandContext {
            explicit_name: None,
            identity: None,
            go: true,
        };
        cmd_stop(db, &args, Some(&go))
    }

    /// A bare name live on one other device resolves to that device's exact
    /// `X:DEV` form, which the command then refuses as a remote mirror.
    #[test]
    #[serial_test::serial]
    fn a_bare_name_live_on_one_remote_device_resolves_to_its_suffixed_form() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        let form = remote_form("luna", FLEET_DEV);
        insert_mirror(&db, &form, FLEET_DEV);
        assert_eq!(resolve_stop_target(&db, "luna").unwrap(), form);
        assert_eq!(run_stop(&db, &["luna"]), 1, "remote stop stays refused");
    }

    #[test]
    #[serial_test::serial]
    fn a_bare_name_live_on_two_remote_devices_is_refused_with_both_forms() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
        insert_mirror(&db, &remote_form("luna", FLEET_DEV_B), FLEET_DEV_B);
        let err = resolve_stop_target(&db, "luna").expect_err("ambiguous");
        assert!(err.contains(&remote_form("luna", FLEET_DEV)), "{err}");
        assert!(err.contains(&remote_form("luna", FLEET_DEV_B)), "{err}");
    }

    /// A refused ambiguous name stops nothing: the local seat in the same
    /// command is left alone and the run fails.
    #[test]
    #[serial_test::serial]
    fn an_ambiguous_bare_name_stops_nothing() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
        insert_mirror(&db, &remote_form("luna", FLEET_DEV_B), FLEET_DEV_B);
        seed(&db, "navi", 1.0, "sess-navi", "proc-navi");
        assert_eq!(run_stop(&db, &["luna", "navi"]), 1);
        assert!(
            db.get_instance_full("navi").unwrap().is_some(),
            "a refused name must not take the rest of the command down with it silently"
        );
    }

    /// A bare name live only on another device alongside a live local seat:
    /// the remote one is skipped as a mirror, the local one is stopped. The
    /// exit code is what tells the two apart from today's not-found error.
    #[test]
    #[serial_test::serial]
    fn a_bare_remote_name_is_skipped_while_the_local_seat_stops() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        insert_mirror(&db, &remote_form("luna", FLEET_DEV), FLEET_DEV);
        seed(&db, "navi", 1.0, "sess-navi", "proc-navi");
        assert_eq!(run_stop(&db, &["luna", "navi"]), 0);
        assert!(db.get_instance_full("navi").unwrap().is_none());
        assert!(
            db.get_instance_full(&remote_form("luna", FLEET_DEV))
                .unwrap()
                .is_some(),
            "a mirror row is never stopped"
        );
    }

    /// A stopped local name has no live candidate anywhere, so the fleet
    /// resolver passes it through and today's not-found error stands.
    #[test]
    #[serial_test::serial]
    fn a_stopped_local_name_keeps_todays_not_found() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        db.log_life_event("luna", "stopped", "test", "exit", None, None)
            .unwrap();
        assert_eq!(resolve_stop_target(&db, "luna").unwrap(), "luna");
        assert_eq!(run_stop(&db, &["luna"]), 1);
    }

    /// An already-suffixed name never reaches the fleet resolver, even when
    /// the bare name would be ambiguous.
    #[test]
    #[serial_test::serial]
    fn a_suffixed_name_is_never_fleet_resolved() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        let form = remote_form("luna", FLEET_DEV);
        insert_mirror(&db, &form, FLEET_DEV);
        insert_mirror(&db, &remote_form("luna", FLEET_DEV_B), FLEET_DEV_B);
        assert_eq!(resolve_stop_target(&db, &form).unwrap(), form);
        assert_eq!(run_stop(&db, &[&form]), 1, "remote stop stays refused");
    }

    /// A live local row is a fleet candidate, not a short-circuit: with a
    /// live mirror of the same base name the stop refuses, naming both
    /// forms, and stops nothing.
    #[test]
    #[serial_test::serial]
    fn a_live_local_name_and_a_live_mirror_are_refused_with_both_forms() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        seed(&db, "luna", 1.0, "sess-luna", "proc-luna");
        let form = remote_form("luna", FLEET_DEV);
        insert_mirror(&db, &form, FLEET_DEV);
        let err = resolve_stop_target(&db, "luna").expect_err("ambiguous");
        assert!(err.contains("@luna,"), "{err}");
        assert!(err.contains(&form), "{err}");
        assert_eq!(run_stop(&db, &["luna"]), 1);
        assert!(
            db.get_instance_full("luna").unwrap().is_some(),
            "a refused name stops nothing"
        );
    }

    /// A stopped local row is never a candidate, so the name belongs to the
    /// one device it is still live on.
    #[test]
    #[serial_test::serial]
    fn a_stopped_local_name_with_a_live_remote_resolves_to_the_remote_form() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let (_dir, db) = fleet_db();
        db.conn()
            .execute(
                "INSERT INTO instances (name, status, status_context, status_time,
                                        created_at, tool)
                 VALUES ('luna', 'stopped', 'exit', 1.0, 1.0, 'omp')",
                [],
            )
            .unwrap();
        let form = remote_form("luna", FLEET_DEV);
        insert_mirror(&db, &form, FLEET_DEV);
        assert_eq!(resolve_stop_target(&db, "luna").unwrap(), form);
        assert_eq!(run_stop(&db, &["luna"]), 1, "remote stop stays refused");
    }
}
