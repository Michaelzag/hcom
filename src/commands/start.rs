//! Start command: `hcom start [--name <agent-id>] [--as <name>] [--orphan <name|pid>]`
//!
//! Runs inside an already-running tool session rather than launching a new one.
//! Used for adhoc/manual setup, identity rebinding, and orphan recovery:
//! - Bare start: detect vanilla tool or create adhoc instance
//! - `--name <agent-id>`: register a subagent (a router-level global flag, not
//!   parsed by `StartArgs` — resolved in `run()` via `flags.name`)
//! - `--orphan`: recover orphaned PTY process
//! - `--as`: rebind session identity

use anyhow::{Result, bail};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::bootstrap;
use crate::claude_actor;
use crate::config::HcomConfig;
use crate::db::{HcomDb, InstanceRow};
use crate::identity;
use crate::instance_binding;
use crate::instance_lifecycle as lifecycle;
use crate::instance_names;
use crate::instances;
use crate::log::log_info;
use crate::paths;
use crate::pidtrack;
use crate::relay;
use crate::router::GlobalFlags;
use crate::shared::constants::ST_ACTIVE;
use crate::shared::context::HcomContext;

/// Parsed arguments for `hcom start`.
#[derive(clap::Parser, Debug)]
#[command(name = "start", about = "Start hcom participation")]
pub struct StartArgs {
    /// Rebind to a different instance name
    #[arg(long = "as")]
    pub as_name: Option<String>,
    /// Recover orphaned PTY process by name or PID
    #[arg(long)]
    pub orphan: Option<String>,
}

/// Run the start command.
pub fn run(argv: &[String], flags: &GlobalFlags) -> Result<i32> {
    // Filter out global flags already consumed by the router (start, --name X, --go)
    let mut filtered = vec!["start".to_string()];
    let mut skip_next = false;
    for arg in argv {
        if skip_next {
            skip_next = false;
            continue;
        }
        match arg.as_str() {
            "start" | "--go" => continue,
            "--name" => {
                skip_next = true;
                continue;
            }
            _ => filtered.push(arg.clone()),
        }
    }

    use clap::Parser;
    let start_args = match StartArgs::try_parse_from(&filtered) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            return Ok(if e.use_stderr() { 1 } else { 0 });
        }
    };

    let orphan_target = start_args.orphan;
    let rebind_target = start_args.as_name;

    let db = HcomDb::open()?;
    let hcom_dir = paths::hcom_dir();

    let mut ctx = HcomContext::from_os();
    let presented_process_id = ctx.process_id.clone();
    ctx.trust_process_id(&db);
    // The id the trust gate just refused. Only a reclaim that restores the
    // target's verified anchor pid may bind it, re-checking trust after the
    // restore (see start_rebind); nothing else ever sees it.
    let refused_process_id = presented_process_id.filter(|_| ctx.process_id.is_none());
    let verified_actor = claude_actor::resolve_env_actor(&db).map_err(anyhow::Error::new)?;
    if let (Some(actor), Some(name)) = (verified_actor.as_ref(), flags.name.as_deref()) {
        claude_actor::ensure_explicit_matches(&db, actor, name).map_err(anyhow::Error::new)?;
    }

    let requested_name = flags
        .name
        .as_deref()
        .map(|name| identity::resolve_display_name(&db, name).unwrap_or_else(|| name.to_string()));

    // A verified child actor can only promote/use its existing row. It cannot
    // rebind or recover another identity, and it does not need --name.
    if let Some(actor) = verified_actor.as_ref()
        && let Some(actor_row) = db.get_instance_full(&actor.name)?
        && instances::is_subagent_instance(&actor_row)
    {
        if rebind_target.is_some() {
            println!("[HCOM] Subagents cannot use --as. End your turn.");
            return Ok(1);
        }
        if orphan_target.is_some() {
            println!("[HCOM] Subagents cannot use --orphan. End your turn.");
            return Ok(1);
        }
        return start_subagent(&db, &actor_row);
    }

    // Without a capability, retain the ordinary manual fallback. A direct
    // indexed child lookup supports the documented --name <agent-id> form
    // without scanning duplicated parent JSON.
    let subagent_via_name = if verified_actor.is_none() {
        requested_name
            .as_deref()
            .and_then(|id| detect_subagent(&db, id))
    } else {
        None
    };
    let subagent_via_as = if verified_actor.is_none() {
        rebind_target
            .as_deref()
            .and_then(|id| detect_subagent(&db, id))
    } else {
        None
    };

    if subagent_via_as.is_some() || (subagent_via_name.is_some() && rebind_target.is_some()) {
        println!("[HCOM] Subagents cannot change identity. End your turn.");
        return Ok(1);
    }

    if let Some(orphan) = orphan_target {
        return start_from_orphan(&db, &hcom_dir, &orphan, &ctx);
    }

    if let Some(rebind) = rebind_target {
        let current_name = verified_actor
            .as_ref()
            .map(|actor| actor.name.as_str())
            .or(requested_name.as_deref());
        return start_rebind(
            &db,
            &rebind,
            &ctx,
            current_name,
            refused_process_id.as_deref(),
        );
    }

    if let Some(subagent) = subagent_via_name {
        return start_subagent(&db, &subagent);
    }

    // A verified root actor stays the root even while children exist.
    let effective_name = verified_actor
        .as_ref()
        .map(|actor| actor.name.as_str())
        .or(requested_name.as_deref());
    start_bare(&db, &hcom_dir, &ctx, effective_name)
}

/// Resolve a live child row directly by agent_id (or by its exact row name).
fn detect_subagent(db: &HcomDb, check_id: &str) -> Option<InstanceRow> {
    let name = db
        .get_instance_by_agent_id(check_id)
        .ok()
        .flatten()
        .unwrap_or_else(|| check_id.to_string());
    let row = db.get_instance_full(&name).ok().flatten()?;
    row.parent_name.as_ref().filter(|name| !name.is_empty())?;
    Some(row)
}

/// Promote an existing dormant child row into active hcom participation.
fn start_subagent(db: &HcomDb, info: &InstanceRow) -> Result<i32> {
    let parent_name = info.parent_name.as_deref().unwrap_or("");
    if parent_name.is_empty() || info.agent_id.as_deref().unwrap_or("").is_empty() {
        bail!(
            "Subagent row '{}' is missing parent/agent identity",
            info.name
        );
    }

    let was_announced = info.name_announced != 0;
    lifecycle::set_status(db, &info.name, ST_ACTIVE, "tool:start", Default::default());
    instance_binding::capture_and_store_launch_context(db, &info.name);

    log_info(
        "lifecycle",
        "start.subagent",
        &format!(
            "name={} parent={} agent_id={} announced={}",
            info.name,
            parent_name,
            info.agent_id.as_deref().unwrap_or(""),
            was_announced
        ),
    );

    if was_announced {
        println!("hcom already started for {}", info.name);
        return Ok(0);
    }

    let bootstrap = bootstrap::get_subagent_bootstrap(&info.name, parent_name);
    if !bootstrap.is_empty() {
        println!("{bootstrap}");
    }
    let mut updates = serde_json::Map::new();
    updates.insert("name_announced".into(), serde_json::json!(true));
    instances::update_instance_position(db, &info.name, &updates);

    Ok(0)
}

/// Recover orphaned PTY process by PID or name.
fn start_from_orphan(
    db: &HcomDb,
    hcom_dir: &std::path::Path,
    target: &str,
    _ctx: &HcomContext,
) -> Result<i32> {
    let active_pids: HashSet<u32> = db
        .iter_instances_full()?
        .iter()
        .filter_map(|inst| inst.pid.map(|p| p as u32))
        .collect();
    let orphans = pidtrack::get_orphan_processes(hcom_dir, Some(&active_pids));

    if orphans.is_empty() {
        bail!("No orphan processes found.");
    }

    // Match by PID or name
    let orphan = if let Ok(pid) = target.parse::<u32>() {
        match orphans.iter().find(|o| o.pid == pid) {
            Some(o) => o,
            None => bail!("Orphan PID {} not found.", pid),
        }
    } else {
        let matches: Vec<_> = orphans
            .iter()
            .filter(|o| o.names.contains(&target.to_string()))
            .collect();
        match matches.len() {
            0 => bail!("Orphan '{}' not found.", target),
            1 => matches[0],
            _ => {
                let pids: Vec<String> = matches.iter().map(|m| m.pid.to_string()).collect();
                bail!(
                    "Multiple orphans match '{}' (PIDs: {}). Use --orphan <pid>.",
                    target,
                    pids.join(", ")
                );
            }
        }
    };

    let pid = orphan.pid;

    if orphan.process_id.is_empty() {
        bail!(
            "Orphan PID {} has no process_id and cannot be recovered.",
            pid
        );
    }

    let preferred_name = orphan.names.last().cloned().unwrap_or_default();
    let can_reuse = !preferred_name.is_empty()
        && identity::is_valid_base_name(&preferred_name)
        && db.get_instance_full(&preferred_name)?.is_none();
    let name = if can_reuse {
        preferred_name
    } else {
        instance_names::generate_unique_name(db)?
    };

    // Core DB registration
    let _ = pidtrack::recover_single_orphan_to_db(db, orphan, &name);

    db.log_event(
        "life",
        &name,
        &json!({
            "action": "started",
            "by": "cli",
            "reason": "orphan_recover",
            "orphan_pid": pid,
        }),
    )
    .ok();

    pidtrack::remove_pid(hcom_dir, pid);

    println!("[hcom:{}]", name);
    if can_reuse {
        println!("Recovered orphan PID {} as '{}'.", pid, name);
    } else {
        println!(
            "Recovered orphan PID {} as new identity '{}' (name conflict/unavailable).",
            pid, name
        );
    }

    log_info(
        "start",
        "orphan.recovered",
        &format!("name={} pid={} tool={}", name, pid, orphan.tool),
    );

    Ok(0)
}

#[derive(Debug, Clone)]
struct ChildLink {
    name: String,
    parent_name: Option<String>,
}

fn snapshot_child_links(db: &HcomDb, session_id: Option<&str>) -> Result<Vec<ChildLink>> {
    let Some(session_id) = session_id.filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut stmt = db
        .conn()
        .prepare("SELECT name, parent_name FROM instances WHERE parent_session_id = ?")?;
    let rows = stmt.query_map(rusqlite::params![session_id], |row| {
        Ok(ChildLink {
            name: row.get(0)?,
            parent_name: row.get(1)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}

fn restore_child_links_after_root_rebind(
    db: &HcomDb,
    links: &[ChildLink],
    session_id: &str,
    old_root: &str,
    new_root: &str,
) -> Result<()> {
    db.with_immediate_transaction(|txn| {
        for link in links {
            let parent_name = match link.parent_name.as_deref() {
                Some(parent) if parent == old_root => Some(new_root),
                other => other,
            };
            txn.execute(
                "UPDATE instances SET parent_session_id = ?, parent_name = ? WHERE name = ?",
                rusqlite::params![session_id, parent_name, &link.name],
            )?;
        }
        Ok(())
    })
}

// Test seam: runs between a rebind's planning reads and its one write
// transaction, so a test can commit a competing reclaim of the name there.
#[cfg(test)]
thread_local! {
    static REBIND_CREATE_GAP_HOOK: crate::db::GapHook = const { std::cell::Cell::new(None) };
}

/// Rebind session identity (`--as <name>`), preserving last_event_id and any
/// live Claude child hierarchy owned by the current root actor.
///
/// `refused_process_id` is the `HCOM_PROCESS_ID` the trust gate refused in
/// [`run`]. It is bound only behind a restored anchor pid (see
/// [`match_reclaim_anchor`]), and trust is evaluated again after the restore.
fn start_rebind(
    db: &HcomDb,
    rebind_target: &str,
    ctx: &HcomContext,
    explicit_name: Option<&str>,
    refused_process_id: Option<&str>,
) -> Result<i32> {
    let hcom_dir = paths::hcom_dir();

    // Resolve the target name
    let target_name = identity::resolve_display_name_or_stopped(db, rebind_target)
        .unwrap_or_else(|| rebind_target.to_string());

    // Guard: refuse to reclaim a subagent slot. Subagents share their parent's
    // session_id, so `hcom start --as <subagent_name>` from inside a subagent
    // bash would rebind session_bindings[parent_sid] to the subagent name,
    // clobbering the parent's identity. `--as` is documented for top-level
    // restartable identities (compaction/resume/clear), not for subagent
    // lifecycle — which has its own SubagentStart bootstrap path.
    if db.was_subagent_name(&target_name) {
        eprintln!(
            "Error: '{target_name}' is a subagent slot; cannot be reclaimed with --as.\n\
             Subagents register via 'hcom start --name <agent-id>' in the SubagentStart context. If your session ended, stop working and end your turn."
        );
        return Ok(1);
    }

    let explicit_current_name = explicit_name.unwrap_or("");

    // Resolve session_id from process binding or existing instance
    let mut session_id: Option<String> = None;
    if let Some(ref process_id) = ctx.process_id
        && let Ok(Some((sid, _))) = db.get_process_binding_full(process_id)
    {
        session_id = sid.filter(|s| !s.is_empty());
    }
    if session_id.is_none()
        && !explicit_current_name.is_empty()
        && let Ok(Some(current_data)) = db.get_instance_full(explicit_current_name)
    {
        session_id = current_data.session_id.filter(|s| !s.is_empty());
    }
    if session_id.is_none() && ctx.tool == crate::tool::Tool::Claude {
        // A vanilla Claude session has neither a process binding nor, before its
        // first start, a row to read the id back from. Its own session id is
        // what makes the rebind stick: without it the reclaimed name stays
        // unbound and the identity it replaces is never cleaned up.
        session_id = resolve_claude_session_id(&ctx.raw_env);
    }
    let current_name = if !explicit_current_name.is_empty() {
        explicit_current_name.to_string()
    } else if let Some(ref sid) = session_id {
        db.get_session_binding(sid)?.unwrap_or_default()
    } else {
        String::new()
    };
    let child_links = snapshot_child_links(db, session_id.as_deref())?;

    // The caller's live row, when it holds an identity other than the target:
    // the row this rebind would rename away.
    let current_row = if !current_name.is_empty() && current_name != target_name {
        db.get_instance_full(&current_name)?
    } else {
        None
    };

    // Guard: a name with no row and no life history was never an identity, so
    // this is not a reclaim. From a process already holding a live identity it
    // would silently rename that identity away (a subagent following a
    // not-found hint inherits its parent's process binding).
    if current_row.is_some()
        && db.get_instance_full(&target_name)?.is_none()
        && !identity::has_life_history(db, &target_name)
    {
        eprintln!(
            "Error: '{target_name}' is not an identity this process held; this process is '{current_name}'.\n\
             If '{target_name}' is an external sender (cron/script/manual alert), use 'hcom send --from {target_name} ...'.\n\
             To rename '{current_name}' to '{target_name}', run 'hcom start --as {target_name}' from a fresh shell."
        );
        return Ok(1);
    }

    let target_meta = instance_binding::load_rebind_target_metadata(db, &target_name).ok();
    if let Some(meta) = &target_meta {
        ensure_rebind_compatible(&target_name, meta, ctx)?;
    }

    // Preserve the target's own cursor. A caller re-registering the identity
    // it holds reads it from its live row (never an older snapshot); a caller
    // reclaiming another name must not inherit the replaced identity's
    // position, which would skip the target's unread messages.
    let mut last_event_id = target_meta.as_ref().map(|m| m.last_event_id);
    let target_data = db.get_instance_full(&target_name)?;

    // Final fallback: use current max to avoid re-delivering old messages
    if last_event_id.is_none() {
        last_event_id = Some(db.get_last_event_id());
    }

    // Process truth gates the rebind: the target row and its bindings are
    // about to be replaced, so a still-alive prior subtree (orphan) or a
    // live holder of the target name must refuse first — the same uniform
    // rule as resume and explicit-name launch
    // (proctruth::check_spawn_allowed). The caller's own identity tree is
    // never a holder there, so a session re-registering its own name
    // proceeds while a leftover carrier from an older binding refuses as
    // the pre-binding orphan it is.
    if let Err(refusal) = crate::proctruth::check_spawn_allowed(db, &target_name) {
        anyhow::bail!("{refusal}");
    }

    // The recreated row gets an anchor pid only from the target's own
    // history, verified against the live process table. Both reads happen
    // before the deletions below rewrite the rows and bindings they consult.
    let anchor = match_reclaim_anchor(db, &target_name);
    // The refused id may ride on the restored anchor only when it is tied to
    // the same history: it must be the process id recorded on the very stop
    // event the anchor was verified from, and no binding may hold it for
    // any instance but the target. Anything else belongs to another seat.
    let claimable_refused_id = match &anchor {
        Ok(matched) => refused_process_id.filter(|id| {
            matched.process_id.as_deref() == Some(*id)
                && match db.get_process_binding(id) {
                    Ok(owner) => owner.is_none_or(|owner| owner == target_name),
                    Err(_) => false,
                }
        }),
        Err(_) => None,
    };

    // A kept remote row is updated in place and never takes a local anchor;
    // a local target row is replaced. `planned_target` is the local row this
    // rebind planned to replace, by its creation-time bits.
    let kept_remote_row = target_data
        .as_ref()
        .and_then(|td| td.origin_device_id.as_deref())
        .is_some_and(|device| !device.is_empty());
    let planned_target = target_data.as_ref().map(|row| row.created_at.to_bits());
    let tool = ctx.tool.as_str();
    let cwd_override = ctx.cwd.to_string_lossy().to_string();

    // Test seam: a competing reclaim of the same name commits here, after
    // this rebind planned and before it writes.
    #[cfg(test)]
    if let Some(hook) = REBIND_CREATE_GAP_HOOK.with(std::cell::Cell::take) {
        hook(db, &target_name);
    }

    // Every write of the rebind happens in ONE write transaction: replacing
    // the target row and its bindings, recording and removing the renamed-
    // away identity, creating the target row with its verified anchor pid
    // and cursor, and the bindings. Either all of it commits or none of it
    // does. The target is re-read first: a local row other than the planned
    // one was committed by a competing reclaim, so this rebind refuses with
    // nothing written — the caller keeps its row, cursor and bindings, and
    // no anchor pid or binding lands on a row this call did not create.
    let committed = db.with_immediate_transaction(|_tx| {
        // A process bound to a live seat other than the one this call renames
        // away belongs to that seat. Taking it here would move a running
        // identity's process binding onto the reclaimed name, so the whole
        // transaction rolls back with the caller's own identity untouched.
        if let Some(pid) = &ctx.process_id
            && let Some(owner) = db.live_process_binding_owner(pid)?
            && owner != target_name
            && owner != current_name
        {
            bail!(
                "refusing to bind this process ({pid}) to '{target_name}': it is bound to live instance '{owner}'. \
                 Run 'hcom start --as <name>' from a shell outside that seat."
            );
        }
        let occupant = db.get_instance_full(&target_name)?;
        // The row about to be replaced is the newest statement of which
        // session this identity holds; its stopped snapshots are older history.
        // The session travels with its transcript, from the same source.
        let occupant_session = occupant.as_ref().and_then(|row| {
            row.session_id
                .clone()
                .filter(|sid| !sid.is_empty())
                .map(|sid| (sid, row.transcript_path.clone()))
        });
        if !kept_remote_row
            && let Some(occupant) = occupant
            && Some(occupant.created_at.to_bits()) != planned_target
        {
            return Ok(None);
        }
        if !kept_remote_row {
            db.delete_instance(&target_name)?;
        }
        db.delete_process_bindings_for_instance(&target_name)?;
        db.delete_session_bindings_for_instance(&target_name)?;

        // A rename is recorded as the old name's stop, so it never
        // disappears without a life event.
        if current_row.is_some() {
            let snapshot = db.get_instance_snapshot(&current_name)?;
            let life = json!({
                "action": "stopped",
                "by": current_name,
                "reason": "renamed",
                "renamed_to": target_name,
                "process_id": ctx.process_id,
                "snapshot": snapshot,
            });
            db.log_event("life", &current_name, &life)?;
        }
        if !current_name.is_empty() && current_name != target_name {
            db.delete_instance(&current_name)?;
        }

        // A reclaim resolved no session of its own: the caller has no process
        // binding, no row, and no Claude env id. Without the target's own
        // session the recreated row is born unbound, so the reclaimed
        // identity's hook traffic has no session to resolve against. Adopt
        // the session the target holds right now, else the one its newest
        // stop recorded — unless another live identity still holds it. The
        // adopted session keeps the transcript recorded beside it.
        let mut adopted_transcript: Option<String> = None;
        if session_id.is_none() {
            // The stopped snapshot is only consulted once the row is gone, so
            // the read stays here rather than in the planning phase above.
            let stopped_session = crate::commands::resume::load_stopped_snapshot(db, &target_name)
                .ok()
                .map(|data| (data.1, data.9))
                .filter(|(sid, _)| !sid.is_empty());
            if let Some((sid, transcript)) = occupant_session.or(stopped_session)
                && session_id_adoptable(db, &sid, &target_name)?
            {
                session_id = Some(sid);
                adopted_transcript = Some(transcript).filter(|path| !path.is_empty());
            }
        }
        let binding_sid = session_id.clone().unwrap_or_default();

        if !instance_binding::initialize_instance_in_position_file(
            db,
            &target_name,
            session_id.as_deref(),
            None, // parent_session_id
            None, // parent_name
            None, // agent_id
            adopted_transcript.as_deref(),
            Some(tool),
            false, // background
            None,  // tag
            None,  // wait_timeout
            None,  // subagent_timeout
            None,  // hints
            Some(&cwd_override),
        ) {
            bail!("could not create the instance row for '{target_name}'");
        }
        // Restore cursor position + mark as announced
        let mut updates = serde_json::Map::new();
        if let Some(eid) = last_event_id {
            updates.insert("last_event_id".into(), serde_json::json!(eid));
        }
        updates.insert("name_announced".into(), serde_json::json!(1));
        db.update_instance_fields(&target_name, &updates)?;
        let restored_pid = match &anchor {
            Ok(matched) if !kept_remote_row => db
                .set_instance_pid_if_unset(&target_name, matched.pid)?
                .then_some(matched.pid),
            _ => None,
        };

        if let Some(sid) = &session_id {
            if let Err(e) = db.set_session_binding(sid, &target_name) {
                eprintln!("[hcom] warn: set_session_binding failed for {target_name}: {e}");
            } else if ctx.tool == crate::tool::Tool::Claude
                && let Err(e) = db.mark_claude_session_validated(sid, &target_name)
            {
                // The cache still names the identity being replaced, and it is
                // keyed by session generation, so it does not expire on its
                // own. Left stale, every hook for this session resolves to
                // no_instance: no status, no delivery, and the reclaimed row is
                // flagged launch_failed ~30s later while the session is alive
                // and bound.
                eprintln!(
                    "[hcom] warn: mark_claude_session_validated failed for {target_name}: {e}"
                );
            }
            if !current_name.is_empty() && current_name != target_name {
                db.rebind_claude_root_actor_state(sid, &current_name, &target_name)?;
            }
        }
        let created_refused_binding = if let Some(process_id) = &ctx.process_id {
            db.set_process_binding(process_id, &binding_sid, &target_name)?;
            false
        } else if restored_pid.is_some()
            && let Some(process_id) = claimable_refused_id
        {
            claim_unbound_process_id(db, process_id, &binding_sid, &target_name)?
        } else {
            false
        };
        Ok(Some((restored_pid, created_refused_binding)))
    })?;
    let Some((restored_pid, created_refused_binding)) = committed else {
        eprintln!(
            "Error: '{target_name}' was reclaimed by another session while this one ran; \
             nothing was changed.\n\
             If this session should hold '{target_name}', run 'hcom start --as {target_name}' again."
        );
        return Ok(1);
    };

    // The child links keep their own write transaction.
    if let Some(sid) = &session_id {
        let old_root = if current_name.is_empty() {
            target_name.as_str()
        } else {
            current_name.as_str()
        };
        restore_child_links_after_root_rebind(db, &child_links, sid, old_root, &target_name)?;
    }

    let mut bound_process_id = ctx.process_id.clone();
    if created_refused_binding && let Some(process_id) = claimable_refused_id {
        bound_process_id = trust_restored_binding(db, ctx, process_id, &target_name);
    }
    if bound_process_id.is_some() {
        // Migrate notify endpoints before notify so wake reaches correct port
        if !current_name.is_empty()
            && current_name != target_name
            && let Err(e) = db.migrate_notify_endpoints(&current_name, &target_name)
        {
            eprintln!("[hcom] warn: migrate_notify_endpoints failed: {e}");
        }

        crate::notify::wake(db, &target_name, crate::notify::WakeKind::DELIVERY_LOOPS);
    }

    // Record which snapshot and pid the reclaim matched, or why it did not.
    let anchor_record = match (&anchor, restored_pid) {
        (Ok(matched), Some(pid)) => json!({
            "restored": true,
            "snapshot_event_id": matched.event_id,
            "pid": pid,
        }),
        (Ok(matched), None) => json!({
            "restored": false,
            "snapshot_event_id": matched.event_id,
            "pid": matched.pid,
            "reason": "anchor pid write failed",
        }),
        (Err(miss), _) => json!({
            "restored": false,
            "snapshot_event_id": miss.event_id,
            "reason": miss.reason,
        }),
    };
    let reclaim = json!({
        "action": "started",
        "by": "cli",
        "reason": "reclaim",
        "process_id": bound_process_id,
        "anchor": anchor_record,
    });
    if let Err(e) = db.log_event("life", &target_name, &reclaim) {
        eprintln!("[hcom] warn: reclaim life event failed for {target_name}: {e}");
    }

    // Only a launcher UUID needs the anchor: its trust is a recorded ancestor
    // pid (proctruth::process_id_trusted). OMP-minted and synthetic ids never
    // read it, so plain seats stay pid-less without a warning.
    let anchor_needed = ctx
        .process_id
        .as_deref()
        .or(refused_process_id)
        .is_some_and(crate::proctruth::is_launcher_process_id);
    let trusted_after = restored_pid.is_some() && bound_process_id.is_some();
    if anchor_needed && !trusted_after {
        let why = match &anchor {
            Err(miss) => miss.reason,
            Ok(_) if restored_pid.is_none() => "anchor pid write failed",
            Ok(_) => "its launcher id could not be bound to the restored anchor",
        };
        println!(
            "[HCOM] '{target_name}' was reclaimed without anchor-based trust ({why}). \
             Its launcher id stays refused until the seat is relaunched: \
             'hcom stop {target_name}', then 'hcom r {target_name}'."
        );
    }

    // Print bootstrap
    let hcom_config = HcomConfig::load(None).unwrap_or_else(|_| {
        let mut c = HcomConfig::default();
        c.normalize();
        c
    });

    let bootstrap_text = bootstrap::get_bootstrap(
        db,
        &hcom_dir,
        &target_name,
        tool,
        false,
        false,
        &ctx.notes,
        &hcom_config.tag,
        relay::is_relay_enabled(&hcom_config),
        None,
    );

    println!("[hcom:{}]", target_name);
    println!("{}", bootstrap_text);
    // Same reason as bare start: keep the new name visible in a tailed snapshot.
    println!("[hcom:{}]", target_name);

    log_info(
        "start",
        "rebind.complete",
        &format!("from={} to={}", current_name, target_name),
    );

    Ok(0)
}

/// The anchor pid a reclaim may restore, and the `life.stopped` event it
/// came from, with the process id that event recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReclaimAnchor {
    event_id: i64,
    pid: u32,
    process_id: Option<String>,
}

/// Why a reclaim restores no anchor pid; `event_id` is the snapshot
/// consulted, if there was one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnchorMiss {
    event_id: Option<i64>,
    reason: &'static str,
}

/// Match `name`'s own newest `life.stopped` snapshot against the live
/// process table ([`crate::proctruth::verify_reclaim_anchor`]): its recorded
/// pid must be a live ancestor of this process, still the incarnation the
/// snapshot recorded (start time, boot id).
fn match_reclaim_anchor(db: &HcomDb, name: &str) -> Result<ReclaimAnchor, AnchorMiss> {
    use rusqlite::OptionalExtension;
    let newest = db
        .conn()
        .query_row(
            "SELECT id, data FROM events
             WHERE type='life'
               AND instance=?
               AND json_extract(data, '$.action') = 'stopped'
             ORDER BY id DESC LIMIT 1",
            rusqlite::params![name],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional();
    let (event_id, data) = match newest {
        Ok(Some(newest)) => newest,
        Ok(None) => {
            return Err(AnchorMiss {
                event_id: None,
                reason: "no stop snapshot for this name",
            });
        }
        Err(_) => {
            return Err(AnchorMiss {
                event_id: None,
                reason: "stop snapshot unreadable",
            });
        }
    };
    let data = serde_json::from_str::<serde_json::Value>(&data).unwrap_or_default();
    let process_id = data
        .get("process_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let snapshot = data.get("snapshot").cloned().unwrap_or_default();
    crate::proctruth::verify_reclaim_anchor(
        &snapshot,
        &crate::proctruth::caller_ancestor_pids(),
        &crate::sys::process::procfs_start_identity,
    )
    .map(|pid| ReclaimAnchor {
        event_id,
        pid,
        process_id,
    })
    .map_err(|reason| AnchorMiss {
        event_id: Some(event_id),
        reason,
    })
}

/// Bind the refused `process_id` to `target_name` only while no binding holds
/// it. Runs inside the rebind's create transaction, right after the row took
/// its restored anchor pid. Returns whether this call created the binding.
fn claim_unbound_process_id(
    db: &HcomDb,
    process_id: &str,
    session_id: &str,
    target_name: &str,
) -> Result<bool> {
    use rusqlite::OptionalExtension;
    let held = db
        .conn()
        .query_row(
            "SELECT 1 FROM process_bindings WHERE process_id = ?",
            rusqlite::params![process_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if held {
        return Ok(false);
    }
    db.set_process_binding(process_id, session_id, target_name)?;
    Ok(true)
}

/// Evaluate trust again for the refused id this reclaim bound behind the
/// restored anchor pid: the verified anchor is the proof. Returns the id when
/// trusted; otherwise removes only that binding.
fn trust_restored_binding(
    db: &HcomDb,
    ctx: &HcomContext,
    process_id: &str,
    target_name: &str,
) -> Option<String> {
    let mut probe = ctx.clone();
    probe.process_id = Some(process_id.to_string());
    probe.trust_process_id(db);
    if probe.process_id.is_none()
        && let Err(e) = db.conn().execute(
            "DELETE FROM process_bindings WHERE process_id = ? AND instance_name = ?",
            rusqlite::params![process_id, target_name],
        )
    {
        eprintln!("[hcom] warn: delete_process_binding failed for {target_name}: {e}");
    }
    probe.process_id
}

fn ensure_rebind_compatible(
    target_name: &str,
    meta: &instance_binding::RebindTargetMetadata,
    ctx: &HcomContext,
) -> Result<()> {
    let current_tool = ctx.tool.as_str();
    if !meta.tool.is_empty() && meta.tool != current_tool {
        bail!(
            "Refusing to reclaim '{target_name}': latest identity used tool '{}' but current session is '{}'",
            meta.tool,
            current_tool
        );
    }

    let current_dir = ctx.cwd.to_string_lossy();
    if !meta.directory.is_empty() && !same_path(&meta.directory, &current_dir) {
        bail!(
            "Refusing to reclaim '{target_name}': latest identity used directory '{}' but current session is '{}'",
            meta.directory,
            current_dir
        );
    }

    Ok(())
}

fn same_path(left: &str, right: &str) -> bool {
    normalize_path_for_compare(left) == normalize_path_for_compare(right)
}

fn normalize_path_for_compare(path: &str) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path))
}

/// Whether `sid` may be adopted by `target_name`: it is unbound, already held
/// by the target itself, or bound by a session that no other live row carries.
/// A session another live identity is using must never be handed to a second
/// row, however the reclaim resolved its own session.
fn session_id_adoptable(db: &HcomDb, sid: &str, target_name: &str) -> Result<bool> {
    if let Some(holder) = db.get_session_binding(sid)?
        && holder != target_name
    {
        return Ok(false);
    }
    let mut stmt = db.conn().prepare(
        "SELECT 1 FROM instances WHERE session_id = ? AND name != ? AND status != 'stopped' LIMIT 1",
    )?;
    Ok(!stmt.exists(rusqlite::params![sid, target_name])?)
}

/// Resolve the Claude session id visible to a CLI invocation.
///
/// Two sources, in order:
/// - `HCOM_CLAUDE_UNIX_SESSION_ID`: hcom's own SessionStart hook appends this
///   export to `CLAUDE_ENV_FILE`, which Claude runs before each Bash command.
/// - `CLAUDE_CODE_SESSION_ID`: Claude sets this directly in every Bash and
///   PowerShell subprocess, and it matches the `session_id` hooks receive.
///
/// The env-file round trip is the fragile one: it needs `CLAUDE_ENV_FILE` to
/// exist and our SessionStart to have run in this session generation. Without
/// the second source, a session that misses it cannot be recognized on a repeat
/// `hcom start`, which then mints a SECOND identity — the first stays bound to
/// nothing and later reports as launch_failed. Both values are set by Claude
/// for the session running this command, so either one binds identity.
fn resolve_claude_session_id(env: &HashMap<String, String>) -> Option<String> {
    ["HCOM_CLAUDE_UNIX_SESSION_ID", "CLAUDE_CODE_SESSION_ID"]
        .into_iter()
        .find_map(|key| env.get(key).filter(|value| !value.is_empty()).cloned())
}

/// Live local Claude instances in this directory that no session id points at.
///
/// These are the plausible earlier identities of a session that exposes no id
/// of its own — the only useful thing to say when hcom cannot recognize it.
fn unbound_claude_candidates(db: &HcomDb, ctx: &HcomContext, exclude: &str) -> Vec<String> {
    let cwd = ctx.cwd.to_string_lossy();
    let mut rows: Vec<InstanceRow> = db
        .iter_instances_full()
        .unwrap_or_default()
        .into_iter()
        .filter(|row| {
            row.tool == "claude"
                && row.status != "stopped"
                && row.name != exclude
                && row.directory == cwd
                && row.session_id.is_none()
                && row.parent_name.is_none()
                && !crate::instances::is_remote_instance(row)
        })
        .collect();
    rows.sort_by(|a, b| b.created_at.total_cmp(&a.created_at));
    rows.truncate(4);
    rows.into_iter().map(|row| row.name).collect()
}

/// Path C: Bare start — detect tool or create adhoc instance.
fn start_bare(
    db: &HcomDb,
    hcom_dir: &std::path::Path,
    ctx: &HcomContext,
    explicit_name: Option<&str>,
) -> Result<i32> {
    let explicit_name = explicit_name
        .map(|name| identity::resolve_display_name(db, name).unwrap_or_else(|| name.to_string()));
    let explicit_name = explicit_name.as_deref();

    // A process already bound to a live seat is that seat. Binding it to a
    // second identity here would silently steal it — the valo incident, where
    // the live seat lost its process binding and a second row was minted for
    // the same process. Refuse before any write: no name is generated, no
    // placeholder or row is created, and the operator is told which seat holds
    // the process.
    if let Some(pid) = &ctx.process_id
        && let Some(owner) = db.live_process_binding_owner(pid)?
        && explicit_name != Some(owner.as_str())
    {
        bail!(
            "refusing to bind this process ({pid}) to a new identity: it is bound to live instance '{owner}'. \
             Use 'hcom start --as <name>' to rename '{owner}', or run 'hcom start' from a shell outside that seat."
        );
    }

    // Skip vanilla detection if --name is provided with an existing instance
    let has_valid_identity = explicit_name
        .and_then(|n| db.get_instance_full(n).ok().flatten())
        .is_some();

    // Vanilla tool detection: auto-install hooks for unmanaged AI tools.
    // Identity is already canonical on HcomContext, so route every released
    // hook-bearing integration through the typed Tool hook adapter. This keeps
    // bare `hcom start` aligned with `hcom hooks add` as integrations evolve.
    if !has_valid_identity && ctx.detect_vanilla_tool().is_some() {
        let vanilla_tool = ctx.tool;
        if !vanilla_tool.hooks().is_empty() && !vanilla_tool.verify_hooks_installed(false) {
            println!("Installing {} hooks...", vanilla_tool.as_str());
            let include_perms = crate::config::load_config_snapshot().core.auto_approve;
            match vanilla_tool.try_setup_hooks(include_perms) {
                Ok(()) => {
                    println!(
                        "\nRestart {} to enable automatic message delivery.",
                        vanilla_tool.spec().label
                    );
                    println!("Then run: hcom start");
                }
                Err(error) if error.is_empty() => {
                    eprintln!(
                        "Failed to install hooks. Run: hcom hooks add {}",
                        vanilla_tool.as_str()
                    );
                }
                Err(error) => {
                    eprintln!(
                        "Failed to install {} hooks: {error}\nRun: hcom hooks add {}",
                        vanilla_tool.as_str(),
                        vanilla_tool.as_str()
                    );
                }
            }
            return Ok(1);
        }

        // Gemini: ensure hooksConfig.enabled is set (self-heal for v0.26.0+)
        if vanilla_tool == crate::tool::Tool::Gemini {
            let _ = crate::hooks::gemini::ensure_hooks_enabled();
        }
    }

    let tool = ctx.tool.as_str();
    let claude_session_id = (ctx.tool == crate::tool::Tool::Claude)
        .then(|| resolve_claude_session_id(&ctx.raw_env))
        .flatten();

    if explicit_name.is_none()
        && let Some(ref session_id) = claude_session_id
        && let Some(bound_name) = db.get_session_binding(session_id)?
    {
        // Only hcom writes session bindings, so a row keyed by this session's
        // own id is trusted identity evidence. Heal bindings created by older
        // versions before returning the existing row.
        db.mark_claude_session_validated(session_id, &bound_name)?;
        println!("hcom already started for {bound_name}");
        return Ok(0);
    }

    // Resolve or generate name
    let name = if let Some(n) = explicit_name {
        n.to_string()
    } else {
        instance_names::generate_unique_name(db)?
    };

    // Remote instances are relay mirrors. Starting them remotely is intentionally
    // unsupported because the useful remote lifecycle operations are launch/resume/kill.
    if let Ok(Some(ref existing)) = db.get_instance_full(&name)
        && crate::instances::is_remote_instance(existing)
    {
        bail!("Remote start is not supported for '{name}'. Start it on the owning device instead.");
    }

    // Check if already exists and active (only for explicit names —
    // generate_unique_name creates a placeholder row we must skip past)
    if explicit_name.is_some()
        && let Ok(Some(existing)) = db.get_instance_full(&name)
        && existing.status != "stopped"
    {
        println!("hcom already started for {}", name);
        return Ok(0);
    }

    instance_binding::initialize_instance_in_position_file(
        db,
        &name,
        claude_session_id.as_deref(),
        None, // parent_session_id
        None, // parent_name
        None, // agent_id
        None, // transcript_path
        Some(tool),
        false, // background
        None,  // tag
        None,  // wait_timeout
        None,  // subagent_timeout
        None,  // hints
        None,  // cwd_override
    );

    if let Some(ref session_id) = claude_session_id {
        db.set_session_binding(session_id, &name)?;
        db.mark_claude_session_validated(session_id, &name)?;
    }

    // Bind process if we have a process_id
    if let Some(ref process_id) = ctx.process_id
        && let Err(e) = db.set_process_binding(process_id, "", &name)
    {
        eprintln!("[hcom] warn: set_process_binding failed for {name}: {e}");
    }

    // Claude builds old enough to expose neither session id leave nothing to
    // recognize this session by, so a later `hcom start` here mints another
    // identity. Say what was just created and name the way back instead of
    // letting the duplicate appear silently.
    if explicit_name.is_none()
        && ctx.tool == crate::tool::Tool::Claude
        && claude_session_id.is_none()
    {
        let candidates = unbound_claude_candidates(db, ctx, &name);
        eprintln!(
            "[hcom] warn: this Claude session exposes no session id, so it was registered \
             as a new identity '{name}'. If it already had one{}, reclaim it with \
             `hcom start --as <name>` and drop this one with `hcom kill {name}`.",
            if candidates.is_empty() {
                String::new()
            } else {
                format!(" (unbound here: {})", candidates.join(", "))
            }
        );
    }

    // Print bootstrap
    let hcom_config = HcomConfig::load(None).unwrap_or_else(|e| {
        eprintln!("[hcom] warn: config load failed, using defaults: {e}");
        let mut c = HcomConfig::default();
        c.normalize();
        c
    });

    let bootstrap_text = bootstrap::get_bootstrap(
        db,
        hcom_dir,
        &name,
        tool,
        false,
        ctx.is_launched,
        &ctx.notes,
        &hcom_config.tag,
        relay::is_relay_enabled(&hcom_config),
        None,
    );

    println!("[hcom:{}]", name);
    println!("{}", bootstrap_text);
    // Repeated deliberately: the header above sits on top of a long bootstrap, so
    // `hcom start | tail -n` shows none of it. A caller that cannot see its own
    // name re-runs start, which is one way duplicate identities appear.
    println!("[hcom:{}]", name);

    // Log
    db.log_event(
        "life",
        &name,
        &json!({
            "action": "started",
            "tool": tool,
            "name": name,
        }),
    )
    .ok();

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use rusqlite::params;
    use serde_json::json;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_ctx(tool_env: &[(&str, &str)], cwd: &str) -> HcomContext {
        let mut env: HashMap<String, String> = std::env::vars().collect();
        // OMP session markers beat CLAUDECODE in tool detection (see
        // tool_detection::OMP_NATIVE): strip them so an ambient OMP shell
        // cannot decide these tests' tool.
        env.remove("HCOM_OMP");
        env.remove("OMPCODE");
        for (k, v) in tool_env {
            env.insert((*k).to_string(), (*v).to_string());
        }
        HcomContext::from_env(&env, PathBuf::from(cwd))
    }

    /// Claude context carrying exactly one session-id source, so an ambient
    /// value from the shell running the tests cannot decide the outcome. The
    /// OMP session markers go too: they beat CLAUDECODE in tool detection.
    fn make_claude_ctx(session: Option<(&str, &str)>, cwd: &str) -> HcomContext {
        let mut env: HashMap<String, String> = std::env::vars().collect();
        env.remove("HCOM_CLAUDE_UNIX_SESSION_ID");
        env.remove("CLAUDE_CODE_SESSION_ID");
        env.remove("HCOM_OMP");
        env.remove("OMPCODE");
        env.insert("CLAUDECODE".to_string(), "1".to_string());
        if let Some((key, value)) = session {
            env.insert(key.to_string(), value.to_string());
        }
        HcomContext::from_env(&env, PathBuf::from(cwd))
    }

    fn log_stopped_snapshot(
        db: &HcomDb,
        name: &str,
        tool: &str,
        directory: &str,
        session_id: &str,
        last_event_id: i64,
    ) {
        db.log_event(
            "life",
            name,
            &json!({
                "action": "stopped",
                "snapshot": {
                    "tool": tool,
                    "directory": directory,
                    "session_id": session_id,
                    "last_event_id": last_event_id
                }
            }),
        )
        .unwrap();
    }
    #[test]
    fn test_start_args_bare() {
        let args = StartArgs::try_parse_from(["start"]).unwrap();
        assert!(args.orphan.is_none());
        assert!(args.as_name.is_none());
    }

    #[test]
    fn test_start_args_orphan() {
        let args = StartArgs::try_parse_from(["start", "--orphan", "1234"]).unwrap();
        assert_eq!(args.orphan, Some("1234".to_string()));
        assert!(args.as_name.is_none());
    }

    #[test]
    fn test_start_args_rebind() {
        let args = StartArgs::try_parse_from(["start", "--as", "luna"]).unwrap();
        assert!(args.orphan.is_none());
        assert_eq!(args.as_name, Some("luna".to_string()));
    }

    #[test]
    fn test_start_args_bare_as_errors() {
        let err = StartArgs::try_parse_from(["start", "--as"]);
        assert!(err.is_err());
    }

    #[test]
    fn test_start_args_bare_orphan_errors() {
        let err = StartArgs::try_parse_from(["start", "--orphan"]);
        assert!(err.is_err());
    }

    #[test]
    fn test_start_args_unknown_flag_errors() {
        let err = StartArgs::try_parse_from(["start", "--bogus"]);
        assert!(err.is_err());
    }

    #[test]
    #[serial]
    fn test_start_rejects_remote_instances() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances (name, origin_device_id, created_at) VALUES (?1, ?2, ?3)",
                params![
                    "luna:ABCD",
                    "remote-device",
                    crate::shared::time::now_epoch_f64()
                ],
            )
            .unwrap();

        let flags = crate::router::GlobalFlags {
            name: Some("luna:ABCD".to_string()),
            go: false,
        };
        let err = run(&["start".to_string()], &flags).unwrap_err();
        assert!(
            err.to_string().contains("Remote start is not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    #[serial]
    fn test_vanilla_claude_start_immediately_binds_exported_session() {
        struct RestoreEnv(Option<std::ffi::OsString>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                unsafe {
                    match self.0.take() {
                        Some(value) => std::env::set_var("HCOM_CLAUDE_UNIX_SESSION_ID", value),
                        None => std::env::remove_var("HCOM_CLAUDE_UNIX_SESSION_ID"),
                    }
                }
            }
        }

        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        assert!(crate::hooks::claude::setup_claude_hooks(false));

        let _restore = RestoreEnv(std::env::var_os("HCOM_CLAUDE_UNIX_SESSION_ID"));
        unsafe {
            std::env::set_var("HCOM_CLAUDE_UNIX_SESSION_ID", "sess-vanilla");
        }
        let ctx = make_ctx(&[("CLAUDECODE", "1")], "/tmp/project");

        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        let name = db
            .get_session_binding("sess-vanilla")
            .unwrap()
            .expect("bare vanilla start must bind immediately");
        let row = db.get_instance_full(&name).unwrap().unwrap();
        assert_eq!(row.session_id.as_deref(), Some("sess-vanilla"));
        assert_eq!(row.tool, "claude");
        assert_eq!(
            db.get_validated_claude_session_owner("sess-vanilla")
                .unwrap()
                .as_deref(),
            Some(name.as_str()),
            "CLI-created Claude bindings must be immediately trusted by hooks"
        );

        let transcript = hcom_dir.join("vanilla.jsonl");
        std::fs::write(&transcript, "{\"sessionId\":\"sess-vanilla\"}\n").unwrap();
        let mut hook_ctx = ctx.clone();
        hook_ctx.process_id = None;
        let (resolved, _, _) = crate::hooks::common::init_hook_context(
            &db,
            &hook_ctx,
            "sess-vanilla",
            transcript.to_str().unwrap(),
        );
        assert_eq!(resolved.as_deref(), Some(name.as_str()));

        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        assert_eq!(
            db.get_session_binding("sess-vanilla").unwrap().as_deref(),
            Some(name.as_str()),
            "repeated bare start must retain the existing vanilla identity"
        );
    }

    #[test]
    fn test_resolve_claude_session_id_sources() {
        let env = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect()
        };

        assert_eq!(
            resolve_claude_session_id(&env(&[
                ("HCOM_CLAUDE_UNIX_SESSION_ID", "hook-sess"),
                ("CLAUDE_CODE_SESSION_ID", "claude-sess"),
            ])),
            Some("hook-sess".to_string()),
            "our own export stays the first source"
        );
        assert_eq!(
            resolve_claude_session_id(&env(&[("CLAUDE_CODE_SESSION_ID", "claude-sess")])),
            Some("claude-sess".to_string()),
            "Claude's own Bash env carries identity when the env file cannot"
        );
        assert_eq!(
            resolve_claude_session_id(&env(&[
                ("HCOM_CLAUDE_UNIX_SESSION_ID", ""),
                ("CLAUDE_CODE_SESSION_ID", "claude-sess"),
            ])),
            Some("claude-sess".to_string()),
            "an empty export is not identity"
        );
        assert_eq!(resolve_claude_session_id(&env(&[])), None);
    }

    #[test]
    #[serial]
    fn test_vanilla_claude_start_reuses_claude_code_session_id() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        assert!(crate::hooks::claude::setup_claude_hooks(false));

        // No CLAUDE_ENV_FILE round trip, so HCOM_CLAUDE_UNIX_SESSION_ID never
        // arrives — the case that used to mint a second identity per start.
        let ctx = make_claude_ctx(
            Some(("CLAUDE_CODE_SESSION_ID", "sess-claude-env")),
            "/tmp/project",
        );

        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        let name = db
            .get_session_binding("sess-claude-env")
            .unwrap()
            .expect("CLAUDE_CODE_SESSION_ID must bind identity");
        assert_eq!(
            db.get_validated_claude_session_owner("sess-claude-env")
                .unwrap()
                .as_deref(),
            Some(name.as_str()),
            "hooks must trust the binding the CLI just created"
        );

        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        assert_eq!(
            db.get_session_binding("sess-claude-env")
                .unwrap()
                .as_deref(),
            Some(name.as_str()),
            "repeat start must return the first identity, not mint a second"
        );
        let claude_rows: Vec<String> = db
            .iter_instances_full()
            .unwrap()
            .into_iter()
            .filter(|row| row.tool == "claude")
            .map(|row| row.name)
            .collect();
        assert_eq!(claude_rows, vec![name], "exactly one identity per session");
    }

    #[test]
    #[serial]
    fn test_vanilla_claude_rebind_binds_session_and_drops_old_identity() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        assert!(crate::hooks::claude::setup_claude_hooks(false));

        let ctx = make_claude_ctx(
            Some(("CLAUDE_CODE_SESSION_ID", "sess-rebind")),
            "/tmp/project",
        );
        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        let first = db.get_session_binding("sess-rebind").unwrap().unwrap();
        // The first start draws its name at random and "nova" is one of the
        // likeliest draws; reclaiming the drawn name would rebind to itself.
        let target = if first == "nova" { "luna" } else { "nova" };
        // Reclaim means the name existed: a never-seen name is refused.
        log_stopped_snapshot(&db, target, "claude", "/tmp/project", "sess-old", 0);

        assert_eq!(start_rebind(&db, target, &ctx, None, None).unwrap(), 0);
        assert_eq!(
            db.get_session_binding("sess-rebind").unwrap().as_deref(),
            Some(target),
            "a reclaimed name must own the session that reclaimed it"
        );
        assert!(
            db.get_instance_full(&first).unwrap().is_none(),
            "the identity being replaced must not be left behind"
        );
        assert_eq!(
            db.get_validated_claude_session_owner("sess-rebind")
                .unwrap()
                .as_deref(),
            Some(target),
            "hooks must resolve the reclaimed name, not reject the session"
        );

        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        assert_eq!(
            db.get_session_binding("sess-rebind").unwrap().as_deref(),
            Some(target),
            "a start after the rebind returns the reclaimed identity"
        );
    }

    #[test]
    #[serial]
    fn test_unidentifiable_claude_start_lists_unbound_candidates() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        assert!(crate::hooks::claude::setup_claude_hooks(false));

        let cwd = std::env::current_dir().unwrap();
        let ctx = make_claude_ctx(None, cwd.to_str().unwrap());

        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        let first = db
            .iter_instances_full()
            .unwrap()
            .into_iter()
            .find(|row| row.tool == "claude")
            .expect("first start creates an identity")
            .name;
        assert!(
            db.get_instance_full(&first)
                .unwrap()
                .unwrap()
                .session_id
                .is_none(),
            "a session with no id leaves the row unbound"
        );

        // Without any session id hcom still cannot recognize the session, so the
        // second start mints another identity — the warning names this one back.
        assert_eq!(start_bare(&db, &hcom_dir, &ctx, None).unwrap(), 0);
        let second = db
            .iter_instances_full()
            .unwrap()
            .into_iter()
            .find(|row| row.tool == "claude" && row.name != first)
            .expect("second start mints a second identity")
            .name;
        assert_eq!(
            unbound_claude_candidates(&db, &ctx, &second),
            vec![first],
            "the earlier unbound identity is the reclaim candidate"
        );
    }

    #[test]
    #[serial]
    fn test_root_rebind_preserves_child_hierarchy_and_actor_state() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();

        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, tool, status, status_time, last_seen, created_at)
                 VALUES ('nova', 'sess-1', 'claude', 'active', 0, 0, 0)",
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, parent_session_id, parent_name, agent_id, tool, status,
                  status_time, last_seen, created_at)
                 VALUES ('nova_task_1', 'sess-1', 'nova', 'agent-1', 'claude',
                         'active', 0, 0, 0)",
                [],
            )
            .unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, parent_session_id, parent_name, agent_id, tool, status,
                  status_time, last_seen, created_at)
                 VALUES ('nova_task_2', 'sess-1', 'nova_task_1', 'agent-2', 'claude',
                         'active', 0, 0, 0)",
                [],
            )
            .unwrap();

        let token = db
            .issue_claude_actor_capability("sess-1", "tool-root", None, "nova")
            .unwrap();

        let links = snapshot_child_links(&db, Some("sess-1")).unwrap();
        assert_eq!(links.len(), 2);
        db.delete_instance("nova").unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, tool, status, status_time, last_seen, created_at)
                 VALUES ('sol', 'sess-1', 'claude', 'active', 0, 0, 0)",
                [],
            )
            .unwrap();

        restore_child_links_after_root_rebind(&db, &links, "sess-1", "nova", "sol").unwrap();
        db.rebind_claude_root_actor_state("sess-1", "nova", "sol")
            .unwrap();

        let direct = db.get_instance_full("nova_task_1").unwrap().unwrap();
        assert_eq!(direct.parent_session_id.as_deref(), Some("sess-1"));
        assert_eq!(direct.parent_name.as_deref(), Some("sol"));
        let nested = db.get_instance_full("nova_task_2").unwrap().unwrap();
        assert_eq!(nested.parent_session_id.as_deref(), Some("sess-1"));
        assert_eq!(nested.parent_name.as_deref(), Some("nova_task_1"));
        assert_eq!(
            db.resolve_claude_actor_capability(&token, "sess-1")
                .unwrap(),
            Some("sol".to_string())
        );
    }

    #[test]
    #[serial]
    fn test_same_name_root_rebind_restores_child_session_links() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, tool, directory, status, status_time, last_seen, created_at)
                 VALUES ('nova', 'sess-1', 'claude', '/tmp/project', 'active', 0, 0, 1)",
                [],
            )
            .unwrap();
        db.set_session_binding("sess-1", "nova").unwrap();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, parent_session_id, parent_name, agent_id, tool, status,
                  status_time, last_seen, created_at)
                 VALUES ('nova_task_1', 'sess-1', 'nova', 'agent-1', 'claude',
                         'active', 0, 0, 2)",
                [],
            )
            .unwrap();
        let token = db
            .issue_claude_actor_capability("sess-1", "tool-child", Some("agent-1"), "nova_task_1")
            .unwrap();

        let ctx = make_ctx(&[("CLAUDECODE", "1")], "/tmp/project");
        assert_eq!(
            start_rebind(&db, "nova", &ctx, Some("nova"), None).unwrap(),
            0
        );

        let child = db.get_instance_full("nova_task_1").unwrap().unwrap();
        assert_eq!(child.parent_session_id.as_deref(), Some("sess-1"));
        assert_eq!(child.parent_name.as_deref(), Some("nova"));
        assert_eq!(
            db.resolve_claude_actor_capability(&token, "sess-1")
                .unwrap(),
            Some("nova_task_1".to_string())
        );
    }

    #[test]
    #[serial]
    fn test_start_rebind_rejects_cross_tool_stopped_snapshot_hijack() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();

        log_stopped_snapshot(
            &db,
            "fama",
            "codex",
            "/tmp/dasha-code/.worktrees/layer1-basic-conversation-fixes",
            "sid-fama",
            42,
        );

        let ctx = make_ctx(
            &[("CLAUDECODE", "1")],
            "/tmp/hcom-gan-harness/.worktrees/bench-infra",
        );

        let err = start_rebind(&db, "fama", &ctx, None, None).unwrap_err();
        assert!(
            err.to_string().contains("Refusing to reclaim 'fama'"),
            "unexpected error: {err}"
        );

        assert!(db.get_instance_full("fama").unwrap().is_none());
        assert_eq!(db.get_session_binding("sid-fama").unwrap(), None);
    }

    #[test]
    #[serial]
    fn test_start_rebind_allows_matching_stopped_snapshot_reclaim() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();

        log_stopped_snapshot(
            &db,
            "nova",
            "claude",
            "/tmp/dasha-code/.worktrees/layer1-basic-conversation-fixes",
            "sid-nova",
            77,
        );

        let ctx = make_ctx(
            &[("CLAUDECODE", "1")],
            "/tmp/dasha-code/.worktrees/layer1-basic-conversation-fixes",
        );

        let exit_code = start_rebind(&db, "nova", &ctx, None, None).unwrap();
        assert_eq!(exit_code, 0);

        let inst = db.get_instance_full("nova").unwrap().unwrap();
        assert_eq!(inst.tool, "claude");
        assert_eq!(
            inst.directory,
            "/tmp/dasha-code/.worktrees/layer1-basic-conversation-fixes"
        );
        assert_eq!(inst.last_event_id, 77);
    }

    #[test]
    #[serial]
    fn test_start_rebind_rejects_cross_directory_stopped_snapshot_hijack() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();

        log_stopped_snapshot(
            &db,
            "mira",
            "claude",
            "/tmp/dasha-code/.worktrees/layer1-basic-conversation-fixes",
            "sid-mira",
            18,
        );

        let ctx = make_ctx(
            &[("CLAUDECODE", "1")],
            "/tmp/hcom-gan-harness/.worktrees/bench-infra",
        );

        let err = start_rebind(&db, "mira", &ctx, None, None).unwrap_err();
        assert!(
            err.to_string().contains("Refusing to reclaim 'mira'"),
            "unexpected error: {err}"
        );

        assert!(db.get_instance_full("mira").unwrap().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn test_same_path_resolves_symlink_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let alias = dir.path().join("alias");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &alias).unwrap();

        assert!(same_path(
            real.to_string_lossy().as_ref(),
            alias.to_string_lossy().as_ref()
        ));
    }

    #[cfg(unix)]
    fn spawn_named_sleeper(name: &str) -> std::process::Child {
        std::process::Command::new("sleep")
            .arg("60")
            .env("HCOM_INSTANCE_NAME", name)
            .env_remove("HCOM_PROCESS_ID")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn sleep")
    }

    #[cfg(unix)]
    fn wait_for_carrier(name: &str, pid: u32) {
        for _ in 0..50 {
            if crate::proctruth::processes_for_instance(name, &[], &[])
                .iter()
                .any(|m| m.pid == pid)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("sleeper {pid} never enumerated under {name}");
    }
    #[cfg(unix)]
    fn insert_live_row(db: &HcomDb, name: &str, tool: &str, directory: &str) {
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, tool, directory, status, status_time, last_seen, created_at)
                 VALUES (?1, ?2, ?3, 'active', 0, 0, ?4)",
                params![name, tool, directory, now],
            )
            .unwrap();
    }

    /// Self-claim past the gate: the caller's identity facts match the
    /// target's carriers and only its own tree is alive, so the rebind
    /// proceeds — the uniform self-tree rule in
    /// `proctruth::check_spawn_allowed`, no short-circuit here.
    #[test]
    #[serial]
    #[cfg(unix)]
    fn test_start_rebind_self_identity_tree_rebinds() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("hcom-start-self-{}", std::process::id());
        let cwd = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let _identity = CallerIdentityEnv::pose(Some(&target), None);
        let ctx = make_ctx(&[("CLAUDECODE", "1")], &cwd);
        insert_live_row(&db, &target, ctx.tool.as_str(), &cwd);

        let mut sleeper = spawn_named_sleeper(&target);
        let spid = sleeper.id();
        wait_for_carrier(&target, spid);

        assert_eq!(start_rebind(&db, &target, &ctx, None, None).unwrap(), 0);
        assert!(
            db.get_instance_full(&target).unwrap().is_some(),
            "self-claim re-creates the target row"
        );

        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    /// Foreign callers still refuse: same live carrier, but the caller
    /// matches neither the env name nor the newest binding.
    #[test]
    #[serial]
    #[cfg(unix)]
    fn test_start_rebind_foreign_still_refuses_live_holder() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("hcom-start-foreign-{}", std::process::id());
        let cwd = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let _identity = CallerIdentityEnv::pose(None, None);
        let ctx = make_ctx(&[("CLAUDECODE", "1")], &cwd);
        insert_live_row(&db, &target, ctx.tool.as_str(), &cwd);

        let mut sleeper = spawn_named_sleeper(&target);
        let spid = sleeper.id();
        wait_for_carrier(&target, spid);

        let err = start_rebind(&db, &target, &ctx, None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("refusing to spawn under '{target}'")),
            "foreign gate refusal unchanged, got: {err}"
        );
        assert!(
            err.to_string().contains(&format!("hcom kill {target}")),
            "foreign gate refusal unchanged, got: {err}"
        );
        assert!(
            db.get_instance_full(&target).unwrap().is_some(),
            "refused rebind leaves the target row alone"
        );

        sleeper.kill().ok();
        sleeper.wait().ok();
    }

    /// Poses the caller's identity env — the spawn gate reads these two from
    /// the live env — and restores whatever was there on drop.
    #[cfg(unix)]
    struct CallerIdentityEnv(Option<std::ffi::OsString>, Option<std::ffi::OsString>);

    #[cfg(unix)]
    impl CallerIdentityEnv {
        fn pose(instance_name: Option<&str>, process_id: Option<&str>) -> Self {
            let saved = (
                std::env::var_os("HCOM_INSTANCE_NAME"),
                std::env::var_os("HCOM_PROCESS_ID"),
            );
            unsafe {
                match instance_name {
                    Some(v) => std::env::set_var("HCOM_INSTANCE_NAME", v),
                    None => std::env::remove_var("HCOM_INSTANCE_NAME"),
                }
                match process_id {
                    Some(v) => std::env::set_var("HCOM_PROCESS_ID", v),
                    None => std::env::remove_var("HCOM_PROCESS_ID"),
                }
            }
            Self(saved.0, saved.1)
        }
    }

    #[cfg(unix)]
    impl Drop for CallerIdentityEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.0 {
                    Some(v) => std::env::set_var("HCOM_INSTANCE_NAME", v),
                    None => std::env::remove_var("HCOM_INSTANCE_NAME"),
                }
                match &self.1 {
                    Some(v) => std::env::set_var("HCOM_PROCESS_ID", v),
                    None => std::env::remove_var("HCOM_PROCESS_ID"),
                }
            }
        }
    }

    #[cfg(unix)]
    fn rand_suffix() -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut h);
        std::thread::current().id().hash(&mut h);
        (h.finish() % 900000) as u32 + 100000
    }

    /// A name-carrying orphan in a tree of its own: `sh` spawns it in the
    /// background and exits, so the sleeper is reparented to init — its ppid
    /// chain never passes through the test process. Not our child: kill it
    /// with `libc::kill`.
    #[cfg(unix)]
    fn spawn_detached_named_sleeper(name: &str, process_id: &str) -> u32 {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 300 >/dev/null 2>&1 & echo $!")
            .env("HCOM_INSTANCE_NAME", name)
            .env("HCOM_PROCESS_ID", process_id)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .expect("spawn detached sleeper");
        String::from_utf8_lossy(&out.stdout)
            .trim()
            .parse()
            .expect("detached sleeper pid")
    }

    #[cfg(unix)]
    fn backdate_binding(db: &HcomDb, process_id: &str, updated_at: f64) {
        db.conn()
            .execute(
                "UPDATE process_bindings SET updated_at = ?1 WHERE process_id = ?2",
                params![updated_at, process_id],
            )
            .unwrap();
    }

    /// Blocker-A regression: the caller matches the target's newest binding,
    /// but a pre-binding orphan (name-carrying, started before the binding)
    /// is alive in a separate tree. The rebind must refuse with the orphan
    /// classification — reclaiming the name would leave that process alive
    /// under the reclaimed identity.
    #[test]
    #[serial]
    #[cfg(unix)]
    fn test_start_rebind_refuses_pre_binding_orphan_outside_caller_tree() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("hcom-start-orphan-{}", std::process::id());
        let cwd = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let orphan = spawn_detached_named_sleeper(&target, &format!("proc-old-{}", rand_suffix()));
        wait_for_carrier(&target, orphan);
        let start = crate::proctruth::processes_for_instance(&target, &[], &[])
            .into_iter()
            .find(|m| m.pid == orphan)
            .expect("detached orphan enumerated")
            .start_epoch;
        // The new harness binds AFTER the orphan started: the orphan predates
        // it and must refuse the reclaim.
        let binding = format!("proc-new-{}", rand_suffix());
        db.set_process_binding(&binding, "sess-orphan", &target)
            .unwrap();
        backdate_binding(&db, &binding, start + 3600.0);
        let _identity = CallerIdentityEnv::pose(None, Some(&binding));
        let ctx = make_ctx(&[("CLAUDECODE", "1")], &cwd);
        insert_live_row(&db, &target, ctx.tool.as_str(), &cwd);

        let err = start_rebind(&db, &target, &ctx, None, None).unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("refusing to spawn under '{target}'")),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("orphan"),
            "must refuse with the orphan classification: {err}"
        );
        assert!(
            db.get_instance_full(&target).unwrap().is_some(),
            "refused rebind leaves the target row alone"
        );
        assert_eq!(
            db.newest_process_binding(&target).unwrap().unwrap().0,
            binding,
            "refused rebind leaves the bindings alone"
        );
        unsafe {
            libc::kill(orphan as libc::pid_t, libc::SIGKILL);
        }
    }

    /// A caller bound to a live identity: row with a delivery cursor, plus
    /// its session and process bindings.
    fn bind_caller(db: &HcomDb, name: &str, sid: &str, process_id: &str, cursor: i64) {
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, session_id, tool, directory, last_event_id, status, status_time,
                  last_seen, created_at)
                 VALUES (?1, ?2, 'claude', '/tmp/project', ?3, 'active', 0, 0, 1)",
                params![name, sid, cursor],
            )
            .unwrap();
        db.set_session_binding(sid, name).unwrap();
        db.set_process_binding(process_id, sid, name).unwrap();
    }

    fn caller_ctx(process_id: &str) -> HcomContext {
        make_ctx(
            &[("CLAUDECODE", "1"), ("HCOM_PROCESS_ID", process_id)],
            "/tmp/project",
        )
    }

    /// The valo incident: a process holding identity A runs
    /// `start --as <never-seen>`. That is not a reclaim, so it must refuse and
    /// leave A's row and both bindings exactly as they were.
    #[test]
    #[serial]
    fn test_start_rebind_refuses_never_seen_name_from_bound_caller() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let caller = format!("stas_a_{}", std::process::id());
        let target = format!("stas_never_{}", std::process::id());
        bind_caller(&db, &caller, "sess-a", "proc-a", 42);

        let code = start_rebind(&db, &target, &caller_ctx("proc-a"), None, None).unwrap();

        assert_eq!(code, 1, "a never-seen name is not the caller's to reclaim");
        let row = db
            .get_instance_full(&caller)
            .unwrap()
            .expect("A's row kept");
        assert_eq!(row.session_id.as_deref(), Some("sess-a"));
        assert_eq!(row.last_event_id, 42);
        assert_eq!(
            db.get_session_binding("sess-a").unwrap().as_deref(),
            Some(caller.as_str())
        );
        assert_eq!(
            db.get_process_binding_full("proc-a").unwrap(),
            Some((Some("sess-a".to_string()), caller.clone()))
        );
        assert!(db.get_instance_full(&target).unwrap().is_none());
        assert!(!identity::has_life_history(&db, &target));
    }

    /// valo reclaiming valo after its row was renamed away: the name has life
    /// history, so the reclaim proceeds and takes both bindings. The cursor is
    /// valo's own: the identity it replaces read further, but messages to valo
    /// past valo's snapshot cursor are still unread.
    #[test]
    #[serial]
    fn test_start_rebind_reclaims_name_with_history_from_bound_caller() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let caller = format!("stas_fill_{}", std::process::id());
        let target = format!("stas_valo_{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", "sess-v", 100);
        bind_caller(&db, &caller, "sess-v", "proc-v", 900);

        let code = start_rebind(&db, &target, &caller_ctx("proc-v"), None, None).unwrap();

        assert_eq!(code, 0, "a name with history is reclaimable");
        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(
            row.last_event_id, 100,
            "the reclaimed name resumes at its own cursor, not the replaced identity's"
        );
        assert_eq!(
            db.get_session_binding("sess-v").unwrap().as_deref(),
            Some(target.as_str())
        );
        assert_eq!(
            db.get_process_binding_full("proc-v").unwrap(),
            Some((Some("sess-v".to_string()), target.clone()))
        );
        assert!(db.get_instance_full(&caller).unwrap().is_none());
    }

    /// Re-registering the identity the caller already holds keeps its live
    /// cursor: an older stopped snapshot of the same name never rewinds it.
    #[test]
    #[serial]
    fn test_start_rebind_same_name_keeps_live_cursor_over_old_snapshot() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let name = format!("stas_self_{}", std::process::id());
        log_stopped_snapshot(&db, &name, "claude", "/tmp/project", "sess-s", 100);
        bind_caller(&db, &name, "sess-s", "proc-s", 900);

        assert_eq!(
            start_rebind(&db, &name, &caller_ctx("proc-s"), None, None).unwrap(),
            0
        );

        let row = db.get_instance_full(&name).unwrap().expect("row kept");
        assert_eq!(row.last_event_id, 900);
    }

    /// A real rename writes the old name's stop: never a silent disappearance.
    #[test]
    #[serial]
    fn test_start_rebind_rename_logs_stopped_renamed_for_old_name() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let caller = format!("stas_old_{}", std::process::id());
        let target = format!("stas_new_{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", "sess-r", 7);
        bind_caller(&db, &caller, "sess-r", "proc-r", 9);

        assert_eq!(
            start_rebind(&db, &target, &caller_ctx("proc-r"), None, None).unwrap(),
            0
        );

        let data: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'life' AND instance = ?
                 ORDER BY id DESC LIMIT 1",
                params![caller],
                |row| row.get(0),
            )
            .expect("the renamed-away name has a life event");
        let life: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(life["action"], "stopped");
        assert_eq!(life["reason"], "renamed");
        assert_eq!(life["by"], caller.as_str());
        assert_eq!(life["renamed_to"], target.as_str());
        assert_eq!(life["snapshot"]["session_id"], "sess-r");
        assert_eq!(life["snapshot"]["last_event_id"], 9);
    }

    /// A competing reclaim commits the target row after this rebind planned
    /// and before it writes. The rebind must refuse with nothing written:
    /// the caller keeps its row, cursor, bindings and life history, and the
    /// competitor's row is untouched.
    #[test]
    #[serial]
    fn test_rebind_losing_race_leaves_caller_unchanged() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let caller = format!("race_caller_{}", std::process::id());
        let target = format!("race_target_{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", "sess-t", 100);
        bind_caller(&db, &caller, "sess-c", "proc-c", 500);
        fn competitor_commits_target(db: &HcomDb, name: &str) {
            db.conn()
                .execute(
                    "INSERT INTO instances
                     (name, session_id, tool, directory, last_event_id, status,
                      status_time, last_seen, created_at)
                     VALUES (?1, 'sess-other', 'claude', '/tmp/project', 7, 'active', 0, 0, 3)",
                    params![name],
                )
                .unwrap();
        }
        REBIND_CREATE_GAP_HOOK.with(|hook| hook.set(Some(competitor_commits_target)));

        let code = start_rebind(&db, &target, &caller_ctx("proc-c"), None, None).unwrap();
        REBIND_CREATE_GAP_HOOK.with(|hook| hook.set(None));

        let row = db
            .get_instance_full(&caller)
            .unwrap()
            .expect("the caller keeps its row");
        assert_eq!(code, 1, "the rebind that lost the race refuses");
        assert_eq!(row.session_id.as_deref(), Some("sess-c"));
        assert_eq!(row.last_event_id, 500);
        assert_eq!(
            db.get_session_binding("sess-c").unwrap().as_deref(),
            Some(caller.as_str())
        );
        assert_eq!(
            db.get_process_binding_full("proc-c").unwrap(),
            Some((Some("sess-c".to_string()), caller.clone()))
        );
        assert!(
            !identity::has_life_history(&db, &caller),
            "no rename was recorded"
        );
        let competitor = db
            .get_instance_full(&target)
            .unwrap()
            .expect("competitor's row");
        assert_eq!(competitor.session_id.as_deref(), Some("sess-other"));
        assert_eq!(competitor.last_event_id, 7);
    }

    /// A launcher id shape (8-4-4-4-12 lowercase hex): trusted only through a
    /// recorded ancestor pid.
    #[cfg(target_os = "linux")]
    const SEAT_UUID: &str = "5a1e0c3d-7b2f-4e8a-9c1d-0f2e3a4b5c6d";

    #[cfg(target_os = "linux")]
    fn stop_snapshot_for(pid: u32, start_time: u64, boot_id: &str) -> serde_json::Value {
        json!({
            "tool": "omp",
            "directory": "/tmp/project",
            "last_event_id": 0,
            "pid": pid,
            "pid_start_time": start_time,
            "boot_id": boot_id,
        })
    }

    /// A launcher seat whose row was lost reclaims its own name from inside
    /// itself: the trust gate refuses its launcher id first, exactly as in
    /// `run`. Returns the exit code and the stop snapshot's event id.
    #[cfg(target_os = "linux")]
    fn lost_seat_reclaim(db: &HcomDb, target: &str, snapshot: serde_json::Value) -> (i32, i64) {
        lost_seat_reclaim_recorded(db, target, snapshot, SEAT_UUID)
    }

    /// [`lost_seat_reclaim`] with the stop event recording `recorded_id` as
    /// the process id it released.
    #[cfg(target_os = "linux")]
    fn lost_seat_reclaim_recorded(
        db: &HcomDb,
        target: &str,
        snapshot: serde_json::Value,
        recorded_id: &str,
    ) -> (i32, i64) {
        let event_id = db
            .log_event(
                "life",
                target,
                &json!({
                    "action": "stopped",
                    "by": "daemon",
                    "reason": "vanished",
                    "process_id": recorded_id,
                    "snapshot": snapshot,
                }),
            )
            .unwrap();
        let mut ctx = make_ctx(
            &[("OMPCODE", "1"), ("HCOM_PROCESS_ID", SEAT_UUID)],
            "/tmp/project",
        );
        let presented = ctx.process_id.clone();
        ctx.trust_process_id(db);
        assert!(
            ctx.process_id.is_none(),
            "the lost seat's id starts refused"
        );
        let code = start_rebind(db, target, &ctx, None, presented.as_deref()).unwrap();
        (code, event_id)
    }

    /// The `anchor` record of the reclaim's life event for `target`.
    #[cfg(target_os = "linux")]
    fn reclaim_anchor_record(db: &HcomDb, target: &str) -> serde_json::Value {
        let data: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'life' AND instance = ?
                   AND json_extract(data, '$.reason') = 'reclaim'
                 ORDER BY id DESC LIMIT 1",
                params![target],
                |row| row.get(0),
            )
            .expect("the reclaim writes a life event");
        let life: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(life["action"], "started");
        life["anchor"].clone()
    }

    #[cfg(target_os = "linux")]
    fn parent_pid() -> u32 {
        // SAFETY: getppid has no preconditions and cannot fail.
        unsafe { libc::getppid() as u32 }
    }

    /// No anchor restored: the row stays pid-less, the refused id stays
    /// unbound and untrusted, and the life event says why.
    #[cfg(target_os = "linux")]
    fn assert_reclaimed_without_anchor(db: &HcomDb, target: &str, event_id: i64, why: &str) {
        let row = db
            .get_instance_full(target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(row.pid, None, "no verified anchor, no pid");
        assert_eq!(db.get_process_binding(SEAT_UUID).unwrap(), None);
        assert!(!crate::proctruth::trusted_process_id_for_omp(db, SEAT_UUID));
        let record = reclaim_anchor_record(db, target);
        assert_eq!(record["restored"], false);
        assert_eq!(record["snapshot_event_id"], event_id);
        let reason = record["reason"].as_str().unwrap();
        assert!(reason.contains(why), "reason {reason:?} lacks {why:?}");
    }

    /// valo's case: the snapshot's pid is a live ancestor, still the recorded
    /// incarnation, so the reclaim restores it, binds the refused launcher
    /// id behind it, and the trust gate then accepts that id.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_restores_verified_anchor_pid() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_ok_{}", std::process::id());
        let anchor = parent_pid();
        let (start_time, boot_id) = crate::sys::process::procfs_start_identity(anchor).unwrap();

        let (code, event_id) = lost_seat_reclaim(
            &db,
            &target,
            stop_snapshot_for(anchor, start_time, &boot_id),
        );

        assert_eq!(code, 0);
        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        // `hcom kill` targets through this pid (kill.rs bails without it).
        assert_eq!(row.pid, Some(i64::from(anchor)));
        assert_eq!(
            db.get_process_binding(SEAT_UUID).unwrap().as_deref(),
            Some(target.as_str())
        );
        assert!(
            crate::proctruth::trusted_process_id_for_omp(&db, SEAT_UUID),
            "the restored anchor proves the launcher id"
        );
        let record = reclaim_anchor_record(&db, &target);
        assert_eq!(record["restored"], true);
        assert_eq!(record["snapshot_event_id"], event_id);
        assert_eq!(record["pid"], anchor);
    }

    /// The refused id is another pid-less seat's binding: the anchor still
    /// restores for the target, but that seat keeps its binding and row.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_leaves_refused_id_bound_to_another_seat() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_claim_{}", std::process::id());
        let other = format!("anchor_holder_{}", std::process::id());
        bind_caller(&db, &other, "sess-holder", SEAT_UUID, 3);
        let anchor = parent_pid();
        let (start_time, boot_id) = crate::sys::process::procfs_start_identity(anchor).unwrap();

        let (code, _) = lost_seat_reclaim(
            &db,
            &target,
            stop_snapshot_for(anchor, start_time, &boot_id),
        );

        assert_eq!(code, 0);
        assert_eq!(
            db.get_process_binding(SEAT_UUID).unwrap().as_deref(),
            Some(other.as_str()),
            "another seat's binding is never taken"
        );
        assert!(db.get_instance_full(&other).unwrap().is_some());
        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(
            row.pid,
            Some(i64::from(anchor)),
            "the anchor itself still restores"
        );
    }

    /// The refused id is not the one the anchor's stop event released, so it
    /// has no history with that anchor and is not bound.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_refuses_id_other_than_snapshot_process_id() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_other_id_{}", std::process::id());
        let anchor = parent_pid();
        let (start_time, boot_id) = crate::sys::process::procfs_start_identity(anchor).unwrap();

        let (code, _) = lost_seat_reclaim_recorded(
            &db,
            &target,
            stop_snapshot_for(anchor, start_time, &boot_id),
            "0badc0de-0000-4000-8000-000000000000",
        );

        assert_eq!(code, 0);
        assert_eq!(db.get_process_binding(SEAT_UUID).unwrap(), None);
        assert!(!crate::proctruth::trusted_process_id_for_omp(
            &db, SEAT_UUID
        ));
    }

    /// Two reclaims of one name race: A recreates the row after B cleared
    /// it, before B recreates it. B must neither write its anchor onto A's
    /// row nor bind onto it; it refuses, and A's own restore still lands.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_refuses_row_a_concurrent_reclaim_created() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_race_{}", std::process::id());
        let anchor = parent_pid();
        let (start_time, boot_id) = crate::sys::process::procfs_start_identity(anchor).unwrap();
        /// Reclaim A's row: committed, its own anchor pid not yet written.
        fn concurrent_reclaim_creates_row(db: &HcomDb, name: &str) {
            db.conn()
                .execute(
                    "INSERT INTO instances
                     (name, tool, directory, last_event_id, status, status_time,
                      last_seen, created_at)
                     VALUES (?1, 'omp', '/tmp/project', 0, 'active', 0, 0, 2)",
                    params![name],
                )
                .unwrap();
        }
        REBIND_CREATE_GAP_HOOK.with(|hook| hook.set(Some(concurrent_reclaim_creates_row)));

        let (code, _) = lost_seat_reclaim(
            &db,
            &target,
            stop_snapshot_for(anchor, start_time, &boot_id),
        );
        REBIND_CREATE_GAP_HOOK.with(|hook| hook.set(None));

        let row = db.get_instance_full(&target).unwrap().expect("A's row");
        assert_eq!(row.pid, None, "B wrote its anchor onto A's row");
        assert_eq!(code, 1, "the reclaim that lost the race refuses");
        assert_eq!(db.get_process_binding(SEAT_UUID).unwrap(), None);
        // A's own restore still finds the row pid-less and lands its pid.
        let a_pid = std::process::id();
        assert!(db.set_instance_pid_if_unset(&target, a_pid).unwrap());
        let row = db.get_instance_full(&target).unwrap().expect("A's row");
        assert_eq!(row.pid, Some(i64::from(a_pid)));
    }

    /// Same pid, another incarnation: a reused pid must not become the anchor.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_refuses_anchor_with_other_start_time() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_start_{}", std::process::id());
        let anchor = parent_pid();
        let (start_time, boot_id) = crate::sys::process::procfs_start_identity(anchor).unwrap();

        let (code, event_id) = lost_seat_reclaim(
            &db,
            &target,
            stop_snapshot_for(anchor, start_time + 1, &boot_id),
        );

        assert_eq!(code, 0, "the reclaim still binds, without a pid");
        assert_reclaimed_without_anchor(&db, &target, event_id, "start time");
    }

    /// A start time recorded on another boot says nothing about this one.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_refuses_anchor_from_other_boot() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_boot_{}", std::process::id());
        let anchor = parent_pid();
        let (start_time, _) = crate::sys::process::procfs_start_identity(anchor).unwrap();

        let (code, event_id) = lost_seat_reclaim(
            &db,
            &target,
            stop_snapshot_for(anchor, start_time, "00000000-0000-0000-0000-000000000000"),
        );

        assert_eq!(code, 0);
        assert_reclaimed_without_anchor(&db, &target, event_id, "boot id");
    }

    /// A live process with the exact recorded identity that is not above the
    /// caller is somebody else's anchor.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_refuses_anchor_outside_caller_ancestry() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_foreign_{}", std::process::id());
        let mut sibling = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let (start_time, boot_id) =
            crate::sys::process::procfs_start_identity(sibling.id()).unwrap();

        let (code, event_id) = lost_seat_reclaim(
            &db,
            &target,
            stop_snapshot_for(sibling.id(), start_time, &boot_id),
        );
        sibling.kill().ok();
        sibling.wait().ok();

        assert_eq!(code, 0);
        assert_reclaimed_without_anchor(&db, &target, event_id, "not a live ancestor");
    }

    /// A snapshot written before stops recorded the anchor's incarnation
    /// carries a bare pid, which can never prove it.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_reclaim_refuses_bare_pid_from_older_snapshot() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("anchor_old_{}", std::process::id());

        let (code, event_id) = lost_seat_reclaim(
            &db,
            &target,
            json!({
                "tool": "omp",
                "directory": "/tmp/project",
                "last_event_id": 0,
                "pid": parent_pid(),
            }),
        );

        assert_eq!(code, 0);
        assert_reclaimed_without_anchor(&db, &target, event_id, "predates");
    }

    /// The rename stop records the renamed-away row's anchor incarnation.
    #[test]
    #[serial]
    #[cfg(target_os = "linux")]
    fn test_start_rebind_rename_snapshot_records_anchor_identity() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let caller = format!("anchor_old_name_{}", std::process::id());
        let target = format!("anchor_new_name_{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", "sess-an", 7);
        bind_caller(&db, &caller, "sess-an", "proc-an", 9);
        let pid = std::process::id();
        db.update_instance_pid(&caller, pid).unwrap();
        let (start_time, boot_id) = crate::sys::process::procfs_start_identity(pid).unwrap();

        assert_eq!(
            start_rebind(&db, &target, &caller_ctx("proc-an"), None, None).unwrap(),
            0
        );

        let data: String = db
            .conn()
            .query_row(
                "SELECT data FROM events WHERE type = 'life' AND instance = ?
                   AND json_extract(data, '$.reason') = 'renamed'",
                params![caller],
                |row| row.get(0),
            )
            .unwrap();
        let snapshot =
            serde_json::from_str::<serde_json::Value>(&data).unwrap()["snapshot"].clone();
        assert_eq!(snapshot["pid"], pid);
        assert_eq!(snapshot["pid_start_time"], start_time);
        assert_eq!(snapshot["boot_id"], boot_id.as_str());
    }

    /// The valo incident, bare form: a shell inside a live seat runs
    /// `hcom start`. Its process is already bound to that seat, so the bind at
    /// the end of `start_bare` would move the binding to a brand-new identity
    /// and leave the seat a running row with no process. Refuse before any
    /// write: no name is drawn, no row appears, and the binding stays put.
    #[test]
    #[serial]
    fn test_start_bare_refuses_process_bound_to_live_instance() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let owner = format!("valo_bare_{}", std::process::id());
        let process_id = format!("omp-bare-{}", std::process::id());
        bind_caller(&db, &owner, "sess-bare", &process_id, 11);

        let err = start_bare(&db, &hcom_dir, &caller_ctx(&process_id), None)
            .expect_err("a process bound to a live seat is not a fresh seat");

        assert!(
            err.to_string().contains(&owner) && err.to_string().contains(&process_id),
            "the refusal names the owning seat and the process: {err}"
        );
        assert_eq!(
            db.get_process_binding(&process_id).unwrap().as_deref(),
            Some(owner.as_str()),
            "the live seat keeps its process binding"
        );
        let rows: Vec<String> = db
            .iter_instances_full()
            .unwrap()
            .into_iter()
            .map(|row| row.name)
            .collect();
        assert_eq!(
            rows,
            vec![owner.clone()],
            "no second identity is minted for the same process"
        );
    }

    /// The same seat asking for a different identity by name: the explicit
    /// name names a row that does not exist, so the existing
    /// "already started" path cannot catch it. Still a theft.
    #[test]
    #[serial]
    fn test_start_bare_refuses_explicit_name_from_bound_live_seat() {
        let (_dir, hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let owner = format!("valo_named_{}", std::process::id());
        let wanted = format!("meme_named_{}", std::process::id());
        let process_id = format!("omp-named-{}", std::process::id());
        bind_caller(&db, &owner, "sess-named", &process_id, 11);

        let err = start_bare(&db, &hcom_dir, &caller_ctx(&process_id), Some(&wanted))
            .expect_err("a bound process cannot be given a second identity");

        assert!(
            err.to_string().contains(&owner),
            "the refusal names the owning seat: {err}"
        );
        assert!(
            db.get_instance_full(&wanted).unwrap().is_none(),
            "the refused start creates no row for the name it asked for"
        );
        assert_eq!(
            db.get_process_binding(&process_id).unwrap().as_deref(),
            Some(owner.as_str()),
            "the live seat keeps its process binding"
        );
    }

    /// `hcom start --as <target>` from a shell whose process belongs to a
    /// third live seat. The reclaim may not take that process binding: the
    /// seat that holds it is running, and the whole transaction rolls back
    /// with the target name still unclaimed.
    #[test]
    #[serial]
    fn test_start_rebind_refuses_process_bound_to_another_live_seat() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("valo_third_{}", std::process::id());
        let third = format!("meme_third_{}", std::process::id());
        let process_id = format!("omp-third-{}", std::process::id());
        log_stopped_snapshot(&db, &target, "omp", "/tmp/project", "sess-third", 3);
        // A plain seat binds its process with no session id, so nothing in the
        // reclaim resolves to the third seat as the caller's own identity.
        db.conn()
            .execute(
                "INSERT INTO instances
                 (name, tool, directory, status, status_time, last_seen, created_at)
                 VALUES (?1, 'omp', '/tmp/project', 'active', 0, 0, 1)",
                params![third],
            )
            .unwrap();
        db.set_process_binding(&process_id, "", &third).unwrap();

        let ctx = make_ctx(
            &[("OMPCODE", "1"), ("HCOM_PROCESS_ID", &process_id)],
            "/tmp/project",
        );
        let err = start_rebind(&db, &target, &ctx, None, None)
            .expect_err("a process bound to another live seat is not the caller's to rebind");

        assert!(
            err.to_string().contains(&third),
            "the refusal names the seat that holds the process: {err}"
        );
        assert_eq!(
            db.get_process_binding(&process_id).unwrap().as_deref(),
            Some(third.as_str()),
            "the third seat keeps its process binding"
        );
        assert!(
            db.get_instance_full(&target).unwrap().is_none(),
            "the refused reclaim creates no target row"
        );
        assert!(
            db.get_instance_full(&third).unwrap().is_some(),
            "the third seat's row is untouched"
        );
    }

    /// F5: reclaiming a stopped identity from a shell with no session id of
    /// its own must not leave the recreated row session-less. The stopped
    /// snapshot is the only durable record of the session the reclaimed
    /// identity's hook traffic is keyed by, so the rebind adopts it.
    #[test]
    #[serial]
    fn test_start_rebind_adopts_stopped_snapshot_session_id() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("valo_adopt_{}", std::process::id());
        let session_id = format!("sid-adopt-{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", &session_id, 3);
        let mut ctx = make_claude_ctx(None, "/tmp/project");
        ctx.process_id = None;

        assert_eq!(start_rebind(&db, &target, &ctx, None, None).unwrap(), 0);

        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(
            row.session_id.as_deref(),
            Some(session_id.as_str()),
            "the recreated row is born with the session its identity held"
        );
        assert_eq!(
            db.get_session_binding(&session_id).unwrap().as_deref(),
            Some(target.as_str())
        );
    }

    /// A reclaim resumes the identity from its stopped snapshot even when
    /// later life events (here failed relaunches) followed the stop: the
    /// cursor is the snapshot's, never the current maximum, so a message sent
    /// while the identity was stopped is still pending; and the adopted
    /// session keeps the transcript recorded beside it.
    #[test]
    #[serial]
    fn test_start_rebind_restores_snapshot_cursor_and_transcript_behind_later_life_events() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("valo_cursor_{}", std::process::id());
        let session_id = format!("sid-cursor-{}", std::process::id());
        let transcript = format!("/tmp/project/{session_id}.jsonl");
        let broadcast = |text: &str| {
            db.log_event(
                "message",
                "nova",
                &json!({"from": "nova", "scope": "broadcast", "text": text}),
            )
            .unwrap()
        };

        let read_before_stop = broadcast("read before the stop");
        db.log_event(
            "life",
            &target,
            &json!({
                "action": "stopped",
                "snapshot": {
                    "tool": "claude",
                    "directory": "/tmp/project",
                    "session_id": session_id,
                    "transcript_path": transcript,
                    "last_event_id": read_before_stop
                }
            }),
        )
        .unwrap();
        for _ in 0..12 {
            db.log_event(
                "life",
                &target,
                &json!({"action": "launch_failed", "reason": "ready_never_observed"}),
            )
            .unwrap();
        }
        let sent_while_stopped = broadcast("broadcast while stopped");
        let mut ctx = make_claude_ctx(None, "/tmp/project");
        ctx.process_id = None;

        assert_eq!(start_rebind(&db, &target, &ctx, None, None).unwrap(), 0);

        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(
            row.last_event_id, read_before_stop,
            "the reclaim resumes from the stopped snapshot's cursor"
        );
        assert!(
            db.get_unread_messages(&target)
                .iter()
                .any(|m| m.event_id == Some(sent_while_stopped)),
            "the message sent while stopped is still pending"
        );
        assert_eq!(row.session_id.as_deref(), Some(session_id.as_str()));
        assert_eq!(row.transcript_path, transcript);
    }

    /// A session another live identity is using is never adopted, however the
    /// reclaim resolved its own session: the recreated row stays unbound and
    /// the other seat's session binding is untouched.
    #[test]
    #[serial]
    fn test_start_rebind_does_not_adopt_session_held_by_live_row() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("valo_held_{}", std::process::id());
        let holder = format!("meme_held_{}", std::process::id());
        let session_id = format!("sid-held-{}", std::process::id());
        let process_id = format!("omp-held-{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", &session_id, 3);
        bind_caller(&db, &holder, &session_id, &process_id, 5);
        let mut ctx = make_claude_ctx(None, "/tmp/project");
        ctx.process_id = None;

        assert_eq!(start_rebind(&db, &target, &ctx, None, None).unwrap(), 0);

        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(
            row.session_id, None,
            "a session another live seat holds is not adopted"
        );
        assert_eq!(
            db.get_session_binding(&session_id).unwrap().as_deref(),
            Some(holder.as_str()),
            "the live seat keeps the session binding"
        );
        assert_eq!(
            db.get_instance_full(&holder)
                .unwrap()
                .unwrap()
                .session_id
                .as_deref(),
            Some(session_id.as_str())
        );
    }

    /// The row being replaced is newer than its own stopped snapshot: a
    /// reclaim that adopted the snapshot's id would hand the recreated row a
    /// session older than the one the identity actually held.
    #[test]
    #[serial]
    fn test_start_rebind_prefers_live_row_session_over_stopped_snapshot() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let db = HcomDb::open().unwrap();
        let target = format!("valo_live_{}", std::process::id());
        let new_session = format!("sid-live-{}", std::process::id());
        let old_session = format!("sid-old-{}", std::process::id());
        let process_id = format!("omp-live-{}", std::process::id());
        log_stopped_snapshot(&db, &target, "claude", "/tmp/project", &old_session, 3);
        bind_caller(&db, &target, &new_session, &process_id, 5);
        let mut ctx = make_claude_ctx(None, "/tmp/project");
        ctx.process_id = None;

        assert_eq!(start_rebind(&db, &target, &ctx, None, None).unwrap(), 0);

        let row = db
            .get_instance_full(&target)
            .unwrap()
            .expect("reclaimed row");
        assert_eq!(
            row.session_id.as_deref(),
            Some(new_session.as_str()),
            "the live row's session wins over the older stopped snapshot"
        );
        assert_eq!(
            db.get_session_binding(&new_session).unwrap().as_deref(),
            Some(target.as_str())
        );
    }
}
