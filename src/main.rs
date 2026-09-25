//! hcom — inter-agent communication for AI coding tools.
//!
//! Humans usually launch agents with `hcom <tool>` and talk to them through
//! each tool's own UI. Agents use `hcom` CLI commands (learnt through bootstrap.rs)
//! as a side-channel for messaging and coordination with other agents.
use std::borrow::Cow;

mod bootstrap;
mod claude_actor;
mod cli_context;
pub mod commands;
mod config;
mod context;
pub mod core;
mod db;
mod delivery;
pub mod hooks;
pub mod identity;
mod instance_binding;
mod instance_lifecycle;
mod instance_names;
mod instances;
pub mod integration_spec;
pub mod launcher;
mod log;
pub mod messages;
mod notify;
mod paths;
mod pidtrack;
mod proctruth;
mod pty;
pub mod relay;
pub mod router;
mod runtime_env;
pub mod scripts;
pub mod shared;
mod shell_env;
mod sys;
pub mod terminal;
pub mod title;
mod tool;
pub mod tools;
pub mod transcript;
mod tui;
mod update;

use anyhow::{Context, Result, bail};
use std::panic;
use std::str::FromStr;

fn main() -> Result<()> {
    // Initialize global config from environment variables
    config::Config::init();

    // Set custom panic hook to log to file instead of stderr (prevents TUI corruption)
    panic::set_hook(Box::new(|panic_info| {
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        log::log_error("native", "panic", &format!("{} at {}", message, location));
    }));

    // Dispatch via router (replaces manual MainAction matching)
    router::dispatch()
}

/// Run PTY wrapper mode.
///
/// Uses Unix pseudo-terminals on Unix and ConPTY (via `portable-pty`) on
/// Windows; the proxy backend is selected inside `pty::Proxy`.
pub fn run_pty(args: &[String]) -> Result<()> {
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        eprintln!("hcom pty - PTY wrapper for hcom");
        eprintln!();
        eprintln!("Usage: hcom pty <tool> [args...]");
        eprintln!();
        let tools = integration_spec::ALL
            .iter()
            .filter(|spec| spec.released)
            .map(|spec| {
                if spec.aliases.is_empty() {
                    spec.name.to_string()
                } else {
                    format!("{} ({})", spec.name, spec.aliases.join(", "))
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!("Tools: {tools}");
        eprintln!();
        eprintln!("The PTY wrapper provides:");
        eprintln!("  - Text injection via TCP port (INJECT_PORT)");
        eprintln!("  - State queries via TCP port (STATE_PORT)");
        eprintln!("  - Ready detection for tool startup");
        eprintln!();
        eprintln!("Environment:");
        eprintln!("  HCOM_INSTANCE_NAME    Instance name for logging");
        eprintln!("  HCOM_DIR              Custom hcom directory");
        if args.is_empty() {
            bail!("Tool name required");
        }
        return Ok(());
    }

    let tool_str = &args[0];
    let (answer_omp_reroot_prompt, tool_args) = consume_pty_tool_args(args)?;

    // Keep arbitrary commands explicit so they cannot inherit a known tool's
    // delivery behavior merely because parsing failed.
    let (ready_pattern, target) = match tool::Tool::from_str(tool_str) {
        Ok(tool) => (tool.ready_pattern().to_vec(), pty::PtyTarget::Known(tool)),
        Err(_) => (vec![], pty::PtyTarget::AdhocCommand(tool_str.to_string())),
    };

    let instance_name = config::Config::get().instance_name;

    // Resolve tool to full path (PATH may be minimal in launched environments)
    let tool_exe = tool_str
        .parse::<tool::Tool>()
        .map(|t| t.spec().cli_binary)
        .unwrap_or(tool_str);
    let resolved = terminal::which_bin(tool_exe).unwrap_or_else(|| tool_exe.to_string());

    // On Termux, some wrapped tools need a launcher override instead of direct exec.
    let (command, extra_args): (String, Vec<String>);
    #[cfg(windows)]
    let windows_launcher = terminal::resolve_windows_tool_launcher(tool_exe, &resolved);
    #[cfg(not(windows))]
    let windows_launcher: Option<(String, Vec<String>)> = None;
    if let Some((launcher, prefix_args)) = windows_launcher {
        command = launcher;
        extra_args = prefix_args;
    } else if let Some((launcher, prefix_args)) =
        terminal::resolve_termux_tool_launcher(tool_exe, &resolved)
    {
        command = launcher;
        extra_args = prefix_args;
    } else {
        command = resolved;
        extra_args = vec![];
    }
    let full_args: Vec<&str> = extra_args
        .iter()
        .map(|s| s.as_str())
        .chain(tool_args.iter().map(|arg| arg.as_ref()))
        .collect();

    // Create and run PTY
    let instance_name_for_failure = instance_name.clone();
    let mut proxy = match pty::Proxy::spawn(
        &command,
        &full_args,
        pty::ProxyConfig {
            ready_pattern,
            instance_name,
            target,
            env_vars: pty_child_env(),
            answer_omp_reroot_prompt,
        },
    ) {
        Ok(proxy) => proxy,
        Err(e) => {
            let err = e.context("Failed to spawn PTY");
            // The launched terminal window may close on process exit before
            // anyone can read stderr (depends on the terminal's own
            // exit/profile behavior, which hcom doesn't control), so stderr
            // alone can't be relied on. Log so the failure survives, and —
            // same path used for a child that exits before binding — push it
            // through the launch-failure event so the launcher (human or the
            // agent that ran `hcom N <tool>`) is notified immediately instead
            // of waiting on the generic stale-placeholder timeout.
            log::log_error("pty", "spawn_failed", &format!("{err:#}"));
            if let Some(name) = instance_name_for_failure.as_deref()
                && let Ok(db) = db::HcomDb::open()
                && let Ok(Some(instance)) = db.get_instance_full(name)
            {
                let fallback = format!("{err:#}");
                if let Some(detail) = instance_lifecycle::finalize_launch_failure_detail(
                    &db,
                    &instance,
                    Some(&fallback),
                ) {
                    let _ = db.emit_launch_failed_event(
                        name,
                        shared::ST_INACTIVE,
                        "launch_failed",
                        "spawn_failed",
                        &detail,
                    );
                }
            }
            return Err(err);
        }
    };

    let exit_code = proxy.run().context("PTY run failed")?;

    // Drop proxy to run cleanup (join delivery thread, which does DB cleanup)
    drop(proxy);

    std::process::exit(exit_code);
}

fn pty_child_env() -> Vec<(String, String)> {
    vec![("HCOM_LAUNCHED".to_string(), "1".to_string())]
}

fn consume_reroot_option(args: &[String]) -> (bool, usize) {
    let enabled = args
        .first()
        .is_some_and(|arg| arg == pty::ANSWER_OMP_REROOT_PROMPT_OPTION);
    (enabled, usize::from(enabled))
}

pub(crate) fn consume_pty_tool_args(args: &[String]) -> Result<(bool, Vec<Cow<'_, str>>)> {
    let (answer_omp_reroot_prompt, consumed) = consume_reroot_option(&args[1..]);
    // `consume_reroot_option` receives the post-tool slice, so translate its
    // relative count back to an index in the full PTY argument vector.
    let tool_arg_start = 1 + consumed;
    if args.get(tool_arg_start).map(String::as_str) != Some("--hcom-args-file") {
        return Ok((
            answer_omp_reroot_prompt,
            args[tool_arg_start..]
                .iter()
                .map(|arg| Cow::Borrowed(arg.as_str()))
                .collect(),
        ));
    }

    let Some(path) = args.get(tool_arg_start + 1) else {
        bail!("--hcom-args-file requires a path");
    };
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read args file {path}"))?;
    let _ = std::fs::remove_file(path);
    let sidecar_args: Vec<String> = serde_json::from_str(&content)
        .with_context(|| format!("Invalid JSON in args file {path}"))?;
    Ok((
        answer_omp_reroot_prompt,
        sidecar_args.into_iter().map(Cow::Owned).collect(),
    ))
}

#[cfg(test)]
mod tests {
    use crate::router::{self, Action};

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|s| s.to_string()).collect()
    }

    /// Test that no args runs Rust TUI
    #[test]
    fn test_no_args_runs_rust_tui() {
        let action = router::resolve_action(&[]);
        assert_eq!(action, Action::Tui);
    }

    /// Test that PTY mode is correctly identified
    #[test]
    fn test_pty_mode() {
        let action = router::resolve_action(&args(&["pty", "claude"]));
        assert_eq!(
            action,
            Action::Pty {
                args: args(&["claude"])
            }
        );
    }

    /// Test that client mode is correctly identified for non-pty commands
    #[test]
    fn test_client_mode() {
        let action = router::resolve_action(&args(&["list"]));
        match action {
            Action::Command { cmd, .. } => assert_eq!(cmd, "list"),
            _ => panic!("Expected Command action, got {:?}", action),
        }
    }

    /// Test PTY mode with multiple args
    #[test]
    fn test_pty_mode_with_args() {
        let action = router::resolve_action(&args(&["pty", "claude", "--arg1", "--arg2"]));
        assert_eq!(
            action,
            Action::Pty {
                args: args(&["claude", "--arg1", "--arg2"])
            }
        );
    }

    #[test]
    fn test_reroot_option_is_proxy_only() {
        let pty_args = args(&[
            "omp",
            crate::pty::ANSWER_OMP_REROOT_PROMPT_OPTION,
            "--model",
            "test-model",
        ]);
        let (enabled, tool_args) = super::consume_pty_tool_args(&pty_args).unwrap();
        assert!(enabled);
        assert_eq!(tool_args, ["--model", "test-model"]);
    }

    #[test]
    fn test_tool_name_is_not_forwarded() {
        let pty_args = args(&["omp", "--continue"]);
        let (enabled, tool_args) = super::consume_pty_tool_args(&pty_args).unwrap();
        assert!(!enabled);
        assert_eq!(tool_args, ["--continue"]);
    }

    #[test]
    fn test_windows_args_file_is_consumed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("omp.args.json");
        std::fs::write(&path, r#"["exec","resume","id","a b"]"#).unwrap();
        let pty_args = args(&[
            "omp",
            crate::pty::ANSWER_OMP_REROOT_PROMPT_OPTION,
            "--hcom-args-file",
            path.to_str().unwrap(),
        ]);

        let (enabled, tool_args) = super::consume_pty_tool_args(&pty_args).unwrap();

        assert!(enabled);
        assert_eq!(tool_args, ["exec", "resume", "id", "a b"]);
        assert!(!path.exists());
    }

    #[test]
    fn test_pty_child_env_marks_launched() {
        assert_eq!(
            super::pty_child_env(),
            vec![("HCOM_LAUNCHED".to_string(), "1".to_string())]
        );
    }
}
