//! Launch command: `hcom [N] <tool> [--tag X] [--terminal X] [--headless] [--hcom-prompt X] [--hcom-system-prompt X] [--batch-id X] [tool-args...]`
//!
//!
//! Parses hcom-level flags, merges env config with CLI args via tool-specific
//! parsers, then delegates to `launcher::launch()`.

use crate::config::HcomConfig;
use crate::core::launch_status::{self, LaunchStatus};
use crate::core::tips::{self, LaunchTipsContext};
use crate::db::HcomDb;
use crate::identity;
use crate::launcher::{self, LaunchParams, LaunchResult, LaunchTool};
use crate::log::log_info;
use crate::router::GlobalFlags;
use crate::shared::HcomContext;
use anyhow::{Result, bail};
use serde_json::json;
use std::time::Instant;

/// Fresh launches keep the short inline wait: nothing about a new agent's
/// startup is expected to be slow, and this path runs on every single launch.
pub(crate) const INLINE_SINGLE_LAUNCH_WAIT_SECS: u64 = 10;

/// Resumes and forks get the longer window. Restoring a large session is
/// legitimately slower than starting a fresh one (ffc-47uy6: luvo's resume was
/// ready 54.8 s after launch on a box at loadavg ~165), and the wait is only a
/// convenience for the caller — a timeout is reported as pending, not failed.
pub(crate) const INLINE_RESUME_LAUNCH_WAIT_SECS: u64 = 30;

/// Run the launch command. `argv` is the full argv[1..] including count/tool.
pub fn run(argv: &[String], flags: &GlobalFlags) -> Result<i32> {
    let (count, tool, hcom_flags, tool_args) = parse_launch_argv(argv)?;
    let launch_tool = LaunchTool::from_str(&tool)?;

    // Count validation
    if count == 0 {
        bail!("Count must be positive.");
    }
    let max_count = launch_tool.spec().launch.max_launch_count;
    if count > max_count {
        bail!("Too many agents requested (max {}).", max_count);
    }

    // `--as NAME`: the moving-a-seat form. A ':' would read as a device suffix
    // (x:DEV), which names another device's seat, not a fresh one here.
    if let Some(name) = hcom_flags.as_name.as_deref()
        && name.contains(':')
    {
        bail!("--as value '{name}' must not contain ':' (that form addresses a remote device)");
    }

    let tag = hcom_flags.tag;
    let terminal = hcom_flags.terminal;
    let headless = hcom_flags.headless;
    let remote_device = hcom_flags.device.clone();
    let dir_override = hcom_flags.dir.clone();
    let tag_for_output = tag.clone();
    let terminal_for_output = terminal.clone();

    let hcom_config = load_hcom_config();
    let preview_background = headless || is_background_from_args(&launch_tool, &tool_args);

    let ctx = HcomContext::from_os();
    if ctx.is_inside_ai_tool() && !flags.go && (!tool_args.is_empty() || count > 5) {
        let remote_launch_note = "Remote launch requested; the target device will still apply its own configured defaults.";
        let remote_preview_note = "Mode shown here is only a local preview; the remote target decides the final launch mode.";
        let notes = if remote_device.is_some() {
            [remote_launch_note, remote_preview_note]
        } else {
            ["", ""]
        };
        print_launch_preview(LaunchPreview {
            action: "launch",
            tool: &tool,
            count,
            background: preview_background,
            args: &tool_args,
            tag: tag.as_deref(),
            cwd: dir_override.as_deref(),
            terminal: terminal.as_deref(),
            config: &hcom_config,
            show_config_args: remote_device.is_none(),
            notes: if remote_device.is_some() { &notes } else { &[] },
        });
        return Ok(0);
    }

    if let Some(ref device) = remote_device {
        if hcom_flags.run_here == Some(true) {
            bail!("Remote launch does not support --run-here");
        }
        if hcom_flags.as_name.is_some() {
            bail!("Remote launch does not support --as (the target device names its own seats)");
        }
        let remote_cwd = dir_override.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Remote launch requires --dir to specify the working directory on the target device"
            )
        })?;
        let db = HcomDb::open()?;
        let launcher_name =
            resolve_launcher_name(&db, flags, std::env::var("HCOM_PROCESS_ID").ok().as_deref());
        let params = json!({
            "tool": tool,
            "count": count,
            "args": tool_args,
            "tag": tag,
            "launcher": launcher_name,
            "background": headless,
            "terminal": terminal.clone(),
            "cwd": remote_cwd,
            "initial_prompt": hcom_flags.initial_prompt,
            "system_prompt": hcom_flags.system_prompt,
            "purpose": hcom_flags.title,
        });

        match crate::relay::control::dispatch_remote(
            &db,
            device,
            None,
            crate::relay::control::rpc_action::LAUNCH,
            &params,
            crate::relay::control::RPC_LAUNCH_TIMEOUT,
        ) {
            Ok(inner) => {
                let launch_result = launch_result_from_json(&inner).map_err(anyhow::Error::msg)?;
                let remote_output = build_remote_launch_output(
                    &db,
                    flags,
                    &launch_result,
                    tag_for_output.clone(),
                    terminal_for_output.clone(),
                    hcom_flags.run_here,
                );
                let output = LaunchOutputContext {
                    action: "launch",
                    tool: &remote_output.tool,
                    requested_count: count,
                    tag: remote_output.tag.as_deref(),
                    launcher_name: &remote_output.launcher_name,
                    terminal: remote_output.terminal.as_deref(),
                    background: remote_output.background,
                    run_here: remote_output.run_here,
                    hcom_config: &hcom_config,
                    inline_readiness_wait_secs: None,
                };
                print_launch_feedback(&db, &launch_result, &output)?;
                return Ok(0);
            }
            Err(e) => bail!("Remote launch failed for device {device}: {e}"),
        }
    }

    // System/initial prompt handling
    let system_prompt = hcom_flags.system_prompt;
    let initial_prompt = hcom_flags.initial_prompt;

    // Merge env config args with CLI args
    let (merged_args, background) =
        prepare_launch_execution(&launch_tool, &tool_args, &hcom_config, headless);

    validate_claude_headless_launch(&tool, background, &merged_args, initial_prompt.as_deref())?;

    // Open DB
    let db = HcomDb::open()?;

    let launcher_name =
        resolve_launcher_name(&db, flags, std::env::var("HCOM_PROCESS_ID").ok().as_deref());
    let launcher_name_ref = launcher_name.as_str();

    let output = LaunchOutputContext {
        action: "launch",
        tool: &tool,
        requested_count: count,
        tag: tag_for_output.as_deref(),
        launcher_name: launcher_name_ref,
        terminal: terminal_for_output.as_deref(),
        background,
        run_here: hcom_flags.run_here,
        hcom_config: &hcom_config,
        inline_readiness_wait_secs: if ctx.is_inside_ai_tool() && count == 1 {
            Some(INLINE_SINGLE_LAUNCH_WAIT_SECS)
        } else {
            None
        },
    };

    let result = launcher::launch(
        &db,
        LaunchParams {
            tool: tool.clone(),
            count,
            args: merged_args,
            persisted_args: None,
            prior_session_id: None,
            tag,
            system_prompt,
            initial_prompt,
            purpose: hcom_flags.title.clone(),
            current: None,
            background,
            cwd: Some(if let Some(ref dir) = dir_override {
                let path = std::path::Path::new(dir);
                if !path.is_dir() {
                    bail!("--dir path does not exist or is not a directory: {}", dir);
                }
                // New instance names are not assigned yet, so no seat here.
                if matches!(launch_tool, LaunchTool::Omp) {
                    crate::shared::launch_dir::guard_launch_dir(dir, None, true)
                        .map_err(|e| anyhow::anyhow!(e))?;
                }
                path.canonicalize()
                    .map(|p| crate::shared::platform::child_process_path(&p))
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| dir.clone())
            } else {
                std::env::current_dir()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| ".".to_string())
            }),
            env: None,
            launcher: Some(launcher_name.clone()),
            run_here: hcom_flags.run_here,
            batch_id: hcom_flags.batch_id,
            // `--as NAME` claims the explicit name; `--name` (router global) is
            // caller identity and never the instance name.
            name: hcom_flags.as_name.clone(),
            skip_validation: false,
            terminal,
            answer_omp_reroot_prompt: false,
            append_reply_handoff: true,
        },
    )?;

    print_launch_feedback(&db, &result, &output)?;
    let readiness_state = output
        .inline_readiness_wait_secs
        .filter(|_| result.launched == 1)
        .map(|secs| print_inline_launch_readiness(&db, &result, secs));

    // Log summary
    log_info(
        "launch",
        "cmd.launch",
        &format!(
            "tool={} count={} launched={} failed={} batch={}",
            tool, count, result.launched, result.failed, result.batch_id
        ),
    );

    Ok(readiness_exit_code(readiness_state, result.failed))
}

pub(crate) fn prepare_launch_execution(
    tool: &LaunchTool,
    cli_args: &[String],
    config: &HcomConfig,
    headless: bool,
) -> (Vec<String>, bool) {
    let mut merged_args = merge_tool_args(tool, cli_args, config);
    let background = headless || is_background_from_args(tool, &merged_args);

    // Print mode needs stream-json for the stop-hook loop. Keep this deliberately
    // grammar-free: hcom appends its required defaults and lets Claude resolve
    // duplicates or reject incompatible combinations.
    if matches!(tool, LaunchTool::Claude | LaunchTool::ClaudePty)
        && background
        && args_contain_any(&merged_args, &["-p", "--print"])
    {
        merged_args.extend([
            "--output-format".to_string(),
            "stream-json".to_string(),
            "--verbose".to_string(),
        ]);
    }

    (merged_args, background)
}

pub(crate) fn validate_claude_headless_launch(
    tool: &str,
    background: bool,
    merged_args: &[String],
    initial_prompt: Option<&str>,
) -> Result<()> {
    if tool != "claude" || !background {
        return Ok(());
    }

    if !args_contain_any(merged_args, &["-p", "--print"]) {
        return Ok(());
    }

    let has_hcom_prompt = initial_prompt.is_some_and(|p| !p.trim().is_empty());
    if has_hcom_prompt {
        return Ok(());
    }
    // User positionals cannot be identified without duplicating Claude's flag
    // grammar. Let Claude validate whether print mode received a prompt.
    Ok(())
}

pub(crate) fn launch_result_to_json(result: &LaunchResult) -> serde_json::Value {
    serde_json::to_value(result).unwrap_or_else(|_| json!({}))
}

pub(crate) fn launch_result_from_json(value: &serde_json::Value) -> Result<LaunchResult, String> {
    serde_json::from_value(value.clone()).map_err(|e| e.to_string())
}

struct RemoteLaunchOutput {
    tool: String,
    tag: Option<String>,
    launcher_name: String,
    terminal: Option<String>,
    background: bool,
    run_here: Option<bool>,
}

fn build_remote_launch_output(
    db: &HcomDb,
    flags: &GlobalFlags,
    launch_result: &LaunchResult,
    tag: Option<String>,
    terminal: Option<String>,
    run_here: Option<bool>,
) -> RemoteLaunchOutput {
    let launcher_name =
        resolve_launcher_name(db, flags, std::env::var("HCOM_PROCESS_ID").ok().as_deref());
    RemoteLaunchOutput {
        tool: launch_result.tool.clone(),
        tag,
        launcher_name,
        terminal,
        background: launch_result.background,
        run_here,
    }
}

pub(crate) fn resolve_launcher_name(
    db: &HcomDb,
    flags: &GlobalFlags,
    process_id: Option<&str>,
) -> String {
    // Launch caller identity only needs explicit --name, then process binding.
    flags
        .name
        .as_deref()
        .map(|name| {
            crate::identity::resolve_display_name(db, name).unwrap_or_else(|| name.to_string())
        })
        .or_else(|| flags.name.clone())
        .unwrap_or_else(|| {
            identity::resolve_identity(db, None, None, None, process_id, None, None)
                .map(|id| id.name)
                .unwrap_or_else(|_| "user".to_string())
        })
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().to_string() + c.as_str(),
    }
}

/// Print launch preview when --go gate blocks inside AI tool.
pub(crate) struct LaunchPreview<'a> {
    pub action: &'a str,
    pub tool: &'a str,
    pub count: usize,
    pub background: bool,
    pub args: &'a [String],
    pub tag: Option<&'a str>,
    pub cwd: Option<&'a str>,
    pub terminal: Option<&'a str>,
    pub config: &'a HcomConfig,
    pub show_config_args: bool,
    pub notes: &'a [&'a str],
}

pub(crate) fn print_launch_preview(preview: LaunchPreview<'_>) {
    let mode = if preview.background {
        "headless"
    } else {
        "interactive"
    };
    let cwd = preview.cwd.map(|s| s.to_string()).unwrap_or_else(|| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| ".".to_string())
    });
    // Drive the args-env label from the spec so we never invent a key (e.g.
    // `HCOM_ANTIGRAVITY_ARGS`) for tools that don't have one.
    let args_key: Option<&'static str> = preview
        .tool
        .parse::<crate::tool::Tool>()
        .ok()
        .and_then(|t| t.spec().launch.args_env);
    let env_args = if preview.show_config_args {
        match preview.tool {
            "claude" => preview.config.claude_args.as_str(),
            "gemini" => preview.config.gemini_args.as_str(),
            "codex" => preview.config.codex_args.as_str(),
            "opencode" => preview.config.opencode_args.as_str(),
            "kilo" | "kilocode" => preview.config.kilo_args.as_str(),
            "pi" | "pi-agent" => preview.config.pi_args.as_str(),
            "omp" | "omp-agent" => preview.config.omp_args.as_str(),
            "cursor" | "cursor-agent" => preview.config.cursor_args.as_str(),
            "copilot" => preview.config.copilot_args.as_str(),
            "kimi" => preview.config.kimi_args.as_str(),
            _ => "",
        }
    } else {
        ""
    };

    let terminal = preview
        .terminal
        .map(|s| s.to_string())
        .or_else(|| std::env::var("HCOM_TERMINAL").ok())
        .unwrap_or_else(|| preview.config.terminal.clone());

    println!("\n== LAUNCH PREVIEW ==");
    println!("Add --go to proceed.\n");
    println!("Action: {}", preview.action);
    println!(
        "Tool: {:<10} Count: {:<4} Mode: {}",
        preview.tool, preview.count, mode
    );
    println!("Directory: {}", cwd);
    println!("Terminal: {}", terminal);
    if let Some(t) = preview.tag {
        println!("Tag: {} (names will be {}-*)", t, t);
    }
    for note in preview.notes {
        println!("{note}");
    }

    // Args — only show if there's something to show
    if !env_args.is_empty() || !preview.args.is_empty() {
        println!("\nArgs:");
        if !env_args.is_empty() {
            match args_key {
                Some(key) => println!("  From config ({}): {}", key, env_args),
                None => println!("  From config: {}", env_args),
            }
        }
        if !preview.args.is_empty() {
            println!("  From CLI: {}", preview.args.join(" "));
        }
        if !env_args.is_empty() && !preview.args.is_empty() {
            println!(
                "  (config args are passed first, then CLI args; the tool resolves duplicates)"
            );
        }
    }
}

/// Hcom-level flags extracted from launch argv.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct HcomLaunchFlags {
    pub tag: Option<String>,
    pub terminal: Option<String>,
    pub device: Option<String>,
    pub headless: bool,
    pub system_prompt: Option<String>,
    pub initial_prompt: Option<String>,
    pub title: Option<String>,
    pub run_here: Option<bool>,
    pub batch_id: Option<String>,
    pub dir: Option<String>,
    /// Explicit instance name for a fresh launch (`--as NAME`), the moving-a-seat
    /// form. Distinct from the router-level `--name`, which is caller identity.
    pub as_name: Option<String>,
}

/// Parse launch argv: extract count, tool name, hcom flags, and tool-specific args.
///
/// Input forms: `[N] <tool> [--tag X] [--terminal X] [--headless] [--hcom-prompt X] [--hcom-system-prompt X] [--batch-id X] [tool-args...]`
fn parse_launch_argv(argv: &[String]) -> Result<(usize, String, HcomLaunchFlags, Vec<String>)> {
    if argv.is_empty() {
        bail!("Usage: hcom [N] <tool> [args...]");
    }

    let mut idx = 0;

    // Skip --name/--go (global flags already extracted by router)
    while idx < argv.len() {
        match argv[idx].as_str() {
            "--name" => {
                idx += 2;
                continue;
            }
            "--go" => {
                idx += 1;
                continue;
            }
            _ => break,
        }
    }

    if idx >= argv.len() {
        bail!("Missing tool name");
    }

    // Count (optional numeric prefix)
    let count: usize = if argv[idx].parse::<u32>().is_ok() {
        let c = argv[idx].parse::<usize>().unwrap_or(1);
        idx += 1;
        c
    } else {
        1
    };

    if idx >= argv.len() {
        bail!("Missing tool name after count");
    }

    // Tool name
    let tool = argv[idx].to_string();
    idx += 1;

    let (flags, tool_args) = extract_launch_flags(&argv[idx..]);

    Ok((count, tool, flags, tool_args))
}

/// Merge env config args with CLI args via tool-specific parsers.
fn append_config_args(config_args: &str, cli_args: &[String]) -> Vec<String> {
    let mut tokens = if config_args.is_empty() {
        Vec::new()
    } else {
        // Don't silently drop hand-edited config args on a parse error (e.g. an
        // unterminated quote) — surface it so the launch isn't quietly missing
        // flags the user configured.
        crate::tools::args_common::shell_split(config_args, cfg!(windows)).unwrap_or_else(|err| {
            eprintln!("hcom: ignoring malformed configured args ({err}): {config_args}");
            Vec::new()
        })
    };
    tokens.extend(cli_args.iter().cloned());
    tokens
}

pub(crate) fn merge_tool_args(
    tool: &LaunchTool,
    cli_args: &[String],
    config: &HcomConfig,
) -> Vec<String> {
    match tool {
        LaunchTool::Claude | LaunchTool::ClaudePty => {
            append_config_args(&config.claude_args, cli_args)
        }
        LaunchTool::Gemini => append_config_args(&config.gemini_args, cli_args),
        LaunchTool::Codex => append_config_args(&config.codex_args, cli_args),
        LaunchTool::Cursor => {
            // env config args first, explicit CLI args last (CLI wins under
            // commander.js last-wins). Print-mode conflicts are rejected by the
            // unified launcher so their meaning is never silently changed.
            append_config_args(&config.cursor_args, cli_args)
        }
        LaunchTool::Copilot => append_config_args(&config.copilot_args, cli_args),
        LaunchTool::Pi => append_config_args(&config.pi_args, cli_args),
        LaunchTool::Omp => append_config_args(&config.omp_args, cli_args),
        LaunchTool::OpenCode => append_config_args(&config.opencode_args, cli_args),
        LaunchTool::Kilo => append_config_args(&config.kilo_args, cli_args),
        LaunchTool::Kimi => append_config_args(&config.kimi_args, cli_args),
        LaunchTool::Antigravity => {
            // IntegrationSpec.launch.args_env is explicitly None: Antigravity
            // has no persisted *_args config to merge.
            cli_args.to_vec()
        }
    }
}

fn args_contain_any(args: &[String], needles: &[&str]) -> bool {
    args.iter().any(|arg| needles.contains(&arg.as_str()))
}

/// Check if args indicate background/headless mode.
pub(crate) fn is_background_from_args(tool: &LaunchTool, args: &[String]) -> bool {
    match tool {
        LaunchTool::Claude | LaunchTool::ClaudePty => args_contain_any(args, &["-p", "--print"]),
        // These tools are always hosted in hcom's PTY. Their native
        // non-interactive modes are rejected by validate_tool_args.
        LaunchTool::Gemini
        | LaunchTool::Codex
        | LaunchTool::OpenCode
        | LaunchTool::Kilo
        | LaunchTool::Pi
        | LaunchTool::Antigravity
        | LaunchTool::Cursor
        | LaunchTool::Kimi
        | LaunchTool::Copilot
        | LaunchTool::Omp => false,
    }
}

pub(crate) fn load_hcom_config() -> HcomConfig {
    HcomConfig::load(None).unwrap_or_else(|_| {
        let mut c = HcomConfig::default();
        c.normalize();
        c
    })
}

pub(crate) fn extract_launch_flags(args: &[String]) -> (HcomLaunchFlags, Vec<String>) {
    let mut flags = HcomLaunchFlags::default();
    let mut tool_args = Vec::new();
    let mut i = 0;

    while i < args.len() {
        if args[i] == "--" {
            tool_args.extend_from_slice(&args[i + 1..]);
            break;
        }
        if args[i].starts_with("--tag=") {
            flags.tag = Some(args[i][6..].to_string());
            i += 1;
            continue;
        }
        if args[i].starts_with("--terminal=") {
            flags.terminal = Some(args[i][11..].to_string());
            i += 1;
            continue;
        }
        if args[i].starts_with("--device=") {
            flags.device = Some(args[i][9..].to_string());
            i += 1;
            continue;
        }
        if args[i].starts_with("--dir=") {
            flags.dir = Some(args[i][6..].to_string());
            i += 1;
            continue;
        }
        if args[i].starts_with("--hcom-title=") {
            flags.title = Some(args[i][13..].to_string());
            i += 1;
            continue;
        }
        if args[i].starts_with("--as=") {
            flags.as_name = Some(args[i][5..].to_string());
            i += 1;
            continue;
        }
        match args[i].as_str() {
            "--tag" if i + 1 < args.len() => {
                flags.tag = Some(args[i + 1].clone());
                i += 2;
            }
            "--terminal" if i + 1 < args.len() => {
                flags.terminal = Some(args[i + 1].clone());
                i += 2;
            }
            "--device" if i + 1 < args.len() => {
                flags.device = Some(args[i + 1].clone());
                i += 2;
            }
            "--dir" if i + 1 < args.len() => {
                flags.dir = Some(args[i + 1].clone());
                i += 2;
            }
            "--headless" => {
                flags.headless = true;
                i += 1;
            }
            "--hcom-system-prompt" if i + 1 < args.len() => {
                flags.system_prompt = Some(args[i + 1].clone());
                i += 2;
            }
            "--system" if i + 1 < args.len() => {
                flags.system_prompt = Some(args[i + 1].clone());
                i += 2;
            }
            "--hcom-prompt" if i + 1 < args.len() => {
                flags.initial_prompt = Some(args[i + 1].clone());
                i += 2;
            }
            "--hcom-title" if i + 1 < args.len() => {
                flags.title = Some(args[i + 1].clone());
                i += 2;
            }
            "--batch-id" if i + 1 < args.len() => {
                flags.batch_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--run-here" => {
                flags.run_here = Some(true);
                i += 1;
            }
            "--no-run-here" => {
                flags.run_here = Some(false);
                i += 1;
            }
            "--name" if i + 1 < args.len() => {
                i += 2;
            }
            "--as" if i + 1 < args.len() => {
                flags.as_name = Some(args[i + 1].clone());
                i += 2;
            }
            "--go" => {
                i += 1;
            }
            "--pty" => {
                // Deprecated no-op: --pty was previously used to request a
                // pseudo-terminal session. PTY behaviour is now the default
                // (or controlled by --headless). Silently consume the flag so
                // legacy scripts continue to work.
                i += 1;
            }
            _ => {
                tool_args.push(args[i].clone());
                i += 1;
            }
        }
    }

    (flags, tool_args)
}

pub(crate) struct LaunchOutputContext<'a> {
    pub action: &'a str,
    pub tool: &'a str,
    pub requested_count: usize,
    pub tag: Option<&'a str>,
    pub launcher_name: &'a str,
    pub terminal: Option<&'a str>,
    pub background: bool,
    pub run_here: Option<bool>,
    pub hcom_config: &'a HcomConfig,
    pub inline_readiness_wait_secs: Option<u64>,
}

pub(crate) fn print_launch_feedback(
    db: &HcomDb,
    result: &LaunchResult,
    ctx: &LaunchOutputContext<'_>,
) -> Result<()> {
    if result.failed > 0 {
        for err in &result.errors {
            if let Some(msg) = err.get("error").and_then(|v| v.as_str()) {
                eprintln!("Error: {}", msg);
            }
        }
    }

    if result.launched == 0 && result.failed > 0 {
        return Ok(());
    }

    let tool_label = capitalize(ctx.tool);
    let plural = if ctx.requested_count != 1 { "s" } else { "" };
    if result.failed > 0 {
        println!(
            "Started the {} process for {}/{} {} agent{} ({} failed)",
            ctx.action, result.launched, ctx.requested_count, tool_label, plural, result.failed
        );
    } else {
        let s = if result.launched != 1 { "s" } else { "" };
        println!(
            "Started the {} process for {} {} agent{}",
            ctx.action, result.launched, tool_label, s
        );
    }

    let instance_names: Vec<&str> = result
        .handles
        .iter()
        .filter_map(|h| h.get("instance_name").and_then(|v| v.as_str()))
        .collect();
    if !instance_names.is_empty() {
        println!("Names: {}", instance_names.join(" "));
    }
    println!("Batch id: {}", result.batch_id);
    if ctx.inline_readiness_wait_secs.is_none() {
        println!("To block until ready or fail (30s timeout), run: hcom events launch");
    }

    let launcher_participating = db
        .get_instance_full(ctx.launcher_name)
        .ok()
        .flatten()
        .is_some();
    let (terminal_mode, terminal_auto_detected) = crate::terminal::resolve_terminal_mode_for_tips(
        ctx.terminal,
        &ctx.hcom_config.terminal,
        ctx.background,
        ctx.run_here.unwrap_or(false),
    );
    tips::print_launch_tips(
        db,
        LaunchTipsContext {
            launched: result.launched,
            tag: ctx.tag,
            launcher_name: Some(ctx.launcher_name),
            launcher_participating,
            background: ctx.background,
            terminal_mode: &terminal_mode,
            terminal_auto_detected,
        },
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InlineLaunchReadiness {
    Ready,
    Failed,
    Blocked,
    /// The readiness window elapsed but the launched tool is still running:
    /// the launch is slow, not broken (ffc-47uy6).
    Pending,
    /// The readiness window elapsed and no pid could be read for the launch,
    /// so nothing is proven either way. Not pending — exit 0 must mean a
    /// verified-alive tool, never an absent one.
    Unverified,
}

/// Map an inline-readiness outcome to a process exit code, shared by launch
/// and resume/fork so all three report readiness the same way. `None` means
/// no readiness wait ran (not inside an AI tool, or multi-launch).
///
/// `Pending` is 0, deliberately distinct from `Failed`: a timed-out wait on a
/// live process used to exit 2, which callers such as fleet read as a failed
/// launch, turning a seat that came up 54.8 s later into a casualty. Exit 0
/// is reserved for a VERIFIED-alive tool, so `Unverified` keeps a non-zero
/// exit rather than joining `Pending`.
pub(crate) fn readiness_exit_code(state: Option<InlineLaunchReadiness>, failed: usize) -> i32 {
    match state {
        Some(InlineLaunchReadiness::Failed) => 1,
        Some(InlineLaunchReadiness::Pending) => 0,
        Some(InlineLaunchReadiness::Blocked | InlineLaunchReadiness::Unverified) => 2,
        _ if failed == 0 => 0,
        _ => 1,
    }
}

/// Liveness of the launched TOOL behind a launched instance.
///
/// The pid hcom records is a WRAPPER, never the tool: a new-window launch
/// records the generated script's shell, which ends in `exec bash -l` and so
/// deliberately outlives the tool; a background launch records the detached
/// runner. A live wrapper therefore proves nothing about the tool — that is
/// exactly how a launch whose tool died before its first hook came to be
/// reported as pending. `Alive` is the tool: either the recorded pid IS the
/// tool (run-here's `exec`, the PTY wrapper's child-pid write) or a live tool
/// process hangs below it. `Gone` is a dead wrapper, or a live one with no
/// tool left under it. `Unknown` means no pid could be read at all, which is
/// no proof of anything and so is never reported as a verified-alive pending.
enum LaunchLiveness {
    /// A live tool process, the one the pending line should name.
    Alive(u32),
    Gone,
    Unknown,
}

/// The recorded pid of `name`'s launched process, preferring the handle the
/// launcher returned (background runner) over the anchored row pid, which a
/// PTY wrapper may have claimed for itself.
fn recorded_launch_pid(db: &HcomDb, result: &LaunchResult, name: &str) -> Option<u32> {
    let from_handle = result
        .handles
        .iter()
        .filter(|h| h.get("instance_name").and_then(|v| v.as_str()) == Some(name))
        .filter_map(|h| h.get("pid"))
        .find_map(|pid| pid.as_u64())
        .and_then(|pid| u32::try_from(pid).ok());
    if from_handle.is_some() {
        return from_handle;
    }
    db.get_instance_full(name)
        .ok()
        .flatten()
        .and_then(|row| row.pid)
        .and_then(|pid| u32::try_from(pid).ok())
}

/// Every name the launched tool answers to: the canonical CLI binary plus its
/// aliases, so a launch through `agy` or `cursor-agent` is still recognized
/// as that tool. The PTY surface (`claude-pty`) is the same binary as
/// `claude`. Empty for a tool string hcom does not know.
fn launched_tool_names(tool: &str) -> Vec<&'static str> {
    let Ok(surface) = crate::launcher::LaunchTool::from_str(tool) else {
        return Vec::new();
    };
    let spec = surface.spec();
    let mut names: Vec<&'static str> = Vec::new();
    for name in std::iter::once(spec.cli_binary).chain(spec.aliases.iter().copied()) {
        // A spec whose alias repeats its own cli_binary contributes one name,
        // not two: `antigravity` is `agy` both ways.
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Whether the tool behind `name` is still running, per
/// [`recorded_launch_pid`] and [`crate::proctruth::live_tool_processes`].
///
/// A zombie counts as gone anywhere in the tree: it is dead, only unreaped.
/// The tool-name rule applies only where it can actually be answered — see
/// [`crate::proctruth::tool_names_are_provable`] — and only for a tool hcom
/// recognizes. Anywhere else the recorded pid's own liveness stands, which is
/// the weaker rule the pid-only check always was, and the one that can still
/// see a launch that never got as far as a tool.
fn launch_liveness(db: &HcomDb, result: &LaunchResult, name: &str) -> LaunchLiveness {
    let Some(pid) = recorded_launch_pid(db, result, name) else {
        return LaunchLiveness::Unknown;
    };
    if crate::proctruth::process_gone(pid) {
        return LaunchLiveness::Gone;
    }
    if !crate::proctruth::tool_names_are_provable() {
        return LaunchLiveness::Alive(pid);
    }
    let tool_names = launched_tool_names(&result.tool);
    if tool_names.is_empty() {
        return LaunchLiveness::Alive(pid);
    }
    match crate::proctruth::live_tool_processes(pid, &tool_names).first() {
        Some(&tool_pid) => LaunchLiveness::Alive(tool_pid),
        None => LaunchLiveness::Gone,
    }
}

/// Names of the launched instances whose tool is gone, so a timed-out wait on
/// a dead launch reports a failure instead of a pending one.
fn dead_launch_names(db: &HcomDb, result: &LaunchResult) -> Vec<String> {
    instance_names_from_launch_result(result)
        .into_iter()
        .filter(|name| matches!(launch_liveness(db, result, name), LaunchLiveness::Gone))
        .collect()
}

/// The live tool pid of the first launched instance, for the pending message.
fn first_live_launch_pid(db: &HcomDb, result: &LaunchResult) -> Option<u32> {
    instance_names_from_launch_result(result)
        .into_iter()
        .find_map(|name| match launch_liveness(db, result, &name) {
            LaunchLiveness::Alive(pid) => Some(pid),
            LaunchLiveness::Gone | LaunchLiveness::Unknown => None,
        })
}

/// The launched names whose liveness could not be established at all, for the
/// unverified line. Not a "first": a timed-out multi-name launch can have
/// several, and the line must name all of them.
fn unverified_launch_names(db: &HcomDb, result: &LaunchResult) -> Vec<String> {
    instance_names_from_launch_result(result)
        .into_iter()
        .filter(|name| matches!(launch_liveness(db, result, name), LaunchLiveness::Unknown))
        .collect()
}

pub(crate) fn print_inline_launch_readiness(
    db: &HcomDb,
    result: &LaunchResult,
    timeout_secs: u64,
) -> InlineLaunchReadiness {
    println!("Waiting up to {timeout_secs}s for launch readiness...");
    let start = Instant::now();
    let wait = launch_status::wait_for_launch(db, None, Some(&result.batch_id), timeout_secs);
    let elapsed_secs = start.elapsed().as_secs_f64();

    // A wait that ran out says nothing about the launch itself: the only
    // question left is whether the launched TOOL is still running. A live tool
    // is pending; a tool that is gone is a failure; no recorded pid proves
    // nothing at all and is reported as unverified, never as pending.
    let timed_out = matches!(
        wait.status,
        LaunchStatus::Timeout | LaunchStatus::NoLaunches
    );
    let dead = if timed_out {
        dead_launch_names(db, result)
    } else {
        Vec::new()
    };
    let unverified = if timed_out && dead.is_empty() {
        unverified_launch_names(db, result)
    } else {
        Vec::new()
    };

    let (state, details) = match wait.status {
        LaunchStatus::Ready => (InlineLaunchReadiness::Ready, Vec::new()),
        LaunchStatus::Error => (InlineLaunchReadiness::Failed, wait.failures),
        LaunchStatus::Blocked => (InlineLaunchReadiness::Blocked, wait.blockers),
        LaunchStatus::Timeout | LaunchStatus::NoLaunches if !dead.is_empty() => (
            InlineLaunchReadiness::Failed,
            vec![format!("{}: tool exited before ready", dead.join(", "))],
        ),
        LaunchStatus::Timeout | LaunchStatus::NoLaunches if !unverified.is_empty() => {
            (InlineLaunchReadiness::Unverified, unverified)
        }
        LaunchStatus::Timeout | LaunchStatus::NoLaunches => {
            (InlineLaunchReadiness::Pending, Vec::new())
        }
    };

    println!(
        "{}",
        format_inline_launch_readiness(
            state,
            result,
            &wait.instances,
            elapsed_secs,
            &details,
            if state == InlineLaunchReadiness::Pending {
                first_live_launch_pid(db, result)
            } else {
                None
            },
        )
    );
    state
}

fn instance_names_from_launch_result(result: &LaunchResult) -> Vec<String> {
    result
        .handles
        .iter()
        .filter_map(|h| {
            h.get("instance_name")
                .and_then(|v| v.as_str())
                .map(ToString::to_string)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn format_inline_launch_readiness(
    state: InlineLaunchReadiness,
    result: &LaunchResult,
    ready_instances: &[String],
    elapsed_secs: f64,
    failures: &[String],
    live_pid: Option<u32>,
) -> String {
    let names = instance_names_from_launch_result(result);
    let target = if names.is_empty() {
        "agent".to_string()
    } else {
        names.join(" ")
    };
    let progress = format!("{}/{} ready", ready_instances.len(), result.launched);
    let elapsed = format!("{elapsed_secs:.1}s");

    match state {
        InlineLaunchReadiness::Ready => {
            let ready = if ready_instances.is_empty() {
                target
            } else {
                ready_instances.join(" ")
            };
            format!("Launch ready: {ready} ({progress}, {elapsed}).")
        }
        InlineLaunchReadiness::Failed => {
            let detail = if failures.is_empty() {
                "no failure detail available".to_string()
            } else {
                failures.join("; ")
            };
            format!("Launch failed: {detail} (batch: {}).", result.batch_id)
        }
        InlineLaunchReadiness::Blocked => {
            let detail = if failures.is_empty() {
                "human attention needed".to_string()
            } else {
                failures.join("; ")
            };
            format!("Launch blocked: {detail} (batch: {}).", result.batch_id)
        }
        // Greppable and exit-0: the launched TOOL is running, it just has not
        // said `ready` inside the window, and it will on its own.
        InlineLaunchReadiness::Pending => {
            let alive = match live_pid {
                Some(pid) => format!("tool process {pid} alive"),
                None => "its tool process is still running".to_string(),
            };
            format!(
                "Launch pending: still starting after {elapsed}, {alive}; it will report ready on its own ({target}, {progress}, batch: {}). Check `hcom list -v` or `hcom events launch {} --timeout 30`.",
                result.batch_id, result.batch_id
            )
        }
        // Non-zero on purpose: no pid was ever recorded, so nothing proves
        // this launch survived. It is NOT a refusal — the command did run —
        // but it cannot be reported as a verified-alive pending either.
        InlineLaunchReadiness::Unverified => {
            let unverified = if failures.is_empty() {
                target.clone()
            } else {
                failures.join(", ")
            };
            format!(
                "Launch unverified: no process recorded for {unverified} (batch: {}). \
                 Check `hcom list -v` to see whether the seat came up.",
                result.batch_id
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    fn lt(tool: &str) -> LaunchTool {
        LaunchTool::from_str(tool).unwrap()
    }

    #[test]
    fn test_parse_launch_argv_simple() {
        let (count, tool, _flags, args) = parse_launch_argv(&s(&["claude"])).unwrap();
        assert_eq!(count, 1);
        assert_eq!(tool, "claude");
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_launch_argv_with_count() {
        let (count, tool, _, args) =
            parse_launch_argv(&s(&["3", "gemini", "-m", "flash"])).unwrap();
        assert_eq!(count, 3);
        assert_eq!(tool, "gemini");
        assert_eq!(args, s(&["-m", "flash"]));
    }

    #[test]
    fn test_parse_launch_argv_with_tag() {
        let (_, tool, flags, args) =
            parse_launch_argv(&s(&["claude", "--tag", "test", "--model", "haiku"])).unwrap();
        assert_eq!(tool, "claude");
        assert_eq!(flags.tag, Some("test".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_carries_as_name() {
        // Every tool shares this parse path, so `hcom omp --as X` and
        // `hcom claude --as X` both land the name in the launch flags.
        for tool in [
            "omp", "claude", "codex", "gemini", "opencode", "kilo", "pi", "agy",
        ] {
            let (_, parsed, flags, args) = parse_launch_argv(&s(&[tool, "--as", "X"])).unwrap();
            assert_eq!(parsed, tool);
            assert_eq!(flags.as_name.as_deref(), Some("X"), "tool {tool}");
            assert!(args.is_empty(), "tool {tool}");
        }
    }

    #[test]
    fn test_parse_launch_argv_as_equals_form() {
        let (_, tool, flags, args) =
            parse_launch_argv(&s(&["omp", "--as=X", "--model", "flash"])).unwrap();
        assert_eq!(tool, "omp");
        assert_eq!(flags.as_name.as_deref(), Some("X"));
        assert_eq!(args, s(&["--model", "flash"]));
    }

    #[test]
    fn test_parse_launch_argv_leaves_name_absent_by_default() {
        let (_, _, flags, _) = parse_launch_argv(&s(&["omp"])).unwrap();
        assert!(flags.as_name.is_none());
    }

    #[test]
    #[serial]
    fn test_as_name_with_colon_is_refused() {
        let (_dir, _hcom_dir, _home, _guard) = crate::hooks::test_helpers::isolated_test_env();
        let err = run(
            &s(&["omp", "--as", "X:ABCD"]),
            &crate::router::GlobalFlags {
                name: None,
                go: true,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not contain ':'"), "{err}");
    }

    #[test]
    fn test_as_name_is_refused_on_remote_launch() {
        // The remote path never builds LaunchParams, so an explicit name
        // there must be refused rather than silently dropped.
        let argv = s(&["omp", "--device", "BOXE", "--dir", ".", "--as", "X"]);
        let err = run(
            &argv,
            &crate::router::GlobalFlags {
                name: None,
                go: true,
            },
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("Remote launch does not support --as"),
            "{err}"
        );
    }

    #[test]
    fn test_parse_launch_argv_accepts_legacy_pty() {
        let (_, tool, flags, args) =
            parse_launch_argv(&s(&["claude", "--headless", "--pty", "--model", "haiku"])).unwrap();
        assert_eq!(tool, "claude");
        assert!(flags.headless);
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_tag_after_tool_args() {
        // --tag after tool-specific args should still be extracted (order-independent)
        let (_, tool, flags, args) =
            parse_launch_argv(&s(&["claude", "--model", "haiku", "--tag", "test"])).unwrap();
        assert_eq!(tool, "claude");
        assert_eq!(flags.tag, Some("test".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_headless() {
        let (_, _, flags, _) = parse_launch_argv(&s(&["claude", "--headless"])).unwrap();
        assert!(flags.headless);
    }

    #[test]
    fn test_parse_launch_argv_no_run_here() {
        let (_, _, flags, _) = parse_launch_argv(&s(&["claude", "--no-run-here"])).unwrap();
        assert_eq!(flags.run_here, Some(false));
    }

    #[test]
    fn test_parse_launch_argv_with_terminal() {
        let (_, _, flags, _) =
            parse_launch_argv(&s(&["claude", "--terminal", "kitty-tab"])).unwrap();
        assert_eq!(flags.terminal, Some("kitty-tab".to_string()));
    }

    #[test]
    fn test_parse_launch_argv_skips_global_flags() {
        let (count, tool, _, _) =
            parse_launch_argv(&s(&["--name", "bot", "--go", "2", "codex"])).unwrap();
        assert_eq!(count, 2);
        assert_eq!(tool, "codex");
    }

    #[test]
    fn test_parse_launch_argv_empty_fails() {
        assert!(parse_launch_argv(&[]).is_err());
    }

    #[test]
    fn test_primary_tool_args_are_concatenated_verbatim() {
        for (tool, field) in [
            ("claude", "claude_args"),
            ("gemini", "gemini_args"),
            ("codex", "codex_args"),
        ] {
            let mut config = HcomConfig::default();
            config.set_field(field, "--future-config value").unwrap();
            let cli = s(&["--future-upstream-flag", "raw-value"]);
            let merged = merge_tool_args(&lt(tool), &cli, &config);
            assert_eq!(
                merged,
                s(&[
                    "--future-config",
                    "value",
                    "--future-upstream-flag",
                    "raw-value"
                ])
            );
        }
    }

    #[test]
    fn test_merge_tool_args_applies_config_for_opencode_family_and_kimi() {
        // These tools previously fell through to the `_` pass-through arm, which
        // silently dropped their `*_args` config at launch.
        let cli = s(&["--yolo"]);
        for (tool, field) in [
            ("opencode", "opencode_args"),
            ("kilo", "kilo_args"),
            ("kimi", "kimi_args"),
        ] {
            let mut config = HcomConfig::default();
            config.set_field(field, "--model from-config").unwrap();
            let merged = merge_tool_args(&lt(tool), &cli, &config);
            assert_eq!(
                merged,
                s(&["--model", "from-config", "--yolo"]),
                "config args must be merged for {tool}"
            );
        }
    }

    #[test]
    fn test_parse_launch_argv_name_after_tool_args() {
        // --name after tool args should be stripped, not passed as tool arg
        let (count, tool, flags, args) = parse_launch_argv(&s(&[
            "1", "claude", "--model", "haiku", "--tag", "test-cl", "--name", "nafo",
        ]))
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(tool, "claude");
        assert_eq!(flags.tag, Some("test-cl".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_go_after_tool_args() {
        // --go after tool args should be stripped
        let (_, _, _, args) =
            parse_launch_argv(&s(&["claude", "--model", "haiku", "--go"])).unwrap();
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_hcom_prompt() {
        let (_, _, flags, args) = parse_launch_argv(&s(&[
            "claude",
            "--hcom-prompt",
            "do the thing",
            "--model",
            "haiku",
        ]))
        .unwrap();
        assert_eq!(flags.initial_prompt, Some("do the thing".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_hcom_system_prompt() {
        let (_, _, flags, args) = parse_launch_argv(&s(&[
            "claude",
            "--hcom-system-prompt",
            "you are helpful",
            "--model",
            "haiku",
        ]))
        .unwrap();
        assert_eq!(flags.system_prompt, Some("you are helpful".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_hcom_title() {
        let (_, _, flags, args) = parse_launch_argv(&s(&[
            "claude",
            "--hcom-title",
            "zagdb: rc.48 roll",
            "--model",
            "haiku",
        ]))
        .unwrap();
        assert_eq!(flags.title, Some("zagdb: rc.48 roll".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));

        let (_, _, flags, _) =
            parse_launch_argv(&s(&["claude", "--hcom-title=zagdb: rc.48 roll"])).unwrap();
        assert_eq!(flags.title, Some("zagdb: rc.48 roll".to_string()));
    }

    #[test]
    fn test_parse_launch_argv_system_legacy_alias() {
        let (_, _, flags, args) =
            parse_launch_argv(&s(&["claude", "--system", "you are helpful"])).unwrap();
        assert_eq!(flags.system_prompt, Some("you are helpful".to_string()));
        assert!(args.is_empty());
    }

    #[test]
    fn test_parse_launch_argv_batch_id() {
        let (_, _, flags, args) = parse_launch_argv(&s(&[
            "claude",
            "--batch-id",
            "batch-123",
            "--model",
            "haiku",
        ]))
        .unwrap();
        assert_eq!(flags.batch_id, Some("batch-123".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_device() {
        let (_, _, flags, args) =
            parse_launch_argv(&s(&["claude", "--device", "ABCD", "--model", "haiku"])).unwrap();
        assert_eq!(flags.device, Some("ABCD".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_prepare_launch_execution_claude_print_adds_background_defaults() {
        // Explicit `-p` opts into print mode → detached print-mode defaults applied.
        let config = HcomConfig::default();
        let (args, background) =
            prepare_launch_execution(&lt("claude"), &s(&["-p"]), &config, true);
        assert!(background);

        assert!(
            args.windows(2)
                .any(|w| w == ["--output-format", "stream-json"])
        );
        assert!(args.iter().any(|arg| arg == "--verbose"));
    }

    #[test]
    fn test_prepare_launch_execution_headless_no_print_flag_stays_pty() {
        // `hcom claude --headless` (no -p) is the live PTY session now — no -p is
        // injected and no print-mode defaults are added.
        let config = HcomConfig::default();
        let (args, background) = prepare_launch_execution(&lt("claude"), &s(&[]), &config, true);
        assert!(background);
        assert!(
            !args
                .iter()
                .any(|arg| matches!(arg.as_str(), "-p" | "--print"))
        );
        assert!(!args.iter().any(|arg| arg == "--output-format"));
    }

    #[test]
    fn test_prepare_launch_execution_headless_positional_prompt_stays_pty() {
        // `hcom claude --headless "task text"` — positional prompt, no -p → PTY.
        let config = HcomConfig::default();
        let (args, _background) =
            prepare_launch_execution(&lt("claude"), &s(&["task text"]), &config, true);
        assert_eq!(args, s(&["task text"]));
    }

    #[test]
    fn test_prepare_launch_execution_headless_only_applies_to_claude() {
        // --headless on other tools must not grow a -p; that flag is Claude-specific.
        let config = HcomConfig::default();
        let (args, _bg) = prepare_launch_execution(&lt("codex"), &s(&[]), &config, true);
        assert!(!args.iter().any(|t| t == "-p"));
    }

    #[test]
    fn test_prepare_launch_execution_interactive_claude_unchanged() {
        // Foreground `hcom claude` (no --headless, no -p) stays untouched.
        let config = HcomConfig::default();
        let (args, background) = prepare_launch_execution(&lt("claude"), &s(&[]), &config, false);
        assert!(!background);
        assert!(args.is_empty());
    }

    #[test]
    fn test_validate_claude_print_defers_prompt_validation_to_claude() {
        assert!(validate_claude_headless_launch("claude", true, &s(&["-p"]), None).is_ok());
    }

    #[test]
    fn test_validate_claude_print_accepts_cli_prompt() {
        assert!(
            validate_claude_headless_launch("claude", true, &s(&["-p", "say hi in hcom"]), None)
                .is_ok()
        );
    }

    #[test]
    fn test_validate_claude_print_accepts_hcom_prompt() {
        assert!(
            validate_claude_headless_launch("claude", true, &s(&["-p"]), Some("say hi in hcom"))
                .is_ok()
        );
    }

    #[test]
    fn test_validate_claude_headless_pty_allows_no_prompt() {
        // Bare `hcom claude --headless` (no -p) is a valid live-session launch —
        // the PTY wrapper keeps the TUI alive waiting for hcom inject.
        assert!(validate_claude_headless_launch("claude", true, &[], None).is_ok());
    }

    #[test]
    fn test_launch_result_json_roundtrip() {
        let result = LaunchResult {
            tool: "claude".to_string(),
            batch_id: "batch-1".to_string(),
            launched: 1,
            failed: 0,
            background: true,
            log_files: vec!["/tmp/test.log".to_string()],
            handles: vec![serde_json::json!({"instance_name": "luna"})],
            errors: Vec::new(),
        };
        let parsed = launch_result_from_json(&launch_result_to_json(&result)).unwrap();
        assert_eq!(parsed.tool, "claude");
        assert_eq!(parsed.batch_id, "batch-1");
        assert_eq!(parsed.launched, 1);
        assert!(parsed.background);
    }

    #[test]
    fn test_format_inline_launch_readiness_ready() {
        let result = LaunchResult {
            tool: "codex".to_string(),
            batch_id: "batch-1".to_string(),
            launched: 1,
            failed: 0,
            background: false,
            log_files: Vec::new(),
            handles: vec![serde_json::json!({"instance_name": "luna"})],
            errors: Vec::new(),
        };

        let line = format_inline_launch_readiness(
            InlineLaunchReadiness::Ready,
            &result,
            &["luna".to_string()],
            2.2,
            &[],
            None,
        );

        assert_eq!(line, "Launch ready: luna (1/1 ready, 2.2s).");
    }

    /// A live launch past its window reports `launch pending` and exits 0 —
    /// the machine-greppable wording ffc-47uy6 replaced `Still launching`
    /// (which paired with exit 2) with. The follow-up command survives.
    #[test]
    fn test_format_inline_launch_readiness_pending_has_followup_command() {
        let result = LaunchResult {
            tool: "gemini".to_string(),
            batch_id: "batch-2".to_string(),
            launched: 1,
            failed: 0,
            background: false,
            log_files: Vec::new(),
            handles: vec![serde_json::json!({"instance_name": "mari"})],
            errors: Vec::new(),
        };

        let line = format_inline_launch_readiness(
            InlineLaunchReadiness::Pending,
            &result,
            &[],
            10.0,
            &[],
            Some(4242),
        );

        assert!(line.contains("Launch pending: still starting after 10.0s"));
        assert!(
            line.contains("tool process 4242 alive"),
            "the pending line names the live TOOL, not the wrapper: {line}"
        );
        assert!(
            line.contains("it will report ready on its own (mari, 0/1 ready, batch: batch-2)"),
            "the pending line must name the seat and its progress: {line}"
        );
        assert!(line.contains("hcom events launch batch-2 --timeout 30"));
        assert!(
            !line.contains("launch refused"),
            "a live launch is never reported as refused: {line}"
        );
    }

    /// A launch with no recorded pid is unverified, not pending: exit 0 must
    /// mean a verified-alive tool, and the wording must never say "refused".
    #[test]
    fn test_format_inline_launch_readiness_unverified_names_the_seat() {
        let result = LaunchResult {
            tool: "claude".to_string(),
            batch_id: "batch-4".to_string(),
            launched: 1,
            failed: 0,
            background: false,
            log_files: Vec::new(),
            handles: vec![serde_json::json!({"instance_name": "nola"})],
            errors: Vec::new(),
        };

        let line = format_inline_launch_readiness(
            InlineLaunchReadiness::Unverified,
            &result,
            &[],
            10.0,
            &["nola".to_string()],
            None,
        );

        assert!(
            line.contains("Launch unverified: no process recorded for nola"),
            "the unverified line must say what is missing: {line}"
        );
        assert!(
            !line.to_lowercase().contains("refused"),
            "an unverified launch is not a refusal: {line}"
        );
    }

    /// The exit-code contract callers depend on: a slow-but-live launch is not
    /// a failure, a real failure still is, and an unprovable one never claims
    /// success.
    #[test]
    fn test_readiness_exit_code_separates_pending_from_failed() {
        assert_eq!(
            readiness_exit_code(Some(InlineLaunchReadiness::Pending), 0),
            0,
            "a live launch past its window must not read as a failure"
        );
        assert_eq!(
            readiness_exit_code(Some(InlineLaunchReadiness::Failed), 0),
            1
        );
        assert_eq!(
            readiness_exit_code(Some(InlineLaunchReadiness::Blocked), 0),
            2
        );
        assert_eq!(
            readiness_exit_code(Some(InlineLaunchReadiness::Unverified), 0),
            2,
            "no recorded pid proves nothing, so it must not exit 0"
        );
        assert_eq!(
            readiness_exit_code(Some(InlineLaunchReadiness::Ready), 0),
            0
        );
        assert_eq!(readiness_exit_code(None, 1), 1);
    }

    /// The launched tool's names come from its spec, so a launch through an
    /// alias (`agy`, `cursor-agent`) is still recognized as that tool, and the
    /// PTY surface resolves to claude's binary.
    #[test]
    fn test_launched_tool_names_cover_aliases() {
        assert_eq!(launched_tool_names("claude"), vec!["claude"]);
        assert_eq!(launched_tool_names("claude-pty"), vec!["claude"]);
        assert_eq!(
            launched_tool_names("antigravity"),
            vec!["agy"],
            "the spec's own alias repeats its cli_binary: one name, not two"
        );
        assert_eq!(launched_tool_names("cursor"), vec!["cursor-agent"]);
        assert_eq!(launched_tool_names("omp"), vec!["omp", "omp-agent"]);
        assert!(
            launched_tool_names("not-a-tool").is_empty(),
            "an unknown tool names nothing, so no descendant can be mistaken for it"
        );
    }

    #[test]
    fn test_format_inline_launch_readiness_failed_includes_detail() {
        let result = LaunchResult {
            tool: "claude".to_string(),
            batch_id: "batch-3".to_string(),
            launched: 1,
            failed: 0,
            background: true,
            log_files: Vec::new(),
            handles: vec![serde_json::json!({"instance_name": "nola"})],
            errors: Vec::new(),
        };

        let line = format_inline_launch_readiness(
            InlineLaunchReadiness::Failed,
            &result,
            &[],
            0.5,
            &["nola: executable not found".to_string()],
            None,
        );

        assert_eq!(
            line,
            "Launch failed: nola: executable not found (batch: batch-3)."
        );
    }

    #[test]
    fn test_build_remote_launch_output_prefers_remote_background() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let output = build_remote_launch_output(
            &db,
            &GlobalFlags::default(),
            &LaunchResult {
                tool: "claude".to_string(),
                batch_id: "batch-1".to_string(),
                launched: 1,
                failed: 0,
                background: false,
                log_files: Vec::new(),
                handles: Vec::new(),
                errors: Vec::new(),
            },
            Some("ops".to_string()),
            Some("kitty".to_string()),
            Some(false),
        );

        assert_eq!(output.tool, "claude");
        assert_eq!(output.tag.as_deref(), Some("ops"));
        assert_eq!(output.terminal.as_deref(), Some("kitty"));
        assert!(!output.background);
        assert_eq!(output.run_here, Some(false));
    }

    #[test]
    fn test_build_remote_launch_output_uses_remote_launch_result_background() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();

        let output = build_remote_launch_output(
            &db,
            &GlobalFlags::default(),
            &LaunchResult {
                tool: "codex".to_string(),
                batch_id: "batch-2".to_string(),
                launched: 1,
                failed: 0,
                background: false,
                log_files: Vec::new(),
                handles: Vec::new(),
                errors: Vec::new(),
            },
            None,
            None,
            None,
        );

        assert_eq!(output.tool, "codex");
        assert!(!output.background);
    }

    #[test]
    fn test_is_background_claude_headless() {
        assert!(is_background_from_args(
            &lt("claude"),
            &s(&["-p", "fix tests", "--output-format", "json"])
        ));
    }

    #[test]
    fn test_is_background_claude_interactive() {
        assert!(!is_background_from_args(
            &lt("claude"),
            &s(&["--model", "haiku"])
        ));
    }

    #[test]
    fn test_resolve_launcher_name_prefers_explicit_name() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        let flags = GlobalFlags {
            name: Some("explicit".to_string()),
            go: false,
        };

        let name = resolve_launcher_name(&db, &flags, Some("pid-123"));
        assert_eq!(name, "explicit");
    }

    #[test]
    fn test_resolve_launcher_name_falls_back_to_process_binding() {
        let _env = crate::hooks::test_helpers::isolated_test_env();
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let db = HcomDb::open_raw(&db_path).unwrap();
        db.init_db().unwrap();
        let now = crate::shared::time::now_epoch_f64();
        db.conn()
            .execute(
                "INSERT INTO instances (name, session_id, directory, last_event_id, last_stop, created_at, status, status_time, status_context, tool)
                 VALUES (?1, '', '.', 0, 0, ?2, 'active', ?2, 'test', 'claude')",
                rusqlite::params!["bound", now],
            )
            .unwrap();
        db.set_process_binding("pid-123", "", "bound").unwrap();

        let name = resolve_launcher_name(&db, &GlobalFlags::default(), Some("pid-123"));
        assert_eq!(name, "bound");
    }

    #[test]
    fn test_parse_launch_argv_dir_flag() {
        let (_, _, flags, args) =
            parse_launch_argv(&s(&["claude", "--dir", "/tmp/project", "--model", "haiku"]))
                .unwrap();
        assert_eq!(flags.dir, Some("/tmp/project".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_dir_equals() {
        let (_, _, flags, args) =
            parse_launch_argv(&s(&["claude", "--dir=/tmp/project", "--model", "haiku"])).unwrap();
        assert_eq!(flags.dir, Some("/tmp/project".to_string()));
        assert_eq!(args, s(&["--model", "haiku"]));
    }

    #[test]
    fn test_parse_launch_argv_dir_not_passed_to_tool() {
        let (_, _, flags, args) =
            parse_launch_argv(&s(&["gemini", "--dir", "/tmp/proj", "-m", "flash"])).unwrap();
        assert_eq!(flags.dir, Some("/tmp/proj".to_string()));
        assert_eq!(args, s(&["-m", "flash"]));
    }
}
