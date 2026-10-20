use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use crate::tui::commands;
use crate::tui::model::Tool;
use crate::tui::rpc::{self, Response, build_launch_argv};

pub enum RpcOp {
    Send {
        recipients: Vec<String>,
        body: String,
        intent: Option<String>,
        reply_to: Option<u64>,
    },
    KillAgent {
        name: String,
    },
    ForkAgent {
        name: String,
        silent: bool,
    },
    ResumeAgent {
        name: String,
        silent: bool,
    },
    KillPid {
        pid: u32,
    },
    Tag {
        name: String,
        tag: String,
    },
    Launch {
        tool: Tool,
        count: u8,
        tag: String,
        headless: bool,
        headless_pty: bool,
        terminal: String,
        prompt: String,
    },
    RelayToggle {
        enable: bool,
    },
    RelayStatus,
    RelayNew,
    RelayConnect {
        token: String,
    },
    Command {
        cmd: String,
    },
}

pub struct RpcResult {
    pub op: RpcOp,
    pub result: Result<Response, String>,
}

pub struct RpcClient {
    tx: Sender<RpcOp>,
    rx: Receiver<RpcResult>,
    pending: usize,
}

impl RpcClient {
    pub fn start() -> Self {
        let (tx_req, rx_req) = mpsc::channel::<RpcOp>();
        let (tx_res, rx_res) = mpsc::channel::<RpcResult>();

        thread::spawn(move || {
            for op in rx_req {
                let result = run_op(&op);
                let _ = tx_res.send(RpcResult { op, result });
            }
        });

        Self {
            tx: tx_req,
            rx: rx_res,
            pending: 0,
        }
    }

    pub fn submit(&mut self, op: RpcOp) -> Result<(), String> {
        self.tx
            .send(op)
            .map_err(|e| format!("rpc queue send: {}", e))?;
        self.pending += 1;
        Ok(())
    }

    pub fn drain(&mut self) -> Vec<RpcResult> {
        let mut out = Vec::new();
        while let Ok(result) = self.rx.try_recv() {
            self.pending = self.pending.saturating_sub(1);
            out.push(result);
        }
        out
    }

    pub fn pending_count(&self) -> usize {
        self.pending
    }
}

fn run_op(op: &RpcOp) -> Result<Response, String> {
    match op {
        RpcOp::Send {
            recipients,
            body,
            intent,
            reply_to,
        } => {
            // The compose box is the one path that speaks as the local
            // operator. `--from bigboss` is refused on the CLI, so this goes
            // through the in-process send instead of a subprocess argv; the
            // send returns its feedback text rather than printing, keeping
            // the TUI's stdout (and its sent-status labels) as they were.
            let db = crate::db::HcomDb::open().map_err(|e| e.to_string())?;
            match crate::commands::send::send_as_operator(
                &db,
                recipients,
                body,
                intent.as_deref(),
                *reply_to,
            ) {
                Ok(stdout) => Ok(Response {
                    exit_code: 0,
                    stdout,
                    stderr: String::new(),
                }),
                Err(message) => Ok(Response {
                    exit_code: 1,
                    stdout: String::new(),
                    stderr: format!("Error: {message}"),
                }),
            }
        }

        RpcOp::Tag { name, tag } => commands::run_native(&[
            "config".into(),
            "-i".into(),
            name.clone(),
            "tag".into(),
            tag.clone(),
        ]),

        RpcOp::RelayToggle { enable } => {
            let flag = if *enable { "on" } else { "off" };
            commands::run_native(&["relay".into(), flag.into()])
        }

        RpcOp::RelayStatus => commands::run_native(&["relay".into()]),

        RpcOp::RelayNew => commands::run_native(&["relay".into(), "new".into()]),

        RpcOp::RelayConnect { token } => {
            commands::run_native(&["relay".into(), "connect".into(), token.clone()])
        }

        RpcOp::Command { cmd } => {
            let argv = rpc::parse_command_argv(cmd)?;
            commands::run_native(&argv)
        }

        RpcOp::KillAgent { name } => commands::run_native(&["kill".into(), name.clone()]),

        RpcOp::ForkAgent { name, .. } => {
            commands::run_native(&["f".into(), name.clone(), "--no-run-here".into()])
        }

        RpcOp::ResumeAgent { name, .. } => {
            commands::run_native(&["r".into(), name.clone(), "--no-run-here".into()])
        }

        RpcOp::KillPid { pid } => commands::run_native(&["kill".into(), pid.to_string()]),

        RpcOp::Launch {
            tool,
            count,
            tag,
            headless,
            headless_pty,
            terminal,
            prompt,
        } => {
            let argv = build_launch_argv(
                tool.clone(),
                *count,
                tag,
                *headless,
                *headless_pty,
                terminal,
                prompt,
            );
            commands::run_native(&argv)
        }
    }
}
