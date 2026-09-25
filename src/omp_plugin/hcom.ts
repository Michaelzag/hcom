import type { ExtensionAPI, ExtensionContext, InputEvent } from "@oh-my-pi/pi-coding-agent";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createServer, type Server } from "node:net";

const HCOM_DIR = process.env.HCOM_DIR || `${homedir()}/.hcom`;
const LOG_PATH = `${HCOM_DIR}/.tmp/logs/hcom.log`;

type HcomResult = {
	code: number;
	stdout: string;
	stderr: string;
};

function log(
	level: "DEBUG" | "INFO" | "WARN" | "ERROR",
	event: string,
	instance?: string | null,
	extra?: Record<string, unknown>,
) {
	const entry = JSON.stringify({
		ts: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
		level,
		subsystem: "plugin",
		event,
		...(instance ? { instance } : {}),
		...extra,
	});
	try {
		mkdirSync(dirname(LOG_PATH), { recursive: true });
		appendFileSync(LOG_PATH, `${entry}\n`);
	} catch {}
}

const HCOM_TIMEOUT_MS = 1800;
const OMP_ID_PATTERN = /^omp-(\d+)-.+$/;
const LAUNCHER_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function ompIdPid(id: string): number | null {
	const match = OMP_ID_PATTERN.exec(id);
	if (!match) return null;
	const pid = Number(match[1]);
	return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
}

function procComm(pid: number): string | null {
	try {
		return readFileSync(`/proc/${pid}/comm`, "utf8").trim();
	} catch {
		return null;
	}
}

function ppidOf(pid: number): number | null {
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
		const close = stat.lastIndexOf(")");
		if (close < 0) return null;
		const ppid = Number(stat.slice(close + 1).trim().split(/\s+/)[1]);
		return Number.isSafeInteger(ppid) && ppid > 0 ? ppid : null;
	} catch {
		return null;
	}
}

function ancestorPids(): Set<number> {
	const pids = new Set<number>();
	let pid: number | null = process.pid;
	for (let depth = 0; pid !== null && !pids.has(pid) && depth < 4096; depth++) {
		pids.add(pid);
		pid = ppidOf(pid);
	}
	return pids;
}

function mintProcessId(): string {
	return `omp-${process.pid}-${randomBytes(4).toString("hex")}-${randomBytes(4).toString("hex")}`;
}

function resolveProcessId(): { id: string; minted: boolean; reason: string } {
	const existing = process.env.HCOM_PROCESS_ID;
	if (!existing) return { id: mintProcessId(), minted: true, reason: "missing" };
	const pid = ompIdPid(existing);
	if (pid === null) {
		// Only a launcher UUID can retain its inherited identity. The Rust
		// hook, not this shape check, proves its row and ancestor pid.
		if (inheritedLauncherCandidate) return { id: existing, minted: false, reason: "launcher_candidate" };
		return { id: mintProcessId(), minted: true, reason: "inherited_non_launcher" };
	}
	if (process.platform !== "linux") {
		return { id: mintProcessId(), minted: true, reason: "non_linux" };
	}
	if (!ancestorPids().has(pid)) {
		return { id: mintProcessId(), minted: true, reason: "non_ancestor" };
	}
	if (procComm(pid) !== "omp") {
		return { id: mintProcessId(), minted: true, reason: "ancestor_not_omp" };
	}
	return { id: existing, minted: false, reason: "trusted_omp_ancestor" };
}

const inheritedLauncherCandidate =
	process.env.HCOM_LAUNCHED === "1" &&
	!!process.env.HCOM_PROCESS_ID &&
	LAUNCHER_ID_PATTERN.test(process.env.HCOM_PROCESS_ID);
const resolvedIdentity = resolveProcessId();
process.env.HCOM_PROCESS_ID = resolvedIdentity.id;
log("INFO", "identity_resolved", null, {
	minted: resolvedIdentity.minted,
	reason: resolvedIdentity.reason,
});

// The Rust gate reads `plain_sessions` as `!is_falsy(value)` (src/config.rs
// `is_falsy`, applied by `HcomConfig::set_field`): exactly these six values
// are false, case-sensitive and untrimmed; everything else is true.
const RUST_FALSY_VALUES: Record<string, true> = { "0": true, false: true, False: true, no: true, off: true, "": true };
export function plainSessionsValueEnabled(value: string): boolean {
	return !Object.hasOwn(RUST_FALSY_VALUES, value);
}

let plainSessionsPromise: Promise<boolean> | null = null;
function plainSessionsEnabled(): Promise<boolean> {
	// `--json` carries the raw value; the plain form prints "(not set)" for an
	// empty one instead of the value itself.
	plainSessionsPromise ??= hcom(["config", "--json", "plain_sessions"]).then((result) => {
		if (result.code !== 0) return false;
		const value = JSON.parse(result.stdout).HCOM_PLAIN_SESSIONS;
		return typeof value === "string" && plainSessionsValueEnabled(value);
	}).catch(() => false);
	return plainSessionsPromise;
}

function hcom(args: string[]): Promise<HcomResult> {
	return new Promise((resolve) => {
		const child = spawn("hcom", args, { stdio: ["ignore", "pipe", "pipe"] });
		let stdout = "";
		let stderr = "";
		let settled = false;
		const finish = (code: number) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolve({ code, stdout, stderr });
		};
		const timer = setTimeout(() => {
			try {
				child.kill("SIGTERM");
			} catch {}
			finish(124);
		}, HCOM_TIMEOUT_MS);
		timer.unref?.();
		child.stdout.setEncoding("utf8");
		child.stderr.setEncoding("utf8");
		child.stdout.on("data", (chunk) => {
			stdout += chunk;
		});
		child.stderr.on("data", (chunk) => {
			stderr += chunk;
		});
		child.on("error", (error) => {
			stderr = stderr || String(error);
			finish(127);
		});
		child.on("close", (code) => finish(code === null ? 1 : code));
	});
}

function formatMessagesForInjection(messages: any[], recipientName: string): string {
	const parts = messages.map((m: any) => {
		const prefix = m.intent
			? m.thread
				? `[${m.intent}:${m.thread} #${m.event_id}]`
				: `[${m.intent} #${m.event_id}]`
			: m.thread
				? `[thread:${m.thread} #${m.event_id}]`
				: `[new message #${m.event_id}]`;
		return `${prefix} ${m.from} -> ${recipientName}: ${m.message}`;
	});
	if (messages.length === 1) return `<hcom>${parts[0]}</hcom>`;
	return `<hcom>[${messages.length} new messages] | ${parts.join(" | ")}</hcom>`;
}

function isBodylessWake(text: string): boolean {
	const trimmed = text.trim();
	return trimmed === "<hcom>" || trimmed === "<hcom></hcom>";
}

// Same-process latch: OMP task subagents load a fresh extension instance in the
// parent Node process (SessionShutdownEvent has no sessionId). The first binder
// owns hcom identity; nested instances skip bind/stop so dispose cannot soft-stop
// the parent (lefo / task repro). ExtensionContext does not expose taskDepth.
const IDENTITY_REGISTRY_KEY = Symbol.for("hcom.omp.identity");
const IDENTITY_OWNER_ENV = "HCOM_OMP_IDENTITY_OWNER";

type OmpIdentityRegistry = {
	owner: string | null;
	tearingDown: boolean;
	// Termination signal seen by this process (recorded, never acted on here).
	exitSignal: NodeJS.Signals | null;
	// Full release owed at process exit after an owner soft-stop.
	pendingExitRelease: { name: string; reason: string } | null;
	signalRecordersInstalled: boolean;
	exitListenerInstalled: boolean;
};

function getIdentityRegistry(): OmpIdentityRegistry {
	const g = globalThis as Record<symbol, OmpIdentityRegistry | undefined>;
	if (!g[IDENTITY_REGISTRY_KEY]) {
		g[IDENTITY_REGISTRY_KEY] = {
			owner: null,
			tearingDown: false,
			exitSignal: null,
			pendingExitRelease: null,
			signalRecordersInstalled: false,
			exitListenerInstalled: false,
		};
	}
	return g[IDENTITY_REGISTRY_KEY]!;
}

function syncIdentityOwnerEnv(owner: string | null): void {
	if (owner) process.env[IDENTITY_OWNER_ENV] = owner;
	else delete process.env[IDENTITY_OWNER_ENV];
}

function clearIdentityOwnership(): void {
	const reg = getIdentityRegistry();
	reg.owner = null;
	reg.tearingDown = false;
	syncIdentityOwnerEnv(null);
}

// Passive, once per process: record which termination signal arrived. omp's
// postmortem already owns these signals (cleanup, then exit without firing
// `exit`); an extra listener does not change exit behavior.
function installExitSignalRecorders(reg: OmpIdentityRegistry): void {
	if (reg.signalRecordersInstalled) return;
	reg.signalRecordersInstalled = true;
	for (const signal of ["SIGTERM", "SIGHUP", "SIGINT"] as const) {
		process.on(signal, () => {
			reg.exitSignal = signal;
		});
	}
}

// Full owner release, synchronous. The signal path and the exit listener both
// run it while this omp process is still alive, which the release relies on:
// it spares the caller's ancestry, omp included. The 10s budget outlasts the
// reap's TERM + KILL waits (5s + 2s), so live MCP/LSP carriers cannot get it
// killed before it commits, as the async hcom() cap (HCOM_TIMEOUT_MS) would.
function releaseOwnerSync(name: string, reason: string): boolean {
	try {
		const result = spawnSync("hcom", ["omp-stop", "--name", name, "--reason", reason], {
			stdio: "ignore",
			timeout: 10000,
		});
		if (result.status === 0) return true;
		log("WARN", "plugin.session_shutdown_stop_failed", name, {
			exit_code: result.status,
			signal: result.signal,
			error: result.error ? String(result.error) : undefined,
			reason,
			soft: false,
		});
	} catch (error) {
		log("ERROR", "plugin.session_shutdown_stop_error", name, {
			error: String(error),
			reason,
			soft: false,
		});
	}
	return false;
}

// Arm the full release for process exit. Graceful quits (/exit, /quit, Ctrl-D,
// double Ctrl-C, print end, RPC EOF) call process.exit, which fires `exit`, so
// the soft-kept row is released there. /restart execvp's the same pid without
// firing `exit`, so the row stays for the new image to rebind.
function armExitRelease(reg: OmpIdentityRegistry, name: string, reason: string): void {
	reg.pendingExitRelease = { name, reason };
	if (reg.exitListenerInstalled) return;
	reg.exitListenerInstalled = true;
	process.on("exit", () => {
		const pending = reg.pendingExitRelease;
		if (!pending) return;
		reg.pendingExitRelease = null;
		releaseOwnerSync(pending.name, pending.reason);
	});
}

export default function hcomExtension(pi: ExtensionAPI) {
	let instanceName: string | null = null;
	let sessionId: string | null = null;
	let ownsIdentity = false;
	let nestedOptOut = false;
	let bootstrapText: string | null = null;
	let bindingPromise: Promise<void> | null = null;
	let notifyServer: Server | null = null;
	let notifyPort: number | null = null;
	let currentCtx: ExtensionContext | null = null;
	let pendingAckId: number | null = null;
	let ackInFlight: Promise<boolean> | null = null;
	let bindingGeneration = 0;
	let deliveryInFlight = false;
	let deliveryPending = false; // a wake arrived while delivery was gated; replay it once clear
	let deliveryRetryScheduled = false; // dedup the queued replay pass
	let reconcileTimer: ReturnType<typeof setInterval> | null = null;
	let reconcileInFlight = false;
	let bootstrapInjectedForSession: string | null = null;
	let lastReportedStatusKey: string | null = null;
	let lastPendingPollAt = 0;
	let agentActive = false;
	let idleTimer: ReturnType<typeof setTimeout> | null = null;

	const PENDING_POLL_MS = 60_000;
	const FALLBACK_PENDING_POLL_MS = 5_000;
	const IDLE_DEBOUNCE_MS = 250;

	function statusKey(status: string, context: string, detail: string): string {
		return `${status}\0${context}\0${detail}`;
	}

	function isBoundSession(candidateSessionId?: string | null): boolean {
		return !candidateSessionId || !sessionId || candidateSessionId === sessionId;
	}

	/** The job-snapshot fields the context query reads. */
	interface AsyncJobSnapshotView {
		running: readonly unknown[];
		delivery: { queued: number; delivering: boolean };
	}

	// `getAsyncJobSnapshot()` is newer than the SDK types hcom pins for the
	// plugin typecheck (17.0.6); the omp this runs inside (>= 18.0) has it. Type
	// the context once with the method optional so a host without it reports the
	// job count as unknown instead of throwing.
	function asyncJobSnapshot(ctx: ExtensionContext): AsyncJobSnapshotView | null {
		const host: ExtensionContext & {
			getAsyncJobSnapshot?: () => AsyncJobSnapshotView | null;
		} = ctx;
		return host.getAsyncJobSnapshot?.() ?? null;
	}

	// One reply line for hcom's `list --context` query (`{"q":"context"}\n`).
	// Usage is null when the seat cannot compute it and the job count is null
	// when the session has no job manager; hcom renders both as unknown, never 0.
	function contextReply(): string {
		try {
			const usage = currentCtx?.getContextUsage() ?? null;
			const snapshot = currentCtx ? asyncJobSnapshot(currentCtx) : null;
			const jobs = snapshot
				? snapshot.running.length +
					snapshot.delivery.queued +
					(snapshot.delivery.delivering ? 1 : 0)
				: null;
			return JSON.stringify({
				tokens: usage ? usage.tokens : null,
				contextWindow: usage ? usage.contextWindow : null,
				percent: usage ? usage.percent : null,
				jobs,
			});
		} catch (error) {
			log("WARN", "notify_server.context_query_failed", instanceName, {
				error: String(error),
			});
			return JSON.stringify({ tokens: null, contextWindow: null, percent: null, jobs: null });
		}
	}

	function startNotifyServer(): Promise<number | null> {
		if (notifyServer && notifyPort) return Promise.resolve(notifyPort);
		return new Promise((resolve) => {
			const server = createServer((socket) => {
				let settled = false;
				// Connection that sends no context request: end it and deliver
				// pending messages, exactly as before. Every existing wake sender
				// connect-drops, so "close" below is what fires this.
				const wake = () => {
					if (settled) return;
					settled = true;
					try {
						socket.end();
					} catch {}
					log("DEBUG", "notify_server.wake", instanceName, { pending_ack: pendingAckId });
					if (currentCtx) void deliverPending(currentCtx);
				};
				let buffer = "";
				socket.setEncoding("utf8");
				socket.on("data", (chunk: Buffer | string) => {
					if (settled) return;
					buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
					const newline = buffer.indexOf("\n");
					if (newline < 0) return;
					let reply: string | null = null;
					try {
						const request: unknown = JSON.parse(buffer.slice(0, newline).trim());
						if (
							request &&
							typeof request === "object" &&
							"q" in request &&
							request.q === "context"
						) {
							reply = contextReply();
						}
					} catch {}
					if (reply === null) {
						// Not a context query — keep today's wake behavior.
						wake();
						return;
					}
					settled = true;
					socket.end(`${reply}\n`);
					log("DEBUG", "notify_server.context_query", instanceName, {});
				});
				socket.on("close", wake);
				socket.on("error", () => {});
			});
			server.on("error", (error) => {
				log("ERROR", "notify_server.start_failed", instanceName, { error: String(error) });
				resolve(null);
			});
			server.listen(0, "127.0.0.1", () => {
				notifyServer = server;
				const address = server.address();
				notifyPort = typeof address === "object" && address ? address.port : null;
				log("INFO", "notify_server.started", instanceName, { port: notifyPort });
				resolve(notifyPort);
			});
		});
	}

	function stopNotifyServer(): void {
		if (notifyServer) {
			try {
				notifyServer.close();
			} catch {}
		}
		notifyServer = null;
		notifyPort = null;
	}

	function nestedSkipReason(): string | null {
		const reg = getIdentityRegistry();
		if (nestedOptOut) return "sticky_nested_opt_out";
		// Owner may rebind after a failed soft-stop while keepOwner retained the latch;
		// tearingDown only blocks nested/non-owner extensions.
		if (reg.tearingDown && !ownsIdentity) return "tearing_down";
		if (reg.owner && !ownsIdentity) return "nested_registry";
		if (!reg.owner && process.env[IDENTITY_OWNER_ENV] && !ownsIdentity) return "nested_env";
		return null;
	}

	// Probe gate: a throwaway omp process that inherited a bound seat's env
	// (`omp -p` print probes, `--no-session` runs, subagent probes) must stay
	// completely inert — no omp-start bind, no config read, no status, no
	// omp-stop/release, no notify server, no delivery. handle_start recovers
	// the seat's binding by HCOM_INSTANCE_NAME / process binding and overwrites
	// the seat's session with the probe's (lave / demo incidents). Probe when
	// (a) there is no UI: print/RPC/json runs — hcom never launches those modes
	// (launch_arg_validation.rs rejects -p/--print/--mode) — or (b) the session
	// is not persisted: the ephemeral session manager keeps no session file,
	// while a persistent one has its path allocated before the first write.
	// Computed once per process: mode and persistence do not change across
	// session switches.
	let probeReason: string | null | undefined;

	function probeSkipReason(ctx: ExtensionContext): string | null {
		if (probeReason === undefined) {
			probeReason = !ctx.hasUI
				? "no_ui"
				: !ctx.sessionManager.getSessionFile()
					? "no_session_file"
					: null;
			log("INFO", probeReason ? "plugin.probe_inert" : "plugin.probe_checked", null, { reason: probeReason });
		}
		return probeReason;
	}

	async function bindIdentity(ctx: ExtensionContext): Promise<void> {
		currentCtx = ctx;
		if (probeSkipReason(ctx)) return;
		if (instanceName || bindingPromise) return bindingPromise ?? Promise.resolve();
		if (!inheritedLauncherCandidate && !(await plainSessionsEnabled())) return;
		const skipReason = nestedSkipReason();
		if (skipReason) {
			nestedOptOut = true;
			const reg = getIdentityRegistry();
			log("INFO", "plugin.bind_skipped_nested", null, {
				reason: skipReason,
				owner: reg.owner ?? process.env[IDENTITY_OWNER_ENV] ?? null,
			});
			return;
		}
		bindingPromise = (async () => {
			try {
				const reg = getIdentityRegistry();
				if ((reg.tearingDown && !ownsIdentity) || (reg.owner && !ownsIdentity)) {
					nestedOptOut = true;
					log("INFO", "plugin.bind_skipped_nested", null, {
						reason: reg.tearingDown && !ownsIdentity ? "tearing_down" : "nested_registry",
						owner: reg.owner,
					});
					return;
				}
				const sid = ctx.sessionManager.getSessionId();
				const transcriptPath = ctx.sessionManager.getSessionFile();
				const port = await startNotifyServer();
				const args = ["omp-start", "--session-id", sid, "--cwd", ctx.cwd];
				if (transcriptPath) args.push("--transcript-path", transcriptPath);
				if (port) args.push("--notify-port", String(port));
				let result = await hcom(args);
				if (result.code !== 0) {
					stopNotifyServer();
					log("WARN", "plugin.bind_failed", null, { exit_code: result.code, stderr: result.stderr.slice(0, 300) });
					return;
				}
				let json = JSON.parse(result.stdout || "{}");
				if (inheritedLauncherCandidate && json.error === "HCOM_PROCESS_ID not set" && (await plainSessionsEnabled())) {
					// The hook refused the inherited UUID. With the plain-session
					// opt-in, give this OMP process its own id and try only once.
					process.env.HCOM_PROCESS_ID = mintProcessId();
					log("INFO", "identity_resolved", null, { minted: true, reason: "unproven_launcher" });
					result = await hcom(args);
					if (result.code !== 0) {
						stopNotifyServer();
						log("WARN", "plugin.bind_failed", null, { exit_code: result.code, stderr: result.stderr.slice(0, 300) });
						return;
					}
					json = JSON.parse(result.stdout || "{}");
				}
				if (json.error || !json.name) {
					stopNotifyServer();
					log("WARN", "plugin.bind_failed", null, { error: json.error || "No instance bound to this process" });
					return;
				}
				instanceName = json.name;
				sessionId = json.session_id || sid;
				ownsIdentity = true;
				reg.owner = instanceName;
				syncIdentityOwnerEnv(instanceName ?? "1");
				// A re-bound row must never be released by an older armed exit release.
				reg.pendingExitRelease = null;
				installExitSignalRecorders(reg);
				bootstrapText = typeof json.bootstrap === "string" ? json.bootstrap : null;
				startReconcileTimer();
				log("INFO", "plugin.bound", instanceName, {
					session_id: sessionId,
					notify_port: port,
					bootstrap_len: bootstrapText?.length ?? 0,
				});
			} catch (error) {
				stopNotifyServer();
				log("ERROR", "plugin.bind_error", null, { error: String(error) });
			} finally {
				bindingPromise = null;
			}
		})();
		await bindingPromise;
	}

	async function fetchPending(): Promise<{ messages: any[]; maxId: number } | null> {
		if (probeReason) return null;
		if (!instanceName) return null;
		const result = await hcom(["omp-read", "--name", instanceName]);
		if (result.code !== 0) {
			log("WARN", "plugin.delivery_read_failed", instanceName, { exit_code: result.code, stderr: result.stderr.slice(0, 300) });
			return null;
		}
		let messages: any[] = [];
		try {
			messages = JSON.parse(result.stdout || "[]");
		} catch (error) {
			log("WARN", "plugin.delivery_parse_failed", instanceName, { error: String(error), raw: result.stdout.slice(0, 300) });
			return null;
		}
		if (!Array.isArray(messages) || messages.length === 0) return null;
		const maxId = Math.max(...messages.map((m: any) => m.event_id || 0));
		if (maxId <= 0) return null;
		return { messages, maxId };
	}

	async function deliverPending(ctx: ExtensionContext): Promise<boolean> {
		currentCtx = ctx;
		if (probeSkipReason(ctx)) return false;
		await bindIdentity(ctx);
		if (!instanceName || !sessionId) return false;
		if (!isBoundSession(ctx.sessionManager.getSessionId())) return false;
		if (deliveryInFlight || pendingAckId !== null) {
			// A delivery is mid-flight or awaiting ack. Drop nothing: record the wake
			// so it is replayed once clear, otherwise a message that arrives in this
			// window stays unread until an unrelated later wake (reconcile is idle-gated).
			deliveryPending = true;
			log("DEBUG", "plugin.delivery_skipped", instanceName, {
				reason: deliveryInFlight ? "delivery_in_flight" : "pending_ack_in_flight",
				pending_ack: pendingAckId,
				queued: true,
			});
			return false;
		}
		deliveryInFlight = true;
		try {
			const pending = await fetchPending();
			if (!pending) return false;
			const formatted = formatMessagesForInjection(pending.messages, instanceName);
			pendingAckId = pending.maxId;
			try {
				const isIdle = ctx.isIdle();
				if (isIdle) {
					await pi.sendUserMessage(formatted);
				} else {
					// Busy lane: `followUp`. The omp aside channel ("injected at
					// the next step boundary without interrupting") is internal
					// only — IRC records, advisor nits, job completions. The
					// extension API (SendUserMessageHandler in SDK 17.0.6) accepts
					// just `steer` | `followUp`, so `aside` never typechecked, and
					// worse, at runtime the session falls an unknown deliverAs
					// through to prompt() with steer-on-stream behavior — the old
					// code steered while claiming not to. `steer` is wrong here:
					// interrupts and can abort the rest of the tool batch.
					// `followUp` waits for the run to end (one probe measured
					// 44 s plus a turn boundary) but delivers visibly and never
					// interrupts. Revisit if the SDK exposes aside to extensions.
					await pi.sendUserMessage(formatted, { deliverAs: "followUp" });
				}
				const sender = String(pending.messages[0]?.from ?? "");
				await reportStatus(ctx, "active", sender ? `deliver:${sender}` : "deliver");
				log("INFO", "plugin.delivery_pending", instanceName, {
					count: pending.messages.length,
					pending_ack: pending.maxId,
					idle: isIdle,
				});
				await ackPending(isIdle ? "sendUserMessage" : "followUp");
				return true;
			} catch (error) {
				if (pendingAckId === pending.maxId) pendingAckId = null;
				log("ERROR", "plugin.delivery_send_failed", instanceName, { error: String(error) });
				return false;
			}
		} finally {
			deliveryInFlight = false;
			drainPendingDelivery("delivery_in_flight_wake");
		}
	}

	// Replay a wake that was queued while delivery was gated. Re-armed once nothing
	// is mid-flight and no ack is pending, so the same unread batch is not delivered
	// twice. The microtask + dedup flag collapse a burst of queued wakes into one pass.
	function schedulePendingDelivery(reason: string): void {
		if (deliveryRetryScheduled) return;
		deliveryRetryScheduled = true;
		log("DEBUG", "plugin.delivery_retry_scheduled", instanceName, { reason });
		queueMicrotask(() => {
			deliveryRetryScheduled = false;
			if (!instanceName || !currentCtx) return;
			void deliverPending(currentCtx);
		});
	}

	function drainPendingDelivery(reason: string): void {
		if (deliveryPending && !deliveryInFlight && pendingAckId === null) {
			deliveryPending = false;
			schedulePendingDelivery(reason);
		}
	}

	async function ackPending(source: string): Promise<boolean> {
		if (probeReason) return false;
		if (ackInFlight) return ackInFlight;
		if (!instanceName || pendingAckId === null) return false;
		const ackInstance = instanceName;
		const ackId = pendingAckId;
		const generation = bindingGeneration;
		const attempt = (async (): Promise<boolean> => {
			const result = await hcom(["omp-read", "--name", ackInstance, "--ack", "--up-to", String(ackId)]);
			if (result.code !== 0) {
				log("WARN", "plugin.delivery_ack_failed", ackInstance, {
					acked_to: ackId,
					source,
					exit_code: result.code,
					stderr: result.stderr.slice(0, 300),
				});
				return false;
			}
			// Keep the delivery gate closed until the durable acknowledgement has
			// succeeded. A reset/rebind invalidates this attempt's local state.
			if (bindingGeneration === generation && instanceName === ackInstance && pendingAckId === ackId) {
				pendingAckId = null;
				log("INFO", "plugin.deferred_ack", ackInstance, { acked_to: ackId, source });
				drainPendingDelivery("post_ack_wake");
			}
			return true;
		})();
		ackInFlight = attempt;
		try {
			return await attempt;
		} finally {
			if (ackInFlight === attempt) ackInFlight = null;
		}
	}

	async function reportStatus(ctx: ExtensionContext, status: "active" | "listening", context = "", detail = ""): Promise<void> {
		if (probeSkipReason(ctx)) return;
		await bindIdentity(ctx);
		if (!instanceName) return;
		const args = ["omp-status", "--name", instanceName, "--status", status];
		if (context) args.push("--context", context);
		if (detail) args.push("--detail", detail);
		await hcom(args);
		lastReportedStatusKey = statusKey(status, context, detail);
	}

	async function reportReconciledStatus(ctx: ExtensionContext): Promise<void> {
		const key = statusKey("listening", "", "");
		if (lastReportedStatusKey !== key) {
			await reportStatus(ctx, "listening");
		}
	}

	async function pollPendingIfDue(ctx: ExtensionContext): Promise<void> {
		const now = Date.now();
		const interval = notifyPort ? PENDING_POLL_MS : FALLBACK_PENDING_POLL_MS;
		if (now - lastPendingPollAt < interval) return;
		lastPendingPollAt = now;
		await deliverPending(ctx);
	}

	function clearIdleTimer(): void {
		if (idleTimer) clearTimeout(idleTimer);
		idleTimer = null;
	}

	async function reconcile(): Promise<void> {
		if (reconcileInFlight || !currentCtx || !instanceName) return;
		reconcileInFlight = true;
		try {
			if (pendingAckId !== null) await ackPending("reconcile");
			if (currentCtx.isIdle()) {
				await reportReconciledStatus(currentCtx);
				await pollPendingIfDue(currentCtx);
			}
		} catch (error) {
			log("ERROR", "plugin.reconcile_error", instanceName, { error: String(error) });
		} finally {
			reconcileInFlight = false;
		}
	}

	function startReconcileTimer(): void {
		stopReconcileTimer();
		reconcileTimer = setInterval(() => void reconcile(), 5_000);
	}

	function stopReconcileTimer(): void {
		if (reconcileTimer) {
			clearInterval(reconcileTimer);
			reconcileTimer = null;
		}
	}

	function resetBinding(opts?: { keepOwner?: boolean }): void {
		stopReconcileTimer();
		stopNotifyServer();
		bindingGeneration++;
		instanceName = null;
		sessionId = null;
		bootstrapText = null;
		bindingPromise = null;
		pendingAckId = null;
		ackInFlight = null;
		deliveryInFlight = false;
		deliveryPending = false;
		deliveryRetryScheduled = false;
		bootstrapInjectedForSession = null;
		lastReportedStatusKey = null;
		lastPendingPollAt = 0;
		agentActive = false;
		clearIdleTimer();
		// keepOwner: session_branch rebinds in the same extension instance — retain
		// process-local ownership so nested task extensions still skip bind.
		if (!opts?.keepOwner && ownsIdentity) {
			clearIdentityOwnership();
			ownsIdentity = false;
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		currentCtx = ctx;
		resetBinding();
		await bindIdentity(ctx);
	});

	// SessionShutdownEvent is only `{ type: "session_shutdown" }` — no sessionId.
	// Stop only when THIS extension instance owns the identity (nested task
	// instances never bind, so they never stop the parent).
	pi.on("session_shutdown", async () => {
		if (probeReason) {
			log("INFO", "plugin.session_shutdown_skipped", null, { reason: "probe", probe_reason: probeReason });
			resetBinding();
			return;
		}
		let keepOwner = false;
		if (instanceName && ownsIdentity) {
			const reg = getIdentityRegistry();
			reg.tearingDown = true;
			const reason = "shutdown";
			const stopName = instanceName;
			// Lets a same-tick signal listener record the signal: omp's postmortem
			// listener runs first and reaches this handler synchronously.
			await Promise.resolve();
			if (reg.exitSignal) {
				// Signal exit: postmortem runs cleanup, then exits without firing
				// `exit`. Release the row now, while omp is still alive.
				keepOwner = !releaseOwnerSync(stopName, reason);
			} else {
				// No signal: a graceful quit (process.exit follows, `exit` fires) or
				// /restart (execvp of the same pid, no `exit`). Soft-stop now so the
				// restarted image can rebind; the full release waits for `exit`.
				let softStopOk = false;
				try {
					const result = await hcom(["omp-stop", "--name", stopName, "--reason", reason, "--soft"]);
					softStopOk = result.code === 0;
					if (!softStopOk) {
						log("WARN", "plugin.session_shutdown_stop_failed", stopName, {
							exit_code: result.code,
							reason,
							soft: true,
							stderr: result.stderr.slice(0, 300),
						});
					}
				} catch (error) {
					log("ERROR", "plugin.session_shutdown_stop_error", stopName, {
						error: String(error),
						reason,
						soft: true,
					});
				}
				armExitRelease(reg, stopName, reason);
				keepOwner = !softStopOk;
			}
			// Shutdown attempt finished. If we retain ownership after a failed stop,
			// drop tearingDown so the owner can re-omp-start; nested skip still uses reg.owner.
			if (keepOwner) {
				reg.tearingDown = false;
			}
		} else {
			const skipReason = nestedSkipReason();
			if (skipReason) {
				nestedOptOut = true;
				const reg = getIdentityRegistry();
				log("INFO", "plugin.session_shutdown_skipped", null, {
					reason: "nested_session",
					skip_reason: skipReason,
					owner: reg.owner ?? process.env[IDENTITY_OWNER_ENV] ?? null,
				});
			}
		}
		resetBinding({ keepOwner });
	});

	pi.on("session_switch", async (_event, ctx) => {
		currentCtx = ctx;
		// Keep process-local ownership across switch rebind so a live nested task
		// extension cannot claim identity in the window between clear and omp-start.
		resetBinding({ keepOwner: true });
		await bindIdentity(ctx);
	});

	// OMP's /branch (and /btw's branched path) calls createBranchedSession(),
	// which mints a NEW session id + file and emits only session_branch — not
	// session_switch. Without rebinding here the cached sessionId stays stale,
	// isBoundSession() fails against the new id, and every later deliverPending
	// silently returns false (delivery dead after branch). Rebind like a switch,
	// but keep process-local ownership so nested task extensions still skip bind.
	// session_tree does NOT mint a new session id/file, so it needs no rebind.
	pi.on("session_branch", async (_event, ctx) => {
		currentCtx = ctx;
		resetBinding({ keepOwner: true });
		await bindIdentity(ctx);
	});

	pi.on("agent_start", async (_event, ctx) => {
		currentCtx = ctx;
		clearIdleTimer();
		agentActive = true;
		await reportStatus(ctx, "active", "agent");
	});

	pi.on("input", async (event: InputEvent, ctx) => {
		currentCtx = ctx;
		await bindIdentity(ctx);
		if (!instanceName) return {};
		if (event.source === "extension") {
			await ackPending("extension");
			return {};
		}
		if (isBodylessWake(event.text) && pendingAckId === null) {
			const pending = await fetchPending();
			if (pending) {
				pendingAckId = pending.maxId;
				return { text: formatMessagesForInjection(pending.messages, instanceName) };
			}
			return { handled: true };
		}
		await reportStatus(ctx, "active", event.text.trim() === "<hcom>" ? "trigger" : "prompt");
		return {};
	});

	pi.on("before_agent_start", async (_event, ctx) => {
		currentCtx = ctx;
		await bindIdentity(ctx);
		if (!instanceName) return undefined;
		// Ack the bodyless-wake transform here. The input handler sets pendingAckId
		// and returns { text } for a bare <hcom>; omp applies that transform INLINE
		// and submits it (input-controller.ts) — it never re-emits an input event
		// with source "extension", so the input handler's extension-ack branch is
		// dead for the transform path. before_agent_start fires for the submitted
		// turn, so ack here; otherwise pendingAckId stays set and deliverPending
		// early-returns forever, permanently jamming delivery. (For the
		// sendUserMessage path deliverPending already acked, so this no-ops.)
		if (pendingAckId !== null) await ackPending("before_agent_start");
		if (!bootstrapText) return undefined;
		const sid = ctx.sessionManager.getSessionId();
		if (bootstrapInjectedForSession === sid) return undefined;
		bootstrapInjectedForSession = sid;
		log("DEBUG", "plugin.hidden_bootstrap", instanceName, { bootstrap_len: bootstrapText.length });
		return {
			message: {
				customType: "hcom-bootstrap",
				content: bootstrapText,
				display: false,
			},
		};
	});

	pi.on("tool_call", async (event, ctx) => {
		currentCtx = ctx;
		if (probeSkipReason(ctx)) return undefined;
		await bindIdentity(ctx);
		if (!instanceName) return undefined;
		await reportStatus(ctx, "active", `tool:${event.toolName}`, String((event.input as any)?.path ?? (event.input as any)?.command ?? ""));
		const result = await hcom([
			"omp-beforetool",
			"--name",
			instanceName,
			"--tool",
			event.toolName,
			"--input-json",
			JSON.stringify(event.input ?? {}),
		]);
		try {
			const json = JSON.parse(result.stdout || "{}");
			if (json.decision === "block") {
				return { block: true, reason: String(json.reason || "Blocked by hcom") };
			}
		} catch {}
		return undefined;
	});

	pi.on("tool_result", async (event, ctx) => {
		currentCtx = ctx;
		await reportStatus(ctx, "active", `tool:${event.toolName}`);
		await deliverPending(ctx);
	});

	pi.on("turn_end", async (_event, ctx) => {
		currentCtx = ctx;
		await deliverPending(ctx);
	});

	pi.on("agent_end", async (_event, ctx) => {
		currentCtx = ctx;
		if (!agentActive) return;
		agentActive = false;
		clearIdleTimer();
		idleTimer = setTimeout(() => {
			idleTimer = null;
			if (currentCtx?.isIdle()) {
				void (async () => {
					await reportStatus(currentCtx, "listening");
					await deliverPending(currentCtx);
				})();
			}
		}, IDLE_DEBOUNCE_MS);
		idleTimer.unref?.();
	});
}
