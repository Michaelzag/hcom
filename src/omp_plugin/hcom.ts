import type { ExtensionAPI, ExtensionContext, InputEvent } from "@oh-my-pi/pi-coding-agent";
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { dirname } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createServer, type Server, type Socket } from "node:net";

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

// Per-delivery consume marker: the delivered message embeds this token and the
// ack-on-consume matcher looks for the exact token on the message omp injects.
// 128 random bits make a marker-looking string forged anywhere (tool result,
// other message) unguessable, and the role/customType gate rejects those anyway.
function newDeliveryMarker(): string {
	return `[hcom-ack:${randomBytes(8).toString("hex")}]`;
}

type PendingMailMessage = {
	event_id: number;
	from: string;
	message: string;
	intent?: string;
	thread?: string | null;
};

function formatMessagesForInjection(
	messages: PendingMailMessage[],
	recipientName: string,
	ackMarker: string,
): string {
	const parts = messages.map((m) => {
		const prefix = m.intent
			? m.thread
				? `[${m.intent}:${m.thread} #${m.event_id}]`
				: `[${m.intent} #${m.event_id}]`
			: m.thread
				? `[thread:${m.thread} #${m.event_id}]`
				: `[new message #${m.event_id}]`;
		return `${prefix} ${m.from} -> ${recipientName}: ${m.message}`;
	});
	if (messages.length === 1) return `<hcom>${parts[0]} ${ackMarker}</hcom>`;
	return `<hcom>[${messages.length} new messages] | ${parts.join(" | ")} ${ackMarker}</hcom>`;
}

// The custom message type the busy-seat aside delivery rides. It is the
// harness-authored mid-run notice channel (the same shape omp itself uses for
// its own asides, e.g. ttsr-injection), never a tool result: tool results carry
// untrusted bytes, so mail there could not be told apart from a forged <hcom>
// block (ffc-98d2g ruling: mail's authority depends on an unspoofable channel).
const HCOM_MAIL_CUSTOM_TYPE = "hcom-mail";

// `deliverAs: "aside"` exists on the extension API from omp 18.1.6 (the release
// whose CHANGELOG advertises "non-interrupting extension messages through
// deliverAs: \"aside\" for pi.sendMessage and pi.sendUserMessage"). On older omp
// (SDK 17.0.6) an unknown deliverAs falls through to prompt() with steer-on-
// stream behavior, so the busy lane may only use aside when the running runtime
// is >= 18.1.6; anything else takes the followUp fallback below.
export function asideSupportedForVersion(raw: string | null | undefined): boolean {
	const match = /^(?:omp\/)?v?(\d+)\.(\d+)\.(\d+)/.exec((raw ?? "").trim());
	if (!match) return false;
	const major = Number(match[1]);
	const minor = Number(match[2]);
	const patch = Number(match[3]);
	if (major !== 18) return major > 18;
	if (minor !== 1) return minor > 1;
	return patch >= 6;
}

// Two documented version surfaces, best first: `omp --version` (cli.ts prints
// `omp/<VERSION>` — the same value every install reports) via pi.exec, then the
// SDK's VERSION export (re-exported from @oh-my-pi/pi-utils, host-resolved to
// the running runtime by omp's extension loader). An unparseable answer from
// either falls through; when neither answers, report unsupported and take the
// fallback — the safe direction: the fallback never risks the old steer-on-stream
// path and still delivers and acks correctly, just at the run's end. Cached per
// extension instance (never at module scope) so the probe runs once per host.

function messageContentText(content: unknown): string {
	if (typeof content === "string") return content;
	if (Array.isArray(content)) {
		return content
			.map((part: unknown) =>
				part && typeof part === "object" && "type" in part && part.type === "text" && "text" in part && typeof part.text === "string"
					? part.text
					: "",
			)
			.join("");
	}
	return "";
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

// ── Notify-port queries ──────────────────────────────────────────────────────

/** The job-snapshot fields the context and compact queries read. */
export interface AsyncJobSnapshotView {
	running: readonly unknown[];
	delivery: { queued: number; delivering: boolean };
}

/** The context-usage fields the context query reports. */
export interface ContextUsageView {
	tokens: number;
	contextWindow: number;
	percent: number;
}

/** The ExtensionContext pieces the context query reads (stubbed in tests). */
export interface ContextQueryContext {
	getContextUsage?: () => ContextUsageView | undefined;
	getAsyncJobSnapshot?: () => AsyncJobSnapshotView | null;
}

/** The ExtensionContext pieces the compact request checks (stubbed in tests). */
export interface CompactCheckContext {
	isIdle(): boolean;
	hasPendingMessages(): boolean;
	getAsyncJobSnapshot?: () => AsyncJobSnapshotView | null;
	// omp 18.3.1 ExtensionContext does not expose isCompacting (it lives on
	// AgentSession). Honored when a host adds it; otherwise only this
	// reservation can see an in-progress compact.
	isCompacting?: () => boolean;
	compact?(focus?: string): Promise<void>;
}

// One reply line for hcom's `list --context` query (`{"q":"context"}\n`).
// Usage is null when the seat cannot compute it and the job count is null
// when the session has no job manager; hcom renders both as unknown, never 0.
// `caps` names what this plugin does beyond answering — the CLI keys the
// plugin-side compact path off it. `getAsyncJobSnapshot` is called optionally:
// a host without it reports the job count as unknown instead of throwing.
export function contextReplyBody(ctx: ContextQueryContext | null): string {
	const usage = ctx?.getContextUsage?.() ?? null;
	const snapshot = ctx?.getAsyncJobSnapshot?.() ?? null;
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
		caps: ["compact"],
	});
}

/** One parsed `{"q":"compact","focus":"<one line>","dry":...}` request. */
export interface CompactRequest {
	focus?: unknown;
	dry?: unknown;
}

// Every reason the plugin refuses to compact, in report order. Live state
// only, read at request time: the session file has no truth a live snapshot
// lacks (it cannot even see a job cancelled without a completion record).
export function compactRefusals(
	ctx: CompactCheckContext | null,
	undeliveredHcomMessages: number,
): string[] {
	if (!ctx) return ["job state unknown"];
	const refusals: string[] = [];
	if (!ctx.isIdle()) refusals.push("live turn");
	const snapshot = ctx.getAsyncJobSnapshot?.() ?? null;
	if (snapshot) {
		const running = snapshot.running.length;
		if (running > 0) refusals.push(`${running} running jobs`);
		const queued = snapshot.delivery.queued + (snapshot.delivery.delivering ? 1 : 0);
		if (queued > 0) refusals.push(`${queued} queued deliveries`);
	}
	if (ctx.hasPendingMessages()) refusals.push("pending messages");
	if (undeliveredHcomMessages > 0) refusals.push("pending hcom messages");
	if (!snapshot) refusals.push("job state unknown");
	return refusals;
}

// One `{"q":"compact"}` reply line, and whether the caller must now start
// `ctx.compact(focus)`. The caller replies first and only then fires it —
// never awaited inside the socket handler.
export function handleCompactQuery(
	query: CompactRequest,
	ctx: CompactCheckContext | null,
	undeliveredHcomMessages: number,
): { reply: string; start: boolean } {
	const refusals = compactRefusals(ctx, undeliveredHcomMessages);
	if (refusals.length > 0) {
		return { reply: JSON.stringify({ ok: false, refuse: refusals }), start: false };
	}
	if (query.dry === true) {
		return { reply: JSON.stringify({ ok: true, would: true }), start: false };
	}
	return { reply: JSON.stringify({ ok: true, compacting: true }), start: true };
}

// Deadline contract, kept next to each other. The plugin budget is strictly
// smaller than the CLI reply deadline (src/context.rs COMPACT_QUERY_TIMEOUT,
// src/commands/compact.rs), so a CLI timeout means this plugin already refused
// or never saw the request — it does not start a compact past the budget.
// Invariant: PLUGIN_COMPACT_BUDGET_MS < CLI_COMPACT_REPLY_DEADLINE_MS.
/** Plugin check budget, from request receipt, monotonic clock. */
export const PLUGIN_COMPACT_BUDGET_MS = 1500;
/** CLI reply deadline for `{"q":"compact"}`. Context probes stay at 500 ms. */
export const CLI_COMPACT_REPLY_DEADLINE_MS = 5000;

export const COMPACT_ALREADY = "compaction already in progress";
export const COMPACT_BUDGET_REFUSAL = `plugin busy: checks exceeded ${PLUGIN_COMPACT_BUDGET_MS} ms`;

/**
 * The held-reservation refusal names the hold's age
 * (`compaction already in progress (started Ns ago)`), in dry runs and
 * refusals alike, so a wedged seat is visible.
 */
export function compactAlreadyInProgress(reservedAtMs: number, nowMs: number): string {
	const ageS = Math.max(0, Math.floor((nowMs - reservedAtMs) / 1000));
	return `${COMPACT_ALREADY} (started ${ageS}s ago)`;
}

/**
 * Injectable timing. Production uses [`systemClock`]; tests pass a
 * controllable fake and advance it explicitly, so no compact-path test
 * depends on real timers, real sleeps, or event-loop liveness.
 */
export interface CompactClock {
	/** Monotonic ms (`performance.now()` in production): the check budget. */
	now(): number;
	/** Epoch ms (`Date.now()` in production): `started_at` and the hold's age. */
	epoch(): number;
	/** Arm `fn` after `ms`. Production unrefs it so it never holds the process. */
	setTimer(fn: () => void, ms: number): unknown;
	/** Cancel a timer armed by `setTimer`. */
	clearTimer(handle: unknown): void;
}

/** Production timing: real clocks and one unref'd timer per budget race. */
export const systemClock: CompactClock = {
	now: () => performance.now(),
	epoch: () => Date.now(),
	setTimer(fn, ms) {
		const timer = setTimeout(fn, ms);
		timer.unref();
		return timer;
	},
	clearTimer(handle) {
		clearTimeout(handle as NodeJS.Timeout);
	},
};

/**
 * One seat's compact reservation. Taken synchronously on a real request,
 * released ONLY when the `ctx.compact()` promise settles (resolve or reject)
 * — or immediately when the request refuses, since a refused request never
 * started anything. There is deliberately no stale bound: the reservation
 * mirrors omp's real compaction state, so a compact whose promise never
 * settles keeps refusing "compaction already in progress (started Ns ago)"
 * until the seat restarts (omp itself cannot compact again either).
 */
export interface CompactGate {
	/** Epoch ms when the live reservation was taken; null when free. */
	reservedAt: number | null;
	/** Identity of the current claim. A settle only releases its own token. */
	token: number;
}

export function createCompactGate(): CompactGate {
	return { reservedAt: null, token: 0 };
}

export interface CompactRequestRun {
	gate: CompactGate;
	query: CompactRequest;
	ctx: CompactCheckContext | null;
	/** Undelivered hcom-message count. Slowed in tests to exceed the budget. */
	fetchPending: () => Promise<number>;
	/** Reply line, without the trailing newline. Called before `ctx.compact`. */
	writeReply: (reply: string) => void;
	/** Timing dependency; defaults to [`systemClock`]. */
	clock?: CompactClock;
	onCompactFailed?: (error: unknown) => void;
}

function refuseReply(reasons: string[]): string {
	return JSON.stringify({ ok: false, refuse: reasons });
}

/** Drop `token`'s reservation. A newer claim (different token) is left alone. */
function releaseOwned(gate: CompactGate, token: number): boolean {
	if (gate.token !== token || gate.reservedAt === null) return false;
	gate.reservedAt = null;
	gate.token += 1;
	return true;
}

class CompactBudgetExceeded extends Error {
	constructor() {
		super("compact checks exceeded budget");
		this.name = "CompactBudgetExceeded";
	}
}

async function awaitWithinBudget<T>(
	work: Promise<T>,
	budgetMs: number,
	startedMono: number,
	clock: CompactClock,
): Promise<T> {
	const left = budgetMs - (clock.now() - startedMono);
	if (left <= 0) throw new CompactBudgetExceeded();
	let timer: unknown;
	const timeout = new Promise<never>((_, reject) => {
		timer = clock.setTimer(() => reject(new CompactBudgetExceeded()), left);
	});
	try {
		return await Promise.race([work, timeout]);
	} finally {
		clock.clearTimer(timer);
	}
}

function fireCompact(
	ctx: CompactCheckContext,
	query: CompactRequest,
	gate: CompactGate,
	token: number,
	onCompactFailed?: (error: unknown) => void,
): void {
	const focus = typeof query.focus === "string" ? query.focus : "";
	const fail = (error: unknown) => {
		releaseOwned(gate, token);
		onCompactFailed?.(error);
	};
	if (typeof ctx.compact !== "function") {
		fail(new Error("ctx.compact is not a function"));
		return;
	}
	try {
		const pending = ctx.compact(focus || undefined);
		void Promise.resolve(pending).then(
			() => {
				releaseOwned(gate, token);
			},
			(error: unknown) => fail(error),
		);
	} catch (error) {
		fail(error);
	}
}

// One compact request: reserve synchronously (real runs only) before any
// await, refuse when a reservation is already held, and never start once the
// check budget has passed. The reply is written before `ctx.compact` is fired;
// the reservation drops when that promise settles (resolve OR reject), or the
// moment the request refuses. There is no stale bound: the reservation mirrors
// omp's compaction state, never the wall clock.
export async function serveCompactRequest(run: CompactRequestRun): Promise<{ start: boolean }> {
	const clock = run.clock ?? systemClock;
	const budgetMs = PLUGIN_COMPACT_BUDGET_MS;
	const receivedMono = clock.now();
	const receivedEpoch = clock.epoch();
	const gate = run.gate;

	// Synchronous, before any await: a second real request must see the hold.
	// A dry run reports the same reason — with the hold's age — and never reserves.
	if (gate.reservedAt !== null) {
		run.writeReply(refuseReply([compactAlreadyInProgress(gate.reservedAt, receivedEpoch)]));
		return { start: false };
	}
	if (typeof run.ctx?.isCompacting === "function" && run.ctx.isCompacting()) {
		run.writeReply(refuseReply([COMPACT_ALREADY]));
		return { start: false };
	}
	const real = run.query.dry !== true;
	let owned: number | null = null;
	if (real) {
		gate.token += 1;
		owned = gate.token;
		gate.reservedAt = receivedEpoch;
	}

	let pendingCount = 0;
	try {
		pendingCount = await awaitWithinBudget(run.fetchPending(), budgetMs, receivedMono, clock);
	} catch (error) {
		if (owned !== null) releaseOwned(gate, owned);
		if (error instanceof CompactBudgetExceeded) {
			run.writeReply(refuseReply([COMPACT_BUDGET_REFUSAL]));
			return { start: false };
		}
		// A thrown lookup is not a start. Reply so the CLI is not left hanging.
		run.writeReply(refuseReply(["job state unknown"]));
		return { start: false };
	}

	if (clock.now() - receivedMono > budgetMs) {
		if (owned !== null) releaseOwned(gate, owned);
		run.writeReply(refuseReply([COMPACT_BUDGET_REFUSAL]));
		return { start: false };
	}

	const answer = handleCompactQuery(run.query, run.ctx, pendingCount);
	if (!answer.start) {
		if (owned !== null) releaseOwned(gate, owned);
		run.writeReply(answer.reply);
		return { start: false };
	}

	// Last synchronous step before the reply: a budget that expired while the
	// checks were finishing still refuses, and never starts.
	if (clock.now() - receivedMono > budgetMs) {
		if (owned !== null) releaseOwned(gate, owned);
		run.writeReply(refuseReply([COMPACT_BUDGET_REFUSAL]));
		return { start: false };
	}
	const startedAt = clock.epoch();
	run.writeReply(JSON.stringify({ ok: true, compacting: true, started_at: startedAt }));
	if (run.ctx && owned !== null) {
		fireCompact(run.ctx, run.query, gate, owned, run.onCompactFailed);
	} else if (owned !== null) {
		releaseOwned(gate, owned);
	}
	return { start: true };
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
	// One reservation for this seat. Taken synchronously on a real compact
	// request, before the pending-message lookup, so a second request cannot
	// also be acknowledged.
	const compactGate = createCompactGate();
	let pendingAckId: number | null = null;
	// Ack-on-consume state for the one outstanding delivery. pendingAckId is the
	// delivery gate AND the ack target (the batch's max event id); the cursor
	// must not advance until the consumed flag is set by a marker-matched
	// consume event — hcom "delivered" means in the session, never in omp's queue.
	let pendingAckMarker: string | null = null;
	let pendingAckRole: "user" | "custom" | null = null;
	let pendingAckConsumed = false;
	// The bodyless-wake transform rewrote input into our delivery text; the
	// submitted turn proves that text entered the session (see before_agent_start).
	let transformAckArmed = false;
	let asideSupportPromise: Promise<boolean> | null = null;
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

	// Detect `deliverAs: "aside"` support on the RUNNING host; see
	// asideSupportedForVersion for the 18.1.6 gate. Cached per instance.
	function asideSupported(): Promise<boolean> {
		asideSupportPromise ??= (async () => {
			try {
				const result = await pi.exec("omp", ["--version"]);
				if (/^(?:omp\/)?v?\d/.test(result.stdout.trim())) return asideSupportedForVersion(result.stdout);
			} catch {}
			// Dynamic on purpose: this must resolve to the RUNNING host's module
			// at probe time (omp's extension loader rewrites the bare specifier
			// to the in-process host), and a static import would kill the whole
			// extension at load on a host that cannot resolve it — the fallback
			// must survive.
			try {
				const sdk = (await import("@oh-my-pi/pi-coding-agent")) as { VERSION?: unknown };
				if (typeof sdk.VERSION === "string" && asideSupportedForVersion(sdk.VERSION)) return true;
			} catch {}
			return false;
		})();
		return asideSupportPromise;
	}

	// Consume proof for THIS plugin's outstanding delivery: the harness-authored
	// message omp injected, matched on role/customType first — a marker-looking
	// string in a tool result or any other message must never ack or count as
	// mail — then on the exact per-delivery marker embedded in the text.
	function isOwnConsumedMessage(message: unknown): boolean {
		if (pendingAckId === null || pendingAckConsumed || !pendingAckMarker || !pendingAckRole) return false;
		if (!message || typeof message !== "object" || !("role" in message)) return false;
		const candidate: { role: unknown; customType?: unknown; content?: unknown } = message;
		if (pendingAckRole === "custom") {
			if (candidate.role !== "custom" || candidate.customType !== HCOM_MAIL_CUSTOM_TYPE) return false;
		} else if (candidate.role !== "user") {
			return false;
		}
		return messageContentText(candidate.content).includes(pendingAckMarker);
	}

	// One reply line for hcom's `list --context` query (`{"q":"context"}\n`).
	function contextReply(): string {
		try {
			return contextReplyBody(currentCtx);
		} catch (error) {
			log("WARN", "notify_server.context_query_failed", instanceName, {
				error: String(error),
			});
			return contextReplyBody(null);
		}
	}

	// One `{"q":"compact"}` request. Reservation and the check budget live in
	// `serveCompactRequest`: the reply is written before `ctx.compact` runs,
	// the reservation is held until that promise settles, and a failure to
	// compact is logged, not returned (the reply already left).
	async function runCompactQuery(socket: Socket, query: CompactRequest): Promise<void> {
		const outcome = await serveCompactRequest({
			gate: compactGate,
			query,
			ctx: currentCtx,
			fetchPending: async () => {
				const pending = await fetchPending();
				return pending ? pending.messages.length : 0;
			},
			writeReply: (reply) => {
				try {
					socket.end(`${reply}\n`);
				} catch {}
			},
			onCompactFailed: (error) => {
				log("ERROR", "plugin.compact_failed", instanceName, { error: String(error) });
			},
		});
		log("DEBUG", "notify_server.compact_query", instanceName, {
			dry: query.dry === true,
			start: outcome.start,
		});
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
					let request: unknown = null;
					try {
						request = JSON.parse(buffer.slice(0, newline).trim());
					} catch {}
					const q =
						request && typeof request === "object" && "q" in request ? request.q : null;
					if (q === "context") {
						settled = true;
						socket.end(`${contextReply()}\n`);
						log("DEBUG", "notify_server.context_query", instanceName, {});
						return;
					}
					if (q === "compact") {
						settled = true;
						void runCompactQuery(
							socket,
							request && typeof request === "object" ? (request as CompactRequest) : {},
						);
						return;
					}
					// Not a query this plugin answers — keep today's wake behavior.
					wake();
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
			const marker = newDeliveryMarker();
			const formatted = formatMessagesForInjection(pending.messages, instanceName, marker);
			// Gate the next delivery AND record what consumption must later ack.
			// The durable ack does NOT run here: hcom records "delivered" only
			// when the message has entered the session's context (ffc-98d2g).
			pendingAckId = pending.maxId;
			pendingAckMarker = marker;
			pendingAckConsumed = false;
			transformAckArmed = false;
			try {
				const isIdle = ctx.isIdle();
				let mode: "idle" | "aside" | "fallback";
				if (isIdle) {
					// Idle seats are unchanged: sendUserMessage starts a turn and
					// the message enters the context at that turn.
					mode = "idle";
					pendingAckRole = "user";
					await pi.sendUserMessage(formatted);
				} else if (await asideSupported()) {
					// Busy lane, omp >= 18.1.6: deliverAs "aside" rides the
					// harness-authored mid-run notice channel — a separate custom
					// message injected at the next agent step boundary without
					// interrupting the in-flight tool batch (extensions/types.ts
					// sendMessage docs; the same channel omp itself uses for its
					// own mid-run asides). It is NEVER appended into a tool
					// result: tool results carry untrusted bytes, so mail there
					// could not be told apart from a forged <hcom> block (the
					// ffc-98d2g ruling bans the tool-result rewrite outright).
					// customType hcom-mail plus the per-delivery marker give the
					// ack-on-consume matcher an unspoofable identity.
					mode = "aside";
					pendingAckRole = "custom";
					await pi.sendMessage(
						{ customType: HCOM_MAIL_CUSTOM_TYPE, content: formatted, display: true },
						{ deliverAs: "aside" },
					);
				} else {
					// FALLBACK (omp without aside, e.g. the SDK 17.0.6): an
					// unknown deliverAs there falls through to prompt() with
					// steer-on-stream behavior — unsafe — so wait as a followUp
					// (delivers visibly at the run's end, never interrupts) and
					// say so meanwhile: "mail queued: N" in the status detail
					// both to the seat and, via `hcom list`, to the sender.
					mode = "fallback";
					pendingAckRole = "user";
					await pi.sendUserMessage(formatted, { deliverAs: "followUp" });
				}
				const sender = String(pending.messages[0]?.from ?? "");
				const queuedDetail = mode === "fallback" ? `mail queued: ${pending.messages.length}` : "";
				await reportStatus(ctx, "active", sender ? `deliver:${sender}` : "deliver", queuedDetail);
				log("INFO", "plugin.delivery_pending", instanceName, {
					count: pending.messages.length,
					pending_ack: pending.maxId,
					mode,
				});
				// No ack here: the ack lands when a consume event (message_start,
				// or the inline-transform submission) proves the message entered
				// the session.
				return true;
			} catch (error) {
				if (pendingAckId === pending.maxId) {
					pendingAckId = null;
					pendingAckMarker = null;
					pendingAckRole = null;
					pendingAckConsumed = false;
					transformAckArmed = false;
				}
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
		// Ack only what has been consumed: the durable cursor must never advance
		// past a message that has not entered the session. Callers like
		// reconcile retry blindly; this gate is what makes that safe.
		if (!pendingAckConsumed) return false;
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
				pendingAckMarker = null;
				pendingAckRole = null;
				pendingAckConsumed = false;
				transformAckArmed = false;
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
		pendingAckMarker = null;
		pendingAckRole = null;
		pendingAckConsumed = false;
		transformAckArmed = false;
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
			// Acks happen only on consume (message_start or the transform
			// submission below): an extension-sourced input is not proof that OUR
			// delivery entered the session, so it must never advance the cursor.
			return {};
		}
		if (isBodylessWake(event.text)) {
			// A bare wake is only a wake, never mail: drop it rather than echo a
			// bodyless <hcom> to the model. When a delivery is already
			// outstanding it owns the mail, so no second fetch (no duplicates).
			if (pendingAckId !== null) return { handled: true };
			const pending = await fetchPending();
			if (pending) {
				// Inline transform: omp applies the rewrite INLINE and submits it
				// (input-controller.ts), so the mail rides this turn's input.
				const marker = newDeliveryMarker();
				pendingAckId = pending.maxId;
				pendingAckMarker = marker;
				pendingAckRole = "user";
				pendingAckConsumed = false;
				transformAckArmed = true;
				return { text: formatMessagesForInjection(pending.messages, instanceName, marker) };
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
		// Consume proof for the bodyless-wake transform: the input handler
		// rewrote the wake into our delivery text and omp applied that transform
		// INLINE and submitted it (it never re-emits an input event with source
		// "extension"). This handler firing for the submitted turn means that
		// text — the mail — has entered the session, so it may be acked. Scoped
		// to the armed transform: any other turn starting while a delivery waits
		// must not ack it. (message_start carries the same marker and acks
		// idempotently when it emits.)
		if (pendingAckId !== null && transformAckArmed) {
			transformAckArmed = false;
			pendingAckConsumed = true;
			await ackPending("before_agent_start");
		}
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

	// Ack-on-consume: message_start fires exactly when the message enters the
	// model-bound context (agent-loop emitInputMessages pushes it into
	// currentContext.messages and emits at the step boundary), and message_end
	// is subscribed as a fallback for hosts that emit only the end event for
	// input messages. Only OUR delivery's own message — matched on role/
	// customType plus its unique marker — acks; a marker-looking string in a
	// tool result or any other message never matches and never acks.
	pi.on("message_start", async (event, ctx) => {
		currentCtx = ctx;
		if (isOwnConsumedMessage(event.message)) {
			pendingAckConsumed = true;
			await ackPending("message_start");
		}
	});
	pi.on("message_end", async (event, ctx) => {
		currentCtx = ctx;
		if (isOwnConsumedMessage(event.message)) {
			pendingAckConsumed = true;
			await ackPending("message_end");
		}
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
