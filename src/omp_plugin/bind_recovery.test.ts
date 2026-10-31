/// <reference lib="es2024.promise" />
// Drives the embedded plugin through the same fake CLI/context boundary as
// delivery_role.test.ts. Child-process completion and the plugin's clocks are
// controlled here; notify queries still exercise the real loopback endpoint.
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { test } from "node:test";
import type { TestContext } from "node:test";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

const TEST_ROOT = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "hcom-bind-recovery-"));
const REGISTRY_KEY = Symbol.for("hcom.omp.identity");
let moduleId = 0;

type Reply = {
	code?: number;
	json?: unknown;
	stdout?: string;
	hold?: boolean;
	commit?: boolean;
	transportError?: boolean;
};

class FakeProcess extends EventEmitter {
	stdout = new PassThrough();
	stderr = new PassThrough();
	finished = false;
	signals: string[] = [];

	kill(signal: string): boolean {
		this.signals.push(signal);
		return true;
	}

	finish(reply: Reply): void {
		if (this.finished) return;
		this.finished = true;
		if (reply.transportError) {
			this.emit("error", new Error("fake transport disconnected"));
			return;
		}
		this.stdout.end(reply.stdout ?? JSON.stringify(reply.json ?? {}));
		this.stderr.end();
		this.emit("close", reply.code ?? 0);
	}
}

type Call = { args: string[]; identity: string; child: FakeProcess };

class FakeHcom {
	calls: Call[] = [];
	configReplies: Reply[] = [];
	startReplies: Reply[] = [];
	stopReplies: Reply[] = [];
	plainEnabled = true;
	rows = new Map<string, string>();
	pending: { event_id: number; from: string; message: string }[] = [];
	cursor = 0;
	waiters: { command: string; count: number; resolve: (call: Call) => void }[] = [];

	get starts(): Call[] {
		return this.calls.filter((call) => call.args[0] === "omp-start");
	}

	spawn(args: readonly string[]): ChildProcess {
		const child = new FakeProcess();
		const call = { args: [...args], identity: process.env.HCOM_PROCESS_ID ?? "", child };
		this.calls.push(call);
		let reply: Reply = {};
		if (args[0] === "config") {
			reply = this.configReplies.shift() ?? { json: { HCOM_PLAIN_SESSIONS: this.plainEnabled ? "1" : "0" } };
		} else if (args[0] === "omp-start") {
			reply = this.startReplies.shift() ?? {};
			const name = this.rows.get(call.identity) ?? `seat-${this.rows.size + 1}`;
			if (reply.commit || (!reply.hold && !reply.transportError && reply.json === undefined && !reply.code)) {
				this.rows.set(call.identity, name);
			}
			if (reply.json === undefined && reply.stdout === undefined) {
				reply = { ...reply, json: { name, session_id: arg(call, "--session-id"), bootstrap: "seat bootstrap" } };
			}
		} else if (args[0] === "omp-stop") {
			reply = this.stopReplies.shift() ?? {};
		} else if (args[0] === "omp-role") {
			reply.json = { ok: true };
		} else if (args[0] === "omp-read") {
			if (args.includes("--ack")) this.cursor = Number(arg(call, "--up-to"));
			reply.json = this.pending.filter((message) => message.event_id > this.cursor);
		}
		if (!reply.hold) queueMicrotask(() => child.finish(reply));
		for (const waiter of [...this.waiters]) {
			const matches = this.calls.filter((entry) => entry.args[0] === waiter.command);
			if (matches.length < waiter.count) continue;
			this.waiters.splice(this.waiters.indexOf(waiter), 1);
			waiter.resolve(matches[waiter.count - 1]);
		}
		// Deliberately emulate only the child-process protocol hcom() consumes.
		return child as unknown as ChildProcess;
	}

	waitFor(command: string, count = 1): Promise<Call> {
		const matches = this.calls.filter((call) => call.args[0] === command);
		if (matches.length >= count) return Promise.resolve(matches[count - 1]);
		const { promise, resolve } = Promise.withResolvers<Call>();
		this.waiters.push({ command, count, resolve });
		return promise;
	}
}

function arg(call: Call, name: string): string {
	const index = call.args.indexOf(name);
	assert.notEqual(index, -1, `missing ${name}`);
	return call.args[index + 1];
}

type StubContext = {
	hasUI: boolean;
	cwd: string;
	sessionManager: {
		getSessionId(): string;
		getSessionFile(): string | undefined;
		getEntries(): { type: string; customType: string }[];
	};
	isIdle(): boolean;
	getContextUsage(): { tokens: number; contextWindow: number; percent: number };
};

function context(sid = "sid-1", options: { hasUI?: boolean; persisted?: boolean; conductor?: boolean } = {}): StubContext {
	return {
		hasUI: options.hasUI ?? true,
		cwd: TEST_ROOT,
		sessionManager: {
			getSessionId: () => sid,
			getSessionFile: () => options.persisted === false ? undefined : join(TEST_ROOT, `${sid}.jsonl`),
			getEntries: () => options.conductor ? [{ type: "custom", customType: "conductor-role" }] : [],
		},
		isIdle: () => true,
		getContextUsage: () => ({ tokens: sid === "sid-new" ? 900 : 100, contextWindow: 1000, percent: 10 }),
	};
}

type Handler = (event: unknown, ctx: StubContext) => unknown;

class StubPi {
	handlers = new Map<string, Handler[]>();
	sends: { role: "user" | "custom"; content: string; customType?: string }[] = [];
	ctx: StubContext;

	constructor(ctx = context()) {
		this.ctx = ctx;
	}

	on(event: string, handler: Handler): void {
		const handlers = this.handlers.get(event) ?? [];
		handlers.push(handler);
		this.handlers.set(event, handlers);
	}

	async emit(event: string, payload: unknown = {}): Promise<unknown> {
		const ctx = this.ctx;
		let result: unknown;
		for (const handler of this.handlers.get(event) ?? []) result = await handler(payload, ctx);
		return result;
	}

	sendUserMessage(content: string): void {
		this.sends.push({ role: "user", content });
	}

	sendMessage(message: { content: string; customType: string }): void {
		this.sends.push({ role: "custom", content: message.content, customType: message.customType });
	}

	async exec(): Promise<{ code: number; stdout: string; stderr: string }> {
		return { code: 0, stdout: "omp/18.14.1\n", stderr: "" };
	}
}

type PluginRegistry = {
	owner: string | null;
	tearingDown: boolean;
	pendingExitRelease: unknown;
	exitSignal: unknown;
};

function registry(): PluginRegistry | undefined {
	// This is the plugin's known in-process registry, not external JSON.
	return Reflect.get(globalThis, REGISTRY_KEY) as PluginRegistry | undefined;
}

async function flush(): Promise<void> {
	const { promise, resolve } = Promise.withResolvers<void>();
	setImmediate(resolve);
	await promise;
}

async function query(port: number): Promise<{ tokens: number }> {
	const { promise, resolve, reject } = Promise.withResolvers<string>();
	const socket = createConnection({ host: "127.0.0.1", port });
	let body = "";
	socket.setEncoding("utf8");
	socket.on("data", (chunk) => { body += chunk; });
	socket.once("error", reject);
	socket.once("end", () => { socket.destroy(); resolve(body); });
	socket.once("connect", () => socket.write('{"q":"context"}\n'));
	return JSON.parse(await promise);
}

async function connectable(port: number): Promise<boolean> {
	const { promise, resolve } = Promise.withResolvers<boolean>();
	const socket = createConnection({ host: "127.0.0.1", port });
	socket.once("connect", () => {
		socket.destroy();
		resolve(true);
	});
	socket.once("error", () => {
		socket.destroy();
		resolve(false);
	});
	return promise;
}

async function fixture(t: TestContext, options: { plainEnabled?: boolean; launcher?: boolean; ctx?: StubContext } = {}) {
	process.env.HCOM_DIR = join(TEST_ROOT, `hcom-${++moduleId}`);
	delete process.env.HCOM_OMP_IDENTITY_OWNER;
	delete process.env.HCOM_PROCESS_ID;
	delete process.env.HCOM_LAUNCHED;
	if (options.launcher) {
		process.env.HCOM_LAUNCHED = "1";
		process.env.HCOM_PROCESS_ID = "12345678-1234-1234-1234-123456789abc";
	}
	const reg = registry();
	if (reg) {
		reg.owner = null;
		reg.tearingDown = false;
		reg.exitSignal = null;
		reg.pendingExitRelease = null;
	}
	const fake = new FakeHcom();
	fake.plainEnabled = options.plainEnabled ?? true;
	// The stub intentionally implements only hcom()'s subset of these overloaded
	// Node APIs; never invoke an actual CLI, including from exit-release.
	const spawn = ((_command: string, args: readonly string[] = []) => fake.spawn(args)) as unknown as typeof childProcess.spawn;
	const spawnSync = (() => ({
		status: 0, signal: null, pid: 0, output: [], stdout: Buffer.alloc(0), stderr: Buffer.alloc(0),
	})) as unknown as typeof childProcess.spawnSync;
	t.mock.method(childProcess, "spawn", spawn);
	t.mock.method(childProcess, "spawnSync", spawnSync);
	syncBuiltinESMExports();
	t.mock.timers.enable({ apis: ["Date", "setTimeout", "setInterval"], now: 1_700_000_000_000 });
	// Deliberately exercise the module-loading boundary: static import would
	// capture the real HCOM_DIR, launcher identity and cached config too early.
	const { default: extension } = await import(new URL(`./hcom.ts?bind-recovery=${moduleId}`, import.meta.url).href);
	const seats: StubPi[] = [];
	function seat(ctx = options.ctx ?? context()): StubPi {
		const pi = new StubPi(ctx);
		extension(pi as unknown as ExtensionAPI);
		seats.push(pi);
		return pi;
	}
	t.after(async () => {
		fake.stopReplies = [];
		for (const call of fake.calls) call.child.finish({ json: { error: "test cleanup" } });
		for (const pi of seats) await pi.emit("session_shutdown");
		const reg = registry();
		if (reg) reg.pendingExitRelease = null;
		await flush();
		t.mock.timers.reset();
		t.mock.restoreAll();
		syncBuiltinESMExports();
	});
	return {
		fake,
		pi: seat(),
		seat,
		async tick(ms: number) {
			t.mock.timers.tick(ms);
			await flush();
		},
	};
}

test("a delayed eligibility check is fenced and concurrent hooks share one current bind", { timeout: 5000 }, async (t) => {
	const { pi, fake } = await fixture(t);
	fake.configReplies = [{ hold: true }];
	fake.startReplies = [{ hold: true }];
	const starting = pi.emit("session_start");
	const config = await fake.waitFor("config");
	pi.ctx = context("sid-new");
	const switching = pi.emit("session_switch");
	const turn = pi.emit("before_agent_start");
	config.child.finish({ json: { HCOM_PLAIN_SESSIONS: "1" } });
	const fresh = await fake.waitFor("omp-start");
	await starting;
	await flush();
	assert.equal(fake.starts.length, 1);
	assert.equal(arg(fresh, "--session-id"), "sid-new");
	fresh.child.finish({ json: { name: "current", session_id: "sid-new" } });
	await switching;
	await turn;
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "current");
});

test("a committed start killed at 1800ms recovers while idle with the same identity and endpoint", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t, { ctx: context("sid-1", { conductor: true }) });
	fake.startReplies = [{ hold: true, commit: true }];
	const starting = pi.emit("session_start");
	const first = await fake.waitFor("omp-start");
	const port = Number(arg(first, "--notify-port"));
	assert.equal((await query(port)).tokens, 100);
	await tick(1800);
	await starting;
	assert.deepEqual(first.child.signals, ["SIGTERM"]);
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, undefined);
	assert.equal((await query(port)).tokens, 100, "timeout must preserve the committed notify endpoint");
	await tick(3200);
	assert.equal(fake.starts.length, 1, "backoff blocks the first five-second timer tick");
	await tick(5000);
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "seat-1", "reconcile alone recovers the owner");
	assert.equal(fake.rows.size, 1, "retry recovers the committed row rather than creating another identity");
	assert.equal(fake.starts[1].identity, first.identity);
	assert.equal(Number(arg(fake.starts[1], "--notify-port")), port);
	assert.equal((await query(port)).tokens, 100);
	assert.equal(fake.calls.filter((call) => call.args[0] === "omp-role").length, 1);
});

for (const code of [0, 1]) {
	test(`explicit transient JSON retries through reconcile (exit ${code})`, { timeout: 5000 }, async (t) => {
		const { pi, fake, tick } = await fixture(t);
		fake.startReplies = [{ code, json: { error: "database is locked", transient: true, ...(code ? { ok: false } : {}) } }];
		await pi.emit("session_start");
		await tick(5000);
		assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "seat-1");
		assert.equal(fake.starts.length, 2);
	});
}

test("transport retries use bounded backoff and stop after five attempts", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t);
	fake.startReplies = Array.from({ length: 5 }, () => ({ transportError: true }));
	await pi.emit("session_start");
	const due = [0, 5000, 15000, 35000, 65000];
	for (let elapsed = 5000; elapsed <= 90000; elapsed += 5000) {
		await tick(5000);
		assert.equal(fake.starts.length, due.filter((at) => at <= elapsed).length, `attempt count at ${elapsed}ms`);
	}
	await pi.emit("before_agent_start");
	assert.equal(fake.starts.length, 5, "input must not bypass exhausted recovery");
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, undefined);
});

const TERMINAL_REPLIES = [
	{ label: "ownership refusal", reply: { json: { error: "process identity owner mismatch" } } },
	{ label: "nonzero ownership refusal", reply: { code: 1, json: { error: "owner incarnation unreadable" } } },
	{ label: "intentional stop", reply: { json: { ok: true, restored: false, stopped: "seat-1" } } },
	{ label: "missing restore", reply: { json: { restored: false } } },
	{ label: "invalid success", reply: { stdout: "not JSON" } },
] satisfies { label: string; reply: Reply }[];

for (const { label, reply } of TERMINAL_REPLIES) {
	test(`${label} remains terminal until a new session generation`, { timeout: 5000 }, async (t) => {
		const { pi, fake, tick } = await fixture(t);
		fake.startReplies = [reply];
		await pi.emit("session_start");
		await tick(90000);
		await pi.emit("before_agent_start");
		await pi.emit("input", { source: "user", text: "hello" });
		assert.equal(fake.starts.length, 1);
		assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, undefined);
		pi.ctx = context("sid-new");
		await pi.emit("session_switch");
		assert.equal(fake.starts.length, 2);
		assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "seat-1");
	});
}

test("a rejected launcher identity never remints or retries a missing-id refusal", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t, { launcher: true });
	fake.startReplies = [{ json: { error: "HCOM_PROCESS_ID not set" } }];
	const identity = process.env.HCOM_PROCESS_ID;
	await pi.emit("session_start");
	await tick(90000);
	await pi.emit("before_agent_start");
	assert.equal(fake.starts.length, 1);
	assert.equal(process.env.HCOM_PROCESS_ID, identity);
});

for (const lifecycle of ["session_switch", "session_branch"]) {
	for (const outcome of ["success", "refusal"]) {
		test(`stale ${outcome} across ${lifecycle} cannot replace owner, close endpoint or unlock the newer bind`, { timeout: 5000 }, async (t) => {
			const { pi, fake, tick } = await fixture(t);
			fake.startReplies = [{ hold: true }, { hold: true }];
			const starting = pi.emit("session_start");
			const old = await fake.waitFor("omp-start");
			pi.ctx = context("sid-new");
			const switching = pi.emit(lifecycle);
			await flush();
			assert.equal(fake.starts.length, 1, "a new generation must not overlap the pending start");
			old.child.finish({ json: outcome === "success"
				? { name: "obsolete", session_id: "sid-1", bootstrap: "obsolete bootstrap" }
				: { error: "obsolete refusal" } });
			await starting;
			const fresh = await fake.waitFor("omp-start", 2);
			const port = Number(arg(fresh, "--notify-port"));
			assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, undefined);
			assert.equal((await query(port)).tokens, 900);
			let turnFinished = false;
			const turn = pi.emit("before_agent_start").then((result) => { turnFinished = true; return result; });
			await flush();
			assert.equal(fake.starts.length, 2, "old finally cannot clear the new binding promise");
			assert.equal(turnFinished, false, "the current turn must still await the current bind");
			fresh.child.finish({ json: { name: "current", session_id: "sid-new", bootstrap: "current bootstrap" } });
			await switching;
			assert.deepEqual(await turn, { message: { customType: "hcom-bootstrap", content: "current bootstrap", display: false } });
			assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "current");
			await tick(30000);
			assert.equal(fake.starts.length, 2, "the stale completion cannot schedule another retry");
			assert.equal((await query(port)).tokens, 900);
		});
	}
}

test("a stale timeout cannot schedule a retry or clear an in-flight switch bind", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t);
	fake.startReplies = [{ hold: true }, { hold: true }];
	const starting = pi.emit("session_start");
	await fake.waitFor("omp-start");
	await tick(1000);
	pi.ctx = context("sid-new");
	const switching = pi.emit("session_switch");
	await tick(800);
	await starting;
	const fresh = await fake.waitFor("omp-start", 2);
	const turn = pi.emit("before_agent_start");
	await flush();
	assert.equal(fake.starts.length, 2);
	fresh.child.finish({ json: { name: "current", session_id: "sid-new" } });
	await switching;
	await turn;
	await tick(30000);
	assert.equal(fake.starts.length, 2);
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "current");
	assert.equal((await query(Number(arg(fresh, "--notify-port")))).tokens, 900);
});

for (const outcome of ["success", "transient"]) {
	test(`pending bind ${outcome} after shutdown cannot revive the stopped generation`, { timeout: 5000 }, async (t) => {
		const { pi, fake, tick } = await fixture(t);
		fake.startReplies = [{ hold: true }];
		const starting = pi.emit("session_start");
		const pending = await fake.waitFor("omp-start");
		await pi.emit("session_shutdown");
		pending.child.finish({ json: outcome === "success"
			? { name: "obsolete", session_id: "sid-1" }
			: { error: "database is locked", transient: true } });
		await starting;
		await tick(90000);
		await pi.emit("before_agent_start");
		assert.equal(fake.starts.length, 1);
		assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, undefined);
		assert.equal(registry()?.owner, null);
		await assert.rejects(query(Number(arg(pending, "--notify-port"))));
	});
}

for (const stopCode of [0, 1]) {
	test(`intentional shutdown never restarts even when stop exits ${stopCode}`, { timeout: 5000 }, async (t) => {
		const { pi, fake, tick } = await fixture(t);
		await pi.emit("session_start");
		fake.stopReplies = [{ code: stopCode }];
		await pi.emit("session_shutdown");
		await tick(90000);
		await pi.emit("input", { source: "user", text: "do not restart" });
		await pi.emit("before_agent_start");
		assert.equal(fake.starts.length, 1);
		assert.equal(fake.calls.filter((call) => call.args[0] === "omp-stop").length, 1);
	});
}

test("an obsolete shutdown result cannot reset or arm exit-release for a newly bound session", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t);
	await pi.emit("session_start");
	fake.stopReplies = [{ hold: true }];
	const shuttingDown = pi.emit("session_shutdown");
	const stop = await fake.waitFor("omp-stop");
	pi.ctx = context("sid-new");
	await pi.emit("session_switch");
	const fresh = fake.starts[1];
	stop.child.finish({ code: 1 });
	await shuttingDown;
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "seat-1");
	assert.equal(registry()?.pendingExitRelease, null);
	assert.equal((await query(Number(arg(fresh, "--notify-port")))).tokens, 900);
	await tick(5000);
	assert.equal(fake.starts.length, 2);
});

test("normal bind retains bootstrap, conductor role and consume-only delivery acknowledgement", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t, { ctx: context("sid-1", { conductor: true }) });
	fake.pending = [{ event_id: 7, from: "peer", message: "mail after idle bind" }];
	await pi.emit("session_start");
	assert.equal(process.env.HCOM_OMP_IDENTITY_OWNER, "seat-1");
	assert.deepEqual(await pi.emit("before_agent_start"), {
		message: { customType: "hcom-bootstrap", content: "seat bootstrap", display: false },
	});
	assert.equal(await pi.emit("before_agent_start"), undefined);
	await tick(5000);
	assert.equal(pi.sends.length, 1);
	assert.match(pi.sends[0].content, /mail after idle bind/);
	assert.equal(fake.cursor, 0, "the idle delivery has not been consumed yet");
	await pi.emit("message_start", { message: pi.sends[0] });
	assert.equal(fake.cursor, 7);
	assert.equal(fake.calls.filter((call) => call.args[0] === "omp-role").length, 1);
});

for (const [label, ctx] of [
	["headless", context("sid-1", { hasUI: false })],
	["ephemeral probe", context("sid-1", { persisted: false })],
] as const) {
	test(`${label} remains inert without config, binding or endpoint work`, { timeout: 5000 }, async (t) => {
		const { pi, fake, tick } = await fixture(t, { ctx });
		await pi.emit("session_start");
		await tick(90000);
		await pi.emit("before_agent_start");
		await pi.emit("session_shutdown");
		assert.deepEqual(fake.calls, []);
	});
}

test("plain_sessions disabled never starts idle recovery", { timeout: 5000 }, async (t) => {
	const { pi, fake, tick } = await fixture(t, { plainEnabled: false });
	await pi.emit("session_start");
	await tick(90000);
	await pi.emit("before_agent_start");
	assert.deepEqual(fake.calls.map((call) => call.args[0]), ["config"]);
});

test("nested opt-out stays inert after the parent releases ownership", { timeout: 5000 }, async (t) => {
	const { pi, fake, seat, tick } = await fixture(t);
	await pi.emit("session_start");
	const nested = seat(context("sid-nested"));
	await nested.emit("session_start");
	await pi.emit("session_shutdown");
	nested.ctx = context("sid-new");
	await nested.emit("session_switch");
	await tick(90000);
	await nested.emit("before_agent_start");
	await nested.emit("session_shutdown");
	assert.equal(fake.starts.length, 1);
	assert.equal(fake.calls.filter((call) => call.args[0] === "omp-stop").length, 1);
});

test("nested retry opt-out closes a retained notify endpoint without disturbing the winner", { timeout: 5000 }, async (t) => {
	const { pi, fake, seat, tick } = await fixture(t);
	fake.startReplies = [{ json: { error: "database is locked", transient: true } }];
	await pi.emit("session_start");
	const retainedPort = Number(arg(fake.starts[0], "--notify-port"));
	assert.equal((await query(retainedPort)).tokens, 100, "transient failure retains its endpoint");
	const winner = seat(context("sid-new"));
	await winner.emit("session_start");
	const winnerPort = Number(arg(fake.starts[1], "--notify-port"));
	assert.equal(registry()?.owner, "seat-1");
	await tick(5000);
	assert.equal(await connectable(retainedPort), false, "terminal nested opt-out must close the retained TCP listener");
	assert.equal((await query(winnerPort)).tokens, 900, "the winning owner's endpoint stays live");
	await tick(90000);
	await pi.emit("before_agent_start");
	assert.equal(fake.starts.length, 2, "the opted-out retry never restarts");
	assert.equal(registry()?.owner, "seat-1");
});
