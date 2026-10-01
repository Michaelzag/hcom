// Conductor delivery role: drives the REAL plugin module (./hcom.ts, the file
// the Rust binary embeds) against a stub of the omp extension API and a fake
// `hcom` CLI that records every argv. A session whose own log carries
// conductor-guard's `conductor-role` entry must send `omp-role ... --role
// conductor` once per binding; any other session never sends it.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";

// Importing the plugin runs its load-time identity resolution and logging, so
// HCOM_DIR must point at a throwaway dir first; that module-loading boundary
// is why ./hcom.ts is imported dynamically below.
const TEST_ROOT = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "hcom-delivery-role-"));
const FAKE_STATE = join(TEST_ROOT, "state");
mkdirSync(FAKE_STATE, { recursive: true });
mkdirSync(join(TEST_ROOT, "bin"), { recursive: true });
process.env.HCOM_DIR = join(TEST_ROOT, "hcom");
process.env.HCOM_FAKE_STATE = FAKE_STATE;
process.env.PATH = `${join(TEST_ROOT, "bin")}${delimiter}${process.env.PATH ?? ""}`;

// `omp-role` answers with the next entry of role_replies.json
// (`{ code, stdout, stderr }`); the last entry repeats forever. With no queue
// file it succeeds.
const FAKE_HCOM = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const stateDir = process.env.HCOM_FAKE_STATE;
const args = process.argv.slice(2);
fs.appendFileSync(path.join(stateDir, "calls.jsonl"), JSON.stringify(args) + "\\n");
const cmd = args[0];
if (cmd === "config") {
	process.stdout.write(JSON.stringify({ HCOM_PLAIN_SESSIONS: "1" }));
} else if (cmd === "omp-start") {
	process.stdout.write(JSON.stringify({ name: "kimi", session_id: "sid-1" }));
} else if (cmd === "omp-role") {
	const file = path.join(stateDir, "role_replies.json");
	let reply = { code: 0, stdout: JSON.stringify({ ok: true, role: "conductor" }), stderr: "" };
	if (fs.existsSync(file)) {
		const queue = JSON.parse(fs.readFileSync(file, "utf8"));
		reply = queue.length > 1 ? queue.shift() : queue[0];
		fs.writeFileSync(file, JSON.stringify(queue));
	}
	process.stdout.write(reply.stdout ?? "");
	process.stderr.write(reply.stderr ?? "");
	process.exitCode = reply.code ?? 0;
} else if (cmd === "omp-read") {
	process.stdout.write("[]");
} else {
	process.stdout.write("{}");
}
`;
const fakeHcomPath = join(TEST_ROOT, "bin", "hcom");
writeFileSync(fakeHcomPath, FAKE_HCOM);
chmodSync(fakeHcomPath, 0o755);

const { default: hcomExtension } = await import("./hcom.ts");

const MARKER = { type: "custom", customType: "conductor-role", data: {} };
const ROLE_ARGV = ["omp-role", "--name", "kimi", "--session-id", "sid-1", "--role", "conductor"];

function calls(): string[][] {
	const file = join(FAKE_STATE, "calls.jsonl");
	if (!existsSync(file)) return [];
	return readFileSync(file, "utf8")
		.split("\n")
		.filter((line: string) => line.length > 0)
		.map((line: string) => JSON.parse(line) as string[]);
}

function roleCalls(): string[][] {
	return calls().filter((args) => args[0] === "omp-role");
}

type StubHandler = (event: unknown, ctx: StubPi["ctx"]) => unknown;

class StubPi {
	handlers = new Map<string, StubHandler[]>();
	/** The session log `ctx.sessionManager.getEntries()` returns. */
	entries: unknown[] = [];
	readonly ctx = {
		hasUI: true,
		cwd: TEST_ROOT,
		sessionManager: {
			getSessionId: () => "sid-1",
			getSessionFile: () => join(TEST_ROOT, "session.jsonl"),
			getEntries: () => this.entries,
		},
		isIdle: () => false,
	};

	on(event: string, handler: StubHandler): void {
		const list = this.handlers.get(event) ?? [];
		list.push(handler);
		this.handlers.set(event, list);
	}

	async emit(event: string, payload: unknown = {}): Promise<void> {
		for (const handler of this.handlers.get(event) ?? []) await handler(payload, this.ctx);
	}

	sendUserMessage(): void {}
	sendMessage(): void {}
	async exec(): Promise<{ code: number; stdout: string; stderr: string }> {
		return { code: 0, stdout: "omp/18.3.3\n", stderr: "" };
	}
}

function clearIdentityRegistry(): void {
	Reflect.deleteProperty(globalThis, Symbol.for("hcom.omp.identity"));
	delete process.env.HCOM_OMP_IDENTITY_OWNER;
}

type RoleReply = { code: number; stdout?: string; stderr?: string };

/** A fresh extension instance (a new omp process) over `entries`. */
async function startSeat(entries: unknown[], roleReplies?: RoleReply[]): Promise<StubPi> {
	clearIdentityRegistry();
	writeFileSync(join(FAKE_STATE, "calls.jsonl"), "");
	rmSync(join(FAKE_STATE, "role_replies.json"), { force: true });
	if (roleReplies) writeFileSync(join(FAKE_STATE, "role_replies.json"), JSON.stringify(roleReplies));
	const pi = new StubPi();
	pi.entries = entries;
	// The stub replaces the session runtime the plugin talks to; the cast is
	// the deliberate seam between the two shapes.
	hcomExtension(pi as unknown as ExtensionAPI);
	await pi.emit("session_start");
	return pi;
}

async function stopSeat(pi: StubPi): Promise<void> {
	await pi.emit("session_shutdown");
	clearIdentityRegistry();
}

test("conductor marker at session start registers the conductor role once", async () => {
	const pi = await startSeat([MARKER]);
	assert.deepEqual(roleCalls(), [ROLE_ARGV]);
	await pi.emit("before_agent_start");
	await pi.emit("before_agent_start");
	assert.equal(roleCalls().length, 1, "one omp-role per binding");
	await stopSeat(pi);
});

test("session without the marker never registers a role", async () => {
	const pi = await startSeat([{ type: "custom", customType: "something-else" }, { type: "message" }]);
	await pi.emit("before_agent_start");
	await pi.emit("before_agent_start");
	assert.ok(
		calls().some((args) => args[0] === "omp-start"),
		"the seat did bind",
	);
	assert.deepEqual(roleCalls(), []);
	await stopSeat(pi);
});

test("marker appended after the bind registers on the next agent turn", async () => {
	// Fresh `omp --conductor`: conductor-guard may stamp the marker after our
	// session_start bind already ran.
	const pi = await startSeat([]);
	assert.deepEqual(roleCalls(), []);
	pi.entries.push(MARKER);
	await pi.emit("before_agent_start");
	assert.deepEqual(roleCalls(), [ROLE_ARGV]);
	await stopSeat(pi);
});

test("resumed conductor session registers again after each rebind", async () => {
	// `hcom r` of a conductor: a new process over the same session log.
	let pi = await startSeat([MARKER]);
	await stopSeat(pi);
	pi = await startSeat([MARKER]);
	assert.deepEqual(roleCalls(), [ROLE_ARGV]);
	// A session switch rebinds in the same process and registers again.
	await pi.emit("session_switch");
	assert.equal(roleCalls().length, 2);
	await stopSeat(pi);
});

async function turns(pi: StubPi, count: number): Promise<void> {
	for (let i = 0; i < count; i++) await pi.emit("before_agent_start");
}

const TRANSIENT: RoleReply = {
	code: 0,
	stdout: JSON.stringify({ error: "database error: database is locked", transient: true }),
};

test("older hcom without omp-role asks once and keeps the seat bound", async () => {
	// An older binary's router rejects the unknown command before any hook.
	const pi = await startSeat([MARKER], [{ code: 1, stderr: "Error: Unknown command 'omp-role'\n" }]);
	await turns(pi, 4);
	assert.deepEqual(roleCalls(), [ROLE_ARGV]);
	await pi.emit("tool_call", { toolName: "bash", input: { command: "ls" } });
	assert.ok(
		calls().some((args) => args[0] === "omp-beforetool" && args[args.indexOf("--name") + 1] === "kimi"),
		"hooks still run under the bound name",
	);
	await stopSeat(pi);
});

test("a refused registration is asked once", async () => {
	const refused = { error: "kimi already holds role deputy; roles are add-only", transient: false };
	const pi = await startSeat([MARKER], [{ code: 0, stdout: JSON.stringify(refused) }]);
	await turns(pi, 4);
	assert.equal(roleCalls().length, 1);
	await stopSeat(pi);
});

test("a transient failure retries on the next turn and then succeeds", async () => {
	const pi = await startSeat([MARKER], [TRANSIENT, { code: 0, stdout: JSON.stringify({ ok: true }) }]);
	assert.equal(roleCalls().length, 1);
	await turns(pi, 1);
	assert.equal(roleCalls().length, 2);
	await turns(pi, 3);
	assert.equal(roleCalls().length, 2, "settled after the success");
	await stopSeat(pi);
});

test("transient failures give up after five attempts", async () => {
	const pi = await startSeat([MARKER], [TRANSIENT]);
	await turns(pi, 10);
	assert.equal(roleCalls().length, 5);
	await stopSeat(pi);
});
