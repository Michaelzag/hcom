// The compact request handler and the context reply are pure over the live
// state the ExtensionContext exposes; the tests stub that ctx, as the plugin
// reads it at request time. Importing the plugin runs its load-time identity
// resolution and logging, so HCOM_DIR must point at a throwaway dir first (see
// plain_sessions.test.ts).
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import type {
	AsyncJobSnapshotView,
	CompactCheckContext,
	CompactRequest,
	ContextQueryContext,
} from "./hcom.ts";

process.env.HCOM_DIR = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "hcom-plugin-test-"));
// Dynamic on purpose: a static import hoists above the HCOM_DIR assignment and
// the plugin's load-time identity resolution would log into the real HCOM_DIR.
const {
	compactRefusals,
	contextReplyBody,
	handleCompactQuery,
	serveCompactRequest,
	createCompactGate,
	PLUGIN_COMPACT_BUDGET_MS,
	CLI_COMPACT_REPLY_DEADLINE_MS,
	COMPACT_RESERVATION_STALE_MS,
} = await import("./hcom.ts");

type Stub = {
	/** default: idle */
	idle?: boolean;
	/** default: no queued messages */
	pending?: boolean;
	/** undefined = a host without getAsyncJobSnapshot; null = no job manager */
	snapshot?: AsyncJobSnapshotView | null;
};

function stubCtx(stub: Stub): CompactCheckContext {
	const ctx: CompactCheckContext = {
		isIdle: () => stub.idle ?? true,
		hasPendingMessages: () => stub.pending ?? false,
	};
	if (stub.snapshot !== undefined) ctx.getAsyncJobSnapshot = () => stub.snapshot ?? null;
	return ctx;
}

function snapshot(running: number, queued: number, delivering: boolean): AsyncJobSnapshotView {
	return {
		running: Array.from({ length: running }, () => ({})),
		delivery: { queued, delivering },
	};
}

// --- one refusal reason alone -----------------------------------------------

test("a live turn refuses alone", () => {
	assert.deepEqual(compactRefusals(stubCtx({ idle: false, snapshot: snapshot(0, 0, false) }), 0), [
		"live turn",
	]);
});

test("running jobs refuse alone", () => {
	assert.deepEqual(compactRefusals(stubCtx({ snapshot: snapshot(2, 0, false) }), 0), [
		"2 running jobs",
	]);
});

test("queued deliveries refuse alone, counting the one being delivered", () => {
	assert.deepEqual(compactRefusals(stubCtx({ snapshot: snapshot(0, 1, true) }), 0), [
		"2 queued deliveries",
	]);
});

test("pending messages refuse alone", () => {
	assert.deepEqual(compactRefusals(stubCtx({ pending: true, snapshot: snapshot(0, 0, false) }), 0), [
		"pending messages",
	]);
});

test("undelivered hcom messages refuse alone", () => {
	assert.deepEqual(compactRefusals(stubCtx({ snapshot: snapshot(0, 0, false) }), 3), [
		"pending hcom messages",
	]);
});

test("an unknown snapshot refuses", () => {
	// A host without getAsyncJobSnapshot: the job state is unknown.
	assert.deepEqual(compactRefusals(stubCtx({}), 0), ["job state unknown"]);
	// A session with no job manager answers null: also unknown, never 0.
	assert.deepEqual(compactRefusals(stubCtx({ snapshot: null }), 0), ["job state unknown"]);
});

// --- every reason that applies, in order ------------------------------------

test("every reason that applies is returned, in order", () => {
	assert.deepEqual(
		compactRefusals(stubCtx({ idle: false, pending: true, snapshot: snapshot(3, 2, true) }), 2),
		[
			"live turn",
			"3 running jobs",
			"3 queued deliveries",
			"pending messages",
			"pending hcom messages",
		],
	);
});

test("an unknown snapshot stacks behind the checks that still ran", () => {
	assert.deepEqual(compactRefusals(stubCtx({ idle: false, pending: true }), 4), [
		"live turn",
		"pending messages",
		"pending hcom messages",
		"job state unknown",
	]);
});

test("a clean seat has no refusals", () => {
	assert.deepEqual(compactRefusals(stubCtx({ snapshot: snapshot(0, 0, false) }), 0), []);
});

// --- dry vs real -------------------------------------------------------------

test("a clean seat answers would on a dry run and starts nothing", () => {
	assert.deepEqual(handleCompactQuery({ dry: true }, stubCtx({ snapshot: snapshot(0, 0, false) }), 0), {
		reply: '{"ok":true,"would":true}',
		start: false,
	});
});

test("a clean real request answers compacting and starts", () => {
	const clean = stubCtx({ snapshot: snapshot(0, 0, false) });
	assert.deepEqual(handleCompactQuery({ dry: false }, clean, 0), {
		reply: '{"ok":true,"compacting":true}',
		start: true,
	});
	// No dry field is a real request, never a silent dry run.
	assert.deepEqual(handleCompactQuery({}, clean, 0), {
		reply: '{"ok":true,"compacting":true}',
		start: true,
	});
});

test("a refused request starts nothing and carries the reasons verbatim", () => {
	const answer = handleCompactQuery(
		{ dry: true },
		stubCtx({ idle: false, snapshot: snapshot(2, 0, false) }),
		0,
	);
	assert.equal(answer.start, false);
	assert.deepEqual(JSON.parse(answer.reply), {
		ok: false,
		refuse: ["live turn", "2 running jobs"],
	});
});

test("the focus travels in the request, never in the reply", () => {
	const query: CompactRequest = { focus: "ship the release", dry: true };
	const answer = handleCompactQuery(query, stubCtx({ snapshot: snapshot(0, 0, false) }), 0);
	assert.deepEqual(JSON.parse(answer.reply), { ok: true, would: true });
});

// --- the context reply ---------------------------------------------------------

test("the context reply advertises compact and keeps its shape", () => {
	const ctx: ContextQueryContext = {
		getContextUsage: () => ({ tokens: 182340, contextWindow: 258400, percent: 70.6 }),
		getAsyncJobSnapshot: () => snapshot(1, 0, false),
	};
	assert.deepEqual(JSON.parse(contextReplyBody(ctx)), {
		tokens: 182340,
		contextWindow: 258400,
		percent: 70.6,
		jobs: 1,
		caps: ["compact"],
	});
});

test("a context reply with unknown usage and jobs is nulls, not zeroes", () => {
	assert.deepEqual(JSON.parse(contextReplyBody(null)), {
		tokens: null,
		contextWindow: null,
		percent: null,
		jobs: null,
		caps: ["compact"],
	});
});

// --- reservation and check budget ---------------------------------------------

function cleanCtx(extra: Partial<CompactCheckContext> = {}): CompactCheckContext {
	return {
		...stubCtx({ snapshot: snapshot(0, 0, false) }),
		compact: async () => {},
		...extra,
	};
}

async function flush(): Promise<void> {
	await Promise.resolve();
	await Promise.resolve();
}

test("the plugin budget is strictly under the CLI deadline", () => {
	assert.equal(PLUGIN_COMPACT_BUDGET_MS, 1500);
	assert.equal(CLI_COMPACT_REPLY_DEADLINE_MS, 5000);
	assert.ok(PLUGIN_COMPACT_BUDGET_MS < CLI_COMPACT_REPLY_DEADLINE_MS);
	assert.equal(COMPACT_RESERVATION_STALE_MS, 630_000);
});

test("a slow lookup refuses and never compacts", async () => {
	// The lookup never settles. The refusal is the product budget race, which
	// this test awaits — it does not sleep past a guess.
	const gate = createCompactGate();
	const pending = Promise.withResolvers<number>();
	let calls = 0;
	const replies: string[] = [];
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			compact: async () => {
				calls += 1;
			},
		}),
		fetchPending: () => pending.promise,
		writeReply: (reply) => replies.push(reply),
		budgetMs: 20,
		staleMs: 60_000,
	});
	assert.equal(calls, 0);
	assert.equal(gate.reservedAt, null);
	assert.deepEqual(JSON.parse(replies[0] ?? ""), {
		ok: false,
		refuse: ["plugin busy: checks exceeded 1500 ms"],
	});
});

test("an elapsed budget is re-checked before start and never compacts", async () => {
	const gate = createCompactGate();
	let mono = 0;
	let calls = 0;
	const replies: string[] = [];
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			compact: async () => {
				calls += 1;
			},
		}),
		fetchPending: async () => {
			mono = 40;
			return 0;
		},
		mono: () => mono,
		writeReply: (reply) => replies.push(reply),
		budgetMs: 30,
		staleMs: 60_000,
	});
	assert.equal(calls, 0);
	assert.equal(gate.reservedAt, null);
	assert.deepEqual(JSON.parse(replies[0] ?? "").refuse, [
		"plugin busy: checks exceeded 1500 ms",
	]);
});

test("two overlapping real requests produce one start and one already in progress", async () => {
	const gate = createCompactGate();
	const replies: string[] = [];
	let calls = 0;
	const compacting = Promise.withResolvers<void>();
	const ctx = cleanCtx({
		compact: () => {
			calls += 1;
			return compacting.promise;
		},
	});
	const pending = Promise.withResolvers<number>();
	const first = serveCompactRequest({
		gate,
		query: { dry: false },
		ctx,
		fetchPending: () => pending.promise,
		writeReply: (reply) => replies.push(reply),
		budgetMs: 500,
		staleMs: 60_000,
	});
	const second = serveCompactRequest({
		gate,
		query: {},
		ctx,
		fetchPending: async () => 0,
		writeReply: (reply) => replies.push(reply),
		budgetMs: 500,
		staleMs: 60_000,
	});
	assert.equal(replies.length, 1);
	assert.deepEqual(JSON.parse(replies[0] ?? ""), {
		ok: false,
		refuse: ["compaction already in progress"],
	});
	assert.equal(calls, 0);
	pending.resolve(0);
	await first;
	await second;
	assert.equal(calls, 1);
	assert.equal(replies.length, 2);
	const started = JSON.parse(replies[1] ?? "");
	assert.equal(started.ok, true);
	assert.equal(started.compacting, true);
	assert.equal(typeof started.started_at, "number");
	assert.notEqual(gate.reservedAt, null);
	compacting.resolve();
	await flush();
	assert.equal(gate.reservedAt, null);
});

test("the reservation is released when compact resolves", async () => {
	const gate = createCompactGate();
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx(),
		fetchPending: async () => 0,
		writeReply: () => {},
		budgetMs: 500,
		staleMs: 60_000,
	});
	await flush();
	assert.equal(gate.reservedAt, null);
});

test("the reservation is released when compact rejects", async () => {
	const gate = createCompactGate();
	const failures: unknown[] = [];
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			compact: () => Promise.reject(new Error("compact failed")),
		}),
		fetchPending: async () => 0,
		writeReply: () => {},
		onCompactFailed: (error) => failures.push(error),
		budgetMs: 500,
		staleMs: 60_000,
	});
	await flush();
	assert.equal(gate.reservedAt, null);
	assert.equal(failures.length, 1);
});

test("the reservation is released after a refusal", async () => {
	const gate = createCompactGate();
	let calls = 0;
	const replies: string[] = [];
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			isIdle: () => false,
			compact: async () => {
				calls += 1;
			},
		}),
		fetchPending: async () => {
			assert.notEqual(gate.reservedAt, null);
			return 0;
		},
		writeReply: (reply) => replies.push(reply),
		budgetMs: 500,
		staleMs: 60_000,
	});
	assert.equal(calls, 0);
	assert.equal(gate.reservedAt, null);
	assert.deepEqual(JSON.parse(replies[0] ?? ""), { ok: false, refuse: ["live turn"] });
});

test("a dry run never reserves", async () => {
	const gate = createCompactGate();
	await serveCompactRequest({
		gate,
		query: { dry: true },
		ctx: cleanCtx(),
		fetchPending: async () => {
			assert.equal(gate.reservedAt, null);
			return 0;
		},
		writeReply: () => {},
		budgetMs: 500,
		staleMs: 60_000,
	});
	assert.equal(gate.reservedAt, null);
});

test("a dry run reports already in progress and does not take the reservation", async () => {
	const gate = createCompactGate();
	const heldAt = Date.now();
	gate.reservedAt = heldAt;
	gate.token = 3;
	const replies: string[] = [];
	await serveCompactRequest({
		gate,
		query: { dry: true },
		ctx: cleanCtx(),
		fetchPending: async () => 0,
		writeReply: (reply) => replies.push(reply),
		budgetMs: 500,
		staleMs: 60_000,
	});
	assert.equal(gate.reservedAt, heldAt);
	assert.equal(gate.token, 3);
	assert.deepEqual(JSON.parse(replies[0] ?? ""), {
		ok: false,
		refuse: ["compaction already in progress"],
	});
});

test("omp already compacting refuses without reserving", async () => {
	const gate = createCompactGate();
	let calls = 0;
	const replies: string[] = [];
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			isCompacting: () => true,
			compact: async () => {
				calls += 1;
			},
		}),
		fetchPending: async () => {
			throw new Error("checks must not run");
		},
		writeReply: (reply) => replies.push(reply),
		budgetMs: 500,
		staleMs: 60_000,
	});
	assert.equal(calls, 0);
	assert.equal(gate.reservedAt, null);
	assert.deepEqual(JSON.parse(replies[0] ?? "").refuse, ["compaction already in progress"]);
});

test("a stale reservation is released and logged", async () => {
	const gate = createCompactGate();
	gate.reservedAt = 1_000;
	gate.token = 4;
	const logged: number[] = [];
	let calls = 0;
	const replies: string[] = [];
	const now = 1_000 + COMPACT_RESERVATION_STALE_MS;
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			compact: async () => {
				calls += 1;
			},
		}),
		fetchPending: async () => 0,
		writeReply: (reply) => replies.push(reply),
		now: () => now,
		staleMs: COMPACT_RESERVATION_STALE_MS,
		onStale: (at) => logged.push(at),
		budgetMs: 500,
	});
	await flush();
	assert.deepEqual(logged, [1_000]);
	assert.equal(calls, 1);
	assert.equal(gate.reservedAt, null);
	assert.equal(JSON.parse(replies[0] ?? "").compacting, true);
});

test("the stale timer releases a hung reservation", async () => {
	// The bound is a real plugin timer. The test awaits that callback rather
	// than sleeping past a guess; a fake clock cannot see the timer the plugin arms.
	const gate = createCompactGate();
	const released = Promise.withResolvers<number>();
	const compacting = Promise.withResolvers<void>();
	await serveCompactRequest({
		gate,
		query: {},
		ctx: cleanCtx({
			compact: () => compacting.promise,
		}),
		fetchPending: async () => 0,
		writeReply: () => {},
		staleMs: 20,
		onStale: (at) => released.resolve(at),
		budgetMs: 500,
	});
	assert.notEqual(gate.reservedAt, null);
	const reservedAt = await released.promise;
	assert.equal(typeof reservedAt, "number");
	assert.equal(gate.reservedAt, null);
	compacting.resolve();
	await flush();
	assert.equal(gate.reservedAt, null);
});
