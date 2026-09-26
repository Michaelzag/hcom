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
const { compactRefusals, contextReplyBody, handleCompactQuery } = await import("./hcom.ts");

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
