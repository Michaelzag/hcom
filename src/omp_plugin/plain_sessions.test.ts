// The plugin's `plain_sessions` opt-in must read a value exactly as the Rust
// gate does. `plain_sessions_cases.json` is the shared table; the Rust side
// checks the same rows in `config::tests::plain_sessions_cases_match_rust_parser`.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

// Importing the plugin runs its load-time identity resolution and logging, so
// HCOM_DIR must point at a throwaway dir first. A static import would hoist
// above this assignment and log into the real HCOM_DIR.
process.env.HCOM_DIR = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "hcom-plugin-test-"));
const { plainSessionsValueEnabled } = await import("./hcom.ts");

const cases: [string, boolean][] = JSON.parse(
	readFileSync(new URL("./plain_sessions_cases.json", import.meta.url), "utf8"),
);

test("plugin reads plain_sessions values the way the Rust gate does", () => {
	const disagreements = cases
		.filter(([value, enabled]) => plainSessionsValueEnabled(value) !== enabled)
		.map(([value, enabled]) => `${JSON.stringify(value)}: rust=${enabled}`);
	assert.deepEqual(disagreements, []);
});
