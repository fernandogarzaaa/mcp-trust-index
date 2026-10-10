// Zero-dependency checks for the whole index (node:test, Node >= 20).
// Run with: npm test   (or: node --test test/*.test.mjs)
//
// - every indexed badge passes the same schema + placement + signature
//   checks CI runs on a PR (validated against the empty tree, so the
//   "already indexed" rule does not trip);
// - every revocation verifies against keys/project.json, validated against
//   the parent of the commit that added it;
// - a tampered badge is rejected;
// - docs/index.json and docs/index.html are fresh (build-site is a no-op).
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const VALIDATE = join(ROOT, "scripts", "validate.mjs");
const git = (...args) => execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
const EMPTY_TREE = git("hash-object", "-t", "tree", "/dev/null");

function listJson(dir) {
	const out = [];
	for (const sub of readdirSync(join(ROOT, dir), { withFileTypes: true })) {
		if (!sub.isDirectory()) continue;
		for (const f of readdirSync(join(ROOT, dir, sub.name))) {
			if (f.endsWith(".json")) out.push(`${dir}/${sub.name}/${f}`);
		}
	}
	return out.sort();
}

function validate(cwd, base, files) {
	return spawnSync(process.execPath, [VALIDATE, "--base", base, "--files", ...files], {
		cwd,
		encoding: "utf8",
	});
}

test("every indexed badge passes schema, placement and signature checks", () => {
	const badges = listJson("badges");
	assert.ok(badges.length > 0, "no badges found");
	const r = validate(ROOT, EMPTY_TREE, badges);
	assert.equal(r.status, 0, r.stderr);
	assert.match(r.stdout, new RegExp(`all ${badges.length} file\\(s\\) valid`));
});

test("every revocation verifies against the project key", () => {
	for (const path of listJson("revocations")) {
		const added = git("log", "--diff-filter=A", "--format=%H", "--", path).split("\n").pop();
		assert.ok(added, `no commit adds ${path} (shallow clone? use fetch-depth: 0)`);
		const r = validate(ROOT, `${added}~1`, [path]);
		assert.equal(r.status, 0, `${path}: ${r.stderr}`);
	}
});

test("a tampered badge is rejected", () => {
	const [path] = listJson("badges").filter((p) => !p.startsWith("badges/fixture-server/"));
	const badge = JSON.parse(readFileSync(join(ROOT, path), "utf8"));
	badge.riskScore = badge.riskScore === 0 ? 1 : 0;
	const dir = mkdtempSync(join(tmpdir(), "sigil-index-test-"));
	try {
		mkdirSync(join(dir, dirname(path)), { recursive: true });
		writeFileSync(join(dir, path), JSON.stringify(badge));
		const r = validate(dir, EMPTY_TREE, [path]);
		assert.equal(r.status, 1);
		assert.match(r.stderr, /signature does not verify/);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("docs/index.json and docs/index.html are fresh", () => {
	const before = {
		json: readFileSync(join(ROOT, "docs/index.json"), "utf8"),
		html: readFileSync(join(ROOT, "docs/index.html"), "utf8"),
	};
	execFileSync(process.execPath, [join(ROOT, "scripts/build-site.mjs")], { cwd: ROOT });
	const after = {
		json: readFileSync(join(ROOT, "docs/index.json"), "utf8"),
		html: readFileSync(join(ROOT, "docs/index.html"), "utf8"),
	};
	assert.equal(after.json, before.json, "docs/index.json is stale: run npm run build and commit");
	assert.equal(after.html, before.html, "docs/index.html is stale: run npm run build and commit");
	const manifest = JSON.parse(after.json);
	assert.equal(manifest.count, listJson("badges").length);
});
