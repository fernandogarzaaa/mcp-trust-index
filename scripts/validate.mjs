/**
 * validate.mjs: CI validation for trust badge submissions.
 *
 * Usage:
 *   node scripts/validate.mjs --base <git-ref> [--files <path...>]
 *
 * With --files, validates exactly those paths. Without it, discovers badge
 * files added by the current branch relative to --base (default origin/main)
 * via `git diff --diff-filter=A`.
 *
 * For each badge file under badges/ it checks:
 *   1. the path matches badges/<sanitized-server>/<sanitized-version>.json
 *      and the badge's server/version fields sanitize to those segments;
 *   2. the badge JSON matches the mcp-trust badge schema (v1), including the
 *      optional artifact field when present;
 *   3. the Ed25519 signature verifies against the embedded public key and
 *      the keyId matches that key (ported from mcp-trust's src/sign.ts;
 *      node stdlib only, no dependencies);
 *   4. the path does not already exist on the base ref (the index is
 *      append-only per version in v1).
 *
 * For each revocation file under revocations/ it checks:
 *   1. the path matches revocations/<sanitized-server>/<sanitized-version>.json
 *      and the revocation's server/version fields sanitize to those segments;
 *   2. the revocation JSON matches the mcp-trust revocation schema (v1);
 *   3. the Ed25519 signature verifies against the project maintainer key
 *      published at keys/project.json on the base ref;
 *   4. a badge for that server@version exists on the base ref (you can only
 *      revoke what is indexed);
 *   5. no revocation for that path already exists on the base ref.
 *
 * keys/ is immutable after bootstrap: a PR may add keys/project.json only
 * when it is absent on the base ref; modifying or deleting it always fails.
 *
 * Any badges/ or revocations/ file that is modified or deleted (not added)
 * fails validation: the index is append-only in v1.
 *
 * Exit 0 when every file is valid, 1 otherwise, with one clear reason per
 * failed file on stderr.
 */

import { execFileSync } from "node:child_process";
import {
	createHash,
	createPublicKey,
	verify as cryptoVerify,
} from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

const BADGE_TYPE = "mcp-trust-badge/v1";
const REVOCATION_TYPE = "mcp-trust-revocation/v1";
const RISK_LEVELS = ["low", "medium", "high", "critical"];
const HEX64 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{16}$/;
const SAFE_SEGMENT = /^[A-Za-z0-9._-]+$/;
const ARTIFACT_TYPES = ["npm", "git", "local"];
const MAINTAINER_KEY_PATH = "keys/project.json";

/** Canonical JSON: object keys sorted recursively, no whitespace. Ported from mcp-trust src/sign.ts. */
function canonicalize(value) {
	if (Array.isArray(value)) {
		return `[${value.map((v) => canonicalize(v)).join(",")}]`;
	}
	if (value !== null && typeof value === "object") {
		const entries = Object.entries(value)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`);
		return `{${entries.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

function sha256Hex(data) {
	return createHash("sha256").update(data, "utf8").digest("hex");
}

/**
 * Path segment rule. Must be identical to the rule in trustscan's publish
 * command: lowercase, anything outside [a-z0-9._-] becomes "-", runs
 * collapsed, never empty, never "." or "..".
 */
export function sanitizeSegment(raw) {
	const out = String(raw)
		.toLowerCase()
		.replace(/[^a-z0-9._-]+/g, "-")
		.replace(/-+/g, "-")
		.replace(/^[-.]+|[-.]+$/g, "");
	return out;
}

/** Full cryptographic verification. Ported from mcp-trust src/sign.ts verifyBadge. */
function verifySignature(badge) {
	if (!badge || badge.type !== BADGE_TYPE) {
		return { ok: false, reason: "not a mcp-trust badge (bad type field)" };
	}
	if (
		!badge.publicKey ||
		typeof badge.publicKey !== "object" ||
		typeof badge.signature !== "string" ||
		badge.signature.length === 0
	) {
		return { ok: false, reason: "badge is missing its public key or signature" };
	}
	let publicKey;
	try {
		publicKey = createPublicKey({ key: badge.publicKey, format: "jwk" });
	} catch (error) {
		return {
			ok: false,
			reason: `embedded public key is invalid: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	const { signature, ...unsigned } = badge;
	const expectedKeyId = sha256Hex(canonicalize(badge.publicKey)).slice(0, 16);
	if (badge.keyId !== expectedKeyId) {
		return {
			ok: false,
			reason: `keyId "${badge.keyId}" does not match the embedded public key (expected "${expectedKeyId}")`,
		};
	}
	let signatureOk = false;
	try {
		signatureOk = cryptoVerify(
			null,
			Buffer.from(canonicalize(unsigned), "utf8"),
			publicKey,
			Buffer.from(signature, "base64"),
		);
	} catch (error) {
		return {
			ok: false,
			reason: `signature check threw: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	if (!signatureOk) {
		return {
			ok: false,
			reason: "signature does not verify against the embedded public key",
		};
	}
	return { ok: true, reason: "" };
}

/** Schema problems for a parsed badge. Returns a list of human-readable problems. */
function schemaProblems(badge) {
	const problems = [];
	const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

	if (!isObj(badge)) return ["badge root is not a JSON object"];
	if (badge.type !== BADGE_TYPE)
		problems.push(`type must be "${BADGE_TYPE}"`);
	if (typeof badge.server !== "string" || badge.server.length === 0)
		problems.push("server must be a non-empty string");
	if (typeof badge.version !== "string" || badge.version.length === 0)
		problems.push("version must be a non-empty string");
	else if (!SAFE_SEGMENT.test(badge.version))
		problems.push(
			`version "${badge.version}" contains characters outside [A-Za-z0-9._-]`,
		);
	if (
		typeof badge.riskScore !== "number" ||
		!Number.isFinite(badge.riskScore) ||
		badge.riskScore < 0 ||
		badge.riskScore > 100
	)
		problems.push("riskScore must be a number between 0 and 100");
	if (!RISK_LEVELS.includes(badge.riskLevel))
		problems.push(`riskLevel must be one of ${RISK_LEVELS.join(", ")}`);
	if (badge.scores !== null) {
		if (!isObj(badge.scores))
			problems.push("scores must be an object or null");
		else {
			for (const [k, v] of Object.entries(badge.scores)) {
				if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 100)
					problems.push(`scores.${k} must be a number between 0 and 100`);
			}
		}
	}
	if (!isObj(badge.findingCounts))
		problems.push("findingCounts must be an object");
	else {
		for (const k of ["critical", "major", "minor", "info"]) {
			const v = badge.findingCounts[k];
			if (!Number.isInteger(v) || v < 0)
				problems.push(`findingCounts.${k} must be a non-negative integer`);
		}
	}
	if (typeof badge.evalHash !== "string" || !HEX64.test(badge.evalHash))
		problems.push("evalHash must be a 64-char lowercase hex SHA-256");
	if (typeof badge.keyId !== "string" || !HEX16.test(badge.keyId))
		problems.push("keyId must be a 16-char lowercase hex string");
	if (!isObj(badge.publicKey)) problems.push("publicKey must be an object");
	else {
		if (badge.publicKey.kty !== "OKP")
			problems.push('publicKey.kty must be "OKP"');
		if (badge.publicKey.crv !== "Ed25519")
			problems.push('publicKey.crv must be "Ed25519"');
		if (typeof badge.publicKey.x !== "string" || badge.publicKey.x.length < 40)
			problems.push("publicKey.x must be the base64url Ed25519 public key");
	}
	if (typeof badge.issuedAt !== "string" || Number.isNaN(Date.parse(badge.issuedAt)))
		problems.push("issuedAt must be an ISO-8601 date string");
	if (typeof badge.signature !== "string" || badge.signature.length === 0)
		problems.push("signature must be a non-empty string");
	if (badge.artifact !== undefined) {
		if (!isObj(badge.artifact)) problems.push("artifact must be an object");
		else {
			if (!ARTIFACT_TYPES.includes(badge.artifact.type))
				problems.push(
					`artifact.type must be one of ${ARTIFACT_TYPES.join(", ")}`,
				);
			if (
				typeof badge.artifact.spec !== "string" ||
				badge.artifact.spec.length === 0
			)
				problems.push("artifact.spec must be a non-empty string");
			if (
				badge.artifact.integrity !== undefined &&
				(typeof badge.artifact.integrity !== "string" ||
					badge.artifact.integrity.length === 0)
			)
				problems.push("artifact.integrity must be a non-empty string");
		}
	}
	return problems;
}

/** Schema problems for a parsed revocation. Returns human-readable problems. */
function schemaProblemsRevocation(rev) {
	const problems = [];
	const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

	if (!isObj(rev)) return ["revocation root is not a JSON object"];
	if (rev.type !== REVOCATION_TYPE)
		problems.push(`type must be "${REVOCATION_TYPE}"`);
	if (typeof rev.server !== "string" || rev.server.length === 0)
		problems.push("server must be a non-empty string");
	if (typeof rev.version !== "string" || rev.version.length === 0)
		problems.push("version must be a non-empty string");
	else if (!SAFE_SEGMENT.test(rev.version))
		problems.push(
			`version "${rev.version}" contains characters outside [A-Za-z0-9._-]`,
		);
	if (rev.status !== "revoked") problems.push('status must be "revoked"');
	if (typeof rev.reason !== "string" || rev.reason.trim().length === 0)
		problems.push("reason must be a non-empty string");
	if (typeof rev.revokedAt !== "string" || Number.isNaN(Date.parse(rev.revokedAt)))
		problems.push("revokedAt must be an ISO-8601 date string");
	if (typeof rev.keyId !== "string" || !HEX16.test(rev.keyId))
		problems.push("keyId must be a 16-char lowercase hex string");
	if (!isObj(rev.publicKey)) problems.push("publicKey must be an object");
	else {
		if (rev.publicKey.kty !== "OKP")
			problems.push('publicKey.kty must be "OKP"');
		if (rev.publicKey.crv !== "Ed25519")
			problems.push('publicKey.crv must be "Ed25519"');
		if (typeof rev.publicKey.x !== "string" || rev.publicKey.x.length < 40)
			problems.push("publicKey.x must be the base64url Ed25519 public key");
	}
	if (typeof rev.signature !== "string" || rev.signature.length === 0)
		problems.push("signature must be a non-empty string");
	return problems;
}

function gitExistsOnRef(ref, path) {
	try {
		execFileSync("git", ["cat-file", "-e", `${ref}:${path}`], {
			stdio: "ignore",
		});
		return true;
	} catch {
		return false;
	}
}

/**
 * Read the project maintainer key. Prefers the base ref (so a PR cannot
 * swap the trust anchor); falls back to the working tree for --files mode.
 * Returns { keyId, publicKey } or throws.
 */
function readMaintainerKey(base, fromWorkingTree) {
	let raw;
	if (!fromWorkingTree) {
		try {
			raw = execFileSync(
				"git",
				["show", `${base}:${MAINTAINER_KEY_PATH}`],
				{ encoding: "utf8" },
			);
		} catch {
			throw new Error(
				`${MAINTAINER_KEY_PATH} is not present on ${base}; the project key must be committed before revocations can be validated`,
			);
		}
	} else {
		if (!existsSync(MAINTAINER_KEY_PATH)) {
			throw new Error(
				`${MAINTAINER_KEY_PATH} not found in the working tree`,
			);
		}
		raw = readFileSync(MAINTAINER_KEY_PATH, "utf8");
	}
	const parsed = JSON.parse(raw);
	if (
		!parsed ||
		typeof parsed.keyId !== "string" ||
		!parsed.publicKey ||
		typeof parsed.publicKey !== "object"
	) {
		throw new Error(`${MAINTAINER_KEY_PATH} is not a valid key file`);
	}
	return { keyId: parsed.keyId, publicKey: parsed.publicKey };
}

/** Verify a revocation's signature against the maintainer key. */
function verifyRevocationSignature(rev, maintainerKey) {
	const embedded = JSON.stringify(rev.publicKey);
	const expected = JSON.stringify(maintainerKey.publicKey);
	if (rev.keyId !== maintainerKey.keyId || embedded !== expected) {
		return {
			ok: false,
			reason: `revocation is not signed by the project key (expected keyId "${maintainerKey.keyId}")`,
		};
	}
	const { signature, ...unsigned } = rev;
	let ok = false;
	try {
		const publicKey = createPublicKey({
			key: maintainerKey.publicKey,
			format: "jwk",
		});
		ok = cryptoVerify(
			null,
			Buffer.from(canonicalize(unsigned), "utf8"),
			publicKey,
			Buffer.from(signature, "base64"),
		);
	} catch (error) {
		return {
			ok: false,
			reason: `signature check threw: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
	if (!ok) return { ok: false, reason: "signature does not verify" };
	return { ok: true, reason: "" };
}

function validateOneRevocation(path, base, maintainerKey) {
	// 1. Path shape.
	const m = path.match(/^revocations\/([^/]+)\/([^/]+)\.json$/);
	if (!m) {
		return `path must be revocations/<server>/<version>.json (got "${path}")`;
	}
	const [, serverSeg, versionSeg] = m;
	// 2. Parse.
	let rev;
	try {
		rev = JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		return `not valid JSON: ${error instanceof Error ? error.message : String(error)}`;
	}
	// 3. Schema.
	const problems = schemaProblemsRevocation(rev);
	if (problems.length > 0) {
		return `schema problems: ${problems.join("; ")}`;
	}
	// 4. Placement matches sanitized fields.
	if (sanitizeSegment(rev.server) !== serverSeg) {
		return `path server segment "${serverSeg}" does not match sanitized revocation server "${sanitizeSegment(rev.server)}"`;
	}
	if (rev.version !== versionSeg) {
		return `path version segment "${versionSeg}" does not match revocation version "${rev.version}"`;
	}
	// 5. The badge being revoked must be indexed on base.
	const badgePath = `badges/${serverSeg}/${versionSeg}.json`;
	if (!gitExistsOnRef(base, badgePath)) {
		return `cannot revoke ${rev.server}@${rev.version}: no badge at ${badgePath} on ${base}`;
	}
	// 6. No duplicate revocation.
	if (gitExistsOnRef(base, path)) {
		return `already revoked: ${path} exists on ${base} (revocations are append-only)`;
	}
	// 7. Maintainer signature.
	const sig = verifyRevocationSignature(rev, maintainerKey);
	if (!sig.ok) return `signature invalid: ${sig.reason}`;
	return null;
}

function addedFiles(base, dir) {
	const out = execFileSync(
		"git",
		["diff", "--name-only", "--diff-filter=A", `${base}...HEAD`, "--", `${dir}/`],
		{ encoding: "utf8" },
	);
	return out
		.split("\n")
		.map((s) => s.trim())
		.filter((s) => s.length > 0 && s.endsWith(".json"));
}

function touchedNonAddedFiles(base, dir) {
	const out = execFileSync(
		"git",
		[
			"diff",
			"--name-only",
			"--diff-filter=MDRT",
			`${base}...HEAD`,
			"--",
			`${dir}/`,
		],
		{ encoding: "utf8" },
	);
	return out
		.split("\n")
		.map((s) => s.trim())
		.filter((s) => s.length > 0);
}

function addedBadgeFiles(base) {
	return addedFiles(base, "badges");
}

function touchedNonAddedBadgeFiles(base) {
	return touchedNonAddedFiles(base, "badges");
}

function addedRevocationFiles(base) {
	return addedFiles(base, "revocations");
}

function touchedNonAddedRevocationFiles(base) {
	return touchedNonAddedFiles(base, "revocations");
}

/**
 * keys/ change policy: the project key may be added only when absent on
 * base (bootstrap); it may never be modified or deleted afterwards.
 * Returns a list of failure messages (empty when the policy holds).
 */
function keysFileProblems(path, base) {
	if (path !== MAINTAINER_KEY_PATH) {
		return [
			`only ${MAINTAINER_KEY_PATH} may live under keys/`,
		];
	}
	if (gitExistsOnRef(base, MAINTAINER_KEY_PATH)) {
		return [
			`the project key already exists on ${base} and is immutable`,
		];
	}
	// Bootstrap: validate the key file shape.
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8"));
		if (
			!parsed ||
			typeof parsed.keyId !== "string" ||
			!HEX16.test(parsed.keyId) ||
			!parsed.publicKey ||
			typeof parsed.publicKey !== "object" ||
			parsed.publicKey.kty !== "OKP" ||
			parsed.publicKey.crv !== "Ed25519" ||
			typeof parsed.publicKey.x !== "string"
		) {
			return [
				`not a valid project key file (needs keyId hex16 + Ed25519 publicKey JWK)`,
			];
		}
	} catch (error) {
		return [
			`not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
		];
	}
	return [];
}

function checkKeysPolicy(base) {
	const failures = [];
	const added = addedFiles(base, "keys");
	const touched = touchedNonAddedFiles(base, "keys");
	for (const path of touched) {
		failures.push(
			`FAIL ${path}: the project key is immutable; keys/ cannot be modified or deleted via PR`,
		);
	}
	for (const path of added) {
		for (const problem of keysFileProblems(path, base)) {
			failures.push(`FAIL ${path}: ${problem}`);
		}
	}
	return failures;
}

function validateOne(path, base) {
	// 1. Path shape and placement.
	const m = path.match(/^badges\/([^/]+)\/([^/]+)\.json$/);
	if (!m) {
		return `path must be badges/<server>/<version>.json (got "${path}")`;
	}
	const [, serverSeg, versionSeg] = m;
	// 2. Parse.
	let badge;
	try {
		badge = JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		return `not valid JSON: ${error instanceof Error ? error.message : String(error)}`;
	}
	// 3. Schema.
	const problems = schemaProblems(badge);
	if (problems.length > 0) {
		return `schema problems: ${problems.join("; ")}`;
	}
	// 4. Placement matches sanitized fields.
	if (sanitizeSegment(badge.server) !== serverSeg) {
		return `path server segment "${serverSeg}" does not match sanitized badge server "${sanitizeSegment(badge.server)}"`;
	}
	if (badge.version !== versionSeg) {
		return `path version segment "${versionSeg}" does not match badge version "${badge.version}"`;
	}
	// 5. Duplicate: already indexed on base.
	if (gitExistsOnRef(base, path)) {
		return `version already indexed: ${path} exists on ${base} (the index is append-only per version in v1)`;
	}
	// 6. Cryptographic signature.
	const sig = verifySignature(badge);
	if (!sig.ok) return `signature invalid: ${sig.reason}`;
	return null;
}

function parseArgs(argv) {
	const args = { base: "origin/main", files: null };
	for (let i = 0; i < argv.length; i++) {
		if (argv[i] === "--base") args.base = argv[++i];
		else if (argv[i] === "--files") {
			args.files = [];
			while (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
				args.files.push(argv[++i]);
			}
		}
	}
	return args;
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	let failures = 0;

	// keys/ immutability policy.
	if (!args.files) {
		for (const failure of checkKeysPolicy(args.base)) {
			console.error(failure);
			failures++;
		}
	}

	// Append-only enforcement: no modified/deleted/renamed badge or
	// revocation files.
	if (!args.files) {
		for (const path of touchedNonAddedBadgeFiles(args.base)) {
			console.error(
				`FAIL ${path}: the trust index is append-only in v1; badges cannot be modified or removed via PR`,
			);
			failures++;
		}
		for (const path of touchedNonAddedRevocationFiles(args.base)) {
			console.error(
				`FAIL ${path}: revocations are append-only; they cannot be modified or removed via PR`,
			);
			failures++;
		}
	}

	// Maintainer key for revocation signatures (from the base ref so a PR
	// cannot swap the trust anchor).
	let maintainerKey = null;
	let maintainerKeyError = null;
	try {
		maintainerKey = readMaintainerKey(args.base, args.files !== null);
	} catch (error) {
		maintainerKeyError = error instanceof Error ? error.message : String(error);
	}

	const badgeFiles =
		args.files?.filter((p) => p.startsWith("badges/")) ??
		addedBadgeFiles(args.base).filter((p) => existsSync(p));
	const revocationFiles =
		args.files?.filter((p) => p.startsWith("revocations/")) ??
		addedRevocationFiles(args.base).filter((p) => existsSync(p));
	const keysFiles = args.files?.filter((p) => p.startsWith("keys/")) ?? [];

	let validated = 0;
	for (const path of badgeFiles) {
		if (!path.endsWith(".json")) {
			console.error(`FAIL ${path}: not a .json file`);
			failures++;
			continue;
		}
		const problem = validateOne(path, args.base);
		if (problem) {
			console.error(`FAIL ${path}: ${problem}`);
			failures++;
		} else {
			console.log(`ok ${path}`);
		}
		validated++;
	}
	for (const path of revocationFiles) {
		if (maintainerKeyError) {
			console.error(`FAIL ${path}: ${maintainerKeyError}`);
			failures++;
			validated++;
			continue;
		}
		const problem = validateOneRevocation(path, args.base, maintainerKey);
		if (problem) {
			console.error(`FAIL ${path}: ${problem}`);
			failures++;
		} else {
			console.log(`ok ${path}`);
		}
		validated++;
	}
	if (args.files) {
		for (const path of keysFiles) {
			for (const problem of keysFileProblems(path, args.base)) {
				console.error(`FAIL ${path}: ${problem}`);
				failures++;
			}
			validated++;
		}
		for (const path of args.files) {
			if (
				!path.startsWith("badges/") &&
				!path.startsWith("revocations/") &&
				!path.startsWith("keys/")
			) {
				console.error(
					`FAIL ${path}: not under badges/, revocations/, or keys/ as a .json file`,
				);
				failures++;
			}
		}
	}

	if (failures > 0) {
		console.error(`${failures} file(s) failed validation`);
		return 1;
	}
	if (validated === 0) {
		console.log("no badge or revocation files to validate");
		return 0;
	}
	console.log(`all ${validated} file(s) valid`);
	return 0;
}

process.exit(main());
