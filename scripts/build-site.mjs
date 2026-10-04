/**
 * build-site.mjs: regenerate the trust index manifest and the static badge
 * table on the GitHub Pages site.
 *
 * Reads every badges/<server>/<version>.json, writes:
 *   docs/index.json   - machine-readable manifest (also fetched by the site JS)
 *   docs/index.html   - the <tbody> between <!-- BADGES:START --> and
 *                       <!-- BADGES:END --> is replaced with one row per badge
 *
 * Run by CI on every push to main that touches badges/. The static rows keep
 * the page meaningful without JavaScript; the inline site script re-renders
 * from index.json for search, sort, and detail views.
 */

import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const BADGES_DIR = join(ROOT, "badges");
const REVOCATIONS_DIR = join(ROOT, "revocations");
const DOCS_DIR = join(ROOT, "docs");
const INDEX_JSON = join(DOCS_DIR, "index.json");
const INDEX_HTML = join(DOCS_DIR, "index.html");

const START_MARKER = "<!-- BADGES:START -->";
const END_MARKER = "<!-- BADGES:END -->";

/** Numeric-aware version compare: 1.10.0 > 1.9.0. A pre-release
 * (extra non-numeric parts) sorts below the release: 1.0.0-alpha < 1.0.0.
 * Missing numeric parts count as 0, so 1.2 == 1.2.0. */
function compareVersions(a, b) {
	const pa = String(a).split(/[.-]/);
	const pb = String(b).split(/[.-]/);
	const n = Math.max(pa.length, pb.length);
	for (let i = 0; i < n; i++) {
		const xa = i < pa.length ? pa[i] : null;
		const xb = i < pb.length ? pb[i] : null;
		if (xa === null && xb === null) continue;
		if (xa === null) return /^\d+$/.test(xb) ? 0 : 1;
		if (xb === null) return /^\d+$/.test(xa) ? 0 : -1;
		const na = /^\d+$/.test(xa) ? Number(xa) : null;
		const nb = /^\d+$/.test(xb) ? Number(xb) : null;
		if (na !== null && nb !== null) {
			if (na !== nb) return na - nb;
		} else if (xa !== xb) {
			return xa < xb ? -1 : 1;
		}
	}
	return 0;
}

/** revocations[serverSegment][versionSegment] = { reason, revokedAt, keyId }. */
function collectRevocations() {
	const out = {};
	let servers;
	try {
		servers = readdirSync(REVOCATIONS_DIR);
	} catch {
		return out;
	}
	for (const server of servers) {
		const serverDir = join(REVOCATIONS_DIR, server);
		let st;
		try {
			st = statSync(serverDir);
		} catch {
			continue;
		}
		if (!st.isDirectory()) continue;
		for (const file of readdirSync(serverDir)) {
			if (!file.endsWith(".json")) continue;
			try {
				const rev = JSON.parse(readFileSync(join(serverDir, file), "utf8"));
				if (rev && rev.status === "revoked") {
					(out[server] ??= {})[file.replace(/\.json$/, "")] = {
						reason: rev.reason,
						revokedAt: rev.revokedAt,
						keyId: rev.keyId,
					};
				}
			} catch {
				// A malformed revocation fails CI validation; the site build skips it.
			}
		}
	}
	return out;
}

function esc(s) {
	return String(s)
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

function levelClass(level) {
	return `pill pill-${level}`;
}

function collectBadges() {
	const revocations = collectRevocations();
	const byServer = new Map();
	let servers;
	try {
		servers = readdirSync(BADGES_DIR);
	} catch {
		return [];
	}
	for (const serverSeg of servers) {
		const serverDir = join(BADGES_DIR, serverSeg);
		if (!statSync(serverDir).isDirectory()) continue;
		for (const file of readdirSync(serverDir)) {
			if (!file.endsWith(".json")) continue;
			const path = join(serverDir, file);
			const badge = JSON.parse(readFileSync(path, "utf8"));
			const versionSeg = file.replace(/\.json$/, "");
			if (!byServer.has(serverSeg)) byServer.set(serverSeg, []);
			byServer.get(serverSeg).push({
				server: badge.server,
				version: badge.version,
				riskScore: badge.riskScore,
				riskLevel: badge.riskLevel,
				scores: badge.scores,
				findingCounts: badge.findingCounts,
				keyId: badge.keyId,
				issuedAt: badge.issuedAt,
				artifact: badge.artifact ?? null,
				path: `badges/${serverSeg}/${file}`,
				_versionSeg: versionSeg,
			});
		}
	}
	const entries = [];
	for (const [serverSeg, list] of byServer) {
		// Status: revoked wins; otherwise every version except the newest
		// for its server is superseded.
		const newest = list
			.map((e) => e.version)
			.sort(compareVersions)
			.pop();
		for (const e of list) {
			const rev = revocations[serverSeg]?.[e._versionSeg];
			if (rev) {
				e.status = "revoked";
				e.revocationReason = rev.reason;
			} else if (e.version !== newest) {
				e.status = "superseded";
			} else {
				e.status = "active";
			}
			delete e._versionSeg;
			entries.push(e);
		}
	}
	entries.sort((a, b) =>
		a.server === b.server
			? b.version.localeCompare(a.version, undefined, { numeric: true })
			: a.server.localeCompare(b.server),
	);
	return entries;
}

function scoreCell(scores, key) {
	if (!scores || typeof scores[key] !== "number") return "<td>—</td>";
	return `<td>${scores[key]}</td>`;
}

function statusCell(e) {
	const label = e.status ?? "active";
	const cls = `status status-${label}`;
	const title =
		label === "revoked" && e.revocationReason
			? ` title="${esc(e.revocationReason)}"`
			: "";
	return `<td><span class="${cls}"${title}>${esc(label)}</span></td>`;
}

function renderRows(entries) {
	if (entries.length === 0) {
		return '    <tr><td colspan="10" class="empty">No badges indexed yet. Publish the first one with <code>sigil publish</code>.</td></tr>';
	}
	return entries
		.map((e) => {
			const fc = e.findingCounts;
			const findings = `${fc.critical}/${fc.major}/${fc.minor}/${fc.info}`;
			const issued = e.issuedAt.slice(0, 10);
			return (
				`    <tr data-path="${esc(e.path)}" data-server="${esc(e.server)}" data-version="${esc(e.version)}" data-level="${esc(e.riskLevel)}" data-score="${e.riskScore}" data-status="${esc(e.status ?? "active")}">\n` +
				`      <td class="server">${esc(e.server)}</td>\n` +
				`      <td><code>${esc(e.version)}</code></td>\n` +
				`      <td><span class="${levelClass(e.riskLevel)}">${e.riskScore}/100 ${esc(e.riskLevel)}</span></td>\n` +
				`      ${statusCell(e)}\n` +
				`      ${scoreCell(e.scores, "schemaQuality")}\n` +
				`      ${scoreCell(e.scores, "conformance")}\n` +
				`      ${scoreCell(e.scores, "robustness")}\n` +
				`      <td title="critical / major / minor / info">${esc(findings)}</td>\n` +
				`      <td><code title="${esc(e.keyId)}">${esc(e.keyId.slice(0, 8))}</code></td>\n` +
				`      <td>${esc(issued)}</td>\n` +
				"    </tr>"
			);
		})
		.join("\n");
}

function main() {
	const entries = collectBadges();
	writeFileSync(
		INDEX_JSON,
		`${JSON.stringify({ generatedAt: new Date().toISOString(), count: entries.length, badges: entries }, null, 2)}\n`,
	);

	let html = readFileSync(INDEX_HTML, "utf8");
	const start = html.indexOf(START_MARKER);
	const end = html.indexOf(END_MARKER);
	if (start === -1 || end === -1 || end < start) {
		throw new Error("index.html is missing the BADGES markers");
	}
	const before = html.slice(0, start + START_MARKER.length);
	const after = html.slice(end);
	const countLine = `<!-- BADGE-COUNT:${entries.length} -->`;
	html = `${before}\n${countLine}\n${renderRows(entries)}\n${after}`;
	writeFileSync(INDEX_HTML, html);
	console.log(`index rebuilt: ${entries.length} badge(s)`);
}

main();
