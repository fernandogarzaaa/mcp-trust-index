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
const DOCS_DIR = join(ROOT, "docs");
const INDEX_JSON = join(DOCS_DIR, "index.json");
const INDEX_HTML = join(DOCS_DIR, "index.html");

const START_MARKER = "<!-- BADGES:START -->";
const END_MARKER = "<!-- BADGES:END -->";

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
	const entries = [];
	let servers;
	try {
		servers = readdirSync(BADGES_DIR);
	} catch {
		return entries;
	}
	for (const server of servers) {
		const serverDir = join(BADGES_DIR, server);
		if (!statSync(serverDir).isDirectory()) continue;
		for (const file of readdirSync(serverDir)) {
			if (!file.endsWith(".json")) continue;
			const path = join(serverDir, file);
			const badge = JSON.parse(readFileSync(path, "utf8"));
			entries.push({
				server: badge.server,
				version: badge.version,
				riskScore: badge.riskScore,
				riskLevel: badge.riskLevel,
				scores: badge.scores,
				findingCounts: badge.findingCounts,
				keyId: badge.keyId,
				issuedAt: badge.issuedAt,
				path: `badges/${server}/${file}`,
			});
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

function renderRows(entries) {
	if (entries.length === 0) {
		return '    <tr><td colspan="9" class="empty">No badges indexed yet. Publish the first one with <code>trustscan publish</code>.</td></tr>';
	}
	return entries
		.map((e) => {
			const fc = e.findingCounts;
			const findings = `${fc.critical}/${fc.major}/${fc.minor}/${fc.info}`;
			const issued = e.issuedAt.slice(0, 10);
			return (
				`    <tr data-path="${esc(e.path)}" data-server="${esc(e.server)}" data-version="${esc(e.version)}" data-level="${esc(e.riskLevel)}" data-score="${e.riskScore}">\n` +
				`      <td class="server">${esc(e.server)}</td>\n` +
				`      <td><code>${esc(e.version)}</code></td>\n` +
				`      <td><span class="${levelClass(e.riskLevel)}">${e.riskScore}/100 ${esc(e.riskLevel)}</span></td>\n` +
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
