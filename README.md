# mcp-trust-index

A public, git-backed index of signed trust badges for MCP servers. Badges are emitted by [`trustscan`](https://github.com/fernandogarzaaa/mcp-trust) (the mcp-trust CLI) and live here at `badges/<server>/<version>.json`. The browsable site is at <https://fernandogarzaaa.github.io/mcp-trust-index/>.

## What a badge is

A badge is a JSON document binding a scan result to an exact server version and a signer:

```json
{
  "type": "mcp-trust-badge/v1",
  "server": "my-server",
  "version": "1.2.3",
  "riskScore": 82,
  "riskLevel": "low",
  "scores": { "schemaQuality": 96, "conformance": 100, "robustness": 88 },
  "findingCounts": { "critical": 0, "major": 1, "minor": 2, "info": 3 },
  "evalHash": "<sha256 of the canonical scored content>",
  "keyId": "<16 hex chars>",
  "publicKey": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "issuedAt": "2026-10-04T00:00:00.000Z",
  "signature": "<base64 Ed25519 signature>"
}
```

`scores` is `null` when the behavioral pass was skipped (the badge says so instead of pretending). The signature covers the whole badge except the signature field itself, and `evalHash` commits to the scored findings, so any tampering with scores or findings invalidates the badge.

## How verification works

Every pull request that adds files under `badges/`, `revocations/`, or `keys/` runs `scripts/validate.mjs` in CI.

**Badges.** For each added badge it checks:

1. **Placement**: the path is `badges/<server>/<version>.json` and the badge's `server`/`version` fields sanitize to exactly those path segments.
2. **Schema**: all required fields present with the right shapes (risk score 0-100, finding counts, 64-char eval hash, embedded Ed25519 public key, ISO date). The optional `artifact` field, when present, must be `{ type: "npm" | "git" | "local", spec: "<install spec>", integrity?: "<dist.integrity>" }`.
3. **Signature**: the Ed25519 signature verifies against the embedded public key, and the `keyId` matches that key. The cryptography is a direct port of mcp-trust's verifier, using only the Node.js standard library.
4. **No duplicates**: the path must not already exist on the target branch. The index is append-only per version: a new scan of a new version adds a new file; existing badges are never modified or removed via PR.

**Revocations.** A badge version can be revoked by the project maintainer by adding `revocations/<server>/<version>.json`:

```json
{
  "type": "mcp-trust-revocation/v1",
  "server": "my-server",
  "version": "1.2.3",
  "status": "revoked",
  "reason": "Signer key compromised; do not trust this badge.",
  "revokedAt": "2026-10-04T00:00:00.000Z",
  "keyId": "<project key id>",
  "publicKey": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
  "signature": "<base64 Ed25519 signature>"
}
```

CI checks placement, schema, that a badge for that server@version is actually indexed, that no revocation already exists for it, and that the signature verifies against the project key published at `keys/project.json` on the target branch. The project key is immutable: after its initial commit, PRs touching `keys/` fail validation.

**Badge status.** The site and the machine-readable manifest derive a status per badge: `revoked` (a revocation exists) wins; otherwise every version except the newest indexed version of a server is `superseded`; the newest is `active`. `trustscan verify` and `trustscan pin` read this status: revoked badges are rejected, superseded ones warn.

To revoke:

```bash
trustscan revoke --server my-server --version 1.2.3 \
  --reason "Signer key compromised" \
  --key ~/.config/mcp-trust/project/key.priv.json \
  --out revocation.json
# then open a PR adding revocations/my-server/1.2.3.json
```

A PR that modifies or deletes an existing badge or revocation file fails validation.

## How to publish a badge

```bash
trustscan scan ./my-server --sign --badge-out my-server.trust.json
trustscan publish --badge my-server.trust.json
# or in one step:
trustscan scan ./my-server --sign --publish
```

`trustscan publish` verifies the badge locally first, then opens a pull request against this repo. CI validates it; a maintainer merges on green. No account or signup needed beyond the GitHub CLI.

You can also open a PR by hand: add `badges/<server>/<version>.json` with a valid signed badge and CI will check it the same way.

## How the site stays current

On every push to `main` that touches `badges/` or `revocations/`, CI regenerates `docs/index.json` (the machine-readable manifest, including each badge's `status` and install `artifact`) and the static badge table in `docs/index.html`, then serves it via GitHub Pages. The page's search, sort, filter, and detail views run entirely client-side.

## Installing a verified version

```bash
trustscan pin my-server@1.2.3      # print the exact verified install command
trustscan install my-server@1.2.3  # install it (npm); --dry-run to preview
trustscan pin my-server            # latest active (non-revoked) version
```

`pin` resolves the badge from this index, refuses revoked versions, and warns on superseded ones. `install` shows the badge summary first, then runs the install.

## Honest limitations

- A badge attests to the exact version scanned, at a point in time. A new release needs a new scan.
- Static checks are heuristics with false positives; findings are review prompts, never verdicts.
- Trust in the **signer** (the key id) is out of band, like a PGP key id. This index proves a badge is intact and well-formed, not that its signer is honest. Check who holds a key before you trust their badges. Badges signed with the project key (`ac22e8d7e54463b7`) were produced by the mcp-trust project itself.
- Revocation covers bad badges, not bad servers: revoking a badge does not uninstall the server. Always verify before you install.
- Verify any badge yourself: `trustscan verify badge.json`.

## License

MIT. Badges are submitted by their signers; the index makes no claim about the quality or safety of indexed servers beyond what each badge states.
