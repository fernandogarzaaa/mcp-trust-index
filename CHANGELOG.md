# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added / Changed
- Dependabot config for GitHub Actions (weekly)
- SECURITY.md with private reporting contact
- `npm test`: zero-dependency checks of every badge and revocation signature, tamper rejection, and docs freshness (`test/index.test.mjs`); `package.json` with `test` / `build` / `validate` scripts
- README: how to install the `sigil` CLI (`npm i -g sigil-mcp`), local checking commands, and the corrected "site stays current" flow (PR authors rebuild `docs/`)
