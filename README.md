> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F9 — Supply-Chain Integrity Gate (SBOM Gate)

Deterministic, offline, standard-library-only supply-chain dependency gate: parse CycloneDX or SPDX SBOMs, match versions against an embedded advisory table with a range-aware matcher, apply a license/policy gate, and emit a traceable PASS / REVIEW / FAIL verdict.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f9-supply-chain-gate.svg)](https://github.com/5h4d0wn1k/f9-supply-chain-gate)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f9-supply-chain-gate.svg)](https://github.com/5h4d0wn1k/f9-supply-chain-gate)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/f9-supply-chain-gate.svg)](https://github.com/5h4d0wn1k/f9-supply-chain-gate)

## Why

Software supply-chain risk starts with knowing what you actually depend on — and acting on it before a vulnerable package ships. F9 turns SBOM data into a decision: it parses CycloneDX or SPDX JSON, matches every component version against an advisory table using a PEP-440-style constraint matcher, and applies a license policy gate (`allowed` / `review` / `denied`). The result is a `PASS`/`REVIEW`/`FAIL` verdict with the exact reasons behind it — deterministic, offline, and safe to run as a CI gate: no package fetching, no network, no build execution.

## Features

- **SBOM-first** — consumes CycloneDX (`bomFormat`) or SPDX (`spdxVersion`) JSON and normalizes components (name, version, licenses, ref, hashes)
- **Range-aware advisory matching** — `==`, `!=`, `<`, `<=`, `>`, `>=`, comma-AND and `||`-OR constraints, severity-ranked findings
- **License/policy gate** — `allowed` / `review` (copyleft) / `denied` plus `NOASSERTION`/`NONE` → `REVIEW`
- **Traceable verdicts** — PASS (0), REVIEW, FAIL (1) with a full `reasons` list
- **Bundled fixtures** — three synthetic SBOMs: `clean` (PASS), `vulnerable` (FAIL), `spdx-legacy` (REVIEW)
- **JSON/Markdown reporting** — to `reports/` (gitignored); clean exit codes (0/1/2)

## Quickstart

```bash
git clone https://github.com/5h4d0wn1k/f9-supply-chain-gate.git && cd f9-supply-chain-gate

# Offline demo: evaluates all three fixtures, exit 0
python3 firmware/supply_chain_gate.py --demo

# Evaluate a specific fixture
python3 firmware/supply_chain_gate.py --fixture vulnerable --report reports/v.json

# Gate an external SBOM; exit 1 if verdict is not PASS
python3 firmware/supply_chain_gate.py --sbom sbom.json --strict

# Unit tests
python3 -m unittest discover -s tests
```

Config lives in `config.json` (`default_fixture`, `advisories_file`, `strict`, `report`); `--advisories` overrides the advisory table path.

## Project structure

- `firmware/supply_chain_gate.py` — gate engine and CLI
- `fixtures/` — `ADVISORIES.json` plus the three synthetic SBOMs
- `config.json` — gate defaults; `tests/` — unit test suite

## Documentation

- [ETHICS.md](ETHICS.md) — educational purpose and authorized use only
- [SCOPE.md](SCOPE.md) — authorized-testing scope checklist
- [SECURITY.md](SECURITY.md) — vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) — safe contribution guidelines

## Contributing

New advisory matchers, license policies, SBOM formats and fixtures are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md); analyze only codebases you own or hold authorization for.

## License

MIT — see [LICENSE](LICENSE). Provided **AS IS**, without warranty, for education and authorized software-composition-analysis use only.