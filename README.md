# F9 — Supply-Chain Integrity Gate

A deterministic, offline, standard-library-only **supply-chain gate** whose
**source of truth is SBOM data**: parse CycloneDX or SPDX JSON SBOMs, match
dependency versions against an **embedded advisory table** with a
range-aware version matcher, apply a **license/policy gate**, and emit a
**PASS / REVIEW / FAIL** verdict with traceable reasons. Deterministic and
fully offline — no package fetching, no network, no build execution.

## Overview

- **SBOM first**: the gate consumes either a CycloneDX (`bomFormat: CycloneDX`)
  or SPDX (`spdxVersion: SPDX-*`) JSON document and normalizes it into a
  component list (name, version, licenses, ref, hashes).
- **Advisory matching**: an embedded advisory table (in `fixtures/ADVISORIES.json`)
  is matched against every component version using a PEP-440-ish subset of
  constraints — `==`, `!=`, `<`, `<=`, `>`, `>=`, comma (`=` AND), and `||`
  (`= OR`) — returning a severity-ranked finding list.
- **License/policy gate**: `allowed` / `review` (copyleft) / `denied` license
  policy surface, plus `NOASSERTION`/`NONE`/unclassified → `REVIEW` with a
  sign-off reason.
- **Verdicts**: `PASS` (green), `REVIEW` (orange), `FAIL` (red) with a
  full `reasons` list for every advisory or license finding.
- **Fixtures**: three embedded synthetic SBOMs —
  `clean` (PASS), `vulnerable` (FAIL: 2 advisories + proprietary license),
  `spdx-legacy` (REVIEW: GPL + undeclared licenses). All names/hosts are
  references to fictional packages and `example.com`/`192.0.2.x` placeholders.
- **Reporting**: JSON or Markdown to `reports/` (gitignored).
- **Clean exit codes**: `0` success, `1` non-PASS verdict under `--strict`,
  `2` config/input error. `--demo` always exits `0`.

## CLI

```bash
python3 firmware/supply_chain_gate.py --help
python3 firmware/supply_chain_gate.py --demo                    # offline, exit 0
python3 firmware/supply_chain_gate.py --fixture vulnerable --report reports/v.json
python3 firmware/supply_chain_gate.py --sbom sbom.json --strict # exit 1 if not PASS
```

Config lives in `config.json` (`default_fixture`, `advisories_file`, `strict`,
`report`). `--advisories` overrides the advisory table path.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

This gate is **decision-support software for software composition analysis**
on codebases you own or are explicitly authorized to analyze. It parses static
SBOM/vulnerability/license data in memory; it performs **no access, no probing,
no package downloads, and no build execution**. But the SBOMs and advisories you
feed it — and any distribution of its findings — must be lawfully obtained.

### Authorization Requirements

Only analyze software you own or have explicit written authorization to assess.
Publishing SBOMs or vulnerability/license findings about third-party software
may be restricted by license, NDA, or export-control obligations.

### Legal Framework

Unauthorized access to or manipulation of computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. Penalties include imprisonment and
significant fines. Redistributing SBOM data may additionally implicate the
license terms of the scanned components (e.g., GPL/AGPL obligations).

### Acceptable Use

- Enforcing supply-chain review gates on repositories you own
- Authorized security audits and dependency/license hygiene on in-scope codebases
- Academic research on software composition analysis (fixtures are fictional)
- CI-prototype and education exercises

### Prohibited Use

- Scanning third-party repositories, feeds, or SBOMs without authorization
- Using findings to attack package ecosystems, build infrastructure, or maintainers
- Circumventing a CI gate by hiding or altering SBOM/advisory evidence
- Publishing non-public SBOM or vulnerability findings about others
- Any use that violates applicable law, licenses, NDA, or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool,
including false PASS/FAIL conclusions from heuristic constraint matching or
incomplete SBOM data.

### Responsible Disclosure

If the gate surfaces a likely compromised or vulnerable third-party dependency,
report it privately to the affected maintainers and package-ecosystem security
contacts, and allow reasonable time for remediation before any public disclosure.

## Live Lab Test Plan

1. **Help** — `python3 firmware/supply_chain_gate.py --help` prints the argparse
   help and exits `0`.
2. **Demo** — `python3 firmware/supply_chain_gate.py --demo` evaluates all three
   bundled fixtures, prints verdicts + reasons, writes `reports/demo.md`, exits
   `0`. Expected: clean `PASS`, vulnerable `FAIL`, spdx-legacy `REVIEW`.
3. **Advisory hit** — `--fixture vulnerable` reports advisory findings for
   `synthetlib 2.0.5` and `example-framework 1.1.0` (from `ADVISORIES.json`).
4. **License gate** — `--fixture vulnerable` returns `FAIL` for the
   `Proprietary` `proprietary-sdk`; `spdx-legacy` flags GPL + undeclared.
5. **Strict gate** — `--fixture vulnerable --strict` exits `1`; `--fixture
   clean --strict` exits `0`.
6. **External SBOM** — `--sbom sbom-clean.json` evaluates a supplied document.
7. **Determinism** — identical SBOM + advisory table produce identical output.
8. **Error paths** — a malformed SBOM or config returns exit `2`.

## Metrics

| Metric | Definition |
|--------|-----------|
| Source of truth | CycloneDX / SPDX JSON SBOM components |
| Advisory matcher | PIP-440-ish constraint subset: ==, !=, <, <=, >, >=, AND, OR |
| Severity ranking | CRITICAL > HIGH > MEDIUM > LOW |
| License policy | allowed / review (copyleft) / denied / undeclared |
| Verdict | PASS (green) / REVIEW (orange) / FAIL (red), with reasons |
| Report | JSON or Markdown to `reports/` (gitignored) |
| Exit codes | 0 success, 1 non-PASS under `--strict`, 2 config/input error |
| Offline | no network, no package fetch, no build execution |

Verified offline: `clean` → PASS (0 advisories), `vulnerable` → FAIL (2
advisory findings + 1 denied license), `spdx-legacy` → REVIEW (GPL + 2
undeclared). `--demo` exits `0`.

## License

MIT License