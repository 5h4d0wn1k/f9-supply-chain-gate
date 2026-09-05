# F9 — Supply-Chain Integrity Gate

A pure-Python supply-chain gate that generates CycloneDX-ish SBOMs, diffs dependency trees between commits, and flags repository anomalies with a taint/risk heuristic for CI on a monorepo.

## Overview

- Generates a CycloneDX-ish SBOM (JSON) for a scanned tree, parsing package files (`requirements.txt`, …) and source imports
- Diffs dependency trees between two commits (embedded before/after trees) and reports added, removed, and version-changed dependencies
- Flags anomalies — new/unexpected maintainer scripts, `configure.ac`-style build changes, unusual binaries — scoring each with a taint/risk heuristic
- Emits a green/red build-gate badge derived from anomaly severity
- Runs entirely offline on an embedded sample repository — zero third-party dependencies

## Features

- **`generate_sbom`** — CycloneDX v1.4-shaped JSON with per-component SHA-256 hashes, package-file markers, and parsed dependency lists
- **`diff_dependency_trees`** — `added`/`removed`/`changed` maps from two SBOMs
- **`detect_anomalies`** — new-maintainer-script (curl-to-shell, urlopen, base64, chmod patterns boost the score), configure.ac changes, unexpected binaries, and dependency version bumps, each with a 0–10 risk score
- **`compute_gate_badge`** — green `PASS` / orange `REVIEW` / red `FAIL` from the anomaly set
- **Offline self-test** — the fictional `app/` + `scripts/` + `vendor/` sample tree (12 → 14 components) exercises every module and exits `0`

## Installation

No external dependencies required — uses Python standard library only.

```bash
git clone <repo> && cd f9-supply-chain-gate
python3 firmware/supply_chain_gate.py
```

## Usage

```python
from firmware.supply_chain_gate import (
    generate_sbom, diff_dependency_trees,
    detect_anomalies, compute_gate_badge,
)

# In CI you would scan two real trees instead of the embedded samples.
bom_before = generate_sbom(before_contents, before_spec)
bom_after  = generate_sbom(after_contents, after_spec)

diff = diff_dependency_trees(bom_before, bom_after)
anomalies = detect_anomalies(before_spec, after_spec, after_contents)
color, label = compute_gate_badge(anomalies)
print(f"gate={label} ({color})")
```

The offline demo emits the full SBOM JSON, the dependency diff, the scored anomaly report, and the final badge:

```python
python3 firmware/supply_chain_gate.py
```

## Example Output

```
[2] Generate SBOM (after commit)
    Components : 14

[3] Dependency Diff (before -> after)
    Changed : {'cryptography': ('41.0.7', '42.0.0')}

[4] Anomaly Detection + Risk Scoring
    [HIGH  ] new-maintainer-script      score=10.0  scripts/install_hook.sh
              > matches pattern 'curl.*\|\s*sh'; matches pattern 'urlopen'
    [HIGH  ] new-binary                 score=7.5   vendor/libssh.so.9
              > unexpected binary (68 bytes, sha256=8df0400d7686)
    [LOW   ] dependency-version-bump    score=4.0   app/requirements.txt
              > cryptography: 41.0.7 -> 42.0.0

[5] Build Gate Badge
    Gate status: FAIL (color=red)
```

## IMPORTANT: Read before use.

This tool is a **prototype gate**, not a security guarantee. Its heuristics are intentionally aggressive so that unexpected supply-chain changes surface for *human* review; benign maintenance changes (a legitimate script bump, a vendored toolchain) can be flagged and require due-diligence sign-off. The embedded trees are fictional and scanned only in memory; nothing here fetches packages or executes build steps.

### Authorization Requirements

Only run this gate against repositories you own or are contractually authorized to analyze and modify. Publishing SBOMs or anomaly findings from third-party code may be restricted by license or NDA.

### Legal Framework

Unauthorized access to or manipulation of computer systems is governed by the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive on Attacks Against Information Systems** (2013/40/EU), and equivalent legislation in other jurisdictions. Penalties include imprisonment and significant fines. Restrictive software licenses (e.g., GPL/AGPL compliance obligations) may separately constrain how you may redistribute SBOM data.

### Acceptable Use

- Enforcing supply-chain review gates on repositories you own
- Authorized security audits and dependency hygiene on in-scope codebases
- Academic research on software composition analysis
- Educational labs and CI-prototype exercises

### Prohibited Use

- Scanning third-party repositories without authorization
- Using findings to attack package ecosystems, build infrastructure, or maintainers
- Circumventing your own CI gate by hiding or altering anomaly evidence
- Any use that violates applicable law, licenses, or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool, including false conclusions drawn from its heuristic scoring.

### Responsible Disclosure

If your gate surfaces a likely compromise (e.g., a maintainer script pulling remote code) in a project you do not own, report it privately to the maintainers and the package ecosystem's security contact, and allow reasonable time for remediation before public disclosure.

## License

MIT License