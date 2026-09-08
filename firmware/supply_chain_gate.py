#!/usr/bin/env python3
"""
F9 — Supply-Chain Integrity Gate.

A deterministic, offline, standard-library-only gate whose SOURCE OF TRUTH is
SBOM data:

  1.  Parse CycloneDX or SPDX JSON SBOM imports into a normalized component list.
  2.  Match component versions against an embedded advisory table using
      range-aware version comparison (==, !=, <, <=, >, >=, comma = AND,
      `||` = OR).
  3.  Apply a license/policy gate per component (allowed / review / denied).
  4.  Emit PASS / REVIEW / FAIL with traceable reasons and a JSON/Markdown
      report under reports/ (gitignored).

Everything is synthetic placeholders: fictional package names, *.example.com
hosts, 192.0.2.x addresses. Intended ONLY for authorized use — see the README
"IMPORTANT: Read before use." section.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# --------------------------------------------------------------------------- #
# Advisory table + policy (embedded; single source of truth in fixtures/).
# --------------------------------------------------------------------------- #
def _default_advisories():
    try:
        return json.loads((FIXTURES_DIR / "ADVISORIES.json").read_text(encoding="utf-8"))
    except Exception:
        return []


ADVISORIES = _default_advisories()

LICENSE_POLICY = {
    "allowed": ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause",
                "ISC", "Unlicense", "PSF-2.0", "0BSD", "MPL-2.0"],
    "review": ["GPL-2.0-only", "GPL-3.0-only", "LGPL-2.1-only",
               "AGPL-3.0-only", "EPL-2.0", "CDDL-1.0"],
    "denied": ["Proprietary", "BUSL-1.1", "Commons-Clause", "CC-BY-NC-4.0"],
}

FIXTURES = {
    "clean": FIXTURES_DIR / "sbom-clean.json",
    "vulnerable": FIXTURES_DIR / "sbom-vulnerable.json",
    "spdx-legacy": FIXTURES_DIR / "sbom-spdx-legacy.json",
}


# --------------------------------------------------------------------------- #
# Version comparison (stdlib-only; a tiny PEP-440-ish subset).
# --------------------------------------------------------------------------- #
def _split_version(version: str) -> tuple:
    core = version.strip().split("+", 1)[0].split("-", 1)[0]
    parts = []
    for token in core.split("."):
        token = token.strip()
        parts.append(int(token) if token.isdigit() else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _cmp_versions(v1: str, v2: str) -> int:
    a = _split_version(v1)
    b = _split_version(v2)
    return (a > b) - (a < b)


def _constraint_match(version: str, op: str, target: str) -> bool:
    c = _cmp_versions(version, target)
    if op == "==":
        return c == 0
    if op == "!=":
        return c != 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    return False


def match_constraints(version: str, spec: str) -> bool:
    """True when `version` satisfies an advisory `affected` spec.

    Grammar subset: empty/`*` matches everything; `||` separates OR groups;
    a comma inside a group means AND; each item is `op version` with op in
    ==, !=, <, <=, >, >=.
    """
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return True
    for group in spec.split("||"):
        ok = True
        for item in group.split(","):
            item = item.strip()
            if not item or item == "*":
                continue
            m = re.match(r"^(<=|>=|==|!=|<|>)\s*(\S+)$", item)
            if not m:
                continue
            if not _constraint_match(version, m.group(1), m.group(2)):
                ok = False
                break
        if ok:
            return True
    return False


# --------------------------------------------------------------------------- #
# SBOM parsing (CycloneDX + SPDX JSON).
# --------------------------------------------------------------------------- #
def parse_sbom(data: dict) -> dict:
    """Normalize a CycloneDX or SPDX JSON document into a component list."""
    if data.get("bomFormat") == "CycloneDX":
        components = []
        for c in data.get("components", []) or []:
            licenses = []
            for lic in c.get("licenses", []) or []:
                if isinstance(lic, str):
                    licenses.append(lic)
                elif isinstance(lic, dict):
                    inner = lic.get("license") or lic.get("expression")
                    if isinstance(inner, dict):
                        lid = inner.get("id") or inner.get("name")
                        if lid:
                            licenses.append(str(lid).strip())
                    elif isinstance(inner, str) and inner.strip():
                        licenses.append(inner.strip())
            components.append({
                "name": str(c.get("name", "") or ""),
                "version": str(c.get("version", "") or ""),
                "type": str(c.get("type", "library")),
                "ref": c.get("bom-ref") or c.get("purl") or "",
                "licenses": licenses,
                "hashes": [str(h.get("content", ""))
                           for h in (c.get("hashes") or [])],
            })
        return {"bom_format": "CycloneDX", "components": components}

    if str(data.get("spdxVersion", "")).startswith("SPDX-"):
        components = []
        for p in data.get("packages", []) or []:
            lic = p.get("licenseConcluded") or p.get("licenseDeclared") or ""
            components.append({
                "name": str(p.get("name", "") or ""),
                "version": str(p.get("versionInfo", "") or ""),
                "type": "package",
                "ref": p.get("SPDXID", "") or p.get("name", "") or "",
                "licenses": [lic.strip()] if lic.strip() else [],
                "hashes": [],
            })
        return {"bom_format": "SPDX", "components": components}

    raise ValueError("unrecognized SBOM format (expected CycloneDX or SPDX JSON)")


def load_sbom(path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_sbom(data)


# --------------------------------------------------------------------------- #
# Advisory matching.
# --------------------------------------------------------------------------- #
def _component_versions(sbom: dict) -> dict:
    out = {}
    for comp in sbom["components"]:
        out.setdefault(comp["name"], []).append(comp["version"])
    return out


def check_advisories(sbom: dict, advisories: list = None) -> list:
    advisories = ADVISORIES if advisories is None else advisories
    versions = _component_versions(sbom)
    findings = []
    for adv in advisories:
        package = adv.get("package")
        for version in versions.get(package, []) or [""]:
            if version and match_constraints(version, adv.get("affected", "*")):
                findings.append({
                    "advisory": adv.get("id", "ADV-?"),
                    "package": package,
                    "version": version,
                    "affected": adv.get("affected", "*"),
                    "severity": adv.get("severity", "MEDIUM"),
                    "summary": adv.get("advisory", ""),
                })
    findings.sort(key=lambda f: (
        SEVERITY_ORDER.index(f["severity"])
        if f["severity"] in SEVERITY_ORDER else 99))
    return findings


# --------------------------------------------------------------------------- #
# License / policy gate.
# --------------------------------------------------------------------------- #
def classify_license(lic: str, policy: dict = None) -> tuple:
    policy = LICENSE_POLICY if policy is None else policy
    lic = (lic or "").strip()
    if not lic:
        return ("REVIEW", "no license metadata declared")
    lu = lic.upper()
    if lu in ("NOASSERTION", "NONE"):
        return ("REVIEW", "no license declared (%s) - needs human sign-off" % lic)
    if lu in {x.upper() for x in policy["denied"]}:
        return ("FAIL", "license denied by policy: %s" % lic)
    if lu in {x.upper() for x in policy["review"]}:
        return ("REVIEW", "reciprocal/copyleft license needs sign-off: %s" % lic)
    if lu in {x.upper() for x in policy["allowed"]}:
        return ("PASS", "allowed license: %s" % lic)
    return ("REVIEW", "unclassified license: %s" % lic)


def evaluate_license_policy(sbom: dict, policy: dict = None) -> list:
    entries = []
    for comp in sbom["components"]:
        name = comp["name"]
        lic_list = comp["licenses"]
        if not lic_list:
            entries.append({
                "package": name, "version": comp["version"], "licenses": [],
                "verdict": "REVIEW",
                "reason": "no license metadata declared - needs human sign-off",
            })
            continue
        decisions = [classify_license(l, policy) for l in lic_list]
        if any(v == "FAIL" for v, _ in decisions):
            overall = "FAIL"
        elif any(v == "REVIEW" for v, _ in decisions):
            overall = "REVIEW"
        else:
            overall = "PASS"
        entries.append({
            "package": name, "version": comp["version"], "licenses": lic_list,
            "verdict": overall,
            "reason": "; ".join(r for _, r in decisions),
        })
    return entries


# --------------------------------------------------------------------------- #
# Gate verdict.
# --------------------------------------------------------------------------- #
def compute_gate(sbom: dict, advisories: list = None, policy: dict = None) -> dict:
    findings = check_advisories(sbom, advisories)
    licenses = evaluate_license_policy(sbom, policy)

    failures, reviews = [], []
    for f in findings:
        rec = {"kind": "advisory", "id": f["advisory"], "package": f["package"],
               "version": f["version"], "severity": f["severity"],
               "detail": f["summary"] or f["affected"]}
        (failures if f["severity"] in ("CRITICAL", "HIGH") else reviews).append(rec)
    for lr in licenses:
        rec = {"kind": "license", "package": lr["package"],
               "version": lr["version"], "severity": lr["verdict"],
               "detail": lr["reason"]}
        if lr["verdict"] == "FAIL":
            failures.append(rec)
        elif lr["verdict"] == "REVIEW":
            reviews.append(rec)

    if failures:
        verdict, color = "FAIL", "red"
    elif reviews:
        verdict, color = "REVIEW", "orange"
    else:
        verdict, color = "PASS", "green"

    reasons = ["FAIL  %-8s %s %s: %s" %
               (r["severity"], r["package"], r.get("version", ""), r["detail"])
               for r in failures]
    reasons += ["REVIEW %-8s %s %s: %s" %
                (r["severity"], r["package"], r.get("version", ""), r["detail"])
                for r in reviews]

    return {
        "verdict": verdict,
        "color": color,
        "components": len(sbom["components"]),
        "findings": findings,
        "licenses": licenses,
        "reasons": reasons,
        "summary": {
            "failures": len(failures),
            "reviews": len(reviews),
            "advisory_findings": len(findings),
            "license_fail": sum(1 for lr in licenses if lr["verdict"] == "FAIL"),
            "license_review": sum(1 for lr in licenses if lr["verdict"] == "REVIEW"),
        },
    }


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _append_result(md: list, result: dict) -> None:
    md.append("## %s (%s)" % (result["source"], result["bom_format"]))
    md.append("")
    md.append("- Components : %d" % result["components"])
    md.append("- Gate       : **%s** (%s)" % (result["verdict"], result["color"]))
    md.append("")
    if result["findings"]:
        md.append("| Advisory | Package | Version | Severity |")
        md.append("|---|---|---|---|")
        for f in result["findings"]:
            md.append("| %s | %s | %s | %s |"
                      % (f["advisory"], f["package"], f["version"], f["severity"]))
        md.append("")
    if result["licenses"]:
        md.append("| Package | Version | Licenses | Verdict |")
        md.append("|---|---|---|---|")
        for lr in result["licenses"]:
            md.append("| %s | %s | %s | %s |"
                      % (lr["package"], lr["version"], ", ".join(lr["licenses"]),
                         lr["verdict"]))
        md.append("")
    if result["reasons"]:
        md.append("**Reasons**")
        md.append("")
        for r in result["reasons"]:
            md.append("- %s" % r)
        md.append("")


def render_markdown(result: dict) -> str:
    md = ["# F9 — Supply-Chain Integrity Gate report", "",
          "Generated: %s" % result.get("generated", _now()), ""]
    if "fixtures" in result:
        md.append("## Demo mode — all bundled fixtures")
        md.append("")
        for fx in result["fixtures"]:
            _append_result(md, fx)
        md.append("## Summary")
        md.append("")
        for row in result["summary"]:
            md.append("- %-16s %s" % (row, result["summary"][row]))
        md.append("")
    else:
        _append_result(md, result)
    return "\n".join(md)


def render_json(result: dict) -> str:
    return json.dumps(result, indent=2)


def _write_report(path, result: dict) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.suffix == ".json":
        out.write_text(render_json(result), encoding="utf-8")
    else:
        out.write_text(render_markdown(result), encoding="utf-8")
    return out


def _format_text(result: dict) -> str:
    lines = ["=" * 62,
             "  F9 - SUPPLY-CHAIN INTEGRITY GATE",
             "=" * 62,
             "  Source      : %s" % result["source"],
             "  BOM format  : %s" % result["bom_format"],
             "  Components  : %d" % result["components"],
             "  Gate        : %s (%s)" % (result["verdict"], result["color"]),
             ""]
    for r in result["reasons"]:
        lines.append("    - %s" % r)
    lines.append("")
    lines.append("  See %s" % result.get("report", "reports/report.md"))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Demo (offline; bundled fixtures only, always exits 0).
# --------------------------------------------------------------------------- #
def run_demo(report_path="reports/report.md", advisories=None, verbose=False) -> int:
    advisories = ADVISORIES if advisories is None else advisories
    print("=" * 62)
    print("  F9 - Supply-Chain Integrity Gate - OFFLINE DEMO")
    print("  Source of truth: CycloneDX/SPDX SBOM fixtures vs embedded advisory")
    print("  table + license policy. All data is synthetic.")
    print("=" * 62)

    fixtures = []
    for name, path in FIXTURES.items():
        sbom = load_sbom(path)
        res = compute_gate(sbom, advisories)
        res["source"] = "fixture:%s" % name
        res["bom_format"] = sbom["bom_format"]
        res["generated"] = _now()
        fixtures.append(res)
        print("\n[%s]  %s (%s)  ->  %-6s (%s)   components=%d"
              % (name.upper(), path.name, res["bom_format"], res["verdict"],
                 res["color"], res["components"]))
        for r in res["reasons"]:
            print("      %s" % r)

    summary = {"fixtures": len(fixtures),
               "pass": sum(1 for f in fixtures if f["verdict"] == "PASS"),
               "review": sum(1 for f in fixtures if f["verdict"] == "REVIEW"),
               "fail": sum(1 for f in fixtures if f["verdict"] == "FAIL")}
    combined = {"tool": "f9-supply-chain-gate", "mode": "demo",
                "generated": _now(), "fixtures": fixtures, "summary": summary}

    out = _write_report(report_path, combined)
    print("\n" + "=" * 62)
    print("  Demo complete. Report: %s" % out)
    print("  PASS=%d  REVIEW=%d  FAIL=%d  (exit 0)"
          % (summary["pass"], summary["review"], summary["fail"]))
    print("=" * 62)
    return 0


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="f9-supply-chain-gate",
        description="Supply-chain integrity gate: parse CycloneDX/SPDX SBOMs, "
                    "match dependencies against an embedded advisory table, and "
                    "apply a license/policy gate -> PASS / REVIEW / FAIL.",
    )
    ap.add_argument("--sbom", default=None,
                    help="path to a CycloneDX or SPDX JSON SBOM (overrides fixture)")
    ap.add_argument("--fixture", choices=sorted(FIXTURES), default=None,
                    help="embedded fixture to evaluate (clean / vulnerable / spdx-legacy)")
    ap.add_argument("--advisories", default=None,
                    help="override advisory table (JSON list of advisories)")
    ap.add_argument("--demo", action="store_true",
                    help="run the offline demo across all bundled fixtures")
    ap.add_argument("--config", default="config.json",
                    help="config JSON (default: config.json)")
    ap.add_argument("--report", default="reports/report.md",
                    help="output report path; .json selects JSON format")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when the gate verdict is not PASS")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("[config] parse error in %s" % cfg_path, file=sys.stderr)
            return 2

    advisories = ADVISORIES
    adv_path = args.advisories or cfg.get("advisories_file")
    if adv_path:
        try:
            advisories = json.loads(Path(adv_path).read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            print("[advisories] cannot load %s: %s" % (adv_path, exc),
                  file=sys.stderr)
            return 2

    demo = args.demo or (args.sbom is None and args.fixture is None)
    if demo:
        return run_demo(args.report, advisories, args.verbose)

    if args.sbom:
        sbom_path = Path(args.sbom)
        source = args.sbom
    else:
        name = args.fixture or cfg.get("default_fixture") or "clean"
        if name not in FIXTURES:
            print("[sbom] unknown fixture: %s (choose from %s)"
                  % (name, ", ".join(sorted(FIXTURES))), file=sys.stderr)
            return 2
        sbom_path = FIXTURES[name]
        source = "fixture:%s" % name

    try:
        sbom = load_sbom(sbom_path)
    except Exception as exc:  # noqa: BLE001
        print("[sbom] cannot load %s: %s" % (sbom_path, exc), file=sys.stderr)
        return 2

    result = compute_gate(sbom, advisories)
    result["source"] = source
    result["bom_format"] = sbom["bom_format"]
    result["generated"] = _now()
    result["report"] = args.report
    _write_report(args.report, result)
    print(_format_text(result))

    if result["verdict"] != "PASS" and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())