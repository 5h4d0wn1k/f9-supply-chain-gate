import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.supply_chain_gate import (  # noqa: E402
    ADVISORIES,
    LICENSE_POLICY,
    check_advisories,
    classify_license,
    compute_gate,
    evaluate_license_policy,
    load_sbom,
    main,
    match_constraints,
    parse_sbom,
    run_demo,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def _load(name):
    return load_sbom(os.path.join(FIXTURES, name))


class VersionCompareTest(unittest.TestCase):
    def test_eq(self):
        self.assertTrue(match_constraints("1.1.0", "==1.1.0"))
        self.assertFalse(match_constraints("1.1.1", "==1.1.0"))
        self.assertFalse(match_constraints("0.9.3", "==1.1.0"))

    def test_relational(self):
        self.assertTrue(match_constraints("2.0.5", "<2.1.0"))
        self.assertTrue(match_constraints("2.0.5", ">=2.0.0"))
        self.assertTrue(match_constraints("0.9.2", "<=0.9.3"))
        self.assertTrue(match_constraints("3.3.4", "!=3.3.3"))
        self.assertFalse(match_constraints("3.3.3", "<3.3.3"))

    def test_and_range(self):
        self.assertTrue(match_constraints("2.0.5", ">=2.0.0,<2.1.0"))
        self.assertFalse(match_constraints("2.1.0", ">=2.0.0,<2.1.0"))
        self.assertFalse(match_constraints("1.9.9", ">=2.0.0,<2.1.0"))

    def test_or_group(self):
        self.assertTrue(match_constraints("2.0.5", "<1.0.0||>=2.0.0,<2.1.0"))
        self.assertFalse(match_constraints("1.5.0", "<1.0.0||>=2.0.0,<2.1.0"))

    def test_wildcard_matches_everything(self):
        self.assertTrue(match_constraints("99.0.0", "*"))
        self.assertTrue(match_constraints("0.0.1", ""))


class ParseSbomTest(unittest.TestCase):
    def test_parse_cyclonedx(self):
        sbom = _load("sbom-clean.json")
        self.assertEqual(sbom["bom_format"], "CycloneDX")
        self.assertEqual(len(sbom["components"]), 4)
        names = {c["name"] for c in sbom["components"]}
        self.assertEqual(names, {"example-framework", "synthetlib",
                                 "fictitiouscore", "decoyutil"})

    def test_parse_cyclonedx_licenses(self):
        sbom = _load("sbom-clean.json")
        framework = next(c for c in sbom["components"]
                         if c["name"] == "example-framework")
        self.assertEqual(framework["licenses"], ["MIT"])

    def test_parse_spdx(self):
        sbom = _load("sbom-spdx-legacy.json")
        self.assertEqual(sbom["bom_format"], "SPDX")
        self.assertEqual(len(sbom["components"]), 4)
        core = next(c for c in sbom["components"] if c["name"] == "legacy-core")
        self.assertEqual(core["version"], "4.5.1")
        self.assertEqual(core["licenses"], ["GPL-3.0-only"])

    def test_unrecognized_format_raises(self):
        with self.assertRaises(ValueError):
            parse_sbom({"bomFormat": "SPDX-weird", "spdxVersion": ""})


class AdvisoryMatchTest(unittest.TestCase):
    def test_vulnerable_fixture_finds_advisories(self):
        sbom = _load("sbom-vulnerable.json")
        findings = check_advisories(sbom, ADVISORIES)
        self.assertEqual(len(findings), 3)
        matched = {(f["package"], f["version"]) for f in findings}
        self.assertIn(("synthetlib", "2.0.5"), matched)
        self.assertIn(("example-framework", "1.1.0"), matched)
        self.assertIn(("fictitiouscore", "0.9.2"), matched)

    def test_clean_fixture_has_no_advisories(self):
        sbom = _load("sbom-clean.json")
        self.assertEqual(check_advisories(sbom, ADVISORIES), [])

    def test_fictitiouscore_boundary_outside(self):
        # 0.9.4 is NOT affected by <<=0.9.3
        findings = [f for f in check_advisories(_load("sbom-clean.json"), ADVISORIES)
                    if f["package"] == "fictitiouscore"]
        self.assertEqual(findings, [])


class LicensePolicyTest(unittest.TestCase):
    def test_allowed_classified_pass(self):
        verdict, _ = classify_license("MIT", LICENSE_POLICY)
        self.assertEqual(verdict, "PASS")

    def test_denied_classified_fail(self):
        verdict, _ = classify_license("Proprietary", LICENSE_POLICY)
        self.assertEqual(verdict, "FAIL")

    def test_copyleft_classified_review(self):
        verdict, _ = classify_license("GPL-3.0-only", LICENSE_POLICY)
        self.assertEqual(verdict, "REVIEW")

    def test_undeclared_classified_review(self):
        verdict, _ = classify_license("NOASSERTION", LICENSE_POLICY)
        self.assertEqual(verdict, "REVIEW")


class GateTest(unittest.TestCase):
    def test_clean_passes(self):
        r = compute_gate(_load("sbom-clean.json"), ADVISORIES, LICENSE_POLICY)
        self.assertEqual(r["verdict"], "PASS")
        self.assertEqual(r["reasons"], [])
        self.assertEqual(r["summary"]["failures"], 0)

    def test_vulnerable_fails_with_reasons(self):
        r = compute_gate(_load("sbom-vulnerable.json"), ADVISORIES, LICENSE_POLICY)
        self.assertEqual(r["verdict"], "FAIL")
        reasons = "\n".join(r["reasons"]).lower()
        self.assertIn("synthetlib", reasons)
        self.assertIn("proprietary-sdk", reasons)
        self.assertIn("fail", reasons)

    def test_spdx_legacy_review(self):
        r = compute_gate(_load("sbom-spdx-legacy.json"), ADVISORIES, LICENSE_POLICY)
        self.assertEqual(r["verdict"], "REVIEW")
        reasons = "\n".join(r["reasons"]).lower()
        self.assertIn("gpl-3.0-only", reasons)

    def test_all_license_verdicts_present(self):
        r = compute_gate(_load("sbom-vulnerable.json"), ADVISORIES, LICENSE_POLICY)
        entries = {e["package"]: e["verdict"] for e in r["licenses"]}
        self.assertEqual(entries["proprietary-sdk"], "FAIL")
        self.assertEqual(entries["example-framework"], "PASS")


class CliTest(unittest.TestCase):
    def test_demo_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "demo.md")
            code = run_demo(rp)
            self.assertEqual(code, 0)
            with open(rp) as fh:
                text = fh.read()
            self.assertIn("fixture:clean", text)
            self.assertIn("fixture:vulnerable", text)

    def test_demo_via_main_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "d.json")
            code = main(["--demo", "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                data = json.loads(fh.read())
            self.assertEqual(data["summary"]["fixtures"], 3)
            self.assertEqual(data["summary"]["pass"], 1)
            self.assertEqual(data["summary"]["fail"], 1)

    def test_fixture_clean_json_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.json")
            code = main(["--fixture", "clean", "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                data = json.loads(fh.read())
            self.assertEqual(data["verdict"], "PASS")

    def test_fixture_vulnerable_strict_exit_one(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--fixture", "vulnerable", "--report", rp, "--strict"])
            self.assertEqual(code, 1)

    def test_fixture_spdx_legacy_md_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.md")
            code = main(["--fixture", "spdx-legacy", "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                self.assertIn("REVIEW", fh.read())

    def test_sbom_file_input(self):
        sb_path = os.path.join(FIXTURES, "sbom-clean.json")
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "r.json")
            code = main(["--sbom", sb_path, "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                self.assertEqual(json.loads(fh.read())["verdict"], "PASS")

    def test_bad_sbom_exit_two(self):
        with tempfile.TemporaryDirectory() as td:
            bad = os.path.join(td, "bad.json")
            with open(bad, "w") as fh:
                fh.write("not json")
            code = main(["--sbom", bad, "--report", os.path.join(td, "r.md")])
            self.assertEqual(code, 2)

    def test_bad_config_exit_two(self):
        with tempfile.TemporaryDirectory() as td:
            bad = os.path.join(td, "bad.json")
            with open(bad, "w") as fh:
                fh.write("{oops")
            code = main(["--fixture", "clean", "--config", bad,
                         "--report", os.path.join(td, "r.md")])
            self.assertEqual(code, 2)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()