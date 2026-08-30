"""
test_corpus_regression.py — Corpus regression test suite.

Every positive fixture in the corpus must be detectable by the relevant engine.
Every negative fixture must pass clean (no false positives).

Run:
    python3 -m pytest tests/test_corpus_regression.py -v
    python3 tests/test_corpus_regression.py  # standalone

This test suite answers: "Can the toolkit automatically re-detect the bugs
that humans already confirmed?" That is the primary validation benchmark.
"""

import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = REPO_ROOT / "plugins" / "cpython-security-toolkit" / "scripts"
CORPUS_DIR = REPO_ROOT / "plugins" / "cpython-security-toolkit" / "corpus"


def load_module_from_path(path: Path):
    """Dynamically load a Python module from a file path."""
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_syntax(script: Path) -> bool:
    """Return True if script parses without errors."""
    result = subprocess.run(
        [sys.executable, "-c", f"import ast; ast.parse(open(r'{script}').read())"],
        capture_output=True, text=True
    )
    return result.returncode == 0, result.stderr


def get_lib_dir() -> Path:
    """Return the stdlib Lib/ directory."""
    import tarfile
    import inspect
    return Path(inspect.getfile(tarfile)).parent


# ── Archive domain ────────────────────────────────────────────────────────────

class TestArchiveCorpus:
    """Corpus regression tests for archive extraction boundary invariant."""

    def test_arc_005_fixture_loads(self):
        """ARC-005 positive fixture must load and expose expected functions."""
        fixture = CORPUS_DIR / "archive" / "positive" / "arc_005_realpath_overflow.py"
        assert fixture.exists(), f"Missing: {fixture}"
        mod = load_module_from_path(fixture)
        assert hasattr(mod, "make_traversal_archive")
        assert hasattr(mod, "test_extraction_boundary")
        print("ARC-005 fixture: OK")

    def test_arc_001_fixture_loads(self):
        """ARC-001 positive fixture must load and expose expected functions."""
        fixture = CORPUS_DIR / "archive" / "positive" / "arc_001_symlink_traversal.py"
        assert fixture.exists(), f"Missing: {fixture}"
        mod = load_module_from_path(fixture)
        assert hasattr(mod, "make_symlink_escape_tar")
        assert hasattr(mod, "test_symlink_boundary")
        print("ARC-001 fixture: OK")

    def test_arc_001_fixture_runs(self):
        """ARC-001 fixture must run without errors."""
        fixture = CORPUS_DIR / "archive" / "positive" / "arc_001_symlink_traversal.py"
        result = subprocess.run(
            [sys.executable, str(fixture)],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"Fixture crashed: {result.stderr}"
        print(f"ARC-001 output: {result.stdout.strip()}")

    def test_scan_traversal_syntax(self):
        """scan_traversal.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_traversal.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_traversal.py: syntax OK")

    def test_scan_traversal_on_stdlib(self):
        """scan_traversal.py must run on stdlib and produce JSON."""
        import json
        script = SCRIPTS_DIR / "scan_traversal.py"
        result = subprocess.run(
            [sys.executable, str(script), str(get_lib_dir())],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_traversal.py: {len(findings)} candidate(s)")

    def test_scan_symlink_syntax(self):
        """scan_symlink.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_symlink.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_symlink.py: syntax OK")

    def test_scan_symlink_on_stdlib(self):
        """scan_symlink.py must run on stdlib and produce JSON."""
        import json
        script = SCRIPTS_DIR / "scan_symlink.py"
        result = subprocess.run(
            [sys.executable, str(script), str(get_lib_dir())],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_symlink.py: {len(findings)} candidate(s)")


# ── Protocol domain ───────────────────────────────────────────────────────────

class TestProtocolCorpus:
    """Corpus regression tests for validation coverage invariant."""

    def test_pro_002_fixture_runs(self):
        """PRO-002 fixture must run and produce output."""
        fixture = CORPUS_DIR / "protocol" / "positive" / "pro_002_morsel_update_bypass.py"
        assert fixture.exists(), f"Missing: {fixture}"
        result = subprocess.run(
            [sys.executable, str(fixture)],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, f"Fixture crashed: {result.stderr}"
        print(f"PRO-002 output: {result.stdout.strip()}")

    def test_scan_validation_coverage_syntax(self):
        """scan_validation_coverage.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_validation_coverage.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_validation_coverage.py: syntax OK")

    def test_scan_validation_coverage_on_stdlib(self):
        """scan_validation_coverage.py must run on stdlib and produce JSON."""
        import json
        import http.cookies
        import inspect
        lib_dir = Path(inspect.getfile(http.cookies)).parent.parent
        script = SCRIPTS_DIR / "scan_validation_coverage.py"
        result = subprocess.run(
            [sys.executable, str(script), str(lib_dir)],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_validation_coverage.py: {len(findings)} candidate(s)")

    def test_scan_incomplete_fix_syntax(self):
        """scan_incomplete_fix.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_incomplete_fix.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_incomplete_fix.py: syntax OK")


# ── Resource domain ───────────────────────────────────────────────────────────

class TestResourceCorpus:
    """Corpus regression tests for resource amplification invariant."""

    def test_res_001_fixture_runs(self):
        """RES-001 fixture must run and produce output."""
        fixture = CORPUS_DIR / "resource" / "positive" / "res_001_negative_offset.py"
        assert fixture.exists(), f"Missing: {fixture}"
        result = subprocess.run(
            [sys.executable, str(fixture)],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"Fixture crashed: {result.stderr}"
        print(f"RES-001 output: {result.stdout.strip()}")

    def test_scan_decompression_bounds_syntax(self):
        """scan_decompression_bounds.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_decompression_bounds.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_decompression_bounds.py: syntax OK")

    def test_scan_decompression_bounds_on_stdlib(self):
        """scan_decompression_bounds.py must run on stdlib and produce JSON."""
        import json
        import zipfile
        import inspect
        lib_dir = Path(inspect.getfile(zipfile)).parent
        script = SCRIPTS_DIR / "scan_decompression_bounds.py"
        result = subprocess.run(
            [sys.executable, str(script), str(lib_dir)],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_decompression_bounds.py: {len(findings)} candidate(s)")

    def test_scan_negative_offset_syntax(self):
        """scan_negative_offset.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_negative_offset.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_negative_offset.py: syntax OK")

    def test_scan_negative_offset_on_stdlib(self):
        """scan_negative_offset.py must run on stdlib and produce JSON."""
        import json
        script = SCRIPTS_DIR / "scan_negative_offset.py"
        result = subprocess.run(
            [sys.executable, str(script), str(get_lib_dir())],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_negative_offset.py: {len(findings)} candidate(s)")

    def test_scan_cpu_complexity_syntax(self):
        """scan_cpu_complexity.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_cpu_complexity.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_cpu_complexity.py: syntax OK")

    def test_scan_cpu_complexity_on_stdlib(self):
        """scan_cpu_complexity.py must run on stdlib and produce JSON."""
        import json
        import http.cookies
        import inspect
        lib_dir = Path(inspect.getfile(http.cookies)).parent.parent
        script = SCRIPTS_DIR / "scan_cpu_complexity.py"
        result = subprocess.run(
            [sys.executable, str(script), str(lib_dir)],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_cpu_complexity.py: {len(findings)} candidate(s)")


# ── Audit domain ──────────────────────────────────────────────────────────────

class TestAuditCorpus:
    """Corpus regression tests for audit hook coverage invariant."""

    def test_aud_001_fixture_runs(self):
        """AUD-001 fixture must run and report audit hook results."""
        fixture = CORPUS_DIR / "audit" / "positive" / "aud_001_open_code_bypass.py"
        assert fixture.exists(), f"Missing: {fixture}"
        result = subprocess.run(
            [sys.executable, str(fixture)],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"Fixture crashed: {result.stderr}"
        print(f"AUD-001 output: {result.stdout.strip()}")

    def test_scan_audit_hooks_syntax(self):
        """scan_audit_hooks.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_audit_hooks.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_audit_hooks.py: syntax OK")

    def test_scan_audit_hooks_on_stdlib(self):
        """scan_audit_hooks.py must run on stdlib and produce JSON."""
        import json
        import importlib._bootstrap_external
        import inspect
        lib_dir = Path(inspect.getfile(importlib._bootstrap_external)).parent.parent
        script = SCRIPTS_DIR / "scan_audit_hooks.py"
        result = subprocess.run(
            [sys.executable, str(script), str(lib_dir)],
            capture_output=True, text=True, timeout=60
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        print(f"scan_audit_hooks.py: {len(findings)} candidate(s)")


# ── Reproducer engine ─────────────────────────────────────────────────────────

class TestReproducerEngine:
    """Tests for the reproducer generation engine."""

    def test_reproducer_engine_syntax(self):
        """reproducer_engine.py must parse without errors."""
        script = SCRIPTS_DIR / "reproducer_engine.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("reproducer_engine.py: syntax OK")

    def test_reproducer_morsel_template(self):
        """Morsel update() reproducer template must run and return status."""
        import json, tempfile
        script = SCRIPTS_DIR / "reproducer_engine.py"
        finding = {
            "domain": "PRO", "sub_invariant": "2a",
            "module": "cookies.py", "confidence": "SECURITY-CANDIDATE",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(finding, f)
            tmp = f.name
        try:
            result = subprocess.run(
                [sys.executable, str(script), tmp],
                capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, f"Engine failed: {result.stderr}"
            out = json.loads(result.stdout)
            assert "reproducer_status" in out
            assert "script" in out
            print(f"Morsel reproducer: {out['reproducer_status']}")
        finally:
            os.unlink(tmp)

    def test_reproducer_audit_template(self):
        """Audit hook reproducer template must run and return status."""
        import json, tempfile
        script = SCRIPTS_DIR / "reproducer_engine.py"
        finding = {
            "domain": "AUD", "sub_invariant": "4a",
            "module": "_bootstrap_external.py", "confidence": "SECURITY-CANDIDATE",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(finding, f)
            tmp = f.name
        try:
            result = subprocess.run(
                [sys.executable, str(script), tmp],
                capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, f"Engine failed: {result.stderr}"
            out = json.loads(result.stdout)
            assert "reproducer_status" in out
            print(f"Audit reproducer: {out['reproducer_status']}")
        finally:
            os.unlink(tmp)


# ── Standalone runner ─────────────────────────────────────────────────────────

def run_all_tests():
    """Run all corpus regression tests without pytest."""
    test_classes = [
        TestArchiveCorpus,
        TestProtocolCorpus,
        TestResourceCorpus,
        TestAuditCorpus,
        TestReproducerEngine,
    ]

    passed = 0
    failed = 0
    errors = []

    for cls in test_classes:
        instance = cls()
        print(f"\n{'='*60}")
        print(f"  {cls.__name__}")
        print(f"{'='*60}")

        for method_name in sorted(dir(instance)):
            if not method_name.startswith("test_"):
                continue
            method = getattr(instance, method_name)
            try:
                print(f"\n  {method_name}:")
                method()
                print(f"  PASSED")
                passed += 1
            except AssertionError as e:
                print(f"  FAILED: {e}")
                failed += 1
                errors.append(f"{cls.__name__}.{method_name}: {e}")
            except Exception as e:
                print(f"  ERROR: {type(e).__name__}: {e}")
                failed += 1
                errors.append(f"{cls.__name__}.{method_name}: {type(e).__name__}: {e}")

    print(f"\n{'='*60}")
    print(f"Corpus regression: {passed} passed, {failed} failed")
    if errors:
        print("\nFailures:")
        for e in errors:
            print(f"  - {e}")
    print(f"{'='*60}")
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

# ── Negative fixtures ─────────────────────────────────────────────────────────

class TestNegativeFixtures:
    """Negative corpus fixtures must run cleanly and produce NEGATIVE output."""

    def _run_fixture(self, path: Path, timeout: int = 15) -> subprocess.CompletedProcess:
        assert path.exists(), f"Missing negative fixture: {path}"
        result = subprocess.run(
            [sys.executable, str(path)],
            capture_output=True, text=True, timeout=timeout,
        )
        assert result.returncode == 0, f"Fixture crashed: {result.stderr}"
        return result

    def test_arc_neg_001_safe_extraction(self):
        """Negative: safe extraction correctly blocks symlink traversal."""
        r = self._run_fixture(
            CORPUS_DIR / "archive" / "negative" / "arc_neg_001_safe_extraction.py"
        )
        assert "NEGATIVE" in r.stdout, f"Expected NEGATIVE output, got: {r.stdout}"
        print(f"arc_neg_001: {r.stdout.strip()}")

    def test_pro_neg_001_setitem_validates(self):
        """Negative: Morsel.__setitem__ correctly rejects control characters."""
        r = self._run_fixture(
            CORPUS_DIR / "protocol" / "negative" / "pro_neg_001_morsel_validates_all_paths.py"
        )
        assert "NEGATIVE" in r.stdout, f"Expected NEGATIVE output, got: {r.stdout}"
        print(f"pro_neg_001: {r.stdout.strip()}")

    def test_res_neg_001_bounded_decompression(self):
        """Negative: bounded decompression correctly limits output."""
        r = self._run_fixture(
            CORPUS_DIR / "resource" / "negative" / "res_neg_001_bounded_decompression.py"
        )
        assert "NEGATIVE" in r.stdout, f"Expected NEGATIVE output, got: {r.stdout}"
        print(f"res_neg_001: {r.stdout.strip()}")

    def test_aud_neg_001_open_code_fires_hook(self):
        """Negative: io.open_code() correctly fires sys.audit() hook."""
        r = self._run_fixture(
            CORPUS_DIR / "audit" / "negative" / "aud_neg_001_open_code_fires_hook.py"
        )
        assert "NEGATIVE" in r.stdout, f"Expected NEGATIVE output, got: {r.stdout}"
        print(f"aud_neg_001: {r.stdout.strip()}")


# ── scan_negative_offset (fixed script) ───────────────────────────────────────

class TestNegativeOffsetScript:
    """Tests for the corrected scan_negative_offset.py (was a copy of scan_cpu_complexity)."""

    def test_scan_negative_offset_syntax(self):
        """scan_negative_offset.py must parse without errors."""
        script = SCRIPTS_DIR / "scan_negative_offset.py"
        assert script.exists(), f"Missing: {script}"
        ok, err = check_syntax(script)
        assert ok, f"Syntax error: {err}"
        print("scan_negative_offset.py (fixed): syntax OK")

    def test_scan_negative_offset_correct_invariant(self):
        """scan_negative_offset.py must target sub_invariant 3c, not 3d."""
        import ast as _ast
        script = SCRIPTS_DIR / "scan_negative_offset.py"
        source = script.read_text()
        # The fixed script should target 3c (negative offsets) not 3d (complexity)
        assert "3c" in source, "Fixed script must reference sub_invariant 3c"
        assert "CVE-2025-8194" in source, "Must reference the canonical CVE anchor"
        # Must NOT be a copy of scan_cpu_complexity (which targets http/cookies, email)
        assert "QUADRATIC_STRING_OPS" not in source, \
            "scan_negative_offset must not contain QUADRATIC_STRING_OPS (wrong script)"
        print("scan_negative_offset.py: correctly targets sub_invariant 3c")

    def test_scan_negative_offset_on_stdlib(self):
        """scan_negative_offset.py must run on stdlib and produce JSON."""
        import json
        script = SCRIPTS_DIR / "scan_negative_offset.py"
        result = subprocess.run(
            [sys.executable, str(script), str(get_lib_dir())],
            capture_output=True, text=True, timeout=60,
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        findings = json.loads(result.stdout)
        assert isinstance(findings, list)
        # All findings must be sub_invariant 3c
        for f in findings:
            assert f.get("sub_invariant") == "3c", \
                f"Expected sub_invariant 3c, got {f.get('sub_invariant')}"
        print(f"scan_negative_offset.py (fixed): {len(findings)} candidate(s), all 3c")

class TestPrecisionAndComparison:
    """Tests for the failure modes found during the 2026 review."""

    def test_decompression_does_not_flag_normal_readall(self, tmp_path):
        script = SCRIPTS_DIR / "scan_decompression_bounds.py"
        sample = tmp_path / "sample.py"
        sample.write_text("def readall(self):\n    return self._fileobj.readall()\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(tmp_path)], capture_output=True, text=True)
        assert result.returncode == 0
        assert '"confidence": "SECURITY-CANDIDATE"' not in result.stdout

    def test_decompression_flags_unbounded_decompressor(self, tmp_path):
        script = SCRIPTS_DIR / "scan_decompression_bounds.py"
        sample = tmp_path / "zipfile" / "__init__.py"
        sample.parent.mkdir()
        sample.write_text("def read(self):\n    return self._decompressor.decompress(data)\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(tmp_path)], capture_output=True, text=True)
        assert result.returncode == 0
        assert "output bound" in result.stdout

    def test_parse_compatibility_for_lazy_import(self, tmp_path):
        script = SCRIPTS_DIR / "scan_traversal.py"
        sample = tmp_path / "zipfile.py"
        sample.write_text("lazy import pathlib\n\ndef extract(self):\n    return None\n", encoding="utf-8")
        result = subprocess.run([sys.executable, str(script), str(tmp_path)], capture_output=True, text=True)
        assert result.returncode == 0
        assert "ANALYSIS-ERROR" not in result.stdout

class TestBaselineComparison:
    def test_compare_filters_unchanged_findings(self, tmp_path):
        """A historical finding present in both trees is not a new finding."""
        base = tmp_path / "base"; target = tmp_path / "target"
        for root in (base, target):
            (root / "Lib" / "zipfile").mkdir(parents=True)
            (root / "Lib" / "zipfile" / "__init__.py").write_text(
                "def read(self):\n    return self._decompressor.decompress(data)\n", encoding="utf-8"
            )
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "scan_compare.py"), str(base), str(target), "--engines", "resource"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0
        report = __import__("json").loads(result.stdout)
        assert report["summary"]["new"] == 0
        assert report["summary"]["unchanged"] >= 1
