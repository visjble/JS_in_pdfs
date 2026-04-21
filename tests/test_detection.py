#!/usr/bin/env python3
"""
Detection tests for pdf_chk.py.

Samples are generated on first run (no binary files committed).
Run with:  python3 -m pytest tests/  -v
       or: python3 tests/test_detection.py
"""

import os
import sys
import unittest
import tempfile

# Allow running from repo root or from tests/
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pdf_chk
from tests.generate_samples import generate

SAMPLES = os.path.join(tempfile.gettempdir(), "pdf_chk_test_samples")


def setUpModule():
    generate(SAMPLES)


def _scan(filename, deep=False):
    path = os.path.join(SAMPLES, filename)
    s = pdf_chk.PDFScanner(path)
    s.scan()
    if deep and s.stats["incremental_updates"] > 0:
        s.deep_incremental_check()
    return s


def _has(scanner, *, severity=None, category=None, contains=None):
    for f in scanner.findings:
        if severity  and f["severity"]    != severity:  continue
        if category  and f["category"]    != category:  continue
        if contains  and contains not in f["description"] + f["details"]: continue
        return True
    return False


# =============================================================================
# Positive detection tests — each variant must trigger the expected finding
# =============================================================================

class TestDecodeParms(unittest.TestCase):

    def test_v01_indirect_ref(self):
        """Numeric DecodeParms field given as indirect reference."""
        s = _scan("v2_01_indirect.pdf")
        self.assertTrue(
            _has(s, severity="HIGH", category="DecodeParms", contains="Indirect"),
            f"Expected HIGH/DecodeParms/Indirect, got: {[f['description'] for f in s.findings]}"
        )

    def test_v02_float_literal(self):
        """Numeric DecodeParms field given as float literal."""
        s = _scan("v2_02_float.pdf")
        self.assertTrue(
            _has(s, severity="HIGH", category="DecodeParms", contains="Float"),
            f"Expected HIGH/DecodeParms/Float, got: {[f['description'] for f in s.findings]}"
        )

    def test_v03_arith_overflow(self):
        """Product of Columns*Colors*BitsPerComponent overflows int32."""
        s = _scan("v2_03_arith_overflow.pdf")
        # Expect at least one DecodeParms finding (overflow or Colors>32)
        dp_findings = [f for f in s.findings if f["category"] == "DecodeParms"]
        self.assertTrue(
            dp_findings,
            "Expected at least one DecodeParms finding for arithmetic overflow"
        )
        severities = {f["severity"] for f in dp_findings}
        self.assertTrue(
            severities & {"CRITICAL", "HIGH"},
            f"Expected CRITICAL or HIGH severity, got: {severities}"
        )

    def test_v04_hex_name_evasion(self):
        """Hex-escaped name keys (/#43olumns) must be normalized before checking."""
        s = _scan("v2_04_hex_name.pdf")
        dp_findings = [f for f in s.findings if f["category"] == "DecodeParms"]
        self.assertTrue(
            dp_findings,
            "Hex-escaped name evasion was not detected — normalize_names may be broken"
        )

    def test_v05_array_form_decode_parms(self):
        """Array-form DecodeParms in a two-filter chain."""
        s = _scan("v2_05_filter_chain.pdf")
        dp_findings = [f for f in s.findings if f["category"] == "DecodeParms"]
        self.assertTrue(
            dp_findings,
            "Expected DecodeParms findings in array-form filter chain"
        )

    def test_v06_incremental_update_flagged(self):
        """File with two %%EOF markers must be flagged."""
        s = _scan("v2_06_incremental.pdf")
        self.assertGreater(
            s.stats["incremental_updates"], 0,
            "Incremental update not detected"
        )
        self.assertTrue(
            _has(s, category="Structure"),
            "Expected Structure finding for incremental update"
        )

    def test_v06_deep_scan_no_crash(self):
        """Deep scan on DecodeParms-only update must not crash."""
        s = _scan("v2_06_incremental.pdf", deep=True)
        self.assertIsInstance(s.findings, list)

    def test_v07_shadow_action_deep(self):
        """Deep scan must detect /JavaScript action added via incremental update."""
        s = _scan("v2_07_shadow_action.pdf", deep=True)
        incr = [f for f in s.findings if f["category"] == "Incremental"]
        self.assertTrue(
            incr,
            "Deep scan did not detect /JavaScript action introduced via incremental update"
        )

    def test_v07_shadow_action_flagged_without_deep(self):
        """Even without deep scan the file must flag %%EOF count."""
        s = _scan("v2_07_shadow_action.pdf")
        self.assertGreater(s.stats["incremental_updates"], 0)


# =============================================================================
# Clean file — must produce no HIGH or CRITICAL findings
# =============================================================================

class TestCleanFile(unittest.TestCase):

    def test_clean_pdf_no_high_risk(self):
        s = _scan("clean.pdf")
        bad = [f for f in s.findings if f["severity"] in ("HIGH", "CRITICAL")]
        self.assertFalse(
            bad,
            f"Clean PDF produced unexpected high-risk findings: {bad}"
        )

    def test_clean_pdf_safe_or_low(self):
        s = _scan("clean.pdf")
        level, _ = s.get_risk_level()
        self.assertIn(level, ("SAFE", "LOW"),
                      f"Clean PDF scored {level} — expected SAFE or LOW")


# =============================================================================
# Robustness — scanner must not raise on any input
# =============================================================================

class TestRobustness(unittest.TestCase):

    def _no_crash(self, filename):
        try:
            s = _scan(filename)
            self.assertIsInstance(s.findings, list)
        except SystemExit:
            pass  # sys.exit() in main is acceptable; unhandled exceptions are not

    def test_no_crash_indirect(self):    self._no_crash("v2_01_indirect.pdf")
    def test_no_crash_float(self):       self._no_crash("v2_02_float.pdf")
    def test_no_crash_overflow(self):    self._no_crash("v2_03_arith_overflow.pdf")
    def test_no_crash_hex_name(self):    self._no_crash("v2_04_hex_name.pdf")
    def test_no_crash_filter_chain(self):self._no_crash("v2_05_filter_chain.pdf")
    def test_no_crash_incremental(self): self._no_crash("v2_06_incremental.pdf")
    def test_no_crash_clean(self):       self._no_crash("clean.pdf")

    def test_empty_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"")
            name = f.name
        try:
            s = pdf_chk.PDFScanner(name)
            s.scan()
            self.assertIsInstance(s.findings, list)
        finally:
            os.unlink(name)

    def test_random_bytes(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(os.urandom(4096))
            name = f.name
        try:
            s = pdf_chk.PDFScanner(name)
            s.scan()
            self.assertIsInstance(s.findings, list)
        finally:
            os.unlink(name)


# =============================================================================
# Unit tests — core helpers
# =============================================================================

class TestNormalizeNames(unittest.TestCase):

    def test_javascript_hex(self):
        self.assertEqual(
            pdf_chk.normalize_names("/#4Aava#53cript"),
            "/JavaScript"
        )

    def test_launch_hex(self):
        self.assertEqual(
            pdf_chk.normalize_names("/#4Caunch"),
            "/Launch"
        )

    def test_no_hash_passthrough(self):
        s = "/OpenAction"
        self.assertIs(pdf_chk.normalize_names(s), s)

    def test_bytes_variant(self):
        self.assertEqual(
            pdf_chk.normalize_names_bytes(b"/#4A#53"),
            b"/JS"
        )


class TestDecodeStream(unittest.TestCase):

    def test_flate_roundtrip(self):
        import zlib
        data = b"Hello, PDF scanner!"
        compressed = zlib.compress(data)
        dict_text = "/Filter /FlateDecode"
        self.assertEqual(pdf_chk.decode_stream(compressed, dict_text), data)

    def test_ascii85_roundtrip(self):
        import base64
        data = b"Blue team test data"
        encoded = base64.a85encode(data, adobe=True)
        dict_text = "/Filter /ASCII85Decode"
        self.assertEqual(pdf_chk.decode_stream(encoded, dict_text), data)

    def test_no_filter_passthrough(self):
        data = b"raw bytes"
        self.assertEqual(pdf_chk.decode_stream(data, "/Length 9"), data)

    def test_unsupported_filter_returns_none(self):
        self.assertIsNone(pdf_chk.decode_stream(b"x", "/Filter /DCTDecode"))


class TestCheckDecodeParms(unittest.TestCase):

    def _run(self, obj_str):
        findings = []
        def add(sev, cat, desc, det=""):
            findings.append({"severity": sev, "category": cat,
                             "description": desc, "details": det})
        pdf_chk.check_decode_parms(obj_str, xref=0, add_finding=add)
        return findings

    def test_overflow_detected(self):
        s = "/DecodeParms << /Predictor 10 /Columns 65537 /Colors 65537 /BitsPerComponent 16 >>"
        f = self._run(s)
        self.assertTrue(any("overflow" in x["description"] for x in f))

    def test_colors_over_32(self):
        s = "/DecodeParms << /Colors 65537 >>"
        f = self._run(s)
        self.assertTrue(any("Colors" in x["description"] for x in f))

    def test_indirect_ref_detected(self):
        s = "/DecodeParms << /Columns 99 0 R >>"
        f = self._run(s)
        self.assertTrue(any("Indirect" in x["description"] for x in f))

    def test_float_detected(self):
        s = "/DecodeParms << /Columns 4294967295.0 >>"
        f = self._run(s)
        self.assertTrue(any("Float" in x["description"] for x in f))

    def test_clean_passthrough(self):
        s = "/DecodeParms << /Predictor 10 /Columns 4 /Colors 1 /BitsPerComponent 8 >>"
        f = self._run(s)
        self.assertEqual(f, [], f"Unexpected finding on clean DecodeParms: {f}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
