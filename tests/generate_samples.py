#!/usr/bin/env python3
"""
Generate adversarial PDF test samples.
Run directly or called automatically by test_detection.py.
All samples are reproducible from source — no binary files committed.
"""

import zlib, base64
from pathlib import Path

HEADER   = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
CONTENT  = b"q\nQ\n"
CATALOG  = (1, b"<< /Type /Catalog /Pages 2 0 R >>")
PAGES    = (2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
PAGE     = (3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
               b"/Contents 4 0 R /Resources << >> >>")


def _flate(data):
    return zlib.compress(data)

def _a85(data):
    return base64.a85encode(data, adobe=True)

def _pdf(objects, trailer_extra=b""):
    buf = bytearray(HEADER)
    offs = {}
    for num, body in objects:
        offs[num] = len(buf)
        buf += f"{num} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_off = len(buf)
    mx = max(offs)
    buf += f"xref\n0 {mx + 1}\n".encode()
    buf += b"0000000000 65535 f \n"
    for n in range(1, mx + 1):
        buf += (f"{offs[n]:010d} 00000 n \n".encode()
                if n in offs else b"0000000000 00000 f \n")
    buf += (b"trailer\n<< /Size " + str(mx + 1).encode()
            + b" /Root 1 0 R" + trailer_extra
            + b" >>\nstartxref\n" + str(xref_off).encode() + b"\n%%EOF\n")
    return bytes(buf)

def _stm(dict_body, data):
    hdr = b"<< /Length " + str(len(data)).encode() + b" " + dict_body + b" >>\n"
    return hdr + b"stream\n" + data + b"\nendstream"

def _write(out_dir, name, data):
    p = Path(out_dir) / name
    p.write_bytes(data)
    return p


def generate(out_dir="."):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    c = _flate(CONTENT)

    # v2_01: indirect reference for /Columns (and other fields)
    _write(out_dir, "v2_01_indirect.pdf", _pdf([
        CATALOG, PAGES, PAGE,
        (4, _stm(b"/Filter /FlateDecode "
                 b"/DecodeParms << /Predictor 10 "
                 b"/Columns 99 0 R /Colors 99 0 R "
                 b"/BitsPerComponent 99 0 R >>", c)),
        (99, b"4294967295"),
    ]))

    # v2_02: float-literal numeric fields
    _write(out_dir, "v2_02_float.pdf", _pdf([
        CATALOG, PAGES, PAGE,
        (4, _stm(b"/Filter /FlateDecode "
                 b"/DecodeParms << /Predictor 10 "
                 b"/Columns 4294967295.0 /Colors 4.0 "
                 b"/BitsPerComponent 8.0 >>", c)),
    ]))

    # v2_03: arithmetic overflow — each field in-range, product overflows int32
    # 65537 * 65537 * 16 / 8 = 8,590,065,664  > INT32_MAX
    _write(out_dir, "v2_03_arith_overflow.pdf", _pdf([
        CATALOG, PAGES, PAGE,
        (4, _stm(b"/Filter /FlateDecode "
                 b"/DecodeParms << /Predictor 10 "
                 b"/Columns 65537 /Colors 65537 "
                 b"/BitsPerComponent 16 >>", c)),
    ]))

    # v2_04: hex-escaped name keys  /#43olumns == /Columns  etc.
    _write(out_dir, "v2_04_hex_name.pdf", _pdf([
        CATALOG, PAGES, PAGE,
        (4, _stm(b"/Filter /FlateDecode "
                 b"/DecodeParms << /#50redictor 10 "
                 b"/#43olumns 4294967295 "
                 b"/#43olors 4294967295 "
                 b"/#42itsPerComponent 4294967295 >>", c)),
    ]))

    # v2_05: array-form DecodeParms in a two-filter chain
    a85c = _a85(c)
    _write(out_dir, "v2_05_filter_chain.pdf", _pdf([
        CATALOG, PAGES, PAGE,
        (4, _stm(b"/Filter [/ASCII85Decode /FlateDecode] "
                 b"/DecodeParms [null << /Predictor 10 "
                 b"/Columns 4294967295 /Colors 4294967295 "
                 b"/BitsPerComponent 4294967295 >>]", a85c)),
    ]))

    # v2_06: incremental update that overwrites obj 4 with malicious DecodeParms
    clean_dp = (b"/Filter /FlateDecode "
                b"/DecodeParms << /Predictor 10 "
                b"/Columns 4 /Colors 1 /BitsPerComponent 8 >>")
    base = _pdf([CATALOG, PAGES, PAGE, (4, _stm(clean_dp, c))])

    update_obj_off = len(base)
    mal_dp = (b"/Filter /FlateDecode "
              b"/DecodeParms << /Predictor 10 "
              b"/Columns 4294967295 /Colors 4294967295 "
              b"/BitsPerComponent 4294967295 >>")
    update_obj = b"4 0 obj\n" + _stm(mal_dp, c) + b"\nendobj\n"
    old_xref = int(base.rsplit(b"startxref\n", 1)[1].split(b"\n", 1)[0])
    update_xref_off = update_obj_off + len(update_obj)
    update_xref = (b"xref\n0 1\n0000000000 65535 f \n4 1\n"
                   + f"{update_obj_off:010d} 00000 n \n".encode())
    update_trailer = (b"trailer\n<< /Size 5 /Root 1 0 R /Prev "
                      + str(old_xref).encode()
                      + b" >>\nstartxref\n"
                      + str(update_xref_off).encode()
                      + b"\n%%EOF\n")
    _write(out_dir, "v2_06_incremental.pdf",
           base + update_obj + update_xref + update_trailer)

    # v2_07: incremental update that adds /OpenAction with /JavaScript — shadow attack
    base2 = _pdf([CATALOG, PAGES, PAGE, (4, _stm(b"/Filter /FlateDecode", c))])
    js_obj_off = len(base2)
    js_obj = b"5 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>\nendobj\n"
    # Overwrite catalog to add OpenAction pointing at obj 5
    cat_obj_off = js_obj_off + len(js_obj)
    cat_obj = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n"
    old_xref2 = int(base2.rsplit(b"startxref\n", 1)[1].split(b"\n", 1)[0])
    upd_xref_off = cat_obj_off + len(cat_obj)
    upd_xref = (b"xref\n"
                b"1 1\n" + f"{cat_obj_off:010d} 00000 n \n".encode()
                + b"5 1\n" + f"{js_obj_off:010d} 00000 n \n".encode())
    upd_trailer = (b"trailer\n<< /Size 6 /Root 1 0 R /Prev "
                   + str(old_xref2).encode()
                   + b" >>\nstartxref\n" + str(upd_xref_off).encode()
                   + b"\n%%EOF\n")
    _write(out_dir, "v2_07_shadow_action.pdf",
           base2 + js_obj + cat_obj + upd_xref + upd_trailer)

    # clean.pdf — a well-formed PDF with no security issues
    _write(out_dir, "clean.pdf", _pdf([CATALOG, PAGES, PAGE,
        (4, _stm(b"/Filter /FlateDecode", c))]))

    print(f"Generated 8 samples in {out_dir}/")


if __name__ == "__main__":
    import sys
    generate(sys.argv[1] if len(sys.argv) > 1 else ".")
