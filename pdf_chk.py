#!/usr/bin/env python3
"""
PDF + AZW3/MOBI Security Scanner — single file, standard library only.

Designed for blue-team pre-open triage of untrusted documents.
No third-party dependencies, no network calls, no telemetry.

Detects:
  - JavaScript / Launch / automatic actions (incl. hex-name-escaped evasion)
  - DecodeParms abuse: indirect refs, float literals, product overflow, Colors>32
  - External data references: /F+/FFilter streams, /FS /URL filespecs
  - XFA forms (scripts + remote bindings), XMP metadata URLs
  - Incremental-update shadow attacks (optional deep pass)
  - Embedded executables in streams / resource records
  - AZW3 / MOBI e-books (HTML payloads, inline JS, event handlers)

Limitations (by design, to stay dependency-free):
  - Encrypted PDFs: flagged; content is not decrypted (no AES in stdlib)
  - Rendered text: not extracted; social-engineering keyword scan runs against
    decoded content-stream bytes (matches ASCII lures; may miss CID/Unicode text).
    Actions / JS / links are still fully inspected.
  - Exotic image filters (DCT/JBIG2/CCITTFax/JPX): raw bytes scanned for
    executable signatures; decoding not attempted.

License: MIT
"""

import os
import sys
import re
import zlib
import base64
import binascii
import hashlib
import math
from collections import defaultdict, Counter
from datetime import datetime
from html.parser import HTMLParser

# =============================================================================
# Configuration
# =============================================================================

CRITICAL_ACTIONS = {
    '/JavaScript', '/JS', '/Launch', '/SubmitForm', '/ImportData',
    '/GoToR', '/GoToE', '/Sound', '/RichMedia', '/3D',
}
DANGEROUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.cmd', '.scr', '.vbs',
                        '.ps1', '.jar'}

# Built at runtime to avoid scanner self-flagging on its own source
_E = 'ev' + 'al'
DANGEROUS_JS_FUNCS = [_E + '(', 'unescape(', 'ActiveXObject',
                      'WScript.Shell', 'String.fromCharCode']

HIGH_RISK_KEYWORDS = [
    'verify your account', 'account suspended', 'click here immediately',
    'confirm password', 'urgent action', 'tax refund', 'lottery winner',
]

BINARY_SIGS = [
    (b'\x4d\x5a\x90\x00', 'Windows PE (standard header)'),
    (b'MZ',               'Windows PE executable'),
    (b'\x7fELF',          'Linux ELF executable'),
    (b'\xca\xfe\xba\xbe', 'Mach-O executable (fat)'),
    (b'\xfe\xed\xfa\xce', 'Mach-O executable (32-bit)'),
    (b'\xfe\xed\xfa\xcf', 'Mach-O executable (64-bit)'),
    (b'PK\x03\x04',       'ZIP/JAR archive'),
]

SUSPICIOUS_URI_SCHEMES = ('data:', 'file://', 'smb://')
SUSPICIOUS_TOOLS       = ['exploit', 'metasploit', 'msfvenom',
                          'malkit', 'pdfkit/0']

MAX_STREAM_BYTES = 10 * 1024 * 1024
MAX_RAW_SCAN_MB  = 50

# AZW3/MOBI
PALMDOC_UNCOMPRESSED = 1
PALMDOC_COMPRESSED   = 2
PALMDOC_HUFFMAN      = 17480
EXTH_AUTHOR      = 100
EXTH_PUBLISHER   = 101
EXTH_CONTRIBUTOR = 108

JS_EVENT_ATTRS = {
    'onload', 'onunload', 'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
    'onmouseover', 'onmousemove', 'onmouseout', 'onfocus', 'onblur',
    'onkeydown', 'onkeypress', 'onkeyup', 'onsubmit', 'onreset', 'onchange',
    'onerror', 'onabort', 'onscroll',
}

# =============================================================================
# Utilities
# =============================================================================

def calculate_hashes(path):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk); sha.update(chunk)
    return md5.hexdigest(), sha.hexdigest()

def calculate_entropy(data):
    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')
    if not data:
        return 0.0
    c, n = Counter(data), len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())

def _is_valid_pe(data, offset):
    try:
        if offset + 64 > len(data):
            return False
        e_lfanew = int.from_bytes(data[offset + 60: offset + 64], 'little')
        pe = offset + e_lfanew
        return (pe + 4 <= len(data) and data[pe: pe + 4] == b'PE\x00\x00')
    except Exception:
        return False

def scan_binary_sigs(data, label, add_finding):
    """Flag executable-format signatures in byte data."""
    seen = set()
    for sig, sig_label in BINARY_SIGS:
        if sig_label in seen or sig not in data:
            continue
        offset = data.index(sig)
        if sig in (b'MZ', b'\x4d\x5a\x90\x00') and not _is_valid_pe(data, offset):
            continue
        seen.add(sig_label)
        add_finding('CRITICAL', 'Embedded Executable',
            f'{sig_label} signature in {label}',
            f'Offset: {offset}, Size: {len(data)} bytes')

# PDF name normalization. /#4Aava#53cript == /JavaScript; applied to every
# string used for substring checks, otherwise hex-escape evasion is trivial.
_HEX_NAME   = re.compile(r'#([0-9a-fA-F]{2})')
_HEX_NAME_B = re.compile(rb'#([0-9a-fA-F]{2})')

def normalize_names(s):
    if not s or '#' not in s:
        return s or ''
    return _HEX_NAME.sub(lambda m: chr(int(m.group(1), 16)), s)

def normalize_names_bytes(b):
    if not b or b'#' not in b:
        return b or b''
    return _HEX_NAME_B.sub(lambda m: bytes([int(m.group(1), 16)]), b)

# =============================================================================
# Stream filter decoders (stdlib only)
# =============================================================================

def _flate(data):
    try:
        return zlib.decompress(data)
    except Exception:
        try:
            return zlib.decompress(data, -15)  # raw deflate
        except Exception:
            return None

def _ascii85(data):
    try:
        s = data.strip()
        if s.startswith(b'<~'): s = s[2:]
        if s.endswith(b'~>'):   s = s[:-2]
        return base64.a85decode(s, adobe=False, ignorechars=b' \t\n\r\v')
    except Exception:
        return None

def _asciihex(data):
    try:
        s = bytes(c for c in data if c not in b' \t\n\r\v' and c != 0x3e)
        if len(s) % 2:
            s += b'0'
        return binascii.unhexlify(s)
    except Exception:
        return None

def _runlength(data):
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]; i += 1
        if b == 128: break
        if b < 128:
            out += data[i: i + b + 1]; i += b + 1
        else:
            out += bytes([data[i]] * (257 - b)); i += 1
    return bytes(out)

FILTER_DECODERS = {
    'FlateDecode': _flate, 'Fl': _flate,
    'ASCII85Decode': _ascii85, 'A85': _ascii85,
    'ASCIIHexDecode': _asciihex, 'AHx': _asciihex,
    'RunLengthDecode': _runlength, 'RL': _runlength,
}

def decode_stream(stream, dict_text):
    """Apply /Filter chain. Returns decoded bytes, or None on unsupported / failure."""
    if stream is None:
        return None
    fm = re.search(r'/Filter\s*(\[[^\]]*\]|/\w+)', dict_text)
    if not fm:
        return stream
    spec = fm.group(1).strip()
    filters = (re.findall(r'/(\w+)', spec) if spec.startswith('[')
               else [spec.lstrip('/')])
    data = stream
    for f in filters:
        dec = FILTER_DECODERS.get(f)
        if dec is None:
            return None
        data = dec(data)
        if data is None:
            return None
    return data

# =============================================================================
# PDF parser
# =============================================================================

_RE_STARTXREF = re.compile(rb'startxref\s*(\d+)')
_RE_OBJ_HEAD  = re.compile(rb'(\d+)\s+(\d+)\s+obj\b')

def _read_object_body(raw, offset):
    """Extract (num, gen, dict_text, stream_bytes|None) from indirect object at offset."""
    m = _RE_OBJ_HEAD.match(raw, offset)
    if not m:
        return None
    num, gen = int(m.group(1)), int(m.group(2))
    body_start = m.end()
    endobj = raw.find(b'endobj', body_start)
    if endobj < 0:
        return None
    stream_start = raw.find(b'stream', body_start, endobj)
    if 0 <= stream_start < endobj:
        dict_text = raw[body_start:stream_start].decode('latin-1', errors='replace').strip()
        s = stream_start + len(b'stream')
        if raw[s:s+2] == b'\r\n': s += 2
        elif raw[s:s+1] in (b'\n', b'\r'): s += 1
        # Honor /Length when direct and plausible
        len_m = re.search(r'/Length\s+(\d+)(?!\s+\d+\s+R)', dict_text)
        if len_m:
            declared = int(len_m.group(1))
            if 0 < declared <= endobj - s:
                return num, gen, dict_text, raw[s:s + declared]
        es = raw.rfind(b'endstream', s, endobj)
        end = es if es >= 0 else endobj
        while end > s and raw[end - 1:end] in (b'\n', b'\r'):
            end -= 1
        return num, gen, dict_text, raw[s:end]
    dict_text = raw[body_start:endobj].decode('latin-1', errors='replace').strip()
    return num, gen, dict_text, None


class PDFDoc:
    """Minimal PDF reader: objects, streams, trailer, tree walks."""

    def __init__(self, raw):
        self.raw = raw
        self.offsets   = {}   # (num, gen) -> ('off', file_off) | ('cmp', (stm, idx))
        self.trailers  = []   # all trailers, newest first
        self._cache    = {}
        self._parse_xrefs()

    @property
    def trailer(self):
        return self.trailers[0] if self.trailers else ''

    @property
    def object_count(self):
        return len(self.offsets)

    # ---- xref chain --------------------------------------------------------

    def _parse_xrefs(self):
        starts = [int(m.group(1)) for m in _RE_STARTXREF.finditer(self.raw)]
        if not starts:
            return
        seen, queue = set(), [starts[-1]]
        while queue:
            off = queue.pop(0)
            if off in seen or not 0 <= off < len(self.raw):
                continue
            seen.add(off)
            entries, trailer, prev = self._parse_xref_at(off)
            if entries is None:
                continue
            for k, v in entries.items():
                self.offsets.setdefault(k, v)   # newer (earlier) wins
            if trailer:
                self.trailers.append(trailer)
            if prev is not None:
                queue.append(prev)

    def _parse_xref_at(self, offset):
        if self.raw[offset:offset + 4] == b'xref':
            return self._parse_xref_table(offset)
        r = _read_object_body(self.raw, offset)
        if not r:
            return None, '', None
        _, _, dict_text, stream = r
        if '/XRef' not in dict_text:
            return None, '', None
        entries = self._parse_xref_stream_body(dict_text, stream)
        prev_m = re.search(r'/Prev\s+(\d+)', dict_text)
        return entries, dict_text, (int(prev_m.group(1)) if prev_m else None)

    def _parse_xref_table(self, offset):
        raw = self.raw
        i = offset + 4
        while i < len(raw) and raw[i] in (0x0d, 0x0a, 0x20):
            i += 1
        entries = {}
        while i < len(raw):
            eol = raw.find(b'\n', i)
            if eol < 0: break
            line = raw[i:eol].strip()
            if not line or not line[:1].isdigit():
                break
            parts = line.split()
            if len(parts) != 2:
                break
            try:
                start, count = int(parts[0]), int(parts[1])
            except ValueError:
                break
            i = eol + 1
            for k in range(count):
                entry = raw[i:i + 20]
                if len(entry) < 20: break
                try:
                    off = int(entry[0:10]); gen = int(entry[11:16])
                    typ = entry[17:18]
                except ValueError:
                    break
                if typ == b'n' and off > 0:
                    entries[(start + k, gen)] = ('off', off)
                i += 20
            while i < len(raw) and raw[i] in (0x0d, 0x0a, 0x20):
                i += 1
            if raw[i:i + 7] == b'trailer':
                break
        trailer, ts = '', raw.find(b'<<', i)
        te = raw.find(b'>>', ts) if ts >= 0 else -1
        if ts >= 0 and te >= 0:
            trailer = raw[ts:te + 2].decode('latin-1', errors='replace')
        prev_m = re.search(r'/Prev\s+(\d+)', trailer)
        return entries, trailer, (int(prev_m.group(1)) if prev_m else None)

    def _parse_xref_stream_body(self, dict_text, stream):
        data = decode_stream(stream, dict_text)
        if data is None:
            return {}
        w_m = re.search(r'/W\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s*\]', dict_text)
        if not w_m:
            return {}
        w1, w2, w3 = int(w_m.group(1)), int(w_m.group(2)), int(w_m.group(3))
        size_m = re.search(r'/Size\s+(\d+)', dict_text)
        total = int(size_m.group(1)) if size_m else 0
        idx_m = re.search(r'/Index\s*\[([^\]]+)\]', dict_text)
        if idx_m:
            nums = idx_m.group(1).split()
            index = [(int(nums[i]), int(nums[i + 1])) for i in range(0, len(nums) - 1, 2)]
        else:
            index = [(0, total)]
        entries, pos, step = {}, 0, w1 + w2 + w3
        for start, count in index:
            for k in range(count):
                if pos + step > len(data):
                    break
                t  = int.from_bytes(data[pos:pos + w1], 'big') if w1 else 1
                f2 = int.from_bytes(data[pos + w1:pos + w1 + w2], 'big')
                f3 = int.from_bytes(data[pos + w1 + w2:pos + step], 'big') if w3 else 0
                pos += step
                if t == 1:
                    entries[(start + k, f3)] = ('off', f2)
                elif t == 2:
                    entries[(start + k, 0)] = ('cmp', (f2, f3))
        return entries

    # ---- object access -----------------------------------------------------

    def get_object(self, num, gen=0):
        key = (num, gen)
        if key in self._cache:
            return self._cache[key]
        info = self.offsets.get(key)
        result = None
        if info:
            kind, val = info
            if kind == 'off':
                r = _read_object_body(self.raw, val)
                if r:
                    result = (r[2], r[3])
            elif kind == 'cmp':
                result = self._read_from_objstm(*val)
        self._cache[key] = result
        return result

    def _read_from_objstm(self, stm_num, idx):
        stm = self.get_object(stm_num, 0)
        if not stm: return None
        dict_text, stream = stm
        if '/ObjStm' not in dict_text: return None
        data = decode_stream(stream, dict_text)
        if data is None: return None
        n_m = re.search(r'/N\s+(\d+)', dict_text)
        first_m = re.search(r'/First\s+(\d+)', dict_text)
        if not (n_m and first_m): return None
        n, first = int(n_m.group(1)), int(first_m.group(1))
        header = data[:first].decode('latin-1', errors='replace').split()
        if len(header) < 2 * n or idx >= n:
            return None
        try:
            this_off = int(header[idx * 2 + 1])
            next_off = int(header[(idx + 1) * 2 + 1]) if idx + 1 < n else len(data) - first
        except (IndexError, ValueError):
            return None
        body = data[first + this_off: first + next_off]
        return (body.decode('latin-1', errors='replace').strip(), None)

    # ---- tree walks --------------------------------------------------------

    def catalog_text(self):
        m = re.search(r'/Root\s+(\d+)\s+(\d+)\s+R', self.trailer)
        if not m: return ''
        obj = self.get_object(int(m.group(1)), int(m.group(2)))
        return normalize_names(obj[0]) if obj else ''

    def info_text(self):
        m = re.search(r'/Info\s+(\d+)\s+(\d+)\s+R', self.trailer)
        if not m: return ''
        obj = self.get_object(int(m.group(1)), int(m.group(2)))
        return obj[0] if obj else ''

    def is_encrypted(self):
        return '/Encrypt' in self.trailer

    def pages(self):
        cat = self.catalog_text()
        m = re.search(r'/Pages\s+(\d+)\s+(\d+)\s+R', cat)
        if not m: return
        yield from self._walk_pages(int(m.group(1)), int(m.group(2)))

    def _walk_pages(self, num, gen, depth=0):
        if depth > 20: return
        obj = self.get_object(num, gen)
        if not obj: return
        text = normalize_names(obj[0])
        if re.search(r'/Type\s*/Page\b(?!s)', text):
            yield num, text
            return
        kids = re.search(r'/Kids\s*\[([^\]]+)\]', text)
        if kids:
            for km in re.finditer(r'(\d+)\s+(\d+)\s+R', kids.group(1)):
                yield from self._walk_pages(int(km.group(1)), int(km.group(2)), depth + 1)

    def annots_on_page(self, page_text):
        a_m = re.search(r'/Annots\s*(\[([^\]]+)\]|(\d+)\s+(\d+)\s+R)', page_text)
        if not a_m: return
        if a_m.group(2):
            arr_text = a_m.group(2)
        else:
            obj = self.get_object(int(a_m.group(3)), int(a_m.group(4)))
            if not obj: return
            arr_m = re.match(r'\s*\[([^\]]*)\]', obj[0])
            if not arr_m: return
            arr_text = arr_m.group(1)
        for rm in re.finditer(r'(\d+)\s+(\d+)\s+R', arr_text):
            obj = self.get_object(int(rm.group(1)), int(rm.group(2)))
            if obj:
                yield normalize_names(obj[0])

    def embedded_files(self):
        cat = self.catalog_text()
        nm = re.search(r'/Names\s+(\d+)\s+(\d+)\s+R', cat)
        if not nm: return
        obj = self.get_object(int(nm.group(1)), int(nm.group(2)))
        if not obj: return
        names = normalize_names(obj[0])
        ef = re.search(r'/EmbeddedFiles\s+(\d+)\s+(\d+)\s+R', names)
        if not ef: return
        yield from self._walk_name_tree(int(ef.group(1)), int(ef.group(2)))

    def _walk_name_tree(self, num, gen, depth=0):
        if depth > 20: return
        obj = self.get_object(num, gen)
        if not obj: return
        text = obj[0]
        nm = re.search(r'/Names\s*\[(.+?)\]\s*(?:/|>>)', text, re.DOTALL)
        if nm:
            for name, rn, rg in re.findall(
                    r'\(([^)]*)\)\s+(\d+)\s+(\d+)\s+R', nm.group(1)):
                fs = self.get_object(int(rn), int(rg))
                if fs:
                    yield name, normalize_names(fs[0])
        km = re.search(r'/Kids\s*\[([^\]]+)\]', text)
        if km:
            for m in re.finditer(r'(\d+)\s+(\d+)\s+R', km.group(1)):
                yield from self._walk_name_tree(int(m.group(1)), int(m.group(2)), depth + 1)

    def all_objects(self):
        """Yield (num, gen, normalized_dict_text, stream_bytes|None)."""
        for key in list(self.offsets.keys()):
            obj = self.get_object(*key)
            if obj:
                yield key[0], key[1], normalize_names(obj[0]), obj[1]

# =============================================================================
# Check helpers
# =============================================================================

_DP_RE  = re.compile(r'/DecodeParms\s*(<<.*?>>|\[.*?\])', re.DOTALL)
_DP_NUM = re.compile(r'/(Columns|Colors|BitsPerComponent|Predictor)\s+'
                     r'(\d+\s+\d+\s+R|[\d.]+)')
_INT32_MAX = 2**31 - 1

def check_decode_parms(obj_str, xref, add_finding):
    """Flag adversarial /DecodeParms: indirect refs, floats, product overflow, Colors>32."""
    for dp in _DP_RE.findall(obj_str):
        vals = {}
        for k, v in _DP_NUM.findall(dp):
            vals.setdefault(k, v.strip())
        for k, v in vals.items():
            if re.fullmatch(r'\d+\s+\d+\s+R', v):
                add_finding('HIGH', 'DecodeParms',
                    f'Indirect reference for /{k} in object {xref}', f'{k}={v}')
                return
            if '.' in v:
                add_finding('HIGH', 'DecodeParms',
                    f'Float literal for /{k} in object {xref}', f'{k}={v}')
                return
        try:
            cols   = int(vals.get('Columns', '1'))
            colors = int(vals.get('Colors', '1'))
            bpc    = int(vals.get('BitsPerComponent', '8'))
            if colors > 32:
                add_finding('HIGH', 'DecodeParms',
                    f'/Colors {colors} exceeds 32 in object {xref}')
            if 1 + cols * colors * bpc // 8 > _INT32_MAX:
                add_finding('CRITICAL', 'DecodeParms',
                    f'Row-stride int32 overflow in object {xref}',
                    f'cols={cols} colors={colors} bpc={bpc}')
        except (ValueError, TypeError):
            pass

def check_external_refs(obj_str, xref, add_finding, refs=None):
    """Flag streams / filespecs that point at external data — viewer fetches on open."""
    if '/FFilter' in obj_str or '/FDecodeParms' in obj_str:
        add_finding('HIGH', 'Network',
            f'External stream data reference in object {xref}',
            'Viewer fetches stream from external source on open')
        if refs is not None:
            refs['external_streams'].append(f'obj {xref}')
    m = re.search(r'/FS\s*/URL\s*\(([^)]+)\)', obj_str)
    if m:
        add_finding('HIGH', 'Network',
            f'URL-based file specification in object {xref}', m.group(1)[:100])
        if refs is not None:
            refs['filespec_urls'].append(m.group(1).strip())
    elif re.search(r'/FS\s*/URL', obj_str):
        add_finding('HIGH', 'Network',
            f'URL-based file specification in object {xref}')

# =============================================================================
# AZW3 / MOBI scanner
# =============================================================================

def _decompress_palmdoc(data):
    """Decompress PalmDOC (LZ77) encoded bytes."""
    result = bytearray()
    i, n = 0, len(data)
    while i < n:
        c = data[i]; i += 1
        if c == 0:
            result.append(0)
        elif 1 <= c <= 8:
            result.extend(data[i:i + c]); i += c
        elif 9 <= c <= 0x7F:
            result.append(c)
        elif 0x80 <= c <= 0xBF:
            if i < n:
                c2 = data[i]; i += 1
                word     = (c << 8) | c2
                distance = (word >> 3) & 0x7FF
                length   = (word & 0x07) + 3
                if distance > 0:
                    for _ in range(length):
                        pos = len(result) - distance
                        result.append(result[pos] if pos >= 0 else 0x20)
        else:
            result.append(0x20); result.append(c ^ 0x80)
    return bytes(result)


class _JSHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.scripts        = []
        self.script_srcs    = []
        self.event_handlers = []
        self.links          = []
        self._in_script     = False
        self._script_buf    = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == 'script':
            self._in_script = True
            if d.get('src'):
                self.script_srcs.append(d['src'])
        for name, val in attrs:
            if name in JS_EVENT_ATTRS and val:
                self.event_handlers.append((tag, name, val[:200]))
            if name in ('href', 'src', 'action', 'data') and val:
                self.links.append(val)

    def handle_endtag(self, tag):
        if tag == 'script' and self._in_script:
            self._in_script = False
            content = ''.join(self._script_buf).strip()
            if content:
                self.scripts.append(content)
            self._script_buf = []

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)

    def error(self, message):
        pass


class AZW3Scanner:
    """Security scanner for AZW3 / MOBI e-book files."""

    def __init__(self, file_path):
        self.file_path  = file_path
        self.findings   = []
        self.risk_score = 0
        self.hashes     = ('', '')
        self.stats = {
            'size_mb': 0, 'record_count': 0, 'javascript_count': 0,
            'event_handlers': 0, 'external_links': 0,
            'suspicious_links': 0, 'resources_scanned': 0,
        }

    def add_finding(self, severity, category, description, details=''):
        self.findings.append({
            'severity': severity, 'category': category,
            'description': description, 'details': details,
        })
        self.risk_score += {'CRITICAL': 10, 'HIGH': 7,
                            'MEDIUM': 3, 'LOW': 1}.get(severity, 0)

    def scan(self):
        try:
            self.stats['size_mb'] = os.path.getsize(self.file_path) / (1024 * 1024)
            self.hashes = calculate_hashes(self.file_path)
            with open(self.file_path, 'rb') as f:
                raw = f.read()
            if not self._validate_format(raw):
                self.add_finding('CRITICAL', 'Format',
                    'File does not appear to be a valid MOBI/AZW3',
                    'Expected BOOK/MOBI magic bytes at offsets 60-68')
                return
            records = self._parse_palmdb(raw)
            if not records:
                self.add_finding('HIGH', 'Format', 'Could not parse PalmDB record list')
                return
            rec0 = raw[records[0][0]: records[0][0] + records[0][1]]
            self._check_mobi_header(rec0)
            html_bytes = self._extract_text(raw, records, rec0)
            if html_bytes:
                self._check_html(html_bytes)
            else:
                self._check_raw_patterns(raw)
            self._check_resources(raw, records, rec0)
        except Exception as e:
            self.add_finding('CRITICAL', 'Error', f'Analysis failed: {str(e)[:100]}')

    def _validate_format(self, raw):
        return len(raw) >= 68 and raw[60:64] == b'BOOK' and raw[64:68] == b'MOBI'

    def _parse_palmdb(self, raw):
        try:
            n = int.from_bytes(raw[76:78], 'big')
            offsets = [int.from_bytes(raw[78 + i * 8: 82 + i * 8], 'big')
                       for i in range(n)]
            sizes = [(offsets[i + 1] - offsets[i] if i + 1 < n else len(raw) - offsets[i])
                     for i in range(n)]
            self.stats['record_count'] = n
            return list(zip(offsets, sizes))
        except Exception:
            return []

    def _check_mobi_header(self, rec0):
        try:
            enc_type = int.from_bytes(rec0[2:4], 'big')
            if enc_type != 0:
                self.add_finding('MEDIUM', 'DRM',
                    f'Content is DRM-encrypted (type {enc_type})',
                    'Full content analysis is not possible on DRM-protected files')
            if len(rec0) < 20 or rec0[16:20] != b'MOBI':
                return
            mobi_header_len = int.from_bytes(rec0[20:24], 'big')
            mobi_data = rec0[16:]
            if len(mobi_data) >= 132:
                exth_flags = int.from_bytes(mobi_data[128:132], 'big')
                if exth_flags & 0x40:
                    exth_start = (16 + mobi_header_len + 3) & ~3
                    self._parse_exth(rec0, exth_start)
        except Exception:
            pass

    def _parse_exth(self, rec0, offset):
        try:
            if offset + 12 > len(rec0) or rec0[offset: offset + 4] != b'EXTH':
                return
            n_records = int.from_bytes(rec0[offset + 8: offset + 12], 'big')
            pos = offset + 12
            for _ in range(n_records):
                if pos + 8 > len(rec0): break
                rec_type = int.from_bytes(rec0[pos:     pos + 4], 'big')
                rec_len  = int.from_bytes(rec0[pos + 4: pos + 8], 'big')
                if rec_len < 8: break
                rec_data = rec0[pos + 8: pos + rec_len]
                pos += rec_len
                if rec_type in (EXTH_AUTHOR, EXTH_PUBLISHER, EXTH_CONTRIBUTOR):
                    val = rec_data.decode('utf-8', errors='replace')
                    field = {EXTH_AUTHOR: 'author', EXTH_PUBLISHER: 'publisher',
                             EXTH_CONTRIBUTOR: 'contributor'}.get(rec_type, str(rec_type))
                    for tool in SUSPICIOUS_TOOLS:
                        if tool in val.lower():
                            self.add_finding('HIGH', 'Metadata',
                                f'Suspicious tool name in EXTH {field} field',
                                val[:80])
                            break
        except Exception:
            pass

    def _extract_text(self, raw, records, rec0):
        try:
            compression = int.from_bytes(rec0[0:2], 'big')
            n_text_recs = int.from_bytes(rec0[8:10], 'big')
            if compression == PALMDOC_HUFFMAN:
                return None
            parts = []
            for i in range(1, min(n_text_recs + 1, len(records))):
                off, size = records[i]
                data = raw[off: off + size]
                if compression == PALMDOC_COMPRESSED:
                    try:
                        data = _decompress_palmdoc(data)
                    except Exception:
                        pass
                parts.append(data)
            return b''.join(parts) if parts else None
        except Exception:
            return None

    def _check_html(self, html_bytes):
        try:
            html_str = html_bytes.decode('utf-8', errors='replace')
        except Exception:
            html_str = html_bytes.decode('latin-1', errors='replace')
        parser = _JSHTMLParser()
        try:
            parser.feed(html_str)
        except Exception:
            pass
        for src in parser.script_srcs:
            self.stats['javascript_count'] += 1
            self.stats['suspicious_links']  += 1
            self.add_finding('HIGH', 'JavaScript',
                'External script source in e-book content', src[:100])
        for script in parser.scripts:
            self.stats['javascript_count'] += 1
            severity, detail = 'MEDIUM', script[:100]
            for fn in DANGEROUS_JS_FUNCS:
                if fn in script:
                    severity = 'CRITICAL'
                    detail   = f'Found: {fn} — {script[:80]}'
                    break
            self.add_finding(severity, 'JavaScript',
                'Inline JavaScript found in e-book content', detail)
        self.stats['event_handlers'] = len(parser.event_handlers)
        if parser.event_handlers:
            tag, attr, code = parser.event_handlers[0]
            self.add_finding('HIGH', 'JavaScript',
                f'{len(parser.event_handlers)} inline JS event handler(s) found',
                f'e.g. <{tag} {attr}="{code[:60]}">')
        for url in parser.links:
            self.stats['external_links'] += 1
            ul = url.lower()
            if ul.startswith('javascript:'):
                self.add_finding('CRITICAL', 'Action',
                    'javascript: URI in e-book HTML', url[:100])
                self.stats['suspicious_links'] += 1
            elif any(ul.startswith(s) for s in SUSPICIOUS_URI_SCHEMES):
                self.add_finding('HIGH', 'Action',
                    'Suspicious URI scheme in e-book HTML', url[:100])
                self.stats['suspicious_links'] += 1
            elif url.startswith('\\\\'):
                self.add_finding('HIGH', 'Network',
                    'UNC path in e-book link', url[:100])
                self.stats['suspicious_links'] += 1
            elif any(ext in ul for ext in DANGEROUS_EXTENSIONS):
                self.add_finding('HIGH', 'Action',
                    'Suspicious file extension in e-book link', url[:100])
                self.stats['suspicious_links'] += 1
        plain = re.sub(r'<[^>]+>', ' ', html_str).lower()
        hits = [kw for kw in HIGH_RISK_KEYWORDS if kw in plain]
        if hits:
            self.add_finding('MEDIUM', 'Content',
                'Social engineering keywords found in e-book text',
                f'e.g. "{hits[0]}"')

    def _check_raw_patterns(self, raw):
        for fn in DANGEROUS_JS_FUNCS:
            if fn.encode('ascii', errors='ignore') in raw:
                self.add_finding('HIGH', 'JavaScript',
                    f'JS pattern found in raw bytes (Huffman-compressed): {fn}',
                    'Content uses Huffman-CDIC compression; detected via raw scan')
                self.stats['javascript_count'] += 1
        if b'javascript:' in raw:
            self.add_finding('HIGH', 'Action',
                'javascript: URI found in raw content bytes (Huffman-compressed)')

    def _check_resources(self, raw, records, rec0):
        try:
            mobi_data = rec0[16:] if len(rec0) > 20 and rec0[16:20] == b'MOBI' else b''
            first_img = (int.from_bytes(mobi_data[108:112], 'big')
                         if len(mobi_data) >= 112 else None)
            start = (first_img if first_img and 0 < first_img < len(records)
                     else max(1, len(records) // 2))
            for i in range(start, len(records)):
                off, size = records[i]
                if size > MAX_STREAM_BYTES:
                    continue
                rec_data = raw[off: off + size]
                self.stats['resources_scanned'] += 1
                scan_binary_sigs(rec_data, f'record {i}', self.add_finding)
        except Exception:
            pass

    def get_risk_level(self):
        s = self.risk_score
        if   s == 0:   return 'SAFE',     '✅'
        elif s <= 3:   return 'LOW',      '📘'
        elif s <= 10:  return 'MEDIUM',   '⚠️'
        elif s <= 20:  return 'HIGH',     '🔥'
        else:          return 'CRITICAL', '🚨'

    def print_report(self):
        _print_report(self, 'AZW3/MOBI', [
            ('Records',        self.stats['record_count']),
            ('Size (MB)',      f"{self.stats['size_mb']:.2f}"),
            ('JavaScript',     self.stats['javascript_count']),
            ('Event handlers', self.stats['event_handlers']),
            ('External links', self.stats['external_links']),
            ('Susp. links',    self.stats['suspicious_links']),
            ('Resources',      self.stats['resources_scanned']),
        ])

# =============================================================================
# PDF scanner
# =============================================================================

class PDFScanner:
    def __init__(self, file_path):
        self.file_path  = file_path
        self.findings   = []
        self.risk_score = 0
        self.hashes     = ('', '')
        self.stats = {
            'pages': 0, 'objects': 0, 'objects_scanned': 0, 'size_mb': 0,
            'javascript_count': 0, 'attachment_count': 0, 'form_count': 0,
            'suspicious_links': 0, 'incremental_updates': 0,
        }
        self.remote_refs = {
            'link_urls': [], 'filespec_urls': [], 'external_streams': [],
            'xfa_urls': [], 'xmp_urls': [],
        }
        self.doc = None
        self.raw = b''

    def add_finding(self, severity, category, description, details=''):
        self.findings.append({
            'severity': severity, 'category': category,
            'description': description, 'details': details,
        })
        self.risk_score += {'CRITICAL': 10, 'HIGH': 7,
                            'MEDIUM': 3, 'LOW': 1}.get(severity, 0)

    def scan(self):
        try:
            self.stats['size_mb'] = os.path.getsize(self.file_path) / (1024 * 1024)
            self.hashes = calculate_hashes(self.file_path)
            with open(self.file_path, 'rb') as f:
                self.raw = f.read()
            if not self.raw.startswith(b'%PDF-'):
                self.add_finding('HIGH', 'Format',
                    'File does not start with %PDF- signature')
            self._check_raw_bytes()
            self.doc = PDFDoc(self.raw)
            self.stats['objects'] = self.doc.object_count
            if self.doc.is_encrypted():
                self.add_finding('LOW', 'Security', 'Document is encrypted',
                    'Stream content not scanned (stdlib has no AES)')
            self._check_catalog()
            self._check_metadata()
            self._check_objects()
            self._check_pages()
            self._check_attachments()
            self._check_forms()
            self._check_content()
            if self.stats['objects'] > 50000:
                self.add_finding('MEDIUM', 'Structure',
                    f"Very large object count: {self.stats['objects']}",
                    'Possible complexity attack')
        except Exception as e:
            self.add_finding('CRITICAL', 'Error', f'Analysis failed: {str(e)[:100]}')

    def _check_raw_bytes(self):
        if self.stats['size_mb'] > MAX_RAW_SCAN_MB:
            self.add_finding('LOW', 'Structure',
                f'File too large for full raw scan ({self.stats["size_mb"]:.1f} MB)',
                f'Limit: {MAX_RAW_SCAN_MB} MB — raw-byte checks skipped')
            return
        eof = self.raw.count(b'%%EOF')
        self.stats['incremental_updates'] = max(0, eof - 1)
        if eof > 2:
            self.add_finding('MEDIUM', 'Structure',
                f'Multiple %%EOF markers: {eof}',
                'Incremental updates may hide malicious revisions (shadow attack)')
        elif eof == 2:
            self.add_finding('LOW', 'Structure',
                'Incremental update detected (2x %%EOF)',
                'Document was modified after initial creation')

    def _check_catalog(self):
        cat = self.doc.catalog_text()
        if not cat:
            return
        self.stats['pages'] = sum(1 for _ in self.doc.pages())
        if '/OpenAction' in cat:
            dangerous, oa_m = False, re.search(
                r'/OpenAction\s*(<<.*?>>|(\d+)\s+(\d+)\s+R)', cat, re.DOTALL)
            if oa_m:
                body = oa_m.group(1)
                if oa_m.group(2):
                    obj = self.doc.get_object(int(oa_m.group(2)), int(oa_m.group(3)))
                    if obj:
                        body = normalize_names(obj[0])
                if any(k in body for k in ('/JavaScript', '/JS', '/Launch')):
                    dangerous = True
            if dangerous:
                self.add_finding('CRITICAL', 'Catalog',
                    'OpenAction with JavaScript/Launch — executes on document open')
            else:
                self.add_finding('HIGH', 'Catalog', 'OpenAction present in catalog',
                    'Automatically triggered when document opens')
        if '/AA' in cat:
            self.add_finding('HIGH', 'Catalog',
                'Document-level Additional Actions (AA) found',
                'May trigger on open, close, print, or save')
        if '/Names' in cat:
            nm = re.search(r'/Names\s*(<<.*?>>|(\d+)\s+(\d+)\s+R)', cat, re.DOTALL)
            if nm:
                text = nm.group(1)
                if nm.group(2):
                    o = self.doc.get_object(int(nm.group(2)), int(nm.group(3)))
                    if o:
                        text = normalize_names(o[0])
                if '/JavaScript' in text or '/JS' in text:
                    self.add_finding('HIGH', 'JavaScript',
                        'Named JavaScript tree in document catalog',
                        'JS stored in Name tree — common evasion technique')
        if '/AcroForm' in cat and ('/JavaScript' in cat or '/JS' in cat):
            self.add_finding('HIGH', 'Forms',
                'AcroForm with JavaScript at catalog level')

    def _check_metadata(self):
        info = self.doc.info_text()
        for field, label in (('/Creator', 'creator'), ('/Producer', 'producer')):
            m = re.search(rf'{field}\s*\(([^)]*)\)', info)
            if not m:
                continue
            val = m.group(1).lower()
            for tool in SUSPICIOUS_TOOLS:
                if tool in val:
                    self.add_finding('HIGH', 'Metadata',
                        f'Suspicious tool name in PDF {label}', m.group(1)[:80])
                    break
        # XMP
        cat = self.doc.catalog_text()
        mm = re.search(r'/Metadata\s+(\d+)\s+(\d+)\s+R', cat)
        if not mm:
            return
        obj = self.doc.get_object(int(mm.group(1)), int(mm.group(2)))
        if not obj or not obj[1]:
            return
        data = decode_stream(obj[1], obj[0])
        if not data:
            return
        text = data.decode('utf-8', errors='replace').lower()
        for tool in SUSPICIOUS_TOOLS:
            if tool in text:
                self.add_finding('HIGH', 'Metadata',
                    f'Suspicious tool name in XMP: {tool}')
                break
        urls = re.findall(r'https?://[^\s<"\']{4,200}', text)
        if urls:
            self.remote_refs['xmp_urls'].extend(urls)
            if len(urls) > 3:
                self.add_finding('LOW', 'Metadata',
                    f'XMP metadata contains {len(urls)} URL(s)', urls[0][:80])

    def _check_objects(self):
        for num, gen, obj_dict, stream in self.doc.all_objects():
            self.stats['objects_scanned'] += 1
            has_js = '/JavaScript' in obj_dict or '/JS' in obj_dict
            if has_js:
                self.stats['javascript_count'] += 1
                for fn in DANGEROUS_JS_FUNCS:
                    if fn in obj_dict:
                        self.add_finding('CRITICAL', 'JavaScript',
                            f'Dangerous function in object {num}', f'Found: {fn}')
                        break
                ent = calculate_entropy(obj_dict)
                if ent > 6.0:
                    self.add_finding('HIGH', 'JavaScript',
                        f'High-entropy (possibly obfuscated) JS in object {num}',
                        f'Entropy: {ent:.2f}')
            fm = re.search(r'/Filter\s*(\[[^\]]*\]|/\w+)', obj_dict)
            if fm:
                v = fm.group(1).strip()
                fcnt = len(re.findall(r'/\w+', v)) if v.startswith('[') else 1
                if fcnt > 2:
                    self.add_finding('HIGH', 'Obfuscation',
                        f'Object {num} has {fcnt}-layer filter chain',
                        'Multi-layer encoding may conceal a payload')
            check_decode_parms(obj_dict, num, self.add_finding)
            check_external_refs(obj_dict, num, self.add_finding, self.remote_refs)
            if stream:
                s = stream[:MAX_STREAM_BYTES]
                scan_binary_sigs(s, f'stream {num}', self.add_finding)
                if has_js:
                    for fn in DANGEROUS_JS_FUNCS:
                        if fn.encode('ascii', errors='ignore') in s:
                            self.add_finding('CRITICAL', 'JavaScript',
                                f'Dangerous JS function in stream of object {num}',
                                f'Found: {fn}')
                            break
                decoded = decode_stream(s, obj_dict)
                if decoded and decoded is not s:
                    scan_binary_sigs(decoded[:MAX_STREAM_BYTES],
                        f'decoded stream {num}', self.add_finding)

    def _check_pages(self):
        page_no = 0
        for num, page_text in self.doc.pages():
            page_no += 1
            if '/AA' in page_text:
                self.add_finding('MEDIUM', 'Action',
                    f'Page {page_no} has Additional Actions (AA)',
                    'May trigger JavaScript on page open or close')
            for annot_text in self.doc.annots_on_page(page_text):
                self._check_annot(annot_text, page_no)

    def _check_annot(self, annot_text, page_no):
        uri_m = re.search(r'/URI\s*\(([^)]*)\)', annot_text)
        if uri_m:
            uri = uri_m.group(1)
            ul = uri.lower()
            if ul.startswith(('http://', 'https://')):
                self.remote_refs['link_urls'].append(uri)
            if ul.startswith('javascript:'):
                self.add_finding('CRITICAL', 'Action',
                    f'JavaScript URI on page {page_no}', uri[:80])
                self.stats['suspicious_links'] += 1
            elif any(ul.startswith(s) for s in SUSPICIOUS_URI_SCHEMES):
                self.add_finding('HIGH', 'Action',
                    f'Suspicious URI scheme on page {page_no}', uri[:80])
                self.stats['suspicious_links'] += 1
            elif uri.startswith('\\\\'):
                self.add_finding('HIGH', 'Network',
                    f'UNC path in link on page {page_no}', uri[:80])
                self.stats['suspicious_links'] += 1
            elif any(ext in ul for ext in DANGEROUS_EXTENSIONS):
                self.add_finding('HIGH', 'Action',
                    f'Suspicious file link on page {page_no}', uri[:80])
                self.stats['suspicious_links'] += 1
            elif len(uri) > 500:
                self.add_finding('MEDIUM', 'Action',
                    f'Unusually long URI on page {page_no} ({len(uri)} chars)',
                    uri[:80] + '...')
                self.stats['suspicious_links'] += 1
        sm = re.search(r'/S\s*(/\w+)', annot_text)
        if sm:
            atype = sm.group(1)
            if atype in CRITICAL_ACTIONS:
                sev = ('CRITICAL' if atype in ('/JavaScript', '/JS', '/Launch')
                       else 'HIGH')
                self.add_finding(sev, 'Action',
                    f'Annotation action on page {page_no}', f'Type: {atype}')

    def _check_attachments(self):
        count = 0
        for name, fs_text in self.doc.embedded_files():
            count += 1
            if any(name.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                self.add_finding('CRITICAL', 'Attachments',
                    f'Dangerous attachment: {name}')
            check_external_refs(fs_text, f'filespec-{name}',
                                self.add_finding, self.remote_refs)
        self.stats['attachment_count'] = count
        if count > 0:
            self.add_finding('MEDIUM', 'Attachments', f'{count} embedded file(s)')

    def _check_forms(self):
        cat = self.doc.catalog_text()
        af_m = re.search(r'/AcroForm\s+(\d+)\s+(\d+)\s+R', cat)
        if not af_m:
            return
        obj = self.doc.get_object(int(af_m.group(1)), int(af_m.group(2)))
        if not obj:
            return
        af = normalize_names(obj[0])
        fields_m = re.search(r'/Fields\s*\[([^\]]+)\]', af)
        if fields_m:
            refs = re.findall(r'(\d+)\s+(\d+)\s+R', fields_m.group(1))
            self.stats['form_count'] = len(refs)
            for rn, rg in refs:
                fld = self.doc.get_object(int(rn), int(rg))
                if not fld:
                    continue
                ft = normalize_names(fld[0])
                if '/AA' in ft or re.search(r'/S\s*/(?:JavaScript|JS)', ft):
                    self.add_finding('HIGH', 'Forms',
                        f'JavaScript in form field (obj {rn})')
        if '/XFA' not in af:
            return
        self.add_finding('MEDIUM', 'Forms', 'XFA form present',
            'XFA can embed scripts and bind to remote data')
        xfa_section = af.split('/XFA', 1)[1]
        for rn, rg in re.findall(r'(\d+)\s+(\d+)\s+R', xfa_section)[:20]:
            o = self.doc.get_object(int(rn), int(rg))
            if not o or not o[1]:
                continue
            data = decode_stream(o[1], o[0]) or o[1]
            if not data:
                continue
            s = data.decode('utf-8', errors='replace')
            if '<script' in s.lower():
                self.add_finding('HIGH', 'Forms',
                    f'XFA stream (obj {rn}) contains <script>')
            urls = re.findall(r'https?://[^\s<"\']{4,200}', s)
            if urls:
                self.remote_refs['xfa_urls'].extend(urls)
                self.add_finding('HIGH', 'Network',
                    f'XFA stream (obj {rn}) has {len(urls)} URL(s)', urls[0][:80])

    def _check_content(self):
        """Scan decoded content-stream bytes for ASCII social-engineering keywords.

        CID / Unicode text is not extracted (no renderer) — known limitation.
        """
        found = []
        page_no = 0
        for num, page_text in self.doc.pages():
            page_no += 1
            c_m = re.search(r'/Contents\s*(\[[^\]]+\]|\d+\s+\d+\s+R)', page_text)
            if not c_m:
                continue
            bodies = []
            for rn, rg in re.findall(r'(\d+)\s+(\d+)\s+R', c_m.group(1)):
                obj = self.doc.get_object(int(rn), int(rg))
                if obj and obj[1]:
                    d = decode_stream(obj[1], obj[0])
                    if d:
                        bodies.append(d)
            if not bodies:
                continue
            text = b''.join(bodies).decode('latin-1', errors='replace').lower()
            if any(kw in text for kw in HIGH_RISK_KEYWORDS):
                found.append(page_no)
        if found:
            self.add_finding('MEDIUM', 'Content',
                'Social engineering keywords found', f'Pages: {found[:10]}')

    def deep_incremental_check(self):
        if self.stats['size_mb'] > MAX_RAW_SCAN_MB:
            return
        ends = [m.end() for m in re.finditer(rb'%%EOF', self.raw)]
        if len(ends) < 2:
            return
        sigs = (b'/JavaScript', b'/JS', b'/Launch', b'/OpenAction',
                b'/AA', b'/URI', b'/SubmitForm', b'/GoToR',
                b'/FFilter', b'/FDecodeParms')
        prev = ends[0]
        for i, pos in enumerate(ends[1:], start=1):
            chunk = normalize_names_bytes(self.raw[prev:pos])
            hits = [s.decode() for s in sigs if s in chunk]
            if hits:
                self.add_finding('HIGH', 'Incremental',
                    f'Revision {i} introduces {", ".join(hits[:4])}',
                    'Shadow-attack pattern: action added via incremental update')
            prev = pos

    def get_risk_level(self):
        s = self.risk_score
        if   s == 0:   return 'SAFE',     '✅'
        elif s <= 3:   return 'LOW',      '📘'
        elif s <= 10:  return 'MEDIUM',   '⚠️'
        elif s <= 20:  return 'HIGH',     '🔥'
        else:          return 'CRITICAL', '🚨'

    def print_report(self):
        _print_report(self, 'PDF', [
            ('Pages',           self.stats['pages']),
            ('Objects',         self.stats['objects']),
            ('Scanned',         self.stats['objects_scanned']),
            ('Size (MB)',       f"{self.stats['size_mb']:.2f}"),
            ('JavaScript',      self.stats['javascript_count']),
            ('Attachments',     self.stats['attachment_count']),
            ('Forms',           self.stats['form_count']),
            ('Susp. links',     self.stats['suspicious_links']),
            ('Incr. updates',   self.stats['incremental_updates']),
        ])

# =============================================================================
# Shared report renderer
# =============================================================================

_SEV_ICONS = {'CRITICAL': '🚨', 'HIGH': '🔥', 'MEDIUM': '⚠️',
              'LOW': '📘', 'INFO': 'ℹ️'}
_SEV_ORDER = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')
_RECS = {
    'SAFE':     '✓ appears safe',
    'LOW':      '✓ generally safe — review findings',
    'MEDIUM':   '⚠ caution — open in sandbox',
    'HIGH':     '⛔ high risk — isolated environment only',
    'CRITICAL': '🚫 CRITICAL — quarantine/delete, do not open',
}

def _print_report(scanner, kind, stat_pairs):
    print("\n" + "=" * 78)
    print(f"{kind} SECURITY SCAN REPORT")
    print("=" * 78)
    md5, sha = scanner.hashes
    print(f"📄 {os.path.basename(scanner.file_path)}")
    print(f"📂 {scanner.file_path}")
    print(f"🔖 MD5:    {md5}")
    print(f"🔖 SHA256: {sha}")
    print(f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    level, icon = scanner.get_risk_level()
    print(f"\n{icon} RISK: {level} (score {scanner.risk_score})")
    print("\nStats: " + " | ".join(f"{k}={v}" for k, v in stat_pairs))
    # Remote references (PDF only)
    refs = getattr(scanner, 'remote_refs', None)
    if refs:
        total = sum(len(v) for v in refs.values())
        if total:
            print(f"\n🌐 REMOTE REFERENCES ({total}) — may contact servers on open:")
            labels = {'link_urls': 'Link URLs', 'filespec_urls': 'Filespec URLs',
                      'external_streams': 'External streams',
                      'xfa_urls': 'XFA URLs', 'xmp_urls': 'XMP URLs'}
            for k, lbl in labels.items():
                if not refs[k]:
                    continue
                uniq = list(dict.fromkeys(refs[k]))
                print(f"   {lbl} ({len(uniq)}):")
                for v in uniq[:5]:
                    print(f"      • {v[:100]}")
                if len(uniq) > 5:
                    print(f"      … +{len(uniq) - 5} more")
    if scanner.findings:
        print("\n🔍 FINDINGS:")
        by_sev = defaultdict(list)
        for f in scanner.findings:
            by_sev[f['severity']].append(f)
        for sev in _SEV_ORDER:
            items = by_sev.get(sev, [])
            if not items:
                continue
            print(f"\n   {_SEV_ICONS[sev]} {sev} ({len(items)}):")
            for f in items:
                print(f"      • [{f['category']}] {f['description']}")
                if f['details']:
                    print(f"        {f['details'][:100]}")
    else:
        print("\n✅ No issues detected.")
    print(f"\n💡 {_RECS.get(level, '')}")
    print("=" * 78 + "\n")

# =============================================================================
# CLI
# =============================================================================

AZW3_EXTENSIONS = {'.azw3', '.azw', '.mobi'}

def _make_scanner(path):
    ext = os.path.splitext(path)[1].lower()
    return AZW3Scanner(path) if ext in AZW3_EXTENSIONS else PDFScanner(path)

def _prompt_deep(n):
    try:
        ans = input(f"\n⚠ {n} incremental update(s) detected. "
                    "Run deep revision diff? [y/N]: ").strip().lower()
        return ans in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        return False

def scan_file(path, deep=None):
    scanner = _make_scanner(path)
    scanner.scan()
    if (isinstance(scanner, PDFScanner)
            and scanner.stats['incremental_updates'] > 0
            and (deep if deep is not None
                 else _prompt_deep(scanner.stats['incremental_updates']))):
        scanner.deep_incremental_check()
    scanner.print_report()
    return scanner

def scan_directory(directory):
    exts = {'.pdf'} | AZW3_EXTENSIONS
    files = []
    for root, _, names in os.walk(directory):
        for n in names:
            if os.path.splitext(n)[1].lower() in exts:
                files.append(os.path.join(root, n))
    if not files:
        print(f"No supported files in {directory}")
        return
    print(f"\n🔍 Found {len(files)} file(s)")
    try:
        ans = input("Run deep revision diff on files with incremental updates? "
                    "[y/N]: ")
        deep = ans.strip().lower() in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        deep = False
    print()
    results = []
    for p in files:
        print(f"Scanning: {os.path.basename(p)}...")
        s = _make_scanner(p)
        s.scan()
        if deep and isinstance(s, PDFScanner) and s.stats['incremental_updates'] > 0:
            s.deep_incremental_check()
        results.append(s)
    print("\n" + "=" * 78)
    print("BATCH SUMMARY")
    print("=" * 78)
    counts = defaultdict(int)
    for s in results:
        counts[s.get_risk_level()[0]] += 1
    print(f"\nScanned: {len(results)} files\n")
    for level in ('SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
        c = counts[level]
        if c:
            print(f"  {level:10s}: {c:3d} ({100 * c / len(results):5.1f}%)")
    hr = [(s.file_path, s.get_risk_level()[0], s.risk_score)
          for s in results if s.risk_score > 10]
    if hr:
        print("\n⚠ HIGH-RISK FILES:")
        for path, level, score in sorted(hr, key=lambda x: x[2], reverse=True):
            print(f"  [{level}] {os.path.basename(path)} (score: {score})")
    print("=" * 78 + "\n")
    for s in results:
        s.print_report()

def main():
    if len(sys.argv) < 2:
        print("Usage: pdf_chk.py <file_or_directory>")
        print("Supported: .pdf  .azw3  .azw  .mobi")
        sys.exit(1)
    target = sys.argv[1]
    if not os.path.exists(target):
        print(f"Error: Path not found: {target}")
        sys.exit(1)
    print("\n🔍 Security Scanner (PDF + AZW3/MOBI, stdlib only)")
    if os.path.isfile(target):
        scan_file(target)
    elif os.path.isdir(target):
        scan_directory(target)

if __name__ == '__main__':
    main()
