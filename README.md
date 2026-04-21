# pdf_chk — PDF + AZW3/MOBI Security Scanner

Blue-team triage tool for untrusted documents. Single file, no dependencies,
no network calls, no telemetry.

```
python3 pdf_chk.py suspicious.pdf
python3 pdf_chk.py /downloads/
```

---

## Why this exists

PDF viewers are complex and routinely execute code on document open —
JavaScript actions, remote resource fetches, form submissions, and more.
Several sites now warn that certain PDFs **contact external servers the moment
they are opened**, before the user interacts with anything.

This scanner lets you inspect a file *before* opening it and understand exactly
what it will try to do.

---

## Requirements

**Python 3.8 or later. Nothing else.**

No pip install. No virtual environment. Runs on Linux, macOS, and Windows,
including air-gapped machines and restricted corporate endpoints where package
managers are unavailable.

```bash
curl -O https://raw.githubusercontent.com/visjble/JS_in_pdfs/main/pdf_chk.py
python3 pdf_chk.py <file_or_directory>
```

---

## What it detects

| Category | Detail |
|---|---|
| **JavaScript / actions** | `/JavaScript`, `/JS`, `/Launch`, `/SubmitForm`, `/ImportData`, `/GoToR`, `/GoToE`, `/RichMedia`, `/3D`, OpenAction on open |
| **Hex-name evasion** | `/#4Aava#53cript` and similar — all checks normalize PDF name hex-escapes before matching, so this bypass is closed |
| **DecodeParms abuse** | Indirect references for numeric fields; float literals; `Columns × Colors × BitsPerComponent` row-stride overflow (int32); `/Colors > 32` |
| **Server contact on open** | External stream data (`/F` + `/FFilter`); URL-based file specifications (`/FS /URL`); XFA remote data bindings; HTTP(S) URLs in XMP metadata |
| **XFA forms** | XML-form `<script>` blocks; remote URL bindings inside XFA streams |
| **XMP metadata** | Suspicious tool names; large clusters of embedded URLs |
| **Shadow attacks** | Multiple `%%EOF` markers flagged; optional deep pass diffs each incremental revision for newly introduced actions |
| **Embedded executables** | PE / ELF / Mach-O / ZIP-JAR signatures in PDF streams and AZW3 resource records |
| **Social engineering** | Keyword scan against decoded content streams (plain-ASCII lures) |
| **Encrypted documents** | Flagged; content noted as unscanned |
| **AZW3 / MOBI** | Inline `<script>`, JS event handlers, `javascript:` URIs, external script sources, UNC paths, binary sigs in resource records |

---

## What it does NOT do

- **Decrypt encrypted PDFs** — no AES in stdlib; content is flagged but not inspected.
- **Render text** — social-engineering keyword scan runs against raw decoded
  content-stream bytes. Plain-ASCII lures are caught; CID-encoded or Unicode
  text may not be. Actions, JS, and links are still fully inspected regardless.
- **Decode exotic image filters** — DCT / JBIG2 / CCITTFax / JPX streams are
  scanned in their raw (compressed) form for embedded-executable signatures;
  pixel data is not reconstructed.
- **Connect to the internet** — the scanner is entirely offline and static.

---

## Usage

### Single file
```
python3 pdf_chk.py document.pdf
```

### Directory (batch)
```
python3 pdf_chk.py /path/to/folder/
```
Produces a risk distribution summary followed by individual reports.
When files with incremental updates are found, you are asked once whether
to run the deep revision-diff pass before scanning begins.

### Incremental update (shadow-attack) deep scan
When a single file has incremental updates, you are prompted interactively:
```
⚠ 2 incremental update(s) detected. Run deep revision diff? [y/N]:
```
The deep pass inspects each revision appended after the first `%%EOF` for
newly introduced action signatures — the mechanism used in shadow attacks.

---

## Sample output

```
================================================================================
PDF SECURITY SCAN REPORT
================================================================================
📄 invoice.pdf
📂 /home/user/downloads/invoice.pdf
🔖 MD5:    d41d8cd98f00b204e9800998ecf8427e
🔖 SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
📅 2026-04-21 14:32:01

🚨 RISK: CRITICAL (score 31)

Stats: Pages=3 | Objects=47 | Scanned=47 | Size (MB)=0.14 | JavaScript=2 |
       Attachments=0 | Forms=1 | Susp. links=1 | Incr. updates=1

🌐 REMOTE REFERENCES (3) — may contact servers on open:
   Link URLs (2):
      • https://tracker.evil.test/beacon?id=abc123
      • https://analytics.evil.test/pixel
   External streams (1):
      • obj 12

🔍 FINDINGS:

   🚨 CRITICAL (2):
      • [Catalog] OpenAction with JavaScript/Launch — executes on document open
      • [JavaScript] Dangerous function in object 8
        Found: eval(

   🔥 HIGH (3):
      • [Catalog] Document-level Additional Actions (AA) found
      • [Network] External stream data reference in object 12
        Viewer fetches stream from external source on open
      • [Incremental] Revision 1 introduces /OpenAction, /JavaScript
        Shadow-attack pattern: action added via incremental update

   ⚠️ MEDIUM (1):
      • [Structure] Multiple %%EOF markers: 2
        Incremental updates may hide malicious revisions (shadow attack)

💡 🚫 CRITICAL — quarantine/delete, do not open
================================================================================
```

---

## False positives

Earlier versions of this tool (and similar tools) flagged `/JS` appearances
inside **font descriptor** objects, producing alerts on clean PDFs that use
certain font naming conventions. This version avoids that by checking for
`/JavaScript` or `/JS` as a PDF action type, not as a bare substring in any
object.

If you encounter a false positive, please open an issue with the MD5/SHA256
of the file and the specific finding category.

---

## Supported formats

| Extension | Format |
|---|---|
| `.pdf` | PDF 1.0 – 2.0, including xref streams (PDF 1.5+) and object streams |
| `.azw3` | Kindle Format 8 |
| `.azw` | Kindle legacy |
| `.mobi` | MOBI / PalmDOC |

---

## Design decisions

**Why no PyMuPDF?**  
PyMuPDF is a large native extension that wraps the MuPDF C++ library, which
has a CVE history. A scanner that parses potentially-malicious files through
unaudited C++ code has a wider attack surface than one written entirely in
Python. Stdlib-only also means zero install friction and full auditability in a
single sitting.

**Why static analysis only?**  
The scanner never opens the file in a renderer. This guarantees no side effects
(no network calls, no JS execution, no file system writes) regardless of the
file's content.

**Why prompt for deep scan instead of always running it?**  
The incremental-update diff reads each appended revision separately. On large
files with many updates this adds measurable time. Quick triage (the default)
gives you the finding in under a second; the deep pass is opt-in.

---

## License

MIT
