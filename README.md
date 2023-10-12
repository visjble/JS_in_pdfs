# JS_in_pdfs

# PDF External References Checker

This tool provides a simple GUI interface to inspect PDF files for potential external references, including embedded JavaScript, hyperlinks, and form submission actions. It also provides the capability to exclude links with certain keywords.

## Features

- GUI based PDF selection.
- Extract and display embedded JavaScript from PDF files.
- List hyperlinks in PDF files.
- Detect form submission actions in PDFs.
- Exclude links based on user-defined keywords.
- Save results to a text file.

## Installation

1. Ensure you have Python installed.
2. Install required packages using pip:
   ```bash
   pip install PyMuPDF tkinter
   ```

## Usage

1. Run the script:
   ```bash
   python pdf_checker.py
   ```

2. Click on "Select PDFs" to open the file dialog and select one or multiple PDF files.
3. If prompted, enter keywords to exclude from the link checks.
4. Review findings in the results window.
5. Optionally, save the results to a text file using the "Save Results" button.

## Dependencies

- [PyMuPDF](https://pymupdf.readthedocs.io/en/latest/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html) (Standard library in Python)

## False positives
Embedded fonts will trigger fals positive if the string JS appears. ex:
  ```
Detected embedded JavaScript:
<<
  /Type /FontDescriptor
  /FontName /JSNCUQ+font351
  /FontFamily (font351)
  /Flags 32
  /FontBBox [ 0 -206 2000 792 ]
  /ItalicAngle 0
  /Ascent 792
  /Descent -206
  /CapHeight 792
  /StemV 80
  /StemH 80
  /FontFile2 5108 0 R
>>
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---
