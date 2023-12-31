import fitz
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog

def show_processing_window():
    processing_window = tk.Toplevel(root)
    processing_window.geometry("300x100")  # Explicit size
    center_window(processing_window)
    label = tk.Label(processing_window, text="Processing PDFs...", font=('Arial', 11))
    label.pack(pady=60, padx=60)
    root.update()
    return processing_window

def center_window(window):
    window.update_idletasks()
    screen_width, screen_height = window.winfo_screenwidth(), window.winfo_screenheight()
    window_width, window_height = window.winfo_width(), window.winfo_height()
    x, y = (screen_width / 2) - (window_width / 2), (screen_height / 2) - (window_height / 2)
    window.geometry(f"{window_width}x{window_height}+{int(x)}+{int(y)}")

def insert_with_color(text_widget, text, color='black'):
    tag_name = f"color_{color}"
    text_widget.tag_configure(tag_name, foreground=color)
    text_widget.insert(tk.INSERT, text, tag_name)

def contains_external_references(pdf_path, exclusion_keywords):
    doc = fitz.open(pdf_path)
    findings = []

    for i in range(doc.xref_length()):
        obj = doc.xref_object(i)
        if obj and ("/JS" in obj or "/JavaScript" in obj):
            findings.append("Detected embedded JavaScript:")
            findings.append(obj)

    for page in doc:
        for link in page.get_links():
            if "rect" in link:
                link_text = page.get_text("text", clip=link["rect"])
                if not any(keyword.lower() in link_text.lower() for keyword in exclusion_keywords):
                    findings.append(f"Link text: '{link_text.strip()}' pointing to {link['uri']}")

        for annot in page.annots():
            if annot.type[1] == 'Widget' and 'A' in annot.info and 'S' in annot.info['A'] and annot.info['A']['S'] == 'SubmitForm':
                findings.append("Detected form submission action.")

    # Check for external links and annotations
    for page in doc:
        for link in page.get_links():
            if 'uri' in link:
                findings.append(f"Detected external link: {link['uri']}")

    return findings

def select_files_and_check():
    keywords = simpledialog.askstring("Input", "Enter keywords of URLs to exclude separated by commas (or leave blank):", parent=root)
    if keywords:
        keywords = [k.strip() for k in keywords.split(",")]
    else:
        keywords = []

    root.withdraw()
    file_paths = filedialog.askopenfilenames(initialdir='~/Documents/', title="Select PDF files", filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
    if not file_paths:
        root.deiconify()
        return

    # Show the processing window
    processing_window = show_processing_window()

    findings_list = [(pdf_path, contains_external_references(pdf_path, keywords)) for pdf_path in file_paths]
    found_any_references = any(findings for _, findings in findings_list)

    # Destroy the processing window once processing is complete
    processing_window.destroy()

    result_window = tk.Toplevel(root)
    result_window.geometry("700x500")  # Explicit size
    center_window(result_window)
    result_display = scrolledtext.ScrolledText(result_window, wrap=tk.WORD, width=60, height=20)
    result_display.pack(padx=30, pady=30)

    for pdf_path, findings in findings_list:
        if findings:
            insert_with_color(result_display, f"PDF {pdf_path} findings:\n", 'red')
            for finding in findings:
                insert_with_color(result_display, f"{finding}\n", 'red')
            result_display.insert(tk.INSERT, "-----------\n")

    if not found_any_references:
        result_display.insert(tk.INSERT, "\n\nNo external references detected in the selected PDFs.\n")


    button_frame = tk.Frame(result_window)
    button_frame.pack(pady=20)
    save_btn = tk.Button(button_frame, text="Save Results", command=lambda: save_results(result_display))
    save_btn.pack(side=tk.LEFT, padx=10)
    quit_result_btn = tk.Button(button_frame, text="Quit", command=result_window.destroy)
    quit_result_btn.pack(side=tk.LEFT, padx=10)

def save_results(text_widget):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'w') as file:
                file.write(text_widget.get("1.0", tk.END))
        except Exception as e:
            tk.messagebox.showerror("Error", f"Failed to save the file. Reason: {e}")

root = tk.Tk()
root.geometry("400x150")
root.title("Check PDFs for External References")
center_window(root)
btn = tk.Button(root, text="Select PDFs", command=select_files_and_check)
btn.pack(pady=20)
quit_btn = tk.Button(root, text="Quit", command=root.destroy)
quit_btn.pack(pady=20)
root.mainloop()
