# run from command line pdf_chk_CLI.py


import os, re
import fitz

def get_file_or_directory_path():
    print("\nPlease paste or drag and drop the file/directory path and press Enter:")
    path = input().strip()

    # Handling drag and drop which might have quotes around the path
    path = path.strip("\"'")

    return path

def find_ip_addresses(text):
    # Regular expression to match 'http://' followed by any non-whitespace characters
    url_pattern = r"http://\S+"
    return re.findall(url_pattern, text)


def contains_external_references(pdf_path):
    # print(f"Opening file: {pdf_path}")  # Debugging info
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
                findings.append(f"Link text: '{link_text.strip()}' pointing to {link['uri']}")

        for annot in page.annots():
            if annot.type[1] == 'Widget' and 'A' in annot.info and 'S' in annot.info['A'] and annot.info['A']['S'] == 'SubmitForm':
                findings.append("Detected form submission action.")
    # IP address detection
    for page in doc:
        text = page.get_text("text")
        urls = find_ip_addresses(text)
        for url in urls:
            print(f"Debug: Detected URL -> {url}")  # Debugging line
            findings.append("Detected URL: " + url)
    
    # Check for external links and annotations
    for page in doc:
        for link in page.get_links():
            if 'uri' in link:
                findings.append(f"Detected external link: {link['uri']}")
       
    return findings

def analyze_path(path):
    if os.path.isfile(path):
        return {path: contains_external_references(path)}
    elif os.path.isdir(path):
        findings = {}
        for root_dir, _, files in os.walk(path):
            for file in files:
                if file.endswith('.pdf'):
                    file_path = os.path.join(root_dir, file)
                    file_findings = contains_external_references(file_path)
                    if file_findings:
                        findings[file_path] = file_findings
        return findings
    else:
        print("The provided path is neither a file nor a directory.")
        return {}

def handle_results(findings):
    has_findings = False
    for file_path, file_findings in findings.items():
        if file_findings:
            has_findings = True
            print(f"\nFindings for {file_path}:\n")
            for finding in file_findings:
                print(finding)

    if not has_findings:
        print("\nNo external references detected in the provided PDFs.")
    else:
        save_choice = input("\nDo you want to save these findings to a .txt file? (yes/no): ").strip().lower()
        if save_choice == 'yes':
            save_path = input("Enter the path where you'd like to save the results (e.g., /path/to/results.txt): ").strip()
            with open(save_path, 'w') as file:
                for file_path, file_findings in findings.items():
                    if file_findings:
                        file.write(f"Findings for {file_path}:\n")
                        for finding in file_findings:
                            file.write(finding + '\n')
                        file.write("\n")
            print(f"\nResults saved to {save_path}")

def main():
    path = get_file_or_directory_path()
    print(f"Analyzing: {path}")
    while not os.path.exists(path):  # Loop until a valid path is provided
        print("\nInvalid path. Please provide a valid file or directory path.")
        path = get_file_or_directory_path()

    findings = analyze_path(path)
    handle_results(findings)

if __name__ == "__main__":
    main()
