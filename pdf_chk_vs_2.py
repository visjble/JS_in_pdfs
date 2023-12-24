# 
import os, re, time
import fitz
import hashlib

def get_file_or_directory_path():
    print("\nPlease paste or drag and drop the file/directory path and press Enter:")
    return input().strip().strip("\"'")

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
url_pattern = r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?"

def find_ip_addresses(text):
    # ip_pattern = r"\b\d{1,3}(\.\d{1,3}){3}\b"  # Simple IPv4 regex
    return re.findall(ip_pattern, text)

def find_urls(text):
    return re.findall(url_pattern, text)


def extract_actions_from_pdf(doc):
    actions = []
    for i in range(doc.xref_length()):
        obj = doc.xref_object(i)
        if isinstance(obj, dict):
            action = obj.get("/A")
            if action and isinstance(action, dict):
                action_type = action.get("/S", "")
                if action_type:
                    actions.append((i, action_type, str(action)))
    return actions

def check_for_font_obfuscation(doc):
    print('Check for obfuscation...')
    obfuscation_findings = []
    for i in range(doc.xref_length()):
        obj = doc.xref_object(i)
        if isinstance(obj, dict):
            if "/Font" in obj:
                font_dict = obj.get("/Font")
                if font_dict:
                    # Perform checks here for font obfuscation
                    if "<some_condition>":  # Replace with actual condition
                        obfuscation_findings.append(f"Potential font obfuscation detected in object {i}")
    if not obfuscation_findings:
        print('\nNo obfuscation found')
    return obfuscation_findings

# def decode_and_check_streams(doc, findings):
#     print('decode and check streams...')
#     comment_single_line_pattern = r"//.*"
#     comment_multi_line_pattern = r"/\*.*?\*/"
#     conditional_pattern = r"\bif\s*\("

#     def detect_patterns(decoded_stream, object_id):
#         def find_with_pattern(pattern, message, stream, obj_id):
#             local_findings = []
#             for match in re.finditer(pattern, stream):
#                 snippet = stream[match.start():match.start()+150] + '...'
#                 local_findings.append(f"{message} at position {match.start()} in decoded stream for object {obj_id}: {snippet}")
#             return local_findings

#         local_findings = []
#         local_findings.extend(find_with_pattern(comment_single_line_pattern, "Detected single-line comment", decoded_stream, object_id))
#         local_findings.extend(find_with_pattern(comment_multi_line_pattern, "Detected multi-line comment", decoded_stream, object_id))
#         local_findings.extend(find_with_pattern(conditional_pattern, "Detected 'if' conditional statement", decoded_stream, object_id))

#         return local_findings

#     for i in range(doc.xref_length()):
#         try:
#             is_stream = doc.xref_stream(i)
#             if is_stream:
#                 stream = doc.xref_stream_raw(i)
#                 try:
#                     decoded_stream = stream.decode(errors='ignore')
#                     findings.extend(detect_patterns(decoded_stream, i))
#                 except Exception as e:
#                     findings.append(f"An error occurred while analyzing object {i}: {str(e)}")
#         except Exception as e:
#             findings.append(f"Could not fetch stream for object {i}: {e}")

def contains_external_references(pdf_path):
    doc = fitz.open(pdf_path)
    findings = []

    for page_num, page in enumerate(doc, start=1):
        for annot in page.annots():
            if annot.type[1] == 'Widget' and annot.info.get('A', {}).get('S') == 'SubmitForm':
                findings.append(f"Page {page_num}: Detected form submission action.")

        text = page.get_text("text")
        ip_addresses = find_ip_addresses(text)
        for ip in ip_addresses:
            findings.append(f"Page {page_num}: Detected IP Address: {ip}")

        urls = find_urls(text)
        for url in urls:
            findings.append(f"Page {page_num}: Detected URL: {url}")

    doc.close()
    return findings


def analyze_path(path):
    findings = {}
    md5_checksums = {}

    if os.path.isfile(path) and path.endswith('.pdf'):
        doc = fitz.open(path)
        file_findings = contains_external_references(doc)
        font_findings = check_for_font_obfuscation(doc)
        actions = extract_actions_from_pdf(doc)
        file_findings.extend(font_findings)
        file_findings.extend(actions)
        md5_checksums[path] = calculate_md5(path)
        doc.close()
        findings[path] = file_findings

    elif os.path.isdir(path):
        for root_dir, _, files in os.walk(path):
            for file in files:
                if file.endswith('.pdf'):
                    file_path = os.path.join(root_dir, file)
                    doc = fitz.open(file_path)
                    file_findings = contains_external_references(doc)
                    font_findings = check_for_font_obfuscation(doc)
                    actions = extract_actions_from_pdf(doc)
                    file_findings.extend(font_findings)
                    file_findings.extend(actions)
                    doc.close()
                    if file_findings:
                        findings[file_path] = file_findings
                        md5_checksums[file_path] = calculate_md5(file_path)

    else:
        print("The provided path is neither a file nor a directory.")

    return findings, md5_checksums





def handle_results(findings):
    if not findings:
        print("\nNo external references detected in the provided PDFs.")
        return

    # Initialize counters
    link_count = 0
    obfuscation_count = 0
    ip_count = 0
    url_count = 0
    action_count = 0

    # Iterate over findings to count each type
    for file_path, file_findings in findings.items():
        for finding in file_findings:
            if 'Link text:' in finding:
                link_count += 1
            elif 'Potential font obfuscation detected' in finding:
                obfuscation_count += 1
            elif 'Detected IP Address:' in finding:
                ip_count += 1
            elif 'Detected URL:' in finding:
                url_count += 1
            elif 'Detected action' in finding:
                action_count += 1

    # Print summary
    print("\nSummary of Findings:")
    print(f"Total Links Found: {link_count}")
    print(f"Total Font Obfuscations Detected: {obfuscation_count}")
    print(f"Total IP Addresses Found: {ip_count}")
    print(f"Total URLs Found: {url_count}")
    print(f"Total Actions Detected: {action_count}")

    # Print details
    for file_path, file_findings in findings.items():
        print(f"\nFindings for {file_path}:\n")
        for finding in file_findings:
            print(finding)


def save_findings_to_file(findings, md5_checksums):
    desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
    save_path_input = input(f"Click Enter to save file as: {os.path.join(desktop_path, 'results.txt')}) or spell dir/file/name: ").strip()
    save_path = save_path_input if save_path_input else os.path.join(desktop_path, 'results.txt')

    with open(save_path, 'w') as file:
        for file_path, file_findings in findings.items():
            file.write(f"Findings for {file_path}:\n")
            for finding in file_findings:
                file.write(f"{finding}\n")
            file.write("\n")
            if file_path in md5_checksums:
                file.write(f"MD5 Checksum for {file_path}: {md5_checksums[file_path]}\n\n")
    print(f"\nResults saved to {save_path}")

def main():
    path = get_file_or_directory_path()
    print(f"Analyzing: {path}")

    while not os.path.exists(path):
        print("\nInvalid path. Please provide a valid file or directory path.")
        path = get_file_or_directory_path()

    findings, md5_checksums = analyze_path(path)
    handle_results(findings)

    # Summary calculation (same logic as in handle_results)
    link_count = sum('Link text:' in finding for file_findings in findings.values() for finding in file_findings)
    obfuscation_count = sum('Potential font obfuscation detected' in finding for file_findings in findings.values() for finding in file_findings)
    ip_count = sum('Detected IP Address:' in finding for file_findings in findings.values() for finding in file_findings)
    url_count = sum('Detected URL:' in finding for file_findings in findings.values() for finding in file_findings)
    action_count = sum('Detected action' in finding for file_findings in findings.values() for finding in file_findings)

    # Print summary
    print("\n=============== Summary of Findings ===============\n")
    print(f"Total Links Found: {link_count}")
    print(f"Total Font Obfuscations Detected: {obfuscation_count}")
    print(f"Total IP Addresses Found: {ip_count}")
    print(f"Total URLs Found: {url_count}")
    print(f"Total Actions Detected: {action_count}")
    print('\n===============SUMMARY END===============\n')

    save_choice = input("\nDo you want to save these findings and MD5 checksums to a .txt file? (y/n): ").strip().lower()
    if save_choice == 'y':
        save_findings_to_file(findings, md5_checksums)
    else:
        print('=========== Vale! ===========')

if __name__ == "__main__":
    main()

    
