import os

# Define the directory to scan
directory_to_scan = "Desktop"

def scan_files(directory):
    # List to hold the paths of detected malicious files
    detected_files = []
    
    # Walk through all the directories and files in the specified directory
    for root, dirs, files in os.walk(directory):
        for file in files:
            # Check if the file has a .txt extension
            if file.endswith('.txt') or file.endswith('.MOV'):
                # Construct the file path
                file_path = os.path.join(root, file)
                print(f"Malicious file detected: {file_path}")
                detected_files.append(file_path)
            else:
                try:
                    # This block is for additional actions, if any, for non-txt files
                    pass
                except Exception as e:
                    # Handle exceptions (e.g., file access permissions)
                    print(f"Error scanning file {file_path}: {e}")
                
    return detected_files

# Perform the scan
malicious_files = scan_files(directory_to_scan)

if malicious_files:
    print("Scan completed. Malicious files detected.")
else:
    print("Scan completed. No malicious files detected.")

