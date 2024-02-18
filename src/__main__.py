# zipscan
# Scans a zip and generates a report of the files inside and any findings
# Github: https://www.github.com/lewisevans2007/ZipScan
# Licence: GNU General Public License v3.0
# By: Lewis Evans

import sys
import zipfile
import os
import magic
import hashlib
import shutil

def unzip_file(zip_file):
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            zip_ref.extractall('zipscan_temp')
        return True
    except:
        return False

def add_to_findings(file_path, message):
    global file_findings
    if len(file_findings) > 0:
        found = False
        for i in range(len(file_findings)):
            if file_findings[i][0] == file_path:
                file_findings[i].append(message)
                found = True
                break
        if not found:
            file_findings.append([file_path, message])
    else:
        file_findings.append([file_path, message])
    
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: zipscan.py <zipfile>")
        sys.exit(1)
    zip_file = sys.argv[1]
    if not os.path.exists(zip_file):
        print("Error: Zip file does not exist.")
        sys.exit(1)
    if not unzip_file(zip_file):
        print("Error: Failed to unzip file. Remove the password or check if the file is corrupted.")
        sys.exit(1)
    file_info = []
    file_findings = []
    for root, dirs, files in os.walk('zipscan_temp'):
        for file in files:
            file_path = os.path.join(root, file)
            mime = magic.Magic(mime=True)
            mime_type = mime.from_file(file_path)
            mime_long = magic.Magic(mime=False).from_file(file_path)
            size = os.path.getsize(file_path)
            sha256_hash = hashlib.sha256()
            with open(file_path,"rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    sha256_hash.update(byte_block)
            md5_hash = hashlib.md5()
            with open(file_path,"rb") as f:
                for byte_block in iter(lambda: f.read(4096),b""):
                    md5_hash.update(byte_block)
            file_info.append([file_path, mime_type, mime_long, sha256_hash.hexdigest(), md5_hash.hexdigest(), size])
            if size > 1000000000:
                add_to_findings(file_path, "File is massive over 1GB. Size: " + str(size) + " bytes.")
            if size < 100:
                add_to_findings(file_path, "File is tiny under 100 bytes. Size: " + str(size) + " bytes.")
            if "executable" in mime_type:
                add_to_findings(file_path, "File is an executable.")
            if "script" in mime_type:
                add_to_findings(file_path, "File is a script.")
                
    f = open("report.md", "w")
    f.write("# ZipScan Report\n\n")
    f.write("Zip file: `" + zip_file + "`\n\n")
    f.write("Number of files: `" + str(len(file_info)) + "`\n\n")

    f.write("## Files:\n\n")
    for file in file_info:
        mime_long_array = file[2].split(",")
        f.write("### `" + file[0] + "`\n")
        f.write("- Mime type: `" + file[1] + "`\n")
        f.write("- Mime long: \n")
        for mime in mime_long_array:
            f.write("\t- `" + mime + "`\n")
        f.write("- SHA256: `" + file[3] + "`\n")
        f.write("- MD5: `" + file[4] + "`\n")
        f.write("- Size: `" + str(file[5]) + "`\n")
        f.write("\n")

    f.write("## Findings:\n\n")
    if len(file_findings) == 0:
        f.write("No findings.")
    else:
        for file in file_findings:
            f.write("### `" + file[0] + "`\n")
            for i in range(1, len(file)):
                f.write("- " + file[i] + "\n")
            f.write("\n")
    f.close()
    print("Report generated in report.md")
    shutil.rmtree('zipscan_temp')