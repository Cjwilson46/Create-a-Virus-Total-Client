import os
import hashlib
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Obtain an API Key from Virus Total
API_KEY = '8230124b78ae549fc2bbb307ce98b5fff200bd27a2d728bff62d07641ca20e97'

def get_file_md5(file_path):
    """Calculate MD5 hash for a file."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def main():
    target_dir = r'C:\Users\Administrator\Downloads\scanFiles'

    # Setup VirusTotal API
    vt = VirusTotalPublicApi(API_KEY)
    results = {}

    # Process each file in the target directory
    for filename in os.listdir(target_dir):
        file_path = os.path.join(target_dir, filename)
        file_hash = get_file_md5(file_path)
        response = vt.get_file_report(file_hash)
        results[filename] = response

    # Print results to the terminal
    print(json.dumps(results, indent=4, sort_keys=False))

if __name__ == "__main__":
    main()
