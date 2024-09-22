import requests
import re
import concurrent.futures

# Tool banner
def print_banner():
    banner = r"""

 ▄▄▄██▀▀▀  ██████ ▓█████ ▒██   ██▒ ██▓███   ▒█████    ██████  █    ██  ██▀███  ▓█████   ██████    
   ▒██   ▒██    ▒ ▓█   ▀ ▒▒ █ █ ▒░▓██░  ██▒▒██▒  ██▒▒██    ▒  ██  ▓██▒▓██ ▒ ██▒▓█   ▀ ▒██    ▒    
   ░██   ░ ▓██▄   ▒███   ░░  █   ░▓██░ ██▓▒▒██░  ██▒░ ▓██▄   ▓██  ▒██░▓██ ░▄█ ▒▒███   ░ ▓██▄      
▓██▄██▓    ▒   ██▒▒▓█  ▄  ░ █ █ ▒ ▒██▄█▓▒ ▒▒██   ██░  ▒   ██▒▓▓█  ░██░▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒   
 ▓███▒   ▒██████▒▒░▒████▒▒██▒ ▒██▒▒██▒ ░  ░░ ████▓▒░▒██████▒▒▒▒█████▓ ░██▓ ▒██▒░▒████▒▒██████▒▒   
 ▒▓▒▒░   ▒ ▒▓▒ ▒ ░░░ ▒░ ░▒▒ ░ ░▓ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░   
 ▒ ░▒░   ░ ░▒  ░ ░ ░ ░  ░░░   ░▒ ░░▒ ░       ░ ▒ ▒░ ░ ░▒  ░ ░░░▒░ ░ ░   ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░   
 ░ ░ ░   ░  ░  ░     ░    ░    ░  ░░       ░ ░ ░ ▒  ░  ░  ░   ░░░ ░ ░   ░░   ░    ░   ░  ░  ░     
 ░   ░         ░     ░  ░ ░    ░               ░ ░        ░     ░        ░        ░  ░      ░     
                   jsexposures - Search for exposures in JS files
                   Author: hidalg0d
    """
    print(banner)

# Load URLs from a text file
def load_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]
    return urls

# Precompiled patterns to search for sensitive information exposures
patterns = [
    (re.compile(r'\bAPI_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "API Key"),
    (re.compile(r'\bAWS_ACCESS_KEY_ID\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r'\bAWS_SECRET_ACCESS_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{40,})(?:\'|")?', re.IGNORECASE), "AWS Secret Access Key"),
    (re.compile(r'\bGOOGLE_API_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Google API Key"),
    (re.compile(r'\bBearer\s+([A-Za-z0-9-_]{20,})', re.IGNORECASE), "Bearer Token"),
    (re.compile(r'\bpassword\s*=\s*(?:\'|")?([A-Za-z0-9-_]{6,})(?:\'|")?', re.IGNORECASE), "Password"),
    (re.compile(r'\bclient_secret\s*=\s*(?:\'|")?([A-Za-z0-9-_]{6,})(?:\'|")?', re.IGNORECASE), "Client Secret"),
    (re.compile(r'\bauthorization\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Authorization Header"),
    (re.compile(r'\bPRIVATE_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{30,})(?:\'|")?', re.IGNORECASE), "Private Key"),
    (re.compile(r'\bANACONDA_TOKEN\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Anaconda Token"),
    (re.compile(r'\bANDROID_DOCS_DEPLOY_TOKEN\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Android Docs Deploy Token"),
    (re.compile(r'\bandroid_sdk_license\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Android SDK License"),
    (re.compile(r'\bANSIBLE_VAULT_PASSWORD\s*=\s*(?:\'|")?([A-Za-z0-9-_]{6,})(?:\'|")?', re.IGNORECASE), "Ansible Vault Password"),
    (re.compile(r'\bAPI_KEY_MCM\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "API Key MCM"),
    (re.compile(r'\bAPI_KEY_SECRET\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "API Key Secret"),
    (re.compile(r'\bAPP_TOKEN\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "App Token"),
    (re.compile(r'\bAPPLE_ID_PASSWORD\s*=\s*(?:\'|")?([A-Za-z0-9-_]{6,})(?:\'|")?', re.IGNORECASE), "Apple ID Password"),
    (re.compile(r'\bSSH_PRIVATE_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_=\n]+)(?:\'|")?', re.IGNORECASE), "SSH Private Key"),
    (re.compile(r'\bJWT_SECRET\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "JWT Secret"),
    (re.compile(r'\bTOKEN\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Generic Token"),
    (re.compile(r'\bDB_PASSWORD\s*=\s*(?:\'|")?([A-Za-z0-9-_]{8,})(?:\'|")?', re.IGNORECASE), "Database Password"),
    (re.compile(r'\bGITHUB_TOKEN\s*=\s*(?:\'|")?([A-Za-z0-9-_]{40})(?:\'|")?', re.IGNORECASE), "GitHub Token"),
    (re.compile(r'\bTWILIO_AUTH_TOKEN\s*=\s*(?:\'|")?([A-Za-z0-9-_]{32})(?:\'|")?', re.IGNORECASE), "Twilio Auth Token"),
    (re.compile(r'\bSENDGRID_API_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "SendGrid API Key"),
    (re.compile(r'\bMAILGUN_API_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20,})(?:\'|")?', re.IGNORECASE), "Mailgun API Key"),
    (re.compile(r'\bPUSHER_APP_KEY\s*=\s*(?:\'|")?([A-Za-z0-9-_]{20})(?:\'|")?', re.IGNORECASE), "Pusher App Key"),
    # New patterns
    (re.compile(r'\b(?:aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|\.env|ssh key|\.git|access key|secret token|oauth_token|oauth_token_secret|smtp)\s*=\s*(?:\'|")?([A-Za-z0-9-_+=]{6,})(?:\'|")?', re.IGNORECASE), "Sensitive Info"),
]

# Function to download the .js file and search for matches
def check_js_for_secrets(url):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            content = response.text
            results = []
            found_matches = set()  # Use a set to avoid duplicates
            for pattern, description in patterns:
                matches = pattern.findall(content)
                for match in matches:
                    if match not in found_matches:  # Only log if not found before
                        found_matches.add(match)
                        results.append((url, match, description))
            return results
    except requests.RequestException as e:
        print(f"Error accessing {url}: {e}")
    return []

# Function to log results to a file
def log_results(results):
    with open('exposure_results.txt', 'a') as file:
        for url, match, description in results:
            file.write(f'Found an exposure: "{match}" ({description}) at URL "{url}"\n')

# Main function to process URLs
def process_js_files():
    urls = load_urls_from_file('js_endpoints.txt')
    all_results = []
    print(f"Processing {len(urls)} URLs.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(check_js_for_secrets, url): url for url in urls}
        
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            results = future.result()
            if results:
                all_results.extend(results)
                print(f"Found results at {url}.")

    log_results(all_results)  # Save all results at the end
    print(f"Analysis complete. Found {len(all_results)} exposures.")

# Start the analysis
if __name__ == "__main__":
    print_banner()
    process_js_files()
