import requests
import re
import concurrent.futures
import logging
import json
import argparse
import urllib3
import time
import signal
import sys


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def configure_logging(level):
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {level}')
    logging.basicConfig(level=numeric_level, format='%(levelname)s: %(message)s')


def signal_handler(sig, frame):
    print("\n[INFO] Exiting program gracefully...")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


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

def load_urls_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
        logging.info(f"Loaded {len(urls)} URLs from {file_path}.")
        return urls
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return []

# Sensitive patterns for secrets and comments
patterns = [
    (re.compile(r'\bApiKey\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{6,})(?:"|\'|)', re.IGNORECASE), "API Key"),
    (re.compile(r'\bSECRET_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "Django Secret Key"),
    (re.compile(r'\bSLACK_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40,})(?:"|\'|)', re.IGNORECASE), "Slack Token"),
    (re.compile(r'\bMAPBOX_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{64})(?:"|\'|)', re.IGNORECASE), "Mapbox Access Token"),
    (re.compile(r'\bAWS_ACCESS_KEY_ID\s*:\s*(?:"|\'|)([A-Z0-9]{20})(?:"|\'|)', re.IGNORECASE), "AWS Access Key ID"),
    (re.compile(r'\bAWS_SECRET_ACCESS_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9/+=]{40})(?:"|\'|)', re.IGNORECASE), "AWS Secret Access Key"),
    (re.compile(r'\bGOOGLE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{39})(?:"|\'|)', re.IGNORECASE), "Google API Key"),
    (re.compile(r'\bBearer\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Bearer Token"),
    (re.compile(r'\bpassword\s*:\s*(?:"|\'|)([A-Za-z0-9-_!@#$%^&*]{8,})(?:"|\'|)', re.IGNORECASE), "Password"),
    (re.compile(r'\bclient_secret\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Client Secret"),
    (re.compile(r'\bauthorization\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Authorization Header"),
    (re.compile(r'\bPRIVATE_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_=\n]+)(?:"|\'|)', re.IGNORECASE), "Private Key"),
    (re.compile(r'\bANACONDA_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Anaconda Token"),
    (re.compile(r'\bANDROID_DOCS_DEPLOY_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Android Docs Deploy Token"),
    (re.compile(r'\bandroid_sdk_license\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Android SDK License"),
    (re.compile(r'\bANSIBLE_VAULT_PASSWORD\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{6,})(?:"|\'|)', re.IGNORECASE), "Ansible Vault Password"),
    (re.compile(r'\bAPI_KEY_MCM\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "API Key MCM"),
    (re.compile(r'\bAPI_KEY_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "API Key Secret"),
    (re.compile(r'\bAPP_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "App Token"),
    (re.compile(r'\bAPPLE_ID_PASSWORD\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{6,})(?:"|\'|)', re.IGNORECASE), "Apple ID Password"),
    (re.compile(r'\bSSH_PRIVATE_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_=\n]+)(?:"|\'|)', re.IGNORECASE), "SSH Private Key"),
    (re.compile(r'\bJWT_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "JWT Secret"),
    (re.compile(r'\bTOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Generic Token"),
    (re.compile(r'\bDB_PASSWORD\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{8,})(?:"|\'|)', re.IGNORECASE), "Database Password"),
    (re.compile(r'\bGITHUB_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "GitHub Token"),
    (re.compile(r'\bTWILIO_AUTH_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Twilio Auth Token"),
    (re.compile(r'\bSENDGRID_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "SendGrid API Key"),
    (re.compile(r'\bMAILGUN_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Mailgun API Key"),
    (re.compile(r'\bPUSHER_APP_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20})(?:"|\'|)', re.IGNORECASE), "Pusher App Key"),
    (re.compile(r'\bFACEBOOK_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "Facebook Secret Key"),
    (re.compile(r'\bFACEBOOK_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40,})(?:"|\'|)', re.IGNORECASE), "Facebook Access Token"),
    (re.compile(r'\bTWITTER_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Twitter API Key"),
    (re.compile(r'\bTWITTER_API_SECRET_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Twitter API Secret Key"),
    (re.compile(r'\bTWITTER_BEARER_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{60,})(?:"|\'|)', re.IGNORECASE), "Twitter Bearer Token"),
    (re.compile(r'\bGITLAB_PERSONAL_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "GitLab Personal Access Token"),
    (re.compile(r'\bPINTEREST_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Pinterest Access Token"),
    (re.compile(r'\bHEROKU_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Heroku API Key"),
    (re.compile(r'\bHEROKU_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Heroku Secret Key"),
    (re.compile(r'\bSTRIPE_SECRET_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "Stripe Secret Key"),
    (re.compile(r'\bSTRIPE_PUBLISHABLE_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Stripe Publishable Key"),
    (re.compile(r'\bSTRIPE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32,})(?:"|\'|)', re.IGNORECASE), "Stripe API Key"),
    (re.compile(r'\bSTRIPE_LIVE_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Stripe Live Key"),
    (re.compile(r'\bSENDGRID_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "SendGrid Secret Key"),
    (re.compile(r'\bTWILIO_ACCOUNT_SID\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{34})(?:"|\'|)', re.IGNORECASE), "Twilio Account SID"),
    (re.compile(r'\bNPM_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{36})(?:"|\'|)', re.IGNORECASE), "NPM Token"),
    (re.compile(r'\bSONARQUBE_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{36})(?:"|\'|)', re.IGNORECASE), "SonarQube Token"),
    (re.compile(r'\bDROPBOX_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40,})(?:"|\'|)', re.IGNORECASE), "Dropbox Access Token"),
    (re.compile(r'\bDOCKER_CONFIG\s*:\s*(?:"|\'|)([A-Za-z0-9-_=\n]+)(?:"|\'|)', re.IGNORECASE), "Docker Config"),
    (re.compile(r'\bFASTLY_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Fastly API Key"),
    (re.compile(r'\bFIREBASE_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Firebase API Key"),
    (re.compile(r'\bFIREBASE_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Firebase Secret"),
    (re.compile(r'\bGITLAB_PRIVATE_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "GitLab Private Token"),
    (re.compile(r'\bBITBUCKET_CLIENT_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "BitBucket Client Secret"),
    (re.compile(r'\bBITBUCKET_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "BitBucket Access Token"),
    (re.compile(r'\bREDDIT_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Reddit API Key"),
    (re.compile(r'\bREDDIT_SECRET_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "Reddit Secret Key"),
    (re.compile(r'\bSHOPIFY_API_KEY\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Shopify API Key"),
    (re.compile(r'\bSHOPIFY_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Shopify Secret Key"),
    (re.compile(r'\bSHOPIFY_ACCESS_TOKEN\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{32})(?:"|\'|)', re.IGNORECASE), "Shopify Access Token"),
    (re.compile(r'\bGITHUB_CLIENT_SECRET\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{40})(?:"|\'|)', re.IGNORECASE), "GitHub Client Secret"),
    (re.compile(r'\bGOOGLE_CLOUD_PROJECT\s*:\s*(?:"|\'|)([A-Za-z0-9-_]{20,})(?:"|\'|)', re.IGNORECASE), "Google Cloud Project ID"), 
    (re.compile(r'\b(?:aws_access_key_id|aws_secret_access_key|api_key|password|client_secret|bearer_token|private_key|github_token|twilio_auth_token|sendgrid_api_key|mailgun_api_key|pusher_app_key)\s*:\s*(?:"|\'|)([A-Za-z0-9-_+=]{20,})(?:"|\'|)', re.IGNORECASE), "Sensitive Info"),
]



def check_js_for_secrets_and_comments(url, retries=3):
    headers = {
        "User-Agent": "security-researcher"
    }
    attempts = 0
    while attempts < retries:
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            content = response.text
            results = []
            found_matches = set()
            for pattern, description in patterns:
                matches = pattern.findall(content)
                for match in matches:
                    if match not in found_matches:
                        found_matches.add(match)
                        results.append((url, match, description))
            return results
        except requests.RequestException as e:
            logging.error(f"Error accessing {url} (attempt {attempts + 1}/{retries}): {e}")
            attempts += 1
            if attempts < retries:
                time.sleep(2)  # Wait for 2 seconds before retrying
    return []


def log_results(results):
    with open('exposure_results.txt', 'a') as file:
        for url, match, description in results:
            file.write(f'Found an exposure: "{match}" ({description}) at URL "{url}" | Length: {len(match)}\n')


def save_results_as_json(results):
    formatted_results = [{'url': url, 'match': match, 'description': description, 'length': len(match)} for url, match, description in results]
    with open('exposure_results.json', 'w') as json_file:
        json.dump(formatted_results, json_file, indent=4)


def process_js_files(file_path, max_workers):
    try:
        urls = load_urls_from_file(file_path)
        if not urls:
            logging.warning("No URLs to process.")
            return

        all_results = []
        logging.info(f"Processing {len(urls)} URLs.")

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_url = {executor.submit(check_js_for_secrets_and_comments, url): url for url in urls}

            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    results = future.result()
                    if results:
                        all_results.extend(results)
                        logging.info(f"Found results at {url}.")
                except Exception as e:
                    logging.error(f"Error processing {url}: {e}")

        if all_results:
            log_results(all_results)
            save_results_as_json(all_results)
            logging.info(f"Analysis complete. Found {len(all_results)} exposures.")
        else:
            logging.info("No exposures found.")
    except KeyboardInterrupt:
        logging.warning("Process interrupted by user. Exiting...")


def main():
    parser = argparse.ArgumentParser(
        description="JS Exposures Finder - A tool to scan JavaScript files for sensitive information.",
        epilog="Example usage: python jsexposures.py --file js_endpoints.txt --max-workers 15 --log-level DEBUG"
    )
    parser.add_argument('--file', type=str, default='js_endpoints.txt', help='Path to the file containing JS URLs to scan (default: js_endpoints.txt)')
    parser.add_argument('--max-workers', type=int, default=10, help='Number of concurrent threads to use for scanning (default: 10)')
    parser.add_argument('--log-level', type=str, default='INFO', help='Set the logging level (default: INFO)')

    args = parser.parse_args()
    
    configure_logging(args.log_level)
    print_banner()
    process_js_files(args.file, args.max_workers)


if __name__ == "__main__":
    main()
              
