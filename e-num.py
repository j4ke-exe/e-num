import os
import sys
import glob
import signal
import readline
import requests
from urllib.parse import urlparse


# Terminal colors
GREEN = "\033[92m"
ORANGE = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


# Handle exit
def signal_handler(signum, frame):
    print(f"\n{ORANGE}[!]{RESET} Exiting.")
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# Autotab
def autotab(text, state):
    matches = glob.glob(os.path.expanduser(text) + "*")
    matches = [m + os.sep if os.path.isdir(m) else m for m in matches]
    return matches[state] if state < len(matches) else None


def enable_autotab():
    readline.set_completer_delims(" \t\n;")
    readline.parse_and_bind("tab: complete")
    readline.set_completer(autotab)


def get_headers(url):
    try:
        with requests.Session() as session:
            r = session.head(url, timeout=5, allow_redirects=True) or session.get(url, timeout=5, allow_redirects=True)
            r.raise_for_status()
            parsed = urlparse(r.url)
            headers = {
                "User-Agent": r.request.headers.get("User-Agent", "Mozilla/5.0"),
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": r.url,
                "Origin": f"{parsed.scheme}://{parsed.netloc}",
                "Connection": "close",
            }
            if r.cookies:
                headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in r.cookies.items())
            return headers
         
    except requests.RequestException as e:
        print(f"{RED}[!] Failed to fetch headers: {e}{RESET}")
        return {
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
        }


def check_email(email, url, headers):
    try:
        r = requests.post(url, headers=headers, timeout=5, data={
           "username": email,
           "password": "password123",
           "function": "login"
        })
        return r.json() if r.content else {"status": "empty"}
     
    except requests.JSONDecodeError:
        return {
        "status": "non_json",
        "message": r.text
    }
     
    except requests.RequestException as e:
        return {
        "status": "error",
        "message": str(e)
    }


def enumerate_emails(file_path, url, error_message):
    valid_emails = []
    headers = get_headers(url)

    try:
        with open(os.path.expanduser(file_path), "r") as file:
            emails = [line.strip() for line in file if line.strip() and "@" in line]
            
    except Exception as e:
        print(f"{RED}[!] Could not read file: {e}{RESET}")
        return valid_emails

    total = len(emails)
    for index, email in enumerate(emails, 1):
        print("\033c", end="")
        for valid_email in valid_emails:
            print(f"{GREEN}[+]{RESET} VALID EMAIL {ORANGE}=>{RESET} [{GREEN}{valid_email}{RESET}]")
        print(f"\n{GREEN}[{RESET} Scanning: {GREEN}{index}{RESET}/{total} {GREEN}]{RESET}")
        
        sys.stdout.flush()

        res = check_email(email, url, headers)
        if (res.get("status") != "error" or error_message.lower() not in res.get("message", "").lower()):
            valid_emails.append(email)

    print("\033c", end="")
    for valid_email in valid_emails:
        print(f"{GREEN}[+]{RESET} VALID: {valid_email}")
    return valid_emails


def main():
    print(
    f"""{GREEN}

      ██████             ████████   █████ ████ █████████████  
     ███░░███ ██████████░░███░░███ ░░███ ░███ ░░███░░███░░███ 
    ░███████ ░░░░░░░░░░  ░███ ░███  ░███ ░███  ░███ ░███ ░███ 
    ░███░░░              ░███ ░███  ░███ ░███  ░███ ░███ ░███ 
    ░░██████             ████ █████ ░░████████ █████░███ █████
     ░░░░░░             ░░░░ ░░░░░   ░░░░░░░░ ░░░░░ ░░░ ░░░░░ v1.0

                Email Enumeration{RESET} | {ORANGE}github.com/j4ke-exe{RESET}

    """)

    enable_autotab()

    email_file = input(f"{ORANGE}[?]{RESET} Email wordlist path: ").strip()
    url = input(f"{ORANGE}[?]{RESET} Target login URL (https://example.com/login): ").strip()
    error_msg = (input(f"{ORANGE}[?]{RESET} Invalid email error response: ").strip() or "")
    print()

    if not url.startswith(("http://", "https://")):
        print(f"{RED}[!] Invalid URL. Use http:// or https://{RESET}")
        sys.exit(1)

    enumerate_emails(email_file, url, error_msg)


if __name__ == "__main__":
    main()
