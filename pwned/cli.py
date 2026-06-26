"""CLI interface for pwned - HaveIBeenPwned checker."""

import argparse
import json
import os
import sys

from pwned.hibp import check_email, check_password, check_pastes, HibpError

# ANSI colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
 ____  _   _ ____  _____ 
|  _ \\| \\ | |  _ \\| ____|
| |_) |  \\| | | | |  _|  
|  __/| |\\  | |_| | |___ 
|_|   |_| \\_|____/|_____|
{RESET}"""

EPILOG = """
examples:
  pwned email user@example.com
  pwned email user@example.com --api-key YOUR_KEY --json
  pwned password MySecretPass123
  pwned paste user@example.com
"""


def print_breaches(breaches, as_json=False):
    if as_json:
        print(json.dumps(breaches, indent=2))
        return
    print(f"\n{RED}{BOLD}[!] Found {len(breaches)} breach(es):{RESET}\n")
    for b in breaches:
        print(f"  {BOLD}{b.get('Title', 'Unknown')}{RESET}")
        print(f"    Domain:      {b.get('Domain', 'N/A')}")
        print(f"    Breach Date: {b.get('BreachDate', 'N/A')}")
        print(f"    Pwn Count:   {b.get('PwnCount', 0):,}")
        print(f"    Data Classes: {', '.join(b.get('DataClasses', []))}")
        print()


def print_pastes(pastes, as_json=False):
    if as_json:
        print(json.dumps(pastes, indent=2))
        return
    print(f"\n{RED}{BOLD}[!] Found {len(pastes)} paste(s):{RESET}\n")
    for p in pastes:
        print(f"  {BOLD}{p.get('Source', 'Unknown')}{RESET}")
        print(f"    Title:  {p.get('Title', 'N/A')}")
        print(f"    Date:   {p.get('Date', 'N/A')}")
        print(f"    Emails: {p.get('EmailCount', 0)}")
        print()


def cmd_email(args):
    api_key = args.api_key or os.environ.get("HIBP_API_KEY")
    if not api_key:
        print(f"{YELLOW}[!] API key required. Use --api-key or set HIBP_API_KEY env var.{RESET}")
        print(f"    Get a free key at: https://haveibeenpwned.com/API/Key")
        sys.exit(1)
    try:
        breaches = check_email(args.address, api_key)
        if breaches:
            print_breaches(breaches, args.json)
            sys.exit(1)
        else:
            if args.json:
                print(json.dumps([]))
            else:
                print(f"{GREEN}[✓] Good news! No breaches found for {args.address}{RESET}")
    except HibpError as e:
        print(f"{RED}[✗] Error: {e}{RESET}")
        sys.exit(1)


def cmd_password(args):
    try:
        count = check_password(args.text)
        if count:
            if args.json:
                print(json.dumps({"pwned": True, "count": count}))
            else:
                print(f"{RED}{BOLD}[!] PWNED!{RESET}")
                print(f"{RED}    This password has appeared {count:,} times in data breaches.{RESET}")
                print(f"{YELLOW}    Change it immediately!{RESET}")
            sys.exit(1)
        else:
            if args.json:
                print(json.dumps({"pwned": False, "count": 0}))
            else:
                print(f"{GREEN}[✓] Good news! This password hasn't been found in any known breaches.{RESET}")
    except HibpError as e:
        print(f"{RED}[✗] Error: {e}{RESET}")
        sys.exit(1)


def cmd_paste(args):
    api_key = args.api_key or os.environ.get("HIBP_API_KEY")
    if not api_key:
        print(f"{YELLOW}[!] API key required. Use --api-key or set HIBP_API_KEY env var.{RESET}")
        print(f"    Get a free key at: https://haveibeenpwned.com/API/Key")
        sys.exit(1)
    try:
        pastes = check_pastes(args.email, api_key)
        if pastes:
            print_pastes(pastes, args.json)
            sys.exit(1)
        else:
            if args.json:
                print(json.dumps([]))
            else:
                print(f"{GREEN}[✓] Good news! No pastes found for {args.email}{RESET}")
    except HibpError as e:
        print(f"{RED}[✗] Error: {e}{RESET}")
        sys.exit(1)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        prog="pwned",
        description="Check if your emails or passwords have been exposed in data breaches.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--api-key", help="HaveIBeenPwned API key (or set HIBP_API_KEY)")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    sub = parser.add_subparsers(dest="command")

    email_p = sub.add_parser("email", help="Check if an email has been in breaches")
    email_p.add_argument("address", help="Email address to check")
    email_p.add_argument("--json", action="store_true", help="Output as JSON")
    email_p.add_argument("--api-key", help="HaveIBeenPwned API key (or set HIBP_API_KEY)")

    pw_p = sub.add_parser("password", help="Check if a password has been pwned")
    pw_p.add_argument("text", help="Password to check")
    pw_p.add_argument("--json", action="store_true", help="Output as JSON")

    paste_p = sub.add_parser("paste", help="Check if email appears in pastes")
    paste_p.add_argument("email", help="Email address to check")
    paste_p.add_argument("--json", action="store_true", help="Output as JSON")
    paste_p.add_argument("--api-key", help="HaveIBeenPwned API key (or set HIBP_API_KEY)")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    {"email": cmd_email, "password": cmd_password, "paste": cmd_paste}[args.command](args)
