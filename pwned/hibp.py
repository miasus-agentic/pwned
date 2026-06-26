"""HaveIBeenPwned API client using only stdlib."""

import hashlib
import json
import urllib.request
import urllib.error

USER_AGENT = "pwned-cli"
BASE_URL = "https://haveibeenpwned.com/api/v3"
PASSWORD_URL = "https://api.pwnedpasswords.com/range"


class HibpError(Exception):
    pass


def _request(url, api_key=None):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if api_key:
        headers["hibp-api-key"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise HibpError("Unauthorized: invalid or missing API key.")
        if e.code == 403:
            raise HibpError("Forbidden: API key is invalid or inactive.")
        if e.code == 404:
            return []  # Not found = not pwned
        if e.code == 429:
            raise HibpError("Rate limited. Please wait and try again.")
        raise HibpError(f"HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise HibpError(f"Network error: {e.reason}")


def check_email(email, api_key):
    """Check if an email appears in known breaches."""
    import urllib.parse
    url = f"{BASE_URL}/breachedaccount/{urllib.parse.quote(email)}"
    return _request(url, api_key)


def check_password(password):
    """Check if a password has been pwned using k-anonymity."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"{PASSWORD_URL}/{prefix}"
    headers = {"User-Agent": USER_AGENT}
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            lines = resp.read().decode().splitlines()
    except urllib.error.URLError as e:
        raise HibpError(f"Network error: {e.reason}")

    for line in lines:
        parts = line.split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return int(parts[1])
    return 0


def check_pastes(email, api_key):
    """Check if an email appears in known paste dumps."""
    import urllib.parse
    url = f"{BASE_URL}/pasteaccount/{urllib.parse.quote(email)}"
    return _request(url, api_key)
