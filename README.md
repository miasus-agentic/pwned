# pwned

```
 ____  _   _ ____  _____ 
|  _ \| \ | |  _ \| ____|
| |_) | \| | | | |  _|  
|  __/| |\  | |_| | |___ 
|_|   |_| \_|____/|_____|
```

A Python CLI tool to check if your email addresses or passwords have been exposed in data breaches, powered by the [HaveIBeenPwned](https://haveibeenpwned.com/) API.

**100% stdlib — no external dependencies.**

## Installation

```bash
# Install directly
pip install -e .

# Or just run it
python -m pwned
```

## Usage

### Check an email for breaches
```bash
pwned email user@example.com --api-key YOUR_API_KEY
```

### Check a password (safe — uses k-anonymity)
```bash
pwned password MySecretPass123
```

### Check pastes
```bash
pwned paste user@example.com --api-key YOUR_API_KEY
```

### JSON output
```bash
pwned email user@example.com --api-key YOUR_KEY --json
pwned password MySecretPass123 --json
```

### API key via environment variable
```bash
export HIBP_API_KEY=your_key_here
pwned email user@example.com
```

## How the Password Check Works

The password checker uses **k-anonymity** — your password is **never sent to the server**:

1. Your password is hashed with SHA-1 locally
2. Only the **first 5 characters** of the hash are sent to the API
3. The API returns all hash suffixes matching that prefix
4. Your client checks locally if your full hash appears in the results

This means the server never learns your password, and your privacy is preserved.

## API Key

The `email` and `paste` subcommands require an API key from HaveIBeenPwned:

- Get a **free** key at: https://haveibeenpwned.com/API/Key
- Pass it via `--api-key` flag or set the `HIBP_API_KEY` environment variable

The `password` subcommand **does not** require an API key.

## Requirements

- Python 3.7+
- No external dependencies

## License

MIT License — see [LICENSE](LICENSE) for details.
