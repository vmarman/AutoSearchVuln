# AutoSearchVuln

AutoSearchVuln is an automated vulnerability detection tool for services discovered by Nmap. It enriches results using:
- Searchsploit
- Exploit-DB web scraping
- ChatGPT (OpenAI)
- Auxiliary tools like DIRB, nuclei, SSLyze, and ssh-audit

It includes HTML report export and an inventory of recommended commands for further manual analysis.

---

## Installation

Run the setup script to create a virtual environment and install dependencies:

```bash
chmod +x script.sh
./script.sh
```

---

## Requirements

- Python 3.10+
- System tools: nmap, searchsploit, dirb, msfconsole, sslyze, nuclei, ssh-audit
- The `OPENAI_API_KEY` environment variable must be set (you can edit it in `script.sh`)

---

## Features

1. Detects open services using nmap.
2. Optionally filters by type: `--ssl`, `--dirb`, `--ssh`, `--nuclei`, etc.
3. For each detected service:
   - Extracts version information using Metasploit if possible.
   - Searches for public exploits using searchsploit, Exploit-DB, and GPT-4o.
   - Classifies vulnerabilities into: RCE, Critical (DoS/infoleak), and Warnings.
   - Displays a clean, deduplicated report in the terminal.
4. Exports findings in HTML format if `--html` is used.

---

## Usage

```bash
python autosearchvuln.py -t <IP> [options]
```

### Examples

- Full analysis with HTML report:
  ```bash
  python autosearchvuln.py -t 192.168.1.147 --full --html
  ```

- SSL/TLS vulnerabilities only:
  ```bash
  python autosearchvuln.py -t 192.168.1.147 --ssl
  ```

- DIRB mode (web directory fuzzing):
  ```bash
  python autosearchvuln.py -t 192.168.1.147 --dirb --html
  ```

---

## Dependencies

Installed automatically:
- rich
- beautifulsoup4
- openai
- requests, urllib3 (latest versions)
- zapcli (installed without dependencies to avoid version pinning)

The system must also have external tools such as nmap, metasploit, nuclei, etc.

---

## License

This project is intended for educational and authorized auditing purposes only. Use it responsibly.
