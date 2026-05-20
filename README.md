
# 🔐 WWSAF — Windows Web Security & Audit Framework

A comprehensive, beginner-to-intermediate security auditing tool built in Python. Performs HTTP reconnaissance, port scanning, vulnerability detection, and generates professional HTML audit reports.

---

## 📸 Screenshots

### Terminal Output
![Terminal scan output showing recon results, open ports and vulnerability findings]

### HTML Report
![Browser report showing severity cards, recon table and vulnerability findings]

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Recon Engine** | HTTP fingerprinting, server detection, security header audit |
| 🔌 **Port Scanner** | Concurrent scan of 22 common ports with risk classification |
| 🛡️ **Vulnerability Checker** | Sensitive path probing, info disclosure, HTTPS enforcement check |
| 📄 **HTML Report** | Professional dark-themed report with severity scoring |

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/jitishakarnam/wwsaf.git
cd wwsaf
```

### 2. Create virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

---

## 🖥️ Usage

### Basic recon scan
```bash
python main.py http://example.com
```

### Recon + port scan
```bash
python main.py http://example.com --ports
```

### Recon + vulnerability check
```bash
python main.py http://example.com --vuln
```

### Full scan with HTML report
```bash
python main.py http://example.com --ports --vuln --report
```

Report is saved to `reports/report_YYYYMMDD_HHMMSS.html`

---

## 📁 Project Structure

```
wwsaf/
├── src/
│   ├── modules/
│   │   ├── recon.py          # HTTP fingerprinting & header audit
│   │   ├── port_scanner.py   # Concurrent port scanner
│   │   ├── vuln_checker.py   # Vulnerability detection
│   │   └── reporter.py       # HTML report generator
│   └── templates/
│       └── report.html       # Jinja2 report template
├── reports/                  # Generated reports (gitignored)
├── main.py                   # CLI entry point
├── requirements.txt
└── README.md
```

---

## 🔍 What Gets Checked

### Recon
- HTTP status code & response time
- Server & technology fingerprinting
- Security headers audit (HSTS, CSP, X-Frame-Options etc.)

### Port Scanner
Scans 22 common ports including:

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | High |
| 22 | SSH | Medium |
| 80 | HTTP | Low |
| 443 | HTTPS | Low |
| 445 | SMB | High |
| 3389 | RDP | High |
| 3306 | MySQL | Medium |

### Vulnerability Checks
- HTTP → HTTPS redirect enforcement
- Sensitive path exposure (`/.env`, `/.git`, `/admin`, `/backup.zip` and more)
- Information disclosure via response headers
- Missing `security.txt`

---

## 📊 Sample Report Output

```
Overall Risk: HIGH

High Severity:   1
Medium Severity: 1
Low Severity:    1
Informational:   0
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized security testing only**.
Do not use against systems you do not own or have explicit permission to test.
The author is not responsible for any misuse.

---

## 🛠️ Built With

- [Python 3.11](https://python.org)
- [httpx](https://www.python-httpx.org/) — Async HTTP client
- [Typer](https://typer.tiangolo.com/) — CLI framework
- [Rich](https://rich.readthedocs.io/) — Terminal formatting
- [Jinja2](https://jinja.palletsprojects.com/) — HTML templating

---

## 👩‍💻 Author

**Jitisha Karnani** — M.Tech Student  
GitHub: [@jitishakarnam](https://github.com/jitishakarnani)

---

## 📜 License

MIT License — free to use, modify and distribute.
