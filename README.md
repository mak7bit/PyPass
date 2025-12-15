# PyPass

PyPass is a free, open-source, Python-based password and hash analysis tool used for security auditing and authorized password assessments. It assists system administrators and security professionals in identifying weak credentials through controlled wordlist testing, supporting proactive defense against real-world attacks.

Designed for authorized security testing, research, and educational purposes, PyPass provides a clean GUI, efficient wordlist searching, hash verification, and support for multiple hash algorithms.

PyPass is not a password cracker that generates guesses and is intended strictly for controlled and authorized environments.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)
![Security Tool](https://img.shields.io/badge/Category-Security-blueviolet)


---

## Features

- Modern PyQt6 GUI
- Fast plaintext search (contains, starts with, ends with, regex)
- Hash verification for:
  - MD5, SHA-1, SHA-256, SHA-384, SHA-512
  - SHA3-256, SHA3-512
  - NTLM
  - bcrypt
  - argon2
  - scrypt
  - pbkdf2
- History tracking
- Wordlist statistics
- Optional slow-KDF verification limits
- Cross-platform support:
  - Windows: standalone `.exe`
  - Linux: run directly with `python3 pypass.py`

---

## Installation (Linux)

Clone the repository:

```
git clone https://github.com/mak7bit/PyPass.git
cd PyPass
```

Create a virtual environment:

```
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

Run PyPass:

```
python3 pypass.py
```

or:

```
chmod +x pypass.py
./pypass.py
```

---

## Installation (Windows)

A prebuilt standalone executable is provided via [GitHub Releases.](https://github.com/mak7bit/PyPass/releases/)

---

## Disclaimer

This tool is intended for educational use, security research, and authorized penetration testing only.

Unauthorized password or hash cracking is illegal and strictly prohibited.  
Users are responsible for ensuring their use of this tool complies with applicable laws and ethical guidelines.

