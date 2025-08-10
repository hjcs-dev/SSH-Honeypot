# SSH Honeypot

A simple Python SSH honeypot that captures authentication attempts and sends detailed connection info to console or a Discord webhook.

## Features

- Captures username and password from SSH login attempts.
- Logs client IP, SSH client version, and connection algorithms.
- Displays all info with colored output.
- Option to send captured data to a Discord webhook.
- Fake successful authentication to lure attackers.
- Simple menu to configure port, webhook URL, and custom message.

## Requirements

- Python 3.8+
- `paramiko`
- `colorama`
- `requests`
- `pystyle`

## Installation

```bash
pip install paramiko colorama requests pystyle
```

```bash
python Main.py
```

Disclaimer

This tool is for educational and authorized testing purposes only.
