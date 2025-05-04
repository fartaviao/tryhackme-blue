<img src="https://raw.githubusercontent.com/fartaviao/fartaviao/refs/heads/main/Banner%20Fausto.jpg" alt="Banner Fausto Artavia Ocampo">

# Blue - TryHackMe Room

## 📘 Overview

This repository contains a detailed walkthrough for the **[Blue](https://tryhackme.com/room/blue)** room on TryHackMe. It covers the complete penetration testing process, including:

- VPN configuration
- Network scanning and SMB enumeration
- Exploitation using EternalBlue (MS17-010)
- Shell to Meterpreter upgrade
- Privilege escalation
- Password hash dumping and cracking
- Flag discovery

---

## 🧰 Tools Used

- `nmap` – Network reconnaissance and vulnerability scanning
- `metasploit` – Exploitation and session management
- `john` – Password hash cracking
- `rockyou.txt` – Wordlist used with John the Ripper

---

## 📁 Repository Structure

```
tryhackme-blue/
├── README.md			# Introduction and overview
├── Blue.md			# Main documentation (full guide)
└── Screenshots/		# Visual references
    ├── Screenshot-01.png
    ├── Screenshot-02.png
    ├── ...
    └── Screenshot-34.png
```

---

## 🚀 Getting Started

To follow this guide, ensure you have:
- A **TryHackMe** account ([Sign up here](https://tryhackme.com/)).
- A machine or VM with **Kali Linux** or **Parrot Security**.
- An active internet connection.

### Connect to TryHackMe VPN
- Follow this [VPN guide](https://github.com/fartaviao/tryhackme-tutorial) to connect using OpenVPN.
- Join and start the machine in the [Blue Room](https://tryhackme.com/room/blue)

## 🔎 Documentation and Screenshots
For detailed documentation and step-by-step guide, refer to the [main documentation](https://github.com/fartaviao/tryhackme-blue/blob/main/Blue.md)

## How to Use This Repository
1. Clone this repository:
   ```bash
   git clone https://github.com/fartaviao/tryhackme-blue.git
   ```
2. Navigate to the repository folder:
   ```bash
   cd tryhackme-blue
   ```
3. Open `Blue.md` to follow the steps.

## License
This documentation is provided for **educational purposes**. Feel free to modify and use it as needed.

### Recommended Resources:
- TryHackMe Official Documentation → [https://tryhackme.com/](https://tryhackme.com/)
- OpenVPN Documentation → [https://openvpn.net/](https://openvpn.net/)
- TryHackMe safe VPN access → [https://github.com/fartaviao/tryhackme-tutorial/blob/main/Tutorial.md](https://github.com/fartaviao/tryhackme-tutorial/blob/main/Tutorial.md)
- MS17-010 CVE Overview → [https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144)

### Security Considerations
- Always **disconnect the VPN** after finishing a session.
- Use **firewall rules** to prevent unauthorized access.

---

## Author
Created by **Fausto Artavia Ocampo** for educational use and cybersecurity training.

Happy hacking! 🚀
