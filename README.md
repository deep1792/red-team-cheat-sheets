# ⚔️ Red Team Cheat Sheets – Ultimate Collection of Hands‑On Attack Recipes

**Red Team Cheat Sheets** aggregates a curated set of threat‑emulation labs and lateral‑movement guides across multiple platforms—Windows, Linux, AD, SQL Server, VOIP, prompt‑injection. It’s a go‑to resource for pentesters, red teamers, and security engineers looking to streamline red‑teaming techniques with ready-to-use steps, commands, and mappings to adversary techniques.

📌 **Purpose**
To provide:

* Hands‑on exploitation guides across common enterprise systems
* Attack chains tailored to Linux, Windows, AD, SQL Server, VOIP, and Prompt environments
* Single-page cheat sheets for rapid reference
* Mapping to MITRE ATT\&CK where applicable

> ⚠️ For educational and authorized assessments only. Never use on unauthorized targets or production systems.

---


Each folder contains:

* **Cheat‑sheet.md** with compact command sets and examples
* **Full‑lab.md** detailing end‑to‑end scenario walkthroughs and context
* Supporting scripts or configuration files where applicable


## 🎯 Cheat‑Sheet Features

* **Quick commands**: One‑page reference with common flags, commands, and payloads
* **End‑to‑end labs**: Full story mode with explanation of each step
* **TTP mapping**: Aligned to relevant MITRE ATT\&CK tags — useful for reporting and detection tuning
* **Downloads/examples**: Input files, scripts, `.sql`, `.ps1`, etc. included for hands‑on use

---

## 🛠️ Getting Started

### 1. Clone the Repository

```
git clone https://github.com/deep1792/red-team-cheat-sheets.git
cd red-team-cheat-sheets
```

### 2. Navigate to a Folder

```
cd <specific-folder>
```

Inside, you’ll find:

* `cheat-sheet.md` – Fast reference CLI commands

### 3. Execute in Your Lab

* Follow instructions in `full‑lab.md` with your VM/environment
* Copy/paste commands from `cheat‑sheet.md` for quick testing and enumeration

### 4. Map to ATT\&CK

Most folders note the MITRE techniques used (e.g., T1059, T1134). Leverage this for exercise reporting or building detection logic.

---

## 🧠 Learning Objectives

* Master targeted attacks: OS privilege escalation, AD takeover, SQL Server compromise
* Learn quick enumeration and exploitation using one‑liners and tools
* Build familiarity with attack patterns and incorporate into detection/blue‑team responses

---

## 🔐 Disclaimer & Usage

* 🛡️ **Only use in authorized labs** – this content is strictly for ethical use
* ⚠️ **Isolate VMs** – no production exploitation, no sensitive data handling
* ℹ️ Contributors disclaim liability for misuse

---

## 👨‍💻 Contributing

Want to add a new cheat‑sheet or lab? Follow this structure:

1. Create a folder named after the attack domain
2. Add `cheat‑sheet.md` + `full‑lab.md`
3. Submit a PR with your lab details and any scripts

See `CONTRIBUTING.md` for formatting templates and style guides.

---

## 📝 License

MIT License — see `LICENSE` at repo root.

---

Enjoy the clarity and speed this collection brings to your red‑team labs and practice. If you find value, feel free to star ⭐ the repo!


## Support This Project via UPI 🇮🇳

If you find **Repo** useful and want to support its development, you can send a payment via UPI:

**UPI ID:** "alivejatt@oksbi"


Or scan the QR code below using any UPI app (Google Pay, PhonePe, Paytm, etc.):
![UPI QR Code](https://api.qrserver.com/v1/create-qr-code/?data=upi://pay?pa=alivejatt@oksbi&size=200x200)

[![Pay via UPI](https://img.shields.io/badge/Pay%20via-UPI-blue?style=for-the-badge&logo=google-pay)](upi://pay?pa=alivejatt@oksbi&pn=Kubepwn+Support&cu=INR)

