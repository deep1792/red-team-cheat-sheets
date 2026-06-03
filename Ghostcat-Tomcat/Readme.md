# Ghostcat-PWN — CVE-2020-1938 Exploitation Framework

**Ghostcat-PWN** is a full‑fledged penetration testing tool for the **Apache Tomcat AJP vulnerability (CVE‑2020‑1938)**.  
It combines reconnaissance, file disclosure, command execution, reverse shell, brute‑forcing, and automated loot collection in a single, easy‑to‑use CLI.

---

## Table of Contents

- [What is Ghostcat?](#-what-is-ghostcat)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage](#-usage)
  - [Global options](#global-options)
  - [check – Vulnerability check](#check--vulnerability-check)
  - [scan – Port scan](#scan--port-scan)
  - [read – File read](#read--file-read)
  - [exec – Command execution](#exec--command-execution)
  - [revshell – Reverse shell trigger](#revshell--reverse-shell-trigger)
  - [snatch – Automated loot collection](#snatch--automated-loot-collection)
  - [upload – File upload](#upload--file-upload)
  - [rce – One‑shot upload + command](#rce--one-shot-upload--command)
  - [brute – Credential brute‑force](#brute--credential-brute-force)
  - [deploy – WAR deployment](#deploy--war-deployment)
- [Theory & Attack Chain](#-theory--attack-chain)
- [Lab Setup (Docker)](#-lab-setup-docker)
- [Mitigation](#️-mitigation)
- [Disclaimer](#️-disclaimer)
- [Author & Credits](#-author--credits)

---

##  What is Ghostcat?

**CVE-2020-1938** is a serious flaw in the **AJP connector** (port 8009) of Apache Tomcat.  
Due to improper handling of AJP attributes, an attacker can trick Tomcat into **reading arbitrary files** inside the web application (`/WEB-INF/web.xml`, configuration files, compiled classes) or, under certain conditions, **evaluating a file as a JSP page** (remote code execution).

Affected versions: Tomcat 6, 7, 8, 9 (< 9.0.31, < 8.5.51, < 7.0.100).  

Ghostcat-PWN automates the entire exploitation process and adds powerful post‑exploitation modules.

---

##  Features

-  **Vulnerability check** – quickly tests if a target is exploitable  
-  **Port scan** – verifies if the AJP port is open  
-  **Arbitrary file read** – steals configuration files, credentials, source code  
-  **Secret extraction** – auto‑detects passwords, JDBC URLs, API keys  
-  **Command execution** – runs system commands via a pre‑uploaded JSP shell  
-  **Reverse shell** – triggers a pre‑positioned reverse shell JSP  
-  **Automated loot** – “snatch” common sensitive files and saves them locally  
-  **File upload** – WebDAV PUT (and Tomcat Manager WAR deploy)  
-  **One‑shot RCE** – uploads a command shell and executes a command in one step  
-  **Brute‑force** – tests default / custom Tomcat Manager credentials  
-  **WAR deployment** – deploys a WAR file using valid Manager credentials  
-  **Proxy support** – SOCKS5 proxy for anonymity  
-  **Verbose mode** – dumps raw AJP packets for debugging  
-  **Modular design** – easily extendable  

---

## Installation

```bash
git clone https://github.com/j0ck3r/ghostcat-pwn.git
cd ghostcat-pwn
pip install -r requirements.txt   # or just install PySocks manually
