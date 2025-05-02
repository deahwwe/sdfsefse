# Bug Bounty Checklist 🛡️

---

## 1. Recon 🔍

### Subdomain Enumeration

- [Subdomain Finder](https://subdomainfinder.c99.nl/)
- Execute the following commands:

```bash
subfinder -d ucartz.com
assetfinder --subs-only ucartz.com
subzy run --targets all.txt  # Subdomain takeover tool
```

- [Dedupelist - حذف التكرار](https://dedupelist.com/):

```bash
cat domains.txt | httpx
```

---

## 2. Session Management Testing 🛡️

### Authentication Testing

- Test for authentication bypass.
- Test account lockout mechanisms.
- Test protection against brute-force attacks.
- Verify password quality rules.
- Test the "Remember Me" functionality.
- Ensure forms and password inputs avoid autocomplete.
- Test password reset and recovery processes.
- Test password change workflows.
- Verify CAPTCHA implementations.
- Test multi-factor authentication (MFA).
- Check logout functionality.
- Test for default login credentials.
- Verify user-accessible authentication logs.
- Ensure sessions terminate properly after logout.
- Test vertical access control issues (privilege escalation).
- Test horizontal access control issues (peer user access).

---

## 3. URL and Parameter Extraction 🔗

### Arjun

**Basic Scan:**

```bash
arjun -u https://example.com
```

**Save Output and Automate:**

```bash
arjun -u https://example.com -o params.json
```

**With Input File:**

```bash
arjun -i urls.txt
```

**Quick JSON Output:**

```bash
arjun -u https://example.com -q -oJ params.json
```

### FUZZ (Hidden Points Exploration)

**Examples:**

```bash
ffuf -w common.txt -u https://dev.ucartz.com/FUZZ
ffuf -w ~/wordlists/parameters.txt -u http://ffuf.me/cd/param/data?FUZZ=1 -mc 200

# Recursive Search
ffuf -w common.txt -recursion -u https://dev.ucartz.com/FUZZ -mc 200
```

### Waymore:

```bash
cat urls.txt | waymore -mode B -oU newurls.txt -P5 -mc 200
```

### Waybackurls (Old Link Extraction)

- Execute the following command:

```bash
cat domains.txt | waybackurls > urls
```

---

## 4. Google Dorks 🔎

- [Dorks by Faisal Ahmed](https://dorks.faisalahmed.me/)
- Search for GitHub Backups.
- Explore `robots.txt`, `sitemap.xml`, `.DS_Store` files.

---

## 5. فحص التكوين الخاطئ (Misconfiguration Testing) ⚙️

- ابحث عن تكوينات غير آمنة في الخوادم والتطبيقات.
- تحقق من:
  - ملفات الإدخال المكشوفة (`.git`, `.env`, `.htaccess`)
  - واجهات إدارة غير محمية
  - الإعدادات الافتراضية (default creds, config)
  - النسخ الاحتياطية المتاحة (`.bak`, `.old`, `.zip`)

### Nuclei

```bash
nuclei -u https://example.com -t cves/ -severity critical,high,medium -o nuclei_results.txt
```

### Nikto

```bash
nikto -h https://example.com
```

### WhatWeb

```bash
whatweb https://example.com
```

### Dirsearch

```bash
dirsearch -u https://example.com -e php,html,txt,zip -x 403,404
```

---

## 17. SQL Injection (SQLi)

- Tools:
  - [sqlmap](https://github.com/sqlmapproject/sqlmap)
  - [NoSQLMap](https://github.com/codingo/NoSQLMap)
- Example:

```bash
sqlmap -u "http://target.com/page.php?id=1" --batch --level=3 --risk=2 --dump
```

- Test:
  - Union-based injection
  - Boolean-based injection
  - Time-based injection
  - Header-based injection

---

## 18. Open Redirect

- Test URLs:
  - `?next=https://evil.com`
  - `?redirect_url=https://evil.com`
- Tool:
  - [OpenRedireX](https://github.com/devanshbatham/OpenRedireX)

---

## 19. CORS Misconfiguration

- Tools:
  - [Corsy](https://github.com/s0md3v/Corsy)
- Check for:
  - `Access-Control-Allow-Origin: *`
  - Reflection of Origin header

---

## 20. JWT Vulnerabilities

- Check:
  - Algorithm none
  - Weak secret keys
  - Unvalidated token signatures
- Tools:
  - [jwt_tool](https://github.com/ticarpi/jwt_tool)
  - [JWT Cracker](https://github.com/brendan-rius/c-jwt-cracker)

---

## 21. Race Conditions

- Concepts:
  - Test concurrent requests for modifying the same resource (e.g., balance, password reset).
  - Look for TOCTOU (Time of Check to Time of Use) vulnerabilities.

- Tools:
  - [RaceTheWeb](https://github.com/insp3ctre/race-the-web)
  - Intruder in Burp Suite with parallel threads

---

## 22. XXE (XML External Entity Injection)

- Payload Example:

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
```

- Tools:
  - [XXEinjector](https://github.com/enjoiz/XXEinjector)
  - Burp Suite Repeater

- Test Targets:
  - File disclosures
  - SSRF via XML
  - DoS attacks (Billion Laughs)

---

## 23. Clickjacking

- Test by loading target site in an iframe:

```html
<iframe src="https://example.com" width="800" height="600"></iframe>
```

- Mitigation Check:
  - Ensure `X-Frame-Options: DENY` or `SAMEORIGIN` headers are present
  - Use CSP (Content Security Policy) `frame-ancestors` directive

---

## 24. Path Traversal

- Payloads:
  - `../../../../etc/passwd`
  - `%2e%2e/%2e%2e/%2e%2e/etc/passwd`
- Tools:
  - Manual testing with Burp
  - [PathTraverser](https://github.com/tegal1337/PathTraverser)
- Test for:
  - Accessing sensitive files
  - Bypassing upload restrictions

---

## 25. Broken Access Control

- Types:
  - Vertical Privilege Escalation
  - Horizontal Privilege Escalation
- Test:
  - Modify user IDs in requests
  - Bypass role checks on server side
  - Access admin endpoints as low-privileged user
- Tools:
  - Burp Suite
  - Manual testing / Intercept requests

---

## 26. Insecure Deserialization

- Symptoms:
  - User-controlled serialized data passed to application
  - Remote Code Execution (RCE) or denial of service
- Payloads:
  - Java: `CommonsCollections`, `JRMP`
  - PHP: `__wakeup()`, `__destruct()` abuse
- Tools:
  - [ysoserial](https://github.com/frohoff/ysoserial)
  - [PHPGGC](https://github.com/ambionics/phpggc)
- Prevention:
  - Avoid unserializing untrusted data
  - Implement integrity checks

---

## 27. Cross-Site Scripting (XSS)

- Basic Payloads:
  - `<script>alert('XSS')</script>`
  - `<img src=x onerror=alert('XSS')>`
  - `<svg/onload=alert('XSS')>`
  - `<iframe srcdoc="<script>alert('XSS')</script>"></iframe>`
  - `<a href="javascript:alert('XSS')">Click</a>`

- WAF Bypass Example:
  - مشفر: `<svg/onload=alert\`XSS\`>`

- Tools:
  - [dalfox](https://github.com/hahwul/dalfox)
  - [XSSor](https://github.com/0xsauby/xsser)
  - [xss-scanner](https://github.com/0xInfection/xss-scanner)

- Techniques:
  - Test input fields, URL parameters, headers
  - Inject in HTML, attributes, scripts, event handlers
  - Encode or obfuscate payloads to bypass filters

---

## 28. Remote Code Execution (RCE)

- Payloads:
  - `; whoami`
  - `| id`
  - `& cat /etc/passwd`
- Test Points:
  - File upload functionality
  - User input reflected into system calls

- Tools:
  - [Commix](https://github.com/commixproject/commix)
  - [Metasploit](https://www.metasploit.com/)

- Detection Tips:
  - Use Burp Suite repeater to inject OS commands
  - Observe delay or system responses (ping, sleep)

---

## 29. Server-Side Request Forgery (SSRF)

- Payloads:
  - `http://127.0.0.1:80`
  - `file:///etc/passwd`
  - `gopher://127.0.0.1`
- Tools:
  - [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
  - Burp Suite Collaborator
- Test:
  - Look for webhooks, URL fetchers, metadata APIs
  - DNS and internal IP disclosure

---

## 30. Insecure File Upload

- Test:
  - Upload scripts with double extensions: `shell.php.jpg`
  - Try bypassing MIME type filters
- Tools:
  - Burp Suite
  - Manual analysis

---

## 31. Information Disclosure

- Look for:
  - Stack traces
  - Debug pages
  - `.git`, `.env`, `.DS_Store`, `config.json`
- Tools:
  - [gitdumper](https://github.com/internetwache/GitTools)
  - [dirsearch](https://github.com/maurosoria/dirsearch)

---

## 32. Business Logic Errors

- Look for:
  - Same user registering twice
  - Applying coupon multiple times
  - Transferring funds without deduction
- Techniques:
  - Understand flow and test unexpected sequences
  - Automate repetitive actions

---