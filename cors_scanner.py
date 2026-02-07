#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import urllib3

# تعطيل تحذيرات SSL (عند استخدام verify=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_lines(path):
    """قراءة ملف كسطور غير فارغة في قائمة."""
    items = []
    with open(path, errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                items.append(s)
    return items


def build_full_url(base, endpoint):
    """دمج الهوست مع الـ endpoint في URL كامل."""
    base = base.rstrip("/")
    if endpoint.startswith("/"):
        return base + endpoint
    else:
        return base + "/" + endpoint


def scan_url(url, origins, timeout=7):
    """
    فحص URL واحد بعدة قيم Origin.
    يرجّع قائمة findings مشبوهة.
    """
    findings = []

    for origin in origins:
        headers = {
            "Origin": origin,
            "User-Agent": "Simple-CORS-Scanner"
        }

        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=False,        # نتجاهل مشاكل SSL
                allow_redirects=True
            )
        except requests.RequestException:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")

        if not acao:
            continue

        acac = acac.strip().lower()

        suspicious = False
        level = "INFO"

        # 1) wildcard + credentials = خطير
        if acao == "*" and acac == "true":
            suspicious = True
            level = "HIGH"
        # 2) انعكاس origin + credentials
        elif acao == origin and acac == "true":
            suspicious = True
            level = "MEDIUM"
        # 3) سماح عام أو مطابق للأصل حتى بدون credentials
        elif acao in ("*", origin):
            suspicious = True
            level = "LOW"

        if suspicious:
            findings.append({
                "url": url,
                "origin": origin,
                "acao": acao,
                "acac": acac,
                "status": resp.status_code,
                "level": level,
            })

    return findings


def main():
    parser = argparse.ArgumentParser(
        description="Simple CORS misconfiguration scanner"
    )
    parser.add_argument(
        "-l", "--live",
        required=True,
        help="ملف الهوستات الحية (من httpx) - سطور مثل https://sub.example.com"
    )
    parser.add_argument(
        "-e", "--endpoints",
        required=True,
        help="ملف الـ endpoints (مسارات مثل /api/login أو /)"
    )
    parser.add_argument(
        "-o", "--output",
        help="ملف لحفظ النتائج (افتراضي: طباعة على الشاشة فقط)"
    )

    args = parser.parse_args()

    live_hosts = load_lines(args.live)
    endpoints = load_lines(args.endpoints)

    if not live_hosts:
        print("[-] ملف الهوستات الحية فارغ.")
        return

    if not endpoints:
        print("[-] ملف الـ endpoints فارغ.")
        return

    # origins نختبر بها
    test_origins = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    out_lines = []
    print(f"[+] عدد الهوستات الحية: {len(live_hosts)}")
    print(f"[+] عدد الـ endpoints : {len(endpoints)}")
    print("[*] بدء فحص CORS ...")

    for host in live_hosts:
        for ep in endpoints:
            full_url = build_full_url(host, ep)
            findings = scan_url(full_url, test_origins)

            for f in findings:
                line = (
                    f"[{f['level']}] {f['url']}  "
                    f"Origin={f['origin']}  "
                    f"Status={f['status']}  "
                    f"ACAO={f['acao']}  "
                    f"ACAC={f['acac']}"
                )
                print(line)
                out_lines.append(line)

    if args.output and out_lines:
        with open(args.output, "w") as f:
            for line in out_lines:
                f.write(line + "\n")
        print(f"[✔] تم حفظ النتائج في: {args.output}")
    elif not out_lines:
        print("[!] لم يتم العثور على أي سلوك CORS مشبوه.")


if __name__ == "__main__":
    main()
