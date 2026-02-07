#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import os
import sys
import argparse
import datetime
from urllib.parse import urlparse


def file_exists_and_not_empty(path):
    return os.path.exists(path) and os.path.getsize(path) > 0


def run_to_file(cmd, description, out_path=None, append=False):
    print(f"[*] {description}...")
    try:
        if out_path:
            mode = "a" if append else "w"
            with open(out_path, mode) as f:
                result = subprocess.run(
                    cmd,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    text=True
                )
        else:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
    except FileNotFoundError:
        print(f"[!] الأداة غير موجودة أو غير مثبتة: {cmd[0]}")
        sys.exit(1)

    if result.returncode != 0:
        print(f"[!] خطأ أثناء تشغيل: {' '.join(cmd)}")
        if result.stderr:
            print(result.stderr.strip())
    return result


def extract_endpoints_from_urls(urls_file):
    """
    استخراج endpoints من الـ URLs:
    - أي URL يبدأ بـ http/https.
    - نأخذ path + query.
    - نسمح حتى بالمسار الجذر "/" كـ endpoint.
    """
    endpoints = set()

    with open(urls_file, errors="ignore") as f:
        for line in f:
            url = line.strip()
            if not url.startswith(("http://", "https://")):
                continue

            parsed = urlparse(url)
            path_q = parsed.path or "/"
            if parsed.query:
                path_q += "?" + parsed.query

            endpoints.add(path_q)

    return endpoints


def extract_js_urls(urls_file):
    """
    استخراج روابط ملفات الـ JS من قائمة الـ URLs.
    """
    js_urls = set()
    with open(urls_file, errors="ignore") as f:
        for line in f:
            url = line.strip()
            if not url.startswith(("http://", "https://")):
                continue

            lower = url.lower()
            if ".js" in lower:
                js_urls.add(url)
    return js_urls


def extract_endpoints_with_linkfinder(js_urls, linkfinder_script):
    """
    تشغيل LinkFinder على كل JS URL واستخراج الـ endpoints.
    """
    endpoints = set()

    if not js_urls:
        return endpoints

    if not os.path.exists(linkfinder_script):
        print(f"[!] لم يتم العثور على {linkfinder_script}، سيتم تخطي فحص JS بـ LinkFinder.")
        return endpoints

    print(f"[*] تشغيل LinkFinder على {len(js_urls)} ملف JS...")

    for url in sorted(js_urls):
        print(f"    [+] JS: {url}")
        try:
            result = subprocess.run(
                ["python3", linkfinder_script, "-i", url, "-o", "cli"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=90
            )
        except FileNotFoundError:
            print("[!] python3 أو linkfinder.py غير موجود. إيقاف خطوة LinkFinder.")
            return endpoints
        except subprocess.TimeoutExpired:
            print(f"[!] LinkFinder أخذ وقت طويل وتجاوز الـ timeout على: {url}")
            continue

        if result.returncode != 0:
            err = (result.stderr or "").strip()
            if err:
                print(f"[!] خطأ من LinkFinder على {url}: {err}")
            continue

        for line in result.stdout.splitlines():
            s = line.strip().strip('"').strip("'")
            if not s:
                continue

            if s.startswith("http://") or s.startswith("https://"):
                parsed = urlparse(s)
                path_q = parsed.path or "/"
                if parsed.query:
                    path_q += "?" + parsed.query
                if path_q not in ("", "/"):
                    endpoints.add(path_q)
            else:
                if not s.startswith("/"):
                    s = "/" + s
                if s not in ("/", ""):
                    endpoints.add(s)

    print(f"[✔] LinkFinder استخرج {len(endpoints)} endpoint إضافي من ملفات الـ JS")
    return endpoints


def main():
    parser = argparse.ArgumentParser(
        description="أتمتة جمع السب دومينات والزحف على الـ URLs واستخراج endpoints + فحص CORS"
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        help="الدومين المستهدف (مثال: example.com)"
    )
    parser.add_argument(
        "-o", "--output",
        help="مسار مجلد الإخراج (افتراضي: output/<domain>_<timestamp>)"
    )
    parser.add_argument(
        "--skip-cors",
        action="store_true",
        help="تخطي خطوة فحص CORS"
    )
    parser.add_argument(
        "--linkfinder",
        default="linkfinder.py",
        help="مسار سكربت LinkFinder (افتراضي: linkfinder.py في نفس المجلد)"
    )

    args = parser.parse_args()
    domain = args.domain.strip()
    linkfinder_script = args.linkfinder

    # تجهيز مجلد الإخراج
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output:
        output_dir = args.output
    else:
        output_dir = os.path.join("output", f"{domain}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    subs_file = os.path.join(output_dir, "subs.txt")
    live_file = os.path.join(output_dir, "live.txt")
    urls_file = os.path.join(output_dir, "urls.txt")
    endpoints_file = os.path.join(output_dir, "endpoints.txt")

    print(f"[+] الدومين المستهدف: {domain}")
    print(f"[+] مجلد الإخراج: {output_dir}")

    # 1️⃣ Enumerate Subdomains (assetfinder)
    run_to_file(
        ["assetfinder", "--subs-only", domain],
        description="جمع السب دومينات باستخدام assetfinder",
        out_path=subs_file
    )

    if not file_exists_and_not_empty(subs_file):
        print("[-] لم يتم العثور على أي سب دومين. إنهاء.")
        sys.exit(1)

    # 2️⃣ Probe Live Hosts (httpx)
    run_to_file(
        ["httpx", "-silent", "-l", subs_file, "-o", live_file],
        description="فحص الهوستات الحية باستخدام httpx"
    )

    if not file_exists_and_not_empty(live_file):
        print("[-] لا يوجد أي هوست حي. إنهاء.")
        sys.exit(1)

    # 3️⃣ Crawl URLs & JS (katana)
    run_to_file(
        ["katana", "-list", live_file, "-jc", "-silent", "-o", urls_file],
        description="زحف الروابط والـ JS باستخدام katana"
    )

    if not file_exists_and_not_empty(urls_file):
        print("[-] لم يتم اكتشاف أي URLs. إنهاء.")
        sys.exit(1)

    # 4️⃣ Extract endpoints from URLs
    print("[*] استخراج الـ endpoints من قائمة الروابط (URLs)...")
    url_endpoints = extract_endpoints_from_urls(urls_file)
    print(f"[✔] تم استخراج {len(url_endpoints)} endpoint من الـ URLs")

    # 5️⃣ Extract endpoints from JS via LinkFinder
    js_urls = extract_js_urls(urls_file)
    print(f"[*] تم العثور على {len(js_urls)} رابط JS لمحاولة استخراج endpoints منها")

    js_endpoints = extract_endpoints_with_linkfinder(js_urls, linkfinder_script)

    # دمج كل النتائج
    all_endpoints = set()
    all_endpoints.update(url_endpoints)
    all_endpoints.update(js_endpoints)

    with open(endpoints_file, "w") as f:
        for ep in sorted(all_endpoints):
            f.write(ep + "\n")

    print(f"[✔] المجموع الكلّي للـ endpoints: {len(all_endpoints)}")
    print(f"[✔] تم حفظها في: {endpoints_file}")

    # 6️⃣ CORS Scanner (اختياري)
    if args.skip_cors:
        print("[*] تم تخطي فحص CORS بناءً على الخيار --skip-cors")
        return

    if len(all_endpoints) == 0:
        print("[!] لا توجد endpoints لفحص CORS.")
        return

    run_to_file(
        ["python3", "cors_scanner.py", "-l", live_file, "-e", endpoints_file],
        description="تشغيل فاحص CORS على الـ endpoints المكتشفة"
    )


if __name__ == "__main__":
    main()
