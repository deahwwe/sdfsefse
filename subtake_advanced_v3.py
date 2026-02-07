#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Subdomain Takeover Scanner v3.0 - Advanced Detection
فحص دقيق ومتقدم لاحتمال استيلاء على النطاقات الفرعية
"""

import argparse
import csv
import re
import dns.resolver
import dns.exception
import requests
import socket
import ssl
import json
from typing import Optional, Dict, Any, List, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection

# إعداد DNS resolver
resolver = dns.resolver.Resolver()
resolver.lifetime = 7
resolver.timeout = 7

# قوائم متقدمة للبصمات والمزودين
VULNERABLE_PROVIDERS = {
    "github.io": {
        "fingerprints": [
            "there isn't a github pages site here",
            "this site is owned by github",
            "404. page not found · github pages",
            "project doesn't exist",
        ],
        "error_codes": [404],
        "takeover_url": "https://github.com/{name}",
    },
    "herokuapp.com": {
        "fingerprints": [
            "no such app",
            "there's nothing here, yet",
            "heroku | no such app",
        ],
        "error_codes": [404],
        "takeover_url": "https://dashboard.heroku.com/new-app?app-name={name}",
    },
    "azurewebsites.net": {
        "fingerprints": [
            "this web app has been stopped",
            "the resource you are looking for has been removed",
            "does not exist",
        ],
        "error_codes": [404, 403],
        "takeover_url": "https://portal.azure.com/#create/Microsoft.WebSite",
    },
    "s3.amazonaws.com": {
        "fingerprints": [
            "the specified bucket does not exist",
            "no such bucket",
            "404 not found",
        ],
        "error_codes": [404, 403],
        "takeover_url": "https://s3.console.aws.amazon.com/s3/create-bucket",
    },
    "firebaseapp.com": {
        "fingerprints": [
            "firebase hosting",
            "does not exist",
            "the requested url was not found",
        ],
        "error_codes": [404],
        "takeover_url": "https://console.firebase.google.com/project/_/hosting",
    },
    "fastly.net": {
        "fingerprints": [
            "fastly error",
            "unknown domain",
            "the request could not be satisfied",
        ],
        "error_codes": [404, 403],
        "takeover_url": "https://manage.fastly.com/",
    },
    "azurefd.net": {
        "fingerprints": [
            "azure front door",
            "does not exist",
        ],
        "error_codes": [404, 403],
        "takeover_url": "https://portal.azure.com/#create/Microsoft.AzureFrontDoor",
    },
    "netlify.app": {
        "fingerprints": [
            "not found",
            "page not found",
            "netlify",
        ],
        "error_codes": [404],
        "takeover_url": "https://app.netlify.com/start",
    },
    "vercel.app": {
        "fingerprints": [
            "404: not found",
            "vercel",
        ],
        "error_codes": [404],
        "takeover_url": "https://vercel.com/new",
    },
    "cloudfront.net": {
        "fingerprints": [
            "error from cloudfront",
            "cloudfront",
        ],
        "error_codes": [404, 403],
        "takeover_url": "https://console.aws.amazon.com/cloudfront/home",
    },
    "myshopify.com": {
        "fingerprints": [
            "sorry, this shop is currently unavailable",
            "storefront password",
        ],
        "error_codes": [404],
        "takeover_url": "https://accounts.shopify.com/store/create",
    },
}

# قائمة بأسماء مزودين معروفين في headers
KNOWN_PROVIDER_HEADERS = {
    'x-served-by': ['fastly', 'cloudflare', 'akamai', 'nginx', 'apache'],
    'server': ['cloudflare', 'nginx', 'apache', 'microsoft-iis', 'github.com'],
    'x-powered-by': ['asp.net', 'php', 'express', 'node.js'],
    'x-cache': ['cloudflare', 'fastly'],
    'via': ['varnish', 'akamai'],
    'cf-ray': ['cloudflare'],
}

# أرقام HTTP التي تشير إلى أخطاء حقيقية
ERROR_STATUS_CODES = [404, 410, 500, 501, 502, 503, 504]
WARNING_STATUS_CODES = [403, 401, 408, 429]

def clean_domain(input_str: str) -> Optional[str]:
    """تنظيف السلسلة لاستخراج النطاق فقط بدقة"""
    if not input_str or not isinstance(input_str, str):
        return None
    
    input_str = input_str.strip().lower()
    
    # إزالة البروتوكول
    if input_str.startswith(('http://', 'https://')):
        input_str = input_str.split('://', 1)[1]
    
    # إزالة المسارات والاستعلامات
    input_str = input_str.split('/')[0]
    input_str = input_str.split('?')[0]
    input_str = input_str.split('#')[0]
    
    # إزالة المنفذ
    if ':' in input_str:
        input_str = input_str.split(':')[0]
    
    # إزالة www. الزائدة
    if input_str.startswith('www.'):
        input_str = input_str[4:]
    
    # تحقق من صحة النطاق
    domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    
    if re.match(domain_pattern, input_str):
        return input_str
    
    return None

def extract_name_from_cname(cname: str) -> Optional[str]:
    """استخراج الاسم الأساسي من CNAME"""
    if not cname:
        return None
    
    # إزالة نطاقات المزودين
    for provider in VULNERABLE_PROVIDERS.keys():
        if provider in cname:
            # استخراج الجزء قبل نطاق المزود
            parts = cname.split(provider)[0].rstrip('.')
            if parts:
                # أخذ الجزء الأخير فقط
                return parts.split('.')[-1] if '.' in parts else parts
    return None

def advanced_dns_check(domain: str) -> Dict[str, Any]:
    """فحص DNS متقدم"""
    result = {
        "has_cname": False,
        "cname": None,
        "cname_chain": [],
        "cname_resolves": False,
        "a_record": False,
        "aaaa_record": False,
        "mx_record": False,
        "txt_record": False,
        "soa_record": False,
        "ns_record": False,
        "provider": None,
        "extracted_name": None,
    }
    
    try:
        # فحص CNAME و chain
        try:
            answers = resolver.resolve(domain, "CNAME")
            if answers:
                result["has_cname"] = True
                cname_target = str(answers[0].target).rstrip(".").lower()
                result["cname"] = cname_target
                result["cname_chain"].append(cname_target)
                
                # تتبع chain كامل
                current = cname_target
                for _ in range(5):  # عمق أقصى 5
                    try:
                        cname_answers = resolver.resolve(current, "CNAME")
                        if cname_answers:
                            next_target = str(cname_answers[0].target).rstrip(".").lower()
                            result["cname_chain"].append(next_target)
                            current = next_target
                        else:
                            break
                    except:
                        break
                
                # استخراج اسم من CNAME
                result["extracted_name"] = extract_name_from_cname(cname_target)
                
                # تحديد المزود
                for provider in VULNERABLE_PROVIDERS.keys():
                    if provider in cname_target:
                        result["provider"] = provider
                        break
                
                # فحص إذا كان CNAME يحل
                try:
                    resolver.resolve(cname_target, "A")
                    result["cname_resolves"] = True
                except:
                    # حاول AAAA
                    try:
                        resolver.resolve(cname_target, "AAAA")
                        result["cname_resolves"] = True
                    except:
                        result["cname_resolves"] = False
        except:
            result["has_cname"] = False
        
        # فحص أنواع DNS الأخرى
        record_types = [
            ("A", "a_record"),
            ("AAAA", "aaaa_record"),
            ("MX", "mx_record"),
            ("TXT", "txt_record"),
            ("SOA", "soa_record"),
            ("NS", "ns_record"),
        ]
        
        for rtype, field in record_types:
            try:
                resolver.resolve(domain, rtype)
                result[field] = True
            except:
                result[field] = False
                
    except Exception as e:
        pass
    
    return result

def advanced_http_check(domain: str, timeout: int = 15) -> Dict[str, Any]:
    """فحص HTTP/HTTPS متقدم"""
    result = {
        "accessible": False,
        "scheme": None,
        "status_code": None,
        "final_url": None,
        "redirect_count": 0,
        "redirect_chain": [],
        "headers": {},
        "body_sample": "",
        "content_length": 0,
        "content_type": None,
        "server_header": None,
        "is_error_page": False,
        "has_provider_header": False,
        "provider_headers": [],
        "ssl_cert": None,
        "response_time": 0,
        "title": "",
    }
    
    schemes = ["https", "http"]
    
    for scheme in schemes:
        url = f"{scheme}://{domain}"
        start_time = time.time()
        
        try:
            response = requests.get(
                url,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "close",
                },
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                stream=True
            )
            
            result["response_time"] = time.time() - start_time
            result["accessible"] = True
            result["scheme"] = scheme
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            result["redirect_count"] = len(response.history)
            result["redirect_chain"] = [resp.url for resp in response.history]
            result["headers"] = dict(response.headers)
            
            if 'server' in response.headers:
                result["server_header"] = response.headers['server'].lower()
            
            if 'content-type' in response.headers:
                result["content_type"] = response.headers['content-type'].lower()
            
            # قراءة جزء من body للتحليل
            content = response.text[:10000].lower()
            result["body_sample"] = content[:500]  # حفظ 500 حرف فقط للعرض
            result["content_length"] = len(response.content)
            
            # استخراج title
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
            if title_match:
                result["title"] = title_match.group(1).strip()[:100]
            
            # فحص headers للمزودين
            for header, value in response.headers.items():
                header_lower = header.lower()
                value_lower = str(value).lower()
                
                for provider_header, provider_keywords in KNOWN_PROVIDER_HEADERS.items():
                    if provider_header in header_lower:
                        for keyword in provider_keywords:
                            if keyword in value_lower:
                                result["has_provider_header"] = True
                                result["provider_headers"].append(f"{header}: {value}")
            
            # فحص إذا كانت صفحة خطأ
            result["is_error_page"] = is_error_page(
                response.status_code,
                content,
                result["title"]
            )
            
            # فحص شهادة SSL
            if scheme == "https":
                try:
                    ctx = ssl.create_default_context()
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                            cert = ssock.getpeercert()
                            result["ssl_cert"] = {
                                "issuer": dict(x[0] for x in cert.get('issuer', [])),
                                "subject": dict(x[0] for x in cert.get('subject', [])),
                                "not_before": cert.get('notBefore'),
                                "not_after": cert.get('notAfter'),
                            }
                except:
                    pass
            
            break  # توقف إذا نجح الاتصال
            
        except requests.exceptions.SSLError:
            if scheme == "https":
                continue  # حاول HTTP
        except Exception:
            continue
    
    return result

def is_error_page(status_code: int, body: str, title: str) -> bool:
    """تحديد إذا كانت الصفحة صفحة خطأ"""
    
    # إذا كان status code خطأ
    if status_code in ERROR_STATUS_CODES:
        return True
    
    # تحليل title
    error_titles = [
        "404", "not found", "page not found", "error",
        "access denied", "forbidden", "unauthorized",
        "server error", "service unavailable",
    ]
    
    title_lower = title.lower()
    for error_title in error_titles:
        if error_title in title_lower:
            return True
    
    # تحليل body
    error_patterns = [
        r"404", r"not.found", r"page.not.found",
        r"error.404", r"does.not.exist", r"no.such",
        r"access.denied", r"forbidden", r"unauthorized",
        r"server.error", r"service.unavailable",
        r"the.requested.url", r"could.not.be.found",
        r"this.page.cannot", r"page.cannot.be.displayed",
    ]
    
    for pattern in error_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            return True
    
    # صفحات قصيرة جداً (أقل من 200 حرف) غالباً صفحات خطأ
    if len(body) < 200 and status_code != 200:
        return True
    
    return False

def match_provider_fingerprint(provider: str, http_result: Dict[str, Any]) -> bool:
    """مطابقة بصمة مزود معين"""
    if not provider or provider not in VULNERABLE_PROVIDERS:
        return False
    
    provider_info = VULNERABLE_PROVIDERS[provider]
    
    # فحص status code
    if http_result["status_code"]:
        if http_result["status_code"] not in provider_info["error_codes"]:
            return False  # ليس خطأ من النوع المتوقع
    
    # فحص البصمات
    body = http_result["body_sample"].lower()
    for fingerprint in provider_info["fingerprints"]:
        if fingerprint in body:
            return True
    
    # فحص title
    title = http_result["title"].lower()
    for fingerprint in provider_info["fingerprints"]:
        if fingerprint in title:
            return True
    
    return False

def check_subdomain_takeover(subdomain: str, timeout: int = 15) -> Dict[str, Any]:
    """فحص شامل ومتقدم لساب دومين"""
    result = {
        "subdomain": subdomain,
        "dns": {},
        "http": {},
        "analysis": {
            "vulnerable_provider": None,
            "possible_takeover": False,
            "confidence": "none",  # none, low, medium, high, critical
            "evidence": [],
            "risk_score": 0,
            "takeover_steps": [],
            "recommendation": "",
        },
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    
    # 1. فحص DNS متقدم
    dns_result = advanced_dns_check(subdomain)
    result["dns"] = dns_result
    
    # 2. فحص HTTP متقدم
    http_result = advanced_http_check(subdomain, timeout)
    result["http"] = http_result
    
    # 3. التحليل المتقدم
    analysis = result["analysis"]
    
    # إذا كان هناك CNAME لمزود قابل للاستيلاء
    if dns_result["provider"]:
        analysis["vulnerable_provider"] = dns_result["provider"]
        
        # الحالة 1: CNAME لا يحل
        if not dns_result["cname_resolves"]:
            analysis["possible_takeover"] = True
            analysis["confidence"] = "high"
            analysis["risk_score"] += 70
            analysis["evidence"].append(f"CNAME يشير إلى {dns_result['cname']} ولا يمكن حله")
            
            # اقتراح خطوات الاستيلاء
            if dns_result["provider"] in VULNERABLE_PROVIDERS:
                provider_info = VULNERABLE_PROVIDERS[dns_result["provider"]]
                takeover_url = provider_info["takeover_url"]
                if dns_result["extracted_name"]:
                    takeover_url = takeover_url.replace("{name}", dns_result["extracted_name"])
                analysis["takeover_steps"].append(f"1. انتقل إلى: {takeover_url}")
                analysis["takeover_steps"].append(f"2. حاول إنشاء خدمة باسم: {dns_result['extracted_name'] or 'الاسم المستخرج من CNAME'}")
                analysis["takeover_steps"].append("3. تحقق إذا استطعت التحكم في النطاق")
        
        # الحالة 2: CNAME يحل ولكن صفحة خطأ للمزود
        elif dns_result["cname_resolves"] and http_result["accessible"]:
            if match_provider_fingerprint(dns_result["provider"], http_result):
                analysis["possible_takeover"] = True
                analysis["confidence"] = "medium"
                analysis["risk_score"] += 50
                analysis["evidence"].append(f"بصمة {dns_result['provider']} موجودة مع CNAME نشط")
    
    # الحالة 3: لا CNAME ولكن صفحة خطأ لمزود معروف
    elif not dns_result["has_cname"] and http_result["accessible"]:
        for provider, provider_info in VULNERABLE_PROVIDERS.items():
            if match_provider_fingerprint(provider, http_result):
                analysis["vulnerable_provider"] = provider
                analysis["possible_takeover"] = True
                analysis["confidence"] = "low"
                analysis["risk_score"] += 30
                analysis["evidence"].append(f"بصمة {provider} موجودة بدون CNAME")
                break
    
    # الحالة 4: DNS لا يحل ولا HTTP يعمل
    elif not dns_result["a_record"] and not dns_result["aaaa_record"] and not http_result["accessible"]:
        if dns_result["has_cname"] and dns_result["provider"]:
            analysis["possible_takeover"] = True
            analysis["confidence"] = "critical"
            analysis["risk_score"] += 90
            analysis["evidence"].append("لا DNS ولا HTTP يعملان مع CNAME لمزود قابل للاستيلاء")
    
    # عوامل تقليل الثقة
    if http_result["accessible"]:
        # إذا كانت صفحة نشطة مع headers مزود
        if http_result["has_provider_header"]:
            analysis["risk_score"] -= 30
            analysis["evidence"].append("headers تشير إلى موقع نشط")
            if analysis["confidence"] in ["high", "critical"]:
                analysis["confidence"] = "medium"
            elif analysis["confidence"] == "medium":
                analysis["confidence"] = "low"
        
        # إذا كانت صفحة خطأ عامة وليست لمزود معين
        if http_result["is_error_page"] and not analysis["vulnerable_provider"]:
            analysis["risk_score"] += 10
            analysis["evidence"].append("صفحة خطأ عامة")
    
    # تحديد التوصية
    if analysis["confidence"] == "critical":
        analysis["recommendation"] = "فحص عاجل - احتمال استيلاء عالي"
    elif analysis["confidence"] == "high":
        analysis["recommendation"] = "فحص فوري - احتمال استيلاء"
    elif analysis["confidence"] == "medium":
        analysis["recommendation"] = "مراقبة - مؤشرات إيجابية"
    elif analysis["confidence"] == "low":
        analysis["recommendation"] = "متابعة - مؤشرات ضعيفة"
    else:
        analysis["recommendation"] = "آمن - لا توجد مؤشرات"
    
    # تقييم النتيجة النهائية
    if analysis["risk_score"] >= 80:
        analysis["confidence"] = "critical"
    elif analysis["risk_score"] >= 60:
        analysis["confidence"] = "high"
    elif analysis["risk_score"] >= 40:
        analysis["confidence"] = "medium"
    elif analysis["risk_score"] >= 20:
        analysis["confidence"] = "low"
    else:
        analysis["confidence"] = "none"
    
    return result

def print_detailed_result(result: Dict[str, Any]):
    """طباعة نتيجة مفصلة"""
    print(f"\n{'='*80}")
    print(f"📊 فحص: {result['subdomain']}")
    print(f"{'='*80}")
    
    # معلومات DNS
    print("\n🔍 معلومات DNS:")
    print(f"  • CNAME: {result['dns'].get('cname', 'لا يوجد')}")
    if result['dns'].get('cname_chain'):
        print(f"  • CNAME Chain: {' → '.join(result['dns']['cname_chain'])}")
    print(f"  • CNAME يحل: {'✅' if result['dns'].get('cname_resolves') else '❌'}")
    print(f"  • A Record: {'✅' if result['dns'].get('a_record') else '❌'}")
    print(f"  • المزود: {result['dns'].get('provider', 'غير معروف')}")
    
    # معلومات HTTP
    if result['http'].get('accessible'):
        print("\n🌐 معلومات HTTP:")
        print(f"  • الحالة: {result['http'].get('status_code')}")
        print(f"  • المخطط: {result['http'].get('scheme')}")
        print(f"  • العنوان: {result['http'].get('title', 'غير متوفر')[:50]}")
        print(f"  • نوع المحتوى: {result['http'].get('content_type', 'غير معروف')}")
        print(f"  • صفحة خطأ: {'✅' if result['http'].get('is_error_page') else '❌'}")
        if result['http'].get('provider_headers'):
            print(f"  • Headers مزود: {', '.join(result['http']['provider_headers'])}")
    
    # التحليل
    print("\n📈 التحليل:")
    confidence_icons = {
        "critical": "🔥🔥",
        "high": "🔥",
        "medium": "⚠️",
        "low": "ℹ️",
        "none": "✅"
    }
    
    icon = confidence_icons.get(result['analysis']['confidence'], "❓")
    print(f"  • الثقة: {icon} {result['analysis']['confidence'].upper()}")
    print(f"  • درجة الخطورة: {result['analysis']['risk_score']}/100")
    print(f"  • احتمال الاستيلاء: {'✅' if result['analysis']['possible_takeover'] else '❌'}")
    
    if result['analysis']['evidence']:
        print(f"  • الأدلة:")
        for evidence in result['analysis']['evidence']:
            print(f"    - {evidence}")
    
    if result['analysis']['takeover_steps']:
        print(f"  • خطوات التحقق:")
        for step in result['analysis']['takeover_steps']:
            print(f"    {step}")
    
    print(f"  • التوصية: {result['analysis']['recommendation']}")
    print(f"{'='*80}")

def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Takeover Scanner v3.0 - فحص دقيق ومتقدم",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
أمثلة:
  %(prog)s -i subdomains.txt --detailed
  %(prog)s -i subdomains.txt -o results.json --json
  %(prog)s -i subdomains.txt --filter critical,high
  %(prog)s -i subdomains.txt --threads 20 --timeout 20
        """
    )
    
    parser.add_argument("-i", "--input", required=True, help="ملف الساب دومينات")
    parser.add_argument("-o", "--output", help="ملف لحفظ النتائج (JSON/CSV)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="عدد الثريدات")
    parser.add_argument("--timeout", type=int, default=15, help="مهلة الطلبات")
    parser.add_argument("--detailed", action="store_true", help="عرض تفاصيل كاملة")
    parser.add_argument("--json", action="store_true", help="حفظ النتائج كـ JSON")
    parser.add_argument("--filter", help="تصفية النتائج (critical,high,medium,low)")
    parser.add_argument("--quiet", action="store_true", help="وضع صامت")
    
    args = parser.parse_args()
    
    print("="*80)
    print("Subdomain Takeover Scanner v3.0 - Advanced Detection")
    print("="*80)
    
    # قراءة الساب دومينات
    subdomains = []
    try:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                domain = clean_domain(line.strip())
                if domain:
                    subdomains.append(domain)
    except Exception as e:
        print(f"[!] خطأ في قراءة الملف: {e}")
        return
    
    if not subdomains:
        print("[!] لا توجد نطاقات صالحة")
        return
    
    print(f"[+] تم تحميل {len(subdomains)} نطاق")
    print("[+] بدء الفحص المتقدم...")
    
    # فحص النطاقات
    results = []
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_subdomain = {
            executor.submit(check_subdomain_takeover, sub, args.timeout): sub 
            for sub in subdomains
        }
        
        for i, future in enumerate(as_completed(future_to_subdomain), 1):
            subdomain = future_to_subdomain[future]
            try:
                result = future.result()
                results.append(result)
                
                if not args.quiet:
                    # عرض مختصر
                    confidence = result['analysis']['confidence']
                    icon = "🔥" if confidence == "critical" else "⚠️" if confidence in ["high", "medium"] else "✅"
                    status = "محتمل" if result['analysis']['possible_takeover'] else "آمن"
                    print(f"[{i}/{len(subdomains)}] {icon} {subdomain} - {status} ({confidence})")
                    
                    if args.detailed:
                        print_detailed_result(result)
                        
            except Exception as e:
                if not args.quiet:
                    print(f"[{i}/{len(subdomains)}] ❌ {subdomain} - خطأ: {str(e)[:50]}")
    
    # تحليل النتائج
    print("\n" + "="*80)
    print("📊 تحليل النتائج النهائي:")
    print("="*80)
    
    confidence_stats = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "none": 0
    }
    
    takeover_count = 0
    providers_found = set()
    
    for result in results:
        confidence = result['analysis']['confidence']
        confidence_stats[confidence] += 1
        
        if result['analysis']['possible_takeover']:
            takeover_count += 1
            
        if result['analysis']['vulnerable_provider']:
            providers_found.add(result['analysis']['vulnerable_provider'])
    
    # عرض الإحصائيات
    print(f"\n📈 الإحصائيات:")
    print(f"  • إجمالي النطاقات: {len(results)}")
    print(f"  • محتملة للاستيلاء: {takeover_count}")
    print(f"  • مزودين معرضين: {', '.join(providers_found) if providers_found else 'لا يوجد'}")
    
    print(f"\n🎯 تصنيف الثقة:")
    for level, count in confidence_stats.items():
        if count > 0:
            icon = "🔥" if level == "critical" else "⚠️" if level in ["high", "medium"] else "✅"
            print(f"  • {icon} {level.upper()}: {count}")
    
    # عرض الحالات الحرجة
    critical_cases = [r for r in results if r['analysis']['confidence'] in ['critical', 'high']]
    if critical_cases:
        print(f"\n🚨 الحالات الحرجة:")
        for case in critical_cases:
            print(f"  • {case['subdomain']}")
            print(f"    - الثقة: {case['analysis']['confidence']}")
            print(f"    - المزود: {case['analysis']['vulnerable_provider'] or 'غير معروف'}")
            print(f"    - الأدلة: {', '.join(case['analysis']['evidence'][:2])}")
    
    # حفظ النتائج
    if args.output:
        try:
            if args.json or args.output.endswith('.json'):
                # حفظ كـ JSON
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                print(f"\n[+] تم حفظ النتائج كـ JSON في: {args.output}")
            else:
                # حفظ كـ CSV مبسط
                fieldnames = [
                    "subdomain", "has_cname", "cname", "provider",
                    "cname_resolves", "http_accessible", "http_status",
                    "is_error_page", "vulnerable_provider", "possible_takeover",
                    "confidence", "risk_score", "recommendation", "timestamp"
                ]
                
                with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for result in results:
                        row = {
                            "subdomain": result["subdomain"],
                            "has_cname": result["dns"].get("has_cname", False),
                            "cname": result["dns"].get("cname", ""),
                            "provider": result["dns"].get("provider", ""),
                            "cname_resolves": result["dns"].get("cname_resolves", False),
                            "http_accessible": result["http"].get("accessible", False),
                            "http_status": result["http"].get("status_code", ""),
                            "is_error_page": result["http"].get("is_error_page", False),
                            "vulnerable_provider": result["analysis"].get("vulnerable_provider", ""),
                            "possible_takeover": result["analysis"].get("possible_takeover", False),
                            "confidence": result["analysis"].get("confidence", ""),
                            "risk_score": result["analysis"].get("risk_score", 0),
                            "recommendation": result["analysis"].get("recommendation", ""),
                            "timestamp": result["timestamp"]
                        }
                        writer.writerow(row)
                
                print(f"\n[+] تم حفظ النتائج كـ CSV في: {args.output}")
                
        except Exception as e:
            print(f"[!] خطأ في حفظ النتائج: {e}")
    
    print(f"\n[+] انتهى الفحص المتقدم")

if __name__ == "__main__":
    main()
