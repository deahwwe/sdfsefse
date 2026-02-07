#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║       Backup File Finder v2.0                        ║
║       Domain = UPPER + lower + Capitalize            ║
║       For Authorized Security Testing Only           ║
╚══════════════════════════════════════════════════════╝
"""

import sys
import requests
import argparse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════
#  الامتدادات - Extensions
# ═══════════════════════════════════════════

ARCHIVE_EXT = ['.rar', '.zip', '.7z', '.tar', '.tar.gz', '.tgz', '.tar.bz2', '.gz', '.bz2', '.xz', '.cab']
BACKUP_EXT  = ['.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp', '.temp', '.copy']
DB_EXT      = ['.sql', '.sql.gz', '.sql.bz2', '.sql.zip', '.sql.rar', '.sql.7z', '.db', '.sqlite', '.mdb', '.dump']
CONFIG_EXT  = ['.conf', '.config', '.cfg', '.ini', '.env', '.yml', '.yaml', '.xml', '.json', '.log']

ALL_EXT = ARCHIVE_EXT + BACKUP_EXT + DB_EXT + CONFIG_EXT

COMMON_NAMES = [
    'backup', 'site', 'web', 'www', 'db', 'database', 'data', 'dump',
    'export', 'archive', 'files', 'old', 'bck', 'public', 'html',
    'htdocs', 'home', 'admin', 'wp', 'wordpress', 'config',
    'full-backup', 'daily', 'weekly', 'monthly'
]

PATHS = ['', 'backup/', 'backups/', 'bak/', 'old/', 'temp/', 'tmp/', 'dump/', 'export/', 'uploads/']

# ═══════════════════════════════════════════
#  الألوان - Colors
# ═══════════════════════════════════════════

class C:
    G = '\033[92m'   # أخضر
    R = '\033[91m'   # أحمر
    Y = '\033[93m'   # أصفر
    CN = '\033[96m'  # سماوي
    M = '\033[95m'   # بنفسجي
    W = '\033[97m'   # أبيض
    B = '\033[1m'    # عريض
    X = '\033[0m'    # ريسيت


def banner():
    print(f"""{C.CN}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗  ██╗  ██╗ ██████╗ ██╗  ██╗██╗   ██╗██████╗         ║
║   ██╔══██╗ ██║ ██╔╝██╔════╝ ██║ ██╔╝██║   ██║██╔══██╗        ║
║   ██████╔╝ █████╔╝ ██║      █████╔╝ ██║   ██║██████╔╝        ║
║   ██╔══██╗ ██╔═██╗ ██║      ██╔═██╗ ██║   ██║██╔═══╝         ║
║   ██████╔╝ ██║  ██╗╚██████╗ ██║  ██╗╚██████╔╝██║             ║
║   ╚═════╝  ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝             ║
║                                                               ║
║   Backup File Finder v2.0                                     ║
║   Domain Variations: lower | UPPER | Capitalize               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{C.X}""")


# ═══════════════════════════════════════════
#  3 حالات الدومين - Domain Cases
# ═══════════════════════════════════════════

def domain_cases(domain):
    """
    nomad → ['nomad', 'NOMAD', 'Nomad']
    """
    return [
        domain.lower(),       # nomad
        domain.upper(),       # NOMAD
        domain.capitalize(),  # Nomad
    ]


def subdomain_cases(sub):
    """
    sec → ['sec', 'SEC', 'Sec']
    """
    if not sub:
        return [None]
    return [
        sub.lower(),       # sec
        sub.upper(),       # SEC
        sub.capitalize(),  # Sec
    ]


# ═══════════════════════════════════════════
#  تحليل الرابط - URL Parser
# ═══════════════════════════════════════════

def parse_target(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return None

    parts = hostname.split('.')

    info = {
        'scheme': parsed.scheme,
        'hostname': hostname,
        'base_url': f"{parsed.scheme}://{hostname}",
        'parts': parts
    }

    if len(parts) >= 3:
        info['tld'] = parts[-1]
        info['domain'] = parts[-2]
        info['subdomain'] = '.'.join(parts[:-2])
    elif len(parts) == 2:
        info['tld'] = parts[-1]
        info['domain'] = parts[0]
        info['subdomain'] = None
    else:
        info['tld'] = ''
        info['domain'] = parts[0]
        info['subdomain'] = None

    return info


# ═══════════════════════════════════════════
#  توليد الروابط - URL Generator
# ═══════════════════════════════════════════

def generate_urls(info, extensions=None):
    if extensions is None:
        extensions = ALL_EXT

    urls = set()
    base = info['base_url']
    sub  = info.get('subdomain')
    dom  = info['domain']
    tld  = info['tld']
    host = info['hostname']

    # 3 حالات الدومين
    dom_cases = domain_cases(dom)   # [nomad, NOMAD, Nomad]
    sub_cases = subdomain_cases(sub)  # [sec, SEC, Sec] or [None]

    for ext in extensions:
        for d in dom_cases:
            for s in sub_cases:

                # ══════════════════════════════════════════════
                #  النمط الرئيسي: sub.Domain.tld.ext
                # ══════════════════════════════════════════════
                if s:
                    # sec.nomad.com.rar | SEC.NOMAD.com.rar | Sec.Nomad.com.rar
                    urls.add(f"{base}/{s}.{d}.{tld}{ext}")

                    # sec.nomad.rar
                    urls.add(f"{base}/{s}.{d}{ext}")

                    # sec_nomad.rar | sec-nomad.rar
                    urls.add(f"{base}/{s}_{d}{ext}")
                    urls.add(f"{base}/{s}-{d}{ext}")

                    # sec_nomad_com.rar | sec-nomad-com.rar
                    urls.add(f"{base}/{s}_{d}_{tld}{ext}")
                    urls.add(f"{base}/{s}-{d}-{tld}{ext}")

                    # sec.rar
                    urls.add(f"{base}/{s}{ext}")

                # ══════════════════════════════════════════════
                #  domain.tld.ext
                # ══════════════════════════════════════════════
                urls.add(f"{base}/{d}.{tld}{ext}")        # nomad.com.rar | NOMAD.com.rar | Nomad.com.rar
                urls.add(f"{base}/{d}{ext}")               # nomad.rar | NOMAD.rar | Nomad.rar
                urls.add(f"{base}/{d}_{tld}{ext}")         # nomad_com.rar
                urls.add(f"{base}/{d}-{tld}{ext}")         # nomad-com.rar

        # ══════════════════════════════════════════════
        #  hostname كامل (بدون تغيير)
        # ══════════════════════════════════════════════
        urls.add(f"{base}/{host}{ext}")                    # sec.nomad.com.rar
        urls.add(f"{base}/{host.replace('.', '_')}{ext}")  # sec_nomad_com.rar
        urls.add(f"{base}/{host.replace('.', '-')}{ext}")  # sec-nomad-com.rar

        # ══════════════════════════════════════════════
        #  أسماء شائعة + Domain كبير وصغير
        # ══════════════════════════════════════════════
        for name in COMMON_NAMES:
            urls.add(f"{base}/{name}{ext}")
            for d in dom_cases:
                urls.add(f"{base}/{name}_{d}{ext}")        # backup_nomad.rar | backup_NOMAD.rar
                urls.add(f"{base}/{name}-{d}{ext}")        # backup-nomad.rar | backup-NOMAD.rar
                urls.add(f"{base}/{name}_{d}_{tld}{ext}")  # backup_nomad_com.rar
                urls.add(f"{base}/{name}-{d}-{tld}{ext}")  # backup-nomad-com.rar
                urls.add(f"{base}/{name}.{d}.{tld}{ext}")  # backup.nomad.com.rar
                urls.add(f"{base}/{d}_{name}{ext}")        # nomad_backup.rar | NOMAD_backup.rar
                urls.add(f"{base}/{d}-{name}{ext}")        # nomad-backup.rar

        # ══════════════════════════════════════════════
        #  مع التاريخ
        # ══════════════════════════════════════════════
        now = datetime.now()
        y = str(now.year)
        m = f"{now.month:02d}"
        dy = f"{now.day:02d}"
        dates = [y, f"{y}{m}", f"{y}{m}{dy}", f"{y}-{m}", f"{y}-{m}-{dy}", f"{y}_{m}_{dy}", f"{dy}-{m}-{y}"]

        for date in dates:
            for d in dom_cases:
                urls.add(f"{base}/{d}-{date}{ext}")
                urls.add(f"{base}/{d}_{date}{ext}")
                urls.add(f"{base}/backup-{date}{ext}")
                urls.add(f"{base}/backup_{date}{ext}")
                if sub:
                    for s in sub_cases:
                        if s:
                            urls.add(f"{base}/{s}.{d}.{tld}-{date}{ext}")
                            urls.add(f"{base}/{s}.{d}.{tld}_{date}{ext}")

        # ══════════════════════════════════════════════
        #  مسارات (مجلدات)
        # ══════════════════════════════════════════════
        for path in PATHS:
            if path:
                for d in dom_cases:
                    urls.add(f"{base}/{path}{d}.{tld}{ext}")
                    urls.add(f"{base}/{path}{d}{ext}")
                    if sub:
                        for s in sub_cases:
                            if s:
                                urls.add(f"{base}/{path}{s}.{d}.{tld}{ext}")

    return sorted(urls)


# ═══════════════════════════════════════════
#  النمط الرئيسي فقط - Main Pattern Only
# ═══════════════════════════════════════════

def generate_main_pattern(info, extensions=None):
    """النمط الرئيسي فقط مع Domain كبير وصغير"""
    if extensions is None:
        extensions = ALL_EXT

    urls = []
    base = info['base_url']
    sub  = info.get('subdomain')
    dom  = info['domain']
    tld  = info['tld']

    dom_cases = domain_cases(dom)
    sub_cases = subdomain_cases(sub)

    for ext in extensions:
        for d in dom_cases:
            for s in sub_cases:
                if s:
                    urls.append(f"{base}/{s}.{d}.{tld}{ext}")
                else:
                    urls.append(f"{base}/{d}.{tld}{ext}")

    return sorted(set(urls))


# ═══════════════════════════════════════════
#  فحص الرابط - URL Checker
# ═══════════════════════════════════════════

def check_url(url, timeout=10):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        }

        r = requests.head(url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
        status = r.status_code
        ct = r.headers.get('Content-Type', 'N/A')
        cl = r.headers.get('Content-Length', 'N/A')

        if status == 200:
            r2 = requests.get(url, timeout=timeout, stream=True, verify=False, headers=headers)
            ct = r2.headers.get('Content-Type', 'N/A')
            cl = r2.headers.get('Content-Length', 'N/A')

            if 'text/html' in ct.lower():
                chunk = r2.raw.read(2048)
                r2.close()
                try:
                    text = chunk.decode('utf-8', errors='ignore').lower()
                    if any(w in text for w in ['not found', '404', 'error', 'does not exist', 'page not found']):
                        return {'url': url, 'status': status, 'found': False, 'note': 'Soft 404'}
                except:
                    pass

            return {'url': url, 'status': status, 'ct': ct, 'cl': cl, 'found': True}

        return {'url': url, 'status': status, 'ct': ct, 'cl': cl, 'found': status in [301, 302, 403]}

    except requests.exceptions.ConnectTimeout:
        return {'url': url, 'status': 'TIMEOUT', 'found': False}
    except requests.exceptions.ConnectionError:
        return {'url': url, 'status': 'CONN_ERR', 'found': False}
    except Exception as e:
        return {'url': url, 'status': f'ERR', 'found': False}


# ═══════════════════════════════════════════
#  عرض النتائج - Display
# ═══════════════════════════════════════════

def show_result(result, show_all=False):
    status = result.get('status', 0)

    if result.get('found'):
        if status == 200:
            print(f"\n{C.G}{C.B}  [✓] FOUND 200 → {result['url']}")
            print(f"      ├── Type: {result.get('ct', 'N/A')}")
            print(f"      └── Size: {result.get('cl', 'N/A')}{C.X}")
            return 'found'

        elif status in [301, 302]:
            print(f"\n{C.Y}  [→] REDIRECT {status} → {result['url']}{C.X}")
            return 'interesting'

        elif status == 403:
            print(f"\n{C.M}  [!] FORBIDDEN 403 → {result['url']}{C.X}")
            return 'interesting'

    elif show_all:
        print(f"  {C.R}[✗] {status} → {result['url']}{C.X}")

    return None


# ═══════════════════════════════════════════
#  الرئيسي - Main
# ═══════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Backup File Finder - Domain كبير وصغير',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://sec.nomad.com
  %(prog)s -u https://sec.nomad.com --main-only
  %(prog)s -l targets.txt -t 20 -o results.txt
  %(prog)s -u https://sec.nomad.com --ext rar,zip,7z
  %(prog)s -u https://sec.nomad.com --generate-only
        """
    )

    parser.add_argument('-u', '--url',   help='رابط هدف واحد')
    parser.add_argument('-l', '--list',  help='ملف قائمة أهداف')
    parser.add_argument('-t', '--threads', type=int, default=10)
    parser.add_argument('-o', '--output', help='ملف حفظ النتائج')
    parser.add_argument('--timeout', type=int, default=10)
    parser.add_argument('--generate-only', action='store_true', help='توليد فقط بدون فحص')
    parser.add_argument('--main-only', action='store_true', help='النمط الرئيسي فقط')
    parser.add_argument('--ext', help='امتدادات محددة (مثال: rar,zip,7z)')
    parser.add_argument('--show-all', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()
    banner()

    # جمع الأهداف
    targets = []
    if args.url:
        targets.append(args.url.strip())
    elif args.list:
        try:
            with open(args.list) as f:
                targets = [l.strip() for l in f if l.strip() and not l.startswith('#')]
        except FileNotFoundError:
            print(f"{C.R}[✗] ملف غير موجود: {args.list}{C.X}")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    # الامتدادات
    extensions = ALL_EXT
    if args.ext:
        extensions = [f'.{e.strip().lstrip(".")}' for e in args.ext.split(',')]

    # توليد
    all_urls = []
    for target in targets:
        info = parse_target(target)
        if not info:
            print(f"{C.R}[✗] رابط غير صحيح: {target}{C.X}")
            continue

        sub = info.get('subdomain') or 'N/A'
        dom = info['domain']
        tld = info['tld']

        print(f"\n{C.CN}{'─' * 55}")
        print(f"  الهدف:     {info['base_url']}")
        print(f"  Subdomain: {sub}")
        print(f"  Domain:    {dom}  →  {C.Y}{dom.lower()}{C.CN} | {C.G}{dom.upper()}{C.CN} | {C.M}{dom.capitalize()}{C.CN}")
        print(f"  TLD:       {tld}")
        print(f"{'─' * 55}{C.X}")

        if args.main_only:
            urls = generate_main_pattern(info, extensions)
        else:
            urls = generate_urls(info, extensions)

        all_urls.extend(urls)

        # عرض أمثلة
        print(f"\n  {C.W}أمثلة على الروابط المولّدة:{C.X}")
        examples = urls[:12]
        for u in examples:
            # تلوين الدومين
            display = u
            for d in domain_cases(dom):
                if d in display:
                    if d == dom.upper():
                        display = display.replace(d, f"{C.G}{d}{C.X}", 1)
                    elif d == dom.capitalize():
                        display = display.replace(d, f"{C.M}{d}{C.X}", 1)
                    elif d == dom.lower():
                        display = display.replace(d, f"{C.Y}{d}{C.X}", 1)
                    break
            print(f"    → {display}")
        if len(urls) > 12:
            print(f"    ... و {len(urls) - 12} رابط آخر")

        print(f"\n  {C.CN}إجمالي: {C.Y}{len(urls)}{C.CN} رابط{C.X}")

    if not all_urls:
        print(f"\n{C.R}[✗] لا توجد روابط{C.X}")
        sys.exit(1)

    all_urls = sorted(set(all_urls))

    # توليد فقط
    if args.generate_only:
        print(f"\n{C.CN}{'═' * 55}")
        print(f"  إجمالي الروابط: {len(all_urls)}")
        print(f"{'═' * 55}{C.X}\n")
        for u in all_urls:
            print(u)
        if args.output:
            with open(args.output, 'w') as f:
                f.write('\n'.join(all_urls) + '\n')
            print(f"\n{C.G}[✓] محفوظ: {args.output}{C.X}")
        return

    # ═══ بدء الفحص ═══
    print(f"\n{C.CN}{'═' * 55}")
    print(f"  بدء الفحص")
    print(f"  روابط: {len(all_urls)} | Threads: {args.threads} | Timeout: {args.timeout}s")
    print(f"{'═' * 55}{C.X}")

    found = []
    interesting = []
    checked = 0

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_url, u, args.timeout): u for u in all_urls}

        for future in as_completed(futures):
            result = future.result()
            checked += 1

            # Progress bar
            pct = checked * 100 // len(all_urls)
            bar = '█' * (pct // 5) + '░' * (20 - pct // 5)
            sys.stdout.write(f"\r  {C.CN}[{bar}] {pct}% ({checked}/{len(all_urls)}){C.X}  ")
            sys.stdout.flush()

            r_type = show_result(result, args.show_all)
            if r_type == 'found':
                found.append(result)
            elif r_type == 'interesting':
                interesting.append(result)

    # ═══ النتائج ═══
    print(f"\n\n{C.CN}{'═' * 55}")
    print(f"  النتائج النهائية")
    print(f"{'═' * 55}{C.X}")
    print(f"  {C.W}تم فحص:          {checked}{C.X}")
    print(f"  {C.G}ملفات موجودة:    {len(found)}{C.X}")
    print(f"  {C.Y}مثيرة للاهتمام:  {len(interesting)}{C.X}")

    if found:
        print(f"\n  {C.G}{C.B}═══ ✓ ملفات موجودة ═══{C.X}")
        for r in found:
            print(f"  {C.G}  → {r['url']}")
            print(f"       Size: {r.get('cl', '?')} | Type: {r.get('ct', '?')}{C.X}")

    if interesting:
        print(f"\n  {C.Y}═══ ! مثيرة للاهتمام ═══{C.X}")
        for r in interesting:
            print(f"  {C.Y}  → [{r['status']}] {r['url']}{C.X}")

    if not found and not interesting:
        print(f"\n  {C.R}لم يتم العثور على ملفات{C.X}")

    # حفظ
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"# Backup Finder Results - {datetime.now()}\n")
            f.write(f"# Targets: {', '.join(targets)}\n\n")
            if found:
                f.write("## FOUND (200)\n")
                for r in found:
                    f.write(f"{r['url']} | Size: {r.get('cl','?')} | Type: {r.get('ct','?')}\n")
            if interesting:
                f.write("\n## INTERESTING\n")
                for r in interesting:
                    f.write(f"[{r['status']}] {r['url']}\n")
        print(f"\n  {C.G}[✓] محفوظ: {args.output}{C.X}")

    print(f"\n  {C.CN}[✓] انتهى{C.X}\n")


if __name__ == '__main__':
    main()
