import re
import os
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Enable ANSI colors on Windows 10+
if os.name == 'nt':
    os.system('color')


# Severity colors for terminal output
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[36m",
    "INFO":     "\033[34m",
}
RESET = "\033[0m"

def severity_tag(severity):
    # Returns colored label like [HIGH]     or [CRITICAL]
    padding = " " * (8 - len(severity))
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}[{severity}]{padding}{RESET}"


# ── Well-known paths to probe ──────────────────────────────────────────────────
#
# Each entry has:
#   name     = what we're looking for
#   path     = URL path to check
#   keyword  = if set, response body must contain this (case-insensitive)
#   severity = CRITICAL / HIGH / MEDIUM / LOW / INFO
#   file     = True means its a raw file (zip, sql, bak etc.)
#              so if the server returns HTML, its a false positive

COMMON_TEMPLATES = [
    # Exposed source / secrets
    {"name": "Exposed .git",          "path": "/.git/HEAD",                "keyword": "refs/heads",           "severity": "HIGH"},
    {"name": "Exposed .env",          "path": "/.env",                     "keyword": "APP_",                 "severity": "CRITICAL"},
    {"name": "phpinfo() page",        "path": "/phpinfo.php",              "keyword": "PHP Version",          "severity": "HIGH"},
    {"name": "Exposed .htaccess",     "path": "/.htaccess",                "keyword": "RewriteEngine",        "severity": "MEDIUM"},

    # Raw file backups (if server returns HTML for these, its a custom error page)
    {"name": "PHP Config Backup",     "path": "/config.php.bak",           "keyword": None,  "severity": "HIGH",   "file": True},
    {"name": "SQL Dump",              "path": "/backup.sql",               "keyword": None,  "severity": "HIGH",   "file": True},
    {"name": "Archive Backup",        "path": "/backup.zip",               "keyword": None,  "severity": "HIGH",   "file": True},
    {"name": "DS_Store Leak",         "path": "/.DS_Store",                "keyword": None,  "severity": "MEDIUM", "file": True},

    # Server info
    {"name": "Apache Server Status",  "path": "/server-status",            "keyword": "Apache Server Status", "severity": "MEDIUM"},
    {"name": "Nginx Status",          "path": "/nginx_status",             "keyword": "Active connections",   "severity": "MEDIUM"},

    # Info files
    {"name": "Robots.txt",            "path": "/robots.txt",               "keyword": "User-agent",           "severity": "INFO"},
    {"name": "Sitemap.xml",           "path": "/sitemap.xml",              "keyword": "<sitemap",             "severity": "INFO"},
    {"name": "Security.txt",          "path": "/.well-known/security.txt", "keyword": "Contact:",             "severity": "INFO"},

    # Admin panels (these are HTML pages, so no "file" flag)
    {"name": "Admin Panel /admin/",   "path": "/admin/",                   "keyword": None,                   "severity": "MEDIUM"},
    {"name": "Admin /administrator/", "path": "/administrator/",           "keyword": None,                   "severity": "MEDIUM"},
    {"name": "WordPress Admin",       "path": "/wp-admin/",                "keyword": None,                   "severity": "MEDIUM"},
    {"name": "phpMyAdmin",            "path": "/phpmyadmin/",              "keyword": "phpMyAdmin",           "severity": "HIGH"},
    {"name": "Adminer",               "path": "/adminer.php",              "keyword": "adminer",              "severity": "HIGH"},
]


# ── Security headers to check ─────────────────────────────────────────────────
#
# type = header_missing  → flag if the header is NOT present
# type = header_present  → flag if the header IS present (info disclosure)
# type = cors            → flag if Access-Control-Allow-Origin is *

VULN_TEMPLATES = [
    # Missing security headers
    {"type": "header_missing", "name": "Missing Content-Security-Policy", "header": "Content-Security-Policy",   "severity": "MEDIUM"},
    {"type": "header_missing", "name": "Missing X-Frame-Options",         "header": "X-Frame-Options",           "severity": "MEDIUM"},
    {"type": "header_missing", "name": "Missing HSTS",                    "header": "Strict-Transport-Security", "severity": "MEDIUM"},
    {"type": "header_missing", "name": "Missing X-Content-Type-Options",  "header": "X-Content-Type-Options",    "severity": "LOW"},
    {"type": "header_missing", "name": "Missing Referrer-Policy",         "header": "Referrer-Policy",           "severity": "LOW"},
    {"type": "header_missing", "name": "Missing Permissions-Policy",      "header": "Permissions-Policy",        "severity": "LOW"},

    # Information disclosure headers
    {"type": "header_present", "name": "Server Header Exposed",           "header": "Server",                    "severity": "INFO"},
    {"type": "header_present", "name": "X-Powered-By Exposed",            "header": "X-Powered-By",              "severity": "LOW"},
    {"type": "header_present", "name": "X-AspNet-Version Exposed",        "header": "X-AspNet-Version",          "severity": "LOW"},

    # CORS misconfiguration
    {"type": "cors",           "name": "CORS Wildcard (*)",                                                       "severity": "HIGH"},
]


# ── Technology fingerprints ────────────────────────────────────────────────────
#
# Each tech has 3 ways to detect it:
#   body    = keywords in page HTML
#   headers = specific header name:value pairs
#   cookies = cookie name prefixes (matched with startswith to avoid false positives)

TECH_SIGNATURES = {
    "WordPress":     {"body": ["wp-content/", "wp-includes/"],     "headers": {},                           "cookies": ["wordpress_logged_in", "wp-settings-"]},
    "Drupal":        {"body": ["Drupal.settings", "/sites/all/"],  "headers": {"X-Generator": "Drupal"},    "cookies": ["SESS"]},
    "Joomla":        {"body": ["/components/com_", "/media/jui/"], "headers": {},                           "cookies": []},
    "Laravel":       {"body": ["laravel"],                          "headers": {},                           "cookies": ["laravel_session"]},
    "Django":        {"body": ["csrfmiddlewaretoken"],              "headers": {},                           "cookies": ["csrftoken", "sessionid"]},
    "ASP.NET":       {"body": ["__VIEWSTATE", "__EVENTVALIDATION"],"headers": {"X-Powered-By": "ASP.NET"},  "cookies": ["ASP.NET_SessionId"]},
    "PHP":           {"body": [],                                   "headers": {"X-Powered-By": "PHP"},      "cookies": ["PHPSESSID"]},
    "Ruby on Rails": {"body": [],                                   "headers": {},                           "cookies": ["_rails_session"]},
    "Express.js":    {"body": [],                                   "headers": {"X-Powered-By": "Express"},  "cookies": []},
    "Spring":        {"body": [],                                   "headers": {},                           "cookies": ["JSESSIONID"]},
}


#  Helper functions
def get_base_url(target):
    # Strips the URL down to scheme://host (and port if present)
    # Example: http://example.com/login.aspx?id=1 → http://example.com
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        base += f":{parsed.port}"
    return base

def make_request(url, timeout=6):
    # Simple GET request with a custom User-Agent, ignores SSL errors
    try:
        return requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; FoxForge/1.0)"}
        )
    except Exception:
        return None


# [7] Common Checks

def run_common_checks(target):
    # Probes well-known paths for exposed files, backups, admin panels etc.
    # Always scans against the domain root, not the full user-supplied path

    base = get_base_url(target)
    print(f"\n[*] Common Checks → {base}")
    print("─" * 55)
    findings = []

    for template in COMMON_TEMPLATES:
        url = base + template["path"]
        resp = make_request(url)

        if resp is None or resp.status_code != 200:
            continue

        # If template has a keyword, the body must contain it
        if template["keyword"]:
            if template["keyword"].lower() not in resp.text.lower():
                continue

        # For raw file templates (zip, sql, bak etc.), if the server
        # returns HTML it means its a custom error page, not the actual file
        if template.get("file") and not template["keyword"]:
            content_type = resp.headers.get("Content-Type", "").lower()
            if "text/html" in content_type:
                continue

        findings.append({
            "name": template["name"],
            "url": url,
            "severity": template["severity"]
        })
        print(f"  {severity_tag(template['severity'])} {template['name']:<30} → {url}")

    if findings:
        print(f"\n  [*] {len(findings)} issue(s) found.")
    else:
        print("  [-] No issues found.")

    return findings


# [8] Vulnerability Templates
def run_vulnerability_templates(target):
    # Makes one request to the domain root and checks headers
    # for missing security controls, CORS wildcard, and info disclosure

    base = get_base_url(target)
    print(f"\n[*] Vulnerability Templates → {base}")
    print("─" * 55)
    findings = []

    resp = make_request(base)
    if resp is None:
        print("  [!] Could not reach target.")
        return findings

    headers = resp.headers

    for template in VULN_TEMPLATES:

        # Check if a security header is missing
        if template["type"] == "header_missing":
            if template["header"] not in headers:
                findings.append({
                    "name": template["name"],
                    "severity": template["severity"],
                    "detail": f"absent: {template['header']}"
                })
                print(f"  {severity_tag(template['severity'])} {template['name']}")

        # Check if an info-disclosure header is present
        elif template["type"] == "header_present":
            if template["header"] in headers:
                val = headers[template["header"]]
                findings.append({
                    "name": template["name"],
                    "severity": template["severity"],
                    "detail": f"{template['header']}: {val}"
                })
                print(f"  {severity_tag(template['severity'])} {template['name']:<38} → {val}")

        # Check for CORS wildcard
        elif template["type"] == "cors":
            if headers.get("Access-Control-Allow-Origin", "").strip() == "*":
                findings.append({
                    "name": template["name"],
                    "severity": template["severity"],
                    "detail": "Access-Control-Allow-Origin: *"
                })
                print(f"  {severity_tag(template['severity'])} {template['name']}")

    if findings:
        print(f"\n  [*] {len(findings)} issue(s) found.")
    else:
        print("  [-] No header issues found.")

    return findings


# Technology Detection 

def run_technology_detection(target):
    # Fingerprints the tech stack using headers, body keywords,
    # cookies, and the <meta name="generator"> tag
    # Always probes the domain root for the most reliable fingerprint

    base = get_base_url(target)
    print(f"\n[*] Technology Detection → {base}")
    print("─" * 55)
    detected = {}

    resp = make_request(base)
    if resp is None:
        print("  [!] Could not reach target.")
        return detected

    body = resp.text.lower()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookies = [c.lower() for c in resp.cookies.keys()]

    # Check raw server/language headers
    for hdr in ("Server", "X-Powered-By"):
        val = resp.headers.get(hdr)
        if val:
            detected[hdr] = val
            print(f"  {severity_tag('INFO')} {hdr:<20} → {val}")

    # Match against known framework/CMS signatures
    for tech, sig in TECH_SIGNATURES.items():
        score = 0
        hits = []

        # Check body keywords
        for keyword in sig["body"]:
            if keyword.lower() in body:
                score += 1
                hits.append(f"body:{keyword}")

        # Check headers
        for header_name, header_value in sig["headers"].items():
            actual = headers_lower.get(header_name.lower(), "")
            if header_value and header_value.lower() in actual.lower():
                score += 2
                hits.append(f"header:{header_name}")
            elif not header_value and actual:
                score += 2
                hits.append(f"header:{header_name}")

        # Check cookies (using startswith to avoid false positives like
        # JSESSIONID matching "sess" from Drupal's SESS pattern)
        for cookie_name in sig["cookies"]:
            if any(c.startswith(cookie_name.lower()) for c in cookies):
                score += 2
                hits.append(f"cookie:{cookie_name}")

        if score > 0:
            detected[tech] = hits
            print(f"  {severity_tag('INFO')} {tech:<20} → {', '.join(hits)}")

    # Check for <meta name="generator" content="..."> tag
    generator = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
        resp.text, re.IGNORECASE
    )
    if generator:
        detected["Generator"] = generator.group(1)
        print(f"  {severity_tag('INFO')} {'Generator':<20} → {generator.group(1)}")

    if detected:
        print(f"\n  [*] {len(detected)} signature(s) detected.")
    else:
        print("  [-] No signatures matched.")

    return detected


# [9] Full Template Scan

def full_template_scan(target):
    # Runs all three checks (Common + Vulnerability + Technology)
    # and prints a severity summary at the end

    base = get_base_url(target)
    print(f"\n{'=' * 55}")
    print(f"  FULL TEMPLATE SCAN  |  {base}")
    print(f"{'=' * 55}")

    common = run_common_checks(target)
    vulns = run_vulnerability_templates(target)
    tech = run_technology_detection(target)

    # Count findings by severity
    all_findings = common + vulns
    counts = {}
    for finding in all_findings:
        sev = finding["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    # Print summary
    print(f"\n{'─' * 55}")
    print("  SUMMARY")
    print(f"{'─' * 55}")
    print(f"  Common Issues      : {len(common)}")
    print(f"  Header Vulns       : {len(vulns)}")
    print(f"  Tech Detected      : {len(tech)}")
    print()

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = counts.get(sev, 0)
        if count:
            print(f"  {severity_tag(sev)} {count} finding(s)")
    print()

    return {"common": common, "vulns": vulns, "tech": tech}


# ── Report formatting (for workspace file output) ─────────────────────────────

def format_report(common=None, vulns=None, tech=None, target=""):
    """
    Builds a plain-text report from the findings returned by the
    template scan functions.  No ANSI colours so the file is readable.
    """
    lines = []
    lines.append("=" * 60)
    lines.append(f"  FoxForge Template Scan Report")
    lines.append(f"  Target: {target}")
    lines.append("=" * 60)

    # -- Common Checks --
    if common is not None:
        lines.append("")
        lines.append("[*] Common Checks")
        lines.append("-" * 55)
        if common:
            for f in common:
                lines.append(f"  [{f['severity']:8s}] {f['name']:<30} -> {f.get('url', '')}")
            lines.append(f"\n  [*] {len(common)} issue(s) found.")
        else:
            lines.append("  [-] No issues found.")

    # -- Vulnerability Templates --
    if vulns is not None:
        lines.append("")
        lines.append("[*] Vulnerability Templates")
        lines.append("-" * 55)
        if vulns:
            for f in vulns:
                detail = f.get("detail", "")
                lines.append(f"  [{f['severity']:8s}] {f['name']:<38} -> {detail}")
            lines.append(f"\n  [*] {len(vulns)} issue(s) found.")
        else:
            lines.append("  [-] No header issues found.")

    # -- Technology Detection --
    if tech is not None:
        lines.append("")
        lines.append("[*] Technology Detection")
        lines.append("-" * 55)
        if tech:
            for name, hits in tech.items():
                if isinstance(hits, list):
                    lines.append(f"  [INFO    ] {name:<20} -> {', '.join(hits)}")
                else:
                    lines.append(f"  [INFO    ] {name:<20} -> {hits}")
            lines.append(f"\n  [*] {len(tech)} signature(s) detected.")
        else:
            lines.append("  [-] No signatures matched.")

    # -- Summary --
    all_findings = (common or []) + (vulns or [])
    if all_findings:
        counts = {}
        for f in all_findings:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1
        lines.append("")
        lines.append("-" * 55)
        lines.append("  SUMMARY")
        lines.append("-" * 55)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = counts.get(sev, 0)
            if count:
                lines.append(f"  [{sev:8s}] {count} finding(s)")

    lines.append("")
    return "\n".join(lines)
